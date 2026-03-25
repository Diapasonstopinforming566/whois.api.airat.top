// WHOIS/RDAP API for Cloudflare Workers.

const SERVICE_NAME = 'whois.api.airat.top';
const RDAP_BASE_URL = 'https://rdap.org/domain/';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,HEAD,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Cache-Control': 'no-store, max-age=0',
  'X-Robots-Tag': 'noindex, nofollow'
};

function normalizePath(pathname) {
  if (pathname.length > 1 && pathname.endsWith('/')) {
    return pathname.slice(0, -1);
  }

  return pathname;
}

function normalizeValue(value) {
  if (value === undefined || value === null || value === '') {
    return null;
  }

  return value;
}

function normalizeBoolean(value) {
  return typeof value === 'boolean' ? value : null;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...CORS_HEADERS
    }
  });
}

function textResponse(text, status = 200) {
  return new Response(text, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      ...CORS_HEADERS
    }
  });
}

function xmlEscape(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function toXml(value, key = 'item', indent = '') {
  if (value === null) {
    return `${indent}<${key} />`;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return `${indent}<${key} />`;
    }

    const rows = value
      .map((entry) => toXml(entry, 'item', `${indent}  `))
      .join('\n');

    return `${indent}<${key}>\n${rows}\n${indent}</${key}>`;
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length === 0) {
      return `${indent}<${key} />`;
    }

    const rows = entries
      .map(([childKey, childValue]) => toXml(childValue, childKey, `${indent}  `))
      .join('\n');

    return `${indent}<${key}>\n${rows}\n${indent}</${key}>`;
  }

  return `${indent}<${key}>${xmlEscape(value)}</${key}>`;
}

function xmlResponse(data, status = 200) {
  const body = `<?xml version="1.0" encoding="UTF-8"?>\n${toXml(data, 'response')}`;

  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      ...CORS_HEADERS
    }
  });
}

function yamlEscapeString(value) {
  return String(value).replace(/'/g, "''");
}

function toYaml(value, indent = 0) {
  const prefix = '  '.repeat(indent);

  if (value === null) {
    return 'null';
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return `${prefix}[]`;
    }

    return value
      .map((entry) => {
        if (entry === null || typeof entry !== 'object') {
          return `${prefix}- ${toYaml(entry, 0)}`;
        }

        const nested = toYaml(entry, indent + 1);
        const lines = nested.split('\n');
        const firstPrefix = '  '.repeat(indent + 1);
        const firstLine = lines[0].startsWith(firstPrefix)
          ? lines[0].slice(firstPrefix.length)
          : lines[0];
        const rest = lines.slice(1).join('\n');

        return rest ? `${prefix}- ${firstLine}\n${rest}` : `${prefix}- ${firstLine}`;
      })
      .join('\n');
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length === 0) {
      return `${prefix}{}`;
    }

    return entries
      .map(([key, child]) => {
        if (Array.isArray(child) && child.length === 0) {
          return `${prefix}${key}: []`;
        }

        if (
          child
          && typeof child === 'object'
          && !Array.isArray(child)
          && Object.keys(child).length === 0
        ) {
          return `${prefix}${key}: {}`;
        }

        if (child === null || typeof child !== 'object') {
          return `${prefix}${key}: ${toYaml(child, 0)}`;
        }

        const nested = toYaml(child, indent + 1);
        return `${prefix}${key}:\n${nested}`;
      })
      .join('\n');
  }

  if (typeof value === 'string') {
    return `'${yamlEscapeString(value)}'`;
  }

  return String(value);
}

function yamlResponse(data, status = 200) {
  return new Response(toYaml(data), {
    status,
    headers: {
      'Content-Type': 'text/yaml; charset=utf-8',
      ...CORS_HEADERS
    }
  });
}

function healthPayload() {
  return { status: 'ok' };
}

function isValidDomain(domain) {
  if (!domain || domain.length > 253) {
    return false;
  }

  const normalized = domain.endsWith('.') ? domain.slice(0, -1) : domain;
  if (!normalized || normalized.includes('..')) {
    return false;
  }

  const labels = normalized.split('.');
  if (labels.length < 2) {
    return false;
  }

  for (const label of labels) {
    if (!label || label.length > 63) {
      return false;
    }

    if (!/^[A-Za-z0-9-]+$/.test(label)) {
      return false;
    }

    if (label.startsWith('-') || label.endsWith('-')) {
      return false;
    }
  }

  return true;
}

function parseDomain(rawDomain) {
  const raw = String(rawDomain || '').trim();
  if (!raw) {
    return {
      ok: false,
      error: 'Missing domain parameter. Example: ?domain=example.com'
    };
  }

  let candidate = raw.toLowerCase();

  if (candidate.startsWith('http://') || candidate.startsWith('https://')) {
    try {
      candidate = new URL(candidate).hostname.toLowerCase();
    } catch {
      return {
        ok: false,
        error: 'Invalid domain parameter. Use a valid domain (example: example.com).'
      };
    }
  }

  if (candidate.endsWith('.')) {
    candidate = candidate.slice(0, -1);
  }

  if (!isValidDomain(candidate)) {
    return {
      ok: false,
      error: 'Invalid domain parameter. Use a valid domain (example: example.com).'
    };
  }

  return { ok: true, domain: candidate };
}

function normalizeVcardValue(value) {
  if (Array.isArray(value)) {
    return normalizeValue(value[0]);
  }

  return normalizeValue(value);
}

function parseVcard(vcardArray) {
  const result = {};

  if (!Array.isArray(vcardArray) || vcardArray[0] !== 'vcard' || !Array.isArray(vcardArray[1])) {
    return result;
  }

  for (const row of vcardArray[1]) {
    if (!Array.isArray(row) || row.length < 4) {
      continue;
    }

    const key = String(row[0] || '').toLowerCase();
    const value = normalizeVcardValue(row[3]);

    if (key === 'fn') {
      result.name = value;
    }
    if (key === 'org') {
      result.organization = value;
    }
    if (key === 'email') {
      result.email = value;
    }
    if (key === 'url') {
      result.url = value;
    }
    if (key === 'tel') {
      result.phone = value;
    }
  }

  return result;
}

function collectEntities(entities, bag = []) {
  if (!Array.isArray(entities)) {
    return bag;
  }

  for (const entity of entities) {
    if (!entity || typeof entity !== 'object') {
      continue;
    }

    bag.push(entity);
    collectEntities(entity.entities, bag);
  }

  return bag;
}

function getIanaRegistrarId(entity) {
  if (!Array.isArray(entity?.publicIds)) {
    return null;
  }

  for (const item of entity.publicIds) {
    const type = String(item?.type || '').toLowerCase();
    if (type.includes('iana')) {
      return normalizeValue(item?.identifier);
    }
  }

  return null;
}

function extractRegistrar(entities) {
  const flat = collectEntities(entities);
  if (flat.length === 0) {
    return null;
  }

  const hasRegistrarRole = (entity) => {
    if (!Array.isArray(entity?.roles)) {
      return false;
    }

    return entity.roles.some((role) => String(role).toLowerCase() === 'registrar');
  };

  let registrar = flat.find(hasRegistrarRole);
  if (!registrar) {
    registrar = flat.find((entity) => getIanaRegistrarId(entity));
  }

  if (!registrar) {
    return null;
  }

  const vcard = parseVcard(registrar.vcardArray);
  const ianaId = getIanaRegistrarId(registrar);

  return {
    name: normalizeValue(vcard.organization || vcard.name),
    ianaId,
    handle: normalizeValue(registrar.handle),
    email: normalizeValue(vcard.email),
    url: normalizeValue(vcard.url),
    phone: normalizeValue(vcard.phone)
  };
}

function extractEvents(events) {
  const result = {
    registration: null,
    expiration: null,
    lastChanged: null,
    lastUpdate: null,
    transfer: null
  };

  if (!Array.isArray(events)) {
    return result;
  }

  const map = {
    registration: 'registration',
    expiration: 'expiration',
    'last changed': 'lastChanged',
    'last update': 'lastUpdate',
    'last update of rdap database': 'lastUpdate',
    transfer: 'transfer'
  };

  for (const event of events) {
    const action = String(event?.eventAction || '').toLowerCase();
    const key = map[action];
    if (!key) {
      continue;
    }

    if (!result[key]) {
      result[key] = normalizeValue(event?.eventDate);
    }
  }

  return result;
}

function extractNameservers(nameservers) {
  if (!Array.isArray(nameservers)) {
    return [];
  }

  return nameservers
    .map((item) => normalizeValue(item?.ldhName || item?.unicodeName || item?.handle))
    .filter(Boolean);
}

function extractErrorMessage(body, fallbackStatus) {
  const description = Array.isArray(body?.description)
    ? body.description.filter(Boolean).join(' ')
    : normalizeValue(body?.description);

  const title = normalizeValue(body?.title);

  if (title && description) {
    return `${title}: ${description}`;
  }

  if (title) {
    return title;
  }

  if (description) {
    return description;
  }

  return `RDAP lookup failed with HTTP ${fallbackStatus}.`;
}

function buildPayload(domain, rdapData, response) {
  const registrar = extractRegistrar(rdapData?.entities);

  return {
    ok: response.ok,
    query: {
      domain
    },
    lookup: {
      rdapUrl: normalizeValue(response.url),
      httpStatus: response.status
    },
    rdap: {
      handle: normalizeValue(rdapData?.handle),
      ldhName: normalizeValue(rdapData?.ldhName),
      unicodeName: normalizeValue(rdapData?.unicodeName),
      status: Array.isArray(rdapData?.status) ? rdapData.status : [],
      registrar,
      events: extractEvents(rdapData?.events),
      nameservers: extractNameservers(rdapData?.nameservers),
      dnssecSigned: normalizeBoolean(rdapData?.secureDNS?.delegationSigned)
    },
    service: SERVICE_NAME,
    generatedAt: new Date().toISOString()
  };
}

async function performWhoisLookup(domain) {
  const rdapUrl = `${RDAP_BASE_URL}${encodeURIComponent(domain)}`;

  let response;
  try {
    response = await fetch(rdapUrl, {
      headers: {
        Accept: 'application/rdap+json, application/json;q=0.9',
        'User-Agent': `${SERVICE_NAME}/1.0 (+https://airat.top)`
      }
    });
  } catch (error) {
    return {
      ok: false,
      status: 502,
      error: `RDAP lookup failed: ${error?.message || 'network error'}`
    };
  }

  let body;
  try {
    body = await response.json();
  } catch {
    return {
      ok: false,
      status: 502,
      error: 'Failed to parse RDAP response.'
    };
  }

  if (!response.ok) {
    return {
      ok: false,
      status: response.status,
      error: extractErrorMessage(body, response.status)
    };
  }

  return {
    ok: true,
    payload: buildPayload(domain, body, response)
  };
}

function renderText(payload) {
  const lines = [];

  lines.push(payload.rdap.ldhName || payload.query.domain);

  const registrarName = payload.rdap.registrar?.name;
  if (registrarName) {
    let registrarLine = `Registrar: ${registrarName}`;
    if (payload.rdap.registrar?.ianaId) {
      registrarLine += ` (IANA ${payload.rdap.registrar.ianaId})`;
    }
    lines.push(registrarLine);
  }

  if (payload.rdap.events.registration) {
    lines.push(`Created: ${payload.rdap.events.registration}`);
  }
  if (payload.rdap.events.expiration) {
    lines.push(`Expires: ${payload.rdap.events.expiration}`);
  }
  if (payload.rdap.events.lastChanged) {
    lines.push(`Updated: ${payload.rdap.events.lastChanged}`);
  }

  if (payload.rdap.status.length > 0) {
    lines.push(`Status: ${payload.rdap.status.join(', ')}`);
  }

  if (payload.rdap.nameservers.length > 0) {
    lines.push('Nameservers:');
    for (const ns of payload.rdap.nameservers) {
      lines.push(`- ${ns}`);
    }
  }

  return lines.join('\n');
}

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (!['GET', 'HEAD'].includes(request.method)) {
      return textResponse('Method Not Allowed', 405);
    }

    const url = new URL(request.url);
    const path = normalizePath(url.pathname);

    if (path === '/robots.txt') {
      return textResponse('User-agent: *\nDisallow: /\n');
    }

    if (path === '/health') {
      return jsonResponse(healthPayload());
    }

    const allowedPaths = new Set(['/', '/json', '/text', '/yaml', '/xml']);
    if (!allowedPaths.has(path)) {
      return textResponse('Not Found', 404);
    }

    const domainResult = parseDomain(url.searchParams.get('domain') || url.searchParams.get('name'));
    if (!domainResult.ok) {
      return jsonResponse({ error: domainResult.error }, 400);
    }

    const lookup = await performWhoisLookup(domainResult.domain);
    if (!lookup.ok) {
      return jsonResponse({ error: lookup.error }, lookup.status || 502);
    }

    const payload = lookup.payload;

    if (path === '/text') {
      return textResponse(renderText(payload));
    }

    if (path === '/yaml') {
      return yamlResponse(payload);
    }

    if (path === '/xml') {
      return xmlResponse(payload);
    }

    return jsonResponse(payload);
  }
};
