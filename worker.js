// WHOIS/RDAP API for Cloudflare Workers.
import { connect } from 'cloudflare:sockets';

const SERVICE_NAME = 'whois.api.airat.top';
const RDAP_BASE_URL = 'https://rdap.org/domain/';
const WHOIS_FALLBACK_BASE_URL = 'https://www.whois.com/whois/';
const WHOIS_CO_IM_BASE_URL = 'https://whois.co.im/';

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

function getDomainTld(domain) {
  const labels = String(domain || '').split('.');
  if (labels.length < 2) {
    return '';
  }

  return String(labels[labels.length - 1] || '').toLowerCase();
}

function isRuDomain(domain) {
  return getDomainTld(domain) === 'ru';
}

function getWhoisServerForDomain(domain) {
  const tld = getDomainTld(domain);

  const map = {
    ru: 'whois.tcinet.ru',
    im: 'whois.nic.im'
  };

  return normalizeValue(map[tld]);
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

function safeJsonParse(value) {
  if (typeof value !== 'string' || value.trim() === '') {
    return null;
  }

  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function decodeHtmlEntities(value) {
  if (typeof value !== 'string' || value === '') {
    return '';
  }

  return value.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (match, entity) => {
    const normalized = String(entity).toLowerCase();

    if (normalized === 'amp') {
      return '&';
    }
    if (normalized === 'lt') {
      return '<';
    }
    if (normalized === 'gt') {
      return '>';
    }
    if (normalized === 'quot') {
      return '"';
    }
    if (normalized === 'apos') {
      return '\'';
    }
    if (normalized === 'nbsp') {
      return ' ';
    }

    if (normalized.startsWith('#x')) {
      const code = Number.parseInt(normalized.slice(2), 16);
      if (Number.isFinite(code) && code >= 0 && code <= 0x10FFFF) {
        return String.fromCodePoint(code);
      }
      return match;
    }

    if (normalized.startsWith('#')) {
      const code = Number.parseInt(normalized.slice(1), 10);
      if (Number.isFinite(code) && code >= 0 && code <= 0x10FFFF) {
        return String.fromCodePoint(code);
      }
      return match;
    }

    return match;
  });
}

function stripHtmlTags(value) {
  if (typeof value !== 'string' || value === '') {
    return '';
  }

  return decodeHtmlEntities(value.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim());
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractRawWhoisFromHtml(html) {
  if (typeof html !== 'string' || html === '') {
    return null;
  }

  const rawBlockMatch = html.match(/<pre[^>]*class=(['"])[^'"]*\bdf-raw\b[^'"]*\1[^>]*>([\s\S]*?)<\/pre>/i);
  if (!rawBlockMatch) {
    return null;
  }

  return normalizeValue(decodeHtmlEntities(rawBlockMatch[2]).trim());
}

function normalizeNameserver(value) {
  const firstToken = String(value || '').trim().split(/\s+/)[0] || '';
  return normalizeValue(firstToken.replace(/\.$/, ''));
}

function parseWhoisKeyValueLines(rawWhois) {
  if (typeof rawWhois !== 'string') {
    return [];
  }

  const entries = [];

  for (const line of rawWhois.split('\n')) {
    const match = line.match(/^\s*([^:#][^:]*?)\s*:\s*(.+?)\s*$/);
    if (!match) {
      continue;
    }

    entries.push({
      key: String(match[1] || '').toLowerCase().trim(),
      value: String(match[2] || '').trim()
    });
  }

  return entries;
}

function pickFirstWhoisValue(entries, keys) {
  for (const wanted of keys) {
    const found = entries.find((entry) => entry.key === wanted);
    if (found) {
      return normalizeValue(found.value);
    }
  }

  return null;
}

function pickAllWhoisValues(entries, keys) {
  const allowed = new Set(keys);

  return entries
    .filter((entry) => allowed.has(entry.key))
    .map((entry) => normalizeValue(entry.value))
    .filter(Boolean);
}

function splitStatusLines(value) {
  if (!value) {
    return [];
  }

  const prepared = String(value).replace(/<br\s*\/?>/gi, '\n');

  return prepared
    .split(/[\n,]/)
    .map((item) => normalizeValue(item))
    .filter(Boolean);
}

function extractWhoisFallbackData(rawWhois) {
  const entries = parseWhoisKeyValueLines(rawWhois);

  const domainName = pickFirstWhoisValue(entries, ['domain', 'domain name']);
  const registrar = pickFirstWhoisValue(entries, ['registrar']);
  const registrarIanaId = pickFirstWhoisValue(entries, ['registrar iana id', 'iana id']);
  const created = pickFirstWhoisValue(entries, [
    'created',
    'creation date',
    'registered on',
    'registration time'
  ]);
  const expires = pickFirstWhoisValue(entries, [
    'paid-till',
    'expiry date',
    'expiration date',
    'expires',
    'expires on',
    'registry expiry date',
    'registrar registration expiration date',
    'renewal date'
  ]);
  const updated = pickFirstWhoisValue(entries, ['last updated on', 'updated date', 'updated on', 'changed']);
  const organization = pickFirstWhoisValue(entries, ['org', 'organization']);
  const registrarEmail = pickFirstWhoisValue(entries, [
    'registrar abuse contact email',
    'email'
  ]);
  const registrarPhone = pickFirstWhoisValue(entries, [
    'registrar abuse contact phone',
    'phone'
  ]);
  const registrarUrl = pickFirstWhoisValue(entries, ['registrar url', 'url']);

  const statusValues = [
    ...pickAllWhoisValues(entries, ['state']),
    ...pickAllWhoisValues(entries, ['status']),
    ...pickAllWhoisValues(entries, ['domain status'])
  ];
  const status = statusValues
    .flatMap((value) => splitStatusLines(value))
    .filter((value, index, list) => list.indexOf(value) === index);

  const nameserverValues = [
    ...pickAllWhoisValues(entries, ['nserver']),
    ...pickAllWhoisValues(entries, ['name server']),
    ...pickAllWhoisValues(entries, ['nameserver'])
  ];
  const nameservers = nameserverValues
    .map((value) => normalizeNameserver(value))
    .filter(Boolean)
    .filter((value, index, list) => list.indexOf(value) === index);

  return {
    domainName,
    registrar,
    registrarIanaId,
    organization,
    registrarEmail,
    registrarPhone,
    registrarUrl,
    created,
    expires,
    updated,
    status,
    nameservers
  };
}

function looksLikeWhoisNotFound(rawWhois) {
  if (typeof rawWhois !== 'string' || rawWhois.trim() === '') {
    return true;
  }

  const body = rawWhois.toLowerCase();
  const notFoundPatterns = [
    'no match for',
    'domain not found',
    'not found',
    'no entries found',
    'object does not exist',
    'status: available',
    'no data found'
  ];

  return notFoundPatterns.some((pattern) => body.includes(pattern));
}

function hasMeaningfulWhoisData(parsed) {
  if (!parsed || typeof parsed !== 'object') {
    return false;
  }

  return Boolean(
    parsed.domainName
    || parsed.registrar
    || parsed.expires
    || parsed.created
    || parsed.updated
    || (Array.isArray(parsed.nameservers) && parsed.nameservers.length > 0)
    || (Array.isArray(parsed.status) && parsed.status.length > 0)
  );
}

function extractWhoisCoImValue(html, label) {
  const regex = new RegExp(
    `<p[^>]*>\\s*<strong>\\s*${escapeRegex(label)}\\s*:<\\/strong>\\s*([\\s\\S]*?)<\\/p>`,
    'i'
  );

  const match = html.match(regex);
  if (!match) {
    return null;
  }

  const value = normalizeValue(stripHtmlTags(match[1]));
  if (!value) {
    return null;
  }

  return value;
}

function extractWhoisCoImList(html, heading) {
  const headingRegex = new RegExp(
    `<div[^>]*class="[^"]*card-header[^"]*"[^>]*>\\s*<strong>\\s*${escapeRegex(heading)}\\s*<\\/strong>\\s*<\\/div>`,
    'i'
  );
  const headingMatch = headingRegex.exec(html);
  if (!headingMatch) {
    return [];
  }

  const afterHeading = html.slice(headingMatch.index);
  const listMatch = afterHeading.match(/<ul[^>]*>([\s\S]*?)<\/ul>/i);
  if (!listMatch) {
    return [];
  }

  const listBody = listMatch[1];
  const liRegex = /<li[^>]*>([\s\S]*?)<\/li>/gi;
  const values = [];

  let itemMatch = liRegex.exec(listBody);
  while (itemMatch) {
    const value = normalizeValue(stripHtmlTags(itemMatch[1]));
    if (value) {
      values.push(value);
    }

    itemMatch = liRegex.exec(listBody);
  }

  return values;
}

function extractWhoisCoImFallbackData(html, domain) {
  const domainName = normalizeValue(
    extractWhoisCoImValue(html, 'Domain')
    || extractWhoisCoImValue(html, 'Domain Name')
    || domain
  );
  const registrar = normalizeValue(extractWhoisCoImValue(html, 'Registrar'));
  const created = normalizeValue(extractWhoisCoImValue(html, 'Created'));
  const updated = normalizeValue(extractWhoisCoImValue(html, 'Updated'));
  const expires = normalizeValue(extractWhoisCoImValue(html, 'Expires'));
  const organization = normalizeValue(extractWhoisCoImValue(html, 'Company'));

  const status = extractWhoisCoImList(html, 'Domain Status');
  const nameservers = extractWhoisCoImList(html, 'Name Servers')
    .map((item) => normalizeNameserver(item))
    .filter(Boolean);

  return {
    domainName,
    registrar,
    registrarIanaId: null,
    organization,
    registrarEmail: null,
    registrarPhone: null,
    registrarUrl: null,
    created,
    expires,
    updated,
    status,
    nameservers
  };
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

function buildWhoisFallbackPayload(
  domain,
  fallbackData,
  sourceUrl,
  status,
  source = 'whois-fallback',
  whoisServer = null
) {
  const fallbackDomain = normalizeValue(fallbackData.domainName || domain);
  const registrarName = normalizeValue(fallbackData.registrar || fallbackData.organization);

  return {
    ok: true,
    query: {
      domain
    },
    lookup: {
      rdapUrl: normalizeValue(sourceUrl),
      httpStatus: status,
      source,
      whoisServer: normalizeValue(whoisServer)
    },
    rdap: {
      handle: null,
      ldhName: fallbackDomain ? fallbackDomain.toUpperCase() : null,
      unicodeName: null,
      status: Array.isArray(fallbackData.status) ? fallbackData.status : [],
      registrar: {
        name: registrarName,
        ianaId: normalizeValue(fallbackData.registrarIanaId),
        handle: null,
        email: normalizeValue(fallbackData.registrarEmail),
        url: normalizeValue(fallbackData.registrarUrl),
        phone: normalizeValue(fallbackData.registrarPhone)
      },
      events: {
        registration: normalizeValue(fallbackData.created),
        expiration: normalizeValue(fallbackData.expires),
        lastChanged: normalizeValue(fallbackData.updated),
        lastUpdate: null,
        transfer: null
      },
      nameservers: Array.isArray(fallbackData.nameservers) ? fallbackData.nameservers : [],
      dnssecSigned: null
    },
    service: SERVICE_NAME,
    generatedAt: new Date().toISOString()
  };
}

async function queryWhoisServer(hostname, queryDomain) {
  let socket;
  let reader;
  let writer;

  try {
    socket = connect({
      hostname,
      port: 43
    });

    writer = socket.writable.getWriter();
    const encoder = new TextEncoder();
    await writer.write(encoder.encode(`${queryDomain}\r\n`));
    await writer.close();

    reader = socket.readable.getReader();
    const decoder = new TextDecoder();

    let response = '';
    const timeoutId = setTimeout(() => {
      try {
        reader.cancel();
      } catch {}

      try {
        socket.close();
      } catch {}
    }, 9000);

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          break;
        }

        if (value) {
          response += decoder.decode(value, { stream: true });
        }
      }

      response += decoder.decode();
    } finally {
      clearTimeout(timeoutId);
    }

    return normalizeValue(response.trim());
  } catch {
    return null;
  } finally {
    try {
      reader?.releaseLock();
    } catch {}

    try {
      writer?.releaseLock();
    } catch {}

    try {
      socket?.close();
    } catch {}
  }
}

async function tryWhoisTcpFallback(domain) {
  const whoisServer = getWhoisServerForDomain(domain);
  if (!whoisServer) {
    return null;
  }

  const rawWhois = await queryWhoisServer(whoisServer, domain);
  if (!rawWhois || looksLikeWhoisNotFound(rawWhois)) {
    return null;
  }

  const fallbackData = extractWhoisFallbackData(rawWhois);
  if (!hasMeaningfulWhoisData(fallbackData)) {
    return null;
  }

  return buildWhoisFallbackPayload(
    domain,
    fallbackData,
    `whois://${whoisServer}/${domain}`,
    200,
    'whois-tcp-fallback',
    whoisServer
  );
}

async function tryRuWhoisFallback(domain) {
  if (!isRuDomain(domain)) {
    return null;
  }

  const fallbackUrl = `${WHOIS_FALLBACK_BASE_URL}${encodeURIComponent(domain)}`;

  let response;
  try {
    response = await fetch(fallbackUrl, {
      headers: {
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'User-Agent': `${SERVICE_NAME}/1.0 (+https://airat.top)`
      }
    });
  } catch {
    return null;
  }

  if (!response.ok) {
    return null;
  }

  let html;
  try {
    html = await response.text();
  } catch {
    return null;
  }

  const rawWhois = extractRawWhoisFromHtml(html);
  if (!rawWhois) {
    return null;
  }

  const fallbackData = extractWhoisFallbackData(rawWhois);

  return buildWhoisFallbackPayload(
    domain,
    fallbackData,
    response.url || fallbackUrl,
    response.status,
    'whois-web-fallback'
  );
}

async function tryWhoisCoImFallback(domain) {
  const fallbackUrl = `${WHOIS_CO_IM_BASE_URL}${encodeURIComponent(domain)}`;

  let response;
  try {
    response = await fetch(fallbackUrl, {
      headers: {
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'User-Agent': `${SERVICE_NAME}/1.0 (+https://airat.top)`
      }
    });
  } catch {
    return null;
  }

  if (!response.ok) {
    return null;
  }

  let html;
  try {
    html = await response.text();
  } catch {
    return null;
  }

  if (!html || !html.includes('hero-title')) {
    return null;
  }

  const fallbackData = extractWhoisCoImFallbackData(html, domain);
  if (!hasMeaningfulWhoisData(fallbackData)) {
    return null;
  }

  return buildWhoisFallbackPayload(
    domain,
    fallbackData,
    response.url || fallbackUrl,
    response.status,
    'whois-coim-fallback',
    'whois.co.im'
  );
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

  let rawBody;
  try {
    rawBody = await response.text();
  } catch {
    return {
      ok: false,
      status: 502,
      error: 'Failed to read RDAP response.'
    };
  }

  const body = safeJsonParse(rawBody);

  if (!response.ok) {
    const tcpWhoisFallbackPayload = await tryWhoisTcpFallback(domain);
    if (tcpWhoisFallbackPayload) {
      return {
        ok: true,
        payload: tcpWhoisFallbackPayload
      };
    }

    const coImFallbackPayload = await tryWhoisCoImFallback(domain);
    if (coImFallbackPayload) {
      return {
        ok: true,
        payload: coImFallbackPayload
      };
    }

    const ruFallbackPayload = await tryRuWhoisFallback(domain);
    if (ruFallbackPayload) {
      return {
        ok: true,
        payload: ruFallbackPayload
      };
    }

    return {
      ok: false,
      status: response.status,
      error: extractErrorMessage(body, response.status)
    };
  }

  if (!body || typeof body !== 'object') {
    const tcpWhoisFallbackPayload = await tryWhoisTcpFallback(domain);
    if (tcpWhoisFallbackPayload) {
      return {
        ok: true,
        payload: tcpWhoisFallbackPayload
      };
    }

    const coImFallbackPayload = await tryWhoisCoImFallback(domain);
    if (coImFallbackPayload) {
      return {
        ok: true,
        payload: coImFallbackPayload
      };
    }

    const ruFallbackPayload = await tryRuWhoisFallback(domain);
    if (ruFallbackPayload) {
      return {
        ok: true,
        payload: ruFallbackPayload
      };
    }

    return {
      ok: false,
      status: 502,
      error: 'Failed to parse RDAP response.'
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
