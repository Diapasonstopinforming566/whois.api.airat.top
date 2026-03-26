# whois.api.airat.top

![whois](https://repository-images.githubusercontent.com/1191141883/0fc0dfe0-a453-4978-a5cf-8aa74d542937)

Public Cloudflare Worker API for domain lookup with RDAP + WHOIS fallback.

- Live endpoint: https://whois.api.airat.top
- Status page: https://status.airat.top

## API

Required query parameter:
- `domain` - domain name to look up (`example.com`).

Alias:
- `name` - works as alias for `domain`.

Lookup strategy:
1. RDAP via `https://rdap.org/domain/<domain>`
2. If RDAP is unavailable for a TLD, fallback via `https://whois.co.im/<domain>`

### `GET /`

Default endpoint. Returns WHOIS/RDAP data as JSON.

```bash
curl 'https://whois.api.airat.top/?domain=example.com'
```

Test in browser: https://whois.api.airat.top/?domain=example.com

Example response:

```json
{
  "ok": true,
  "query": {
    "domain": "example.com"
  },
  "lookup": {
    "rdapUrl": "https://rdap.verisign.com/com/v1/domain/example.com",
    "httpStatus": 200
  },
  "rdap": {
    "handle": "2336799_DOMAIN_COM-VRSN",
    "ldhName": "EXAMPLE.COM",
    "unicodeName": null,
    "status": ["client delete prohibited", "client transfer prohibited"],
    "registrar": {
      "name": "RESERVED-Internet Assigned Numbers Authority",
      "ianaId": "376",
      "handle": "376",
      "email": null,
      "url": null,
      "phone": null
    },
    "events": {
      "registration": "1995-08-14T04:00:00Z",
      "expiration": "2026-08-13T04:00:00Z",
      "lastChanged": "2025-08-14T00:00:00Z",
      "lastUpdate": "2025-08-14T00:00:00Z",
      "transfer": null
    },
    "nameservers": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"],
    "dnssecSigned": false
  },
  "service": "whois.api.airat.top",
  "generatedAt": "2026-03-25T00:00:00.000Z"
}
```

Fallback response example (for domains where RDAP is unavailable):

```json
{
  "ok": true,
  "query": {
    "domain": "bushido-coffee.ru"
  },
  "lookup": {
    "rdapUrl": "https://whois.co.im/bushido-coffee.ru",
    "httpStatus": 200,
    "source": "whois-coim-fallback",
    "whoisServer": "whois.co.im"
  },
  "rdap": {
    "handle": null,
    "ldhName": "BUSHIDO-COFFEE.RU",
    "unicodeName": null,
    "status": ["DELEGATED", "REGISTERED", "VERIFIED"],
    "registrar": {
      "name": "R01-RU",
      "ianaId": null,
      "handle": null,
      "email": null,
      "url": null,
      "phone": null
    },
    "events": {
      "registration": "September 20, 2007 at 8:00 PM UTC",
      "expiration": "September 20, 2026 at 9:00 PM UTC",
      "lastChanged": null,
      "lastUpdate": null,
      "transfer": null
    },
    "nameservers": ["ns1.expired.r01.ru", "ns2.expired.r01.ru"],
    "dnssecSigned": null
  },
  "service": "whois.api.airat.top",
  "generatedAt": "2026-03-26T00:00:00.000Z"
}
```

### `GET /json`

JSON alias for `/`.

```bash
curl 'https://whois.api.airat.top/json?domain=example.com'
```

Test in browser: https://whois.api.airat.top/json?domain=example.com

### `GET /text`

Returns a compact text summary.

```bash
curl 'https://whois.api.airat.top/text?domain=example.com'
```

Test in browser: https://whois.api.airat.top/text?domain=example.com

### `GET /yaml`

Returns the same payload as YAML.

```bash
curl 'https://whois.api.airat.top/yaml?domain=example.com'
```

Test in browser: https://whois.api.airat.top/yaml?domain=example.com

### `GET /xml`

Returns the same payload as XML.

```bash
curl 'https://whois.api.airat.top/xml?domain=example.com'
```

Test in browser: https://whois.api.airat.top/xml?domain=example.com

### `GET /health`

Health check endpoint.

```bash
curl 'https://whois.api.airat.top/health'
```

Response:

```json
{
  "status": "ok"
}
```

Test in browser: https://whois.api.airat.top/health

### Validation errors

Missing or invalid `domain` returns `400`:

```bash
curl 'https://whois.api.airat.top/?domain=bad domain'
```

```json
{
  "error": "Invalid domain parameter. Use a valid domain (example: example.com)."
}
```

### CORS

CORS is enabled for all origins (`*`).

## Privacy

No analytics or request logs are collected by this project.

## Project structure

- `worker.js` - Cloudflare Worker script.
- `wrangler.toml` - Wrangler configuration.

## Deployment

Deploy with Wrangler:

```bash
npx wrangler deploy
```

If you use Cloudflare Workers Builds (GitHub integration), keep root directory as `/` and deploy command as `npx wrangler deploy`.

For custom domain binding, configure it in **Workers & Pages -> Domains & Routes**.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE).

---

## Author

**AiratTop**

- Website: [airat.top](https://airat.top)
- GitHub: [@AiratTop](https://github.com/AiratTop)
- Email: [mail@airat.top](mailto:mail@airat.top)
- Repository: [whois.api.airat.top](https://github.com/AiratTop/whois.api.airat.top)
