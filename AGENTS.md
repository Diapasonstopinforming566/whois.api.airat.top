# AGENTS.md

## Purpose
Public domain lookup API using RDAP with WHOIS fallback.

## Repository Role
- Category: `*.api.airat.top` (public API project).
- Deployment platform: Cloudflare Workers.
- Main files: `worker.js`, `wrangler.toml`.

## API Summary
- Live endpoint: `https://whois.api.airat.top`.
- Status page: `https://status.airat.top`.
- Required param: `domain` (alias: `name`).
- Lookup strategy: RDAP first, fallback to WHOIS source when needed.
- Routes: `/`, `/json`, `/text`, `/yaml`, `/xml`, `/health`.

## AI Working Notes
- Keep fallback behavior and source attribution in output.
- Keep domain validation and `400` responses for invalid input.
- Keep output structure stable for downstream parsing.
