# AsekWAF

AsekWAF is an **open-source Web Application Firewall management platform** for
**ModSecurity v3 and OWASP Core Rule Set (CRS)** running on Nginx. It also acts as a
reverse proxy, allowing operators to manage application upstreams, public ports,
security rules, exclusions, IP lists, and audit logs from a browser.

> Status: production baseline for controlled, single-administrator deployments. For
> production, use `.env.production` and follow [PRODUCTION.md](PRODUCTION.md).

## Features

- Responsive AdminLTE dashboard with light, dark, and automatic themes.
- ModSecurity audit events, filters, rule details, and quick allow/block actions.
- OWASP CRS catalog, tuning, exclusions, and automatic release updates.
- Visual and raw custom-rule editors with `deny`, `pass`, and `allow` actions.
- Managed CVE virtual-patch feeds synchronized from selected HTTPS URLs.
- IP allowlist/blocklist, community threat intelligence, and rate limiting.
- Reverse proxy by hostname or dynamic public port, including wildcard hosts.
- WebSocket support, upstream TLS verification, per-site HTTPS certificates, and per-site WAF control.
- Test Console for sending requests through the actual WAF path.
- Custom 400/403/404/429/500/502/503/504 response pages.
- Audit-log retention and automatic pruning.
- Export/import for reverse-proxy sites and safe settings.
- Transactional configuration validation, reload, and rollback.
- English, Indonesian, Chinese, Arabic, and Japanese interfaces.

## Architecture

```text
Browser ─► Manager :8081 ─► Docker socket proxy ─► Docker Engine
              │
              └── writes state and generated configuration

Client ─► WAF Nginx :8080/:8443/dynamic ports ─► application upstream
                    └── ModSecurity + OWASP CRS
```

| Service | Purpose | Port |
|---|---|---|
| `waf` | Nginx, ModSecurity, CRS, and reverse proxy | `8080`, `8443`, dynamic ports |
| `manager` | API and AdminLTE management panel | `127.0.0.1:8081` |
| `bootstrap` | Seeds the CRS volume and prepares permissions, then exits | — |
| `docker-proxy` | Restricts the Docker API available to the manager | internal |

Important generated files include:

- `deploy/modsec/openwaf-state.json` — application state.
- `deploy/modsec/modsecurity-override.conf` — ModSecurity settings.
- `deploy/nginx/default-upstream.conf` — fallback routing.
- `deploy/nginx/sites.conf` — generated site listeners.
- `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` — scoped exclusions.
- `REQUEST-904-OPENWAF-BASELINE.conf` — baseline and built-in virtual patches.
- `REQUEST-905-OPENWAF-CUSTOM.conf` — custom and managed feed rules.

## Quick start

Requirements: Docker Engine and Docker Compose v2.

```bash
cp .env.example .env
# Replace OPENWAF_ADMIN_PASSWORD and OPENWAF_SESSION_SECRET.
make up
```

Without Make:

```bash
docker compose up -d --build
```

Endpoints:

- Management panel: `http://localhost:8081`
- WAF and hostname routing: `http://localhost:8080`
- Testing HTTPS listener: `https://localhost:8443`

Sign in with `OPENWAF_ADMIN_PASSWORD`. The unsafe fallback password is `admin` and
must be changed. For rootless Docker, set `OPENWAF_MANAGER_UID` and
`OPENWAF_MANAGER_GID` to the output of `id -u` and `id -g`.

```bash
make ps
make logs
curl -fsS http://127.0.0.1:8081/healthz
curl -kfsS https://127.0.0.1:8443/healthz
```

New installations return HTTP 404 for unmatched hosts. Add a site in Reverse Proxy or
select **Forward to default upstream** when fallback routing is required.

## Reverse proxy

### Unmatched requests

- **Return 404 (recommended)** rejects unknown hosts locally.
- **Forward to default upstream** sends unknown hosts to a configured backend.

Upstream URLs contain only a scheme, host, and optional port:

```text
http://app:3000
https://backend.internal:8443
```

### Hostname or public-port routing

Example site:

- Name: `Sikoas`
- Hostname: `app.example.com`, `*.example.com`, or `*`
- Upstream: `http://192.168.192.108:4416`
- Public port: `6677`

The application is then available at `http://ASEKWAF-IP:6677`. Test hostname routing
without changing DNS:

```bash
curl -H 'Host: app.example.com' http://127.0.0.1:8080/
```

Ports `1–65535` are supported except reserved ports `8081`, `8443`, and `18080`.
Because the WAF uses host networking, open only required ports in the host firewall.
Every generated listener still passes through ModSecurity when site protection is enabled.

Each reverse-proxy site can terminate HTTPS on its configured public port. In the site
form, enable **HTTPS listener**, then upload or paste a PEM certificate/full chain and
its matching unencrypted PEM private key. AsekWAF validates the pair and certificate
dates before reloading Nginx. The selected port serves HTTPS instead of HTTP.

Certificates are stored locally under `deploy/nginx/certificates/`, excluded from Git
and configuration exports, and removed when HTTPS is disabled or the site is deleted.
Back them up separately and protect the private keys. Port 8443 still uses the image's
testing certificate and is not intended as a production certificate.

If AsekWAF is behind a trusted proxy, configure `OPENWAF_TRUSTED_PROXY`. Never use
`0.0.0.0/0`, because clients could spoof `X-Forwarded-For`.

When a CDN or load balancer accepts public HTTPS on port 443 and forwards it to a
dynamic AsekWAF listener (for example port 8121), AsekWAF preserves the public origin
through `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-Port`. Applications
therefore generate public URLs without leaking the internal listener port. Configure
the upstream framework to trust only the actual proxy addresses. For direct access
with an explicit port in the `Host` header, AsekWAF retains that port.

## Rules and false positives

Use the narrowest available control:

1. Add a path/host exclusion for a false-positive CRS rule.
2. Use custom `allow` only for a highly specific trusted condition.
3. Use IP allowlisting only for trusted infrastructure because it disables inspection.

The `/healthz` endpoint is locally allowed and excluded from audit logging because it is
used by AsekWAF container health checks.

## Managed CVE rule feeds

Settings can synchronize virtual patches from HTTPS JSON feeds. A feed is limited to
2 MB and 500 rules. Redirects and URLs with embedded credentials are rejected. IDs
`9900000–9999999` are reserved for managed rules.

```json
{
  "version": 1,
  "rules": [
    {
      "id": 9900001,
      "name": "Example CVE virtual patch",
      "cves": ["CVE-2099-0001"],
      "enabled": true,
      "raw": "SecRule ARGS \"@contains exploit-marker\" \"id:9900001,phase:2,deny,status:403,log,msg:'CVE virtual patch',severity:'CRITICAL',tag:'openwaf/cve-feed'\""
    }
  ]
}
```

Rules are validated before replacing active feed rules. Download, parsing, validation,
or reload failure leaves the previous rule set active. Automatic synchronization runs
when CRS updates are checked or installed.

HTTPS and format validation do not provide cryptographic publisher authentication.
Production feeds should be delivered through trusted, reviewed infrastructure.

### PHP2Shell virtual patch

Rule `9000606` detects the known multipart session-upload pattern used by
CVE-2026-109618 and CVE-2026-109619. This is defense in depth and does not replace
upgrading PHP. Do not globally exclude this rule.

## Export and import

Open **Settings → Configuration backup**. Exports include:

- Reverse-proxy sites, ports, and fallback behavior
- ModSecurity and CRS tuning
- Rate limiting and threat-intelligence settings
- Audit retention and custom error pages
- Managed CVE feed configuration

Passwords, session secrets, certificates, audit logs, and downloaded feed caches are
never exported. Keep exports encrypted because they may contain internal upstream URLs.
Import regenerates managed files, validates Nginx, and reloads the WAF.

## CRS updates and reset

Use Settings for normal CRS updates. Custom state is stored outside the CRS volume and
is preserved during updates.

```bash
make backup
make reset-crs
```

Manual changes inside the CRS volume are not preserved. AsekWAF regenerates managed
configuration from state after a reset.

## Production deployment

Use [.env.production.example](.env.production.example) and read
[PRODUCTION.md](PRODUCTION.md).

```bash
cp .env.production.example .env.production
# Set strong unique secrets and pin reviewed container versions.
make production-check
make production-up
```

Keep the management panel behind HTTPS plus a VPN, SSH tunnel, or identity-aware access
proxy. Review [SECURITY.md](SECURITY.md) before exposing applications publicly.

## Local development

Node.js 20 or newer is required.

```bash
npm ci --prefix manager
make check
make dev
```

Development mode uses `test/fixtures`, runs at `http://localhost:8081`, and uses password
`admin`. Docker operations and WAF reloads are skipped.

## Project structure

```text
.
├── docker-compose.yml
├── .env.example
├── .env.production.example
├── Makefile
├── PRODUCTION.md
├── SECURITY.md
├── deploy/
│   ├── examples/
│   ├── modsec/
│   └── nginx/
├── manager/
│   ├── server.js
│   ├── lib/
│   └── public/
└── test/fixtures/
```

## Make commands

| Command | Purpose |
|---|---|
| `make up` | Initialize, build, and start services |
| `make down` | Stop services while preserving volumes |
| `make logs` | Follow service logs |
| `make ps` | Show container status |
| `make check` | Run syntax and dependency checks |
| `make dev` | Start the manager using fixtures |
| `make reload` | Validate and reload Nginx manually |
| `make reset-crs` | Reseed the CRS volume |
| `make reset-all` | Remove containers and volumes, including audit logs |
| `make backup` | Archive `deploy/` and `.env` |
| `make production-check` | Validate production settings |
| `make production-up` | Start with `.env.production` |

## Troubleshooting

### Changes are saved but not active

Use Reload in the top bar. Inspect **Settings → Container logs** if validation fails.

### 502 Bad Gateway

Verify that the upstream is reachable from the host-networked WAF container and that
the application listens on the configured address and port.

### A public site port is unreachable

Confirm that the site is enabled, the port is not reserved, and the host firewall allows
it. Use **Reverse Proxy → Check integration** and inspect listeners with `ss -lntp`.

### No audit events appear

`SecAuditEngine RelevantOnly` records relevant rule matches. Change it temporarily to
`On` when full request auditing is required.

### CVE feed synchronization fails

The URL must use HTTPS without credentials or redirects. Check the JSON schema, the
2 MB/500-rule limits, and IDs `9900000–9999999`. Previous rules remain active.

### Session is lost after restart

Set a persistent `OPENWAF_SESSION_SECRET`.

## Security limitations

- One administrator credential; built-in RBAC, SSO, and 2FA are not yet available.
- Certificate renewal is manual; replace the certificate from the site's edit form before expiry.
- Raw ModSecurity rules are privileged and must be limited to trusted operators.
- IP allowlisting disables WAF inspection for matching clients.
- Engine `Off` turns AsekWAF into an unprotected reverse proxy.
- Docker API access remains security-sensitive even through the restricted proxy.
- A WAF complements rather than replaces patching, secure coding, authentication,
  least privilege, monitoring, and network segmentation.

## License

AsekWAF is open-source software released under the [MIT License](LICENSE).

## Security reports

Do not disclose unpatched vulnerabilities through public issues. Follow
[SECURITY.md](SECURITY.md).
