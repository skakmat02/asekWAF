# Production deployment

AsekWAF is open-source software distributed under the MIT License.

## Preconditions

- A dedicated, patched Linux host with Docker Engine and Compose v2.
- The admin panel is reachable only through HTTPS and a VPN or access proxy.
- DNS, public certificates, monitoring, off-host backups, and an incident-response owner.
- A staging environment that mirrors production.

## Deploy

1. Copy `.env.production.example` to `.env.production`.
2. Generate independent secrets. The password must contain at least 16 characters and
   the session secret at least 32 random characters.
3. Verify every pinned image version in staging. For the strongest reproducibility,
   replace tags with registry digests approved by your deployment process.
4. Run `make production-check`. This validates `.env.production` against the single
   `docker-compose.yml` used by every deployment mode.
5. Run `make production-up`.
6. Put `127.0.0.1:8081` behind HTTPS. Do not publish it directly.
7. Verify `/healthz`, login throttling, secure cookies, WAF blocking, proxy routing,
   WebSocket traffic, error pages, audit pruning, and restore from backup.

Production mode refuses to start when the admin password or session secret is missing
or weak, or when secure cookies are disabled.

## Operations

- Monitor container health, 4xx/5xx rate, WAF blocks, disk usage, audit pruning, and
  upstream latency.
- Back up `.env.production`, `deploy/`, and both named volumes using encrypted off-host
  storage. Test restoration regularly.
- Upgrade CRS and AsekWAF in staging first. Review false positives before rollout.
- Rotate the admin password and session secret after suspected compromise. Changing the
  session secret invalidates every active session.
- Keep the WAF engine `On`; alert when it changes to `DetectionOnly` or `Off`.

## Known architectural limits

- One administrator credential; no built-in RBAC, SSO, or 2FA.
- Per-site certificates can be installed from the UI, but renewal remains an operator responsibility.
- Docker API access is narrowed through a proxy but remains privileged enough to execute
  commands in the WAF container.

Organizations requiring RBAC, mandatory 2FA, immutable admin audit trails, or formal
compliance certification must add those controls before approving production use.

Runtime-generated files under `deploy/modsec` and `deploy/nginx` are ignored by Git.
Only sanitized seeds under `deploy/examples` belong in the public repository. Before a
first push, confirm with `git status --ignored` that `.env.production`, state, generated
sites, certificates, logs, and backups are not staged.
