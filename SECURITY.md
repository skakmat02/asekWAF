# Security Policy

AsekWAF is an open-source project. Responsible disclosure helps protect every user.

## Supported versions

Security fixes are provided for the latest tagged release. Deployments should pin the
AsekWAF release, CRS image, and Docker socket proxy image instead of tracking a moving tag.

## Reporting a vulnerability

Do not open a public issue for an unpatched vulnerability. Contact the repository
maintainer privately and include the affected version, reproduction steps, impact, and
any suggested mitigation. The maintainer should acknowledge a report within 72 hours
and coordinate disclosure after a fix is available.

Never include production credentials, audit logs, client IPs, private rules, or upstream
URLs in a report without redacting them.

## Security boundaries

- The admin panel is intended for trusted operators and must stay behind HTTPS plus a
  VPN, SSH tunnel, or identity-aware access proxy.
- AsekWAF is one security layer, not a replacement for secure application code,
  authentication, patch management, or network segmentation.
- Raw ModSecurity rules and WAF container operations are privileged administrative
  capabilities.
- The single Compose configuration uses a restricted Docker API proxy. Anyone who controls
  the manager can still execute commands inside the WAF container; protect the panel.
