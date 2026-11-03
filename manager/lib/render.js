import path from 'node:path';
import { writeTextAtomic, writeTextInPlace } from './util.js';
import {
  ZZZ_FILE,
  BASELINE_FILE,
  BEFORE_FILE,
  DEFAULT_UPSTREAM_FILE,
  SITES_FILE,
  RATE_LIMIT_ZONE_FILE,
  RATE_LIMIT_LOCATION_FILE,
  WAF_COMMUNITY_BLOCKLIST,
  ERROR_PAGES_CONF,
  ERROR_PAGES_DIR,
} from './config.js';
import { globalExcludedIds } from './state.js';

const HEADER = `# ===========================================================================
# This file is generated automatically by AsekWAF.
# JANGAN edit manual: perubahan akan ditimpa saat konfigurasi disimpan.
# ===========================================================================
`;

export function renderBaseline() {
  return `${HEADER}# AsekWAF baseline rules - high confidence gaps di luar CRS PL1.

# SQL boolean comparison / tautology sederhana (contoh: OR 'a'='a').
SecRule ARGS "@rx (?i)(?:^|[^a-z0-9_])(?:or|and)[\\s\\x0b]+.{1,32}=" "id:9000600,phase:2,deny,status:403,log,msg:'AsekWAF baseline: SQL boolean comparison',severity:'CRITICAL',tag:'openwaf/baseline',tag:'attack-sqli',t:urlDecodeUni,t:lowercase"

# File rahasia dan metadata source-control tidak boleh diakses dari web.
SecRule REQUEST_URI_RAW "@rx (?i)(?:^|/)(?:\\.env(?:[./?]|$)|\\.(?:git|svn|hg)(?:/|$)|id_rsa(?:[./?]|$)|authorized_keys(?:[./?]|$))" "id:9000601,phase:1,deny,status:403,log,msg:'AsekWAF baseline: sensitive file access',severity:'CRITICAL',tag:'openwaf/baseline',tag:'attack-disclosure',t:urlDecodeUni"

# PHP stream-wrapper injection pada parameter.
SecRule ARGS "@rx (?i)(?:php|phar|data|expect|file|zip)://" "id:9000602,phase:2,deny,status:403,log,msg:'AsekWAF baseline: PHP stream wrapper injection',severity:'CRITICAL',tag:'openwaf/baseline',tag:'attack-lfi',t:urlDecodeUni,t:lowercase"

# Null-byte encoding, termasuk double encoding.
SecRule REQUEST_URI_RAW "@rx (?i)(?:%00|%2500)" "id:9000603,phase:1,deny,status:403,log,msg:'AsekWAF baseline: null byte encoding',severity:'CRITICAL',tag:'openwaf/baseline',tag:'attack-evasion'"

# JNDI lookup injection (Log4Shell dan varian protokol umum).
SecRule REQUEST_HEADERS|ARGS "@rx (?i)\\$\\{jndi:(?:ldap|rmi|dns|iiop|https?)://" "id:9000604,phase:2,deny,status:403,log,msg:'AsekWAF baseline: JNDI lookup injection',severity:'CRITICAL',tag:'openwaf/baseline',tag:'attack-rce',t:urlDecodeUni"

# Command separator yang langsung diikuti perintah sistem berisiko tinggi.
SecRule ARGS "@rx (?i)(?:;|\\||&&|\\$\\()[\\s\\x0b]*(?:cat|id|whoami|uname|curl|wget|bash|sh|powershell)(?:[\\s\\x0b]|$)" "id:9000605,phase:2,deny,status:403,log,msg:'AsekWAF baseline: command injection',severity:'CRITICAL',tag:'openwaf/baseline',tag:'attack-rce',t:urlDecodeUni"

# PHP2Shell virtual patch (CVE-2026-109618 / CVE-2026-109619).
# PHP session upload progress is a prerequisite for the public multipart exploit chain.
SecRule REQUEST_METHOD "@streq POST" "id:9000606,phase:2,deny,status:403,log,chain,msg:'AsekWAF baseline: PHP2Shell session upload exploit attempt',severity:'CRITICAL',tag:'openwaf/baseline',tag:'attack-rce',tag:'cve/2026-109618',tag:'cve/2026-109619'"
 SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^multipart/form-data(?:;|$)" "chain"
  SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" "t:none"
`;
}

function sanitizeInline(value, field) {
  const str = String(value ?? '');
  if (/[\r\n]/.test(str)) throw new Error(`${field} tidak boleh mengandung baris baru`);
  return str;
}

function quote(value, field) {
  return sanitizeInline(value, field).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function singleQuote(value, field) {
  return sanitizeInline(value, field).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function html(value) {
  const chars = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return String(value ?? '').replace(/[&<>"']/g, (ch) => chars[ch]);
}

export function renderErrorPagesConfig(state) {
  if (state.errorPages?.enabled === false) return `${HEADER}# Custom error pages dinonaktifkan.\n`;
  const codes = [400, 403, 404, 429, 500, 502, 503, 504];
  return `${HEADER}${codes.map((code) => `error_page ${code} /__openwaf_error/${code}.html;`).join('\n')}

location ^~ /__openwaf_error/ {
    internal;
    alias /etc/openwaf-generated/error-pages/;
    add_header Cache-Control "no-store" always;
}
`;
}

export function renderErrorPage(state, code) {
  const cfg = state.errorPages || {};
  const page = cfg.pages?.[code] || {};
  const accent = /^#[0-9a-f]{6}$/i.test(cfg.accent || '') ? cfg.accent : '#2dd4bf';
  const language = ['en', 'id', 'zh', 'ar', 'ja'].includes(cfg.language) ? cfg.language : 'en';
  const direction = language === 'ar' ? 'rtl' : 'ltr';
  return `<!doctype html><html lang="${language}" dir="${direction}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${code} · ${html(page.title)}</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 50% 20%,#10233b 0,#070d18 55%);color:#e9f1fc;font-family:Inter,Segoe UI,system-ui,sans-serif}.card{width:min(560px,100%);padding:42px;border:1px solid #1d2f4a;border-radius:20px;background:rgba(14,26,44,.94);box-shadow:0 28px 70px -35px #000}.brand{font-size:14px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:${accent}}.code{margin:26px 0 4px;font-size:clamp(64px,15vw,112px);font-weight:800;line-height:.9;letter-spacing:-.06em;color:${accent}}h1{margin:20px 0 10px;font-size:28px}p{margin:0;color:#9bb0ca;line-height:1.7}.support{margin-top:24px;padding-top:20px;border-top:1px solid #1d2f4a;font-size:13px}@media(max-width:520px){.card{padding:28px}.code{font-size:72px}h1{font-size:23px}}</style></head><body><main class="card"><div class="brand">${html(cfg.brand || 'AsekWAF')}</div><div class="code">${code}</div><h1>${html(page.title)}</h1><p>${html(page.message)}</p><p class="support">${html(cfg.supportText || '')}</p></main></body></html>\n`;
}

export function renderZzz(state) {
  const parts = [HEADER];

  const allow = state.ipAllowlist.map((i) => i.value).filter(Boolean);
  if (allow.length) {
    parts.push(`# --- IP allowlist: WAF dimatikan untuk IP berikut ---`);
    parts.push(
      `SecRule REMOTE_ADDR "@ipMatch ${allow.join(',')}" "id:9000500,phase:1,pass,nolog,ctl:ruleEngine=Off,tag:'openwaf/allowlist'"`
    );
    parts.push('');
  }

  const block = state.ipBlocklist.map((i) => i.value).filter(Boolean);
  if (block.length) {
    parts.push(`# --- IP blocklist ---`);
    parts.push(
      `SecRule REMOTE_ADDR "@ipMatch ${block.join(',')}" "id:9000501,phase:1,deny,status:403,log,msg:'AsekWAF: alamat IP diblokir',tag:'openwaf/blocklist'"`
    );
    parts.push('');
  }

  if (state.threatIntel?.enabled && state.threatIntel.count > 0) {
    parts.push(`# --- Community threat intelligence blocklist ---`);
    parts.push(`# ${state.threatIntel.count} entri dari sumber komunitas`);
    parts.push(
      `SecRule REMOTE_ADDR "@ipMatchFromFile ${WAF_COMMUNITY_BLOCKLIST}" "id:9000510,phase:1,deny,status:403,log,msg:'AsekWAF: IP terindikasi berbahaya (community blocklist)',tag:'openwaf/community-blocklist'"`
    );
    parts.push('');
  }

  const disabled = [...globalExcludedIds(state)].sort((a, b) => a - b);
  if (disabled.length) {
    parts.push(`# --- Rule CRS yang dinonaktifkan / dikecualikan secara global ---`);
    for (const id of disabled) parts.push(`SecRuleRemoveById ${id}`);
    parts.push('');
  }

  const custom = state.customRules.filter((r) => r.enabled && r.raw.trim());
  if (custom.length) {
    parts.push(`# --- Custom rules ---`);
    for (const rule of custom) {
      parts.push(`# ${rule.name} (id:${rule.id})`);
      parts.push(rule.raw.trim());
      parts.push('');
    }
  }

  const cveRules = state.cveRuleFeeds?.enabled ? state.cveRuleFeeds.rules.filter((r) => r.enabled && r.raw.trim()) : [];
  if (cveRules.length) {
    parts.push(`# --- Managed CVE feed rules ---`);
    for (const rule of cveRules) {
      parts.push(`# ${rule.name} (id:${rule.id}, source:${rule.source || 'feed'})`);
      parts.push(rule.raw.trim(), '');
    }
  }

  if (parts.length === 1) parts.push('# Belum ada konfigurasi tambahan.');
  return `${parts.join('\n').trimEnd()}\n`;
}

export function renderBefore(state) {
  const parts = [HEADER];
  const exclusions = state.exclusions.filter(
    (exc) => exc.enabled && exc.scope !== 'global' && exc.ruleIds.length > 0
  );

  if (exclusions.length) {
    parts.push(`# --- Exclusion rules berbasis path / host ---`);
    for (const exc of exclusions) {
      const ctls = exc.ruleIds.map((id) => `ctl:ruleRemoveById=${id}`).join(',');
      if (exc.scope === 'host_path') {
        parts.push(`# ${exc.note || `Exclusion ${exc.id}`}`);
        parts.push(
          `SecRule REQUEST_HEADERS:Host "@streq ${quote(exc.host, 'Host')}" "id:${exc.genId},phase:1,pass,nolog,chain,tag:'openwaf/exclusion'"`
        );
        parts.push(` SecRule REQUEST_FILENAME "@streq ${quote(exc.match, 'Path')}" "${ctls}"`);
        parts.push('');
        continue;
      }
      const target =
        exc.scope === 'host'
          ? `REQUEST_HEADERS:Host "@rx ${quote(exc.match, 'Host')}"`
          : `REQUEST_URI "@beginsWith ${quote(exc.match, 'Path')}"`;
      parts.push(`# ${exc.note || `Exclusion ${exc.id}`}`);
      parts.push(
        `SecRule ${target} "id:${exc.genId},phase:1,pass,nolog,${ctls},tag:'openwaf/exclusion'"`
      );
      parts.push('');
    }
  } else {
    parts.push('# Belum ada exclusion berbasis path / host.');
  }

  return `${parts.join('\n').trimEnd()}\n`;
}

export async function writeGeneratedFiles(state) {
  const errorCodes = [400, 403, 404, 429, 500, 502, 503, 504];
  await Promise.all([
    writeTextAtomic(BASELINE_FILE, renderBaseline()),
    writeTextAtomic(ZZZ_FILE, renderZzz(state)),
    writeTextAtomic(BEFORE_FILE, renderBefore(state)),
    writeTextInPlace(DEFAULT_UPSTREAM_FILE, renderDefaultUpstream(state)),
    writeTextInPlace(SITES_FILE, renderSites(state)),
    writeTextInPlace(RATE_LIMIT_ZONE_FILE, renderRateLimitZone(state)),
    writeTextInPlace(RATE_LIMIT_LOCATION_FILE, renderRateLimitLocation(state)),
    writeTextInPlace(ERROR_PAGES_CONF, renderErrorPagesConfig(state)),
    ...errorCodes.map((code) =>
      writeTextAtomic(path.join(ERROR_PAGES_DIR, `${code}.html`), renderErrorPage(state, code))
    ),
  ]);
}

export function renderRateLimitZone(state) {
  const rate = Math.min(100000, Math.max(1, Number(state.rateLimit?.requestsPerMinute) || 120));
  return `${HEADER}
# Zone limit_req per client IP (http context).
limit_req_zone $binary_remote_addr zone=openwaf_limit:10m rate=${rate}r/m;
limit_req_status 429;
limit_req_log_level warn;
`;
}

export function renderRateLimitLocation(state) {
  const rl = state.rateLimit || {};
  if (!rl.enabled) {
    return `${HEADER}# Rate limit sedang dinonaktifkan dari panel.\n`;
  }
  const burst = Math.min(100000, Math.max(0, Number(rl.burst) || 0));
  const nodelay = rl.nodelay !== false ? ' nodelay' : '';
  return `${HEADER}# Rate limit aktif: ${rl.requestsPerMinute || 120} request/menit, burst ${burst}${nodelay.trim() ? ', nodelay' : ''}.
limit_req zone=openwaf_limit burst=${burst}${nodelay};
`;
}

function parseUpstream(upstream) {
  try {
    const url = new URL(String(upstream));
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    return { protocol: url.protocol, host: url.host, isHttps: url.protocol === 'https:' };
  } catch {
    return null;
  }
}

function proxyHeaders(preserveHost, websocket, host, interceptErrors = false) {
  return [
    `proxy_set_header Host ${preserveHost ? '$host' : host};`,
    'proxy_set_header Proxy "";',
    websocket ? 'proxy_set_header Upgrade $http_upgrade;' : '',
    websocket ? 'proxy_set_header Connection $connection_upgrade;' : 'proxy_set_header Connection "";',
    'proxy_set_header X-Real-IP $remote_addr;',
    'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
    'proxy_set_header X-Forwarded-Port $server_port;',
    'proxy_set_header X-Forwarded-Proto $scheme;',
    'proxy_http_version 1.1;',
    'proxy_buffering off;',
    'proxy_connect_timeout 60s;',
    'proxy_read_timeout 36000s;',
    'proxy_redirect off;',
    'proxy_pass_header Authorization;',
    interceptErrors ? 'proxy_intercept_errors on;' : '',
  ].filter(Boolean);
}

function tlsUpstream(verifyTls) {
  return [
    'proxy_ssl_server_name on;',
    verifyTls ? 'proxy_ssl_verify on;' : 'proxy_ssl_verify off;',
    verifyTls ? 'proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;' : '',
    verifyTls ? 'proxy_ssl_verify_depth 2;' : '',
  ].filter(Boolean);
}

export function renderDefaultUpstream(state) {
  const rp = state.reverseProxy || {};
  if (rp.fallbackMode === 'return404') {
    return `# AsekWAF - generated default fallback\n# Host yang tidak cocok ditolak dan tidak diteruskan ke backend.\nreturn 404;\n`;
  }
  const upstream = parseUpstream(rp.defaultUpstream || 'http://127.0.0.1:80') || {
    protocol: 'http:',
    host: '127.0.0.1:80',
    isHttps: false,
  };
  const preserveHost = rp.defaultPreserveHost !== false;
  const lines = [
    `# AsekWAF - generated default upstream`,
    `# Upstream default untuk reverse proxy (host yang tidak cocok dengan situs lain).`,
    `set $openwaf_default_upstream "${upstream.protocol}//${upstream.host}";`,
    ...proxyHeaders(preserveHost, true, upstream.host, state.errorPages?.enabled !== false),
    ...(upstream.isHttps ? tlsUpstream(false) : []),
    'proxy_pass $openwaf_default_upstream;',
  ];
  return `${lines.join('\n')}\n`;
}

export function renderSites(state) {
  const sites = state.reverseProxy?.sites || [];
  const parts = [
    '# ===========================================================================',
    '# AsekWAF - generated reverse proxy virtual hosts',
    '# This file is generated automatically. Do not edit it manually.',
    '# ===========================================================================',
    '',
  ];

  let count = 0;
  for (const site of sites) {
    if (!site.enabled || !site.hosts?.length) continue;
    const upstream = parseUpstream(site.upstream);
    if (!upstream) continue;
    const varName = `openwaf_up_${String(site.id).replace(/[^a-zA-Z0-9_]/g, '_')}`;
    const catchAll = site.hosts.includes('*');
    const hosts = site.hosts.filter((host) => host !== '*' && /^[a-z0-9.*-]+$/.test(host)).join(' ');
    const listenPort = Number.isInteger(site.listenPort) ? site.listenPort : 8080;
    if (!hosts && !catchAll) continue;
    count += 1;

    parts.push(`# ${site.name} (${site.id})`);
    parts.push('server {');
    parts.push(`    listen ${listenPort}${catchAll && listenPort !== 8080 ? ' default_server' : ''};`);
    parts.push(`    server_name ${catchAll ? (listenPort === 8080 ? '~^.*$' : '_') : hosts};`);
    parts.push('    client_max_body_size 0;');
    if (site.wafEnabled) {
      parts.push('    modsecurity on;');
      parts.push('    # Proteksi memakai konfigurasi CRS global /etc/modsecurity.d/setup.conf');
    } else {
      parts.push('    modsecurity off;');
      parts.push('    # WAF dinonaktifkan untuk virtual host ini');
    }
    parts.push('');
    parts.push('    location / {');
    parts.push('        include /etc/nginx/openwaf-ratelimit.conf;');
    parts.push(`        set $${varName} "${upstream.protocol}//${upstream.host}";`);
    for (const line of proxyHeaders(site.preserveHost !== false, site.websocket !== false, upstream.host, state.errorPages?.enabled !== false)) {
      parts.push(`        ${line}`);
    }
    if (upstream.isHttps) {
      for (const line of tlsUpstream(site.verifyTls === true)) parts.push(`        ${line}`);
    }
    parts.push(`        proxy_pass $${varName};`);
    parts.push('    }');
    parts.push('    include /etc/openwaf-generated/error-pages.conf;');
    parts.push('    include /etc/asekwaf-location-common.conf;');
    parts.push('}');
    parts.push('');
  }

  if (!count) parts.push('# Belum ada virtual host tambahan.');
  return `${parts.join('\n').trimEnd()}\n`;
}

export function buildCustomRule(input, id) {
  const field = sanitizeInline(input.field, 'Field');
  const operator = sanitizeInline(input.operator, 'Operator');
  const pattern = sanitizeInline(input.pattern, 'Pattern');
  const message = sanitizeInline(input.message || `AsekWAF custom rule ${id}`, 'Message');
  const action = ['deny', 'pass', 'allow'].includes(input.action) ? input.action : 'deny';
  const phase = Math.min(5, Math.max(1, Number.parseInt(input.phase, 10) || 2));
  const status = Math.min(599, Math.max(100, Number.parseInt(input.status, 10) || 403));
  const severity = sanitizeInline(input.severity || 'CRITICAL', 'Severity').toUpperCase();

  const allowedFields = new Set([
    'REQUEST_URI',
    'REQUEST_FILENAME',
    'QUERY_STRING',
    'REQUEST_METHOD',
    'REQUEST_BODY',
    'ARGS',
    'ARGS_NAMES',
    'REQUEST_COOKIES',
    'REQUEST_HEADERS:User-Agent',
    'REQUEST_HEADERS:Host',
    'REQUEST_HEADERS:Referer',
    'REQUEST_HEADERS:X-Forwarded-For',
    'REMOTE_ADDR',
  ]);
  const allowedOperators = new Set([
    '@rx',
    '@contains',
    '@beginsWith',
    '@endsWith',
    '@eq',
    '@ipMatch',
    '@pm',
    '@gt',
    '@lt',
  ]);
  const allowedSeverity = new Set([
    'EMERGENCY',
    'ALERT',
    'CRITICAL',
    'ERROR',
    'WARNING',
    'NOTICE',
    'INFO',
    'DEBUG',
  ]);

  if (!allowedFields.has(field)) throw new Error('Field tidak didukung');
  if (!allowedOperators.has(operator)) throw new Error('Operator tidak didukung');
  if (!pattern.trim()) throw new Error('Pattern tidak boleh kosong');
  if (!allowedSeverity.has(severity)) throw new Error('Severity tidak valid');

  const disruptiveActions = action === 'deny' ? `deny,status:${status},log` : `${action},log`;
  return [
    `SecRule ${field} "${operator} ${quote(pattern, 'Pattern')}" \\`,
    `    "id:${id},phase:${phase},${disruptiveActions},msg:'${singleQuote(message, 'Message')}',severity:'${severity}',tag:'openwaf/custom',t:none"`,
  ].join('\n');
}

export function validateRawRule(raw, id) {
  const text = String(raw || '').trim();
  if (!/^Sec(Rule|Action)\b/.test(text)) {
    throw new Error('Rule harus diawali dengan SecRule atau SecAction');
  }
  if (!new RegExp(`\\bid\\s*:\\s*'?${id}\\b`).test(text)) {
    throw new Error(`Rule harus memuat id:${id}`);
  }
  if (!/\bphase\s*:\s*[1-5]\b/.test(text)) {
    throw new Error('Rule harus memuat phase:1 sampai phase:5');
  }
  if (/[\r\n]\s*Include\b/i.test(text) || /^Include\b/m.test(text)) {
    throw new Error('Directive Include tidak diizinkan di custom rule');
  }
  return text;
}
