import http from 'node:http';
import { createReadStream } from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
  PORT,
  ADMIN_PASSWORD,
  OPENWAF_VERSION,
  WAF_URL,
  WAF_CONTAINER,
  CONFIG_DIR,
  CRS_DIR,
  AUDIT_LOG,
  STATE_FILE,
  OVERRIDE_FILE,
  CRS_SETUP_FILE,
  CRS_RULES_DIR,
  ZZZ_FILE,
  BASELINE_FILE,
  BEFORE_FILE,
  NGINX_DIR,
  DEFAULT_UPSTREAM_FILE,
  SITES_FILE,
  RATE_LIMIT_ZONE_FILE,
  RATE_LIMIT_LOCATION_FILE,
  ERROR_PAGES_CONF,
  CERTIFICATES_DIR,
  COMMUNITY_BLOCKLIST_FILE,
  ENGINE_MODES,
  AUDIT_MODES,
  PRODUCTION_MODE,
  validateRuntimeSecurity,
  loadRawSettings,
  parseSettings,
  parseCrsVersion,
  applySettingsToCrs,
  renderOverride,
} from './lib/config.js';
import {
  HttpError,
  ensureDir,
  readText,
  writeTextAtomic,
  writeTextInPlace,
  parseCookies,
  truncate,
  nowIso,
} from './lib/util.js';
import {
  loadState,
  saveState,
  mutateState,
  allocateRuleId,
  globalExcludedIds,
  takePreviousState,
} from './lib/state.js';
import { writeGeneratedFiles, buildCustomRule, validateRawRule } from './lib/render.js';
import { getCatalog, getRule, catalogStats } from './lib/crs.js';
import { checkForUpdate, downloadCrsRelease } from './lib/crsupdate.js';
import { THREAT_SOURCES, fetchThreatIntel, threatIntelDue, isPublicThreatEntry } from './lib/threatintel.js';
import { createAuditStore } from './lib/audit.js';
import {
  dockerAvailable,
  dockerError,
  inspectContainer,
  reloadWaf,
  reopenWafLogs,
  restartWaf,
  containerLogs,
} from './lib/docker.js';
import {
  issueSession,
  clearSessionCookie,
  verifySession,
  checkPassword,
  loginRateLimit,
  recordFailedLogin,
  resetFailedLogins,
  usingDefaultPassword,
  COOKIE_NAME,
} from './lib/auth.js';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)));
const geoIpCache = new Map();
const GEO_CACHE_MS = 24 * 3600_000;

async function attackCountries(hours = 24) {
  const attacks = audit.attackIps(hours, 100);
  const publicAttacks = attacks.filter((item) => isPublicThreatEntry(item.ip));
  const localEvents = attacks.filter((item) => !isPublicThreatEntry(item.ip)).reduce((sum, item) => sum + item.count, 0);
  const now = Date.now();
  const missing = publicAttacks
    .map((item) => item.ip)
    .filter((ip) => !geoIpCache.has(ip) || now - geoIpCache.get(ip).at > GEO_CACHE_MS);
  let lookupError = '';
  if (missing.length) {
    try {
      // Maksimal 10 lookup per refresh untuk mengikuti batas infrastruktur
      // provider. Hasil disimpan 24 jam sehingga refresh berikutnya murah.
      const rows = await Promise.all(missing.slice(0, 10).map(async (ip) => {
        const response = await fetch(`https://api.country.is/${encodeURIComponent(ip)}?fields=location`, {
          headers: { 'User-Agent': 'AsekWAF/1.0' },
          signal: AbortSignal.timeout(6000),
        });
        if (!response.ok) throw new Error(`GeoIP HTTP ${response.status}`);
        return response.json();
      }));
      for (const row of rows) {
        if (!row?.ip) continue;
        geoIpCache.set(row.ip, {
          at: now,
          country: String(row.country || '').toUpperCase(),
          latitude: Number(row.location?.latitude),
          longitude: Number(row.location?.longitude),
        });
      }
    } catch (err) {
      lookupError = err.message;
    }
  }
  const grouped = new Map();
  for (const item of publicAttacks) {
    const geo = geoIpCache.get(item.ip);
    if (!geo?.country) continue;
    const current = grouped.get(geo.country) || {
      country: geo.country,
      count: 0,
      ips: 0,
      latitude: geo.latitude,
      longitude: geo.longitude,
    };
    current.count += item.count;
    current.ips += 1;
    grouped.set(geo.country, current);
  }
  return {
    hours,
    countries: [...grouped.values()].sort((a, b) => b.count - a.count),
    publicIps: publicAttacks.length,
    localEvents,
    provider: 'country.is',
    error: lookupError || null,
  };
}
const PUBLIC_DIR = path.join(APP_ROOT, 'public');
const ADMINLTE_CSS = path.join(APP_ROOT, 'node_modules', 'admin-lte', 'dist', 'css', 'adminlte.min.css');
const audit = createAuditStore(AUDIT_LOG);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
};

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/;
const IPV6 = /^[0-9a-fA-F:]+(?:\/\d{1,3})?$/;

function log(...args) {
  console.log(`[openwaf] ${new Date().toISOString()}`, ...args);
}

function clientIp(req) {
  return req.socket.remoteAddress || 'unknown';
}

function json(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (PRODUCTION_MODE) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
  );
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 2 * 1024 * 1024) throw new HttpError(413, 'Body terlalu besar');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'JSON tidak valid');
  }
}

function snapshot(files) {
  return Promise.all(
    files.map(async (file) => {
      try {
        return { file, data: await fsp.readFile(file) };
      } catch (err) {
        if (err.code === 'ENOENT') return { file, data: null };
        throw err;
      }
    })
  );
}

async function restore(snap) {
  for (const item of snap) {
    try {
      if (item.data === null) await fsp.unlink(item.file).catch(() => {});
      else await fsp.writeFile(item.file, item.data);
    } catch (err) {
      log('Gagal restore', item.file, err.message);
    }
  }
}

async function commitState(state, previousState = null) {
  previousState ||= takePreviousState(state);
  const snap = await snapshot([
    STATE_FILE,
    ZZZ_FILE,
    BASELINE_FILE,
    BEFORE_FILE,
    DEFAULT_UPSTREAM_FILE,
    SITES_FILE,
    RATE_LIMIT_ZONE_FILE,
    RATE_LIMIT_LOCATION_FILE,
    ERROR_PAGES_CONF,
    COMMUNITY_BLOCKLIST_FILE,
  ]);
  if (previousState) {
    const stateItem = snap.find((item) => item.file === STATE_FILE);
    if (stateItem) stateItem.data = Buffer.from(`${JSON.stringify(previousState, null, 2)}\n`);
  }
  try {
    await writeGeneratedFiles(state);
    const saved = await saveState(state);
    const reload = await reloadWaf();
    if (!reload.ok) {
      await restore(snap);
      throw new HttpError(422, reload.message || 'Konfigurasi ditolak oleh ModSecurity/Nginx', {
        output: reload.output || '',
      });
    }
    return { state: saved, reload };
  } catch (err) {
    if (!(err instanceof HttpError)) await restore(snap);
    throw err;
  }
}

let threatSyncRunning = false;
let auditPruneRunning = false;

async function pruneAuditLog(retention) {
  if (auditPruneRunning) throw new HttpError(409, 'Prune audit log sedang berjalan');
  auditPruneRunning = true;
  try {
    const result = await audit.prune(retention.days);
    const reopen = await reopenWafLogs();
    if (!reopen.ok) throw new Error(`Gagal membuka ulang audit log: ${reopen.message}`);
    await audit.resetAfterPrune();
    const saved = await mutateState(async (state) => {
      state.auditRetention = {
        ...state.auditRetention,
        lastPrune: nowIso(),
        lastRemoved: result.removed,
        lastKept: result.kept,
        lastSizeBefore: result.sizeBefore,
        lastSizeAfter: result.sizeAfter,
        lastError: null,
      };
      return state.auditRetention;
    });
    return { ...result, retention: saved.state.auditRetention };
  } catch (err) {
    await mutateState(async (state) => {
      state.auditRetention.lastError = String(err.message || err).slice(0, 600);
    }).catch(() => {});
    throw err;
  } finally {
    auditPruneRunning = false;
  }
}

function auditPruneDue(retention) {
  if (!retention?.enabled) return false;
  const last = retention.lastPrune ? new Date(retention.lastPrune).getTime() : 0;
  return !Number.isFinite(last) || Date.now() - last >= 24 * 3600_000;
}

async function syncThreatIntel() {
  if (threatSyncRunning) throw new HttpError(409, 'Sinkronisasi threat intelligence sedang berjalan');
  threatSyncRunning = true;
  const state = await loadState();
  const snap = await snapshot([COMMUNITY_BLOCKLIST_FILE, STATE_FILE, ZZZ_FILE]);
  try {
    const fetched = await fetchThreatIntel(state.threatIntel.sources);
    await writeTextAtomic(COMMUNITY_BLOCKLIST_FILE, `${fetched.entries.join('\n')}\n`);
    state.threatIntel = {
      ...state.threatIntel,
      count: fetched.entries.length,
      sourceCounts: fetched.sourceCounts,
      lastSync: fetched.fetchedAt,
      lastError: fetched.errors.length ? fetched.errors.join(' | ').slice(0, 600) : null,
      lastDurationMs: fetched.durationMs,
    };
    const commit = await commitState(state);
    return { fetched, commit };
  } catch (err) {
    await restore(snap);
    throw err;
  } finally {
    threatSyncRunning = false;
  }
}

function validateUpstream(value) {
  const text = String(value || '').trim();
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error('URL upstream tidak valid. Contoh: http://app:3000');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Upstream harus menggunakan http:// atau https://');
  }
  if (url.username || url.password) throw new Error('URL upstream tidak boleh memuat kredensial');
  if ((url.pathname && url.pathname !== '/') || url.search || url.hash) {
    throw new Error('Upstream hanya boleh berisi skema, host, dan port (tanpa path/query)');
  }
  if (!url.hostname) throw new Error('Host upstream tidak valid');
  return `${url.protocol}//${url.host}`;
}

function validateHosts(value) {
  const list = Array.isArray(value) ? value : String(value || '').split(/[\s,]+/);
  const hosts = [...new Set(list.map((host) => String(host).trim().toLowerCase().replace(/\.$/, '')).filter(Boolean))];
  if (!hosts.length) throw new Error('Minimal satu hostname wajib diisi');
  if (hosts.length > 50) throw new Error('Maksimal 50 hostname per situs');
  const pattern = /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;
  for (const host of hosts) {
    if ((host !== '*' && !pattern.test(host)) || host.length > 253) {
      throw new Error(`Hostname tidak valid: ${host}`);
    }
  }
  return hosts;
}

function validateListenPort(value, fallback = 8080) {
  const port = Number.parseInt(value ?? fallback, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Port publik harus berupa angka antara 1 dan 65535');
  }
  if ([8081, 8443, 18080].includes(port)) {
    throw new Error(`Port ${port} dicadangkan untuk layanan internal AsekWAF`);
  }
  return port;
}

function validateSite(body, state, existing = null) {
  const name = String(body.name ?? existing?.name ?? 'Situs').trim().slice(0, 120) || 'Situs';
  const hosts = validateHosts(body.hosts ?? existing?.hosts ?? []);
  const upstream = validateUpstream(body.upstream ?? existing?.upstream ?? '');
  const listenPort = validateListenPort(body.listenPort, existing?.listenPort ?? 8080);

  for (const site of state.reverseProxy.sites) {
    if (existing && site.id === existing.id) continue;
    if ((site.listenPort || 8080) !== listenPort) continue;
    const requestedTls = body.tlsEnabled ?? existing?.tls?.enabled ?? false;
    if ((site.tls?.enabled === true) !== (requestedTls === true)) {
      throw new Error(`All sites on port ${listenPort} must use the same HTTP or HTTPS protocol`);
    }
    const overlap = site.hosts.filter((host) => hosts.includes(host) || host === '*' || hosts.includes('*'));
    if (overlap.length) {
      throw new Error(`Hostname sudah dipakai situs "${site.name}": ${overlap.join(', ')}`);
    }
  }

  return {
    name,
    hosts,
    upstream,
    listenPort,
    preserveHost: (body.preserveHost ?? existing?.preserveHost ?? true) !== false,
    websocket: (body.websocket ?? existing?.websocket ?? true) !== false,
    verifyTls: (body.verifyTls ?? existing?.verifyTls ?? false) === true,
    tls: existing?.tls || { enabled: false },
    wafEnabled: (body.wafEnabled ?? existing?.wafEnabled ?? true) !== false,
    enabled: (body.enabled ?? existing?.enabled ?? true) !== false,
    note: String(body.note ?? existing?.note ?? '').slice(0, 300),
  };
}

function certificatePaths(siteId) {
  if (!/^site_[a-f0-9]{8}$/.test(siteId)) throw new HttpError(400, 'Invalid site ID');
  return {
    cert: path.join(CERTIFICATES_DIR, `${siteId}.crt`),
    key: path.join(CERTIFICATES_DIR, `${siteId}.key`),
  };
}

function validateCertificatePair(certificatePem, privateKeyPem) {
  const certPem = String(certificatePem || '').trim();
  const keyPem = String(privateKeyPem || '').trim();
  if (!certPem || !keyPem) throw new HttpError(400, 'Certificate and private key are required');
  if (Buffer.byteLength(certPem) > 512 * 1024 || Buffer.byteLength(keyPem) > 128 * 1024) {
    throw new HttpError(413, 'Certificate or private key is too large');
  }
  let certificate;
  let privateKey;
  try {
    certificate = new crypto.X509Certificate(certPem);
  } catch {
    throw new HttpError(400, 'Invalid X.509 certificate PEM');
  }
  try {
    privateKey = crypto.createPrivateKey(keyPem);
  } catch {
    throw new HttpError(400, 'Invalid or encrypted private key PEM');
  }
  const certificatePublicKey = certificate.publicKey.export({ type: 'spki', format: 'der' });
  const privatePublicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  if (!certificatePublicKey.equals(privatePublicKey)) {
    throw new HttpError(400, 'The private key does not match the certificate');
  }
  const now = Date.now();
  const validFrom = Date.parse(certificate.validFrom);
  const validTo = Date.parse(certificate.validTo);
  if (!Number.isFinite(validFrom) || !Number.isFinite(validTo) || now < validFrom || now > validTo) {
    throw new HttpError(400, 'The certificate is not currently valid');
  }
  return {
    certPem: `${certPem}\n`,
    keyPem: `${keyPem}\n`,
    metadata: {
      enabled: true,
      subject: certificate.subject,
      issuer: certificate.issuer,
      validFrom: new Date(validFrom).toISOString(),
      validTo: new Date(validTo).toISOString(),
      fingerprint256: certificate.fingerprint256,
    },
  };
}

async function applySiteCertificate(siteId, body, existingTls = null) {
  const paths = certificatePaths(siteId);
  const files = [paths.cert, paths.key];
  const snap = await snapshot(files);
  const tlsRequested = body.tlsEnabled === undefined ? existingTls?.enabled === true : body.tlsEnabled === true;
  const hasNewPair = Boolean(String(body.certificatePem || '').trim() || String(body.privateKeyPem || '').trim());
  try {
    if (!tlsRequested) {
      for (const file of files) await fsp.unlink(file).catch((err) => { if (err.code !== 'ENOENT') throw err; });
      return { tls: { enabled: false }, snap };
    }
    if (!hasNewPair) {
      if (existingTls?.enabled !== true || !(await Promise.all(files.map(async (file) => {
        try { await fsp.access(file); return true; } catch { return false; }
      }))).every(Boolean)) {
        throw new HttpError(400, 'Upload or paste a certificate and matching private key');
      }
      return { tls: existingTls, snap };
    }
    const pair = validateCertificatePair(body.certificatePem, body.privateKeyPem);
    ensureDir(CERTIFICATES_DIR);
    await writeTextAtomic(paths.cert, pair.certPem);
    await writeTextAtomic(paths.key, pair.keyPem, { mode: 0o600 });
    await fsp.chmod(paths.cert, 0o644);
    await fsp.chmod(paths.key, 0o600);
    return { tls: pair.metadata, snap };
  } catch (err) {
    await restore(snap);
    throw err;
  }
}

function validateIpValue(value) {
  const text = String(value || '').trim();
  const v4 = text.match(IPV4);
  if (v4) {
    const octets = v4.slice(1, 5).map(Number);
    const prefix = v4[5] === undefined ? 32 : Number(v4[5]);
    if (octets.every((o) => o >= 0 && o <= 255) && prefix >= 0 && prefix <= 32) return text;
  }
  if (text.includes(':') && IPV6.test(text)) return text;
  throw new Error(`Alamat IP/CIDR tidak valid: ${text}`);
}

function validateExclusionInput(input) {
  const scope = input.scope;
  if (!['global', 'path', 'host', 'host_path'].includes(scope)) throw new Error('Scope exclusion tidak valid');
  const ruleIds = [...new Set((Array.isArray(input.ruleIds) ? input.ruleIds : String(input.ruleIds || '').split(/[\s,]+/))
    .map((v) => Number.parseInt(v, 10))
    .filter((v) => Number.isFinite(v) && v >= 1 && v <= 9_999_999))];
  if (!ruleIds.length) throw new Error('Minimal satu rule ID harus diisi');
  const match = String(input.match || '').trim();
  const host = String(input.host || '').trim().toLowerCase();
  if (scope !== 'global') {
    if (!match) throw new Error('Path/Host wajib diisi');
    if (/[\r\n"']/.test(match)) throw new Error('Path/Host mengandung karakter tidak valid');
    if ((scope === 'path' || scope === 'host_path') && !match.startsWith('/')) throw new Error('Path harus diawali dengan /');
  }
  if (scope === 'host_path') {
    if (!host) throw new Error('Host wajib diisi');
    if (/[\r\n"']/.test(host)) throw new Error('Host mengandung karakter tidak valid');
  }
  return { scope, ruleIds, match: scope === 'global' ? '' : match, host: scope === 'host_path' ? host : '' };
}

function modsecQuoted(value) {
  return String(value || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/[\r\n]/g, '');
}

function ruleIsEnabled(rule, state, excluded) {
  return !excluded.has(rule.id) && state.disabledRules.indexOf(rule.id) === -1;
}

function publicRule(rule, state, excluded) {
  return {
    id: rule.id,
    msg: rule.msg,
    severity: rule.severity,
    phase: rule.phase,
    tags: rule.tags,
    category: rule.category,
    paranoia: rule.paranoia,
    file: rule.file,
    line: rule.line,
    enabled: ruleIsEnabled(rule, state, excluded),
    reason: excluded.has(rule.id)
      ? state.disabledRules.includes(rule.id)
        ? 'disabled'
        : 'excluded'
      : 'enabled',
  };
}

async function rulesPayload(query, state) {
  const catalog = await getCatalog();
  const excluded = globalExcludedIds(state);
  const q = String(query.get('q') || '').trim().toLowerCase();
  const severity = String(query.get('severity') || '').trim().toUpperCase();
  const tag = String(query.get('tag') || '').trim().toLowerCase();
  const status = String(query.get('status') || '').trim().toLowerCase();
  const pl = Number.parseInt(query.get('pl') || '0', 10) || 0;
  const sort = String(query.get('sort') || 'id');
  const limit = Math.min(200, Math.max(1, Number.parseInt(query.get('limit') || '50', 10) || 50));
  const page = Math.max(1, Number.parseInt(query.get('page') || '1', 10) || 1);

  let rules = catalog.rules;
  if (severity) rules = rules.filter((rule) => rule.severity === severity);
  if (pl) rules = rules.filter((rule) => rule.paranoia === pl);
  if (tag) {
    rules = rules.filter(
      (rule) =>
        rule.category === tag ||
        rule.tags.some((t) => t.toLowerCase().includes(tag)) ||
        rule.msg.toLowerCase().includes(tag)
    );
  }
  if (q) {
    rules = rules.filter(
      (rule) =>
        String(rule.id).includes(q) ||
        rule.msg.toLowerCase().includes(q) ||
        rule.tags.some((t) => t.toLowerCase().includes(q))
    );
  }
  if (status === 'enabled' || status === 'disabled') {
    rules = rules.filter((rule) => {
      const enabled = ruleIsEnabled(rule, state, excluded);
      return status === 'enabled' ? enabled : !enabled;
    });
  }

  if (sort === 'severity') {
    const order = { CRITICAL: 0, ERROR: 1, WARNING: 2, NOTICE: 3, INFO: 4 };
    rules = [...rules].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9) || a.id - b.id);
  }

  const disabledCount = catalog.rules.filter((rule) => excluded.has(rule.id)).length;
  const pages = Math.max(1, Math.ceil(rules.length / limit));
  const safePage = Math.min(page, pages);
  const items = rules
    .slice((safePage - 1) * limit, safePage * limit)
    .map((rule) => publicRule(rule, state, excluded));

  const categories = [...new Set(catalog.rules.map((rule) => rule.category))].sort();

  return {
    items,
    total: rules.length,
    page: safePage,
    pages,
    limit,
    counts: {
      total: catalog.rules.length,
      enabled: catalog.rules.length - disabledCount,
      disabled: disabledCount,
    },
    categories,
    files: catalog.files,
  };
}

async function overviewPayload() {
  const state = await loadState();
  const excluded = globalExcludedIds(state);
  const { settings } = await loadRawSettings();
  const stats = audit.stats(24);
  const recent = audit.list({ limit: 8 });
  const catalog = await getCatalog();
  const dockerUp = await dockerAvailable();
  let container = null;
  let containerError = dockerError();
  if (dockerUp) {
    try {
      container = await inspectContainer();
    } catch (err) {
      containerError = err.message;
    }
  }
  const ruleStats = {
    total: catalog.rules.length,
    disabled: catalog.rules.filter((rule) => excluded.has(rule.id)).length,
    files: catalog.files.length,
  };

  return {
    version: OPENWAF_VERSION,
    waf: {
      container: WAF_CONTAINER,
      containerInfo: container,
      dockerAvailable: dockerUp,
      dockerError: containerError,
      online: Boolean(container?.running),
      engineMode: settings.engineMode,
      auditEngine: settings.auditEngine,
      url: WAF_URL,
    },
    crs: {
      version: settings.crsVersion,
      ...ruleStats,
      customRules: state.customRules.length,
      exclusions: state.exclusions.length,
      ipBlocks: state.ipBlocklist.length,
      ipAllows: state.ipAllowlist.length,
    },
    settings: {
      paranoia: settings.paranoia,
      inboundThreshold: settings.inboundThreshold,
      outboundThreshold: settings.outboundThreshold,
      allowedMethods: settings.allowedMethods,
    },
    reverseProxy: {
      defaultUpstream: state.reverseProxy.defaultUpstream,
      sites: state.reverseProxy.sites.length,
      enabledSites: state.reverseProxy.sites.filter((site) => site.enabled).length,
      generatedFile: SITES_FILE,
    },
    stats,
    recentEvents: recent.items,
    audit: audit.status(),
    defaultPassword: usingDefaultPassword(),
    timestamp: nowIso(),
  };
}

function validateSettingsPatch(body) {
  const patch = {};
  const has = (key) => Object.prototype.hasOwnProperty.call(body, key);

  if (has('engineMode')) {
    if (!ENGINE_MODES.includes(body.engineMode)) throw new Error('Engine mode tidak valid');
    patch.engineMode = body.engineMode;
  }
  if (has('auditEngine')) {
    if (!AUDIT_MODES.includes(body.auditEngine)) throw new Error('Audit engine tidak valid');
    patch.auditEngine = body.auditEngine;
  }
  if (has('requestBodyLimit')) {
    const num = Number(body.requestBodyLimit);
    if (!Number.isFinite(num) || num < 1024 || num > 1_073_741_824) {
      throw new Error('Request body limit harus antara 1024 dan 1073741824 byte');
    }
    patch.requestBodyLimit = Math.round(num);
  }
  if (has('responseBodyLimit')) {
    const num = Number(body.responseBodyLimit);
    if (!Number.isFinite(num) || num < 0 || num > 1_073_741_824) {
      throw new Error('Response body limit tidak valid');
    }
    patch.responseBodyLimit = Math.round(num);
  }
  if (has('paranoia')) {
    const num = Number(body.paranoia);
    if (![1, 2, 3, 4].includes(num)) throw new Error('Paranoia level harus 1-4');
    patch.paranoia = num;
  }
  if (has('detectionParanoia')) {
    const num = Number(body.detectionParanoia);
    if (![1, 2, 3, 4].includes(num)) throw new Error('Detection paranoia harus 1-4');
    patch.detectionParanoia = num;
  }
  for (const [key, label, min, max] of [
    ['inboundThreshold', 'Inbound threshold', 1, 10000],
    ['outboundThreshold', 'Outbound threshold', 1, 10000],
    ['reportingLevel', 'Reporting level', 0, 5],
    ['maxNumArgs', 'Max arguments', 1, 100000],
  ]) {
    if (has(key)) {
      const num = Number(body[key]);
      if (!Number.isFinite(num) || num < min || num > max) {
        throw new Error(`${label} harus antara ${min} dan ${max}`);
      }
      patch[key] = Math.round(num);
    }
  }
  if (has('paranoia') && has('detectionParanoia') && patch.detectionParanoia < patch.paranoia) {
    throw new Error('Detection paranoia tidak boleh lebih rendah dari blocking paranoia');
  }
  for (const [key, label] of [
    ['allowedMethods', 'Allowed methods'],
    ['allowedContentTypes', 'Allowed content types'],
    ['restrictedExtensions', 'Restricted extensions'],
  ]) {
    if (has(key)) {
      const value = String(body[key] || '').trim();
      if (!value) throw new Error(`${label} tidak boleh kosong`);
      if (/[\r\n"']/.test(value)) throw new Error(`${label} mengandung karakter tidak valid`);
      patch[key] = value;
    }
  }
  return patch;
}

async function saveSettings(body) {
  const patch = validateSettingsPatch(body);
  const snap = await snapshot([OVERRIDE_FILE, CRS_SETUP_FILE, ZZZ_FILE, BEFORE_FILE]);
  try {
    const { settings, crsContent, overrideContent } = await loadRawSettings();
    let nextCrs = crsContent;
    if (
      ['paranoia', 'detectionParanoia', 'inboundThreshold', 'outboundThreshold', 'reportingLevel', 'allowedMethods', 'maxNumArgs', 'allowedContentTypes', 'restrictedExtensions'].some(
        (key) => Object.prototype.hasOwnProperty.call(patch, key)
      )
    ) {
      nextCrs = applySettingsToCrs(crsContent, patch);
    }
    const merged = { ...settings, ...patch };
    const nextOverride = renderOverride(merged);

    if (nextCrs !== crsContent) await writeTextAtomic(CRS_SETUP_FILE, nextCrs);
    if (nextOverride !== overrideContent) await writeTextInPlace(OVERRIDE_FILE, nextOverride);

    const reload = await reloadWaf();
    if (!reload.ok) {
      await restore(snap);
      throw new HttpError(422, reload.message || 'Konfigurasi ditolak oleh ModSecurity/Nginx', {
        output: reload.output || '',
      });
    }
    const fresh = await loadRawSettings();
    return { settings: fresh.settings, reload };
  } catch (err) {
    if (!(err instanceof HttpError)) await restore(snap);
    throw err;
  }
}

const ROUTES = [];
function route(method, pattern, handler, { auth = true } = {}) {
  ROUTES.push({ method, pattern, handler, auth });
}

route(
  'GET',
  '/api/session',
  async (req, res) => {
    json(res, 200, {
      authenticated: Boolean(req.session),
      version: OPENWAF_VERSION,
      defaultPassword: usingDefaultPassword(),
    });
  },
  { auth: false }
);

route(
  'POST',
  '/api/login',
  async (req, res) => {
    const ip = clientIp(req);
    const limit = loginRateLimit(ip);
    if (!limit.allowed) {
      throw new HttpError(429, 'Terlalu banyak percobaan login. Coba lagi dalam 10 menit.');
    }
    const body = await readJson(req);
    if (!checkPassword(body.password)) {
      recordFailedLogin(ip);
      throw new HttpError(401, 'Password salah');
    }
    resetFailedLogins(ip);
    const session = issueSession();
    res.setHeader('Set-Cookie', session.cookie);
    json(res, 200, {
      ok: true,
      defaultPassword: usingDefaultPassword(),
      expiresAt: new Date(session.expiresAt).toISOString(),
    });
  },
  { auth: false }
);

route('POST', '/api/logout', async (req, res) => {
  res.setHeader('Set-Cookie', clearSessionCookie());
  json(res, 200, { ok: true });
});

route('GET', '/api/overview', async (req, res) => {
  json(res, 200, await overviewPayload());
});

route('GET', '/api/rules', async (req, res, { url }) => {
  const state = await loadState();
  json(res, 200, await rulesPayload(url.searchParams, state));
});

route('GET', '/api/rules/:id', async (req, res, { params }) => {
  const rule = await getRule(params.id);
  if (!rule) throw new HttpError(404, 'Rule tidak ditemukan');
  const state = await loadState();
  const excluded = globalExcludedIds(state);
  json(res, 200, {
    ...publicRule(rule, state, excluded),
    raw: rule.raw,
    tags: rule.tags,
  });
});

route('POST', '/api/rules/toggle', async (req, res) => {
  const body = await readJson(req);
  const ids = [...new Set((Array.isArray(body.ids) ? body.ids : [body.id]).map((v) => Number.parseInt(v, 10)).filter(Boolean))];
  if (!ids.length) throw new HttpError(400, 'Daftar rule ID kosong');
  if (ids.length > 5000) throw new HttpError(400, 'Maksimal 5000 rule per perubahan');
  const enabled = Boolean(body.enabled);

  const result = await mutateState(async (state) => {
    const set = new Set(state.disabledRules);
    for (const id of ids) {
      if (enabled) set.delete(id);
      else set.add(id);
    }
    state.disabledRules = [...set].sort((a, b) => a - b);
    return ids.length;
  });

  const commit = await commitState(result.state);
  json(res, 200, {
    ok: true,
    changed: ids.length,
    enabled,
    reload: commit.reload,
    counts: (await catalogStats(result.state, globalExcludedIds(result.state))),
  });
});

route('GET', '/api/events', async (req, res, { url }) => {
  const limit = Math.min(200, Math.max(1, Number.parseInt(url.searchParams.get('limit') || '50', 10) || 50));
  const offset = Math.max(0, Number.parseInt(url.searchParams.get('offset') || '0', 10) || 0);
  const data = audit.list({
    limit,
    offset,
    q: url.searchParams.get('q') || '',
    action: url.searchParams.get('action') || '',
    ip: url.searchParams.get('ip') || '',
    rule: url.searchParams.get('rule') || '',
    range: url.searchParams.get('range') || 'all',
  });
  json(res, 200, { ...data, status: audit.status() });
});

route('GET', '/api/events/:uid', async (req, res, { params }) => {
  const event = audit.get(params.uid);
  if (!event) throw new HttpError(404, 'Event tidak ditemukan');
  json(res, 200, event);
});

route('POST', '/api/events/:uid/path-action', async (req, res, { params }) => {
  const event = audit.get(params.uid);
  if (!event) throw new HttpError(404, 'Event tidak ditemukan');
  const body = await readJson(req);
  if (!['allow', 'block'].includes(body.action)) throw new HttpError(400, 'Aksi path harus allow atau block');
  const host = String(event.host || '').trim().toLowerCase();
  const requestPath = String(event.path || '').trim();
  if (!host || !requestPath.startsWith('/')) throw new HttpError(400, 'Event tidak memiliki host/path yang valid');

  let saved = null;
  const result = await mutateState(async (state) => {
    if (body.action === 'allow') {
      const ruleIds = [...new Set((event.rules || []).map((rule) => Number.parseInt(rule.id, 10)).filter(Boolean))];
      if (!ruleIds.length) throw new HttpError(400, 'Event tidak memiliki rule terpicu yang dapat dikecualikan');
      const existing = state.exclusions.find(
        (item) => item.scope === 'host_path' && item.host === host && item.match === requestPath
      );
      if (existing) {
        existing.ruleIds = [...new Set([...existing.ruleIds, ...ruleIds])].sort((a, b) => a - b);
        existing.enabled = true;
        existing.updatedAt = nowIso();
        saved = existing;
        return existing.id;
      }
      saved = {
        id: `exc_${crypto.randomBytes(4).toString('hex')}`,
        genId: allocateRuleId(state),
        scope: 'host_path',
        host,
        match: requestPath,
        ruleIds,
        note: `Audit event ${event.uniqueId || event.uid}: allow exact host + path`,
        enabled: true,
        createdAt: nowIso(),
      };
      state.exclusions.push(saved);
      return saved.id;
    }

    const existing = state.customRules.find(
      (rule) => rule.auditPathBlock?.host === host && rule.auditPathBlock?.path === requestPath
    );
    if (existing) {
      existing.enabled = true;
      existing.updatedAt = nowIso();
      saved = existing;
      return existing.id;
    }
    const id = allocateRuleId(state);
    const raw = `SecRule REQUEST_HEADERS:Host "@streq ${modsecQuoted(host)}" "id:${id},phase:1,deny,status:403,log,chain,msg:'AsekWAF: blocked exact host and path',severity:'CRITICAL',tag:'openwaf/audit-path-block'"\n SecRule REQUEST_FILENAME "@streq ${modsecQuoted(requestPath)}" "t:none"`;
    saved = {
      id,
      name: `Block ${host}${requestPath}`.slice(0, 120),
      enabled: true,
      phase: 1,
      severity: 'CRITICAL',
      action: 'deny',
      field: 'REQUEST_HEADERS:Host + REQUEST_FILENAME',
      operator: '@streq',
      pattern: `${host}${requestPath}`,
      status: 403,
      message: 'AsekWAF: blocked exact host and path',
      note: `Created from audit event ${event.uniqueId || event.uid}`,
      mode: 'raw',
      raw,
      auditPathBlock: { host, path: requestPath },
      createdAt: nowIso(),
    };
    state.customRules.push(saved);
    return saved.id;
  });
  const commit = await commitState(result.state);
  json(res, 200, { ok: true, action: body.action, item: saved, reload: commit.reload });
});

route('GET', '/api/stats', async (req, res, { url }) => {
  const hours = Math.min(24 * 30, Math.max(1, Number.parseInt(url.searchParams.get('hours') || '24', 10) || 24));
  json(res, 200, { ...audit.stats(hours), audit: audit.status() });
});

route('GET', '/api/stats/countries', async (req, res, { url }) => {
  const hours = Math.min(24 * 30, Math.max(1, Number.parseInt(url.searchParams.get('hours') || '24', 10) || 24));
  json(res, 200, await attackCountries(hours));
});

route('GET', '/api/custom-rules', async (req, res) => {
  const state = await loadState();
  json(res, 200, { items: state.customRules, nextId: state.nextRuleId });
});

route('POST', '/api/custom-rules', async (req, res) => {
  const body = await readJson(req);
  let created = null;
  const result = await mutateState(async (state) => {
    let id;
    let raw;
    if (body.mode === 'raw') {
      const match = String(body.raw || '').match(/\bid\s*:\s*'?(\d{7})/);
      if (!match) throw new HttpError(400, 'Raw rule harus memuat id 7 digit (contoh 9001234)');
      id = Number(match[1]);
      if (id < 9_000_000 || id > 9_999_999) {
        throw new HttpError(400, 'ID custom rule harus di rentang 9000000-9999999');
      }
      if (
        state.customRules.some((rule) => rule.id === id) ||
        state.exclusions.some((exc) => exc.genId === id)
      ) {
        throw new HttpError(409, `ID ${id} sudah dipakai`);
      }
      raw = validateRawRule(body.raw, id);
      state.nextRuleId = Math.max(state.nextRuleId, id + 1);
    } else {
      id = allocateRuleId(state);
      raw = buildCustomRule(body, id);
    }
    const phase = Number.parseInt(body.phase, 10) || 2;
    const entry = {
      id,
      name: String(body.name || `Custom rule ${id}`).slice(0, 120),
      enabled: body.enabled !== false,
      phase: Math.min(5, Math.max(1, phase)),
      severity: String(body.severity || 'CRITICAL').toUpperCase(),
      action: ['deny', 'pass', 'allow'].includes(body.action) ? body.action : 'deny',
      field: String(body.field || ''),
      operator: String(body.operator || ''),
      pattern: String(body.pattern || ''),
      status: Number.parseInt(body.status, 10) || 403,
      message: String(body.message || ''),
      note: String(body.note || ''),
      mode: body.mode === 'raw' ? 'raw' : 'builder',
      raw,
      createdAt: nowIso(),
    };
    state.customRules.push(entry);
    created = entry;
    return entry.id;
  });
  const commit = await commitState(result.state);
  json(res, 201, { ok: true, item: created, reload: commit.reload });
});

route('PUT', '/api/custom-rules/:id', async (req, res, { params }) => {
  const body = await readJson(req);
  const id = Number.parseInt(params.id, 10);
  let updated = null;
  const result = await mutateState(async (state) => {
    const rule = state.customRules.find((item) => item.id === id);
    if (!rule) throw new HttpError(404, 'Custom rule tidak ditemukan');

    if (body.mode === 'raw' && body.raw !== undefined) {
      rule.raw = validateRawRule(body.raw, id);
      rule.mode = 'raw';
    } else {
      const merged = { ...rule, ...body };
      if (
        body.field !== undefined ||
        body.operator !== undefined ||
        body.pattern !== undefined ||
        body.message !== undefined ||
        body.action !== undefined ||
        body.phase !== undefined ||
        body.status !== undefined ||
        body.severity !== undefined
      ) {
        rule.raw = buildCustomRule(merged, id);
        rule.mode = 'builder';
      }
    }

    if (body.name !== undefined) rule.name = String(body.name).slice(0, 120);
    if (body.enabled !== undefined) rule.enabled = Boolean(body.enabled);
    if (body.note !== undefined) rule.note = String(body.note);
    for (const key of ['phase', 'severity', 'field', 'operator', 'pattern', 'status', 'message']) {
      if (body[key] !== undefined) rule[key] = body[key];
    }
    if (body.action !== undefined) {
      rule.action = ['deny', 'pass', 'allow'].includes(body.action) ? body.action : 'deny';
    }
    rule.updatedAt = nowIso();
    updated = rule;
    return id;
  });
  const commit = await commitState(result.state);
  json(res, 200, { ok: true, item: updated, reload: commit.reload });
});

route('DELETE', '/api/custom-rules/:id', async (req, res, { params }) => {
  const id = Number.parseInt(params.id, 10);
  const result = await mutateState(async (state) => {
    const index = state.customRules.findIndex((item) => item.id === id);
    if (index === -1) throw new HttpError(404, 'Custom rule tidak ditemukan');
    state.customRules.splice(index, 1);
    return id;
  });
  const commit = await commitState(result.state);
  json(res, 200, { ok: true, deleted: id, reload: commit.reload });
});

route('GET', '/api/exclusions', async (req, res) => {
  const state = await loadState();
  json(res, 200, { items: state.exclusions });
});

route('POST', '/api/exclusions', async (req, res) => {
  const body = await readJson(req);
  let created = null;
  const result = await mutateState(async (state) => {
    const input = validateExclusionInput(body);
    const genId = allocateRuleId(state);
    const entry = {
      id: `exc_${crypto.randomBytes(4).toString('hex')}`,
      genId,
      note: String(body.note || '').slice(0, 300),
      enabled: body.enabled !== false,
      ...input,
      createdAt: nowIso(),
    };
    state.exclusions.push(entry);
    created = entry;
    return entry.id;
  });
  const commit = await commitState(result.state);
  json(res, 201, { ok: true, item: created, reload: commit.reload });
});

route('PUT', '/api/exclusions/:id', async (req, res, { params }) => {
  const body = await readJson(req);
  let updated = null;
  const result = await mutateState(async (state) => {
    const entry = state.exclusions.find((item) => item.id === params.id);
    if (!entry) throw new HttpError(404, 'Exclusion tidak ditemukan');
    const merged = {
      ...entry,
      scope: body.scope ?? entry.scope,
      match: body.match ?? entry.match,
      host: body.host ?? entry.host,
      ruleIds: body.ruleIds ?? entry.ruleIds,
    };
    const input = validateExclusionInput(merged);
    Object.assign(entry, input);
    if (body.note !== undefined) entry.note = String(body.note).slice(0, 300);
    if (body.enabled !== undefined) entry.enabled = Boolean(body.enabled);
    entry.updatedAt = nowIso();
    updated = entry;
    return entry.id;
  });
  const commit = await commitState(result.state);
  json(res, 200, { ok: true, item: updated, reload: commit.reload });
});

route('DELETE', '/api/exclusions/:id', async (req, res, { params }) => {
  const result = await mutateState(async (state) => {
    const index = state.exclusions.findIndex((item) => item.id === params.id);
    if (index === -1) throw new HttpError(404, 'Exclusion tidak ditemukan');
    state.exclusions.splice(index, 1);
    return params.id;
  });
  const commit = await commitState(result.state);
  json(res, 200, { ok: true, deleted: params.id, reload: commit.reload });
});

route('GET', '/api/ip-lists', async (req, res) => {
  const state = await loadState();
  json(res, 200, {
    allow: state.ipAllowlist,
    block: state.ipBlocklist,
    counts: { allow: state.ipAllowlist.length, block: state.ipBlocklist.length },
  });
});

route('POST', '/api/ip-lists', async (req, res) => {
  const body = await readJson(req);
  const type = body.type === 'allow' ? 'allow' : 'block';
  let value;
  try {
    value = validateIpValue(body.value);
  } catch (err) {
    throw new HttpError(400, err.message);
  }
  let created = null;
  const result = await mutateState(async (state) => {
    const list = type === 'allow' ? state.ipAllowlist : state.ipBlocklist;
    if (list.length >= 500) throw new HttpError(400, 'Maksimal 500 entri per daftar');
    if (list.some((item) => item.value === value)) throw new HttpError(409, 'Entri sudah ada');
    const entry = {
      id: `ip_${crypto.randomBytes(4).toString('hex')}`,
      value,
      note: String(body.note || '').slice(0, 200),
      enabled: true,
      createdAt: nowIso(),
    };
    list.push(entry);
    created = entry;
    return entry.id;
  });
  const commit = await commitState(result.state);
  json(res, 201, { ok: true, item: created, reload: commit.reload });
});

route('POST', '/api/ip-lists/quick-action', async (req, res) => {
  const body = await readJson(req);
  if (!['allow', 'block'].includes(body.type)) {
    throw new HttpError(400, 'Aksi IP harus allow atau block');
  }
  let value;
  try {
    value = validateIpValue(body.value);
  } catch (err) {
    throw new HttpError(400, err.message);
  }
  if (!isPublicThreatEntry(value)) {
    throw new HttpError(400, 'IP lokal, privat, loopback, dan reserved tidak dapat diubah dari Audit Events');
  }

  let saved = null;
  const result = await mutateState(async (state) => {
    const targetKey = body.type === 'allow' ? 'ipAllowlist' : 'ipBlocklist';
    const oppositeKey = body.type === 'allow' ? 'ipBlocklist' : 'ipAllowlist';
    state[oppositeKey] = state[oppositeKey].filter((item) => item.value !== value);

    const existing = state[targetKey].find((item) => item.value === value);
    if (existing) {
      existing.enabled = true;
      existing.note = String(body.note || existing.note || '').slice(0, 200);
      saved = existing;
      return existing.id;
    }
    if (state[targetKey].length >= 500) throw new HttpError(400, 'Maksimal 500 entri per daftar');
    saved = {
      id: `ip_${crypto.randomBytes(4).toString('hex')}`,
      value,
      note: String(body.note || '').slice(0, 200),
      enabled: true,
      createdAt: nowIso(),
    };
    state[targetKey].push(saved);
    return saved.id;
  });
  const commit = await commitState(result.state);
  json(res, 200, { ok: true, item: saved, type: body.type, reload: commit.reload });
});

route('DELETE', '/api/ip-lists/:id', async (req, res, { params }) => {
  const result = await mutateState(async (state) => {
    const before = state.ipAllowlist.length + state.ipBlocklist.length;
    state.ipAllowlist = state.ipAllowlist.filter((item) => item.id !== params.id);
    state.ipBlocklist = state.ipBlocklist.filter((item) => item.id !== params.id);
    if (state.ipAllowlist.length + state.ipBlocklist.length === before) {
      throw new HttpError(404, 'Entri tidak ditemukan');
    }
    return params.id;
  });
  const commit = await commitState(result.state);
  json(res, 200, { ok: true, deleted: params.id, reload: commit.reload });
});

route('GET', '/api/security-controls', async (req, res) => {
  const state = await loadState();
  json(res, 200, {
    rateLimit: state.rateLimit,
    threatIntel: state.threatIntel,
    auditRetention: state.auditRetention,
    errorPages: state.errorPages,
    crsUpdate: state.crsUpdate,
    cveRuleFeeds: state.cveRuleFeeds,
    threatSources: Object.entries(THREAT_SOURCES).map(([id, source]) => ({ id, ...source })),
  });
});

route('PUT', '/api/security-controls/audit-retention', async (req, res) => {
  const body = await readJson(req);
  const days = Number.parseInt(body.days, 10);
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    throw new HttpError(400, 'Retensi audit log harus antara 1 dan 3650 hari');
  }
  const result = await mutateState(async (state) => {
    state.auditRetention = { ...state.auditRetention, enabled: body.enabled !== false, days };
    return state.auditRetention;
  });
  json(res, 200, { ok: true, auditRetention: result.state.auditRetention });
});

route('PUT', '/api/security-controls/error-pages', async (req, res) => {
  const body = await readJson(req);
  const brand = String(body.brand || '').trim();
  const accent = String(body.accent || '').trim();
  const supportText = String(body.supportText || '').trim();
  const language = String(body.language || 'en');
  if (!brand || brand.length > 80) throw new HttpError(400, 'Nama brand wajib diisi, maksimal 80 karakter');
  if (!/^#[0-9a-f]{6}$/i.test(accent)) throw new HttpError(400, 'Warna aksen harus berupa hex, contoh #2dd4bf');
  if (supportText.length > 300) throw new HttpError(400, 'Teks bantuan maksimal 300 karakter');
  if (!['en', 'id', 'zh', 'ar', 'ja'].includes(language)) throw new HttpError(400, 'Bahasa halaman error tidak valid');
  const pages = {};
  for (const code of [400, 403, 404, 429, 500, 502, 503, 504]) {
    const input = body.pages?.[code] || body.pages?.[String(code)] || {};
    const title = String(input.title || '').trim();
    const message = String(input.message || '').trim();
    if (!title || title.length > 100) throw new HttpError(400, `Judul halaman ${code} wajib diisi, maksimal 100 karakter`);
    if (!message || message.length > 500) throw new HttpError(400, `Pesan halaman ${code} wajib diisi, maksimal 500 karakter`);
    pages[code] = { title, message };
  }
  const result = await mutateState(async (state) => {
    state.errorPages = { enabled: body.enabled !== false, language, brand, accent, supportText, pages };
    return state.errorPages;
  });
  const commit = await commitState(result.state);
  json(res, 200, { ok: true, errorPages: commit.state.errorPages, reload: commit.reload });
});

route('POST', '/api/security-controls/audit-retention/prune', async (req, res) => {
  const state = await loadState();
  const result = await pruneAuditLog(state.auditRetention);
  json(res, 200, { ok: true, result });
});

route('PUT', '/api/security-controls/rate-limit', async (req, res) => {
  const body = await readJson(req);
  const requestsPerMinute = Number.parseInt(body.requestsPerMinute, 10);
  const burst = Number.parseInt(body.burst, 10);
  if (!Number.isInteger(requestsPerMinute) || requestsPerMinute < 1 || requestsPerMinute > 100000) {
    throw new HttpError(400, 'Request per menit harus antara 1 dan 100000');
  }
  if (!Number.isInteger(burst) || burst < 0 || burst > 100000) {
    throw new HttpError(400, 'Burst harus antara 0 dan 100000');
  }
  const result = await mutateState(async (state) => {
    state.rateLimit = {
      enabled: body.enabled === true,
      requestsPerMinute,
      burst,
      nodelay: body.nodelay !== false,
    };
    return state.rateLimit;
  });
  const commit = await commitState(result.state);
  json(res, 200, { ok: true, rateLimit: commit.state.rateLimit, reload: commit.reload });
});

route('PUT', '/api/security-controls/threat-intel', async (req, res) => {
  const body = await readJson(req);
  const sources = [...new Set((Array.isArray(body.sources) ? body.sources : []).map(String))]
    .filter((id) => THREAT_SOURCES[id]);
  if (!sources.length) throw new HttpError(400, 'Pilih minimal satu sumber threat intelligence');
  const refreshHours = Number.parseInt(body.refreshHours, 10);
  if (!Number.isInteger(refreshHours) || refreshHours < 1 || refreshHours > 720) {
    throw new HttpError(400, 'Interval refresh harus antara 1 dan 720 jam');
  }
  const result = await mutateState(async (state) => {
    state.threatIntel = {
      ...state.threatIntel,
      enabled: body.enabled === true,
      sources,
      refreshHours,
    };
    return state.threatIntel;
  });
  const commit = await commitState(result.state);
  json(res, 200, { ok: true, threatIntel: commit.state.threatIntel, reload: commit.reload });
});

route('POST', '/api/security-controls/threat-intel/sync', async (req, res) => {
  const { fetched, commit } = await syncThreatIntel();
  json(res, 200, { ok: true, threatIntel: commit.state.threatIntel, warnings: fetched.errors, reload: commit.reload });
});

route('GET', '/api/proxy', async (req, res) => {
  const state = await loadState();
  const { settings } = await loadRawSettings();
  json(res, 200, {
    ...state.reverseProxy,
    listenPort: 8080,
    publicPortRange: { min: 1, max: 65535, reserved: [8081, 8443, 18080] },
    tlsListenPort: 8443,
    wafEngine: settings.engineMode,
    wafProtectedSites: state.reverseProxy.sites.filter((site) => site.enabled && site.wafEnabled).length,
    generatedFile: SITES_FILE,
    upstreamFile: DEFAULT_UPSTREAM_FILE,
  });
});

route('POST', '/api/proxy/diagnostics', async (req, res) => {
  const state = await loadState();
  const { settings } = await loadRawSettings();
  const checks = [];
  const targets = [
    ...(state.reverseProxy.fallbackMode === 'offline' ? [] : [{ name: 'Upstream default', host: '' }]),
    ...state.reverseProxy.sites
      .filter((site) => site.enabled)
      .slice(0, 20)
      .map((site) => ({ name: site.name, host: site.hosts[0] === '*' ? '' : site.hosts[0] || '', port: site.listenPort || 8080, wafEnabled: site.wafEnabled })),
  ];
  for (const target of targets) {
    try {
      const targetUrl = target.port && target.port !== 8080
        ? `${new URL(WAF_URL).protocol}//${new URL(WAF_URL).hostname}:${target.port}/healthz`
        : `${WAF_URL}/healthz`;
      const response = await fetch(targetUrl, {
        headers: target.host ? { Host: target.host } : {},
        redirect: 'manual',
        signal: AbortSignal.timeout(5000),
      });
      checks.push({ ...target, ok: response.ok, status: response.status });
    } catch (err) {
      checks.push({ ...target, ok: false, status: 0, error: err.message });
    }
  }
  json(res, 200, {
    ok: checks.every((check) => check.ok),
    engineMode: settings.engineMode,
    checks,
    note: 'Health check memverifikasi listener dan pemilihan Host. Gunakan Test Console dengan hostname untuk menguji rule WAF dan upstream aplikasi.',
  });
});

route('PUT', '/api/proxy/default', async (req, res) => {
  const body = await readJson(req);
  const mode = body.mode === 'forward' ? 'forward' : 'offline';
  const current = (await loadState()).reverseProxy.defaultUpstream;
  const upstream = validateUpstream(body.upstream || current);
  const preserveHost = body.preserveHost !== false;
  const result = await mutateState(async (state) => {
    state.reverseProxy.fallbackMode = mode;
    state.reverseProxy.defaultUpstream = upstream;
    state.reverseProxy.defaultPreserveHost = preserveHost;
    return { mode, upstream, preserveHost };
  });
  const commit = await commitState(result.state);
  json(res, 200, { ok: true, ...result.result, reload: commit.reload });
});

route('POST', '/api/proxy/sites', async (req, res) => {
  const body = await readJson(req);
  const siteId = `site_${crypto.randomBytes(4).toString('hex')}`;
  const certificate = await applySiteCertificate(siteId, body);
  let created = null;
  try {
    const result = await mutateState(async (state) => {
      const input = validateSite(body, state);
      const site = { id: siteId, ...input, tls: certificate.tls, createdAt: nowIso() };
      state.reverseProxy.sites.push(site);
      created = site;
      return site.id;
    });
    const commit = await commitState(result.state);
    json(res, 201, { ok: true, item: created, reload: commit.reload });
  } catch (err) {
    await restore(certificate.snap);
    throw err;
  }
});

route('PUT', '/api/proxy/sites/:id', async (req, res, { params }) => {
  const body = await readJson(req);
  const currentState = await loadState();
  const currentSite = currentState.reverseProxy.sites.find((item) => item.id === params.id);
  if (!currentSite) throw new HttpError(404, 'Reverse proxy site not found');
  const certificate = await applySiteCertificate(params.id, body, currentSite.tls);
  let updated = null;
  try {
    const result = await mutateState(async (state) => {
      const site = state.reverseProxy.sites.find((item) => item.id === params.id);
      if (!site) throw new HttpError(404, 'Reverse proxy site not found');
      Object.assign(site, validateSite(body, state, site), { tls: certificate.tls });
      site.updatedAt = nowIso();
      updated = site;
      return site.id;
    });
    const commit = await commitState(result.state);
    json(res, 200, { ok: true, item: updated, reload: commit.reload });
  } catch (err) {
    await restore(certificate.snap);
    throw err;
  }
});

route('DELETE', '/api/proxy/sites/:id', async (req, res, { params }) => {
  const paths = certificatePaths(params.id);
  const certSnap = await snapshot([paths.cert, paths.key]);
  try {
    await fsp.unlink(paths.cert).catch((err) => { if (err.code !== 'ENOENT') throw err; });
    await fsp.unlink(paths.key).catch((err) => { if (err.code !== 'ENOENT') throw err; });
    const result = await mutateState(async (state) => {
      const index = state.reverseProxy.sites.findIndex((item) => item.id === params.id);
      if (index === -1) throw new HttpError(404, 'Reverse proxy site not found');
      state.reverseProxy.sites.splice(index, 1);
      return params.id;
    });
    const commit = await commitState(result.state);
    json(res, 200, { ok: true, deleted: params.id, reload: commit.reload });
  } catch (err) {
    await restore(certSnap);
    throw err;
  }
});

route('GET', '/api/settings', async (req, res) => {
  const { settings } = await loadRawSettings();
  const dockerUp = await dockerAvailable();
  let container = null;
  if (dockerUp) {
    try {
      container = await inspectContainer();
    } catch {
      container = null;
    }
  }
  json(res, 200, {
    settings,
    dockerAvailable: dockerUp,
    dockerError: dockerError(),
    container,
    paths: { config: CONFIG_DIR, crs: CRS_DIR, auditLog: AUDIT_LOG, nginx: NGINX_DIR },
  });
});

route('PUT', '/api/settings', async (req, res) => {
  const body = await readJson(req);
  const result = await saveSettings(body);
  json(res, 200, { ok: true, ...result });
});

async function syncCveRuleFeeds() {
  const state = await loadState();
  if (!state.cveRuleFeeds.enabled) return { state, count: state.cveRuleFeeds.rules.length, skipped: true };
  const collected = [];
  try {
    for (const source of state.cveRuleFeeds.sources) {
      const url = new URL(source);
      if (url.protocol !== 'https:' || url.username || url.password) throw new Error(`Only credential-free HTTPS feed URLs are allowed: ${source}`);
      const response = await fetch(url, { headers: { Accept: 'application/json', 'User-Agent': `AsekWAF/${OPENWAF_VERSION}` }, signal: AbortSignal.timeout(12_000), redirect: 'error' });
      if (!response.ok) throw new Error(`${url.hostname}: HTTP ${response.status}`);
      const text = await response.text();
      if (Buffer.byteLength(text) > 2_000_000) throw new Error(`${url.hostname}: feed exceeds 2 MB`);
      const feed = JSON.parse(text);
      if (!Array.isArray(feed.rules) || feed.rules.length > 500) throw new Error(`${url.hostname}: invalid rules array`);
      for (const item of feed.rules) {
        const id = Number(item.id);
        if (!Number.isInteger(id) || id < 9_900_000 || id > 9_999_999) throw new Error(`${url.hostname}: rule IDs must be 9900000-9999999`);
        const raw = validateRawRule(String(item.raw || ''), id);
        collected.push({ id, name: String(item.name || `CVE rule ${id}`).slice(0, 120), raw, enabled: item.enabled !== false, cves: Array.isArray(item.cves) ? item.cves.map(String).slice(0, 20) : [], source: url.origin + url.pathname });
      }
    }
    const ids = new Set();
    for (const rule of collected) {
      if (ids.has(rule.id) || state.customRules.some((item) => item.id === rule.id)) throw new Error(`Duplicate rule ID ${rule.id}`);
      ids.add(rule.id);
    }
    state.cveRuleFeeds.rules = collected;
    state.cveRuleFeeds.lastSync = nowIso();
    state.cveRuleFeeds.lastError = null;
    const commit = await commitState(state);
    return { state: commit.state, count: collected.length, reload: commit.reload };
  } catch (err) {
    state.cveRuleFeeds.lastError = err.message;
    await saveState(state);
    throw err;
  }
}

route('PUT', '/api/cve-rule-feeds', async (req, res) => {
  const body = await readJson(req);
  const sources = [...new Set(String(body.sources || '').split(/\r?\n/).map((v) => v.trim()).filter(Boolean))];
  if (sources.length > 10) throw new HttpError(400, 'Maximum 10 feed URLs');
  for (const source of sources) { const url = new URL(source); if (url.protocol !== 'https:' || url.username || url.password) throw new HttpError(400, 'Feed URLs must use HTTPS without embedded credentials'); }
  const result = await mutateState(async (state) => { state.cveRuleFeeds.enabled = body.enabled === true; state.cveRuleFeeds.autoSync = body.autoSync !== false; state.cveRuleFeeds.sources = sources; });
  const saved = await saveState(result.state);
  json(res, 200, { ok: true, cveRuleFeeds: saved.cveRuleFeeds });
});

route('POST', '/api/cve-rule-feeds/sync', async (req, res) => {
  try { json(res, 200, { ok: true, ...(await syncCveRuleFeeds()) }); }
  catch (err) { throw new HttpError(502, `CVE rule feed sync failed: ${err.message}`); }
});

route('GET', '/api/config/export', async (req, res) => {
  const state = await loadState();
  const { settings } = await loadRawSettings();
  const reverseProxy = {
    ...state.reverseProxy,
    // Private keys are deliberately never exported. Imported sites start as HTTP
    // until an administrator installs their certificate on the destination host.
    sites: state.reverseProxy.sites.map((site) => ({ ...site, tls: { enabled: false } })),
  };
  json(res, 200, { format: 'asekwaf-config', version: 1, exportedAt: nowIso(), reverseProxy, settings, rateLimit: state.rateLimit, threatIntel: { ...state.threatIntel, count: 0, sourceCounts: {}, lastSync: null, lastError: null }, auditRetention: state.auditRetention, errorPages: state.errorPages, cveRuleFeeds: { ...state.cveRuleFeeds, rules: [], lastSync: null, lastError: null } });
});

route('POST', '/api/config/import', async (req, res) => {
  const body = await readJson(req, 3_000_000);
  if (body.format !== 'asekwaf-config' || body.version !== 1) throw new HttpError(400, 'Unsupported AsekWAF configuration file');
  if (body.settings) await saveSettings(body.settings);
  const result = await mutateState(async (state) => {
    for (const key of ['reverseProxy', 'rateLimit', 'threatIntel', 'auditRetention', 'errorPages', 'cveRuleFeeds']) if (body[key] && typeof body[key] === 'object') state[key] = body[key];
    if (body.reverseProxy?.sites) {
      state.reverseProxy.sites = state.reverseProxy.sites.map((site) => ({ ...site, tls: { enabled: false } }));
    }
  });
  const commit = await commitState(result.state);
  json(res, 200, { ok: true, reload: commit.reload });
});

route('GET', '/api/crs/update', async (req, res) => {
  const { settings } = await loadRawSettings();
  const force = req.url?.includes('force=1');
  try {
    const info = await checkForUpdate(settings.crsVersion, force);
    const result = await mutateState(async (state) => {
      state.crsUpdate = { ...info, lastError: null };
      return state.crsUpdate;
    });
    await saveState(result.state);
    if (result.state.cveRuleFeeds?.enabled && result.state.cveRuleFeeds?.autoSync) await syncCveRuleFeeds().catch((feedErr) => log('CVE rule feed sync failed:', feedErr.message));
    json(res, 200, info);
  } catch (err) {
    const state = await loadState();
    if (state.crsUpdate?.latestVersion) {
      state.crsUpdate.lastError = err.message;
      await saveState(state);
      json(res, 200, { ...state.crsUpdate, currentVersion: settings.crsVersion, stale: true, error: err.message });
      return;
    }
    throw new HttpError(502, `Gagal memeriksa update CRS: ${err.message}`);
  }
});

let crsUpdateRunning = false;
route('POST', '/api/crs/update', async (req, res) => {
  if (crsUpdateRunning) throw new HttpError(409, 'Update CRS sedang berjalan');
  crsUpdateRunning = true;
  let release = null;
  const backupDir = path.join(path.dirname(CRS_DIR), `.openwaf-crs-backup-${Date.now()}`);
  try {
    const { settings, crsContent } = await loadRawSettings();
    const info = await checkForUpdate(settings.crsVersion, true);
    if (!info.available) {
      json(res, 200, { ok: true, updated: false, message: 'CRS sudah versi terbaru.', ...info });
      return;
    }
    release = await downloadCrsRelease(info.release.tag);
    await fsp.cp(CRS_DIR, backupDir, { recursive: true, force: true });
    await fsp.rm(CRS_RULES_DIR, { recursive: true, force: true });
    await fsp.cp(release.rulesDir, CRS_RULES_DIR, { recursive: true });
    const freshSetup = await fsp.readFile(release.setupExample, 'utf8');
    const tunedSetup = applySettingsToCrs(freshSetup, settings);
    await writeTextAtomic(CRS_SETUP_FILE, tunedSetup.replace(/OWASP\s+CRS\s+ver\.?\s*[0-9][\w.-]*/i, `OWASP CRS ver. ${release.version}`));
    const state = await loadState();
    await writeGeneratedFiles(state);
    const reload = await reloadWaf();
    if (!reload.ok) throw new HttpError(422, 'CRS baru gagal divalidasi; versi lama dipulihkan.', { output: reload.output });
    await fsp.rm(backupDir, { recursive: true, force: true });
    const checkedAt = nowIso();
    state.crsUpdate = {
      currentVersion: release.version,
      latestVersion: release.version,
      available: false,
      upToDate: true,
      checkedAt,
      release: info.release,
      lastError: null,
    };
    await saveState(state);
    if (state.cveRuleFeeds?.enabled && state.cveRuleFeeds?.autoSync) await syncCveRuleFeeds().catch((feedErr) => log('CVE rule feed sync after CRS update failed:', feedErr.message));
    json(res, 200, { ok: true, updated: true, from: settings.crsVersion, to: release.version, reload });
  } catch (err) {
    try {
      await fsp.access(backupDir);
      await fsp.rm(CRS_DIR, { recursive: true, force: true });
      await fsp.cp(backupDir, CRS_DIR, { recursive: true });
      await fsp.rm(backupDir, { recursive: true, force: true });
      await reloadWaf();
    } catch {
      /* backup belum dibuat atau restore gagal; error asli tetap dilaporkan */
    }
    throw err;
  } finally {
    crsUpdateRunning = false;
    if (release) await release.cleanup();
  }
});

route('GET', '/api/system', async (req, res) => {
  const dockerUp = await dockerAvailable();
  let container = null;
  let logs = null;
  if (dockerUp) {
    try {
      container = await inspectContainer();
      const logResult = await containerLogs(WAF_CONTAINER, 120);
      logs = logResult.ok ? truncate(logResult.output, 20000) : null;
    } catch (err) {
      container = { error: err.message };
    }
  }
  const { settings } = await loadRawSettings();
  json(res, 200, {
    version: OPENWAF_VERSION,
    node: process.version,
    uptime: Math.round(process.uptime()),
    docker: { available: dockerUp, error: dockerError(), container: WAF_CONTAINER },
    container,
    logs,
    settings,
    audit: audit.status(),
    paths: { config: CONFIG_DIR, crs: CRS_DIR, auditLog: AUDIT_LOG, state: STATE_FILE },
    defaultPassword: usingDefaultPassword(),
  });
});

route('POST', '/api/system/reload', async (req, res) => {
  const result = await reloadWaf();
  if (!result.ok) throw new HttpError(422, result.message, { output: result.output });
  json(res, 200, { ok: true, ...result });
});

route('POST', '/api/system/restart', async (req, res) => {
  const result = await restartWaf();
  if (!result.ok) throw new HttpError(422, result.message);
  json(res, 200, { ok: true, ...result });
});

route('GET', '/api/system/files', async (req, res) => {
  const [setup, override, zzz, before, defaultUpstream, sites, rateLimitZone, rateLimitLocation] = await Promise.all([
    readText(CRS_SETUP_FILE, ''),
    readText(OVERRIDE_FILE, ''),
    readText(ZZZ_FILE, ''),
    readText(BEFORE_FILE, ''),
    readText(DEFAULT_UPSTREAM_FILE, ''),
    readText(SITES_FILE, ''),
    readText(RATE_LIMIT_ZONE_FILE, ''),
    readText(RATE_LIMIT_LOCATION_FILE, ''),
  ]);
  json(res, 200, { setup, override, zzz, before, defaultUpstream, sites, rateLimitZone, rateLimitLocation });
});

route('POST', '/api/test', async (req, res) => {
  const body = await readJson(req);
  const method = String(body.method || 'GET').toUpperCase();
  const allowed = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
  if (!allowed.includes(method)) throw new HttpError(400, 'Method tidak didukung');
  let target = String(body.path || '/');
  if (!target.startsWith('/')) target = `/${target}`;
  if (target.startsWith('//')) throw new HttpError(400, 'Path tidak valid');

  const marker = crypto.randomUUID();
  const headers = { 'X-AsekWAF-Test': marker, 'User-Agent': 'AsekWAF-TestConsole/1.0' };
  const testHost = String(body.host || '').trim().toLowerCase();
  if (testHost) {
    if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(testHost)) {
      throw new HttpError(400, 'Hostname pengujian tidak valid');
    }
    headers.Host = testHost;
  }
  if (body.headers && typeof body.headers === 'object') {
    for (const [key, value] of Object.entries(body.headers).slice(0, 30)) {
      const name = String(key).trim();
      if (!/^[A-Za-z0-9-]+$/.test(name)) continue;
      if (/^(host|content-length|connection|x-openwaf-test)$/i.test(name)) continue;
      headers[name] = String(value);
    }
  }

  const start = Date.now();
  let response = null;
  let error = null;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);
    const proxied = await fetch(`${WAF_URL}${target}`, {
      method,
      headers,
      body: ['GET', 'HEAD'].includes(method) ? undefined : String(body.body || ''),
      redirect: 'manual',
      signal: controller.signal,
    });
    clearTimeout(timeout);
    const text = await proxied.text();
    const responseHeaders = {};
    for (const [key, value] of proxied.headers.entries()) responseHeaders[key] = value;
    response = {
      status: proxied.status,
      statusText: proxied.statusText,
      headers: responseHeaders,
      body: truncate(text, 8000),
    };
  } catch (err) {
    error = err.name === 'AbortError' ? 'Request timeout (12s)' : err.message;
  }
  const duration = Date.now() - start;

  let matches = [];
  if (!error) {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, attempt === 0 ? 250 : 500));
      try {
        await audit.poll(false);
      } catch {
        /* ignore */
      }
      matches = audit.findByMarker(marker, start - 60_000);
      if (matches.length) break;
    }
  }

  const event = matches[0] || null;
  json(res, 200, {
    ok: !error,
    error,
    marker,
    durationMs: duration,
    request: { method, path: target, host: testHost || null, headers, body: truncate(body.body || '', 4000) },
    response,
    audit: event
      ? {
          found: true,
          uid: event.uid,
          blocked: event.blocked,
          status: event.status,
          score: event.score,
          rules: event.rules,
          timestamp: event.ts,
        }
      : { found: false, note: 'Tidak ada audit event. Pastikan audit engine aktif dan request menghasilkan event.' },
  });
});

function matchRoute(method, pathname) {
  for (const item of ROUTES) {
    if (item.method !== method) continue;
    const keys = [];
    const pattern = item.pattern.replace(/:([A-Za-z0-9_]+)/g, (_, key) => {
      keys.push(key);
      return '([^/]+)';
    });
    const re = new RegExp(`^${pattern}$`);
    const match = pathname.match(re);
    if (!match) continue;
    const params = {};
    keys.forEach((key, index) => {
      params[key] = decodeURIComponent(match[index + 1]);
    });
    return { handler: item.handler, auth: item.auth, params };
  }
  return null;
}

async function serveStatic(req, res, pathname) {
  if (pathname === '/vendor/adminlte/adminlte.min.css') {
    try {
      const stat = await fsp.stat(ADMINLTE_CSS);
      res.writeHead(200, {
        'Content-Type': 'text/css; charset=utf-8',
        'Content-Length': stat.size,
        'Cache-Control': 'public, max-age=86400',
      });
      createReadStream(ADMINLTE_CSS).pipe(res);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('AdminLTE asset is not installed');
    }
    return;
  }
  const name = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  if (name.includes('..') || name.includes('\0')) {
    res.writeHead(400);
    res.end('Bad request');
    return;
  }
  const file = path.join(PUBLIC_DIR, name);
  try {
    const data = await fsp.readFile(file);
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Content-Length': data.length,
      'Cache-Control': ['.html', '.js', '.css'].includes(ext) ? 'no-cache, must-revalidate' : 'public, max-age=300',
    });
    res.end(data);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
  }
}

function isMutating(method) {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
}

function csrfOk(req) {
  if (req.headers['x-requested-with'] !== 'openwaf') return false;
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    return parsed.host === req.headers.host;
  } catch {
    return false;
  }
}

const server = http.createServer(async (req, res) => {
  securityHeaders(res);
  let url;
  try {
    url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  } catch {
    json(res, 400, { error: 'URL tidak valid' });
    return;
  }
  const pathname = url.pathname;

  if (pathname === '/healthz') {
    json(res, 200, { ok: true, version: OPENWAF_VERSION });
    return;
  }

  if (pathname.startsWith('/api/')) {
    try {
      const cookies = parseCookies(req.headers.cookie || '');
      req.session = verifySession(cookies[COOKIE_NAME]);
      const matched = matchRoute(req.method, pathname);
      if (!matched) {
        json(res, 404, { error: 'Endpoint tidak ditemukan' });
        return;
      }
      if (matched.auth && !req.session) {
        json(res, 401, { error: 'Sesi tidak valid. Silakan login.' });
        return;
      }
      if (isMutating(req.method) && !csrfOk(req)) {
        json(res, 403, { error: 'Permintaan ditolak (CSRF/invalid request header)' });
        return;
      }
      await matched.handler(req, res, { url, params: matched.params });
    } catch (err) {
      if (err instanceof HttpError) {
        json(res, err.status, { error: err.message, details: err.details ?? null });
      } else {
        log('API error', req.method, pathname, err.stack || err.message);
        json(res, 500, { error: PRODUCTION_MODE ? 'Internal server error' : (err.message || 'Internal server error') });
      }
    }
    return;
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    await serveStatic(req, res, pathname);
    return;
  }

  res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Method not allowed');
});

async function bootstrap() {
  if (PRODUCTION_MODE) {
    const security = validateRuntimeSecurity();
    security.warnings.forEach((warning) => log(`PERINGATAN KEAMANAN: ${warning}`));
    if (security.errors.length) {
      throw new Error(`Konfigurasi produksi tidak aman:\n- ${security.errors.join('\n- ')}`);
    }
  }
  await ensureDir(CONFIG_DIR);
  try {
    await ensureDir(path.dirname(AUDIT_LOG));
  } catch {
    /* ignore */
  }

  const state = await loadState();
  if (!state.createdAt) await saveState(state);

  try {
    await writeGeneratedFiles(state);
  } catch (err) {
    log('Peringatan: gagal menulis file generated:', err.message);
  }

  const { overrideContent, crsContent } = await loadRawSettings();
  if (!crsContent) {
    log(`Peringatan: ${CRS_SETUP_FILE} tidak ditemukan. Jalankan bootstrap container.`);
  }
  if (!overrideContent) {
    const settings = parseSettings('', crsContent);
    await writeTextInPlace(OVERRIDE_FILE, renderOverride(settings));
    log('File override ModSecurity dibuat.');
  }

  // Terapkan file generated ke container WAF bila sudah berjalan (mis. manager
  // restart dengan state lama). Kegagalan di sini tidak fatal; user dapat
  // menekan Reload di panel.
  try {
    const reload = await reloadWaf();
    if (reload.skipped) {
      // Docker tidak tersedia (mode dev) — abaikan.
    } else if (!reload.ok) {
      log('Peringatan: reload WAF saat startup gagal:', reload.message);
    }
  } catch (err) {
    log('Peringatan: tidak dapat reload WAF saat startup:', err.message);
  }

  try {
    await audit.start();
  } catch (err) {
    log('Peringatan: audit log belum bisa dibaca:', err.message);
  }

  const threatTimer = setInterval(async () => {
    try {
      const current = await loadState();
      if (threatIntelDue(current.threatIntel) && !threatSyncRunning) {
        const { commit } = await syncThreatIntel();
        log(`Threat intelligence diperbarui otomatis: ${commit.state.threatIntel.count} entri.`);
      }
    } catch (err) {
      log('Peringatan: sinkronisasi threat intelligence otomatis gagal:', err.message);
    }
  }, 15 * 60 * 1000);
  threatTimer.unref();

  const auditPruneTimer = setInterval(async () => {
    try {
      const current = await loadState();
      if (auditPruneDue(current.auditRetention) && !auditPruneRunning) {
        const result = await pruneAuditLog(current.auditRetention);
        log(`Audit log dipangkas otomatis: ${result.removed} dihapus, ${result.kept} dipertahankan.`);
      }
    } catch (err) {
      log('Peringatan: prune audit log otomatis gagal:', err.message);
    }
  }, 60 * 60 * 1000);
  auditPruneTimer.unref();

  server.listen(PORT, '0.0.0.0', () => {
    log(`AsekWAF Manager v${OPENWAF_VERSION} berjalan di http://0.0.0.0:${PORT}`);
    log(`WAF container: ${WAF_CONTAINER} | WAF URL: ${WAF_URL}`);
    if (usingDefaultPassword()) {
      log('PERINGATAN: password default "admin" masih digunakan. Set OPENWAF_ADMIN_PASSWORD!');
    }
  });
}

process.on('SIGTERM', () => {
  audit.stop();
  server.close(() => process.exit(0));
});

server.requestTimeout = 30_000;
server.headersTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.maxRequestsPerSocket = 1000;
process.on('SIGINT', () => {
  audit.stop();
  server.close(() => process.exit(0));
});

bootstrap().catch((err) => {
  console.error('Gagal menjalankan AsekWAF Manager:', err);
  process.exit(1);
});
