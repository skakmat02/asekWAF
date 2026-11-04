import { readText, writeTextAtomic, nowIso } from './util.js';
import { STATE_FILE } from './config.js';

const EMPTY_STATE = {
  version: 1,
  disabledRules: [],
  customRules: [],
  exclusions: [],
  ipAllowlist: [],
  ipBlocklist: [],
  reverseProxy: {
    fallbackMode: 'offline',
    defaultUpstream: 'http://127.0.0.1:18080',
    defaultPreserveHost: true,
    sites: [],
  },
  rateLimit: {
    enabled: false,
    requestsPerMinute: 120,
    burst: 40,
    nodelay: true,
  },
  threatIntel: {
    enabled: false,
    sources: ['firehol1', 'spamhaus_drop', 'et_compromised'],
    refreshHours: 24,
    count: 0,
    sourceCounts: {},
    lastSync: null,
    lastError: null,
    lastDurationMs: null,
  },
  auditRetention: {
    enabled: true,
    days: 30,
    lastPrune: null,
    lastRemoved: 0,
    lastKept: 0,
    lastSizeBefore: 0,
    lastSizeAfter: 0,
    lastError: null,
  },
  crsUpdate: {
    currentVersion: null,
    latestVersion: null,
    available: false,
    upToDate: false,
    checkedAt: null,
    release: null,
    lastError: null,
  },
  cveRuleFeeds: { enabled: false, autoSync: true, sources: [], rules: [], lastSync: null, lastError: null },
  errorPages: {
    enabled: true,
    language: 'en',
    brand: 'AsekWAF',
    accent: '#2dd4bf',
    supportText: 'If the problem continues, contact the system administrator.',
    pages: {
      400: { title: 'Bad Request', message: 'The request could not be processed because its format is invalid.' },
      403: { title: 'Forbidden', message: 'The request was blocked by the AsekWAF security policy.' },
      404: { title: 'Not Found', message: 'The requested page or resource could not be found.' },
      429: { title: 'Too Many Requests', message: 'Too many requests were received. Please try again later.' },
      500: { title: 'Internal Server Error', message: 'An internal error occurred while processing the request.' },
      502: { title: 'Bad Gateway', message: 'AsekWAF received an invalid response from the upstream application.' },
      503: { title: 'Service Unavailable', message: 'The service is currently unavailable. Please try again later.' },
      504: { title: 'Gateway Timeout', message: 'The upstream application did not respond within the allowed time.' },
    },
  },
  nextRuleId: 9001000,
  createdAt: null,
  updatedAt: null,
};

let queue = Promise.resolve();
const previousStates = new WeakMap();

function asInt(value, fallback = null) {
  const num = Number.parseInt(value, 10);
  return Number.isFinite(num) ? num : fallback;
}

function normalizeEntry(entry) {
  const created = entry?.createdAt || nowIso();
  return {
    ...entry,
    id: String(entry?.id || ''),
    enabled: entry?.enabled !== false,
    createdAt: created,
  };
}

export function normalizeState(input) {
  const state = { ...EMPTY_STATE, ...(input || {}) };

  state.disabledRules = [...new Set((state.disabledRules || []).map((v) => asInt(v)).filter(Boolean))].sort(
    (a, b) => a - b
  );

  state.customRules = (state.customRules || [])
    .map((rule) => ({
      ...normalizeEntry(rule),
      id: asInt(rule.id),
      name: String(rule.name || `Rule ${rule.id}`),
      phase: asInt(rule.phase, 2),
      severity: String(rule.severity || 'CRITICAL'),
      raw: String(rule.raw || ''),
    }))
    .filter((rule) => Number.isFinite(rule.id));

  state.exclusions = (state.exclusions || [])
    .map((exc) => ({
      ...normalizeEntry(exc),
      id: String(exc.id || `exc_${Math.random().toString(36).slice(2, 10)}`),
      genId: asInt(exc.genId),
      scope: ['global', 'path', 'host', 'host_path'].includes(exc.scope) ? exc.scope : 'path',
      match: String(exc.match || ''),
      host: String(exc.host || '').trim().toLowerCase(),
      ruleIds: [...new Set((exc.ruleIds || []).map((v) => asInt(v)).filter(Boolean))],
      note: String(exc.note || ''),
    }))
    .filter((exc) => exc.genId);

  state.ipAllowlist = (state.ipAllowlist || []).map((item) => ({
    ...normalizeEntry(item),
    id: String(item.id || `ip_${Math.random().toString(36).slice(2, 10)}`),
    value: String(item.value || '').trim(),
    note: String(item.note || ''),
  }));

  state.ipBlocklist = (state.ipBlocklist || []).map((item) => ({
    ...normalizeEntry(item),
    id: String(item.id || `ip_${Math.random().toString(36).slice(2, 10)}`),
    value: String(item.value || '').trim(),
    note: String(item.note || ''),
  }));

  const usedIds = [
    ...state.customRules.map((r) => r.id),
    ...state.exclusions.map((e) => e.genId),
  ];
  state.nextRuleId = Math.max(asInt(state.nextRuleId, 9001000), 9001000, ...usedIds.map((v) => v + 1));

  const rp = state.reverseProxy || {};
  const rawDefaultUpstream = String(rp.defaultUpstream || 'http://127.0.0.1:18080').trim();
  const defaultUpstream = /^http:\/\/demo(?::80)?\/?$/i.test(rawDefaultUpstream)
    ? 'http://127.0.0.1:18080'
    : rawDefaultUpstream;
  const seen = new Set();
  state.reverseProxy = {
    fallbackMode: rp.fallbackMode === 'forward' ? 'forward' : 'offline',
    defaultUpstream,
    defaultPreserveHost: rp.defaultPreserveHost !== false,
    sites: (rp.sites || [])
      .map((site) => ({
        ...site,
        id: String(site.id || `site_${Math.random().toString(36).slice(2, 10)}`),
        name: String(site.name || 'Situs').slice(0, 120),
        hosts: [...new Set((site.hosts || []).map((h) => String(h).trim().toLowerCase()).filter(Boolean))],
        upstream: String(site.upstream || '').trim(),
        listenPort: Math.min(65535, Math.max(1, asInt(site.listenPort, 8080))),
        preserveHost: site.preserveHost !== false,
        websocket: site.websocket !== false,
        verifyTls: site.verifyTls === true,
        tls: site.tls?.enabled === true
          ? {
              enabled: true,
              subject: String(site.tls.subject || ''),
              issuer: String(site.tls.issuer || ''),
              validFrom: String(site.tls.validFrom || ''),
              validTo: String(site.tls.validTo || ''),
              fingerprint256: String(site.tls.fingerprint256 || ''),
            }
          : { enabled: false },
        wafEnabled: site.wafEnabled !== false,
        enabled: site.enabled !== false,
        note: String(site.note || ''),
        createdAt: site.createdAt || nowIso(),
      }))
      .filter((site) => !seen.has(site.id) && seen.add(site.id)),
  };

  const rl = state.rateLimit || {};
  state.rateLimit = {
    enabled: rl.enabled === true,
    requestsPerMinute: Math.min(100000, Math.max(1, asInt(rl.requestsPerMinute, 120))),
    burst: Math.min(100000, Math.max(0, asInt(rl.burst, 40))),
    nodelay: rl.nodelay !== false,
  };

  const ti = state.threatIntel || {};
  const sourceCounts = {};
  for (const [key, value] of Object.entries(ti.sourceCounts || {})) {
    const count = asInt(value, 0);
    if (count > 0) sourceCounts[String(key)] = count;
  }
  state.threatIntel = {
    enabled: ti.enabled === true,
    sources: [...new Set((ti.sources || []).map((id) => String(id).trim()).filter(Boolean))],
    refreshHours: Math.min(720, Math.max(1, asInt(ti.refreshHours, 24))),
    count: Math.min(1_000_000, Math.max(0, asInt(ti.count, 0))),
    sourceCounts,
    lastSync: ti.lastSync ? String(ti.lastSync) : null,
    lastError: ti.lastError ? String(ti.lastError).slice(0, 600) : null,
    lastDurationMs: Number.isFinite(Number(ti.lastDurationMs))
      ? Math.max(0, Number(ti.lastDurationMs))
      : null,
  };

  const ar = state.auditRetention || {};
  state.auditRetention = {
    enabled: ar.enabled !== false,
    days: Math.min(3650, Math.max(1, asInt(ar.days, 30))),
    lastPrune: ar.lastPrune ? String(ar.lastPrune) : null,
    lastRemoved: Math.max(0, asInt(ar.lastRemoved, 0)),
    lastKept: Math.max(0, asInt(ar.lastKept, 0)),
    lastSizeBefore: Math.max(0, asInt(ar.lastSizeBefore, 0)),
    lastSizeAfter: Math.max(0, asInt(ar.lastSizeAfter, 0)),
    lastError: ar.lastError ? String(ar.lastError).slice(0, 600) : null,
  };

  const cu = state.crsUpdate || {};
  state.crsUpdate = {
    currentVersion: cu.currentVersion ? String(cu.currentVersion) : null,
    latestVersion: cu.latestVersion ? String(cu.latestVersion) : null,
    available: cu.available === true,
    upToDate: cu.upToDate === true,
    checkedAt: cu.checkedAt ? String(cu.checkedAt) : null,
    release: cu.release && typeof cu.release === 'object' ? cu.release : null,
    lastError: cu.lastError ? String(cu.lastError).slice(0, 500) : null,
  };

  const cf = state.cveRuleFeeds || {};
  state.cveRuleFeeds = {
    enabled: cf.enabled === true,
    autoSync: cf.autoSync !== false,
    sources: [...new Set((cf.sources || []).map((url) => String(url).trim()).filter(Boolean))].slice(0, 10),
    rules: (cf.rules || []).filter((rule) => Number.isInteger(Number(rule.id)) && String(rule.raw || '').trim()).map((rule) => ({ ...rule, id: Number(rule.id), raw: String(rule.raw), name: String(rule.name || `CVE rule ${rule.id}`).slice(0, 120), enabled: rule.enabled !== false })),
    lastSync: cf.lastSync ? String(cf.lastSync) : null,
    lastError: cf.lastError ? String(cf.lastError).slice(0, 600) : null,
  };

  const ep = state.errorPages || {};
  const defaultPages = EMPTY_STATE.errorPages.pages;
  const pages = {};
  for (const code of [400, 403, 404, 429, 500, 502, 503, 504]) {
    const page = ep.pages?.[code] || ep.pages?.[String(code)] || {};
    pages[code] = {
      title: String(page.title || defaultPages[code].title).slice(0, 100),
      message: String(page.message || defaultPages[code].message).slice(0, 500),
    };
  }
  state.errorPages = {
    enabled: ep.enabled !== false,
    language: ['en', 'id', 'zh', 'ar', 'ja'].includes(ep.language) ? ep.language : 'en',
    brand: String(ep.brand || 'AsekWAF').slice(0, 80),
    accent: /^#[0-9a-f]{6}$/i.test(String(ep.accent || '')) ? String(ep.accent) : '#2dd4bf',
    supportText: String(ep.supportText || EMPTY_STATE.errorPages.supportText).slice(0, 300),
    pages,
  };

  return state;
}

export async function loadState() {
  const raw = await readText(STATE_FILE, '');
  if (!raw.trim()) {
    const fresh = normalizeState({ ...EMPTY_STATE, createdAt: nowIso() });
    return fresh;
  }
  try {
    return normalizeState(JSON.parse(raw));
  } catch {
    return normalizeState({ ...EMPTY_STATE, createdAt: nowIso() });
  }
}

export async function saveState(state) {
  const normalized = normalizeState(state);
  normalized.updatedAt = nowIso();
  if (!normalized.createdAt) normalized.createdAt = normalized.updatedAt;
  await writeTextAtomic(STATE_FILE, `${JSON.stringify(normalized, null, 2)}\n`);
  return normalized;
}

export function allocateRuleId(state) {
  const used = new Set([
    ...state.customRules.map((r) => r.id),
    ...state.exclusions.map((e) => e.genId),
  ]);
  let candidate = Math.max(9001000, asInt(state.nextRuleId, 9001000));
  while (used.has(candidate)) candidate += 1;
  state.nextRuleId = candidate + 1;
  return candidate;
}

export function mutateState(mutator) {
  const run = async () => {
    const state = await loadState();
    const previous = structuredClone(state);
    const result = await mutator(state);
    const saved = await saveState(state);
    previousStates.set(saved, previous);
    return { state: saved, previous, result };
  };
  const next = queue.then(run, run);
  queue = next.then(
    () => undefined,
    () => undefined
  );
  return next;
}

export function takePreviousState(state) {
  const previous = previousStates.get(state) || null;
  previousStates.delete(state);
  return previous;
}

export function globalExcludedIds(state) {
  const ids = new Set(state.disabledRules);
  for (const exc of state.exclusions) {
    if (exc.enabled && exc.scope === 'global') {
      for (const id of exc.ruleIds) ids.add(id);
    }
  }
  return ids;
}
