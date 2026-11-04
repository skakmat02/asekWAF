import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readText, clampInt, fileExists } from './util.js';

export const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const REPO_ROOT = path.resolve(APP_ROOT, '..');

export const CONFIG_DIR =
  process.env.OPENWAF_CONFIG_DIR || path.resolve(REPO_ROOT, 'deploy', 'modsec');
export const CRS_DIR = process.env.CRS_DIR || path.resolve(REPO_ROOT, 'test', 'fixtures', 'crs');
export const AUDIT_LOG =
  process.env.AUDIT_LOG || path.resolve(REPO_ROOT, 'deploy', 'logs', 'audit.log');
export const NGINX_DIR =
  process.env.OPENWAF_NGINX_DIR || path.resolve(REPO_ROOT, 'deploy', 'nginx');

export const STATE_FILE = path.join(CONFIG_DIR, 'openwaf-state.json');
export const OVERRIDE_FILE = path.join(CONFIG_DIR, 'modsecurity-override.conf');
export const CRS_SETUP_FILE = path.join(CRS_DIR, 'crs-setup.conf');
export const CRS_RULES_DIR = path.join(CRS_DIR, 'rules');
export const ZZZ_FILE = path.join(CRS_RULES_DIR, 'REQUEST-905-OPENWAF-CUSTOM.conf');
export const BASELINE_FILE = path.join(CRS_RULES_DIR, 'REQUEST-904-OPENWAF-BASELINE.conf');
export const BEFORE_FILE = path.join(
  CRS_RULES_DIR,
  'REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf'
);
export const DEFAULT_UPSTREAM_FILE = path.join(NGINX_DIR, 'default-upstream.conf');
export const SITES_FILE = path.join(NGINX_DIR, 'sites.conf');
export const RATE_LIMIT_ZONE_FILE = path.join(NGINX_DIR, 'rate-limit-zone.conf');
export const RATE_LIMIT_LOCATION_FILE = path.join(NGINX_DIR, 'rate-limit-location.conf');
export const ERROR_PAGES_CONF = path.join(NGINX_DIR, 'error-pages.conf');
export const ERROR_PAGES_DIR = path.join(NGINX_DIR, 'error-pages');
export const CERTIFICATES_DIR = path.join(NGINX_DIR, 'certificates');
export const COMMUNITY_BLOCKLIST_FILE = path.join(
  CRS_RULES_DIR,
  'openwaf-community-blocklist.txt'
);
export const WAF_CRS_DIR = (process.env.WAF_CRS_DIR || '/opt/owasp-crs').replace(/\/+$/, '');
export const WAF_COMMUNITY_BLOCKLIST = `${WAF_CRS_DIR}/rules/openwaf-community-blocklist.txt`;

export const PORT = clampInt(process.env.MANAGER_PORT, 1, 65535, 8081);
export const ADMIN_PASSWORD = process.env.OPENWAF_ADMIN_PASSWORD || 'admin';
export const DEFAULT_PASSWORD = !process.env.OPENWAF_ADMIN_PASSWORD;
export const SESSION_SECRET = process.env.OPENWAF_SESSION_SECRET || '';
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const COOKIE_SECURE = String(process.env.OPENWAF_COOKIE_SECURE || '').toLowerCase() === 'true';

export const WAF_URL = (process.env.WAF_URL || 'http://127.0.0.1:8080').replace(/\/+$/, '');
export const WAF_CONTAINER = process.env.WAF_CONTAINER || 'asekwaf-waf';
export const DOCKER_SOCKET = process.env.DOCKER_SOCKET || '/var/run/docker.sock';
export const DOCKER_HOST = (process.env.DOCKER_HOST || '').replace(/\/+$/, '');
export const OPENWAF_VERSION = '1.0.0';
export const PRODUCTION_MODE = String(process.env.OPENWAF_PRODUCTION || '').toLowerCase() === 'true';

export function validateRuntimeSecurity() {
  const errors = [];
  const warnings = [];
  if (DEFAULT_PASSWORD) errors.push('OPENWAF_ADMIN_PASSWORD wajib diatur');
  if (ADMIN_PASSWORD.length < 16) errors.push('OPENWAF_ADMIN_PASSWORD minimal 16 karakter');
  if (!SESSION_SECRET) errors.push('OPENWAF_SESSION_SECRET wajib diatur');
  if (SESSION_SECRET && SESSION_SECRET.length < 32) errors.push('OPENWAF_SESSION_SECRET minimal 32 karakter');
  if (!COOKIE_SECURE) errors.push('OPENWAF_COOKIE_SECURE harus true pada mode produksi');
  if (!DOCKER_HOST && DOCKER_SOCKET === '/var/run/docker.sock') {
    warnings.push('manager memakai Docker socket langsung; gunakan socket proxy pada deployment produksi');
  }
  return { errors, warnings };
}

export const ENGINE_MODES = ['On', 'DetectionOnly', 'Off'];
export const AUDIT_MODES = ['On', 'RelevantOnly', 'Off'];

export const CRS_DEFAULTS = {
  paranoia: 1,
  detectionParanoia: 1,
  inboundThreshold: 5,
  outboundThreshold: 4,
  reportingLevel: 4,
  allowedMethods: 'GET HEAD POST OPTIONS',
  maxNumArgs: 255,
  allowedContentTypes:
    '|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json|',
  restrictedExtensions:
    '.ani/ .asa/ .asax/ .ascx/ .back/ .backup/ .bak/ .bck/ .bk/ .bkp/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .cnf/ .com/ .config/ .conf/ .copy/ .crt/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dist/ .dll/ .dos/ .dpkg-dist/ .drv/ .gadget/ .hta/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .inf/ .ini/ .jks/ .jse/ .key/ .licx/ .lnk/ .log/ .mdb/ .msc/ .ocx/ .old/ .pass/ .pdb/ .pfx/ .pif/ .pem/ .pol/ .prf/ .printer/ .pwd/ .rdb/ .rdp/ .reg/ .resources/ .resx/ .sav/ .save/ .scr/ .sct/ .sh/ .shs/ .sql/ .sqlite/ .sqlite3/ .swap/ .swo/ .swp/ .sys/ .temp/ .tfstate/ .tlb/ .tmp/ .vb/ .vbe/ .vbs/ .vbproj/ .vsdisco/ .vxd/ .webinfo/ .ws/ .wsc/ .wsf/ .wsh/ .xsd/ .xsx/',
};

const CRS_SETACTION_IDS = {
  paranoia: '900000',
  detectionParanoia: '900001',
  thresholds: '900110',
  reportingLevel: '900115',
  allowedMethods: '900200',
  allowedContentTypes: '900220',
  restrictedExtensions: '900240',
  maxNumArgs: '900300',
};

function firstLineValue(content, variable) {
  const re = new RegExp(`setvar:'?tx\\.${variable}=([^'"\\n\\\\]*)`);
  const match = content.match(re);
  if (!match) return null;
  const raw = match[1].trim();
  return raw === '' ? '' : raw;
}

function activeValue(content, variable) {
  const lines = content.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('#')) continue;
    const re = new RegExp(`setvar:'?tx\\.${variable}=(['"]?)([^'"\\\\\\n]*)\\1`);
    const match = trimmed.match(re);
    if (match) return match[2].trim();
  }
  return null;
}

export function parseCrsVersion(content) {
  const match = content.match(/OWASP\s+CRS\s+ver\.?\s*([0-9][\w.-]*)/i);
  return match ? match[1] : 'unknown';
}

export function parseSettings(overrideContent, crsContent) {
  const engineMatch = overrideContent.match(/^\s*SecRuleEngine\s+(\w+)/im);
  const auditMatch = overrideContent.match(/^\s*SecAuditEngine\s+(\w+)/im);
  const reqBodyMatch = overrideContent.match(/^\s*SecRequestBodyLimit\s+(\d+)/im);
  const respBodyMatch = overrideContent.match(/^\s*SecResponseBodyLimit\s+(\d+)/im);

  const pick = (name, fallback) => {
    const active = activeValue(crsContent, name);
    if (active !== null) return active;
    const anyValue = firstLineValue(crsContent, name);
    if (anyValue !== null) return anyValue;
    return fallback;
  };

  const int = (name, fallback) => clampInt(pick(name, fallback), 0, 1_000_000, fallback);

  return {
    engineMode: ENGINE_MODES.includes(engineMatch?.[1]) ? engineMatch[1] : 'On',
    auditEngine: AUDIT_MODES.includes(auditMatch?.[1]) ? auditMatch[1] : 'RelevantOnly',
    requestBodyLimit: clampInt(reqBodyMatch?.[1], 1024, 1_073_741_824, 13_107_200),
    responseBodyLimit: clampInt(respBodyMatch?.[1], 0, 1_073_741_824, 1_048_576),
    paranoia: int('blocking_paranoia_level', CRS_DEFAULTS.paranoia),
    detectionParanoia: int('detection_paranoia_level', CRS_DEFAULTS.detectionParanoia),
    inboundThreshold: int('inbound_anomaly_score_threshold', CRS_DEFAULTS.inboundThreshold),
    outboundThreshold: int('outbound_anomaly_score_threshold', CRS_DEFAULTS.outboundThreshold),
    reportingLevel: int('reporting_level', CRS_DEFAULTS.reportingLevel),
    allowedMethods: pick('allowed_methods', CRS_DEFAULTS.allowedMethods),
    maxNumArgs: int('max_num_args', CRS_DEFAULTS.maxNumArgs),
    allowedContentTypes: pick('allowed_request_content_type', CRS_DEFAULTS.allowedContentTypes),
    restrictedExtensions: pick('restricted_extensions', CRS_DEFAULTS.restrictedExtensions),
    crsVersion: parseCrsVersion(crsContent),
  };
}

function findRuleBlock(lines, id) {
  const idPattern = new RegExp(`id\\s*:\\s*'?${id}'?`);
  const idIndex = lines.findIndex((line) => idPattern.test(line));
  if (idIndex === -1) return null;

  let start = -1;
  for (let i = idIndex; i >= Math.max(0, idIndex - 32); i -= 1) {
    const stripped = lines[i].replace(/^\s*#\s?/, '').trim();
    if (/^SecAction\b/.test(stripped)) {
      start = i;
      break;
    }
  }
  if (start === -1) return null;

  let end = start;
  for (let i = idIndex; i < lines.length && i < idIndex + 40; i += 1) {
    if (lines[i].trimEnd().endsWith('"')) {
      end = i;
      break;
    }
  }
  return { start, end };
}

function secActionValueSet(content, id, variable, value) {
  const lines = content.split('\n');
  const block = findRuleBlock(lines, id);
  if (!block) {
    throw new Error(`Tidak menemukan SecAction id:${id} di crs-setup.conf`);
  }

  const varPattern = new RegExp(`(tx\\.${variable}\\s*=\\s*)[^'"\\\\,\\n]*`);
  let found = false;

  for (let i = block.start; i <= block.end; i += 1) {
    lines[i] = lines[i].replace(/^(\s*)#\s?/, '$1');
    if (varPattern.test(lines[i])) {
      lines[i] = lines[i].replace(varPattern, `$1${value}`);
      found = true;
    }
  }

  if (!found) {
    throw new Error(`Variabel tx.${variable} tidak ditemukan pada SecAction id:${id}`);
  }
  return lines.join('\n');
}

export function applySettingsToCrs(content, patch) {
  let out = content;

  if (patch.paranoia !== undefined) {
    const level = clampInt(patch.paranoia, 1, 4, 1);
    out = secActionValueSet(out, CRS_SETACTION_IDS.paranoia, 'blocking_paranoia_level', level);
    out = secActionValueSet(
      out,
      CRS_SETACTION_IDS.detectionParanoia,
      'detection_paranoia_level',
      Math.max(level, clampInt(patch.detectionParanoia ?? level, level, 4, level))
    );
  } else if (patch.detectionParanoia !== undefined) {
    out = secActionValueSet(
      out,
      CRS_SETACTION_IDS.detectionParanoia,
      'detection_paranoia_level',
      clampInt(patch.detectionParanoia, 1, 4, 1)
    );
  }

  if (patch.inboundThreshold !== undefined || patch.outboundThreshold !== undefined) {
    const current = parseSettings('', out);
    const inbound = clampInt(patch.inboundThreshold, 1, 10000, current.inboundThreshold);
    const outbound = clampInt(patch.outboundThreshold, 1, 10000, current.outboundThreshold);
    out = secActionValueSet(out, CRS_SETACTION_IDS.thresholds, 'inbound_anomaly_score_threshold', inbound);
    out = secActionValueSet(out, CRS_SETACTION_IDS.thresholds, 'outbound_anomaly_score_threshold', outbound);
  }

  if (patch.reportingLevel !== undefined) {
    out = secActionValueSet(
      out,
      CRS_SETACTION_IDS.reportingLevel,
      'reporting_level',
      clampInt(patch.reportingLevel, 0, 5, 4)
    );
  }

  if (patch.allowedMethods !== undefined) {
    const methods = String(patch.allowedMethods)
      .split(/\s+/)
      .map((m) => m.trim().toUpperCase())
      .filter((m) => /^[A-Z]+$/.test(m));
    if (!methods.length) throw new Error('Allowed methods tidak boleh kosong');
    out = secActionValueSet(
      out,
      CRS_SETACTION_IDS.allowedMethods,
      'allowed_methods',
      methods.join(' ')
    );
  }

  if (patch.maxNumArgs !== undefined) {
    out = secActionValueSet(
      out,
      CRS_SETACTION_IDS.maxNumArgs,
      'max_num_args',
      clampInt(patch.maxNumArgs, 1, 100000, 255)
    );
  }

  if (patch.allowedContentTypes !== undefined) {
    const value = String(patch.allowedContentTypes).trim();
    if (!value || /['"\n\r]/.test(value)) throw new Error('Allowed content types tidak valid');
    out = secActionValueSet(
      out,
      CRS_SETACTION_IDS.allowedContentTypes,
      'allowed_request_content_type',
      value
    );
  }

  if (patch.restrictedExtensions !== undefined) {
    const value = String(patch.restrictedExtensions).trim();
    if (!value || /['"\n\r]/.test(value)) throw new Error('Restricted extensions tidak valid');
    out = secActionValueSet(
      out,
      CRS_SETACTION_IDS.restrictedExtensions,
      'restricted_extensions',
      value
    );
  }

  return out;
}

export function renderOverride(settings) {
  const mode = ENGINE_MODES.includes(settings.engineMode) ? settings.engineMode : 'On';
  const audit = AUDIT_MODES.includes(settings.auditEngine) ? settings.auditEngine : 'RelevantOnly';
  return `# ---------------------------------------------------------------------------
# AsekWAF - generated ModSecurity override
# This file is generated automatically by the AsekWAF panel.
# Manual changes are overwritten when settings are saved.
# ---------------------------------------------------------------------------

SecRuleEngine ${mode}
SecAuditEngine ${audit}
SecRequestBodyLimit ${clampInt(settings.requestBodyLimit, 1024, 1_073_741_824, 13_107_200)}
SecResponseBodyLimit ${clampInt(settings.responseBodyLimit, 0, 1_073_741_824, 1_048_576)}
`;
}

export async function loadRawSettings() {
  const [overrideContent, crsContent] = await Promise.all([
    readText(OVERRIDE_FILE, ''),
    readText(CRS_SETUP_FILE, ''),
  ]);
  return {
    overrideContent,
    crsContent,
    settings: parseSettings(overrideContent, crsContent),
  };
}

export async function settingsFilesPresent() {
  const [crs, override] = await Promise.all([fileExists(CRS_SETUP_FILE), fileExists(OVERRIDE_FILE)]);
  return { crs, override };
}
