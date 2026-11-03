import fsp from 'node:fs/promises';
import path from 'node:path';
import { CRS_RULES_DIR } from './config.js';

const MANAGED_FILES = new Set([
  'zzz-openwaf.conf',
  'REQUEST-905-OPENWAF-CUSTOM.conf',
  'REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf',
]);

let cache = {
  signature: '',
  loadedAt: 0,
  rules: [],
  files: [],
};

function unescape(value) {
  return value.replace(/\\'/g, "'").replace(/\\"/g, '"').replace(/\\\\/g, '\\');
}

function parseBlock(block, file, line) {
  const text = block.join('\n');
  const idMatch = text.match(/\bid\s*:\s*'?(\d{1,7})/);
  if (!idMatch) return null;
  const msgMatch = text.match(/msg\s*:\s*(['"])([\s\S]*?)\1/);
  const sevMatch = text.match(/severity\s*:\s*'?([A-Za-z]+)/);
  const phaseMatch = text.match(/\bphase\s*:\s*(\d)/);
  const tags = [...text.matchAll(/tag\s*:\s*'([^']+)'/g)].map((m) => m[1]);
  const paranoiaTag = tags.find((tag) => /^paranoia-level\/\d+$/.test(tag));

  return {
    id: Number(idMatch[1]),
    msg: unescape(msgMatch ? msgMatch[2] : `Rule ${idMatch[1]}`),
    severity: (sevMatch?.[1] || 'UNKNOWN').toUpperCase(),
    phase: phaseMatch ? Number(phaseMatch[1]) : 2,
    tags,
    category: tags.find((tag) => tag.startsWith('attack-')) || 'owasp-crs',
    paranoia: paranoiaTag ? Number(paranoiaTag.split('/')[1]) : 0,
    file,
    line,
    raw: text,
  };
}

async function loadCatalog() {
  let entries = [];
  try {
    entries = await fsp.readdir(CRS_RULES_DIR, { withFileTypes: true });
  } catch {
    return { rules: [], files: [] };
  }

  const files = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.conf') && !MANAGED_FILES.has(entry.name))
    .map((entry) => entry.name)
    .sort();

  const signatureParts = [];
  for (const name of files) {
    try {
      const stat = await fsp.stat(path.join(CRS_RULES_DIR, name));
      signatureParts.push(`${name}:${stat.mtimeMs}:${stat.size}`);
    } catch {
      /* ignore */
    }
  }
  const signature = signatureParts.join('|');

  if (cache.signature === signature && cache.rules.length) {
    return cache;
  }

  const rules = [];
  const seen = new Set();

  for (const name of files) {
    let content = '';
    try {
      content = await fsp.readFile(path.join(CRS_RULES_DIR, name), 'utf8');
    } catch {
      continue;
    }
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i += 1) {
      const trimmed = lines[i].trimStart();
      if (!trimmed.startsWith('SecRule ') && trimmed !== 'SecRule') continue;
      const block = [lines[i]];
      while (block[block.length - 1].trimEnd().endsWith('\\') && i + 1 < lines.length) {
        i += 1;
        block.push(lines[i]);
      }
      const parsed = parseBlock(block, name, i + 1 - (block.length - 1));
      if (!parsed || seen.has(parsed.id)) continue;
      seen.add(parsed.id);
      rules.push(parsed);
    }
  }

  rules.sort((a, b) => a.id - b.id);
  cache = { signature, loadedAt: Date.now(), rules, files };
  return cache;
}

export async function getCatalog() {
  return loadCatalog();
}

export async function getRule(id) {
  const catalog = await loadCatalog();
  return catalog.rules.find((rule) => rule.id === Number(id)) || null;
}

export async function catalogStats(state, globalExcluded) {
  const catalog = await loadCatalog();
  const bySeverity = {};
  const byParanoia = {};
  let disabled = 0;

  for (const rule of catalog.rules) {
    bySeverity[rule.severity] = (bySeverity[rule.severity] || 0) + 1;
    if (rule.paranoia) byParanoia[rule.paranoia] = (byParanoia[rule.paranoia] || 0) + 1;
    if (globalExcluded.has(rule.id)) disabled += 1;
  }

  return {
    total: catalog.rules.length,
    enabled: catalog.rules.length - disabled,
    disabled,
    files: catalog.files.length,
    bySeverity,
    byParanoia,
    customRules: state.customRules.length,
    customRulesEnabled: state.customRules.filter((r) => r.enabled).length,
    exclusions: state.exclusions.length,
    ipBlocks: state.ipBlocklist.length,
    ipAllows: state.ipAllowlist.length,
  };
}

export function invalidateCatalog() {
  cache = { signature: '', loadedAt: 0, rules: [], files: [] };
}
