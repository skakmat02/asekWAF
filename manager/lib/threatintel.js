import net from 'node:net';

// Sumber komunitas yang stabil dan dapat diunduh tanpa API key.
// Beberapa daftar memakai komentar / skor; parser hanya mengambil token IP/CIDR.
export const THREAT_SOURCES = {
  firehol1: {
    name: 'FireHOL Level 1',
    url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
    description: 'Gabungan blocklist level 1 FireHOL (CIDR). False positive relatif rendah.',
    home: 'https://github.com/firehol/blocklist-ipsets',
  },
  spamhaus_drop: {
    name: 'Spamhaus DROP',
    url: 'https://www.spamhaus.org/drop/drop.txt',
    description: 'Rentang IP yang dikendalikan penyerang/spam menurut Spamhaus (CIDR).',
    home: 'https://www.spamhaus.org/drop/',
  },
  et_compromised: {
    name: 'ET Compromised',
    url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    description: 'IP yang terdeteksi sebagai host terkompromi oleh Emerging Threats.',
    home: 'https://rules.emergingthreats.net/',
  },
  blocklist_de: {
    name: 'blocklist.de',
    url: 'https://lists.blocklist.de/lists/all.txt',
    description: 'Laporan komunitas honeypot/JAM (brute force, spam, scan).',
    home: 'https://www.blocklist.de/en/export.html',
  },
  cins: {
    name: 'CINS Army',
    url: 'https://cinsscore.com/list/ci-badguys.txt',
    description: 'Daftar IP penyerang dari sensor CINS (Community Intelligence Network).',
    home: 'https://cinsscore.com/list/ci-badguys.txt',
  },
  ipsum: {
    name: 'IPsum (score ≥ 3)',
    url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
    description: 'Agregasi 30+ blocklist; hanya IP dengan skor minimal 3 yang diambil.',
    home: 'https://github.com/stamparm/ipsum',
    minScore: 3,
  },
};

export const DEFAULT_THREAT_SOURCES = ['firehol1', 'spamhaus_drop', 'et_compromised'];
export const THREAT_SOURCE_IDS = Object.keys(THREAT_SOURCES);
const MAX_SOURCE_BYTES = 12 * 1024 * 1024;
const MAX_ENTRIES = 200_000;
const RESERVED_V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
];

function ipv4Number(ip) {
  return ip.split('.').reduce((value, octet) => (value << 8n) | BigInt(octet), 0n);
}

function ipv4Range(ip, prefix) {
  const size = 1n << BigInt(32 - prefix);
  const start = ipv4Number(ip) & ~(size - 1n);
  return [start, start + size - 1n];
}

const RESERVED_V4_RANGES = RESERVED_V4.map(([ip, prefix]) => ipv4Range(ip, prefix));

export function isPublicThreatEntry(entry) {
  const [base, prefixText] = String(entry || '').split('/');
  const family = net.isIP(base);
  if (family === 4) {
    const prefix = prefixText === undefined ? 32 : Number(prefixText);
    const [start, end] = ipv4Range(base, prefix);
    return !RESERVED_V4_RANGES.some(([reservedStart, reservedEnd]) => start <= reservedEnd && end >= reservedStart);
  }
  if (family === 6) {
    const value = base.toLowerCase();
    const prefix = prefixText === undefined ? 128 : Number(prefixText);
    if (prefix < 3) return false;
    return !(
      value === '::' || value === '::1' || value.startsWith('::ffff:') ||
      /^(fc|fd)/.test(value) || /^fe[89ab]/.test(value) || value.startsWith('ff') ||
      value.startsWith('2001:db8:') || value === '2001:db8::'
    );
  }
  return false;
}

function normalizeCidr(token) {
  const text = String(token || '').trim().replace(/^["']|["']$/g, '');
  if (!text) return null;

  const v4 = text.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (v4) {
    const octets = v4.slice(1, 5).map(Number);
    const prefix = v4[5] === undefined ? null : Number(v4[5]);
    if (octets.some((octet) => octet < 0 || octet > 255)) return null;
    if (prefix !== null && (prefix < 0 || prefix > 32)) return null;
    return prefix === null ? v4.slice(1, 5).join('.') : `${v4.slice(1, 5).join('.')}/${prefix}`;
  }

  if (text.includes(':')) {
    const [base, prefixText] = text.split('/');
    if (net.isIP(base) !== 6) return null;
    if (prefixText !== undefined) {
      const prefix = Number(prefixText);
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return null;
      return `${base}/${prefix}`;
    }
    return base;
  }

  return null;
}

function parseSourceText(text, source) {
  const entries = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    const cleaned = line.replace(/#.*$/, '').replace(/;.*$/, '').trim();
    if (!cleaned) continue;
    const fields = cleaned.split(/[\s,]+/).filter(Boolean);
    if (!fields.length) continue;
    if (source.minScore) {
      const score = Number.parseInt(fields[1], 10);
      if (!Number.isFinite(score) || score < source.minScore) continue;
    }
    const entry = normalizeCidr(fields[0]);
    if (entry && isPublicThreatEntry(entry)) entries.push(entry);
  }
  return entries;
}

async function fetchSource(id) {
  const source = THREAT_SOURCES[id];
  if (!source) throw new Error(`Sumber threat intel tidak dikenal: ${id}`);
  const response = await fetch(source.url, {
    headers: {
      'User-Agent': 'AsekWAF/1.0 (+https://github.com/openwaf)',
      Accept: 'text/plain,*/*',
    },
    redirect: 'follow',
    signal: AbortSignal.timeout(45_000),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} ${response.statusText}`.trim());
  }
  const contentLength = Number(response.headers.get('content-length') || 0);
  if (contentLength > MAX_SOURCE_BYTES) {
    throw new Error(`File terlalu besar (${contentLength} byte)`);
  }
  const text = await response.text();
  if (text.length > MAX_SOURCE_BYTES) {
    throw new Error(`File terlalu besar (${text.length} byte)`);
  }
  return parseSourceText(text, source);
}

export async function fetchThreatIntel(sourceIds) {
  const ids = [...new Set(sourceIds)].filter((id) => THREAT_SOURCES[id]);
  if (!ids.length) throw new Error('Pilih minimal satu sumber threat intelligence');

  const started = Date.now();
  const results = await Promise.allSettled(ids.map((id) => fetchSource(id)));
  const entries = new Set();
  const sourceCounts = {};
  const errors = [];

  results.forEach((result, index) => {
    const id = ids[index];
    if (result.status === 'rejected') {
      errors.push(`${THREAT_SOURCES[id].name}: ${result.reason?.message || result.reason}`);
      return;
    }
    const unique = new Set(result.value);
    sourceCounts[id] = unique.size;
    for (const entry of unique) entries.add(entry);
  });

  if (!Object.keys(sourceCounts).length) {
    throw new Error(`Semua sumber gagal diunduh. ${errors.join(' | ')}`);
  }

  let list = [...entries];
  let truncated = false;
  if (list.length > MAX_ENTRIES) {
    list = list.slice(0, MAX_ENTRIES);
    truncated = true;
    errors.push(`Daftar dipotong ke ${MAX_ENTRIES} entri`);
  }

  return {
    entries: list,
    sourceCounts,
    errors,
    truncated,
    durationMs: Date.now() - started,
    fetchedAt: new Date().toISOString(),
  };
}

export function threatIntelDue(threatIntel, now = Date.now()) {
  if (!threatIntel?.enabled) return false;
  if (!threatIntel.lastSync) return true;
  const last = Date.parse(threatIntel.lastSync);
  if (!Number.isFinite(last)) return true;
  return now - last >= Math.max(1, threatIntel.refreshHours || 24) * 3600_000;
}
