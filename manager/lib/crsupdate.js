import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const RELEASES_URL = 'https://api.github.com/repos/coreruleset/coreruleset/releases/latest';
const UA = 'AsekWAF/1.0 (+https://github.com/openwaf)';
const CACHE_MS = 30 * 60 * 1000;

let cache = { at: 0, value: null };

export function compareVersions(a, b) {
  const parse = (value) => {
    const match = String(value || '').trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/);
    if (!match) return null;
    return {
      parts: [Number(match[1]), Number(match[2]), Number(match[3])],
      pre: match[4] || '',
    };
  };
  const left = parse(a);
  const right = parse(b);
  if (!left && !right) return 0;
  if (!left) return -1;
  if (!right) return 1;
  for (let index = 0; index < 3; index += 1) {
    if (left.parts[index] !== right.parts[index]) {
      return left.parts[index] > right.parts[index] ? 1 : -1;
    }
  }
  if (left.pre === right.pre) return 0;
  if (!left.pre) return 1;
  if (!right.pre) return -1;
  return left.pre > right.pre ? 1 : -1;
}

export async function fetchLatestRelease(force = false) {
  if (!force && cache.value && Date.now() - cache.at < CACHE_MS) {
    return { ...cache.value, cached: true };
  }
  const response = await fetch(RELEASES_URL, {
    headers: {
      'User-Agent': UA,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    redirect: 'follow',
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) {
    throw new Error(`GitHub API HTTP ${response.status} ${response.statusText}`.trim());
  }
  const release = await response.json();
  const tag = String(release.tag_name || '').trim();
  if (!/^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(tag)) {
    throw new Error(`Tag release CRS tidak valid: ${tag || '(kosong)'}`);
  }
  const value = {
    tag,
    version: tag.replace(/^v/, ''),
    name: String(release.name || tag).slice(0, 200),
    url: String(release.html_url || ''),
    publishedAt: release.published_at || null,
    notes: String(release.body || '').slice(0, 12_000),
  };
  cache = { at: Date.now(), value };
  return { ...value, cached: false };
}

export async function checkForUpdate(currentVersion, force = false) {
  const latest = await fetchLatestRelease(force);
  const comparison = compareVersions(latest.version, currentVersion);
  return {
    currentVersion: currentVersion || 'unknown',
    latestVersion: latest.version,
    available: comparison > 0,
    upToDate: comparison <= 0,
    localAhead: comparison < 0,
    release: {
      tag: latest.tag,
      name: latest.name,
      url: latest.url,
      publishedAt: latest.publishedAt,
      notes: latest.notes,
    },
    checkedAt: new Date().toISOString(),
    cached: latest.cached,
  };
}

export async function downloadCrsRelease(tag) {
  const safeTag = String(tag || '').trim();
  if (!/^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(safeTag)) {
    throw new Error('Tag release CRS tidak valid');
  }
  const url = `https://github.com/coreruleset/coreruleset/archive/refs/tags/${safeTag}.tar.gz`;
  const response = await fetch(url, {
    headers: { 'User-Agent': UA, Accept: 'application/gzip,*/*' },
    redirect: 'follow',
    signal: AbortSignal.timeout(60_000),
  });
  if (!response.ok) {
    throw new Error(`Unduhan CRS gagal: HTTP ${response.status} ${response.statusText}`.trim());
  }
  const arrayBuffer = await response.arrayBuffer();
  if (arrayBuffer.byteLength > 80 * 1024 * 1024) {
    throw new Error('Ukuran arsip CRS melebihi batas 80 MB');
  }

  const tempDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'openwaf-crs-'));
  const archive = path.join(tempDir, 'crs.tar.gz');
  await fsp.writeFile(archive, Buffer.from(arrayBuffer));
  try {
    await execFileAsync('tar', ['-xzf', archive, '-C', tempDir], { timeout: 60_000 });
  } catch (err) {
    await fsp.rm(tempDir, { recursive: true, force: true });
    throw new Error(`Gagal mengekstrak arsip CRS: ${err.message}`);
  }

  const entries = await fsp.readdir(tempDir, { withFileTypes: true });
  const rootName = entries.find((entry) => entry.isDirectory() && entry.name.startsWith('coreruleset-'))?.name;
  if (!rootName) {
    await fsp.rm(tempDir, { recursive: true, force: true });
    throw new Error('Struktur arsip CRS tidak dikenali (folder coreruleset-* tidak ditemukan)');
  }
  const rootDir = path.join(tempDir, rootName);
  const rulesDir = path.join(rootDir, 'rules');
  const setupExample = path.join(rootDir, 'crs-setup.conf.example');
  await fsp.access(rulesDir);
  await fsp.access(setupExample);

  return {
    tempDir,
    rootDir,
    rulesDir,
    setupExample,
    tag: safeTag,
    version: safeTag.replace(/^v/, ''),
    async cleanup() {
      await fsp.rm(tempDir, { recursive: true, force: true }).catch(() => {});
    },
  };
}
