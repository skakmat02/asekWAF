import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

export class HttpError extends Error {
  constructor(status, message, details = undefined) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

export function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

export async function readText(file, fallback = '') {
  try {
    return await fsp.readFile(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return fallback;
    throw err;
  }
}

export async function writeTextAtomic(file, content, options = undefined) {
  const dir = path.dirname(file);
  ensureDir(dir);
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  await fsp.writeFile(tmp, content, options ? { encoding: 'utf8', ...options } : 'utf8');
  await fsp.rename(tmp, file);
}

// Menulis tanpa rename. Wajib untuk file yang di-bind-mount satu file ke
// container lain: rename akan mengganti inode dan bind mount tetap menunjuk
// file lama sampai container di-restart.
export async function writeTextInPlace(file, content) {
  ensureDir(path.dirname(file));
  await fsp.writeFile(file, content, 'utf8');
}

export function readTextSync(file, fallback = '') {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return fallback;
    throw err;
  }
}

export async function fileExists(file) {
  try {
    await fsp.access(file);
    return true;
  } catch {
    return false;
  }
}

export function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    if (!key) continue;
    out[key] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

export function safeEqual(a = '', b = '') {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

export function hmac(secret, value) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

export function hashId(value) {
  return crypto.createHash('sha1').update(String(value)).digest('hex').slice(0, 16);
}

export function nowIso() {
  return new Date().toISOString();
}

export function clampInt(value, min, max, fallback) {
  const num = Number.parseInt(value, 10);
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

export function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function splitList(value) {
  return String(value ?? '')
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter(Boolean);
}

export function jsonClone(value) {
  return JSON.parse(JSON.stringify(value));
}

export function truncate(text, max = 4000) {
  const str = String(text ?? '');
  return str.length > max ? `${str.slice(0, max)}\n… (truncated)` : str;
}
