import crypto from 'node:crypto';
import {
  ADMIN_PASSWORD,
  SESSION_SECRET,
  SESSION_TTL_MS,
  COOKIE_SECURE,
  DEFAULT_PASSWORD,
} from './config.js';
import { hmac, safeEqual } from './util.js';

const SECRET = SESSION_SECRET || crypto.randomBytes(32).toString('hex');
export const COOKIE_NAME = 'openwaf_session';

const attempts = new Map();
const MAX_ATTEMPTS = 8;
const WINDOW_MS = 10 * 60 * 1000;

function encode(payload) {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

export function issueSession() {
  const payload = {
    v: 1,
    iat: Date.now(),
    exp: Date.now() + SESSION_TTL_MS,
    nonce: crypto.randomBytes(8).toString('hex'),
  };
  const body = encode(payload);
  const signature = hmac(SECRET, body);
  const token = `${body}.${signature}`;
  const flags = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ];
  if (COOKIE_SECURE) flags.push('Secure');
  return { token, cookie: flags.join('; '), expiresAt: payload.exp };
}

export function clearSessionCookie() {
  const flags = [`${COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0'];
  if (COOKIE_SECURE) flags.push('Secure');
  return flags.join('; ');
}

export function verifySession(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const idx = token.lastIndexOf('.');
  const body = token.slice(0, idx);
  const signature = token.slice(idx + 1);
  if (!safeEqual(signature, hmac(SECRET, body))) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload || payload.v !== 1) return null;
    if (!Number.isFinite(payload.exp) || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

export function checkPassword(password) {
  return safeEqual(password || '', ADMIN_PASSWORD);
}

export function loginRateLimit(ip) {
  const now = Date.now();
  const entry = attempts.get(ip);
  if (!entry || entry.resetAt < now) {
    attempts.set(ip, { count: 0, resetAt: now + WINDOW_MS });
    return { allowed: true, remaining: MAX_ATTEMPTS };
  }
  return { allowed: entry.count < MAX_ATTEMPTS, remaining: Math.max(0, MAX_ATTEMPTS - entry.count) };
}

export function recordFailedLogin(ip) {
  const now = Date.now();
  const entry = attempts.get(ip);
  if (!entry || entry.resetAt < now) {
    attempts.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return;
  }
  entry.count += 1;
}

export function resetFailedLogins(ip) {
  attempts.delete(ip);
}

export function usingDefaultPassword() {
  return DEFAULT_PASSWORD;
}
