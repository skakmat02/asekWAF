import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline';
import net from 'node:net';
import { pipeline } from 'node:stream/promises';
import { hashId, truncate } from './util.js';

const MAX_EVENTS = Number.parseInt(process.env.AUDIT_MAX_EVENTS || '5000', 10) || 5000;
const INITIAL_TAIL_BYTES = 8 * 1024 * 1024;
const POLL_MS = 1500;

const SEVERITY_NAMES = {
  0: 'EMERGENCY',
  1: 'ALERT',
  2: 'CRITICAL',
  3: 'ERROR',
  4: 'WARNING',
  5: 'NOTICE',
  6: 'INFO',
  7: 'DEBUG',
};

function lowerHeaders(headers) {
  const out = {};
  if (!headers || typeof headers !== 'object') return out;
  for (const [key, value] of Object.entries(headers)) {
    out[String(key).toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
  }
  return out;
}

function first(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return undefined;
}

function normalizeIp(value) {
  let text = String(value || '').trim();
  if (text.startsWith('[') && text.includes(']')) text = text.slice(1, text.indexOf(']'));
  if (text.startsWith('::ffff:') && net.isIP(text.slice(7)) === 4) text = text.slice(7);
  return net.isIP(text) ? text : '';
}

function isLoopback(value) {
  const ip = normalizeIp(value);
  return ip === '::1' || ip.startsWith('127.');
}

// ModSecurity can retain the TCP peer (for example cloudflared on 127.0.0.1)
// in transaction.client_ip even after Nginx received the original client-IP
// headers. Only trust those headers when the recorded peer is loopback; a
// direct remote client must never be able to override its own address.
function effectiveClientIp(transaction, request, headers) {
  const peer = normalizeIp(first(
    transaction.client_ip,
    transaction.remote_address,
    request.remote_address,
    request.client_ip
  ));
  if (!isLoopback(peer)) return peer;

  const cloudflare = normalizeIp(headers['cf-connecting-ip']);
  if (cloudflare) return cloudflare;

  for (const item of String(headers['x-forwarded-for'] || '').split(',')) {
    const candidate = normalizeIp(item);
    if (candidate) return candidate;
  }
  return peer;
}

function parseDate(value) {
  if (!value) return NaN;
  const direct = new Date(value).getTime();
  if (Number.isFinite(direct)) return direct;
  const cleaned = String(value).replace(/\s+/g, ' ').trim();
  const retry = new Date(cleaned).getTime();
  return Number.isFinite(retry) ? retry : NaN;
}

function severityLabel(raw) {
  if (raw === undefined || raw === null) return 'UNKNOWN';
  const str = String(raw).trim();
  if (/^\d+$/.test(str)) return SEVERITY_NAMES[str] || 'UNKNOWN';
  return str.toUpperCase();
}

function scoreFrom(messages, action) {
  const candidates = [
    action?.message,
    ...messages.map((m) => m.message),
    ...messages.map((m) => m.details?.data),
  ].filter(Boolean);
  for (const text of candidates) {
    const match = String(text).match(/(?:Total Score|score)[^0-9]*(\d+)/i);
    if (match) return Number(match[1]);
  }
  return 0;
}

function normalizeEvent(obj, fallbackTime) {
  const transaction = obj.transaction || {};
  const request = obj.request || transaction.request || {};
  const response = obj.response || transaction.response || {};
  const audit = obj.audit_data || transaction.audit_data || {};
  const headers = lowerHeaders(request.headers);
  const responseHeaders = lowerHeaders(response.headers);
  const messages = Array.isArray(audit.messages)
    ? audit.messages
    : Array.isArray(transaction.messages)
      ? transaction.messages
      : Array.isArray(obj.messages)
        ? obj.messages
        : [];
  const action = audit.action || transaction.action || {};

  const rules = [];
  const seen = new Set();
  for (const message of messages) {
    const details = message.details || message;
    const id = Number.parseInt(details.ruleId ?? details.rule_id ?? message.ruleId, 10);
    if (!Number.isFinite(id)) continue;
    if (seen.has(id)) continue;
    seen.add(id);
    rules.push({
      id,
      msg: unescapeMessage(message.message || details.message || `Rule ${id}`),
      severity: severityLabel(details.severity),
      tags: Array.isArray(details.tags) ? details.tags : [],
      data: truncate(details.data || '', 500),
      file: details.file || '',
      line: details.lineNumber || details.line || '',
    });
  }

  const actionRuleId = Number.parseInt(action.ruleId ?? action.rule_id, 10);
  if (Number.isFinite(actionRuleId) && !seen.has(actionRuleId)) {
    rules.push({
      id: actionRuleId,
      msg: unescapeMessage(action.message || `Rule ${actionRuleId}`),
      severity: 'UNKNOWN',
      tags: [],
      data: '',
      file: '',
      line: '',
    });
  }

  const uri = String(first(request.uri, request.request_uri, transaction.request?.uri) || '');
  const [pathname, query = ''] = uri.split('?');
  const tsRaw = first(
    transaction.time_stamp,
    transaction.timestamp,
    request.timestamp,
    response.timestamp,
    obj.timestamp
  );
  const parsedTs = parseDate(tsRaw);
  const tsMs = Number.isFinite(parsedTs) ? parsedTs : fallbackTime;
  const timestamp = new Date(tsMs).toISOString();

  const status = Number.parseInt(
    first(response.http_code, transaction.response?.http_code, transaction.status, 0),
    10
  );
  const blocked = Boolean(
    transaction.is_interrupted ??
      transaction.interrupted ??
      action.intercepted ??
      (Number.isFinite(status) && status === 403 && rules.length > 0)
  );
  const score = scoreFrom(messages, action);
  const unique = first(transaction.unique_id, transaction.uniqueId, transaction.id, obj.unique_id);
  const clientIp = effectiveClientIp(transaction, request, headers);
  const uidBase =
    unique ||
    `${tsMs}-${clientIp || 'ip'}-${uri}`;
  const uid = hashId(uidBase);

  return {
    uid,
    ts: timestamp,
    tsMs,
    rawTs: tsRaw || '',
    ip: clientIp,
    method: String(first(request.method, transaction.request?.method) || ''),
    uri,
    path: pathname || '/',
    query,
    host: String(first(headers.host, headers[':authority']) || ''),
    status: Number.isFinite(status) ? status : 0,
    blocked,
    interrupted: Boolean(transaction.is_interrupted ?? transaction.interrupted ?? action.intercepted),
    score,
    phase: Number.parseInt(action.phase, 10) || 0,
    actionMessage: unescapeMessage(action.message || ''),
    rules,
    requestHeaders: headers,
    responseHeaders,
    userAgent: String(first(headers['user-agent'], headers['user_agent']) || ''),
    marker: String(headers['x-openwaf-test'] || ''),
    uniqueId: String(unique || ''),
    raw: obj,
  };
}

function unescapeMessage(value) {
  return String(value || '')
    .replace(/\\'/g, "'")
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, '\\');
}

function extractJsonObjects(text) {
  const objects = [];
  let index = 0;
  while (index < text.length) {
    const start = text.indexOf('{', index);
    if (start === -1) {
      return { objects, remainder: '' };
    }
    let depth = 0;
    let inString = false;
    let escaped = false;
    let end = -1;
    for (let i = start; i < text.length; i += 1) {
      const ch = text[i];
      if (inString) {
        if (escaped) escaped = false;
        else if (ch === '\\') escaped = true;
        else if (ch === '"') inString = false;
        continue;
      }
      if (ch === '"') inString = true;
      else if (ch === '{') depth += 1;
      else if (ch === '}') {
        depth -= 1;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    if (end === -1) {
      return { objects, remainder: text.slice(start) };
    }
    const chunk = text.slice(start, end + 1);
    try {
      objects.push(JSON.parse(chunk));
    } catch {
      /* skip malformed object */
    }
    index = end + 1;
  }
  return { objects, remainder: '' };
}

export class AuditStore {
  constructor(file) {
    this.file = file;
    this.events = [];
    this.offset = 0;
    this.remainder = '';
    this.ino = null;
    this.timer = null;
    this.primed = false;
    this.lastError = null;
    this.lastReadAt = 0;
  }

  async start() {
    await this.poll(true);
    this.timer = setInterval(() => {
      this.poll(false).catch((err) => {
        this.lastError = err.message;
      });
    }, POLL_MS);
    if (this.timer.unref) this.timer.unref();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async poll(initial = false) {
    let stat;
    try {
      stat = await fsp.stat(this.file);
    } catch (err) {
      if (err.code === 'ENOENT') {
        this.lastError = 'Audit log belum tersedia';
        return;
      }
      throw err;
    }

    const rotated = this.ino !== null && stat.ino !== this.ino;
    const truncated = stat.size < this.offset;
    if (initial || rotated || truncated) {
      const startAt = initial && !this.primed ? Math.max(0, stat.size - INITIAL_TAIL_BYTES) : 0;
      await this.readRange(startAt, stat.size, initial && !this.primed);
      this.ino = stat.ino;
      this.primed = true;
      this.offset = stat.size;
      return;
    }

    this.ino = stat.ino;
    if (stat.size > this.offset) {
      await this.readRange(this.offset, stat.size, false);
      this.offset = stat.size;
    }
  }

  async prune(retentionDays) {
    const days = Math.min(3650, Math.max(1, Number.parseInt(retentionDays, 10) || 30));
    const cutoff = Date.now() - days * 86400_000;
    const stat = await fsp.stat(this.file);
    const temp = path.join(path.dirname(this.file), `.${path.basename(this.file)}.prune-${process.pid}`);
    const input = fs.createReadStream(this.file, { encoding: 'utf8' });
    const output = fs.createWriteStream(temp, { encoding: 'utf8', mode: stat.mode });
    const lines = readline.createInterface({ input, crlfDelay: Infinity });
    let kept = 0;
    let removed = 0;

    try {
      for await (const line of lines) {
        if (!line.trim()) continue;
        let keep = true;
        try {
          const obj = JSON.parse(line);
          keep = normalizeEvent(obj, stat.mtimeMs).tsMs >= cutoff;
        } catch {
          // Pertahankan baris yang tidak dapat diparse agar prune tidak merusak bukti audit.
          keep = true;
        }
        if (keep) {
          if (!output.write(`${line}\n`)) await new Promise((resolve) => output.once('drain', resolve));
          kept += 1;
        } else {
          removed += 1;
        }
      }
      await new Promise((resolve, reject) => output.end((err) => (err ? reject(err) : resolve())));
      // Pertahankan inode audit.log. LibModSecurity memegang file descriptor
      // sendiri dan tidak selalu mengikuti rename/reopen Nginx.
      await fsp.truncate(this.file, 0);
      await pipeline(
        fs.createReadStream(temp),
        fs.createWriteStream(this.file, { flags: 'r+', start: 0 })
      );
      await fsp.unlink(temp).catch(() => {});
      const after = await fsp.stat(this.file);
      return { days, cutoff: new Date(cutoff).toISOString(), kept, removed, sizeBefore: stat.size, sizeAfter: after.size };
    } catch (err) {
      output.destroy();
      await fsp.unlink(temp).catch(() => {});
      throw err;
    }
  }

  async resetAfterPrune() {
    this.events = [];
    this.offset = 0;
    this.remainder = '';
    this.ino = null;
    this.primed = false;
    await this.poll(true);
  }

  async readRange(start, end, initialTail) {
    const length = end - start;
    if (length <= 0) return;
    const handle = await fsp.open(this.file, 'r');
    try {
      const buffer = Buffer.alloc(length);
      await handle.read(buffer, 0, length, start);
      let text = buffer.toString('utf8');
      if (initialTail) {
        const firstBrace = text.indexOf('{');
        if (firstBrace > 0) text = text.slice(firstBrace);
      }
      const combined = this.remainder + text;
      const { objects, remainder } = extractJsonObjects(combined);
      this.remainder = remainder;
      const now = Date.now();
      for (const obj of objects) {
        const event = normalizeEvent(obj, now);
        if (!event.ip && !event.uri && !event.rules.length) continue;
        this.events.push(event);
      }
      if (this.events.length > MAX_EVENTS) {
        this.events.splice(0, this.events.length - MAX_EVENTS);
      }
      this.lastReadAt = now;
      this.lastError = null;
    } finally {
      await handle.close();
    }
  }

  status() {
    return {
      file: this.file,
      events: this.events.length,
      lastReadAt: this.lastReadAt ? new Date(this.lastReadAt).toISOString() : null,
      error: this.lastError,
    };
  }

  get(uid) {
    return this.events.find((event) => event.uid === uid) || null;
  }

  attackIps(hours = 24, limit = 100) {
    const since = Date.now() - Math.max(1, hours) * 3600_000;
    const counts = new Map();
    for (const event of this.events) {
      if (event.tsMs < since || (!event.blocked && event.rules.length === 0) || !event.ip) continue;
      counts.set(event.ip, (counts.get(event.ip) || 0) + 1);
    }
    return [...counts.entries()]
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, Math.max(1, limit));
  }

  findByMarker(marker, sinceMs = 0) {
    if (!marker) return [];
    return this.events.filter((event) => event.marker === marker && event.tsMs >= sinceMs);
  }

  list({ limit = 50, offset = 0, q = '', action = '', ip = '', rule = '', range = 'all' }) {
    const now = Date.now();
    const ranges = { '1h': 3600_000, '6h': 6 * 3600_000, '24h': 24 * 3600_000, '7d': 7 * 86400_000 };
    const since = ranges[range] ? now - ranges[range] : 0;
    const query = String(q || '').trim().toLowerCase();
    const ruleId = Number.parseInt(rule, 10);

    const filtered = this.events.filter((event) => {
      if (event.tsMs < since) return false;
      if (ip && event.ip !== ip) return false;
      if (ruleId && !event.rules.some((r) => r.id === ruleId)) return false;
      if (action === 'blocked' && !event.blocked) return false;
      if (action === 'detected' && (event.blocked || event.rules.length === 0)) return false;
      if (action === 'allowed' && (event.blocked || event.rules.length > 0)) return false;
      if (query) {
        const haystack = [
          event.uniqueId,
          event.uid,
          event.ip,
          event.uri,
          event.method,
          event.host,
          event.userAgent,
          event.status,
          ...event.rules.map((r) => `${r.id} ${r.msg}`),
        ]
          .join(' ')
          .toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      return true;
    });

    filtered.sort((a, b) => b.tsMs - a.tsMs);
    const total = filtered.length;
    const items = filtered.slice(offset, offset + limit).map((event) => ({
      uid: event.uid,
      ts: event.ts,
      ip: event.ip,
      method: event.method,
      uri: event.uri,
      host: event.host,
      status: event.status,
      blocked: event.blocked,
      score: event.score,
      rules: event.rules.slice(0, 5),
      ruleCount: event.rules.length,
      userAgent: event.userAgent,
    }));

    return { total, items, offset, limit };
  }

  stats(hours = 24) {
    const now = Date.now();
    const since = now - hours * 3600_000;
    const events = this.events.filter((event) => event.tsMs >= since);

    const buckets = new Map();
    const bucketMs = 3600_000;
    const firstBucket = Math.floor((now - hours * 3600_000) / bucketMs) * bucketMs;
    for (let t = firstBucket; t <= now; t += bucketMs) {
      buckets.set(t, { t: new Date(t).toISOString(), blocked: 0, detected: 0, allowed: 0 });
    }

    const topRules = new Map();
    const topIps = new Map();
    const topPaths = new Map();
    const severities = {};
    let blocked = 0;
    let detected = 0;
    let allowed = 0;

    for (const event of events) {
      const bucket = buckets.get(Math.floor(event.tsMs / bucketMs) * bucketMs);
      if (event.blocked) {
        blocked += 1;
        if (bucket) bucket.blocked += 1;
      } else if (event.rules.length) {
        detected += 1;
        if (bucket) bucket.detected += 1;
      } else {
        allowed += 1;
        if (bucket) bucket.allowed += 1;
      }

      for (const rule of event.rules) {
        const key = String(rule.id);
        const current = topRules.get(key) || { id: rule.id, msg: rule.msg, severity: rule.severity, count: 0 };
        current.count += 1;
        topRules.set(key, current);
        severities[rule.severity] = (severities[rule.severity] || 0) + 1;
      }

      if (event.ip) {
        const current = topIps.get(event.ip) || { ip: event.ip, count: 0, blocked: 0 };
        current.count += 1;
        if (event.blocked) current.blocked += 1;
        topIps.set(event.ip, current);
      }

      if (event.path) {
        const current = topPaths.get(event.path) || { path: event.path, count: 0, blocked: 0 };
        current.count += 1;
        if (event.blocked) current.blocked += 1;
        topPaths.set(event.path, current);
      }
    }

    return {
      hours,
      total: events.length,
      blocked,
      detected,
      allowed,
      blockedPct: events.length ? Math.round((blocked / events.length) * 1000) / 10 : 0,
      uniqueIps: topIps.size,
      timeline: [...buckets.values()],
      topRules: [...topRules.values()].sort((a, b) => b.count - a.count).slice(0, 8),
      topIps: [...topIps.values()].sort((a, b) => b.count - a.count).slice(0, 8),
      topPaths: [...topPaths.values()].sort((a, b) => b.count - a.count).slice(0, 8),
      severities,
    };
  }
}

export function createAuditStore(file) {
  return new AuditStore(file);
}

// Keep a reference to fs to avoid unused import warnings in older bundlers.
void fs;
