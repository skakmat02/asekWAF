import http from 'node:http';
import https from 'node:https';
import { DOCKER_HOST, DOCKER_SOCKET, WAF_CONTAINER } from './config.js';

let dockerEndpoint = null;
if (DOCKER_HOST) {
  const parsed = new URL(DOCKER_HOST);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('DOCKER_HOST harus berupa URL HTTP(S)');
  dockerEndpoint = parsed;
}

function apiRequest(method, apiPath, body, { binary = false, timeout = 20000 } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const transport = dockerEndpoint?.protocol === 'https:' ? https : http;
    const req = transport.request(
      {
        ...(dockerEndpoint
          ? { hostname: dockerEndpoint.hostname, port: dockerEndpoint.port || undefined }
          : { socketPath: DOCKER_SOCKET }),
        path: apiPath,
        method,
        headers: payload
          ? { 'Content-Type': 'application/json', 'Content-Length': payload.length }
          : {},
        timeout,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const buffer = Buffer.concat(chunks);
          if (binary) {
            resolve({ status: res.statusCode, headers: res.headers, buffer });
            return;
          }
          const text = buffer.toString('utf8');
          let json = null;
          try {
            json = text ? JSON.parse(text) : null;
          } catch {
            json = null;
          }
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('Docker API timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function parseMultiplexed(buffer) {
  if (!buffer || buffer.length === 0) return '';
  if (buffer[0] !== 1 && buffer[0] !== 2) return buffer.toString('utf8');
  let offset = 0;
  let out = '';
  while (offset + 8 <= buffer.length) {
    const type = buffer[offset];
    const size = buffer.readUInt32BE(offset + 4);
    const start = offset + 8;
    const end = start + size;
    if (end > buffer.length) break;
    if (type === 1 || type === 2) out += buffer.subarray(start, end).toString('utf8');
    offset = end;
  }
  return out;
}

let availability = { at: 0, value: null };

export async function dockerAvailable(force = false) {
  const now = Date.now();
  if (!force && availability.value !== null && now - availability.at < 5000) {
    return availability.value;
  }
  try {
    const res = await apiRequest('GET', '/version', undefined, { timeout: 2500 });
    const value = res.status === 200;
    availability = { at: now, value, error: value ? null : `HTTP ${res.status}` };
    return value;
  } catch (err) {
    availability = { at: now, value: false, error: err.message };
    return false;
  }
}

export function dockerError() {
  return availability.error || null;
}

export async function inspectContainer(name = WAF_CONTAINER) {
  const res = await apiRequest('GET', `/containers/${encodeURIComponent(name)}/json`);
  if (res.status === 404) return null;
  if (res.status >= 300) throw new Error(res.json?.message || `Docker API HTTP ${res.status}`);
  const data = res.json;
  return {
    name: data.Name?.replace(/^\//, '') || name,
    image: data.Config?.Image || '',
    status: data.State?.Status || 'unknown',
    running: Boolean(data.State?.Running),
    restarting: Boolean(data.State?.Restarting),
    startedAt: data.State?.StartedAt || null,
    finishedAt: data.State?.FinishedAt || null,
    exitCode: data.State?.ExitCode ?? null,
    health: data.State?.Health?.Status || null,
    pid: data.State?.Pid ?? null,
  };
}

export async function execInContainer(cmd, { name = WAF_CONTAINER, timeout = 30000 } = {}) {
  const create = await apiRequest('POST', `/containers/${encodeURIComponent(name)}/exec`, {
    AttachStdout: true,
    AttachStderr: true,
    Tty: false,
    Cmd: cmd,
  });
  if (create.status >= 300) {
    throw new Error(create.json?.message || `Gagal membuat exec (HTTP ${create.status})`);
  }
  const execId = create.json?.Id;
  if (!execId) throw new Error('Docker tidak mengembalikan exec ID');

  const started = await apiRequest(
    'POST',
    `/exec/${encodeURIComponent(execId)}/start`,
    { Detach: false, Tty: false },
    { binary: true, timeout }
  );
  if (started.status >= 300) {
    const text = started.buffer?.toString('utf8') || '';
    throw new Error(text || `Gagal menjalankan exec (HTTP ${started.status})`);
  }

  const combined = parseMultiplexed(started.buffer);
  const inspect = await apiRequest(
    'GET',
    `/exec/${encodeURIComponent(execId)}/json`
  );
  return {
    exitCode: inspect.json?.ExitCode ?? null,
    running: inspect.json?.Running ?? false,
    output: combined,
  };
}

export async function reloadWaf(name = WAF_CONTAINER) {
  if (!(await dockerAvailable())) {
    return {
      ok: true,
      skipped: true,
      message: 'Docker socket tidak tersedia. Perubahan tersimpan, reload harus dilakukan manual.',
    };
  }

  const script = [
    'set -e',
    'mkdir -p /etc/nginx/modsecurity.d',
    'envsubst < /etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template > /etc/nginx/modsecurity.d/modsecurity-override.conf',
    'cp /etc/nginx/modsecurity.d/modsecurity-override.conf /etc/modsecurity.d/modsecurity-override.conf',
    'nginx -t',
    'nginx -s reload',
    'echo OPENWAF_RELOAD_OK',
  ].join('\n');

  try {
    const result = await execInContainer(['/bin/sh', '-c', script], { name, timeout: 45000 });
    const output = result.output.trim();
    const ok = result.exitCode === 0 && output.includes('OPENWAF_RELOAD_OK');
    return {
      ok,
      skipped: false,
      exitCode: result.exitCode,
      message: ok ? 'Konfigurasi valid dan WAF berhasil di-reload.' : 'Validasi/reload gagal.',
      output,
    };
  } catch (err) {
    return { ok: false, skipped: false, message: err.message, output: '' };
  }
}

export async function reopenWafLogs(name = WAF_CONTAINER) {
  if (!(await dockerAvailable())) return { ok: false, message: 'Docker socket tidak tersedia.' };
  try {
    const result = await execInContainer(['/bin/sh', '-c', 'nginx -s reopen'], { name, timeout: 15000 });
    return { ok: result.exitCode === 0, message: result.output.trim() };
  } catch (err) {
    return { ok: false, message: err.message };
  }
}

export async function restartWaf(name = WAF_CONTAINER) {
  if (!(await dockerAvailable())) {
    return { ok: false, skipped: true, message: 'Docker socket tidak tersedia.' };
  }
  try {
    const res = await apiRequest(
      'POST',
      `/containers/${encodeURIComponent(name)}/restart?t=10`,
      undefined,
      { timeout: 30000 }
    );
    if (res.status >= 300) throw new Error(res.json?.message || `HTTP ${res.status}`);
    return { ok: true, message: 'Container WAF sedang direstart.' };
  } catch (err) {
    return { ok: false, message: err.message };
  }
}

export async function containerLogs(name = WAF_CONTAINER, tail = 200) {
  if (!(await dockerAvailable())) return { ok: false, message: 'Docker socket tidak tersedia.' };
  try {
    const res = await apiRequest(
      'GET',
      `/containers/${encodeURIComponent(name)}/logs?stdout=1&stderr=1&tail=${tail}&timestamps=0`,
      undefined,
      { binary: true, timeout: 8000 }
    );
    if (res.status >= 300) throw new Error(`HTTP ${res.status}`);
    return { ok: true, output: parseMultiplexed(res.buffer) };
  } catch (err) {
    return { ok: false, message: err.message };
  }
}
