import { PGlite } from '@electric-sql/pglite';
import { setPool } from '../netlify/lib/db.mjs';
import { _resetBoot } from '../netlify/functions/api.mjs';
import handler from '../netlify/functions/api.mjs';

// A pg.Pool lookalike over PGlite (single connection, so a mutex plays the pool's role).
export async function makePool() {
  const pg = new PGlite();
  let chain = Promise.resolve();
  const lock = () => { let release; const p = new Promise((r) => (release = r)); const prev = chain; chain = chain.then(() => p); return prev.then(() => release); };
  const run = async (text, params) => {
    const r = await pg.query(text, params);
    const n = typeof r.affectedRows === 'number' && r.affectedRows > 0 ? r.affectedRows : r.rows.length;
    return { rows: r.rows, rowCount: n };
  };
  return {
    pg,
    async query(t, p) { const rel = await lock(); try { return await run(t, p); } finally { rel(); } },
    async connect() { const rel = await lock(); return { query: run, release: rel }; },
  };
}
export async function boot() {
  const pool = await makePool();
  setPool(pool); _resetBoot();
  return pool;
}
export async function call(method, path, { token, body, ip = '1.1.1.1', raw } = {}) {
  const headers = { 'x-nf-client-connection-ip': ip };
  if (token) headers.authorization = 'Bearer ' + token;
  if (body !== undefined || raw !== undefined) headers['content-type'] = 'application/json';
  const res = await handler(new Request('http://localhost' + path, { method, headers, body: raw !== undefined ? raw : body !== undefined ? JSON.stringify(body) : undefined }));
  let json = null; try { json = await res.json(); } catch { /* none */ }
  return { status: res.status, json };
}
let pass = 0, fail = 0;
export function ok(cond, name, extra) {
  if (cond) { pass++; } else { fail++; console.log('  FAIL:', name, extra !== undefined ? JSON.stringify(extra) : ''); }
}
export function summary(label) {
  console.log(`${label}: ${pass} passed, ${fail} failed`);
  if (fail) process.exitCode = 1;
}
