// Data layer. Everything is stored as JSON documents in one Postgres table
// (coll, id, data jsonb) so the app keeps its simple "collections of documents"
// shape. On Netlify the pool comes from @netlify/database; tests inject their own.
import crypto from 'node:crypto';
import { getDatabase } from '@netlify/database';

let pool = null;
let readyPromise = null;

export function setPool(p) { pool = p; readyPromise = null; }
export function getPool() {
  if (!pool) pool = getDatabase().pool;
  return pool;
}

export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export const bad = (m) => new HttpError(400, m);
export const forbidden = (m = 'Not allowed') => new HttpError(403, m);
export const notFound = (m = 'Not found') => new HttpError(404, m);
export const conflict = (m) => new HttpError(409, m);

export function newId() { return crypto.randomUUID().replace(/-/g, '').slice(0, 20); }
export const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS docs (
     coll text NOT NULL,
     id   text NOT NULL,
     data jsonb NOT NULL,
     PRIMARY KEY (coll, id)
   )`,
  `CREATE INDEX IF NOT EXISTS docs_user_idx ON docs (coll, (data->>'userId'))`,
  `CREATE UNIQUE INDEX IF NOT EXISTS docs_user_email_uq ON docs ((lower(data->>'email'))) WHERE coll = 'users'`,
];

export function ensureSchema() {
  if (!readyPromise) {
    readyPromise = (async () => {
      const p = getPool();
      for (const sql of SCHEMA) await p.query(sql);
    })().catch((e) => { readyPromise = null; throw e; });
  }
  return readyPromise;
}

// Run fn inside a transaction. A single advisory lock serialises all writers,
// which removes every read-modify-write race (double redemptions, lost XP...).
// This app is small, so the throughput cost doesn't matter.
export async function tx(fn) {
  await ensureSchema();
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(7311)');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    throw e;
  } finally {
    client.release();
  }
}

export async function read(fn) {
  await ensureSchema();
  return fn(getPool());
}

// ---- document helpers (c = pool or transaction client) ----
export async function getDoc(c, coll, id) {
  const r = await c.query('SELECT data FROM docs WHERE coll=$1 AND id=$2', [coll, id]);
  return r.rows[0] ? r.rows[0].data : undefined;
}
export async function putDoc(c, coll, id, data) {
  await c.query(
    'INSERT INTO docs(coll,id,data) VALUES($1,$2,$3::jsonb) ON CONFLICT (coll,id) DO UPDATE SET data=EXCLUDED.data',
    [coll, id, JSON.stringify(data)]);
}
export async function patchDoc(c, coll, id, patch) {
  const r = await c.query('UPDATE docs SET data = data || $3::jsonb WHERE coll=$1 AND id=$2', [coll, id, JSON.stringify(patch)]);
  return r.rowCount > 0;
}
export async function delDoc(c, coll, id) {
  await c.query('DELETE FROM docs WHERE coll=$1 AND id=$2', [coll, id]);
}
// Insert only if absent. Returns true when inserted.
export async function insertOnce(c, coll, id, data) {
  const r = await c.query('INSERT INTO docs(coll,id,data) VALUES($1,$2,$3::jsonb) ON CONFLICT DO NOTHING', [coll, id, JSON.stringify(data)]);
  return r.rowCount > 0;
}

const FIELD_RE = /^[A-Za-z0-9_]{1,40}$/;
const OPS = new Set(['==', '!=', '<', '<=', '>', '>=', 'array-contains']);

function buildConds(coll, wheres, params) {
  params.push(coll);
  const conds = ['coll = $1'];
  for (const w of wheres) {
    if (!Array.isArray(w) || w.length !== 3) throw bad('Bad query');
    const [f, op, v] = w;
    if (typeof f !== 'string' || !FIELD_RE.test(f) || !OPS.has(op)) throw bad('Bad query');
    params.push(f); const col = `(data -> $${params.length}::text)`;
    params.push(JSON.stringify(op === 'array-contains' ? [v] : v)); const val = `$${params.length}::jsonb`;
    if (op === '==') conds.push(`${col} = ${val}`);
    else if (op === '!=') conds.push(`${col} IS DISTINCT FROM ${val}`);
    else if (op === 'array-contains') conds.push(`(jsonb_typeof(${col}) = 'array' AND ${col} @> ${val})`);
    else conds.push(`${col} ${op} ${val}`);
  }
  return conds;
}

// Query a collection. wheres = [[field, op, value], ...]
export async function find(c, coll, { wheres = [], orderBy = null, dir = 'asc', limit = null } = {}) {
  const params = [];
  const conds = buildConds(coll, wheres, params);
  let order = 'ORDER BY id';
  if (orderBy) {
    if (typeof orderBy !== 'string' || !FIELD_RE.test(orderBy)) throw bad('Bad query');
    params.push(orderBy);
    order = `ORDER BY (data -> $${params.length}::text) ${dir === 'desc' ? 'DESC' : 'ASC'} NULLS LAST, id`;
  }
  const n = limit != null ? Math.max(1, Math.min(500, parseInt(limit, 10) || 1)) : 2000;
  const r = await c.query(`SELECT id, data FROM docs WHERE ${conds.join(' AND ')} ${order} LIMIT ${n}`, params);
  return r.rows.map((x) => ({ id: x.id, data: x.data }));
}

export async function countDocs(c, coll, wheres = []) {
  const params = [];
  const conds = buildConds(coll, wheres, params);
  const r = await c.query(`SELECT count(*)::int AS n FROM docs WHERE ${conds.join(' AND ')}`, params);
  return r.rows[0].n;
}
