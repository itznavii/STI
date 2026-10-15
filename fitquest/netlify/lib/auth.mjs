import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { getDoc, putDoc, HttpError } from './db.mjs';

const scrypt = promisify(crypto.scrypt);
const b64 = (b) => Buffer.from(b).toString('base64url');

export async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 64);
  return `scrypt$${salt.toString('hex')}$${h.toString('hex')}`;
}
// Returns { ok, upgrade } — upgrade=true when a legacy unsalted SHA-256 hash matched.
export async function verifyPassword(pw, stored) {
  if (typeof stored !== 'string') return { ok: false };
  if (stored.startsWith('scrypt$')) {
    const [, saltHex, hashHex] = stored.split('$');
    const h = await scrypt(pw, Buffer.from(saltHex, 'hex'), 64);
    const want = Buffer.from(hashHex, 'hex');
    return { ok: want.length === h.length && crypto.timingSafeEqual(want, h) };
  }
  if (/^[0-9a-f]{64}$/.test(stored)) {
    const h = crypto.createHash('sha256').update(pw).digest('hex');
    return { ok: h === stored, upgrade: h === stored };
  }
  return { ok: false };
}

let secretCache = null;
async function getSecret(c) {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  if (secretCache) return secretCache;
  let doc = await getDoc(c, 'meta', 'session_secret');
  if (!doc) {
    // first run: generate one and keep it in the database so every function instance agrees
    await c.query(`INSERT INTO docs(coll,id,data) VALUES('meta','session_secret',$1::jsonb) ON CONFLICT DO NOTHING`,
      [JSON.stringify({ secret: crypto.randomBytes(32).toString('hex') })]);
    doc = await getDoc(c, 'meta', 'session_secret');
  }
  secretCache = doc.secret;
  return secretCache;
}
export function _resetSecretCache() { secretCache = null; }

const SESSION_MS = 30 * 86400000;
export async function signToken(c, uid) {
  const body = b64(JSON.stringify({ uid, exp: Date.now() + SESSION_MS }));
  const sig = crypto.createHmac('sha256', await getSecret(c)).update(body).digest('base64url');
  return `${body}.${sig}`;
}
export async function verifyToken(c, token) {
  if (typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const want = crypto.createHmac('sha256', await getSecret(c)).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(want);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}

// Fields that must never leave the server.
export function publicUser(id, u) {
  if (!u) return null;
  const { passwordHash, ...rest } = u; // eslint-disable-line no-unused-vars
  return { ...rest, id };
}

export async function authenticate(c, req) {
  const h = req.headers.get('authorization') || '';
  const m = /^Bearer (.+)$/.exec(h);
  if (!m) throw new HttpError(401, 'Please log in');
  const p = await verifyToken(c, m[1]);
  if (!p) throw new HttpError(401, 'Session expired — please log in again');
  const u = await getDoc(c, 'users', p.uid);
  if (!u) throw new HttpError(401, 'Account not found');
  return { id: p.uid, ...u };
}
