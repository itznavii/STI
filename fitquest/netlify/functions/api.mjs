// The whole FitQuest backend as ONE Netlify Function, mounted at /api/*.
import {
  HttpError, bad, forbidden, notFound, conflict, ID_RE,
  tx, read, ensureSchema, getPool, getDoc, putDoc, patchDoc, delDoc, find,
} from '../lib/db.mjs';
import { authenticate, signToken, publicUser, hashPassword, verifyPassword } from '../lib/auth.mjs';
import * as L from '../lib/logic.mjs';
import { tzName, dateIso } from '../lib/time.mjs';

// ---------- boot: schema + first-run seed, once per function instance ----------
let booted = null;
export function _resetBoot() { booted = null; }
function boot() {
  if (!booted) {
    booted = (async () => { await ensureSchema(); await tx((c) => L.seed(c)); })()
      .catch((e) => { booted = null; throw e; });
  }
  return booted;
}

// ---------- tiny in-memory rate limiter (per function instance; best effort) ----------
const hits = new Map();
function limit(key, max, windowMs) {
  const now = Date.now();
  const h = hits.get(key);
  if (!h || now - h.start > windowMs) { hits.set(key, { n: 1, start: now }); return; }
  if (++h.n > max) throw new HttpError(429, 'Too many attempts — wait a few minutes and try again.');
}
function clearLimit(key) { hits.delete(key); }
function clientIp(req) {
  return req.headers.get('x-nf-client-connection-ip') || (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'unknown';
}

// ---------- helpers ----------
const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
});
async function readBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'DELETE') return {};
  const text = await req.text();
  if (text.length > 50000) throw new HttpError(413, 'Request too large');
  if (!text.trim()) return {};
  let v;
  try { v = JSON.parse(text); } catch { throw bad('Invalid JSON'); }
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw bad('Expected a JSON object');
  return v;
}
const needId = (id) => { if (!ID_RE.test(id)) throw bad('Bad id'); return id; };

// ---------- what each role may read through the generic query endpoints ----------
const OPEN = new Set(['quests', 'rewards', 'seasonal', 'team_ups']);
const OWN_BY_USERID = new Set(['completions', 'seasonal_completions', 'checkins', 'xp_tx', 'rp_tx', 'notifications', 'member_achievements', 'redemptions', 'loyalty_stamps']);
const STAFF_READ = new Set(['users', 'referrals', 'audit_logs', 'leaderboard_awards', ...OPEN, ...OWN_BY_USERID]);
const stripUser = (d) => { const { passwordHash, ...rest } = d; return rest; }; // eslint-disable-line no-unused-vars

function readRule(user, coll) {
  if (user.role === 'staff') {
    if (!STAFF_READ.has(coll)) throw forbidden();
    return { forced: [], canSee: () => true };
  }
  if (OPEN.has(coll)) return { forced: [], canSee: () => true };
  if (OWN_BY_USERID.has(coll)) return { forced: [['userId', '==', user.id]], canSee: (d) => d.userId === user.id };
  if (coll === 'referrals') return { forced: [['referrerId', '==', user.id]], canSee: (d) => d.referrerId === user.id };
  if (coll === 'users') return { forced: null, canSee: (d, id) => id === user.id }; // single own doc only
  throw forbidden();
}
const shape = (coll, id, data) => ({ id, data: coll === 'users' ? stripUser(data) : data });

// Generic writes are staff-only and limited to catalogue data. Everything that moves
// points or statuses goes through the action endpoints, never through these.
const GENERIC_WRITE = { quests: ['PUT', 'PATCH', 'DELETE'], rewards: ['PUT', 'PATCH', 'DELETE'], seasonal: ['DELETE'] };
const NUM_FIELDS = { quests: ['xpReward', 'rpReward'], rewards: ['cost', 'totalQty', 'availableQty', 'redeemedQty'] };
function checkCatalogShape(coll, body) {
  for (const f of (Object.hasOwn(NUM_FIELDS, coll) ? NUM_FIELDS[coll] : [])) {
    if (f in body && (!Number.isFinite(body[f]) || body[f] < 0 || body[f] > 1e7)) throw bad(f + ' must be a non-negative number');
  }
  for (const f of ['title', 'name', 'category', 'difficulty']) {
    if (f in body && (typeof body[f] !== 'string' || body[f].length > 80)) throw bad(f + ' must be short text');
  }
}

// ---------- route table ----------
const routes = [];
const route = (method, pattern, handler, pub = false) => routes.push({ method, pub, re: new RegExp('^' + pattern.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '/?$'), handler });

// -- accounts --
route('POST', '/api/auth/register', async ({ req, body }) => {
  limit('reg|' + clientIp(req), 20, 3600000);
  const { id, data } = await tx((c) => L.register(c, body));
  const token = await signToken(getPool(), id);
  return { token, user: publicUser(id, data), tz: tzName(), today: dateIso(Date.now()) };
}, true);
route('POST', '/api/auth/login', async ({ req, body }) => {
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const pass = typeof body.password === 'string' ? body.password : '';
  const key = 'login|' + clientIp(req) + '|' + email;
  limit(key, 8, 600000);
  const row = await L.findUserForLogin(getPool(), email);
  const v = row ? await verifyPassword(pass, row.data.passwordHash) : { ok: false };
  if (!row || !v.ok) throw new HttpError(401, 'Incorrect email or password');
  clearLimit(key);
  if (v.upgrade) await patchDoc(getPool(), 'users', row.id, { passwordHash: await hashPassword(pass) });
  return { token: await signToken(getPool(), row.id), user: publicUser(row.id, row.data), tz: tzName(), today: dateIso(Date.now()) };
}, true);
route('GET', '/api/auth/me', async ({ user }) => ({ user: publicUser(user.id, user), tz: tzName(), today: dateIso(Date.now()) }));

// -- member actions --
route('GET', '/api/home', ({ user }) => read((c) => L.home(c, user)));
route('POST', '/api/checkin', ({ user }) => tx((c) => L.checkIn(c, user)));
route('POST', '/api/quests/:id/submit', ({ user, params }) => tx((c) => L.submitQuest(c, user, needId(params.id))));
route('POST', '/api/seasonal/:id/submit', ({ user, params }) => tx((c) => L.submitSeasonal(c, user, needId(params.id))));
route('POST', '/api/rewards/:id/redeem', ({ user, params }) => tx((c) => L.redeemReward(c, user, needId(params.id))));
route('POST', '/api/redemptions/:id/cancel', ({ user, params }) => tx((c) => L.cancelRedemption(c, user, needId(params.id))));
route('POST', '/api/teams', ({ user, body }) => tx((c) => L.createTeam(c, user, body)));
route('POST', '/api/teams/:id/join', ({ user, params }) => tx((c) => L.joinTeam(c, user, needId(params.id))));
route('POST', '/api/teams/:id/leave', ({ user, params }) => tx((c) => L.leaveTeam(c, user, needId(params.id))));
route('PATCH', '/api/profile', ({ user, body }) => tx((c) => L.updateProfile(c, user, body)));
route('POST', '/api/notifications/read-all', ({ user }) => tx((c) => L.readAllNotifications(c, user)));
route('GET', '/api/leaderboard', ({ user, url }) =>
  read((c) => L.leaderboard(c, user, url.searchParams.get('range') || 'week', url.searchParams.get('metric') || 'xp')));

// -- staff actions --
route('POST', '/api/completions/:id/decision', ({ user, params, body }) => tx((c) => L.decideCompletion(c, user, needId(params.id), body.decision)));
route('POST', '/api/seasonal-completions/:id/decision', ({ user, params, body }) => tx((c) => L.decideSeasonal(c, user, needId(params.id), body.decision)));
route('POST', '/api/redemptions/:id/decision', ({ user, params, body }) => tx((c) => L.decideRedemption(c, user, needId(params.id), body.decision)));
route('POST', '/api/members/:id/adjust', ({ user, params, body }) => tx((c) => L.adjustMember(c, user, needId(params.id), body)));
route('POST', '/api/members/:id/renew', ({ user, params }) => tx((c) => L.renewMember(c, user, needId(params.id))));
route('POST', '/api/seasonal', ({ user, body }) => tx((c) => L.createSeasonal(c, user, body)));
route('POST', '/api/leaderboard/award', ({ user, body }) => tx((c) => L.awardTop3(c, user, body.range, body.metric)));

// -- generic reads --
route('GET', '/api/doc/:coll/:id', async ({ user, params }) => {
  const { coll, id } = params; needId(id);
  const rule = readRule(user, coll);
  const data = await read((c) => getDoc(c, coll, id));
  if (data === undefined || !rule.canSee(data, id)) return { id, exists: false, data: null };
  return { id, exists: true, data: shape(coll, id, data).data };
});
route('GET', '/api/collection/:coll', async ({ user, params, url }) => {
  const { coll } = params;
  const rule = readRule(user, coll);
  if (rule.forced === null) throw forbidden();
  let q = {};
  try { q = JSON.parse(url.searchParams.get('query') || '{}'); } catch { throw bad('Bad query'); }
  const wheres = [...(Array.isArray(q.wheres) ? q.wheres : []), ...rule.forced];
  const docs = await read((c) => find(c, coll, {
    wheres, orderBy: q.orderByField || null, dir: q.orderByDir, limit: q.limitN,
  }));
  return { docs: docs.map((d) => shape(coll, d.id, d.data)) };
});

// -- generic catalogue writes (staff) --
for (const m of ['PUT', 'PATCH', 'DELETE']) {
  route(m, '/api/doc/:coll/:id', async ({ user, params, body }) => {
    if (user.role !== 'staff') throw forbidden('Staff only');
    const { coll, id } = params; needId(id);
    if (!Object.hasOwn(GENERIC_WRITE, coll) || !GENERIC_WRITE[coll].includes(m)) throw forbidden();
    if (m === 'DELETE') { await tx((c) => delDoc(c, coll, id)); return { ok: true }; }
    checkCatalogShape(coll, body);
    if (m === 'PUT') await tx((c) => putDoc(c, coll, id, body));
    else if (!(await tx((c) => patchDoc(c, coll, id, body)))) throw notFound();
    return { ok: true };
  });
}

// ---------- entry point ----------
export default async (req) => {
  try {
    const url = new URL(req.url);
    const path = url.pathname;
    let matched = null;
    for (const r of routes) {
      if (r.method !== req.method) continue;
      const m = r.re.exec(path);
      if (m) { matched = { r, params: { ...(m.groups || {}) } }; break; }
    }
    if (!matched) {
      const exists = routes.some((r) => r.re.test(path));
      return json({ error: exists ? 'Method not allowed' : 'Not found' }, exists ? 405 : 404);
    }
    await boot();
    const body = await readBody(req);
    const user = matched.r.pub ? null : await authenticate(getPool(), req);
    const out = await matched.r.handler({ req, url, body, user, params: matched.params });
    return json(out);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    if (e && e.code === '23505') return json({ error: 'That already exists' }, 409);
    console.error('[fitquest]', e);
    return json({ error: 'Server error' }, 500);
  }
};

export const config = { path: '/api/*' };
