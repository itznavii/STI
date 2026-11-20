process.env.APP_TIMEZONE = 'Asia/Manila';
import { boot, call, ok, summary } from './harness.mjs';
import { dateIso, dayStart, periodStart, periodKey } from '../netlify/lib/time.mjs';
import crypto from 'node:crypto';

const pool = await boot();

// ---------- time helpers ----------
{
  const t = Date.UTC(2026, 9, 3, 17, 0, 0); // 01:00 on Oct 4 in Manila
  ok(dateIso(t, 'Asia/Manila') === '2026-10-04', 'manila date rolls over before UTC does');
  ok(dateIso(t, 'UTC') === '2026-10-03', 'utc date');
  ok(dayStart(t, 'Asia/Manila') === Date.UTC(2026, 9, 3, 16, 0, 0), 'manila day start');
  ok(dayStart(Date.UTC(2026, 9, 14, 12), 'America/Los_Angeles') === Date.UTC(2026, 9, 14, 7), 'LA midnight in PDT');
  ok(dayStart(Date.UTC(2026, 10, 2, 12), 'America/Los_Angeles') === Date.UTC(2026, 10, 2, 8), 'LA midnight in PST');
  const wed = Date.UTC(2026, 9, 14, 4); // Wed Oct 14 2026
  ok(periodStart('week', wed, 'Asia/Manila') === Date.UTC(2026, 9, 11, 16), 'week starts Monday');
  ok(periodStart('month', wed, 'Asia/Manila') === Date.UTC(2026, 8, 30, 16), 'month start');
  ok(periodKey('month', 'xp', wed, 'Asia/Manila') === 'xp_month_2026-10', 'month key');
}

// ---------- basics ----------
let r = await call('GET', '/api/home');
ok(r.status === 401, 'unauthenticated is 401', r);
r = await call('GET', '/api/nope');
ok(r.status === 404, '404 for unknown route');
r = await call('GET', '/api/checkin');
ok(r.status === 405, '405 wrong method');
r = await call('POST', '/api/auth/login', { raw: '{bad' });
ok(r.status === 400 && !JSON.stringify(r.json).includes('at '), 'invalid JSON is a clean 400', r);
r = await call('POST', '/api/auth/login', { body: { email: 'staff@fitquest.demo', password: 'wrong' } });
ok(r.status === 401 && r.json.error === 'Incorrect email or password', 'bad password', r);
r = await call('POST', '/api/auth/login', { body: { email: 'nobody@x.com', password: 'x' } });
ok(r.status === 401 && r.json.error === 'Incorrect email or password', 'unknown email gives same message (no enumeration)', r);
r = await call('POST', '/api/auth/login', { body: { email: 'STAFF@fitquest.demo', password: 'staff123' } });
ok(r.status === 200 && r.json.user.role === 'staff' && !('passwordHash' in r.json.user), 'staff login (case-insensitive email), no hash leaked', r);
const S = r.json.token;
ok(r.json.tz === 'Asia/Manila', 'tz returned');

// ---------- registration ----------
r = await call('POST', '/api/auth/register', { body: { name: 'Ana', email: 'ana@x.com', password: '123' } });
ok(r.status === 400, 'short password rejected', r);
r = await call('POST', '/api/auth/register', { body: { name: 'Ana', email: 'not-an-email', password: '123456' } });
ok(r.status === 400, 'bad email rejected', r);
r = await call('POST', '/api/auth/register', { body: { name: "Ana O'Brien", email: 'Ana@x.com', password: 'secret1', phone: '0999' } });
ok(r.status === 200 && !('passwordHash' in r.json.user) && r.json.user.role === 'member', 'register ana', r);
const A = r.json.token, aId = r.json.user.id, aCode = r.json.user.referralCode;
ok(/^FQ[A-Z2-9]{6}$/.test(aCode), 'referral code format', aCode);
r = await call('POST', '/api/auth/register', { body: { name: 'Ana2', email: 'ANA@x.com', password: 'secret1' } });
ok(r.status === 409, 'duplicate email (any case) rejected', r);
r = await call('POST', '/api/auth/register', { body: { name: 'Nope', email: 'nope@x.com', password: 'secret1', refCode: 'FQ000000' } });
ok(r.status === 400 && /Referral code not found/.test(r.json.error), 'unknown referral code is an error, not silently ignored', r);
r = await call('POST', '/api/auth/login', { body: { email: 'nope@x.com', password: 'secret1' } });
ok(r.status === 401, 'and no account was created by the failed registration');
r = await call('POST', '/api/auth/register', { body: { name: 'Ben Cruz', email: 'ben@x.com', password: 'secret1', refCode: aCode.toLowerCase() } });
const B = r.json.token, bId = r.json.user.id;
ok(r.status === 200 && r.json.referralApplied === true, 'register ben with referral (lowercase code works)', r);
r = await call('POST', '/api/auth/register', { body: { name: 'X', email: 'staff@fitquest.demo', password: 'secret1' } });
ok(r.status === 409, 'cannot register the staff email', r);

// ---------- tokens ----------
r = await call('GET', '/api/auth/me', { token: A });
ok(r.status === 200 && r.json.user.email === 'ana@x.com', 'me', r);
r = await call('GET', '/api/auth/me', { token: A.slice(0, -3) + 'xxx' });
ok(r.status === 401, 'tampered signature rejected');
const [body] = A.split('.');
const forged = Buffer.from(JSON.stringify({ uid: 'staffdemo', exp: Date.now() + 1e9 })).toString('base64url');
r = await call('GET', '/api/auth/me', { token: forged + '.' + A.split('.')[1] });
ok(r.status === 401, 'forged payload rejected');

// ---------- read access rules ----------
r = await call('GET', '/api/collection/users', { token: A });
ok(r.status === 403, 'member cannot list users', r);
r = await call('GET', '/api/doc/users/staffdemo', { token: A });
ok(r.json && r.json.exists === false, 'member cannot read the staff doc');
r = await call('GET', '/api/doc/users/' + aId, { token: A });
ok(r.json.exists && !('passwordHash' in r.json.data), 'member reads own doc without hash');
r = await call('GET', '/api/doc/users/' + bId, { token: A });
ok(r.json.exists === false, "member cannot read another member's doc");
r = await call('GET', '/api/collection/users', { token: S });
ok(r.status === 200 && r.json.docs.length === 3 && r.json.docs.every((d) => !('passwordHash' in d.data)), 'staff lists users with no hashes', r.json && r.json.docs.length);
for (const coll of ['meta', 'audit_logs', 'leaderboard_awards', '__proto__', 'constructor']) {
  r = await call('GET', '/api/collection/' + coll, { token: A });
  ok(r.status === 403, 'member forbidden: ' + coll, r.status);
}
r = await call('GET', '/api/collection/meta', { token: S });
ok(r.status === 403, 'even staff cannot read meta (session secret)');
r = await call('GET', '/api/doc/meta/session_secret', { token: S });
ok(r.status === 403, 'even staff cannot read the session secret doc');
r = await call('GET', '/api/collection/quests', { token: A });
const quests = r.json.docs; ok(quests.length === 4, 'seeded quests visible', quests.length);
const qIds = quests.map((d) => d.id);

// ---------- write access rules ----------
r = await call('PUT', '/api/doc/quests/zzz', { token: A, body: { title: 'x', xpReward: 1e6 } });
ok(r.status === 403, 'member cannot create quests');
r = await call('PATCH', '/api/doc/users/' + aId, { token: A, body: { xp: 99999, role: 'staff' } });
ok(r.status === 403, 'member cannot edit own xp/role', r);
r = await call('PUT', '/api/doc/users/' + aId, { token: S, body: { role: 'staff' } });
ok(r.status === 403, 'staff cannot bulk-write users through the generic API either');
r = await call('PUT', '/api/doc/quests/q_ok1', { token: S, body: { title: 'Plank', category: 'Strength', difficulty: 'Easy', xpReward: 10, rpReward: 10, active: true, repeatable: true, createdAt: 1 } });
ok(r.status === 200, 'staff creates quest', r);
r = await call('PUT', '/api/doc/quests/q_bad', { token: S, body: { title: 'x', xpReward: 'lots' } });
ok(r.status === 400, 'quest shape validated', r);
r = await call('PUT', '/api/doc/__proto__/x', { token: S, body: { a: 1 } });
ok(r.status === 403 && ({}).x === undefined, 'prototype-pollution attempt blocked');
r = await call('GET', '/api/doc/quests/' + encodeURIComponent('a b'), { token: A });
ok(r.status === 400, 'bad id rejected');
r = await call('GET', '/api/collection/quests?query=' + encodeURIComponent(JSON.stringify({ wheres: [["title') OR 1=1 --", '==', 'x']] })), { token: A });
ok(r.status === 400, 'sql-injection-looking field rejected', r);
r = await call('GET', '/api/collection/quests?query=' + encodeURIComponent(JSON.stringify({ wheres: [['title', '==', "x' OR '1'='1"]] })), { token: A });
ok(r.status === 200 && r.json.docs.length === 0, 'sql-injection-looking value is just a value', r);
r = await call('POST', '/api/members/' + aId + '/adjust', { token: A, body: { xp: 9999, reason: 'me' } });
ok(r.status === 403, 'member cannot adjust own balance', r);
r = await call('POST', '/api/auth/login', { raw: 'x'.repeat(60000) });
ok(r.status === 413, 'oversized body rejected', r.status);
await call('DELETE', '/api/doc/quests/q_ok1', { token: S });

// ---------- check-in ----------
const [c1, c2] = await Promise.all([call('POST', '/api/checkin', { token: A }), call('POST', '/api/checkin', { token: A })]);
ok([c1.status, c2.status].sort().join() === '200,409', 'two simultaneous check-ins: exactly one wins', [c1.status, c2.status]);
r = await call('GET', '/api/auth/me', { token: A });
ok(r.json.user.xp === 10 && r.json.user.rp === 5 && r.json.user.streak === 1, 'check-in awards once', r.json.user);
ok((c1.json && c1.json.unlocked || c2.json && c2.json.unlocked || []).includes('First Check-In'), 'achievement reported');
r = await call('GET', '/api/home', { token: A });
ok(r.json.checkedInToday === true && r.json.today === dateIso(Date.now()), 'home reports checked in', r.json);
r = await call('POST', '/api/checkin', { token: S });
ok(r.status === 403, 'staff cannot check in');

// ---------- quests + verification ----------
r = await call('POST', '/api/quests/' + qIds[0] + '/submit', { token: A });
ok(r.status === 200, 'submit quest', r);
r = await call('POST', '/api/quests/' + qIds[0] + '/submit', { token: A });
ok(r.status === 409, 'duplicate pending submit blocked', r);
r = await call('POST', '/api/quests/nope/submit', { token: A });
ok(r.status === 404, 'unknown quest', r);
let comps = (await call('GET', '/api/collection/completions?query=' + encodeURIComponent(JSON.stringify({ wheres: [['status', '==', 'pending']] })), { token: S })).json.docs;
ok(comps.length === 1, 'staff sees pending', comps.length);
r = await call('POST', '/api/completions/' + comps[0].id + '/decision', { token: A, body: { decision: 'approved' } });
ok(r.status === 403, 'member cannot approve own quest', r);
r = await call('POST', '/api/completions/' + comps[0].id + '/decision', { token: S, body: { decision: 'maybe' } });
ok(r.status === 400, 'bad decision rejected');
r = await call('POST', '/api/completions/' + comps[0].id + '/decision', { token: S, body: { decision: 'approved' } });
ok(r.status === 200, 'staff approves', r);
r = await call('POST', '/api/completions/' + comps[0].id + '/decision', { token: S, body: { decision: 'approved' } });
ok(r.status === 409, 'cannot approve twice', r);
r = await call('GET', '/api/auth/me', { token: A });
ok(r.json.user.xp === 20 && r.json.user.rp === 15, 'quest awarded 10/10', r.json.user);
// ---------- referrals: staff approve, nothing is paid automatically ----------
r = await call('GET', '/api/collection/referrals', { token: A });
ok(r.json.docs.length === 1 && r.json.docs[0].data.status === 'pending' && r.json.docs[0].data.referredName === 'Ben', 'referrer sees the friend by first name, pending', r.json.docs);
ok(!JSON.stringify(r.json).includes('Cruz') && !JSON.stringify(r.json).includes('ben@x.com'), "referrer sees only the friend's first name");
r = await call('GET', '/api/collection/notifications', { token: A });
ok(r.json.docs.some((d) => /Ben signed up with your referral code/.test(d.data.msg)), 'referrer is told the code was used');
// ben's quest being approved must NOT pay the referral any more
r = await call('POST', '/api/quests/' + qIds[1] + '/submit', { token: B });
comps = (await call('GET', '/api/collection/completions?query=' + encodeURIComponent(JSON.stringify({ wheres: [['status', '==', 'pending']] })), { token: S })).json.docs;
await call('POST', '/api/completions/' + comps[0].id + '/decision', { token: S, body: { decision: 'approved' } });
r = await call('GET', '/api/auth/me', { token: A });
ok(r.json.user.rp === 15, 'quest approval alone does not pay the referral', r.json.user.rp);
const refDoc = (await call('GET', '/api/collection/referrals?query=' + encodeURIComponent(JSON.stringify({ wheres: [['status', '==', 'pending']] })), { token: S })).json.docs;
ok(refDoc.length === 1, 'staff see the pending referral');
r = await call('POST', '/api/referrals/' + refDoc[0].id + '/decision', { token: A, body: { decision: 'approved' } });
ok(r.status === 403, 'referrer cannot approve their own referral');
r = await call('POST', '/api/referrals/' + refDoc[0].id + '/decision', { token: B, body: { decision: 'approved' } });
ok(r.status === 403, 'the friend cannot approve it either');
r = await call('POST', '/api/referrals/' + refDoc[0].id + '/decision', { token: S, body: { decision: 'whatever' } });
ok(r.status === 400, 'bad decision rejected');
r = await call('POST', '/api/referrals/' + refDoc[0].id + '/decision', { token: S, body: { decision: 'approved' } });
ok(r.status === 200, 'staff approve referral', r);
r = await call('GET', '/api/auth/me', { token: A });
ok(r.json.user.rp === 115, 'referrer gets +100 RP on approval', r.json.user.rp);
r = await call('POST', '/api/referrals/' + refDoc[0].id + '/decision', { token: S, body: { decision: 'approved' } });
ok(r.status === 409, 'cannot be paid twice', r);
r = await call('GET', '/api/collection/notifications', { token: A });
ok(r.json.docs.some((d) => /Referral approved: \+100 RP/.test(d.data.msg)), 'referrer is notified of the approval');
r = await call('GET', '/api/collection/member_achievements', { token: A });
ok(r.json.docs.some((d) => d.data.achId === 'refer1'), 'Refer a Friend achievement unlocked');
// rejection path pays nothing
r = await call('POST', '/api/auth/register', { body: { name: 'Cara Lim', email: 'cara@x.com', password: 'secret1', refCode: aCode } });
const cId = r.json.user.id;
const pend = (await call('GET', '/api/collection/referrals?query=' + encodeURIComponent(JSON.stringify({ wheres: [['status', '==', 'pending']] })), { token: S })).json.docs;
ok(pend.length === 1 && pend[0].data.referredId === cId, 'second referral queued');
r = await call('POST', '/api/referrals/' + pend[0].id + '/decision', { token: S, body: { decision: 'rejected' } });
ok(r.status === 200 && (await call('GET', '/api/auth/me', { token: A })).json.user.rp === 115, 'rejected referral pays nothing');
r = await call('POST', '/api/auth/register', { body: { name: 'Self', email: 'self@x.com', password: 'secret1', refCode: '' } });
ok(r.status === 200 && (await call('GET', '/api/collection/referrals', { token: r.json.token })).json.docs.length === 0, 'no code = no referral record');
// daily cap: ana already has 1 quest award today; approve 3 more -> 3rd+ is capped (cap = 3/day)
for (const q of qIds) await call('POST', '/api/quests/' + q + '/submit', { token: A });
comps = (await call('GET', '/api/collection/completions?query=' + encodeURIComponent(JSON.stringify({ wheres: [['status', '==', 'pending']], orderByField: 'submittedAt' })), { token: S })).json.docs;
ok(comps.length === 4, 'four pending', comps.length);
for (const c of comps) await call('POST', '/api/completions/' + c.id + '/decision', { token: S, body: { decision: 'approved' } });
r = await call('GET', '/api/auth/me', { token: A });
ok(r.json.user.xp === 40, 'daily cap stops XP after 3 awards (20 + 2x10)', r.json.user);
r = await call('GET', '/api/collection/completions?query=' + encodeURIComponent(JSON.stringify({ wheres: [['xpAwarded', '==', 0]] })), { token: A });
ok(r.json.docs.length === 2, 'two capped approvals recorded', r.json.docs.length);

// ---------- deleted quest must not break verification ----------
await call('PUT', '/api/doc/quests/q_tmp', { token: S, body: { title: 'Temp', category: 'Cardio', difficulty: 'Easy', xpReward: 10, rpReward: 10, active: true, repeatable: true, createdAt: 1 } });
await call('POST', '/api/quests/q_tmp/submit', { token: B });
await call('DELETE', '/api/doc/quests/q_tmp', { token: S });
comps = (await call('GET', '/api/collection/completions?query=' + encodeURIComponent(JSON.stringify({ wheres: [['questId', '==', 'q_tmp']] })), { token: S })).json.docs;
r = await call('POST', '/api/completions/' + comps[0].id + '/decision', { token: S, body: { decision: 'approved' } });
ok(r.status === 409 && /deleted/.test(r.json.error), 'approving a deleted quest gives a clear error, not a crash', r);
r = await call('POST', '/api/completions/' + comps[0].id + '/decision', { token: S, body: { decision: 'rejected' } });
ok(r.status === 200, 'can still reject it');

// ---------- manual adjustments ----------
r = await call('POST', '/api/members/' + aId + '/adjust', { token: S, body: { xp: 0, rp: 5000, reason: '' } });
ok(r.status === 400, 'reason required');
r = await call('POST', '/api/members/' + aId + '/adjust', { token: S, body: { rp: 5000, reason: 'promo' } });
ok(r.status === 200, 'staff adds RP', r);
r = await call('POST', '/api/members/' + aId + '/adjust', { token: S, body: { rp: -99999, reason: 'oops' } });
ok(r.status === 400, 'cannot deduct more RP than the member has', r);
r = await call('POST', '/api/members/' + bId + '/adjust', { token: S, body: { xp: -5000, reason: 'test clamp' } });
r = await call('GET', '/api/auth/me', { token: B });
ok(r.json.user.xp === 0 && r.json.user.level === 1, 'xp clamps at 0, level never below 1', r.json.user);
r = await call('GET', '/api/collection/audit_logs', { token: S });
ok(r.json.docs.length === 2, 'audit entries written only for successful adjustments', r.json.docs.length);
r = await call('POST', '/api/members/staffdemo/adjust', { token: S, body: { rp: 5, reason: 'x' } });
ok(r.status === 404, 'cannot adjust a staff account');

// ---------- level / rank controller ----------
r = await call('POST', '/api/auth/register', { body: { name: 'Lena Rank', email: 'lena@x.com', password: 'secret1' }, ip: '9.9.9.9' });
const LR = r.json.token, lrId = r.json.user.id;
r = await call('POST', '/api/members/' + lrId + '/level-rank', { token: LR, body: { level: 50, reason: 'me' } });
ok(r.status === 403, 'member cannot set own level/rank', r);
r = await call('POST', '/api/members/' + lrId + '/level-rank', { token: S, body: { level: 5 } });
ok(r.status === 400, 'level/rank change needs a reason', r);
r = await call('POST', '/api/members/' + lrId + '/level-rank', { token: S, body: { reason: 'x' } });
ok(r.status === 400, 'must choose a level or a rank', r);
for (const bad of [0, 101, 2.5, 'abc', -3]) {
  r = await call('POST', '/api/members/' + lrId + '/level-rank', { token: S, body: { level: bad, reason: 'x' } });
  ok(r.status === 400, 'rejects level ' + JSON.stringify(bad), r);
}
r = await call('POST', '/api/members/' + lrId + '/level-rank', { token: S, body: { rank: 'god', reason: 'x' } });
ok(r.status === 400, 'rejects unknown rank', r);
r = await call('POST', '/api/members/' + lrId + '/level-rank', { token: S, body: { level: 5, rank: 'hero', reason: 'VIP' } });
ok(r.status === 200 && r.json.level === 5 && r.json.rank === 'hero', 'staff sets level 5 and rank hero', r);
r = await call('GET', '/api/auth/me', { token: LR });
ok(r.json.user.level === 5 && r.json.user.xp === 400 && r.json.user.rankOverride === 'hero', 'member data updated (level 5 = 400 XP)', r.json.user);
r = await call('GET', '/api/collection/notifications', { token: LR });
ok(r.json.docs.some((d) => /Staff updated your level 5 and rank hero/.test(d.data.msg)), 'member is notified', r.json.docs.map((d) => d.data.msg));
ok(r.json.docs.some((d) => /Level 5/.test(d.data.msg) || /Level up/.test(d.data.msg)), 'level-up notification fires when raised');
r = await call('POST', '/api/members/' + lrId + '/level-rank', { token: S, body: { level: 5, rank: 'hero', reason: 'again' } });
ok(r.status === 400 && /Nothing changed/.test(r.json.error), 'no-op change is refused', r);
r = await call('POST', '/api/members/' + lrId + '/level-rank', { token: S, body: { level: 2, rank: 'auto', reason: 'demoted' } });
ok(r.status === 200, 'staff lowers level and resets rank to auto', r);
r = await call('GET', '/api/auth/me', { token: LR });
ok(r.json.user.level === 2 && r.json.user.xp === 100 && !r.json.user.rankOverride, 'level 2 = 100 XP, rank override cleared', r.json.user);
r = await call('GET', '/api/leaderboard?range=month&metric=xp', { token: LR });
ok(!r.json.rows.some((x) => x.userId === lrId), 'manual level changes do not count toward leaderboards');
r = await call('GET', '/api/collection/audit_logs', { token: S });
ok(r.json.docs.filter((d) => d.data.action === 'Changed level/rank').length === 2, 'each successful change is in the audit log');
r = await call('POST', '/api/members/staffdemo/level-rank', { token: S, body: { level: 3, reason: 'x' } });
ok(r.status === 404, 'cannot change level/rank of a staff account');

// ---------- rewards ----------
const rewards = (await call('GET', '/api/collection/rewards', { token: A })).json.docs;
const towel = rewards.find((d) => d.data.name === 'Portable Mini Towel').id;
const cap = rewards.find((d) => d.data.name === 'FitQuest Cap').id;
let me = (await call('GET', '/api/auth/me', { token: A })).json.user; const rpBefore = me.rp;
r = await call('POST', '/api/rewards/' + towel + '/redeem', { token: A });
ok(r.status === 200, 'redeem', r);
me = (await call('GET', '/api/auth/me', { token: A })).json.user;
ok(me.rp === rpBefore - 1200, 'RP held on request', me.rp);
let reds = (await call('GET', '/api/collection/redemptions', { token: A })).json.docs;
ok(reds.length === 1 && reds[0].data.cost === 1200, 'redemption uses server-side price');
r = await call('POST', '/api/redemptions/' + reds[0].id + '/cancel', { token: B });
ok(r.status === 404, "cannot cancel someone else's redemption", r);
r = await call('POST', '/api/redemptions/' + reds[0].id + '/cancel', { token: A });
ok(r.status === 200, 'cancel', r);
me = (await call('GET', '/api/auth/me', { token: A })).json.user;
ok(me.rp === rpBefore, 'cancel refunds', me.rp);
r = await call('POST', '/api/rewards/' + cap + '/redeem', { token: B });
ok(r.status === 409 && /Not enough/.test(r.json.error), 'not enough RP', r);
await call('POST', '/api/rewards/' + towel + '/redeem', { token: A });
reds = (await call('GET', '/api/collection/redemptions?query=' + encodeURIComponent(JSON.stringify({ wheres: [['status', '==', 'pending']] })), { token: S })).json.docs;
r = await call('POST', '/api/redemptions/' + reds[0].id + '/decision', { token: S, body: { decision: 'approved' } });
ok(r.status === 200, 'approve redemption', r);
const rw = (await call('GET', '/api/doc/rewards/' + towel, { token: A })).json.data;
ok(rw.availableQty === 19 && rw.redeemedQty === 1, 'stock decremented');
// reward deleted while pending -> refund
await call('POST', '/api/rewards/' + cap + '/redeem', { token: A });
await call('DELETE', '/api/doc/rewards/' + cap, { token: S });
reds = (await call('GET', '/api/collection/redemptions?query=' + encodeURIComponent(JSON.stringify({ wheres: [['status', '==', 'pending']] })), { token: S })).json.docs;
const before2 = (await call('GET', '/api/auth/me', { token: A })).json.user.rp;
r = await call('POST', '/api/redemptions/' + reds[0].id + '/decision', { token: S, body: { decision: 'approved' } });
const after2 = (await call('GET', '/api/auth/me', { token: A })).json.user.rp;
ok(r.status === 200 && after2 === before2 + 3400, 'deleted reward -> auto-reject with refund', { before2, after2 });

// ---------- teams ----------
r = await call('POST', '/api/teams', { token: A, body: { name: 'Iron <b>Crew</b>', goalTarget: 2 } });
ok(r.status === 200, 'create team', r);
r = await call('POST', '/api/teams', { token: A, body: { name: 'Second' } });
ok(r.status === 409, 'cannot create a second team while in one', r);
let teams = (await call('GET', '/api/collection/team_ups', { token: B })).json.docs;
ok(teams.length === 1, 'members can browse teams');
r = await call('POST', '/api/teams/' + teams[0].id + '/join', { token: B });
ok(r.status === 200, 'ben joins', r);
r = await call('POST', '/api/teams/' + teams[0].id + '/join', { token: B });
ok(r.status === 409, 'cannot join twice');
const xpA = (await call('GET', '/api/auth/me', { token: A })).json.user.xp;
// ben completes two quests (his daily cap is not an issue, he has 1 so far)
for (const q of [qIds[2], qIds[3]]) {
  await call('POST', '/api/quests/' + q + '/submit', { token: B });
  const p = (await call('GET', '/api/collection/completions?query=' + encodeURIComponent(JSON.stringify({ wheres: [['status', '==', 'pending'], ['userId', '==', bId]] })), { token: S })).json.docs;
  await call('POST', '/api/completions/' + p[0].id + '/decision', { token: S, body: { decision: 'approved' } });
}
teams = (await call('GET', '/api/collection/team_ups', { token: A })).json.docs;
ok(teams[0].data.status === 'completed' && teams[0].data.rewarded, 'team completes at goal', teams[0].data);
ok((await call('GET', '/api/auth/me', { token: A })).json.user.xp === xpA + 50, 'team reward paid to every member');
r = await call('POST', '/api/teams', { token: A, body: { name: 'Solo', goalTarget: -5 } });
ok(r.status === 200, 'new team ok after the old one completed');
teams = (await call('GET', '/api/collection/team_ups?query=' + encodeURIComponent(JSON.stringify({ wheres: [['status', '==', 'active']] })), { token: A })).json.docs;
ok(teams[0].data.goalTarget === 1, 'goal clamped to >= 1');
r = await call('POST', '/api/teams/' + teams[0].id + '/leave', { token: A });
teams = (await call('GET', '/api/collection/team_ups?query=' + encodeURIComponent(JSON.stringify({ wheres: [['status', '==', 'active']] })), { token: A })).json.docs;
ok(teams.length === 0, 'team disbands when the last member leaves');

// ---------- seasonal ----------
const today = dateIso(Date.now());
r = await call('POST', '/api/seasonal', { token: S, body: { name: 'Bad', start: '', end: '' } });
ok(r.status === 400, 'seasonal needs dates (no more NaN)', r);
r = await call('POST', '/api/seasonal', { token: S, body: { name: 'Bad', start: '2026-10-10', end: '2026-10-01' } });
ok(r.status === 400, 'end before start rejected');
r = await call('POST', '/api/seasonal', { token: A, body: { name: 'Sneaky', start: today, end: today } });
ok(r.status === 403, 'member cannot create seasonal');
r = await call('POST', '/api/seasonal', { token: S, body: { name: 'Today Only', description: 'd', start: today, end: today } });
ok(r.status === 200, 'create seasonal that ends today', r);
let seas = (await call('GET', '/api/collection/seasonal', { token: A })).json.docs;
ok(seas.length === 1 && seas[0].data.startDate <= Date.now() && Date.now() <= seas[0].data.endDate, 'end day is included (active all day)');
r = await call('POST', '/api/seasonal/' + seas[0].id + '/submit', { token: A });
ok(r.status === 200, 'submit seasonal');
r = await call('POST', '/api/seasonal/' + seas[0].id + '/submit', { token: A });
ok(r.status === 409, 'no double submit');
let sc = (await call('GET', '/api/collection/seasonal_completions', { token: S })).json.docs;
const xpS = (await call('GET', '/api/auth/me', { token: A })).json.user.xp;
r = await call('POST', '/api/seasonal-completions/' + sc[0].id + '/decision', { token: S, body: { decision: 'approved' } });
ok(r.status === 200 && (await call('GET', '/api/auth/me', { token: A })).json.user.xp === xpS + 25, 'seasonal approved +25 XP', r);

// ---------- renewals / loyalty ----------
const exp0 = (await call('GET', '/api/auth/me', { token: B })).json.user.membershipExpiry;
r = await call('POST', '/api/members/' + bId + '/renew', { token: B });
ok(r.status === 403, 'members cannot renew themselves for free');
r = await call('POST', '/api/members/' + bId + '/renew', { token: S });
let bu = (await call('GET', '/api/auth/me', { token: B })).json.user;
ok(r.status === 200 && bu.membershipExpiry === exp0 + 30 * 86400000 && bu.loyaltyStamps === 1, 'staff renewal extends 30 days + stamp', bu);
const rpB = bu.rp;
for (let i = 0; i < 11; i++) await call('POST', '/api/members/' + bId + '/renew', { token: S });
bu = (await call('GET', '/api/auth/me', { token: B })).json.user;
ok(bu.loyaltyStamps === 12 && bu.rp === rpB + 500, '12th stamp pays the 500 RP bonus', bu);

// ---------- leaderboards ----------
r = await call('POST', '/api/leaderboard/award', { token: S, body: { range: 'week', metric: 'xp' } });
ok(r.status === 200 && r.json.count === 2, 'award top members', r);
r = await call('POST', '/api/leaderboard/award', { token: S, body: { range: 'week', metric: 'xp' } });
ok(r.status === 409, 'a period can only be awarded once');
r = await call('POST', '/api/leaderboard/award', { token: A, body: { range: 'week', metric: 'xp' } });
ok(r.status === 403, 'members cannot award');
r = await call('GET', '/api/leaderboard?range=year&metric=xp', { token: A });
ok(r.status === 400, 'bad range rejected');
r = await call('PATCH', '/api/profile', { token: B, body: { hideOnBoard: true, nickname: 'ShadowShadowShadowShadowShadow' } });
ok(r.status === 200, 'ben hides himself', r);
r = await call('GET', '/api/leaderboard?range=week&metric=xp', { token: A });
const hidden = r.json.rows.find((x) => x.userId === bId);
ok(hidden && hidden.u.name === 'Hidden hero' && !JSON.stringify(r.json).includes('Ben') && !JSON.stringify(r.json).includes('ben@x.com') && !JSON.stringify(r.json).includes('Shadow'), "hidden member's real name never reaches other members", hidden);
ok(!JSON.stringify(r.json).includes('passwordHash') && !('rp' in r.json.rows[0].u), 'leaderboard leaks no hash / RP to members');
r = await call('GET', '/api/leaderboard?range=week&metric=xp', { token: S });
ok(r.json.rows.find((x) => x.userId === bId).u.name === 'Ben Cruz' && r.json.awarded, 'staff sees real names + awarded state');
r = await call('GET', '/api/leaderboard?range=month&metric=quests', { token: A });
ok(r.status === 200 && r.json.rows.length >= 1, 'quest leaderboard');

// ---------- leaderboard reset ----------
r = await call('POST', '/api/leaderboard/reset', { token: A, body: { reason: 'me' } });
ok(r.status === 403, 'members cannot reset the leaderboard', r);
r = await call('POST', '/api/leaderboard/reset/undo', { token: A });
ok(r.status === 403, 'members cannot undo a reset', r);
r = await call('POST', '/api/leaderboard/reset', { token: S, body: {} });
ok(r.status === 400, 'reset needs a reason', r);
r = await call('POST', '/api/leaderboard/reset/undo', { token: S });
ok(r.status === 409, 'cannot undo when nothing was reset', r);
r = await call('GET', '/api/leaderboard?range=month&metric=xp', { token: S });
const rowsBefore = r.json.rows.length;
ok(rowsBefore >= 1 && r.json.resetAt === null, 'before reset: board has rows and no reset time', r.json);
const xpBefore = (await call('GET', '/api/auth/me', { token: A })).json.user.xp;
await new Promise((res) => setTimeout(res, 15));
r = await call('POST', '/api/leaderboard/reset', { token: S, body: { reason: 'New season' } });
ok(r.status === 200 && r.json.resetAt > 0, 'staff resets the leaderboard', r);
for (const [range, metric] of [['today', 'xp'], ['week', 'xp'], ['month', 'xp'], ['week', 'quests'], ['month', 'quests']]) {
  r = await call('GET', `/api/leaderboard?range=${range}&metric=${metric}`, { token: A });
  ok(r.status === 200 && r.json.rows.length === 0 && r.json.resetAt > 0, `${range}/${metric} board is empty right after reset`, r.json);
}
ok((await call('GET', '/api/auth/me', { token: A })).json.user.xp === xpBefore, 'reset does not touch members XP');
r = await call('POST', '/api/leaderboard/award', { token: S, body: { range: 'week', metric: 'xp' } });
ok(r.status === 400, 'nothing to award on an empty board', r);
r = await call('POST', '/api/checkin', { token: LR });
ok(r.status === 200, 'member checks in after the reset', r);
r = await call('GET', '/api/leaderboard?range=week&metric=xp', { token: S });
ok(r.json.rows.length === 1 && r.json.rows[0].userId === lrId && r.json.rows[0].val === 10 && r.json.awarded === null, 'only activity after the reset counts, and the new round is not yet awarded', r.json);
r = await call('POST', '/api/leaderboard/award', { token: S, body: { range: 'week', metric: 'xp' } });
ok(r.status === 200 && r.json.count === 1, 'the new round can be awarded even though the old week was awarded', r);
r = await call('POST', '/api/leaderboard/award', { token: S, body: { range: 'week', metric: 'xp' } });
ok(r.status === 409, 'the new round can only be awarded once');
r = await call('POST', '/api/leaderboard/reset/undo', { token: S });
ok(r.status === 200, 'staff undoes the reset', r);
r = await call('GET', '/api/leaderboard?range=month&metric=xp', { token: S });
ok(r.json.rows.length >= rowsBefore && r.json.resetAt === null, 'after undo the full board is back', r.json);
r = await call('POST', '/api/leaderboard/award', { token: S, body: { range: 'week', metric: 'xp' } });
ok(r.status === 409, 'after undo the original week is still marked awarded');
r = await call('POST', '/api/leaderboard/reset/undo', { token: S });
ok(r.status === 409, 'cannot undo twice');
r = await call('GET', '/api/collection/audit_logs', { token: S });
ok(r.json.docs.some((d) => d.data.action === 'Reset leaderboards' && d.data.reason === 'New season') && r.json.docs.some((d) => d.data.action === 'Undid leaderboard reset'), 'reset and undo are in the audit log');
r = await call('GET', '/api/doc/meta/leaderboard_reset', { token: S });
ok(r.status === 403, 'reset marker is not readable through the generic API');

// ---------- reset award ----------
const awardBody = (o = {}) => ({ range: 'week', metric: 'xp', reason: 'Awarded by mistake', ...o });
r = await call('POST', '/api/leaderboard/award/reset', { token: A, body: awardBody() });
ok(r.status === 403, 'members cannot reset an award', r);
r = await call('POST', '/api/leaderboard/award/reset', { token: S, body: awardBody({ reason: '' }) });
ok(r.status === 400, 'reset award needs a reason', r);
r = await call('POST', '/api/leaderboard/award/reset', { token: S, body: awardBody({ range: 'year' }) });
ok(r.status === 400, 'reset award rejects a bad range', r);
r = await call('POST', '/api/leaderboard/award/reset', { token: S, body: awardBody({ range: 'month', metric: 'quests' }) });
ok(r.status === 409, 'cannot reset a period that was not awarded', r);
const rpOf = async (tok) => (await call('GET', '/api/auth/me', { token: tok })).json.user.rp;
const weekKey = (await call('GET', '/api/leaderboard?range=week&metric=xp', { token: S })).json.key;
const winners = (await call('GET', '/api/collection/leaderboard_awards', { token: S })).json.docs.find((d) => d.id === weekKey).data.winners;
const winTok = { [aId]: A, [bId]: B };
const awRp = {}; for (const w of winners) awRp[w.userId] = await rpOf(winTok[w.userId]);
ok(winners.length >= 1 && winners.every((w) => winTok[w.userId]), 'found the winners of the awarded week', winners);
r = await call('POST', '/api/leaderboard/award/reset', { token: S, body: awardBody() });
ok(r.status === 200 && r.json.takeBack === true && r.json.recovered === winners.reduce((n, w) => n + Math.min(w.rp, awRp[w.userId]), 0), 'staff resets the award and takes the RP back', r);
for (const w of winners) ok(await rpOf(winTok[w.userId]) === awRp[w.userId] - Math.min(w.rp, awRp[w.userId]), 'winner RP reduced by the award', w);
r = await call('GET', '/api/leaderboard?range=week&metric=xp', { token: S });
ok(r.json.awarded === null, 'the board shows the period as not awarded after the reset');
r = await call('POST', '/api/leaderboard/award/reset', { token: S, body: awardBody() });
ok(r.status === 409, 'cannot reset the same award twice');
r = await call('GET', '/api/collection/notifications', { token: winTok[winners[0].userId] });
ok(r.json.docs.some((d) => /withdrew your leaderboard award/.test(d.data.msg)), 'winner is notified that the award was withdrawn');
r = await call('POST', '/api/leaderboard/award', { token: S, body: { range: 'week', metric: 'xp' } });
ok(r.status === 200, 'the period can be awarded again after the reset', r);
for (const w of winners) ok(await rpOf(winTok[w.userId]) === awRp[w.userId], 'winners are back to the original RP after re-award', w);
r = await call('POST', '/api/leaderboard/award/reset', { token: S, body: awardBody({ takeBack: false, reason: 'Redo, keep RP' }) });
ok(r.status === 200 && r.json.takeBack === false && r.json.recovered === 0, 'reset can keep the RP the winners received', r);
for (const w of winners) ok(await rpOf(winTok[w.userId]) === awRp[w.userId], 'RP untouched when "keep RP" is chosen', w);
r = await call('GET', '/api/collection/audit_logs', { token: S });
ok(r.json.docs.some((d) => /Reset leaderboard award \(RP taken back\)/.test(d.data.action)) && r.json.docs.some((d) => /Reset leaderboard award \(RP kept\)/.test(d.data.action)), 'award resets are in the audit log');
// RP a winner already spent is not clawed back below zero
r = await call('POST', '/api/leaderboard/reset', { token: S, body: { reason: 'round for clamp test' } });
r = await call('POST', '/api/auth/register', { body: { name: 'Sam Spend', email: 'sam@x.com', password: 'secret1' }, ip: '8.8.8.8' });
const SP = r.json.token, spId = r.json.user.id;
await call('POST', '/api/checkin', { token: SP });
r = await call('POST', '/api/leaderboard/award', { token: S, body: { range: 'week', metric: 'xp' } });
ok(r.status === 200 && r.json.count === 1 && await rpOf(SP) === 105, 'new round awards Sam 100 RP (+5 check-in)', r);
await call('POST', '/api/members/' + spId + '/adjust', { token: S, body: { rp: -90, reason: 'simulate spending' } });
r = await call('POST', '/api/leaderboard/award/reset', { token: S, body: awardBody() });
ok(r.status === 200 && r.json.recovered === 15 && r.json.missing === 85 && await rpOf(SP) === 0, 'only the RP Sam still has is taken back, never below zero', r);
await call('POST', '/api/leaderboard/reset/undo', { token: S });

// ---------- profile ----------
r = await call('PATCH', '/api/profile', { token: A, body: { avatar: 'evil.png' } });
ok(r.status === 400, 'avatar whitelist');
r = await call('PATCH', '/api/profile', { token: A, body: { goal: 'Become a god' } });
ok(r.status === 400, 'goal whitelist');
r = await call('PATCH', '/api/profile', { token: A, body: { xp: 99999, role: 'staff', favorites: ['Cardio', 'Hax'], nickname: '  Annie  ', avatar: 'av2' } });
me = (await call('GET', '/api/auth/me', { token: A })).json.user;
ok(r.status === 200 && me.role === 'member' && me.xp < 99999 && me.nickname === 'Annie' && me.favorites.join() === 'Cardio' && me.avatar === 'av2', 'profile ignores xp/role and unknown favorites', me);

// ---------- notifications ----------
r = await call('GET', '/api/collection/notifications?query=' + encodeURIComponent(JSON.stringify({ wheres: [['read', '==', false]] })), { token: A });
ok(r.json.docs.length > 0, 'unread notifications exist');
r = await call('POST', '/api/notifications/read-all', { token: A });
r = await call('GET', '/api/collection/notifications?query=' + encodeURIComponent(JSON.stringify({ wheres: [['read', '==', false]] })), { token: A });
ok(r.json.docs.length === 0, 'read-all clears them');
r = await call('GET', '/api/collection/notifications?query=' + encodeURIComponent(JSON.stringify({ wheres: [['userId', '==', bId]] })), { token: A });
ok(r.json.docs.length === 0, "cannot read another member's notifications by naming their id");

// ---------- legacy hash + staff password env ----------
const legacy = crypto.createHash('sha256').update('oldpass').digest('hex');
await pool.query(`INSERT INTO docs(coll,id,data) VALUES('users','legacy1',$1::jsonb)`, [JSON.stringify({ name: 'Old', email: 'old@x.com', passwordHash: legacy, role: 'member', xp: 0, rp: 0, level: 1, createdAt: 1, membershipStart: 1 })]);
r = await call('POST', '/api/auth/login', { body: { email: 'old@x.com', password: 'oldpass' } });
ok(r.status === 200, 'legacy sha256 account can still log in', r);
const row = await pool.query(`SELECT data->>'passwordHash' h FROM docs WHERE id='legacy1'`);
ok(row.rows[0].h.startsWith('scrypt$'), 'and is upgraded to salted scrypt');

// ---------- login throttle ----------
let last;
for (let i = 0; i < 10; i++) last = await call('POST', '/api/auth/login', { body: { email: 'throttle@x.com', password: 'nope' }, ip: '9.9.9.9' });
ok(last.status === 429, 'repeated bad logins get throttled', last.status);
r = await call('POST', '/api/auth/login', { body: { email: 'ana@x.com', password: 'secret1' }, ip: '2.2.2.2' });
ok(r.status === 200, 'normal login unaffected by someone else being throttled');

// ---------- nothing sensitive in any member-visible payload ----------
for (const path of ['/api/collection/quests', '/api/collection/rewards', '/api/collection/team_ups', '/api/collection/seasonal']) {
  const t = JSON.stringify((await call('GET', path, { token: A })).json);
  ok(!/passwordHash|scrypt\$|session_secret/.test(t), 'no secrets in ' + path);
}

summary('API tests');
