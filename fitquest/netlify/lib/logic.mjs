// FitQuest business rules. These used to run in the browser (which meant any
// member could edit their own XP/RP). Now every point-changing action runs here,
// inside a database transaction, after the caller's identity and role are checked.
import {
  getDoc, putDoc, patchDoc, delDoc, insertOnce, find, countDocs,
  newId, bad, forbidden, notFound, conflict,
} from './db.mjs';
import { hashPassword, verifyPassword } from './auth.mjs';
import {
  dateIso, dayStart, yesterdayIso, periodStart, periodKey, localMidnight, tzName,
} from './time.mjs';

export const GOALS = ['Build strength', 'Lose weight', 'Improve cardio', 'Get more flexible', 'Stay active'];
export const CATS = ['Cardio', 'Strength', 'Upper Body', 'Lower Body', 'Glutes', 'Flexibility'];
const AVATARS = ['av1', 'av2', 'av3'];
const DAILY_QUEST_CAP = 3;

export const ACH = [
  { id: 'first_workout', name: 'First Workout', check: (s) => s.completions >= 1 },
  { id: 'first_checkin', name: 'First Check-In', check: (s) => s.checkins >= 1 },
  { id: 'streak3', name: '3-Day Streak', check: (s) => s.longestStreak >= 3 },
  { id: 'streak7', name: '7-Day Streak', check: (s) => s.longestStreak >= 7 },
  { id: 'streak30', name: '30-Day Streak', check: (s) => s.longestStreak >= 30 },
  { id: 'streak100', name: '100-Day Streak', check: (s) => s.longestStreak >= 100 },
  { id: 'workouts10', name: '10 Workouts', check: (s) => s.completions >= 10 },
  { id: 'workouts50', name: '50 Workouts', check: (s) => s.completions >= 50 },
  { id: 'workouts100', name: '100 Workouts', check: (s) => s.completions >= 100 },
  { id: 'xp1000', name: '1,000 XP', check: (s) => s.xp >= 1000 },
  { id: 'xp5000', name: '5,000 XP', check: (s) => s.xp >= 5000 },
  { id: 'xp10000', name: '10,000 XP', check: (s) => s.xp >= 10000 },
  { id: 'level5', name: 'Level 5', check: (s) => s.level >= 5 },
  { id: 'jointeam', name: 'Join a Team', check: (s) => s.teamsJoined >= 1 },
  { id: 'teamcomplete', name: 'Complete Team Challenge', check: (s) => s.teamsCompleted >= 1 },
  { id: 'refer1', name: 'Refer a Friend', check: (s) => s.referrals >= 1 },
  { id: 'loyal12', name: '12 Stamps', check: (s) => s.loyaltyStamps >= 12 },
  { id: 'loyal24', name: '24 Stamps', check: (s) => s.loyaltyStamps >= 24 },
  { id: 'checkin10', name: '10 Gym Visits', check: (s) => s.checkins >= 10 },
  { id: 'checkin50', name: '50 Gym Visits', check: (s) => s.checkins >= 50 },
  { id: 'checkin100', name: '100 Gym Visits', check: (s) => s.checkins >= 100 },
];

// ---------- small helpers ----------
const levelFromXp = (xp) => Math.floor(xp / 100) + 1;
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const toInt = (v) => { const n = Number(v); return Number.isFinite(n) ? Math.trunc(n) : 0; };
const requireRole = (user, role) => { if (user.role !== role) throw forbidden(role === 'staff' ? 'Staff only' : 'Members only'); };

async function notify(c, userId, msg) {
  await putDoc(c, 'notifications', newId(), { userId, msg, read: false, createdAt: Date.now() });
}
async function logTx(c, coll, userId, amount, source, refId) {
  await putDoc(c, coll, newId(), { userId, amount, source, refId: refId || '', createdAt: Date.now() });
}

// XP never drops below 0 (a negative staff adjustment is clamped).
async function addXP(c, userId, amount, source, refId) {
  if (!amount) return 0;
  const u = await getDoc(c, 'users', userId);
  if (!u) return 0;
  const before = u.xp || 0;
  const after = Math.max(0, before + amount);
  const real = after - before;
  if (!real) return 0;
  const level = levelFromXp(after);
  await patchDoc(c, 'users', userId, { xp: after, level });
  await logTx(c, 'xp_tx', userId, real, source, refId);
  if (level > (u.level || 1)) await notify(c, userId, 'Level up! You reached level ' + level + '.');
  return real;
}
async function addRP(c, userId, amount, source, refId) {
  if (!amount) return 0;
  const u = await getDoc(c, 'users', userId);
  if (!u) return 0;
  const before = u.rp || 0;
  const after = Math.max(0, before + amount);
  if (after === before) return 0;
  await patchDoc(c, 'users', userId, { rp: after });
  await logTx(c, 'rp_tx', userId, after - before, source, refId);
  return after - before;
}
async function spendRP(c, userId, amount, source, refId) {
  const u = await getDoc(c, 'users', userId);
  if (!u || (u.rp || 0) < amount) return false;
  await patchDoc(c, 'users', userId, { rp: u.rp - amount });
  await logTx(c, 'rp_tx', userId, -amount, source, refId);
  return true;
}
async function bumpStreak(c, userId) {
  const u = await getDoc(c, 'users', userId);
  const today = dateIso(Date.now());
  if (!u || u.lastActivityDate === today) return;
  const streak = u.lastActivityDate === yesterdayIso() ? (u.streak || 0) + 1 : 1;
  await patchDoc(c, 'users', userId, {
    streak, longestStreak: Math.max(u.longestStreak || 0, streak), lastActivityDate: today,
  });
}
// Returns names of newly unlocked achievements.
async function evaluateAchievements(c, userId) {
  const u = await getDoc(c, 'users', userId);
  if (!u) return [];
  const [completions, checkins, teamsJoined, teamsCompleted, referrals, unlocked] = await Promise.all([
    countDocs(c, 'completions', [['userId', '==', userId], ['status', '==', 'approved']]),
    countDocs(c, 'checkins', [['userId', '==', userId]]),
    countDocs(c, 'team_ups', [['memberIds', 'array-contains', userId]]),
    countDocs(c, 'team_ups', [['memberIds', 'array-contains', userId], ['status', '==', 'completed']]),
    countDocs(c, 'referrals', [['referrerId', '==', userId], ['rewarded', '==', true]]),
    find(c, 'member_achievements', { wheres: [['userId', '==', userId]] }),
  ]);
  const stats = {
    completions, checkins, teamsJoined, teamsCompleted, referrals,
    longestStreak: u.longestStreak || 0, level: u.level || 1, xp: u.xp || 0, loyaltyStamps: u.loyaltyStamps || 0,
  };
  const have = new Set(unlocked.map((d) => d.data.achId));
  const fresh = [];
  for (const a of ACH) {
    if (!have.has(a.id) && a.check(stats)) {
      const inserted = await insertOnce(c, 'member_achievements', userId + '_' + a.id, { userId, achId: a.id, unlockedAt: Date.now() });
      if (inserted) { await notify(c, userId, 'Achievement unlocked: ' + a.name); fresh.push(a.name); }
    }
  }
  return fresh;
}

// ---------- seed (runs once per cold start) ----------
export async function seed(c) {
  const email = (process.env.STAFF_EMAIL || 'staff@fitquest.demo').toLowerCase();
  const pw = process.env.STAFF_PASSWORD || 'staff123';
  const staff = await getDoc(c, 'users', 'staffdemo');
  if (!staff) {
    await putDoc(c, 'users', 'staffdemo', {
      name: 'Staff Demo', email, passwordHash: await hashPassword(pw), role: 'staff',
      xp: 0, rp: 0, level: 1, streak: 0, longestStreak: 0, lastActivityDate: null,
      createdAt: Date.now(), membershipStart: Date.now(),
    });
    if (!process.env.STAFF_PASSWORD) console.warn('[fitquest] STAFF_PASSWORD is not set — using the default demo staff password. Set it in Netlify env vars.');
  } else {
    const patch = {};
    if (staff.email !== email) patch.email = email;
    if (process.env.STAFF_PASSWORD && !(await verifyPassword(pw, staff.passwordHash)).ok) patch.passwordHash = await hashPassword(pw);
    if (Object.keys(patch).length) await patchDoc(c, 'users', 'staffdemo', patch);
  }
  if (!(await getDoc(c, 'meta', 'seeded'))) {
    for (const [title, category, difficulty] of [['Cardio Blast', 'Cardio', 'Easy'], ['Leg Day Finisher', 'Lower Body', 'Medium'], ['Upper Body Pump', 'Upper Body', 'Medium'], ['Core Circuit', 'Strength', 'Easy']]) {
      await putDoc(c, 'quests', newId(), { title, category, difficulty, xpReward: 10, rpReward: 10, active: true, repeatable: true, createdAt: Date.now() });
    }
    for (const [name, cost] of [['Portable Mini Towel', 1200], ['Shake Bottle', 1800], ['Resistance Band', 3300], ['FitQuest Cap', 3400], ['FitQuest Shirt', 3600], ['10% Membership Discount', 3000], ['20% Membership Discount', 6000]]) {
      await putDoc(c, 'rewards', newId(), { name, cost, totalQty: 20, availableQty: 20, redeemedQty: 0, active: true });
    }
    await putDoc(c, 'meta', 'seeded', { at: Date.now() });
  }
}

// ---------- accounts ----------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
async function newReferralCode(c) {
  for (;;) {
    let code = 'FQ';
    for (let i = 0; i < 6; i++) code += CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)];
    if (!(await countDocs(c, 'users', [['referralCode', '==', code]]))) return code;
  }
}

export async function register(c, b) {
  const name = str(b.name, 60), email = str(b.email, 120).toLowerCase(), phone = str(b.phone, 30);
  const pass = typeof b.password === 'string' ? b.password : '', refCode = str(b.refCode, 20).toUpperCase();
  if (!name || !email || !pass) throw bad('Fill all required fields');
  if (!EMAIL_RE.test(email)) throw bad('Enter a valid email address');
  if (pass.length < 6 || pass.length > 200) throw bad('Password must be at least 6 characters');
  const taken = await c.query(`SELECT 1 FROM docs WHERE coll='users' AND lower(data->>'email') = $1`, [email]);
  if (taken.rowCount) throw conflict('Email already registered');
  const id = newId(), now = Date.now();
  const data = {
    name, email, phone, passwordHash: await hashPassword(pass), role: 'member', xp: 0, rp: 0, level: 1,
    streak: 0, longestStreak: 0, lastActivityDate: null, createdAt: now, membershipStart: now,
    membershipExpiry: now + 30 * 86400000, referralCode: await newReferralCode(c), loyaltyStamps: 0,
  };
  await putDoc(c, 'users', id, data);
  if (refCode) {
    const [ref] = await find(c, 'users', { wheres: [['referralCode', '==', refCode]], limit: 1 });
    if (ref && ref.id !== id) await putDoc(c, 'referrals', newId(), { referrerId: ref.id, referredId: id, status: 'pending', rewarded: false, createdAt: now });
  }
  return { id, data };
}

// Not run inside tx(): read-only except for the optional hash upgrade.
export async function findUserForLogin(pool, emailRaw) {
  const email = str(emailRaw, 120).toLowerCase();
  const r = await pool.query(`SELECT id, data FROM docs WHERE coll='users' AND lower(data->>'email') = $1 LIMIT 1`, [email]);
  return r.rows[0] || null;
}

// ---------- member actions ----------
export async function checkIn(c, user) {
  requireRole(user, 'member');
  const today = dateIso(Date.now());
  if (await countDocs(c, 'checkins', [['userId', '==', user.id], ['date', '==', today]])) throw conflict('Already checked in today');
  await putDoc(c, 'checkins', newId(), { userId: user.id, date: today, createdAt: Date.now() });
  await addXP(c, user.id, 10, 'checkin', '');
  await addRP(c, user.id, 5, 'checkin', '');
  await bumpStreak(c, user.id);
  const unlocked = await evaluateAchievements(c, user.id);
  await notify(c, user.id, 'Checked in! +10 XP, +5 RP.');
  return { ok: true, unlocked };
}

export async function submitQuest(c, user, questId) {
  requireRole(user, 'member');
  const quest = await getDoc(c, 'quests', questId);
  if (!quest || !quest.active) throw notFound('That quest is not available');
  if (await countDocs(c, 'completions', [['userId', '==', user.id], ['questId', '==', questId], ['status', '==', 'pending']])) throw conflict('Already submitted — waiting for staff');
  if (!quest.repeatable && await countDocs(c, 'completions', [['userId', '==', user.id], ['questId', '==', questId], ['status', '==', 'approved']])) throw conflict('You already completed this quest');
  await putDoc(c, 'completions', newId(), { userId: user.id, questId, status: 'pending', submittedAt: Date.now() });
  return { ok: true };
}

export async function submitSeasonal(c, user, seasonalId) {
  requireRole(user, 'member');
  const s = await getDoc(c, 'seasonal', seasonalId);
  const now = Date.now();
  if (!s || !(s.startDate <= now && now <= s.endDate)) throw notFound('That challenge is not active');
  if (await countDocs(c, 'seasonal_completions', [['userId', '==', user.id], ['seasonalId', '==', seasonalId]])) throw conflict('You already submitted this challenge');
  await putDoc(c, 'seasonal_completions', newId(), { userId: user.id, seasonalId, status: 'pending', submittedAt: now });
  return { ok: true };
}

export async function redeemReward(c, user, rewardId) {
  requireRole(user, 'member');
  const r = await getDoc(c, 'rewards', rewardId);
  if (!r || !r.active) throw notFound('That reward is not available');
  if ((r.availableQty || 0) <= 0) throw conflict('Out of stock');
  const id = newId();
  if (!(await spendRP(c, user.id, r.cost, 'redemption_hold', id))) throw conflict('Not enough RP');
  await putDoc(c, 'redemptions', id, { userId: user.id, rewardId, rewardName: r.name, cost: r.cost, status: 'pending', requestedAt: Date.now() });
  return { ok: true };
}

export async function cancelRedemption(c, user, redId) {
  const r = await getDoc(c, 'redemptions', redId);
  if (!r || r.userId !== user.id) throw notFound('Redemption not found');
  if (r.status !== 'pending') throw conflict('Cannot cancel — already reviewed');
  await addRP(c, r.userId, r.cost, 'redemption_refund', redId);
  await patchDoc(c, 'redemptions', redId, { status: 'cancelled', reviewedAt: Date.now() });
  return { ok: true };
}

// ---------- teams ----------
async function activeTeamOf(c, userId) {
  const [t] = await find(c, 'team_ups', { wheres: [['memberIds', 'array-contains', userId], ['status', '==', 'active']], limit: 1 });
  return t || null;
}
export async function createTeam(c, user, b) {
  requireRole(user, 'member');
  const name = str(b.name, 40);
  if (!name) throw bad('Team name required');
  const goalTarget = Math.max(1, Math.min(500, toInt(b.goalTarget) || 10));
  if (await activeTeamOf(c, user.id)) throw conflict('Leave your current team first');
  await putDoc(c, 'team_ups', newId(), { name, creatorId: user.id, memberIds: [user.id], goalTarget, progress: 0, xpReward: 50, rpReward: 50, status: 'active', rewarded: false, createdAt: Date.now() });
  return { ok: true };
}
export async function joinTeam(c, user, teamId) {
  requireRole(user, 'member');
  const t = await getDoc(c, 'team_ups', teamId);
  if (!t || t.status !== 'active') throw notFound('That team is not open');
  if (t.memberIds.includes(user.id)) throw conflict('Already a member');
  if (await activeTeamOf(c, user.id)) throw conflict('Leave your current team first');
  await patchDoc(c, 'team_ups', teamId, { memberIds: [...t.memberIds, user.id] });
  return { ok: true };
}
export async function leaveTeam(c, user, teamId) {
  const t = await getDoc(c, 'team_ups', teamId);
  if (!t || !t.memberIds.includes(user.id)) throw notFound('You are not on that team');
  const memberIds = t.memberIds.filter((m) => m !== user.id);
  await patchDoc(c, 'team_ups', teamId, memberIds.length ? { memberIds } : { memberIds, status: 'disbanded' });
  return { ok: true };
}

// ---------- profile / notifications ----------
export async function updateProfile(c, user, b) {
  const patch = {};
  if ('nickname' in b) patch.nickname = str(b.nickname, 20);
  if ('phone' in b) patch.phone = str(b.phone, 30);
  if ('goal' in b) { const g = str(b.goal, 40); if (g && !GOALS.includes(g)) throw bad('Unknown goal'); patch.goal = g; }
  if ('favorites' in b) patch.favorites = [...new Set((Array.isArray(b.favorites) ? b.favorites : []).filter((x) => CATS.includes(x)))];
  if ('hideOnBoard' in b) patch.hideOnBoard = b.hideOnBoard === true;
  if ('avatar' in b) { if (!AVATARS.includes(b.avatar)) throw bad('Unknown avatar'); patch.avatar = b.avatar; }
  if (!Object.keys(patch).length) throw bad('Nothing to update');
  await patchDoc(c, 'users', user.id, patch);
  return { ok: true };
}
export async function readAllNotifications(c, user) {
  await c.query(
    `UPDATE docs SET data = data || '{"read": true}'::jsonb WHERE coll='notifications' AND data->>'userId' = $1 AND data->>'read' = 'false'`,
    [user.id]);
  return { ok: true };
}

// ---------- staff: verification ----------
export async function decideCompletion(c, staff, compId, decision) {
  requireRole(staff, 'staff');
  if (!['approved', 'rejected'].includes(decision)) throw bad('Bad decision');
  const comp = await getDoc(c, 'completions', compId);
  if (!comp) throw notFound('Submission not found');
  if (comp.status !== 'pending') throw conflict('Already reviewed');
  if (decision === 'rejected') {
    await patchDoc(c, 'completions', compId, { status: 'rejected', reviewedAt: Date.now() });
    await notify(c, comp.userId, 'Your quest submission was rejected.');
    return { ok: true };
  }
  const quest = await getDoc(c, 'quests', comp.questId);
  if (!quest) throw conflict('That quest was deleted — reject this submission instead.');
  const now = Date.now();
  const doneToday = await countDocs(c, 'xp_tx', [['userId', '==', comp.userId], ['source', '==', 'quest'], ['createdAt', '>=', dayStart(now)]]);
  const capped = doneToday >= DAILY_QUEST_CAP;
  const xpAward = capped ? 0 : quest.xpReward, rpAward = capped ? 0 : quest.rpReward;
  await patchDoc(c, 'completions', compId, { status: 'approved', reviewedAt: now, xpAwarded: xpAward, rpAwarded: rpAward });
  if (xpAward > 0) { await addXP(c, comp.userId, xpAward, 'quest', compId); await addRP(c, comp.userId, rpAward, 'quest', compId); }
  await bumpStreak(c, comp.userId);
  await notify(c, comp.userId, capped
    ? "Quest approved, but today's XP/RP cap (" + DAILY_QUEST_CAP + ') was reached — no reward this time.'
    : `Quest approved! +${xpAward} XP, +${rpAward} RP.`);
  await evaluateAchievements(c, comp.userId);

  // referral: reward the referrer on the referred member's first approved quest
  if ((await countDocs(c, 'completions', [['userId', '==', comp.userId], ['status', '==', 'approved']])) === 1) {
    const [ref] = await find(c, 'referrals', { wheres: [['referredId', '==', comp.userId], ['rewarded', '==', false]], limit: 1 });
    if (ref) {
      await addRP(c, ref.data.referrerId, 100, 'referral', ref.id);
      await patchDoc(c, 'referrals', ref.id, { status: 'completed', rewarded: true });
      await notify(c, ref.data.referrerId, 'Referral reward: +100 RP for a successful referral!');
      await evaluateAchievements(c, ref.data.referrerId);
    }
  }
  // team-up progress
  const teams = await find(c, 'team_ups', { wheres: [['memberIds', 'array-contains', comp.userId], ['status', '==', 'active']] });
  for (const { id, data: t } of teams) {
    const progress = (t.progress || 0) + 1;
    if (progress >= t.goalTarget && !t.rewarded) {
      await patchDoc(c, 'team_ups', id, { progress, status: 'completed', rewarded: true });
      for (const m of t.memberIds) {
        await addXP(c, m, t.xpReward, 'teamup', id); await addRP(c, m, t.rpReward, 'teamup', id);
        await notify(c, m, 'Team-Up "' + t.name + '" complete! +' + t.xpReward + ' XP, +' + t.rpReward + ' RP.');
        await evaluateAchievements(c, m);
      }
    } else await patchDoc(c, 'team_ups', id, { progress });
  }
  return { ok: true };
}

export async function decideSeasonal(c, staff, id, decision) {
  requireRole(staff, 'staff');
  if (!['approved', 'rejected'].includes(decision)) throw bad('Bad decision');
  const comp = await getDoc(c, 'seasonal_completions', id);
  if (!comp) throw notFound('Submission not found');
  if (comp.status !== 'pending') throw conflict('Already reviewed');
  if (decision === 'rejected') {
    await patchDoc(c, 'seasonal_completions', id, { status: 'rejected', reviewedAt: Date.now() });
    await notify(c, comp.userId, 'Seasonal challenge submission rejected.');
    return { ok: true };
  }
  const s = await getDoc(c, 'seasonal', comp.seasonalId);
  if (!s) throw conflict('That challenge was deleted — reject this submission instead.');
  await addXP(c, comp.userId, s.xpReward, 'seasonal', id);
  await addRP(c, comp.userId, s.rpReward, 'seasonal', id);
  await patchDoc(c, 'seasonal_completions', id, { status: 'approved', reviewedAt: Date.now() });
  await notify(c, comp.userId, 'Seasonal challenge approved! +' + s.xpReward + ' XP, +' + s.rpReward + ' RP.');
  await evaluateAchievements(c, comp.userId);
  return { ok: true };
}

export async function decideRedemption(c, staff, redId, decision) {
  requireRole(staff, 'staff');
  if (!['approved', 'rejected'].includes(decision)) throw bad('Bad decision');
  const r = await getDoc(c, 'redemptions', redId);
  if (!r) throw notFound('Redemption not found');
  if (r.status !== 'pending') throw conflict('Already reviewed');
  const refuse = async (msg, note) => {
    await addRP(c, r.userId, r.cost, 'redemption_refund', redId);
    await patchDoc(c, 'redemptions', redId, { status: 'rejected', reviewedAt: Date.now() });
    await notify(c, r.userId, msg);
    return { ok: true, note };
  };
  if (decision === 'rejected') return refuse('Your redemption for ' + r.rewardName + ' was rejected — RP refunded.', 'Rejected — RP refunded');
  const reward = await getDoc(c, 'rewards', r.rewardId);
  if (!reward || (reward.availableQty || 0) <= 0) return refuse('Redemption rejected — out of stock. RP refunded.', 'Out of stock — rejected, RP refunded');
  await patchDoc(c, 'rewards', r.rewardId, { availableQty: reward.availableQty - 1, redeemedQty: (reward.redeemedQty || 0) + 1 });
  await patchDoc(c, 'redemptions', redId, { status: 'approved', reviewedAt: Date.now() });
  await notify(c, r.userId, 'Redemption approved: ' + r.rewardName + '. Ready for pickup!');
  return { ok: true };
}

// ---------- staff: members ----------
async function memberOrThrow(c, id) {
  const u = await getDoc(c, 'users', id);
  if (!u || u.role !== 'member') throw notFound('Member not found');
  return u;
}
async function audit(c, staff, action, memberId, previous, next, reason) {
  await putDoc(c, 'audit_logs', newId(), { staffId: staff.id, staffName: staff.name, action, memberId, previous, new: next, reason, createdAt: Date.now() });
}

export async function adjustMember(c, staff, memberId, b) {
  requireRole(staff, 'staff');
  const m = await memberOrThrow(c, memberId);
  const dxp = toInt(b.xp), drp = toInt(b.rp), reason = str(b.reason, 200);
  if (!reason) throw bad('Reason is required');
  if (!dxp && !drp) throw bad('Enter an XP or RP change');
  if (Math.abs(dxp) > 100000 || Math.abs(drp) > 100000) throw bad('That change is too large');
  if (drp < 0 && (m.rp || 0) < -drp) throw bad('Member only has ' + (m.rp || 0) + ' RP — cannot deduct ' + (-drp));
  const prev = { xp: m.xp || 0, rp: m.rp || 0 };
  if (dxp) await addXP(c, memberId, dxp, 'manual_adjustment', staff.id);
  if (drp > 0) await addRP(c, memberId, drp, 'manual_adjustment', staff.id);
  if (drp < 0) await spendRP(c, memberId, -drp, 'manual_adjustment', staff.id);
  const after = await getDoc(c, 'users', memberId);
  await audit(c, staff, 'Adjusted XP/RP', memberId, prev, { xp: after.xp, rp: after.rp }, reason);
  await notify(c, memberId, 'Staff adjusted your balance: ' + (dxp ? dxp + ' XP ' : '') + (drp ? drp + ' RP' : '') + ' — ' + reason);
  await evaluateAchievements(c, memberId);
  return { ok: true };
}

// In-person renewal: +30 days of membership and +1 loyalty stamp. Members cannot do this themselves.
export async function renewMember(c, staff, memberId) {
  requireRole(staff, 'staff');
  const u = await memberOrThrow(c, memberId);
  const now = Date.now();
  const base = u.membershipExpiry && u.membershipExpiry > now ? u.membershipExpiry : now;
  const membershipExpiry = base + 30 * 86400000, stamps = (u.loyaltyStamps || 0) + 1;
  await patchDoc(c, 'users', memberId, { membershipExpiry, loyaltyStamps: stamps });
  await putDoc(c, 'loyalty_stamps', newId(), { userId: memberId, createdAt: now, source: 'staff' });
  await audit(c, staff, 'Renewed membership (+30 days, +1 stamp)', memberId, { stamps: u.loyaltyStamps || 0 }, { stamps, membershipExpiry }, 'Membership renewal (in person)');
  if (stamps % 12 === 0) {
    await addRP(c, memberId, 500, 'loyalty', '');
    await notify(c, memberId, 'Loyalty milestone! 12 stamps reached — +500 RP bonus.');
  } else await notify(c, memberId, 'Membership renewed until ' + dateIso(membershipExpiry) + ' · loyalty stamp ' + (stamps % 12) + '/12.');
  await evaluateAchievements(c, memberId);
  return { ok: true };
}

export async function createSeasonal(c, staff, b) {
  requireRole(staff, 'staff');
  const name = str(b.name, 60), description = str(b.description, 200);
  const D = /^(\d{4})-(\d{2})-(\d{2})$/;
  const s = D.exec(b.start || ''), e = D.exec(b.end || '');
  if (!name) throw bad('Name required');
  if (!s || !e) throw bad('Pick a start and end date');
  const startDate = localMidnight(+s[1], +s[2], +s[3]);
  const endDate = localMidnight(+e[1], +e[2], +e[3]) + 86400000 - 1; // the whole end day counts
  if (endDate < startDate) throw bad('End date must be on or after the start date');
  await putDoc(c, 'seasonal', newId(), { name, description, startDate, endDate, xpReward: 25, rpReward: 25, createdAt: Date.now() });
  return { ok: true };
}

// ---------- leaderboards ----------
const RANGES = ['today', 'week', 'month'];
const METRICS = ['xp', 'quests'];
function checkBoardArgs(range, metric) {
  if (!RANGES.includes(range) || !METRICS.includes(metric)) throw bad('Bad leaderboard options');
}
// What other people are allowed to see about a member on a leaderboard.
function boardUser(id, u, viewer) {
  const isStaff = viewer.role === 'staff';
  const hidden = u.hideOnBoard && id !== viewer.id && !isStaff;
  const out = {
    name: hidden ? 'Hidden hero' : u.name, nickname: hidden ? '' : (u.nickname || ''), hideOnBoard: !!u.hideOnBoard,
    level: u.level, membershipStart: u.membershipStart, createdAt: u.createdAt,
  };
  if (!hidden && u.avatar) out.avatar = u.avatar;
  if (isStaff) out.rp = u.rp;
  return out;
}
async function boardRows(c, range, metric, limit) {
  const since = periodStart(range);
  const r = metric === 'xp'
    ? await c.query(
      `SELECT data->>'userId' AS uid, SUM((data->>'amount')::numeric)::int AS val FROM docs
       WHERE coll='xp_tx' AND (data->>'createdAt')::numeric >= $1 AND data->>'source' <> 'manual_adjustment'
       GROUP BY 1 HAVING SUM((data->>'amount')::numeric) > 0 ORDER BY val DESC LIMIT 100`, [since])
    : await c.query(
      `SELECT data->>'userId' AS uid, count(*)::int AS val FROM docs
       WHERE coll='completions' AND data->>'status'='approved' AND (data->>'reviewedAt')::numeric >= $1
       GROUP BY 1 ORDER BY val DESC LIMIT 100`, [since]);
  const out = [];
  for (const row of r.rows) {
    const u = await getDoc(c, 'users', row.uid);
    if (u && u.role !== 'staff') out.push({ userId: row.uid, val: row.val, user: u });
    if (out.length >= limit) break;
  }
  return out;
}
export async function leaderboard(c, viewer, range, metric) {
  checkBoardArgs(range, metric);
  const rows = await boardRows(c, range, metric, 20);
  const key = periodKey(range, metric);
  const out = { rows: rows.map((r) => ({ userId: r.userId, val: r.val, u: boardUser(r.userId, r.user, viewer) })), key };
  if (viewer.role === 'staff') {
    const done = await getDoc(c, 'leaderboard_awards', key);
    out.awarded = done ? { createdAt: done.createdAt } : null;
  }
  return out;
}
export async function awardTop3(c, staff, range, metric) {
  requireRole(staff, 'staff');
  checkBoardArgs(range, metric);
  const key = periodKey(range, metric), pts = [100, 75, 50];
  if (await getDoc(c, 'leaderboard_awards', key)) throw conflict('Already awarded for this period');
  const rows = await boardRows(c, range, metric, 3);
  if (!rows.length) throw bad('No members to reward yet');
  await putDoc(c, 'leaderboard_awards', key, { range, metric, staffId: staff.id, winners: rows.map((r, i) => ({ userId: r.userId, rp: pts[i] })), createdAt: Date.now() });
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i], before = r.user.rp || 0;
    await addRP(c, r.userId, pts[i], 'leaderboard', key);
    await notify(c, r.userId, 'Leaderboard place #' + (i + 1) + '! +' + pts[i] + ' RP');
    await audit(c, staff, 'Awarded leaderboard place #' + (i + 1) + ' (+' + pts[i] + ' RP)', r.userId, { rp: before }, { rp: before + pts[i] }, range + ' ' + metric + ' leaderboard');
  }
  return { ok: true, count: rows.length };
}

// ---------- home screen ----------
export async function home(c, user) {
  const today = dateIso(Date.now());
  const [ck, quests] = await Promise.all([
    countDocs(c, 'checkins', [['userId', '==', user.id], ['date', '==', today]]),
    countDocs(c, 'completions', [['userId', '==', user.id], ['status', '==', 'approved'], ['reviewedAt', '>=', dayStart(Date.now())]]),
  ]);
  return { checkedInToday: ck > 0, questsToday: quests, today, tz: tzName() };
}

export { delDoc };
