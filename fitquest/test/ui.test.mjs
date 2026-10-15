process.env.APP_TIMEZONE = 'Asia/Manila';
import fs from 'node:fs';
import { JSDOM, VirtualConsole } from 'jsdom';
import { boot, ok, summary } from './harness.mjs';
import handler from '../netlify/functions/api.mjs';

await boot();
await handler(new Request('http://localhost/api/auth/me')); // warm up: schema + seed
const errors = [];
const vc = new VirtualConsole();
vc.on('jsdomError', (e) => errors.push('jsdomError: ' + e.message));
vc.on('error', (...a) => errors.push('console.error: ' + a.join(' ')));

const html = fs.readFileSync('public/index.html', 'utf8');
function newBrowser() {
  const dom = new JSDOM(html, {
    url: 'http://localhost/', runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(w) {
      w.fetch = (path, opts = {}) => handler(new Request('http://localhost' + path, { method: opts.method || 'GET', headers: opts.headers, body: opts.body }));
      w.scrollTo = () => {}; w.Element.prototype.scrollIntoView = () => {};
    },
  });
  return dom.window;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const $ = (w, id) => w.document.getElementById(id);
const toastText = (w) => $(w, 'toast').textContent;
async function until(fn, ms = 4000) { const t = Date.now(); while (Date.now() - t < ms) { if (fn()) return true; await sleep(25); } return false; }
function type(w, id, v) { $(w, id).value = v; }
async function visitAllTabs(w, label) {
  const tabs = [...w.document.querySelectorAll('#tabs .tab, #tabs button, #tabs [onclick]')];
  ok(tabs.length >= 5, label + ': tabs rendered', tabs.length);
  for (const t of tabs) {
    errors.length = 0;
    t.click(); await sleep(250);
    ok(errors.length === 0, `${label}: tab "${t.textContent.trim()}" renders without errors`, errors.slice());
    const shown = [...w.document.querySelectorAll('#views > .view.active')];
    ok(shown.length === 1 && shown[0].textContent.trim().length > 10 && !/undefined|NaN|\[object/.test(shown[0].textContent), `${label}: tab "${t.textContent.trim()}" has real content`, shown.map((x) => x.id + ':' + x.textContent.slice(0, 120)));
  }
}

// ======== member browser ========
const m = newBrowser();
await sleep(200);
ok($(m, 'authView').style.display !== 'none', 'login screen shows first');
ok(!/staff123/.test(m.document.body.textContent), 'staff demo password is no longer printed on the login page');

// registration validation comes from the server
type(m, 'rg-name', "Zed O'Brien"); type(m, 'rg-email', 'zed@x.com'); type(m, 'rg-pass', '123'); type(m, 'rg-phone', ''); type(m, 'rg-ref', '');
m.register(); await sleep(400);
ok(/at least 6/.test(toastText(m)), 'short password shows the server message', toastText(m));
type(m, 'rg-pass', 'secret1'); m.register();
ok(await until(() => $(m, 'appView').style.display !== 'none'), 'registered and entered the app');
ok(/Zed O'Brien/.test($(m, 'whoami').textContent), 'name shown');
ok(m.localStorage.getItem('fq_token'), 'session token stored');
ok(!m.localStorage.getItem('fq_uid'), 'no raw user id kept as a "login"');

await sleep(300);
const homeHtml = $(m, 'views').innerHTML;
ok(/Check in \(\+10 XP/.test(homeHtml), 'home offers check-in');
errors.length = 0;
await m.checkIn(); await sleep(400);
ok(/Checked in/.test(toastText(m)) && /Checked in today/.test($(m, 'views').innerHTML), 'check-in works, button flips to "Checked in today"', toastText(m));
await m.checkIn(); await sleep(300);
ok(/Already checked in/.test(toastText(m)), 'second check-in shows the server error');
ok(errors.length === 0, 'no JS errors on home/check-in', errors.slice());

await visitAllTabs(m, 'member');

// tampering from the console cannot grant points
const forge = await m.fetch('/api/doc/users/' + JSON.parse(Buffer.from(m.localStorage.getItem('fq_token').split('.')[0], 'base64url')).uid, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + m.localStorage.getItem('fq_token') }, body: JSON.stringify({ xp: 999999 }) });
ok(forge.status === 403, 'member cannot PATCH their own XP from the browser console', forge.status);

// ======== staff browser ========
const s = newBrowser(); await sleep(200);
type(s, 'li-email', 'staff@fitquest.demo'); type(s, 'li-pass', 'nope'); s.login(); await sleep(400);
ok(/Incorrect email or password/.test(toastText(s)), 'wrong password toast');
type(s, 'li-pass', 'staff123'); s.login();
ok(await until(() => $(s, 'appView').style.display !== 'none'), 'staff logged in');
ok(s.document.body.classList.contains('staff'), 'staff theme');
await sleep(300);

// a second member with a hostile name
const evil = newBrowser(); await sleep(150);
type(evil, 'rg-name', '<img src=x onerror="window.__pwn=1">'); type(evil, 'rg-email', 'evil@x.com'); type(evil, 'rg-pass', 'secret1'); evil.register();
await until(() => $(evil, 'appView').style.display !== 'none');
await sleep(300);

// member submits a quest
m.switchTab ? m.switchTab('quests') : null; await sleep(300);
const qBtn = [...m.document.querySelectorAll('#views button')].find((b) => /Submit|Complete|Done/i.test(b.textContent));
ok(!!qBtn, 'member sees a quest submit button');
if (qBtn) { qBtn.click(); await sleep(500); }
ok(/Submitted/.test(toastText(m)), 'quest submitted toast', toastText(m));

// staff verifies
await visitAllTabs(s, 'staff');
const verifyTab = [...s.document.querySelectorAll('#tabs [onclick]')].find((t) => /verif/i.test(t.textContent));
verifyTab.click(); await sleep(400);
const approve = [...s.document.querySelectorAll('#views button')].find((b) => /Approve/i.test(b.textContent));
ok(!!approve, 'staff sees an Approve button');
approve.click(); await sleep(600);
ok(/Approved/.test(toastText(s)), 'approved toast', toastText(s));
await m.refreshMe(); 
ok(/20|XP/.test(m.document.body.textContent), 'member data refreshed');
const meNow = JSON.parse((await (await m.fetch('/api/auth/me', { headers: { Authorization: 'Bearer ' + m.localStorage.getItem('fq_token') } })).text())).user;
ok(meNow.xp === 20, 'member XP is 20 after check-in + approved quest', meNow.xp);

// members tab: apostrophe + XSS names
const memTab = [...s.document.querySelectorAll('#tabs [onclick]')].find((t) => /member/i.test(t.textContent));
memTab.click(); await sleep(500);
ok(s.__pwn === undefined, 'hostile name did not execute script');
ok(s.document.querySelectorAll('#views img[src="x"]').length === 0, 'hostile name rendered as text, not HTML');
const adj = [...s.document.querySelectorAll('#views button')].find((b) => /Adjust XP\/RP/.test(b.textContent) && b.dataset.name === "Zed O'Brien");
ok(!!adj, 'Adjust button exists for a name with an apostrophe');
errors.length = 0;
adj.click(); await sleep(200);
ok(/Zed O'Brien/.test($(s, 'modal').textContent) && errors.length === 0, "Adjust dialog opens for Zed O'Brien (this used to be a JS syntax error)", errors.slice());
type(s, 'adj-xp', '5'); type(s, 'adj-rp', '2000'); type(s, 'adj-reason', 'test');
s.applyAdjust([...s.document.querySelectorAll('#views button')].find((b) => /Adjust/.test(b.textContent)).dataset.id);
await sleep(100);
// find zed's id
const zedId = JSON.parse(Buffer.from(m.localStorage.getItem('fq_token').split('.')[0], 'base64url')).uid;
type(s, 'adj-xp', '5'); type(s, 'adj-rp', '2000'); type(s, 'adj-reason', 'test'); await s.applyAdjust(zedId); await sleep(500);
ok(/Adjustment applied/.test(toastText(s)), 'adjustment applied', toastText(s));

// reward redeem from the member UI with an apostrophe-named reward
await s.eval(`db.doc('rewards/r_apos')`).set({ name: "Men's Shirt", cost: 100, totalQty: 3, availableQty: 3, redeemedQty: 0, active: true });
m.switchTab('rewards'); await sleep(500);
const redeemBtn = [...m.document.querySelectorAll('#views button')].find((b) => /Redeem/.test(b.textContent) && !b.disabled && /Men's Shirt/.test(b.closest('.card')?.textContent || ''));
ok(!!redeemBtn, "reward named Men's Shirt is shown with an enabled Redeem button");
errors.length = 0;
if (redeemBtn) { redeemBtn.click(); await sleep(600); }
ok(/RP reserved/.test(toastText(m)) && errors.length === 0, 'redeem works for apostrophe names (used to be a JS syntax error)', { t: toastText(m), errors: errors.slice() });

// profile / leaderboard / seasonal staff screens once more after data exists
await visitAllTabs(m, 'member (with data)');
await visitAllTabs(s, 'staff (with data)');

// logout clears the session
m.logout(); await sleep(100);
ok(!m.localStorage.getItem('fq_token') && $(m, 'authView').style.display !== 'none', 'logout clears the token');
summary('UI tests');
process.exit(process.exitCode || 0);
