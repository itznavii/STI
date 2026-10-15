// All "what day is it" logic runs in ONE timezone (the gym's), not UTC and not
// the visitor's browser. Set APP_TIMEZONE in Netlify env vars (IANA name).
export const tzName = () => process.env.APP_TIMEZONE || 'Asia/Manila';

export function dateIso(ts, tz = tzName()) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(ts);
}
function offsetMs(ts, tz) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: tz, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric',
    hour: 'numeric', minute: 'numeric', second: 'numeric',
  }).formatToParts(ts);
  const g = (t) => +parts.find((p) => p.type === t).value;
  return Date.UTC(g('year'), g('month') - 1, g('day'), g('hour'), g('minute'), g('second')) - Math.floor(ts / 1000) * 1000;
}
// UTC ms of local midnight for y-m-d in tz
export function localMidnight(y, m, d, tz = tzName()) {
  const guess = Date.UTC(y, m - 1, d);
  const t1 = guess - offsetMs(guess, tz);
  return guess - offsetMs(t1, tz);
}
export function dayStart(ts = Date.now(), tz = tzName()) {
  const [y, m, d] = dateIso(ts, tz).split('-').map(Number);
  return localMidnight(y, m, d, tz);
}
export function yesterdayIso(ts = Date.now(), tz = tzName()) {
  return dateIso(dayStart(ts, tz) - 1, tz);
}
export function periodStart(range, ts = Date.now(), tz = tzName()) {
  const [y, m, d] = dateIso(ts, tz).split('-').map(Number);
  if (range === 'month') return localMidnight(y, m, 1, tz);
  if (range === 'week') {
    const dow = new Date(Date.UTC(y, m - 1, d)).getUTCDay();           // 0 = Sunday
    const back = (dow + 6) % 7;                                         // weeks start Monday
    const s = new Date(Date.UTC(y, m - 1, d - back));
    return localMidnight(s.getUTCFullYear(), s.getUTCMonth() + 1, s.getUTCDate(), tz);
  }
  return localMidnight(y, m, d, tz);
}
export function periodKey(range, metric, ts = Date.now(), tz = tzName()) {
  const day = dateIso(periodStart(range, ts, tz), tz);
  return `${metric}_${range}_${range === 'month' ? day.slice(0, 7) : day}`;
}
