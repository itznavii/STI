# FitQuest (Netlify edition)

Static site (`public/`) + one Netlify Function (`netlify/functions/api.mjs`) + Netlify Database (Postgres).
Staff on one phone and members on other devices all use the same live data.

## Deploy

1. Put this folder in a GitHub repo and, in Netlify, choose **Add new site → Import an existing project**.
   (Settings are read from `netlify.toml`; no build command is needed.)
2. Before the first visit, add these environment variables (Site configuration → Environment variables):

   | Variable | What it does |
   |---|---|
   | `STAFF_PASSWORD` | **Required in practice.** Password for the staff account. If missing, the default `staff123` is used. |
   | `STAFF_EMAIL` | Staff login email. Default `staff@fitquest.demo`. |
   | `APP_TIMEZONE` | The gym's timezone, e.g. `Asia/Manila`. Decides when "today" starts for check-ins, streaks, daily caps and leaderboards. Default `Asia/Manila`. |
   | `SESSION_SECRET` | Optional. If unset, a secret is generated and stored in the database. |

3. Deploy. Installing `@netlify/database` makes Netlify create the database on that deploy. The tables are created
   automatically on the first request, and the staff account plus starter quests/rewards are seeded.
   Netlify Database needs a plan that includes it; check your account if the deploy says the database is unavailable.
4. Open the site URL (HTTPS). Staff log in with `STAFF_EMAIL` / `STAFF_PASSWORD`; members register themselves.

Changing `STAFF_PASSWORD` later and redeploying updates the staff password.

## Local development

    npm install
    npx netlify dev        # needs the Netlify CLI; runs a local database automatically
    npm test               # API + UI tests (uses an in-memory Postgres; no Netlify needed)

## How it is built

* Every action that changes points, statuses or stock runs on the server inside a database transaction
  (`netlify/lib/logic.mjs`). The browser can no longer edit XP/RP/roles.
* Passwords are salted scrypt hashes, checked on the server. Sessions are signed tokens (30 days).
* Members can only read their own records; leaderboards hide members who opted out; staff-only data stays staff-only.
* Membership renewal is now done by staff in person (Members → "Renew +30d"). It extends the membership and adds a loyalty stamp.
* Referrals: a friend types the member's code when registering; the referral then waits in the staff **Verifications** tab. Approving it pays the referrer +100 RP (nothing is paid automatically). A wrong code shows an error at registration.
* Numbers use the Jersey 10 pixel font (`public/fonts/`) because the main pixel font draws 5 and 6 like the letter S.
* The app refreshes notifications every 20 s while the tab is visible (each refresh is one function call).

## Known limits

* Registration is open to anyone with the URL.
* Login throttling is per function instance (best effort).
* No password reset: staff would need to edit the database, or you can add a reset flow later.
