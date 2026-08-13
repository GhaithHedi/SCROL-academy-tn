# أكاديمية SCROL — SCROL Academy 🇹🇳

A locally runnable e-learning platform for **Math & Physics**, covering
Tunisian levels from **7ème année de base** to the **Baccalauréat**.
Arabic RTL interface, original design ("student notebook" theme), built with
**Python Flask + SQLite**, plus an AI tutor powered by the **Claude API**.

> Original project (its own brand, texts, and design), inspired only by the
> general *feature set* of Tunisian e-learning platforms.

---

## ⚡ Quick start

```bash
# 1) (optional) create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2) install dependencies
pip install -r requirements.txt

# 3) (optional) enable the AI tutor — create a .env file:
#    ANTHROPIC_API_KEY=sk-ant-...
#    Without it, the chat widget still renders but replies with a
#    "not configured" message instead of erroring out.

# 4) run
python app.py
```

Then open **http://localhost:5000**

On first run the app creates and seeds `academy.db` automatically
(14 courses = 7 levels × 2 subjects, ~65 lessons, 5 upcoming live sessions,
3 demo accounts). Delete `academy.db` to reset everything to the seed state.

---

## 👤 Demo accounts

| Role                  | Email              | Password | Notes                          |
|-----------------------|--------------------|----------|--------------------------------|
| Admin                 | admin@scrol.tn     | admin123 | Full admin panel at `/admin`   |
| Student (free)        | ahmed@test.tn      | 123456   | Sees only the free lessons     |
| Student (subscribed)  | mariem@test.tn     | 123456   | Monthly subscription active    |

You can also register any new account from the site itself.

---

## ✅ What's implemented

**Public site**
- Landing page: hero, stats band, how-it-works, levels grid, free sample
  lessons, features, pricing preview, FAQ accordion, CTA, footer.
- Accounts: register (name, email, phone, level, password), login, logout.
  Passwords are hashed (Werkzeug).
- Catalog: `/courses` with level + subject filters, auto-defaulted to the
  logged-in student's own level; course pages list all lessons with lock
  states. First video of every course is free for any logged-in account.
- Subscriptions: 3 plans (monthly 29 DT / trimester 69 DT / yearly 179 DT).
  Checkout simulates Tunisian payment methods (D17, Flouci, bank transfer,
  mandat) → creates a **pending** payment that an admin must approve — no
  auto-activation, by design.
- Live sessions: `/live` schedule; the stream link is visible only to
  subscribers.

**Student space** (`/dashboard` and a persistent sidebar app-shell)
- Dashboard: subscription status, per-subject progress bars (lessons
  watched vs. total, computed from real `lesson_progress` tracking), a
  "next lesson to learn" link, live sessions filtered to the student's own
  level, payment history.
- Lesson player (`/watch/<id>`): mark-as-watched toggle, checkmarks in the
  lesson sidebar, view logging for admin analytics.
- Profile (`/profile`): account info, completed-lesson count.
- Study schedule (`/schedule`): student defines personal review blocks
  (date + start/end time + optional subject/note), sees this week + upcoming.
- Group chat (`/chat`): one room per level; only admins post, students react
  with 👍❤️🎉🔥.
- Leaderboard (`/leaderboard`): ranks students within their level by lessons
  completed, medals for top 3, auto-refreshes every 15s via a small JSON
  endpoint (no full reload).
- Notifications: bell icon with unread badge, admin-sent (broadcast or
  per-level), marked read on open.
- **AI tutor chatbot**: floating widget (Claude API), aware of the lesson
  currently being watched, guides instead of just handing over answers,
  plain-text formatting (no raw Markdown/LaTeX in the bubble), conversation
  persisted in `sessionStorage` across navigation and cleared on logout,
  **30 messages/day/student cap** to control API cost.

**Admin panel** (`/admin`, same sidebar app-shell as students)
- Overview stats, per-level dashboards (students, subscribers, lesson views,
  completions per level, drill-down per course).
- Payments: approve/reject.
- Users: grant/extend/revoke subscriptions.
- Content: add courses, add video lessons (accepts full YouTube URLs).
- Live sessions: schedule/delete.
- Chat: compose a message to any level's group chat, see history + reaction
  counts.
- Notifications: compose and send to all students or one level, see recent
  sends with recipient counts.

**Everything else**: 404/403 pages, terms & privacy pages, flash messages,
responsive RTL design, reduced-motion support.

---

## 🎬 Replacing the placeholder videos

Every seeded lesson uses YouTube's public demo clip (`M7lc1UVf-VE`) as a
placeholder. To use your real lessons:

1. Log in as admin → **لوحة الإدارة → المحتوى**.
2. Add a lesson and paste your YouTube link (`https://youtu.be/...` or a full
   watch URL — the video ID is extracted automatically).
3. Or edit directly in SQLite: `UPDATE lessons SET youtube_id='XXXX' WHERE id=...;`

---

## 🗂 Project structure

```
tafawok-academy/            # folder name unchanged — only the app's brand
                             # was renamed to SCROL Academy; rename the
                             # folder yourself if you want that too.
├── app.py                  # All routes, DB schema, seed data, business logic
├── requirements.txt        # flask, anthropic, gunicorn
├── academy.db               # SQLite DB (auto-created on first run)
├── .env                     # ANTHROPIC_API_KEY, SECRET_KEY (gitignored)
├── Dockerfile / fly.toml    # production image + Fly.io deploy config
├── templates/
│   ├── base.html            # student/admin sidebar app-shell + guest nav
│   ├── index.html           # landing page
│   ├── register.html / login.html
│   ├── courses.html / course.html / watch.html
│   ├── pricing.html / checkout.html
│   ├── live.html / dashboard.html / profile.html
│   ├── schedule.html / chat.html / leaderboard.html / notifications.html
│   ├── legal.html / error.html
│   └── admin/panel.html     # tabbed admin dashboard
└── static/
    ├── css/style.css        # full design system (RTL, "notebook" theme)
    ├── js/main.js           # nav, sidebar, AI chat widget, reveal/counters
    └── img/favicon.svg
```

---

## 🔧 Customization pointers

- **Brand / contact info**: `templates/base.html` (footer) and `checkout.html`
  (payment numbers — replace the placeholder `+216 00 000 000` / RIB).
- **Plans & prices**: the `PLANS` dict at the top of `app.py`.
- **Levels / subjects**: `LEVELS` and `SUBJECTS` in `app.py`.
- **Seed chapters**: `MATH_CHAPTERS` / `PHYS_CHAPTERS` in `app.py`.
- **AI tutor system prompt**: `AI_SYSTEM_PROMPT` in `app.py`; daily cap via
  `AI_DAILY_LIMIT`.
- **Colors & fonts**: CSS variables at the top of `static/css/style.css`.
- **Secrets**: `SECRET_KEY` and `ANTHROPIC_API_KEY` — set via `.env` locally,
  via `fly secrets set` in production. Never hardcode them in `app.py`.

## ⚠️ Notes for going further

Still missing before a larger real-world launch: email verification, password
reset, a real payment gateway (e.g. Paymee/Konnect APIs), and exercise/exam
generation by the AI (chat-based tutoring is live; generation is the planned
next step). Production deployment (gunicorn + Docker + Fly.io) is prepared —
see `Dockerfile` and `fly.toml`.
