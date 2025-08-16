# GameVerse — OAuth, Multiplayer & More Games

## New
- **Google OAuth via Firebase** (client) + server verification (`/auth/firebase` — Firebase Admin).
- **Password reset** via email token (`/reset`, `/reset/<token>`). Configure SMTP.
- **Multiplayer Tic-Tac-Toe** using **Flask-SocketIO** (rooms). Join the `public` room or any custom room ID.
- Extra games: **Memory** & **Breakout** (single-player, score posts to API).

## Env Vars
- `FLASK_SECRET_KEY` — long random.
- `ADMIN_EMAILS` — CSV list for auto-admin on signup/Firebase first login.
- `SESSION_COOKIE_SECURE=true` — on production.
- `DB_PATH=/var/data/users.db` — if using Render disk.
- **Firebase (required for Google OAuth button):**
  - `FIREBASE_API_KEY`
  - `FIREBASE_AUTH_DOMAIN`
  - `FIREBASE_PROJECT_ID`
  - `FIREBASE_APP_ID`
- **SMTP (for password reset):**
  - `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM`

## Deploy on Render
- **Build:** `pip install -r requirements.txt`
- **Start:** `gunicorn -k eventlet -w 1 app:app`
- WebSockets are supported by Render; eventlet worker is required for Socket.IO.

## Firebase setup
1. Create a Firebase project; enable **Authentication → Sign-in method → Google**.
2. Grab Web SDK config (apiKey, authDomain, projectId, appId) and set env vars above.
3. The **Login** page shows a **Continue with Google** button and posts the ID token to `/auth/firebase`.

## Notes
- Local accounts & Firebase accounts coexist. Provider is stored (`local` or `firebase`).
- Password reset works only for **local** accounts (Firebase users should use Firebase reset flow).

