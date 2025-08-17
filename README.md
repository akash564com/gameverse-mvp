# GameVerse MVP (Patched)

Fixes:
- CSRF on forms via Flask-WTF (`hidden_tag`).
- `/signup` 500 due to plain WTForms.
- Firebase Google sign-in via `/auth/firebase` with CSRF exempt.
- SQLite file placed in project dir to avoid Render permission error.

## Local
```bash
pip install -r requirements.txt
export SECRET_KEY=$(python - <<'PY'
import secrets;print(secrets.token_hex(32))
PY
)
# Optional: Firebase Admin
# export FIREBASE_CREDENTIALS_JSON='{"type":"service_account",...}'
python app.py
```

## Render
Build: `pip install -r requirements.txt`  
Start: `gunicorn app:app`

Env:
- SECRET_KEY
- (Optional) FIREBASE_API_KEY, FIREBASE_AUTH_DOMAIN, FIREBASE_PROJECT_ID, FIREBASE_APP_ID
- (Optional) FIREBASE_CREDENTIALS_JSON (paste JSON as single line)

Firebase Console → Auth → Settings → Authorized domains:
- Add `gameverse-mvp.onrender.com` and `localhost`
