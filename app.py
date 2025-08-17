import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, jsonify
from firebase_admin import auth as firebase_auth



from forms import SignupForm, LoginForm

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "gameverse.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_" + os.urandom(16).hex())

csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(BASE_DIR, exist_ok=True)
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT,
            password_hash TEXT,
            provider TEXT DEFAULT 'local'
        )
        """)

init_db()

class User(UserMixin):
    def __init__(self, id, email, username, provider):
        self.id = id
        self.email = email
        self.username = username
        self.provider = provider

def find_user_by_email(email):
    with get_db() as conn:
        row = conn.execute("SELECT id,email,username,provider FROM users WHERE email=?", (email,)).fetchone()
    if row:
        return User(row["id"], row["email"], row["username"], row["provider"])
    return None

def create_user(email, username, password_hash=None, provider="local"):
    with get_db() as conn:
        conn.execute("INSERT OR IGNORE INTO users(email, username, password_hash, provider) VALUES(?,?,?,?)",
                     (email, username, password_hash, provider))
        row = conn.execute("SELECT id,email,username,provider FROM users WHERE email=?", (email,)).fetchone()
    return User(row["id"], row["email"], row["username"], row["provider"])

@login_manager.user_loader
def load_user(user_id):
    with get_db() as conn:
        row = conn.execute("SELECT id,email,username,provider FROM users WHERE id=?", (user_id,)).fetchone()
    if row:
        return User(row["id"], row["email"], row["username"], row["provider"])
    return None

FIREBASE_CREDENTIALS = os.environ.get("FIREBASE_CREDENTIALS_JSON")
firebase_ready = False
if FIREBASE_CREDENTIALS:
    try:
        import firebase_admin
        from firebase_admin import auth, credentials
        cred = credentials.Certificate(eval(FIREBASE_CREDENTIALS) if FIREBASE_CREDENTIALS.strip().startswith("{") else FIREBASE_CREDENTIALS)
        firebase_admin.initialize_app(cred)
        firebase_ready = True
    except Exception as e:
        print("Firebase Admin init failed:", e)

@app.route("/")
def index():
    games = [
        {"slug":"snake", "name":"Snake", "description":"Classic snake game", "image": "https://picsum.photos/seed/snake/300/160"},
        {"slug":"tetris", "name":"Tetris", "description":"Block stacking fun", "image": "https://picsum.photos/seed/tetris/300/160"},
        {"slug":"pong", "name":"Pong", "description":"Two-player retro pong", "image": "https://picsum.photos/seed/pong/300/160"},
    ]
    return render_template("home.html", games=games)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        email = form.email.data.lower().strip()
        password = form.password.data
        with get_db() as conn:
            row = conn.execute("SELECT id,email,username,password_hash,provider FROM users WHERE email=?", (email,)).fetchone()
        if not row or not row["password_hash"] or not check_password_hash(row["password_hash"], password):
            flash("Invalid credentials", "danger")
            return render_template("login.html", form=form), 400
        user = User(row["id"], row["email"], row["username"], row["provider"])
        login_user(user)
        flash("Welcome back!", "success")
        return redirect(url_for("index"))
    fb_cfg = {
        "apiKey": os.environ.get("FIREBASE_API_KEY"),
        "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN"),
        "projectId": os.environ.get("FIREBASE_PROJECT_ID"),
        "appId": os.environ.get("FIREBASE_APP_ID"),
    }
    return render_template("login.html", form=form, firebase_config=fb_cfg)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if request.method == "POST" and form.validate_on_submit():
        email = form.email.data.lower().strip()
        username = form.username.data.strip()
        password = form.password.data
        if find_user_by_email(email):
            flash("Email already registered", "warning")
            return render_template("signup.html", form=form), 400
        pwd_hash = generate_password_hash(password)
        user = create_user(email, username, pwd_hash, provider="local")
        login_user(user)
        flash("Account created!", "success")
        return redirect(url_for("index"))
    return render_template("signup.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("index"))

@app.route("/auth/firebase", methods=["POST"])
@csrf.exempt  # disable CSRF for API endpoint
def auth_firebase():
    data = request.get_json(silent=True)
    print("DEBUG /auth/firebase payload:", data)  # helpful in Render logs

    if not data or "idToken" not in data:
        return jsonify({"error": "Missing idToken"}), 400

    id_token = data["idToken"]

    try:
        decoded_token = firebase_auth.verify_id_token(id_token)
        uid = decoded_token["uid"]
        # 🔐 At this point you can create/login a user in your DB session
        session["user_id"] = uid
        return jsonify({"success": True, "uid": uid}), 200
    except Exception as e:
        print("Firebase verify failed:", e)
        return jsonify({"error": "Invalid token"}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
