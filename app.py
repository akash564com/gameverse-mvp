from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_wtf import CSRFProtect
from wtforms import Form, StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3, os, datetime, smtplib, ssl
from email.message import EmailMessage

# Firebase Admin for verifying ID tokens
import firebase_admin
from firebase_admin import auth as fb_auth
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length

class SignupForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Sign Up")

# -------- Config --------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")

# Secure cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
)

# Socket.IO (eventlet/gevent supported)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# Database path (supports Render disk via env DB_PATH)
DB = os.getenv("DB_PATH", "users.db")
os.makedirs(os.path.dirname(DB), exist_ok=True) if os.path.dirname(DB) else None

login_manager = LoginManager(app)
login_manager.login_view = "login"

csrf = CSRFProtect(app)

# Admin emails (comma-separated)
ADMIN_EMAILS = set(e.strip().lower() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip())

# Email (SMTP) settings for password reset
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
MAIL_FROM = os.getenv("MAIL_FROM", SMTP_USER or "noreply@example.com")

# Firebase client config (exposed to templates)
FIREBASE_CONFIG = {
    "apiKey": os.getenv("FIREBASE_API_KEY", ""),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN", ""),
    "projectId": os.getenv("FIREBASE_PROJECT_ID", ""),
    "appId": os.getenv("FIREBASE_APP_ID", ""),
}

# Initialize Firebase Admin (no creds needed for token verification)
if not firebase_admin._apps:
    firebase_admin.initialize_app()

# Token serializer for password reset
serializer = URLSafeTimedSerializer(app.secret_key, salt="reset-salt")

# -------- DB Helpers --------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            provider TEXT NOT NULL DEFAULT 'local'
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            game_slug TEXT NOT NULL,
            score INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            image TEXT NOT NULL,
            premium INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1
        )""")
        # Seed default games if empty
        c.execute("SELECT COUNT(*) FROM games")
        if c.fetchone()[0] == 0:
            seed = [
                ("tetris","Tetris","Classic block-stacking puzzle game.","https://via.placeholder.com/200x120.png?text=Tetris",0,1),
                ("pong","Pong","The original arcade tennis game.","https://via.placeholder.com/200x120.png?text=Pong",0,1),
                ("snake","Snake","Eat, grow, don’t crash.","https://via.placeholder.com/200x120.png?text=Snake",0,1),
                ("memory","Memory Match","Flip and match pairs.","https://via.placeholder.com/200x120.png?text=Memory",0,1),
                ("breakout","Breakout","Break the bricks!","https://via.placeholder.com/200x120.png?text=Breakout",0,1),
                ("tictactoe","Tic-Tac-Toe (Multiplayer)","Play with a friend online.","https://via.placeholder.com/200x120.png?text=TicTacToe",0,1),
            ]
            c.executemany("INSERT INTO games(slug,name,description,image,premium,enabled) VALUES (?,?,?,?,?,?)", seed)
        conn.commit()

init_db()

# -------- User model --------
class User(UserMixin):
    def __init__(self, id, email, password, username, is_admin, created_at, provider="local"):
        self.id = str(id)
        self.email = email
        self.password = password
        self.username = username
        self.is_admin = bool(is_admin)
        self.created_at = created_at
        self.provider = provider

@login_manager.user_loader
def load_user(user_id):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id,email,password,username,is_admin,created_at,provider FROM users WHERE id=?", (user_id,))
        row = c.fetchone()
        return User(*row) if row else None

# -------- Forms --------
class SignupForm(Form):
    email = StringField("Email", [DataRequired(), Email(), Length(max=200)])
    username = StringField("Username", [DataRequired(), Length(min=3, max=32)])
    password = PasswordField("Password", [DataRequired(), Length(min=6, max=128)])

class LoginForm(Form):
    email = StringField("Email", [DataRequired(), Email()])
    password = PasswordField("Password", [DataRequired()])

class ResetRequestForm(Form):
    email = StringField("Email", [DataRequired(), Email()])

class ResetForm(Form):
    password = PasswordField("Password", [DataRequired(), Length(min=6, max=128)])

# -------- Utilities --------
def current_games(include_disabled=False):
    with get_db() as conn:
        c = conn.cursor()
        if include_disabled:
            c.execute("SELECT slug,name,description,image,premium,enabled FROM games ORDER BY name")
        else:
            c.execute("SELECT slug,name,description,image,premium,enabled FROM games WHERE enabled=1 ORDER BY name")
        rows = c.fetchall()
        return [dict(slug=r[0], name=r[1], description=r[2], image=r[3], premium=bool(r[4]), enabled=bool(r[5])) for r in rows]

def get_game(slug):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT slug,name,description,image,premium,enabled FROM games WHERE slug=?", (slug,))
        r = c.fetchone()
        return dict(slug=r[0], name=r[1], description=r[2], image=r[3], premium=bool(r[4]), enabled=bool(r[5])) if r else None

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def send_reset_email(to_email, token):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        print("SMTP not configured; skipping email.")
        return
    link = url_for("reset_token", token=token, _external=True)
    msg = EmailMessage()
    msg["Subject"] = "GameVerse password reset"
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    msg.set_content(f"Click to reset your password:\n{link}\nThis link expires in 1 hour.")
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

# -------- Context processors --------
@app.context_processor
def inject_config():
    return dict(FIREBASE_CONFIG=FIREBASE_CONFIG)

# -------- Routes --------
@app.route("/")
def home():
    games = current_games()
    return render_template("home.html", games=games)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm(request.form)
    if request.method == "POST" and form.validate():
        email = form.email.data.strip().lower()
        username = form.username.data.strip()
        password = generate_password_hash(form.password.data)
        try:
            with get_db() as conn:
                c = conn.cursor()
                is_admin = 1 if email in ADMIN_EMAILS else 0
                c.execute("INSERT INTO users (email,password,username,is_admin,created_at,provider) VALUES (?,?,?,?,?,?)",
                          (email, password, username, is_admin, datetime.datetime.utcnow().isoformat(), "local"))
                conn.commit()
            flash("Account created! Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError as e:
            if "users.email" in str(e):
                flash("Email already exists.", "danger")
            elif "users.username" in str(e):
                flash("Username already taken.", "danger")
            else:
                flash("Could not create account.", "danger")
    return render_template("signup.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        email = form.email.data.strip().lower()
        password = form.password.data
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id,email,password,username,is_admin,created_at,provider FROM users WHERE email=?", (email,))
            row = c.fetchone()
            if row and check_password_hash(row[2], password):
                user = User(*row)
                login_user(user)
                flash("Welcome back!", "success")
                return redirect(url_for("home"))
        flash("Invalid credentials", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("home"))

# --- Password reset ---
@app.route("/reset", methods=["GET", "POST"])
def reset_request():
    form = ResetRequestForm(request.form)
    if request.method == "POST" and form.validate():
        email = form.email.data.strip().lower()
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE email=?", (email,))
            row = c.fetchone()
            if row:
                token = serializer.dumps(email)
                try:
                    send_reset_email(email, token)
                    flash("If your email exists, a reset link has been sent.", "info")
                except Exception as e:
                    print("Reset email failed:", e)
                    flash("Email service not configured. Token: " + token, "warning")
            else:
                flash("If your email exists, a reset link has been sent.", "info")
        return redirect(url_for("login"))
    return render_template("reset_request.html", form=form)

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_token(token):
    form = ResetForm(request.form)
    email = None
    try:
        email = serializer.loads(token, max_age=3600)
    except SignatureExpired:
        flash("Reset link expired.", "danger")
        return redirect(url_for("reset_request"))
    except BadSignature:
        flash("Invalid reset link.", "danger")
        return redirect(url_for("reset_request"))
    if request.method == "POST" and form.validate():
        new_pw = generate_password_hash(form.password.data)
        with get_db() as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET password=? WHERE email=?", (new_pw, email))
            conn.commit()
        flash("Password updated. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("reset_form.html", form=form, token=token)

# --- Firebase OAuth endpoint ---
@app.route("/auth/firebase", methods=["POST"])
@csrf.exempt
def auth_firebase():
    # Expects JSON: {"idToken": "..."}
    data = request.get_json(silent=True) or {}
    id_token = data.get("idToken")
    if not id_token:
        return jsonify({"ok": False, "error": "Missing idToken"}), 400
    try:
        decoded = fb_auth.verify_id_token(id_token)
        email = decoded.get("email", "").lower()
        if not email:
            return jsonify({"ok": False, "error": "No email in token"}), 400
        username = email.split("@")[0][:16]
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id,email,password,username,is_admin,created_at,provider FROM users WHERE email=?", (email,))
            row = c.fetchone()
            if row:
                user = User(*row)
            else:
                is_admin = 1 if email in ADMIN_EMAILS else 0
                c.execute("INSERT INTO users (email,password,username,is_admin,created_at,provider) VALUES (?,?,?,?,?,?)",
                          (email, "", username, is_admin, datetime.datetime.utcnow().isoformat(), "firebase"))
                conn.commit()
                c.execute("SELECT id,email,password,username,is_admin,created_at,provider FROM users WHERE email=?", (email,))
                user = User(*c.fetchone())
        login_user(user)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/play/<slug>")
@login_required
def play(slug):
    game = get_game(slug)
    if not game or not game["enabled"]:
        return "Game not found", 404
    return render_template("play.html", game=game)

@app.route("/profile/<username>")
@login_required
def profile(username):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id,email,username,is_admin,created_at FROM users WHERE username=?", (username,))
        u = c.fetchone()
        if not u:
            return "User not found", 404
        user_info = dict(id=u[0], email=u[1], username=u[2], is_admin=bool(u[3]), created_at=u[4])
        c.execute("""SELECT game_slug, MAX(score) as best FROM scores WHERE user_id=? GROUP BY game_slug ORDER BY best DESC""", (u[0],))
        best = [dict(game_slug=r[0], best=r[1]) for r in c.fetchall()]
    return render_template("profile.html", user_info=user_info, best_scores=best)

@app.route("/leaderboard/<slug>")
def leaderboard(slug):
    game = get_game(slug)
    if not game:
        return "Game not found", 404
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT u.username, MAX(s.score) as best
            FROM scores s JOIN users u ON s.user_id=u.id
            WHERE s.game_slug=?
            GROUP BY u.username
            ORDER BY best DESC
            LIMIT 50
        """, (slug,))
        rows = [dict(username=r[0], score=r[1]) for r in c.fetchall()]
    return render_template("leaderboard.html", game=game, rows=rows)

# ----- Admin: manage games metadata -----
@app.route("/admin/games", methods=["GET", "POST"])
@login_required
def admin_games():
    if not current_user.is_admin:
        abort(403)
    if request.method == "POST":
        slug = request.form.get("slug","").strip()
        name = request.form.get("name","").strip()
        description = request.form.get("description","").strip()
        image = request.form.get("image","").strip()
        premium = 1 if request.form.get("premium") == "on" else 0
        enabled = 1 if request.form.get("enabled") == "on" else 0
        if not slug or not name:
            flash("Slug and name are required.", "danger")
        else:
            with get_db() as conn:
                c = conn.cursor()
                c.execute("INSERT OR REPLACE INTO games (id,slug,name,description,image,premium,enabled) VALUES ((SELECT id FROM games WHERE slug=?),?,?,?,?,?,?)",
                          (slug, slug, name, description, image, premium, enabled))
                conn.commit()
                flash("Game saved.", "success")
    return render_template("admin_games.html", games=current_games(include_disabled=True))

# ----- API for posting scores -----
from flask_wtf.csrf import CSRFError

@app.errorhandler(CSRFError)
def handle_csrf(e):
    return render_template("csrf_error.html", reason=e.description), 400

@app.route("/api/scores", methods=["POST"])
@login_required
@csrf.exempt  # JSON endpoint; implement your own token scheme if needed
def post_score():
    try:
        data = request.get_json(force=True)
        slug = data.get("slug")
        score = int(data.get("score"))
    except Exception:
        return jsonify({"ok": False, "error": "Invalid JSON"}), 400

    game = get_game(slug)
    if not game or not game["enabled"]:
        return jsonify({"ok": False, "error": "Unknown game"}), 404

    with get_db() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO scores (user_id, game_slug, score, created_at) VALUES (?,?,?,?)",
                  (int(current_user.id), slug, score, datetime.datetime.utcnow().isoformat()))
        conn.commit()
    return jsonify({"ok": True})

@app.route("/api/games")
def api_games():
    return jsonify(current_games())

# -------- Security headers --------
@app.after_request
def add_headers(resp):
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

# --------- Socket.IO: Tic-Tac-Toe ---------
rooms = {}  # room_id -> dict(board, turn, players, winner)

def fresh_board():
    return ['']*9

@socketio.on("join")
def on_join(data):
    room = data.get("room")
    if not room:
        return
    join_room(room)
    r = rooms.setdefault(room, {"board": fresh_board(), "turn": "X", "players": {}, "winner": ""})
    if request.sid not in r["players"]:
        symbol = "X" if "X" not in r["players"].values() else "Y" if "Y" not in r["players"].values() else "O" if "O" not in r["players"].values() else None
        # default to X/O only
        symbol = "X" if "X" not in r["players"].values() else "O"
        r["players"][request.sid] = symbol
    emit("state", r, room=room)

def winner(board):
    lines = [(0,1,2),(3,4,5),(6,7,8),(0,3,6),(1,4,7),(2,5,8),(0,4,8),(2,4,6)]
    for a,b,c in lines:
        if board[a] and board[a]==board[b]==board[c]:
            return board[a]
    if all(board):
        return "draw"
    return ""

@socketio.on("move")
def on_move(data):
    room = data.get("room")
    idx = int(data.get("idx", -1))
    r = rooms.get(room)
    if not r or r["winner"] or idx<0 or idx>8:
        return
    sym = r["players"].get(request.sid, "X")
    if r["board"][idx] or r["turn"] != sym:
        return
    r["board"][idx] = sym
    r["turn"] = "O" if sym=="X" else "X"
    r["winner"] = winner(r["board"])
    emit("state", r, room=room)

@socketio.on("reset")
def on_reset(data):
    room = data.get("room")
    if room in rooms:
        rooms[room]["board"] = fresh_board()
        rooms[room]["turn"] = "X"
        rooms[room]["winner"] = ""
        emit("state", rooms[room], room=room)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
