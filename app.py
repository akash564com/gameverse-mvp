from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from games import games

app = Flask(__name__)
app.secret_key = "supersecretkey"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

DB = "users.db"

def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS users (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     email TEXT UNIQUE NOT NULL,
                     password TEXT NOT NULL)""")
        conn.commit()
init_db()

class User(UserMixin):
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT id, email, password FROM users WHERE id=?", (user_id,))
        row = c.fetchone()
        if row:
            return User(*row)
    return None

@app.route("/")
def home():
    return render_template("home.html", games=games)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        try:
            with sqlite3.connect(DB) as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
                conn.commit()
            flash("Account created! Please login.", "success")
            return redirect(url_for("login"))
        except:
            flash("Email already exists.", "danger")
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("SELECT id, email, password FROM users WHERE email=?", (email,))
            row = c.fetchone()
            if row and check_password_hash(row[2], password):
                user = User(*row)
                login_user(user)
                return redirect(url_for("home"))
        flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route("/play/<slug>")
@login_required
def play(slug):
    game = next((g for g in games if g["slug"] == slug), None)
    if not game:
        return "Game not found", 404
    return render_template("play.html", game=game)

if __name__ == "__main__":
    app.run(debug=True)
