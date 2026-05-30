import os
import sqlite3
import secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory
)

from PIL import Image
import imagehash

# -----------------------------
# Config
# -----------------------------
APP_NAME = "Realtime Cloud Biometric Banking"
DATABASE = "database.db"
UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Admin (static username/password as requested)
ADMIN_USER = "admin"
ADMIN_PASS = "admin@123"   # static, demo-only

# Biometric matching threshold (Hamming distance)
BIOMETRIC_MAX_DISTANCE = 6  # 0 = exact; 6–8 is tolerant for pHash

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = secrets.token_hex(32)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# -----------------------------
# Utilities
# -----------------------------
def get_db():
    conn = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript(
        """
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            account_number TEXT UNIQUE NOT NULL,
            biometric_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            balance REAL NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL, -- 'deposit', 'transfer_out', 'transfer_in'
            amount REAL NOT NULL,
            counterparty_ac TEXT, -- target/source account number
            created_at TEXT NOT NULL,
            balance_after REAL NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    conn.commit()
    conn.close()

def compute_biometric_hash(image_path: str) -> str:
    """Compute a perceptual hash (pHash) for the image."""
    with Image.open(image_path) as img:
        img = img.convert("RGB")
        ph = imagehash.phash(img)
        return str(ph)  # hex string

def hamming_distance(hash1: str, hash2: str) -> int:
    """Compute Hamming distance between two hex string hashes."""
    return imagehash.hex_to_hash(hash1) - imagehash.hex_to_hash(hash2)

def logged_in_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin login required.", "warning")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper

def generate_account_number():
    # Simple demo generator: 12-digit numeric
    return "".join(secrets.choice("0123456789") for _ in range(12))

def get_user_and_account(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cur.fetchone()
    cur.execute("SELECT * FROM accounts WHERE user_id=?", (user_id,))
    account = cur.fetchone()
    conn.close()
    return user, account

# -----------------------------
# Routes: Public
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html", app_name=APP_NAME)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        bio_file = request.files.get("biometric")

        if not name or not email or not bio_file:
            flash("All fields are required (Name, Email, Biometric Image).", "danger")
            return redirect(url_for("register"))

        # Save uploaded image
        filename = f"user_{secrets.token_hex(8)}.jpg"
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        bio_file.save(save_path)

        # Compute biometric template (hash)
        try:
            bio_hash = compute_biometric_hash(save_path)
        except Exception as e:
            flash(f"Failed to process biometric image: {e}", "danger")
            return redirect(url_for("register"))

        # Insert user + account
        try:
            conn = get_db()
            cur = conn.cursor()
            account_number = generate_account_number()
            now = datetime.utcnow().isoformat()

            cur.execute(
                "INSERT INTO users (name, email, account_number, biometric_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, email, account_number, bio_hash, now)
            )
            user_id = cur.lastrowid

            cur.execute(
                "INSERT INTO accounts (user_id, balance) VALUES (?, ?)",
                (user_id, 0.0)
            )
            conn.commit()
            conn.close()
            flash("Registration successful! Please log in using your biometric.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email is already registered.", "danger")
            return redirect(url_for("register"))

    return render_template("register.html", app_name=APP_NAME)

import base64
from io import BytesIO

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        bio_data = request.form.get("biometric", "")

        if not email or not bio_data:
            flash("Email and Biometric are required.", "danger")
            return redirect(url_for("login"))

        # Decode base64 image from webcam
        try:
            header, encoded = bio_data.split(",", 1)
            img_bytes = base64.b64decode(encoded)
            temp_name = f"login_{secrets.token_hex(8)}.jpg"
            temp_path = os.path.join(app.config["UPLOAD_FOLDER"], temp_name)
            with open(temp_path, "wb") as f:
                f.write(img_bytes)
            login_hash = compute_biometric_hash(temp_path)
        except Exception as e:
            flash(f"Biometric processing failed: {e}", "danger")
            return redirect(url_for("login"))

        # DB lookup
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, biometric_hash FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        conn.close()

        if not row:
            flash("No user found with that email.", "danger")
            return redirect(url_for("login"))

        stored_hash = row["biometric_hash"]
        dist = hamming_distance(stored_hash, login_hash)

        if dist <= BIOMETRIC_MAX_DISTANCE:
            session["user_id"] = row["id"]
            session["is_admin"] = False
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Biometric mismatch. Please try again.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html", app_name=APP_NAME)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

# -----------------------------
# Routes: User Dashboard & Banking
# -----------------------------
@app.route("/dashboard")
@logged_in_required
def dashboard():
    user, account = get_user_and_account(session["user_id"])
    return render_template("user_dashboard.html", user=user, account=account, app_name=APP_NAME)

@app.route("/deposit", methods=["GET", "POST"])
@logged_in_required
def deposit():
    user, account = get_user_and_account(session["user_id"])
    if request.method == "POST":
        try:
            amount = float(request.form.get("amount", "0").strip())
        except ValueError:
            amount = 0.0

        if amount <= 0:
            flash("Enter a positive amount.", "danger")
            return redirect(url_for("deposit"))

        conn = get_db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()
            # Get fresh balance
            cur.execute("SELECT balance FROM accounts WHERE user_id=?", (user["id"],))
            bal = cur.fetchone()["balance"]
            new_bal = bal + amount
            cur.execute("UPDATE accounts SET balance=? WHERE user_id=?", (new_bal, user["id"]))
            cur.execute(
                "INSERT INTO transactions (user_id, type, amount, counterparty_ac, created_at, balance_after) VALUES (?, ?, ?, ?, ?, ?)",
                (user["id"], "deposit", amount, None, datetime.utcnow().isoformat(), new_bal)
            )
            conn.commit()
            flash("Deposit successful.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Deposit failed: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for("dashboard"))
    return render_template("deposit.html", user=user, account=account, app_name=APP_NAME)

@app.route("/transfer", methods=["GET", "POST"])
@logged_in_required
def transfer():
    user, account = get_user_and_account(session["user_id"])
    if request.method == "POST":
        target_ac = request.form.get("target_ac", "").strip()
        try:
            amount = float(request.form.get("amount", "0").strip())
        except ValueError:
            amount = 0.0

        if amount <= 0:
            flash("Enter a positive amount.", "danger")
            return redirect(url_for("transfer"))
        if not target_ac:
            flash("Target account number required.", "danger")
            return redirect(url_for("transfer"))

        conn = get_db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()

            # Fetch sender balance
            cur.execute("SELECT balance FROM accounts WHERE user_id=?", (user["id"],))
            sender_bal = cur.fetchone()["balance"]
            if sender_bal < amount:
                raise ValueError("Insufficient funds.")

            # Find target user/account
            cur.execute("SELECT id FROM users WHERE account_number=?", (target_ac,))
            target_user_row = cur.fetchone()
            if not target_user_row:
                raise ValueError("Target account not found.")
            target_user_id = target_user_row["id"]

            # Update balances
            new_sender_bal = sender_bal - amount
            cur.execute("UPDATE accounts SET balance=? WHERE user_id=?", (new_sender_bal, user["id"]))

            cur.execute("SELECT balance FROM accounts WHERE user_id=?", (target_user_id,))
            target_bal = cur.fetchone()["balance"]
            new_target_bal = target_bal + amount
            cur.execute("UPDATE accounts SET balance=? WHERE user_id=?", (new_target_bal, target_user_id))

            # Record transactions
            now = datetime.utcnow().isoformat()
            cur.execute(
                "INSERT INTO transactions (user_id, type, amount, counterparty_ac, created_at, balance_after) VALUES (?, ?, ?, ?, ?, ?)",
                (user["id"], "transfer_out", amount, target_ac, now, new_sender_bal)
            )
            # Need counterparty account for target (sender's account)
            cur.execute("SELECT account_number FROM users WHERE id=?", (user["id"],))
            sender_ac = cur.fetchone()["account_number"]
            cur.execute(
                "INSERT INTO transactions (user_id, type, amount, counterparty_ac, created_at, balance_after) VALUES (?, ?, ?, ?, ?, ?)",
                (target_user_id, "transfer_in", amount, sender_ac, now, new_target_bal)
            )

            conn.commit()
            flash("Transfer successful.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Transfer failed: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for("dashboard"))
    return render_template("transfer.html", user=user, account=account, app_name=APP_NAME)

@app.route("/history")
@logged_in_required
def history():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY datetime(created_at) DESC", (session["user_id"],))
    txns = cur.fetchall()
    conn.close()
    user, account = get_user_and_account(session["user_id"])
    return render_template("history.html", user=user, account=account, txns=txns, app_name=APP_NAME)

# -----------------------------
# Routes: Admin
# -----------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == ADMIN_USER and password == ADMIN_PASS:
            session.clear()
            session["is_admin"] = True
            flash("Admin login successful.", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid admin credentials.", "danger")
            return redirect(url_for("admin_login"))
    return render_template("admin_login.html", app_name=APP_NAME)

@app.route("/admin/logout")
@admin_required
def admin_logout():
    session.clear()
    flash("Admin logged out.", "info")
    return redirect(url_for("index"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM users")
    user_count = cur.fetchone()["c"]
    cur.execute("SELECT IFNULL(SUM(balance),0) AS total_bal FROM accounts")
    total_bal = cur.fetchone()["total_bal"]
    cur.execute("SELECT COUNT(*) AS tx_count FROM transactions")
    tx_count = cur.fetchone()["tx_count"]
    conn.close()
    return render_template("admin_dashboard.html", user_count=user_count, total_bal=total_bal, tx_count=tx_count, app_name=APP_NAME)

@app.route("/admin/users")
@admin_required
def admin_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, account_number, created_at FROM users ORDER BY id DESC")
    users = cur.fetchall()
    conn.close()
    return render_template("users.html", users=users, app_name=APP_NAME)

@app.route("/admin/users/<int:user_id>/transactions")
@admin_required
def admin_user_transactions(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name, account_number FROM users WHERE id=?", (user_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("admin_users"))
    cur.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY datetime(created_at) DESC", (user_id,))
    txns = cur.fetchall()
    conn.close()
    return render_template("user_transactions.html", user=user, txns=txns, app_name=APP_NAME)

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        flash("User deleted.", "info")
    except Exception as e:
        conn.rollback()
        flash(f"Delete failed: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for("admin_users"))

# -----------------------------
# Static uploads (optional direct serving)
# -----------------------------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# -----------------------------
# Entry
# -----------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
