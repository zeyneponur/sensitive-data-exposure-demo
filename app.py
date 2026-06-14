from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import hashlib
import bcrypt
from cryptography.fernet import Fernet
from pathlib import Path

app = Flask(__name__)
app.secret_key = "demo-secret-key"

DB_PATH = Path("security_demo.db")
FERNET_KEY_PATH = Path("fernet.key")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_fernet():
    """
    Demo için encryption key dosyada tutuluyor.
    Gerçek projede bu key source code içinde tutulmaz;
    environment variable veya secret manager gibi güvenli yerlerde tutulur.
    """
    if not FERNET_KEY_PATH.exists():
        FERNET_KEY_PATH.write_bytes(Fernet.generate_key())

    return Fernet(FERNET_KEY_PATH.read_bytes())


def sha256_hash(password: str) -> str:
    """
    SHA-256 genel amaçlı bir hash algoritmasıdır.
    Salt'ı otomatik üretmez; burada özellikle salting yapmadan kullanıyoruz.
    """
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def extract_bcrypt_salt(full_hash: str) -> str:
    """
    bcrypt çıktısında salt bilgisi hash stringinin içinde yer alır.
    Format: $2b$12$ + 22 karakterlik salt + hash çıktısı
    İlk 29 karakter salt bilgisini temsil eder.
    """
    return full_hash[:29]


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS plaintext_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS sha256_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt_info TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS bcrypt_salt_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt_value TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS encrypted_cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL,
                encrypted_card TEXT NOT NULL
            )
        """)


@app.route("/")
def index():
    with get_connection() as conn:
        plaintext_users = conn.execute("SELECT * FROM plaintext_users").fetchall()
        sha256_users = conn.execute("SELECT * FROM sha256_users").fetchall()
        bcrypt_salt_users = conn.execute("SELECT * FROM bcrypt_salt_users").fetchall()
        encrypted_cards = conn.execute("SELECT * FROM encrypted_cards").fetchall()

    return render_template(
        "index.html",
        plaintext_users=plaintext_users,
        sha256_users=sha256_users,
        bcrypt_salt_users=bcrypt_salt_users,
        encrypted_cards=encrypted_cards,
        login_result=None,
        hash_read_result=None,
        decrypted_card=None,
    )


@app.route("/plaintext/register", methods=["POST"])
def register_plaintext():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Düz metin demo için kullanıcı adı ve şifre gerekli.")
        return redirect(url_for("index"))

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO plaintext_users (username, password) VALUES (?, ?)",
            (username, password)
        )

    flash("Düz metin kayıt eklendi. Veritabanında şifre açık şekilde duruyor.")
    return redirect(url_for("index"))


@app.route("/sha256/register", methods=["POST"])
def register_sha256():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("SHA-256 demo için kullanıcı adı ve şifre gerekli.")
        return redirect(url_for("index"))

    password_hash = sha256_hash(password)

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO sha256_users (username, password_hash, salt_info) VALUES (?, ?, ?)",
            (username, password_hash, "Salt yok")
        )

    flash("SHA-256 algoritması ile salting yapmadan hash kaydı eklendi.")
    return redirect(url_for("index"))


@app.route("/bcrypt-salt/register", methods=["POST"])
def register_bcrypt_salt():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("bcrypt demo için kullanıcı adı ve şifre gerekli.")
        return redirect(url_for("index"))

    generated_salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        generated_salt
    ).decode("utf-8")

    salt_value = extract_bcrypt_salt(password_hash)

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO bcrypt_salt_users (username, password_hash, salt_value) VALUES (?, ?, ?)",
            (username, password_hash, salt_value)
        )

    flash("bcrypt algoritması ile salt kullanılarak hash kaydı eklendi.")
    return redirect(url_for("index"))


@app.route("/bcrypt/login", methods=["POST"])
def login_bcrypt():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with get_connection() as conn:
        user = conn.execute(
            "SELECT * FROM bcrypt_salt_users WHERE username = ? ORDER BY id DESC LIMIT 1",
            (username,)
        ).fetchone()

        plaintext_users = conn.execute("SELECT * FROM plaintext_users").fetchall()
        sha256_users = conn.execute("SELECT * FROM sha256_users").fetchall()
        bcrypt_salt_users = conn.execute("SELECT * FROM bcrypt_salt_users").fetchall()
        encrypted_cards = conn.execute("SELECT * FROM encrypted_cards").fetchall()

    if user is None:
        login_result = {
            "success": False,
            "message": "Kullanıcı bulunamadı. Önce 'Salt ile Hashleme' bölümünden kayıt ekleyin.",
            "username": username,
        }
    else:
        is_correct = bcrypt.checkpw(
            password.encode("utf-8"),
            user["password_hash"].encode("utf-8")
        )

        login_result = {
            "success": is_correct,
            "message": "Giriş başarılı. Şifre doğru." if is_correct else "Giriş başarısız. Şifre yanlış.",
            "username": username,
        }

    return render_template(
        "index.html",
        plaintext_users=plaintext_users,
        sha256_users=sha256_users,
        bcrypt_salt_users=bcrypt_salt_users,
        encrypted_cards=encrypted_cards,
        login_result=login_result,
        hash_read_result=None,
        decrypted_card=None,
    )


@app.route("/hash/read/<int:user_id>", methods=["POST"])
def try_read_hash(user_id):
    with get_connection() as conn:
        user = conn.execute("SELECT * FROM bcrypt_salt_users WHERE id = ?", (user_id,)).fetchone()
        plaintext_users = conn.execute("SELECT * FROM plaintext_users").fetchall()
        sha256_users = conn.execute("SELECT * FROM sha256_users").fetchall()
        bcrypt_salt_users = conn.execute("SELECT * FROM bcrypt_salt_users").fetchall()
        encrypted_cards = conn.execute("SELECT * FROM encrypted_cards").fetchall()

    if user is None:
        hash_read_result = {
            "success": False,
            "message": "Kayıt bulunamadı.",
            "hash": "",
        }
    else:
        hash_read_result = {
            "success": False,
            "message": "Bu hash geri okunamaz. Hashing tek yönlüdür; sistem şifreyi bulmaz, sadece doğrulama yapar.",
            "hash": user["password_hash"],
        }

    return render_template(
        "index.html",
        plaintext_users=plaintext_users,
        sha256_users=sha256_users,
        bcrypt_salt_users=bcrypt_salt_users,
        encrypted_cards=encrypted_cards,
        login_result=None,
        hash_read_result=hash_read_result,
        decrypted_card=None,
    )


@app.route("/card/encrypt", methods=["POST"])
def encrypt_card():
    owner = request.form.get("owner", "").strip()
    card_number = request.form.get("card_number", "").strip()

    if not owner or not card_number:
        flash("Encryption demo için isim ve kart numarası gerekli.")
        return redirect(url_for("index"))

    fernet = get_fernet()
    encrypted_card = fernet.encrypt(card_number.encode("utf-8")).decode("utf-8")

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO encrypted_cards (owner, encrypted_card) VALUES (?, ?)",
            (owner, encrypted_card)
        )

    flash("Kart numarası encryption ile şifrelenerek saklandı.")
    return redirect(url_for("index"))


@app.route("/card/decrypt/<int:card_id>", methods=["POST"])
def decrypt_card(card_id):
    with get_connection() as conn:
        card = conn.execute("SELECT * FROM encrypted_cards WHERE id = ?", (card_id,)).fetchone()
        plaintext_users = conn.execute("SELECT * FROM plaintext_users").fetchall()
        sha256_users = conn.execute("SELECT * FROM sha256_users").fetchall()
        bcrypt_salt_users = conn.execute("SELECT * FROM bcrypt_salt_users").fetchall()
        encrypted_cards = conn.execute("SELECT * FROM encrypted_cards").fetchall()

    decrypted_card = None

    if card is not None:
        fernet = get_fernet()
        decrypted_value = fernet.decrypt(card["encrypted_card"].encode("utf-8")).decode("utf-8")
        decrypted_card = {
            "owner": card["owner"],
            "encrypted_card": card["encrypted_card"],
            "plain_card": decrypted_value,
        }

    return render_template(
        "index.html",
        plaintext_users=plaintext_users,
        sha256_users=sha256_users,
        bcrypt_salt_users=bcrypt_salt_users,
        encrypted_cards=encrypted_cards,
        login_result=None,
        hash_read_result=None,
        decrypted_card=decrypted_card,
    )


@app.route("/reset", methods=["POST"])
def reset():
    with get_connection() as conn:
        conn.execute("DELETE FROM plaintext_users")
        conn.execute("DELETE FROM sha256_users")
        conn.execute("DELETE FROM bcrypt_salt_users")
        conn.execute("DELETE FROM encrypted_cards")

    flash("Demo veritabanı temizlendi.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
