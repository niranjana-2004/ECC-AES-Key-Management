import sqlite3
import hashlib
import secrets
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIRECTORY = PROJECT_ROOT / "data"
DATABASE_PATH = DATA_DIRECTORY / "users.db"


def get_connection():
    """Create a connection to the user database."""
    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """
    Create the users table if it does not already exist.
    Also add 2FA columns to existing databases.
    """
    connection = get_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                two_factor_secret TEXT,
                two_factor_enabled INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        # Migration for existing databases created before 2FA support.
        cursor = connection.execute(
            "PRAGMA table_info(users)"
        )

        existing_columns = {
            row["name"]
            for row in cursor.fetchall()
        }

        if "two_factor_secret" not in existing_columns:
            connection.execute(
                """
                ALTER TABLE users
                ADD COLUMN two_factor_secret TEXT
                """
            )

        if "two_factor_enabled" not in existing_columns:
            connection.execute(
                """
                ALTER TABLE users
                ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0
                """
            )

        connection.commit()

    finally:
        connection.close()


def hash_password(password):
    """Hash a password using PBKDF2-HMAC-SHA256."""
    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000
    )

    return (
        password_hash.hex(),
        salt.hex()
    )


def verify_password(password, stored_hash, stored_salt):
    """Verify a password against its stored hash."""
    salt = bytes.fromhex(stored_salt)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000
    )

    return secrets.compare_digest(
        password_hash.hex(),
        stored_hash
    )


def create_user(username, password, role="USER"):
    """Create a new user."""
    username = username.strip()

    if not username:
        raise ValueError("Username cannot be empty.")

    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")

    role = role.upper()

    allowed_roles = {"ADMIN", "USER", "VIEWER"}

    if role not in allowed_roles:
        raise ValueError(
            f"Invalid role. Allowed roles: {', '.join(sorted(allowed_roles))}"
        )

    password_hash, salt = hash_password(password)

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO users
            (
                username,
                password_hash,
                salt,
                role,
                is_active,
                two_factor_secret,
                two_factor_enabled
            )
            VALUES (?, ?, ?, ?, 1, NULL, 0)
            """,
            (
                username,
                password_hash,
                salt,
                role
            )
        )

        connection.commit()

    except sqlite3.IntegrityError:
        raise ValueError(
            f"Username '{username}' already exists."
        )

    finally:
        connection.close()


def get_user(username):
    """Retrieve a user by username."""
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            SELECT
                id,
                username,
                password_hash,
                salt,
                role,
                is_active,
                two_factor_secret,
                two_factor_enabled
            FROM users
            WHERE username = ?
            """,
            (username,)
        )

        return cursor.fetchone()

    finally:
        connection.close()


def authenticate_user(username, password):
    """Authenticate a user and return their user record."""
    user = get_user(username)

    if user is None:
        return None

    if not user["is_active"]:
        return None

    if not verify_password(
        password,
        user["password_hash"],
        user["salt"]
    ):
        return None

    return user


def enable_two_factor(username, secret):
    """Enable TOTP-based 2FA for a user."""
    if not secret:
        raise ValueError("2FA secret cannot be empty.")

    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            UPDATE users
            SET two_factor_secret = ?,
                two_factor_enabled = 1
            WHERE username = ?
            """,
            (secret, username)
        )

        if cursor.rowcount == 0:
            raise ValueError(
                f"User '{username}' does not exist."
            )

        connection.commit()

    finally:
        connection.close()


def disable_two_factor(username):
    """Disable TOTP-based 2FA for a user."""
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            UPDATE users
            SET two_factor_secret = NULL,
                two_factor_enabled = 0
            WHERE username = ?
            """,
            (username,)
        )

        if cursor.rowcount == 0:
            raise ValueError(
                f"User '{username}' does not exist."
            )

        connection.commit()

    finally:
        connection.close()


def get_two_factor_status(username):
    """Return 2FA configuration for a user."""
    user = get_user(username)

    if user is None:
        return None

    return {
        "enabled": bool(user["two_factor_enabled"]),
        "secret": user["two_factor_secret"],
    }