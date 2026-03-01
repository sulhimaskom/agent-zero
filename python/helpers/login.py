import bcrypt

from python.helpers import dotenv


def get_credentials_hash():
    """Get the bcrypt hash of stored credentials for session validation."""
    user = dotenv.get_dotenv_value("AUTH_LOGIN")
    password = dotenv.get_dotenv_value("AUTH_PASSWORD")
    if not user or not password:
        return None
    # Generate salt and hash with bcrypt (salt is embedded in hash)
    return hash_password(user, password)


def hash_password(user: str, password: str) -> str:
    """Hash a password with bcrypt using the username as salt key."""
    # Use username as the salt key for deterministic hashing based on user
    salt = bcrypt.gensalt(rounds=12)
    # Combine user and password for hashing
    return bcrypt.hashpw(f"{user}:{password}".encode(), salt).decode()


def verify_password(user: str, password: str, stored_hash: str) -> bool:
    """Verify a password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(f"{user}:{password}".encode(), stored_hash.encode())
    except Exception:
        return False


def is_login_required():
    user = dotenv.get_dotenv_value("AUTH_LOGIN")
    return bool(user)
