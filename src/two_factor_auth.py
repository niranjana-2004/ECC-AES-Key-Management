import pyotp


def generate_secret() -> str:
    """
    Generate a new Base32 secret for a user.
    """
    return pyotp.random_base32()


def generate_totp(secret: str) -> str:
    """
    Generate the current 6-digit TOTP code.
    """
    totp = pyotp.TOTP(secret)
    return totp.now()


def verify_totp(secret: str, code: str) -> bool:
    """
    Verify a user-provided TOTP code.

    A small valid time window is allowed to account for
    minor clock differences.
    """
    if not secret:
        return False

    if not code:
        return False

    code = str(code).strip()

    if not code.isdigit() or len(code) != 6:
        return False

    totp = pyotp.TOTP(secret)

    return totp.verify(
        code,
        valid_window=1,
    )