from getpass import getpass

from src.user_database import authenticate_user
from src.access_control import Role
from src.two_factor_auth import verify_totp


def login():
    print("\n===== ESKMS LOGIN =====")

    username = input("Username: ").strip()
    password = getpass("Password: ")

    user = authenticate_user(username, password)

    if user is None:
        print("\nAuthentication failed.")
        return None

    # Check whether 2FA is enabled for this account
    if user["two_factor_enabled"]:
        print("\nTwo-factor authentication enabled.")

        code = getpass("Enter 6-digit TOTP code: ").strip()

        if not verify_totp(user["two_factor_secret"], code):
            print("\nAuthentication failed: Invalid 2FA code.")
            return None

        print("2FA verification successful!")

    print("\nLogin successful!")
    print(f"Username : {user['username']}")
    print(f"Role     : {user['role']}")

    return user


def require_role(user, allowed_roles):
    if user is None:
        raise PermissionError("Authentication required.")

    user_role = Role(user["role"])

    if user_role not in allowed_roles:
        raise PermissionError(
            f"Access denied for role: {user_role.value}"
        )

    return True