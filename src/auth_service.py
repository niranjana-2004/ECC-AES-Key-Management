from getpass import getpass

from src.user_database import authenticate_user
from src.access_control import Role


def login():
    """
    Authenticate a user through the CLI.

    Returns the authenticated user record,
    or None if authentication fails.
    """

    print("\n===== ESKMS LOGIN =====")

    username = input("Username: ").strip()
    password = getpass("Password: ")

    user = authenticate_user(username, password)

    if user is None:
        print("\nAuthentication failed.")
        return None

    print("\nLogin successful!")
    print(f"Username : {user['username']}")
    print(f"Role     : {user['role']}")

    return user


def require_role(user, allowed_roles):
    """
    Check whether the authenticated user has one
    of the required roles.
    """

    if user is None:
        raise PermissionError("Authentication required.")

    user_role = Role(user["role"])

    if user_role not in allowed_roles:
        raise PermissionError(
            f"Access denied for role: {user_role.value}"
        )

    return True