from src.user_database import initialize_database, authenticate_user
from src.protected_operations import (
    protected_upload,
    protected_download,
    protected_delete,
    protected_list,
    protected_manage_users
)


initialize_database()


def get_test_user():
    return authenticate_user(
        "testuser",
        "TestPassword123!"
    )


user = get_test_user()

if user is None:
    print("ERROR: Could not authenticate test user.")
    exit(1)


print("===== TESTING PROTECTED OPERATIONS =====")
print(f"User  : {user['username']}")
print(f"Role  : {user['role']}\n")


print("[1] Testing upload...")
try:
    protected_upload(user)
except PermissionError as error:
    print(f"DENIED: {error}")


print("\n[2] Testing download...")
try:
    protected_download(user)
except PermissionError as error:
    print(f"DENIED: {error}")


print("\n[3] Testing list...")
try:
    protected_list(user)
except PermissionError as error:
    print(f"DENIED: {error}")


print("\n[4] Testing delete...")
try:
    protected_delete(user)
except PermissionError as error:
    print(f"DENIED: {error}")


print("\n[5] Testing user management...")
try:
    protected_manage_users(user)
except PermissionError as error:
    print(f"DENIED: {error}")


print("\nProtected operation test completed!")