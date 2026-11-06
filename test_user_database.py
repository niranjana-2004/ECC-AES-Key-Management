from src.user_database import (
    initialize_database,
    create_user,
    authenticate_user,
    get_user
)


print("Initializing user database...")
initialize_database()

print("Creating test user...")

try:
    create_user(
        username="testuser",
        password="TestPassword123!",
        role="USER"
    )
    print("User created successfully.")

except ValueError as error:
    print(f"User creation skipped: {error}")


print("\nTesting correct password...")

user = authenticate_user(
    "testuser",
    "TestPassword123!"
)

if user:
    print("Authentication successful!")
    print(f"Username: {user['username']}")
    print(f"Role: {user['role']}")
else:
    print("Authentication failed!")


print("\nTesting incorrect password...")

user = authenticate_user(
    "testuser",
    "WrongPassword123!"
)

if user is None:
    print("Incorrect password rejected successfully!")
else:
    print("ERROR: Incorrect password was accepted!")


print("\nTesting stored user...")

user = get_user("testuser")

if user:
    print(f"User ID: {user['id']}")
    print(f"Username: {user['username']}")
    print(f"Role: {user['role']}")
    print(f"Active: {bool(user['is_active'])}")

print("\nUser database test completed!")