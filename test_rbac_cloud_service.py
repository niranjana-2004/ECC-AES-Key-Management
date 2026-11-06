from src.user_database import initialize_database, authenticate_user
from src.rbac_cloud_service import (
    list_documents,
    upload_document,
    download_document,
    delete_document,
)


initialize_database()

user = authenticate_user(
    "testuser",
    "TestPassword123!"
)

if user is None:
    print("ERROR: Could not authenticate test user.")
    exit(1)


print("===== RBAC CLOUD SERVICE TEST =====")
print(f"Username: {user['username']}")
print(f"Role: {user['role']}")
print()


print("[1] Testing document listing...")

try:
    objects = list_documents(user)

    print("LIST ALLOWED")
    print(f"Objects found: {len(objects)}")

except PermissionError as error:
    print(f"LIST DENIED: {error}")


print("\n[2] Testing upload permission...")

try:
    upload_document(
        user,
        "sample_data/research_note.txt",
        "rbac_test/research_note.txt"
    )

    print("UPLOAD ALLOWED")

except PermissionError as error:
    print(f"UPLOAD DENIED: {error}")


print("\n[3] Testing download permission...")

try:
    download_document(
        user,
        "rbac_test/research_note.txt",
        "results/rbac_download_test.txt"
    )

    print("DOWNLOAD ALLOWED")

except PermissionError as error:
    print(f"DOWNLOAD DENIED: {error}")


print("\n[4] Testing delete permission...")

try:
    delete_document(
        user,
        "rbac_test/research_note.txt"
    )

    print("DELETE ALLOWED")

except PermissionError as error:
    print(f"DELETE DENIED: {error}")


print("\nRBAC cloud service test completed!")