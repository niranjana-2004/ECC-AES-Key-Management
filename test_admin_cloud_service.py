from src.user_database import initialize_database, authenticate_user
from src.rbac_cloud_service import (
    list_documents,
    upload_document,
    download_document,
    delete_document,
)


initialize_database()

username = input("Admin username: ")
password = input("Admin password: ")

admin = authenticate_user(username, password)

if admin is None:
    print("\nERROR: Admin authentication failed.")
    exit(1)

print("\n===== ADMIN RBAC CLOUD TEST =====")
print(f"Username: {admin['username']}")
print(f"Role: {admin['role']}")
print()


print("[1] Testing document listing...")

try:
    objects = list_documents(admin)

    print("LIST ALLOWED")
    print(f"Objects found: {len(objects)}")

except PermissionError as error:
    print(f"LIST DENIED: {error}")


print("\n[2] Testing upload permission...")

try:
    upload_document(
        admin,
        "sample_data/research_note.txt",
        "admin_rbac_test/research_note.txt"
    )

    print("UPLOAD ALLOWED")

except PermissionError as error:
    print(f"UPLOAD DENIED: {error}")


print("\n[3] Testing download permission...")

try:
    download_document(
        admin,
        "admin_rbac_test/research_note.txt",
        "results/admin_rbac_download_test.txt"
    )

    print("DOWNLOAD ALLOWED")

except PermissionError as error:
    print(f"DOWNLOAD DENIED: {error}")


print("\n[4] Testing delete permission...")

try:
    delete_document(
        admin,
        "admin_rbac_test/research_note.txt"
    )

    print("DELETE ALLOWED")

except PermissionError as error:
    print(f"DELETE DENIED: {error}")


print("\nADMIN RBAC cloud service test completed!")