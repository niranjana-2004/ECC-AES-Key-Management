from pathlib import Path

from src.auth_service import login
from src.cloud_workflow import (
    encrypt_and_upload,
    rotate_document_aes_key,
    download_and_decrypt,
)


PROJECT_ROOT = Path(__file__).resolve().parent

original_file = (
    PROJECT_ROOT
    / "sample_data"
    / "research_note.txt"
)

rotated_recovered_file = (
    PROJECT_ROOT
    / "results"
    / "rotated_cloud_recovered.txt"
)


print("=" * 60)
print("AES DATA-KEY ROTATION CLOUD INTEGRATION TEST")
print("=" * 60)


# ---------------------------------------------------------
# 1. Authenticate user
# ---------------------------------------------------------

user = login()

if user is None:
    raise RuntimeError("Authentication failed.")


# ---------------------------------------------------------
# 2. Upload original encrypted document
# ---------------------------------------------------------

print("\n[1] Creating initial encrypted cloud document...")

original_prefix = encrypt_and_upload(
    user,
    str(original_file),
)

print("\nInitial object prefix:", original_prefix)


# ---------------------------------------------------------
# 3. Rotate AES data key
# ---------------------------------------------------------

print("\n[2] Rotating AES data key...")

rotated_prefix = rotate_document_aes_key(
    user,
    original_prefix,
)

print("\nRotated object prefix:", rotated_prefix)


# ---------------------------------------------------------
# 4. Download and decrypt rotated version
# ---------------------------------------------------------

print("\n[3] Downloading and decrypting rotated document...")

download_and_decrypt(
    user,
    rotated_prefix,
    str(rotated_recovered_file),
)


# ---------------------------------------------------------
# 5. Verify recovered document
# ---------------------------------------------------------

print("\n[4] Verifying rotated document...")

original_data = original_file.read_bytes()
rotated_data = rotated_recovered_file.read_bytes()


if original_data != rotated_data:
    raise RuntimeError(
        "Rotation verification failed: "
        "recovered document differs from original."
    )


print(
    "SUCCESS: Rotated document matches the original!"
)


print("\n" + "=" * 60)
print("AES DATA-KEY ROTATION CLOUD TEST PASSED")
print("=" * 60)