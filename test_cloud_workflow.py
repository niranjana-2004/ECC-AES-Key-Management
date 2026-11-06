from pathlib import Path

from src.auth_service import login

from src.cloud_workflow import (
    encrypt_and_upload,
    download_and_decrypt,
)


project_root = Path(__file__).resolve().parent

original_file = (
    project_root / "sample_data" / "research_note.txt"
)

recovered_file = (
    project_root / "results" / "cloud_recovered.txt"
)

print("=" * 55)
print("ECC-AES CLOUD STORAGE INTEGRATION TEST")
print("=" * 55)

# Step 0: Authenticate user.
user = login()

if user is None:
    raise RuntimeError("Authentication failed.")

# Step 1: Encrypt and upload.
object_prefix = encrypt_and_upload(
    user,
    str(original_file)
)

print("\nUploaded object prefix:", object_prefix)

# Step 2: Download and decrypt.
download_and_decrypt(
    user,
    object_prefix,
    str(recovered_file),
)

# Step 3: Verify the recovered document.
original_data = original_file.read_bytes()
recovered_data = recovered_file.read_bytes()

print("\nVerifying recovered document...")

if original_data == recovered_data:
    print("SUCCESS: Original and recovered files are identical!")
else:
    raise RuntimeError(
        "Verification failed: file contents differ."
    )

print("\n" + "=" * 55)
print("COMPLETE CLOUD WORKFLOW TEST PASSED")
print("=" * 55)