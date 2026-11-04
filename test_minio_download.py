
from pathlib import Path

from src.cloud_storage import download_file
from src.aes_encryption import decrypt_data

project_root = Path(__file__).resolve().parent

encrypted_cloud_file = (
    project_root / "results" / "research_note_downloaded.enc"
)

original_file = (
    project_root / "sample_data" / "research_note.txt"
)

print("Downloading encrypted file from MinIO...")

download_file(
    object_name="research_note.enc",
    destination_path=str(encrypted_cloud_file),
)

print("Encrypted file downloaded successfully!")

print("\nComparing downloaded and original ciphertext...")

local_encrypted = (
    project_root / "results" / "research_note.enc"
).read_bytes()

downloaded_encrypted = encrypted_cloud_file.read_bytes()

if local_encrypted != downloaded_encrypted:
    raise RuntimeError("Downloaded ciphertext does not match!")

print("Ciphertext integrity comparison successful!")

print("\nNext step: decrypt using the original AES key and nonce.")
