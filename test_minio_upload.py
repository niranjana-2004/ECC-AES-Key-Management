
from pathlib import Path

from src.cloud_storage import upload_file, list_files

project_root = Path(__file__).resolve().parent

encrypted_file = project_root / "results" / "research_note.enc"

print("Starting encrypted file upload...")

uploaded_object = upload_file(
    str(encrypted_file),
    object_name="research_note.enc",
)

print(f"Upload successful: {uploaded_object}")

print("\nObjects currently stored in MinIO:")

for filename in list_files():
    print("-", filename)
