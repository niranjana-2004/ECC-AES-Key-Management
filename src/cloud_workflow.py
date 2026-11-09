from src.auth_service import login
from src.access_control import Permission, has_permission
import base64
import json
import tempfile
import uuid

from pathlib import Path

from src.aes_encryption import (
    generate_aes_key,
    encrypt_data,
    decrypt_data,
)

from src.ecc_key_protection import (
    protect_aes_key,
    recover_aes_key,
)

from src.key_splitting import (
    split_protected_key,
    reassemble_protected_key,
)

from src.key_storage import get_or_create_key_pair

from src.cloud_storage import (
    upload_file,
    download_file,
)
from src.key_rotation import rotate_aes_data_key


def _encode_bytes(data: bytes) -> str:
    """Encode bytes for JSON storage."""
    return base64.b64encode(data).decode("ascii")


def _decode_bytes(data: str) -> bytes:
    """Decode Base64 data."""
    return base64.b64decode(data, validate=True)


def encrypt_and_upload(user,input_path: str) -> str:
    """
    Encrypt a document, protect and split its AES key,
    then upload all required components to MinIO.
    """
    if user is None:
        raise PermissionError("Authentication required.")

    if not has_permission(user["role"], Permission.UPLOAD):
        raise PermissionError(
            f"Access denied: {user['role']} does not have UPLOAD permission."
        )

    source = Path(input_path)

    if not source.is_file():
        raise FileNotFoundError(
            f"Input file not found: {source}"
        )

    print("\n[1] Loading ECC recipient key pair...")

    _, public_key = get_or_create_key_pair()

    original_data = source.read_bytes()

    print("[2] Generating AES-256 key and encrypting document...")

    aes_key = generate_aes_key()
    ciphertext, file_nonce = encrypt_data(
        original_data,
        aes_key,
    )

    print("[3] Protecting AES key using ECC...")

    protected_package = protect_aes_key(
        aes_key,
        public_key,
    )

    print("[4] Splitting protected AES-key payload...")

    key_metadata, part1, part2 = split_protected_key(
        protected_package
    )

    # A unique prefix prevents accidental overwriting.
    object_prefix = f"documents/{uuid.uuid4().hex}"

    print("[5] Preparing cloud-storage objects...")

    metadata_json = {
        name: _encode_bytes(value)
        for name, value in key_metadata.items()
    }

    file_metadata = {
        "original_filename": source.name,
        "original_size": len(original_data),
        "encrypted_size": len(ciphertext),
        "file_nonce": _encode_bytes(file_nonce),
    }

    with tempfile.TemporaryDirectory() as temp_dir:

        temp_path = Path(temp_dir)

        encrypted_path = temp_path / "document.enc"
        metadata_path = temp_path / "key_metadata.json"
        part1_path = temp_path / "key_part1.bin"
        part2_path = temp_path / "key_part2.bin"
        file_metadata_path = temp_path / "file_metadata.json"

        encrypted_path.write_bytes(ciphertext)

        metadata_path.write_text(
            json.dumps(metadata_json, indent=4),
            encoding="utf-8",
        )

        part1_path.write_bytes(part1)
        part2_path.write_bytes(part2)

        file_metadata_path.write_text(
            json.dumps(file_metadata, indent=4),
            encoding="utf-8",
        )

        print("[6] Uploading encrypted document...")

        upload_file(
            str(encrypted_path),
            f"{object_prefix}/document.enc",
        )

        print("[7] Uploading protected key components...")

        upload_file(
            str(metadata_path),
            f"{object_prefix}/key_metadata.json",
        )

        upload_file(
            str(part1_path),
            f"{object_prefix}/key_part1.bin",
        )

        upload_file(
            str(part2_path),
            f"{object_prefix}/key_part2.bin",
        )

        upload_file(
            str(file_metadata_path),
            f"{object_prefix}/file_metadata.json",
        )

    print("\nCloud upload completed successfully!")
    print("Object prefix:", object_prefix)

    return object_prefix

def rotate_document_aes_key(
    user,
    object_prefix: str,
) -> str:
    """
    Rotate the AES data key for an existing encrypted document.

    The document is downloaded and decrypted using the current AES key.
    A new AES-256 key is then generated, the document is re-encrypted,
    and the new protected key package is uploaded under a new object prefix.

    Returns:
        str: New cloud object prefix.
    """
    if user is None:
        raise PermissionError("Authentication required.")

    if not has_permission(user["role"], Permission.UPLOAD):
        raise PermissionError(
            f"Access denied: {user['role']} does not have UPLOAD permission."
        )

    print("\n===== AES DATA-KEY ROTATION =====")

    print("\n[1] Loading ECC recipient key pair...")

    private_key, public_key = get_or_create_key_pair()

    with tempfile.TemporaryDirectory() as temp_dir:

        temp_path = Path(temp_dir)

        encrypted_path = temp_path / "document.enc"
        metadata_path = temp_path / "key_metadata.json"
        part1_path = temp_path / "key_part1.bin"
        part2_path = temp_path / "key_part2.bin"
        file_metadata_path = temp_path / "file_metadata.json"

        print("[2] Downloading current encrypted document...")

        download_file(
            f"{object_prefix}/document.enc",
            str(encrypted_path),
        )

        print("[3] Downloading current protected AES-key components...")

        download_file(
            f"{object_prefix}/key_metadata.json",
            str(metadata_path),
        )

        download_file(
            f"{object_prefix}/key_part1.bin",
            str(part1_path),
        )

        download_file(
            f"{object_prefix}/key_part2.bin",
            str(part2_path),
        )

        download_file(
            f"{object_prefix}/file_metadata.json",
            str(file_metadata_path),
        )

        print("[4] Recovering current AES data key...")

        encoded_metadata = json.loads(
            metadata_path.read_text(encoding="utf-8")
        )

        key_metadata = {
            name: _decode_bytes(value)
            for name, value in encoded_metadata.items()
        }

        protected_package = reassemble_protected_key(
            key_metadata,
            part1_path.read_bytes(),
            part2_path.read_bytes(),
        )

        old_aes_key = recover_aes_key(
            protected_package,
            private_key,
        )

        file_metadata = json.loads(
            file_metadata_path.read_text(encoding="utf-8")
        )

        file_nonce = _decode_bytes(
            file_metadata["file_nonce"]
        )

        ciphertext = encrypted_path.read_bytes()

        original_data = decrypt_data(
            ciphertext,
            old_aes_key,
            file_nonce,
        )

        print("[5] Generating NEW AES-256 data key...")

        new_aes_key = rotate_aes_data_key()

        print("[6] Re-encrypting document with NEW AES key...")

        new_ciphertext, new_file_nonce = encrypt_data(
            original_data,
            new_aes_key,
        )

        print("[7] Protecting NEW AES key using ECC...")

        new_protected_package = protect_aes_key(
            new_aes_key,
            public_key,
        )

        print("[8] Splitting NEW protected AES-key payload...")

        new_key_metadata, new_part1, new_part2 = (
            split_protected_key(
                new_protected_package
            )
        )

        new_object_prefix = (
            f"documents/{uuid.uuid4().hex}"
        )

        new_metadata_json = {
            name: _encode_bytes(value)
            for name, value in new_key_metadata.items()
        }

        new_file_metadata = {
            "original_filename": file_metadata["original_filename"],
            "original_size": len(original_data),
            "encrypted_size": len(new_ciphertext),
            "file_nonce": _encode_bytes(new_file_nonce),
        }

        new_encrypted_path = temp_path / "new_document.enc"
        new_metadata_path = temp_path / "new_key_metadata.json"
        new_part1_path = temp_path / "new_key_part1.bin"
        new_part2_path = temp_path / "new_key_part2.bin"
        new_file_metadata_path = temp_path / "new_file_metadata.json"

        new_encrypted_path.write_bytes(new_ciphertext)

        new_metadata_path.write_text(
            json.dumps(
                new_metadata_json,
                indent=4,
            ),
            encoding="utf-8",
        )

        new_part1_path.write_bytes(new_part1)
        new_part2_path.write_bytes(new_part2)

        new_file_metadata_path.write_text(
            json.dumps(
                new_file_metadata,
                indent=4,
            ),
            encoding="utf-8",
        )

        print("[9] Uploading rotated encrypted document...")

        upload_file(
            str(new_encrypted_path),
            f"{new_object_prefix}/document.enc",
        )

        print("[10] Uploading rotated protected key components...")

        upload_file(
            str(new_metadata_path),
            f"{new_object_prefix}/key_metadata.json",
        )

        upload_file(
            str(new_part1_path),
            f"{new_object_prefix}/key_part1.bin",
        )

        upload_file(
            str(new_part2_path),
            f"{new_object_prefix}/key_part2.bin",
        )

        upload_file(
            str(new_file_metadata_path),
            f"{new_object_prefix}/file_metadata.json",
        )

        # Verify that the new key can decrypt the newly encrypted document.
        verification_plaintext = decrypt_data(
            new_ciphertext,
            new_aes_key,
            new_file_nonce,
        )

        if verification_plaintext != original_data:
            raise RuntimeError(
                "AES key rotation verification failed."
            )

    print("\nAES data-key rotation completed successfully!")
    print("Old object prefix:", object_prefix)
    print("New object prefix:", new_object_prefix)

    return new_object_prefix

def download_and_decrypt(
    user,
    object_prefix: str,
    output_path: str,
) -> str:
    """
    Download encrypted document and protected key components,
    recover the AES key, and decrypt the document.
    """
    if user is None:
        raise PermissionError("Authentication required.")

    if not has_permission(user["role"], Permission.DOWNLOAD):
        raise PermissionError(
            f"Access denied: {user['role']} does not have DOWNLOAD permission."
        )

    print("\n[1] Loading ECC recipient private key...")

    private_key, _ = get_or_create_key_pair()

    with tempfile.TemporaryDirectory() as temp_dir:

        temp_path = Path(temp_dir)

        encrypted_path = temp_path / "document.enc"
        metadata_path = temp_path / "key_metadata.json"
        part1_path = temp_path / "key_part1.bin"
        part2_path = temp_path / "key_part2.bin"
        file_metadata_path = temp_path / "file_metadata.json"

        print("[2] Downloading encrypted document...")

        download_file(
            f"{object_prefix}/document.enc",
            str(encrypted_path),
        )

        print("[3] Downloading protected key components...")

        download_file(
            f"{object_prefix}/key_metadata.json",
            str(metadata_path),
        )

        download_file(
            f"{object_prefix}/key_part1.bin",
            str(part1_path),
        )

        download_file(
            f"{object_prefix}/key_part2.bin",
            str(part2_path),
        )

        download_file(
            f"{object_prefix}/file_metadata.json",
            str(file_metadata_path),
        )

        print("[4] Reconstructing protected AES key...")

        encoded_metadata = json.loads(
            metadata_path.read_text(encoding="utf-8")
        )

        key_metadata = {
            name: _decode_bytes(value)
            for name, value in encoded_metadata.items()
        }

        reconstructed_package = reassemble_protected_key(
            key_metadata,
            part1_path.read_bytes(),
            part2_path.read_bytes(),
        )

        print("[5] Recovering AES key using ECC...")

        recovered_aes_key = recover_aes_key(
            reconstructed_package,
            private_key,
        )

        print("[6] Decrypting downloaded document...")

        file_metadata = json.loads(
            file_metadata_path.read_text(encoding="utf-8")
        )

        file_nonce = _decode_bytes(
            file_metadata["file_nonce"]
        )

        ciphertext = encrypted_path.read_bytes()

        plaintext = decrypt_data(
            ciphertext,
            recovered_aes_key,
            file_nonce,
        )

        if len(plaintext) != file_metadata["original_size"]:
            raise RuntimeError(
                "Recovered file size does not match metadata."
            )

        destination = Path(output_path)
        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        destination.write_bytes(plaintext)

    print("[7] Cloud decryption completed successfully!")
    print("Recovered file:", destination)

    return str(destination)
