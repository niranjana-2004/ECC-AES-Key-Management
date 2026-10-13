
from pathlib import Path

from src.aes_encryption import (
    generate_aes_key,
    encrypt_data,
    decrypt_data,
)


def encrypt_file(input_path: str, output_path: str, key: bytes) -> dict:
    """Encrypt a file and save its ciphertext and nonce."""
    source = Path(input_path)
    destination = Path(output_path)

    if not source.is_file():
        raise FileNotFoundError(f"Input file not found: {source}")

    if source.resolve() == destination.resolve():
        raise ValueError("Input and output paths must be different.")

    data = source.read_bytes()
    ciphertext, nonce = encrypt_data(data, key)

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(ciphertext)

    return {
        "nonce": nonce,
        "original_size": len(data),
        "encrypted_size": len(ciphertext),
    }


def decrypt_file(
    encrypted_path: str,
    output_path: str,
    key: bytes,
    nonce: bytes,
) -> None:
    """Decrypt a file and save the recovered original data."""
    source = Path(encrypted_path)
    destination = Path(output_path)

    if not source.is_file():
        raise FileNotFoundError(f"Encrypted file not found: {source}")

    if source.resolve() == destination.resolve():
        raise ValueError(
            "Encrypted input and decrypted output paths must be different."
        )

    ciphertext = source.read_bytes()
    plaintext = decrypt_data(ciphertext, key, nonce)

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(plaintext)
