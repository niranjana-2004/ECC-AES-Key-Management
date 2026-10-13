
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_aes_key() -> bytes:
    """Generate a cryptographically secure 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)

def encrypt_data(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt data using AES-256-GCM.

    Returns:
        ciphertext: Encrypted data with authentication tag.
        nonce: Random nonce required for decryption.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    return ciphertext, nonce


def decrypt_data(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes
) -> bytes:
    """Decrypt and authenticate AES-256-GCM encrypted data."""
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
