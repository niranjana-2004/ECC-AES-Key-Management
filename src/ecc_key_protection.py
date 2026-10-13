
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Domain separation: identifies this key-protection protocol.
HKDF_INFO = b"ecc-aes-key-protection-v1"
AAD = b"ecc-aes-key-protection-v1"


def generate_ecc_key_pair():
    """Generate an ECC P-256 private/public key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def _derive_wrapping_key(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive a 256-bit AES wrapping key from the ECDH shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=HKDF_INFO,
    ).derive(shared_secret)


def protect_aes_key(aes_key: bytes, recipient_public_key):
    """
    Protect an AES-256 key using ephemeral ECDH, HKDF and AES-GCM.

    The recipient's public key is used to establish a shared secret.
    Returns the information required to recover the AES key.
    """
    if len(aes_key) != 32:
        raise ValueError("Expected a 32-byte AES-256 key.")

    if not isinstance(recipient_public_key, ec.EllipticCurvePublicKey):
        raise TypeError("Expected an ECC public key.")

    # Create a fresh ephemeral ECC key pair for this operation.
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Establish a shared secret using ECDH.
    shared_secret = ephemeral_private_key.exchange(
        ec.ECDH(), recipient_public_key
    )

    salt = os.urandom(16)
    wrapping_key = _derive_wrapping_key(shared_secret, salt)

    # Encrypt and authenticate the AES key.
    nonce = os.urandom(12)
    wrapped_key = AESGCM(wrapping_key).encrypt(
        nonce, aes_key, AAD
    )

    # Store the ephemeral public key, not its private key.
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "ephemeral_public_key": ephemeral_public_bytes,
        "salt": salt,
        "nonce": nonce,
        "wrapped_key": wrapped_key,
    }


def recover_aes_key(protected_data: dict, recipient_private_key) -> bytes:
    """Recover the AES key using the recipient's ECC private key."""
    if not isinstance(recipient_private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Expected an ECC private key.")

    ephemeral_public_key = serialization.load_der_public_key(
        protected_data["ephemeral_public_key"]
    )

    if not isinstance(ephemeral_public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Stored ephemeral key is not an ECC public key.")

    # Derive the same shared secret using the recipient's private key.
    shared_secret = recipient_private_key.exchange(
        ec.ECDH(), ephemeral_public_key
    )

    wrapping_key = _derive_wrapping_key(
        shared_secret, protected_data["salt"]
    )

    # Authentication fails if the key, nonce, or ciphertext is incorrect.
    return AESGCM(wrapping_key).decrypt(
        protected_data["nonce"],
        protected_data["wrapped_key"],
        AAD,
    )
