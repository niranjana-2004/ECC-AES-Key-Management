
from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from src.ecc_key_protection import generate_ecc_key_pair


PROJECT_ROOT = Path(__file__).resolve().parent.parent
KEY_DIRECTORY = PROJECT_ROOT / "keys"
PRIVATE_KEY_PATH = KEY_DIRECTORY / "recipient_private_key.pem"


def save_private_key(private_key, password: str) -> None:
    """Save the ECC private key in password-encrypted PKCS#8 PEM format."""

    if not password:
        raise ValueError("A password is required.")

    KEY_DIRECTORY.mkdir(parents=True, exist_ok=True)

    encrypted_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ),
    )

    if PRIVATE_KEY_PATH.exists():
        raise FileExistsError(
            "Private key already exists. Refusing to overwrite it."
        )

    PRIVATE_KEY_PATH.write_bytes(encrypted_pem)


def load_private_key(password: str):
    """Load the ECC private key using its password."""

    if not PRIVATE_KEY_PATH.is_file():
        raise FileNotFoundError(
            f"Private key not found: {PRIVATE_KEY_PATH}"
        )

    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(),
        password=password.encode("utf-8"),
    )

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Stored key is not an ECC private key.")

    if not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError("Expected an ECC P-256 private key.")

    return private_key


def get_or_create_key_pair():
    """Load the existing recipient key or create a new encrypted one."""

    if PRIVATE_KEY_PATH.exists():
        print("Existing ECC private key found.")
        password = getpass("Enter your private-key password: ")

        private_key = load_private_key(password)
        print("ECC private key loaded successfully.")

    else:
        print("No ECC private key found. Creating a new key pair.")

        password = getpass("Create a password for your ECC private key: ")
        confirmation = getpass("Confirm your password: ")

        if len(password) < 12:
            raise ValueError(
                "Use a password containing at least 12 characters."
            )

        if password != confirmation:
            raise ValueError("Passwords do not match.")

        private_key, _ = generate_ecc_key_pair()
        save_private_key(private_key, password)

        print("Encrypted ECC private key saved successfully.")

    public_key = private_key.public_key()

    return private_key, public_key
