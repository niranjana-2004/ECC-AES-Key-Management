import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from cryptography.exceptions import InvalidTag

from src.aes_encryption import (
    generate_aes_key,
    encrypt_data,
    decrypt_data,
)

from src.ecc_key_protection import (
    generate_ecc_key_pair,
    protect_aes_key,
    recover_aes_key,
)


def main():

    print("=" * 60)
    print("SYSTEM 1 TAMPER-DETECTION SECURITY TEST")
    print("=" * 60)

    # ---------------------------------------------------------
    # 1. Prepare original data and AES key
    # ---------------------------------------------------------

    original_data = (
        b"ESKMS System 1 security testing document."
    )

    aes_key = generate_aes_key()

    # ---------------------------------------------------------
    # 2. Encrypt original document
    # ---------------------------------------------------------

    ciphertext, nonce = encrypt_data(
        original_data,
        aes_key
    )

    print("\nOriginal document encrypted successfully.")

    # ---------------------------------------------------------
    # 3. Tamper with ciphertext
    # ---------------------------------------------------------

    tampered_ciphertext = bytearray(ciphertext)

    tampered_ciphertext[0] ^= 1

    tampered_ciphertext = bytes(tampered_ciphertext)

    print("\n[1] Testing tampered ciphertext rejection...")

    try:

        decrypt_data(
            tampered_ciphertext,
            aes_key,
            nonce
        )

        print(
            "FAIL: Tampered ciphertext was accepted."
        )

    except InvalidTag:

        print(
            "PASS: Tampered ciphertext was rejected."
        )

    # ---------------------------------------------------------
    # 4. ECC key protection
    # ---------------------------------------------------------

    private_key, public_key = generate_ecc_key_pair()

    protected_key = protect_aes_key(
        aes_key,
        public_key
    )

    recovered_key = recover_aes_key(
        protected_key,
        private_key
    )

    print(
        "\nECC-protected AES key recovery:",
        "PASS"
        if recovered_key == aes_key
        else "FAIL"
    )

    # ---------------------------------------------------------
    # 5. Tamper with wrapped AES key
    # ---------------------------------------------------------

    tampered_protected_key = protected_key.copy()

    tampered_wrapped_key = bytearray(
        tampered_protected_key["wrapped_key"]
    )

    tampered_wrapped_key[0] ^= 1

    tampered_protected_key["wrapped_key"] = bytes(
        tampered_wrapped_key
    )

    print(
        "\n[2] Testing tampered ECC-protected AES-key rejection..."
    )

    try:

        recover_aes_key(
            tampered_protected_key,
            private_key
        )

        print(
            "FAIL: Tampered protected AES key was accepted."
        )

    except InvalidTag:

        print(
            "PASS: Tampered protected AES key was rejected."
        )

    print("\n" + "=" * 60)
    print("TAMPER-DETECTION SECURITY TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()