
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

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
from src.key_rotation import rotate_ecc_key_pair


class TestECCKeyRotation(unittest.TestCase):

    def test_rotation_preserves_file_decryption(self):
        original_data = b"Testing ECC key rotation."

        # Encrypt data with an AES key.
        aes_key = generate_aes_key()
        ciphertext, nonce = encrypt_data(original_data, aes_key)

        # Protect the AES key with the old ECC key pair.
        old_private_key, old_public_key = generate_ecc_key_pair()
        old_package = protect_aes_key(aes_key, old_public_key)

        # Rotate the ECC key pair.
        new_private_key, new_public_key, new_package = (
            rotate_ecc_key_pair(old_package, old_private_key)
        )

        # The encrypted file remains unchanged.
        recovered_aes_key = recover_aes_key(
            new_package, new_private_key
        )
        recovered_data = decrypt_data(
            ciphertext, recovered_aes_key, nonce
        )

        self.assertEqual(recovered_data, original_data)
        self.assertEqual(recovered_aes_key, aes_key)

        # The new private key must not recover the old package.
        # The old private key must not recover the new package.
        with self.assertRaises(Exception):
            recover_aes_key(new_package, old_private_key)

        with self.assertRaises(Exception):
            recover_aes_key(old_package, new_private_key)


if __name__ == "__main__":
    unittest.main()
