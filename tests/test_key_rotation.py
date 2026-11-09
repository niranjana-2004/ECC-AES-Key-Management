
import sys
import unittest
from pathlib import Path
from src.key_rotation import (
    rotate_ecc_key_pair,
    rotate_aes_data_key,
)

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

class TestAESDataKeyRotation(unittest.TestCase):

    def test_rotation_generates_new_aes_key(self):
        original_key = generate_aes_key()
        new_key = rotate_aes_data_key()

        self.assertEqual(len(original_key), 32)
        self.assertEqual(len(new_key), 32)

        self.assertNotEqual(
            original_key,
            new_key,
        )


    def test_rotated_key_can_encrypt_and_decrypt(self):
        original_data = b"Testing AES data key rotation."

        # Generate the original AES key.
        old_aes_key = generate_aes_key()

        # Encrypt the original data using the old key.
        old_ciphertext, old_nonce = encrypt_data(
            original_data,
            old_aes_key,
        )

        # Generate a new AES data key.
        new_aes_key = rotate_aes_data_key()

        # Re-encrypt the data using the new key.
        new_ciphertext, new_nonce = encrypt_data(
            original_data,
            new_aes_key,
        )

        # Recover the data using the new key.
        recovered_data = decrypt_data(
            new_ciphertext,
            new_aes_key,
            new_nonce,
        )

        self.assertEqual(
            recovered_data,
            original_data,
        )

        # The rotated key must be different from the old key.
        self.assertNotEqual(
            old_aes_key,
            new_aes_key,
        )

        # The old key must not successfully decrypt the new ciphertext.
        with self.assertRaises(Exception):
            decrypt_data(
                new_ciphertext,
                old_aes_key,
                new_nonce,
            )

if __name__ == "__main__":
    unittest.main()
