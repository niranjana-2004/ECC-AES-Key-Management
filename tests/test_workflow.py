
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.aes_encryption import generate_aes_key
from src.ecc_key_protection import (
    generate_ecc_key_pair,
    protect_aes_key,
    recover_aes_key,
)
from src.key_splitting import (
    split_protected_key,
    reassemble_protected_key,
)
from src.file_service import encrypt_file, decrypt_file


class TestCompleteWorkflow(unittest.TestCase):

    def test_encrypt_protect_split_recover_decrypt_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir)

            original_file = folder / "original.txt"
            encrypted_file = folder / "encrypted.bin"
            recovered_file = folder / "recovered.txt"

            original_data = (
                b"Complete ECC-AES research workflow test."
            )
            original_file.write_bytes(original_data)

            # Encrypt the file
            aes_key = generate_aes_key()
            metadata = encrypt_file(
                str(original_file),
                str(encrypted_file),
                aes_key,
            )

            # Protect the AES key
            private_key, public_key = generate_ecc_key_pair()
            package = protect_aes_key(aes_key, public_key)

            # Split and reconstruct the protected package
            key_metadata, part1, part2 = split_protected_key(package)

            reconstructed = reassemble_protected_key(key_metadata,part1,part2)

            # Recover the AES key
            recovered_key = recover_aes_key(
                reconstructed, private_key
            )

            # Decrypt the file
            decrypt_file(
                str(encrypted_file),
                str(recovered_file),
                recovered_key,
                metadata["nonce"],
            )

            self.assertEqual(
                recovered_file.read_bytes(),
                original_file.read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
