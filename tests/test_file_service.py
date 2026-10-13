
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.aes_encryption import generate_aes_key
from src.file_service import encrypt_file, decrypt_file


class TestFileService(unittest.TestCase):

    def test_file_encryption_and_decryption(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir)

            original_file = folder / "original.txt"
            encrypted_file = folder / "encrypted.bin"
            decrypted_file = folder / "decrypted.txt"

            original_data = (
                b"Testing actual file encryption for my research."
            )
            original_file.write_bytes(original_data)

            key = generate_aes_key()

            metadata = encrypt_file(
                str(original_file),
                str(encrypted_file),
                key,
            )

            self.assertTrue(encrypted_file.is_file())
            self.assertNotEqual(
                encrypted_file.read_bytes(), original_data
            )

            decrypt_file(
                str(encrypted_file),
                str(decrypted_file),
                key,
                metadata["nonce"],
            )

            self.assertEqual(
                decrypted_file.read_bytes(), original_data
            )

    def test_missing_input_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_file = Path(temp_dir) / "missing.txt"
            output_file = Path(temp_dir) / "encrypted.bin"

            with self.assertRaises(FileNotFoundError):
                encrypt_file(
                    str(missing_file),
                    str(output_file),
                    generate_aes_key(),
                )


if __name__ == "__main__":
    unittest.main()
