import os
import sys
import time
import tempfile
from pathlib import Path

# Make sure the project root is available
PROJECT_ROOT = Path(__file__).resolve().parent
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

from src.key_splitting import (
    split_protected_key,
    reassemble_protected_key,
)

from src.cloud_storage import (
    upload_file,
    download_file,
)


def measure(func, *args):
    """Measure execution time of a function in milliseconds."""
    start = time.perf_counter()
    result = func(*args)
    end = time.perf_counter()

    elapsed_ms = (end - start) * 1000

    return result, elapsed_ms


def main():

    print("=" * 60)
    print("SYSTEM 1 PERFORMANCE BENCHMARK")
    print("=" * 60)

    # ---------------------------------------------------------
    # 1. Prepare test data
    # ---------------------------------------------------------

    test_data = (
        b"ESKMS System 1 performance evaluation test document.\n"
        * 10000
    )

    print("\nTest data size:", len(test_data), "bytes")

    # ---------------------------------------------------------
    # 2. Generate AES key
    # ---------------------------------------------------------

    aes_key, aes_key_generation_time = measure(
        generate_aes_key
    )

    print(
        f"\nAES-256 key generation: "
        f"{aes_key_generation_time:.4f} ms"
    )

    # ---------------------------------------------------------
    # 3. AES encryption
    # ---------------------------------------------------------

    (ciphertext, nonce), aes_encryption_time = measure(
        encrypt_data,
        test_data,
        aes_key,
    )

    print(
        f"AES-256 encryption: "
        f"{aes_encryption_time:.4f} ms"
    )

    print(
        f"Encrypted data size: "
        f"{len(ciphertext)} bytes"
    )

    # ---------------------------------------------------------
    # 4. AES decryption
    # ---------------------------------------------------------

    recovered_data, aes_decryption_time = measure(
        decrypt_data,
        ciphertext,
        aes_key,
        nonce,
    )

    print(
        f"AES-256 decryption: "
        f"{aes_decryption_time:.4f} ms"
    )

    print(
        "AES verification:",
        "PASS" if recovered_data == test_data else "FAIL"
    )

    # ---------------------------------------------------------
    # 5. ECC key-pair generation
    # ---------------------------------------------------------

    (ecc_private_key, ecc_public_key), ecc_generation_time = measure(
        generate_ecc_key_pair
    )

    print(
        f"\nECC P-256 key-pair generation: "
        f"{ecc_generation_time:.4f} ms"
    )

    # ---------------------------------------------------------
    # 6. ECC protection of AES key
    # ---------------------------------------------------------

    protected_key, ecc_protection_time = measure(
        protect_aes_key,
        aes_key,
        ecc_public_key,
    )

    print(
        f"ECC AES-key protection: "
        f"{ecc_protection_time:.4f} ms"
    )

    # ---------------------------------------------------------
    # 7. ECC recovery of AES key
    # ---------------------------------------------------------

    recovered_aes_key, ecc_recovery_time = measure(
        recover_aes_key,
        protected_key,
        ecc_private_key,
    )

    print(
        f"ECC AES-key recovery: "
        f"{ecc_recovery_time:.4f} ms"
    )

    print(
        "ECC key recovery verification:",
        "PASS" if recovered_aes_key == aes_key else "FAIL"
    )

    # ---------------------------------------------------------
    # 8. Key splitting
    # ---------------------------------------------------------

    split_result, key_split_time = measure(
        split_protected_key,
        protected_key,
    )

    metadata, part1, part2 = split_result

    print(
        f"\nKey splitting: "
        f"{key_split_time:.4f} ms"
    )

    print(
        f"Key part 1 size: {len(part1)} bytes"
    )

    print(
        f"Key part 2 size: {len(part2)} bytes"
    )

    # ---------------------------------------------------------
    # 9. Key reassembly
    # ---------------------------------------------------------

    reassembled_key, key_reassembly_time = measure(
        reassemble_protected_key,
        metadata,
        part1,
        part2,
    )

    print(
        f"Key reassembly: "
        f"{key_reassembly_time:.4f} ms"
    )

    print(
        "Key reassembly verification:",
        "PASS"
        if reassembled_key["wrapped_key"]
        == protected_key["wrapped_key"]
        else "FAIL"
    )

    # ---------------------------------------------------------
    # 10. Cloud upload
    # ---------------------------------------------------------

    with tempfile.TemporaryDirectory() as temp_dir:

        temp_dir = Path(temp_dir)

        encrypted_file = temp_dir / "benchmark.enc"

        encrypted_file.write_bytes(ciphertext)

        object_name = (
            "benchmarks/benchmark_system1.enc"
        )

        print("\nUploading encrypted file to MinIO...")

        uploaded_object, cloud_upload_time = measure(
            upload_file,
            str(encrypted_file),
            object_name,
        )

        print(
            f"Cloud upload time: "
            f"{cloud_upload_time:.4f} ms"
        )

        print(
            f"Uploaded object: {uploaded_object}"
        )

        # -----------------------------------------------------
        # 11. Cloud download
        # -----------------------------------------------------

        downloaded_file = (
            temp_dir / "benchmark_downloaded.enc"
        )

        print("\nDownloading encrypted file from MinIO...")

        downloaded_path, cloud_download_time = measure(
            download_file,
            object_name,
            str(downloaded_file),
        )

        print(
            f"Cloud download time: "
            f"{cloud_download_time:.4f} ms"
        )

        downloaded_data = downloaded_file.read_bytes()

        print(
            "Cloud ciphertext verification:",
            "PASS"
            if downloaded_data == ciphertext
            else "FAIL"
        )

    # ---------------------------------------------------------
    # 12. Communication/storage overhead
    # ---------------------------------------------------------

    ciphertext_overhead = (
        len(ciphertext) - len(test_data)
    )

    protected_key_size = (
        len(protected_key["ephemeral_public_key"])
        + len(protected_key["salt"])
        + len(protected_key["nonce"])
        + len(protected_key["wrapped_key"])
    )

    total_key_split_storage = (
        len(part1) + len(part2)
    )

    print("\n" + "=" * 60)
    print("BENCHMARK SUMMARY")
    print("=" * 60)

    print(
        f"Original data size:          {len(test_data)} bytes"
    )

    print(
        f"Encrypted data size:         {len(ciphertext)} bytes"
    )

    print(
        f"AES ciphertext overhead:     "
        f"{ciphertext_overhead} bytes"
    )

    print(
        f"ECC protected-key package:   "
        f"{protected_key_size} bytes"
    )

    print(
        f"Split key payload storage:   "
        f"{total_key_split_storage} bytes"
    )

    print(
        f"\nAES encryption:              "
        f"{aes_encryption_time:.4f} ms"
    )

    print(
        f"AES decryption:              "
        f"{aes_decryption_time:.4f} ms"
    )

    print(
        f"ECC key protection:          "
        f"{ecc_protection_time:.4f} ms"
    )

    print(
        f"ECC key recovery:            "
        f"{ecc_recovery_time:.4f} ms"
    )

    print(
        f"Key splitting:               "
        f"{key_split_time:.4f} ms"
    )

    print(
        f"Key reassembly:              "
        f"{key_reassembly_time:.4f} ms"
    )

    print(
        f"Cloud upload:                "
        f"{cloud_upload_time:.4f} ms"
    )

    print(
        f"Cloud download:              "
        f"{cloud_download_time:.4f} ms"
    )

    print("\n" + "=" * 60)
    print("SYSTEM 1 BENCHMARK COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()