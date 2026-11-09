import os
import sys
import time
import uuid
import threading
from pathlib import Path

import psutil

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


def monitor_resources(stop_event, samples):
    """Continuously record CPU and memory usage."""
    process = psutil.Process(os.getpid())

    while not stop_event.is_set():
        cpu = process.cpu_percent(interval=0.1)
        memory = process.memory_info().rss / (1024 * 1024)

        samples.append({
            "cpu": cpu,
            "memory": memory,
        })


def calculate_average(values):
    if not values:
        return 0.0

    return sum(values) / len(values)


def main():
    print("=" * 60)
    print("SYSTEM 1 RESOURCE USAGE EVALUATION")
    print("=" * 60)

    # ---------------------------------------------------------
    # Test data
    # ---------------------------------------------------------

    test_data = (
        b"ESKMS System 1 resource usage evaluation document. "
        * 10000
    )

    print(f"\nTest data size: {len(test_data)} bytes")

    # ---------------------------------------------------------
    # Resource monitoring setup
    # ---------------------------------------------------------

    samples = []
    stop_event = threading.Event()

    monitor = threading.Thread(
        target=monitor_resources,
        args=(stop_event, samples),
        daemon=True,
    )

    process = psutil.Process(os.getpid())

    baseline_memory = (
        process.memory_info().rss / (1024 * 1024)
    )

    monitor.start()

    start_time = time.perf_counter()

    # ---------------------------------------------------------
    # SYSTEM 1 WORKFLOW
    # ---------------------------------------------------------

    print("\nStarting System 1 cryptographic workflow...")

    # AES key generation
    aes_key = generate_aes_key()

    # AES encryption
    ciphertext, nonce = encrypt_data(
        test_data,
        aes_key
    )

    # ECC key-pair generation
    private_key, public_key = generate_ecc_key_pair()

    # ECC protection of AES key
    protected_key = protect_aes_key(
        aes_key,
        public_key
    )

    # Split protected AES-key payload
    metadata, part1, part2 = split_protected_key(
        protected_key
    )

    # Reassemble protected AES-key payload
    reassembled_key = reassemble_protected_key(
        metadata,
        part1,
        part2
    )

    # ECC recovery
    recovered_aes_key = recover_aes_key(
        reassembled_key,
        private_key
    )

    # AES decryption
    recovered_data = decrypt_data(
        ciphertext,
        recovered_aes_key,
        nonce
    )

    end_time = time.perf_counter()

    # ---------------------------------------------------------
    # Stop monitoring
    # ---------------------------------------------------------

    stop_event.set()
    monitor.join(timeout=1)

    peak_memory = max(
        (sample["memory"] for sample in samples),
        default=baseline_memory
    )

    average_cpu = calculate_average(
        [sample["cpu"] for sample in samples]
    )

    peak_cpu = max(
        (sample["cpu"] for sample in samples),
        default=0.0
    )

    average_memory = calculate_average(
        [sample["memory"] for sample in samples]
    )

    execution_time = (
        end_time - start_time
    ) * 1000

    memory_increase = (
        peak_memory - baseline_memory
    )

    # ---------------------------------------------------------
    # Verification
    # ---------------------------------------------------------

    encryption_verified = (
        decrypt_data(
            ciphertext,
            aes_key,
            nonce
        ) == test_data
    )

    ecc_verified = (
        recovered_aes_key == aes_key
    )

    full_workflow_verified = (
        recovered_data == test_data
        and reassembled_key["wrapped_key"]
        == protected_key["wrapped_key"]
    )

    # ---------------------------------------------------------
    # Results
    # ---------------------------------------------------------

    print("\n" + "=" * 60)
    print("RESOURCE USAGE RESULTS")
    print("=" * 60)

    print(f"\nBaseline memory:       {baseline_memory:.2f} MB")
    print(f"Average memory:        {average_memory:.2f} MB")
    print(f"Peak memory:           {peak_memory:.2f} MB")
    print(f"Memory increase:       {memory_increase:.2f} MB")

    print(f"\nAverage CPU usage:     {average_cpu:.2f}%")
    print(f"Peak CPU usage:        {peak_cpu:.2f}%")

    print(f"\nWorkflow execution:    {execution_time:.4f} ms")

    print("\nVerification:")

    print(
        "AES encryption/decryption: ",
        "PASS" if encryption_verified else "FAIL"
    )

    print(
        "ECC key protection/recovery:",
        "PASS" if ecc_verified else "FAIL"
    )

    print(
        "Complete workflow:          ",
        "PASS" if full_workflow_verified else "FAIL"
    )

    print("\n" + "=" * 60)
    print("SYSTEM 1 RESOURCE USAGE TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()