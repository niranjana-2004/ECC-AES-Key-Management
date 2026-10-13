
import csv
import statistics
import sys
import time
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
from src.key_splitting import (
    serialize_protected_key,
    split_protected_key,
)
from src.key_rotation import rotate_ecc_key_pair


RESULTS_DIR = PROJECT_ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

REPEATS = 10


def measure_time(operation, repeats=REPEATS):
    """Return the average and median execution time in milliseconds."""
    durations = []

    for _ in range(repeats):
        start = time.perf_counter()
        operation()
        elapsed = time.perf_counter() - start
        durations.append(elapsed * 1000)

    return statistics.mean(durations), statistics.median(durations)


def write_csv(filename, rows, headers):
    output_path = RESULTS_DIR / filename

    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved: {output_path}")


def benchmark_operations():
    """Measure the time taken by individual cryptographic operations."""
    data = b"R" * 1024  # 1 KiB test payload
    aes_key = generate_aes_key()
    ciphertext, nonce = encrypt_data(data, aes_key)

    private_key, public_key = generate_ecc_key_pair()
    package = protect_aes_key(aes_key, public_key)

    operations = {
        "AES encryption (1 KiB)": lambda: encrypt_data(data, aes_key),
        "AES decryption (1 KiB)": lambda: decrypt_data(
            ciphertext, aes_key, nonce
        ),
        "ECC key-pair generation": generate_ecc_key_pair,
        "AES key protection": lambda: protect_aes_key(aes_key, public_key),
        "AES key recovery": lambda: recover_aes_key(package, private_key),
        "ECC key-pair rotation": lambda: rotate_ecc_key_pair(
            package, private_key
        ),
    }

    rows = []

    print("\n--- Operation timing benchmark ---")

    for name, operation in operations.items():
        average_ms, median_ms = measure_time(operation)

        rows.append({
            "operation": name,
            "repeats": REPEATS,
            "average_ms": round(average_ms, 6),
            "median_ms": round(median_ms, 6),
        })

        print(
            f"{name}: average={average_ms:.4f} ms, "
            f"median={median_ms:.4f} ms"
        )

    write_csv(
        "operation_timings.csv",
        rows,
        ["operation", "repeats", "average_ms", "median_ms"],
    )


def benchmark_communication():
    """Measure the size of the protected-key package and its two parts."""
    aes_key = generate_aes_key()
    _, public_key = generate_ecc_key_pair()
    package = protect_aes_key(aes_key, public_key)

    serialized = serialize_protected_key(package)
    metadata, part1, part2 = split_protected_key(package)

    rows = [
    {
        "item": "Serialized protected-key package",
        "size_bytes": len(serialized),
    },
    {
        "item": "Wrapped AES-key payload",
        "size_bytes": len(package["wrapped_key"]),
    },
    {"item": "Split part 1", "size_bytes": len(part1)},
    {"item": "Split part 2", "size_bytes": len(part2)},
    {
        "item": "Total split-part bytes",
        "size_bytes": len(part1) + len(part2),
    },
]

    print("\n--- Communication-size benchmark ---")

    for row in rows:
        print(f"{row['item']}: {row['size_bytes']} bytes")

    write_csv(
        "communication_overhead.csv",
        rows,
        ["item", "size_bytes"],
    )


def benchmark_scalability():
    """Measure the time required to rotate increasing numbers of keys."""
    key_counts = [10, 50, 100, 500, 1000]
    rows = []

    print("\n--- Key-rotation scalability benchmark ---")

    for count in key_counts:
        # Prepare independent key packages before timing rotation.
        items = []

        for _ in range(count):
            aes_key = generate_aes_key()
            old_private, old_public = generate_ecc_key_pair()
            package = protect_aes_key(aes_key, old_public)
            items.append((package, old_private))

        start = time.perf_counter()

        for package, old_private in items:
            rotate_ecc_key_pair(package, old_private)

        elapsed_ms = (time.perf_counter() - start) * 1000

        rows.append({
            "key_count": count,
            "rotation_time_ms": round(elapsed_ms, 6),
            "average_ms_per_key": round(elapsed_ms / count, 6),
        })

        print(
            f"{count} keys: total={elapsed_ms:.2f} ms, "
            f"average={elapsed_ms / count:.4f} ms/key"
        )

    write_csv(
        "scalability_results.csv",
        rows,
        ["key_count", "rotation_time_ms", "average_ms_per_key"],
    )


def main():
    print("ECC-AES baseline performance experiments")
    print("Python perf_counter timing; results are machine-dependent.")

    benchmark_operations()
    benchmark_communication()
    benchmark_scalability()

    print("\nAll benchmark experiments completed.")


if __name__ == "__main__":
    main()
