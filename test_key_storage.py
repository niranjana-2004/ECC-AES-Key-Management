
from src.key_storage import get_or_create_key_pair

print("Testing ECC private-key storage...")

private_key, public_key = get_or_create_key_pair()

print("\nPrivate key type:", type(private_key).__name__)
print("Public key type:", type(public_key).__name__)
print("Curve:", private_key.curve.name)

print("\nECC key storage test completed successfully!")
