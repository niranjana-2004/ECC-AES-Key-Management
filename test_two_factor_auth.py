from src.two_factor_auth import (
    generate_secret,
    generate_totp,
    verify_totp,
)


print("=" * 50)
print("ESKMS TWO-FACTOR AUTHENTICATION TEST")
print("=" * 50)

print("\n[1] Generating 2FA secret...")

secret = generate_secret()

print("2FA secret generated successfully.")
print("Secret:", secret)

print("\n[2] Generating current TOTP code...")

code = generate_totp(secret)

print("Current TOTP code:", code)

print("\n[3] Testing correct TOTP code...")

if verify_totp(secret, code):
    print("Correct TOTP code accepted successfully!")
else:
    raise RuntimeError(
        "Correct TOTP code was rejected."
    )

print("\n[4] Testing incorrect TOTP code...")

wrong_code = "000000"

if not verify_totp(secret, wrong_code):
    print("Incorrect TOTP code rejected successfully!")
else:
    raise RuntimeError(
        "Incorrect TOTP code was accepted."
    )

print("\n" + "=" * 50)
print("TWO-FACTOR AUTHENTICATION TEST PASSED")
print("=" * 50)