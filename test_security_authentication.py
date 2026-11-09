import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.user_database import authenticate_user
from src.two_factor_auth import verify_totp


def main():

    print("=" * 60)
    print("SYSTEM 1 AUTHENTICATION SECURITY TEST")
    print("=" * 60)

    username = input("\nEnter test username: ").strip()

    # ---------------------------------------------------------
    # 1. Wrong password
    # ---------------------------------------------------------

    print("\n[1] Testing incorrect password rejection...")

    wrong_password = input(
        "Enter an intentionally incorrect password: "
    )

    user = authenticate_user(
        username,
        wrong_password
    )

    if user is None:
        print("PASS: Incorrect password was rejected.")
    else:
        print("FAIL: Incorrect password was accepted.")

    # ---------------------------------------------------------
    # 2. Correct password
    # ---------------------------------------------------------

    print("\n[2] Testing correct password authentication...")

    correct_password = input(
        "Enter the correct password: "
    )

    user = authenticate_user(
        username,
        correct_password
    )

    if user is None:
        print("FAIL: Correct password was rejected.")
        return

    print("PASS: Correct password authentication succeeded.")

    # ---------------------------------------------------------
    # 3. 2FA verification
    # ---------------------------------------------------------

    if user["two_factor_enabled"]:

        print("\n[3] Testing incorrect TOTP rejection...")

        wrong_totp = input(
            "Enter an intentionally incorrect 6-digit TOTP: "
        ).strip()

        if not verify_totp(
            user["two_factor_secret"],
            wrong_totp
        ):
            print("PASS: Incorrect TOTP was rejected.")
        else:
            print("FAIL: Incorrect TOTP was accepted.")

        print("\n[4] Testing correct TOTP...")

        correct_totp = input(
            "Enter the current 6-digit TOTP: "
        ).strip()

        if verify_totp(
            user["two_factor_secret"],
            correct_totp
        ):
            print("PASS: Correct TOTP was accepted.")
        else:
            print("FAIL: Correct TOTP was rejected.")

    else:
        print("\n2FA is not enabled for this account.")

    print("\n" + "=" * 60)
    print("AUTHENTICATION SECURITY TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()