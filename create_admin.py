from getpass import getpass

from src.user_database import initialize_database, create_user, get_user


def main():
    print("===== ESKMS ADMIN ACCOUNT SETUP =====\n")

    initialize_database()

    username = input("Enter admin username: ").strip()

    if not username:
        print("ERROR: Username cannot be empty.")
        return

    if get_user(username):
        print(f"ERROR: Username '{username}' already exists.")
        return

    password = getpass("Enter admin password: ")
    confirm_password = getpass("Confirm admin password: ")

    if password != confirm_password:
        print("ERROR: Passwords do not match.")
        return

    try:
        create_user(
            username=username,
            password=password,
            role="ADMIN"
        )

        print("\nADMIN account created successfully!")
        print(f"Username: {username}")
        print("Role: ADMIN")

    except ValueError as error:
        print(f"\nERROR: {error}")


if __name__ == "__main__":
    main()