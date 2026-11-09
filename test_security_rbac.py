import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.access_control import (
    Role,
    Permission,
    has_permission,
)


def test_role(role, expected_permissions):
    print(f"\nTesting role: {role.value}")

    all_passed = True

    for permission in Permission:

        expected = permission in expected_permissions
        actual = has_permission(role, permission)

        status = "PASS" if actual == expected else "FAIL"

        print(
            f"{permission.value:<20} "
            f"Expected={expected:<5} "
            f"Actual={actual:<5} "
            f"{status}"
        )

        if actual != expected:
            all_passed = False

    return all_passed


def main():

    print("=" * 60)
    print("SYSTEM 1 RBAC SECURITY TEST")
    print("=" * 60)

    admin_permissions = {
        Permission.UPLOAD,
        Permission.DOWNLOAD,
        Permission.DELETE,
        Permission.LIST_DOCUMENTS,
        Permission.MANAGE_USERS,
    }

    user_permissions = {
        Permission.UPLOAD,
        Permission.DOWNLOAD,
        Permission.LIST_DOCUMENTS,
    }

    viewer_permissions = {
        Permission.LIST_DOCUMENTS,
    }

    results = []

    results.append(
        test_role(Role.ADMIN, admin_permissions)
    )

    results.append(
        test_role(Role.USER, user_permissions)
    )

    results.append(
        test_role(Role.VIEWER, viewer_permissions)
    )

    print("\n" + "=" * 60)

    if all(results):
        print("RBAC SECURITY TEST PASSED")
    else:
        print("RBAC SECURITY TEST FAILED")

    print("=" * 60)


if __name__ == "__main__":
    main()