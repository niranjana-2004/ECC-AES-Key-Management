from src.access_control import (
    Role,
    Permission,
    has_permission,
    get_permissions
)


print("Testing RBAC access control...\n")


roles = [
    Role.ADMIN,
    Role.USER,
    Role.VIEWER
]


for role in roles:
    print(f"Role: {role.value}")

    permissions = get_permissions(role)

    for permission in Permission:
        status = "ALLOWED" if permission in permissions else "DENIED"

        print(f"  {permission.value}: {status}")

    print()


print("Testing individual permissions...\n")

tests = [
    (Role.ADMIN, Permission.DELETE, True),
    (Role.ADMIN, Permission.MANAGE_USERS, True),

    (Role.USER, Permission.UPLOAD, True),
    (Role.USER, Permission.DOWNLOAD, True),
    (Role.USER, Permission.DELETE, False),
    (Role.USER, Permission.MANAGE_USERS, False),

    (Role.VIEWER, Permission.LIST_DOCUMENTS, True),
    (Role.VIEWER, Permission.UPLOAD, False),
    (Role.VIEWER, Permission.DOWNLOAD, False),
    (Role.VIEWER, Permission.DELETE, False),
]


all_passed = True

for role, permission, expected in tests:

    result = has_permission(role, permission)

    status = "PASS" if result == expected else "FAIL"

    print(
        f"{status}: "
        f"{role.value} -> {permission.value} "
        f"(expected={expected}, actual={result})"
    )

    if result != expected:
        all_passed = False


print()

if all_passed:
    print("RBAC ACCESS CONTROL TEST PASSED!")
else:
    print("RBAC ACCESS CONTROL TEST FAILED!")