from src.auth_service import login


print("Testing ESKMS authentication...\n")

user = login()

if user:
    print("\nAuthentication test PASSED!")
else:
    print("\nAuthentication test FAILED!")