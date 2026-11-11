"""Print an argon2 hash for ADMIN_PASSWORD_HASH.  Usage: python -m app.hashpw"""
import getpass
import sys

from argon2 import PasswordHasher

if __name__ == "__main__":
    pw = sys.argv[1] if len(sys.argv) > 1 else getpass.getpass("Admin password: ")
    if not sys.argv[1:] and pw != getpass.getpass("Repeat: "):
        sys.exit("Passwords don't match.")
    print(PasswordHasher().hash(pw))
