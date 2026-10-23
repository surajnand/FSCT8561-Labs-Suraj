

import hashlib
import hmac
import os
import pyotp

# Demo login credentials
USERNAME = "suraj"
DEMO_PASSWORD = "123"

# Generate a random salt for password hashing
SALT = os.urandom(16)

# Hash the password using PBKDF2-HMAC-SHA256
PASSWORD_HASH = hashlib.pbkdf2_hmac(
    "sha256",
    DEMO_PASSWORD.encode("utf-8"),
    SALT,
    200000
)

# Generate TOTP secret
TOTP_SECRET = pyotp.random_base32()


def verify_password(username, password):
    if not isinstance(username, str) or not isinstance(password, str):
        return False

    candidate_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        SALT,
        200000
    )

    return (
        hmac.compare_digest(username, USERNAME)
        and hmac.compare_digest(candidate_hash, PASSWORD_HASH)
    )


def verify_totp(code):
    if not isinstance(code, str):
        return False

    if len(code) != 6 or not code.isdigit():
        return False

    totp = pyotp.TOTP(TOTP_SECRET)

    # Allow one time step before or after current code
    return totp.verify(code, valid_window=1)


def get_current_totp():
    return pyotp.TOTP(TOTP_SECRET).now()


if __name__ == "__main__":
    print("Operation Sentinel - Authentication Test")
    print("Correct password:", verify_password("suraj", "123"))
    print("Incorrect password:", verify_password("suraj", "wrong"))

    code = get_current_totp()
    print("Current TOTP:", code)
    print("Valid TOTP:", verify_totp(code))
    print("Invalid TOTP:", verify_totp("invalid"))
