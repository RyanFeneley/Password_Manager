"""
2FA.py
Author: Ryan Feneley
Date: September 2024
"""

import pyotp
import random
import string

class TwoFactorAuth:
    """Class to manage two-factor authentication."""

    def __init__(self, secret=None):
        """Initialize with a secret for the user."""
        self.secret = secret or self.generate_secret()

    def generate_secret(self):
        """Generates a random base32 secret for TOTP."""
        return pyotp.random_base32()

    def generate_totp(self):
        """Generates a TOTP token based on the secret."""
        totp = pyotp.TOTP(self.secret)
        return totp.now()

    def verify_totp(self, token):
        """Verifies the provided TOTP token against the secret."""
        totp = pyotp.TOTP(self.secret)
        return totp.verify(token)

    def get_qr_code_url(self, username):
        """Returns the QR code URL for setting up 2FA in an authenticator app."""
        totp = pyotp.TOTP(self.secret)
        return totp.provisioning_uri(name=username, issuer="PasswordManagerApp")

# Example usage:
if __name__ == "__main__":
    username = "testuser"
    two_fa = TwoFactorAuth()

    print("Secret:", two_fa.secret)
    print("TOTP:", two_fa.generate_totp())
    print("QR Code URL:", two_fa.get_qr_code_url(username))
