"""password_crypto.py

Encrypt and decrypt passwords (or any small string) using a passphrase‑derived key
with PBKDF2‑HMAC‑SHA256 + Fernet (AES‑128‑CBC + HMAC‑SHA256).

This module can be:
1. Imported by other scripts (e.g., password_generator.py)
2. Run directly to encrypt/decrypt arbitrary strings.

Dependencies
------------
$ pip install cryptography
"""
from __future__ import annotations

import base64
import os
from hashlib import pbkdf2_hmac
from getpass import getpass

from cryptography.fernet import Fernet

PBKDF2_ITERS = 200_000  # Number of PBKDF2 iterations
KEY_LEN = 32            # 32 bytes → 256‑bit key (Fernet expects this)
SALT_LEN = 16           # 128‑bit random salt

# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a symmetric key from *passphrase* and *salt* using PBKDF2‑HMAC‑SHA256."""
    return pbkdf2_hmac('sha256', passphrase.encode(), salt, PBKDF2_ITERS, KEY_LEN)


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def encrypt_password(password: str, passphrase: str) -> str:
    """Encrypt *password* with a key derived from *passphrase*.

    Returns:
        str: URL‑safe base64 string containing **salt‖ciphertext**.
    """
    salt = os.urandom(SALT_LEN)
    key = _derive_key(passphrase, salt)
    token = Fernet(base64.urlsafe_b64encode(key)).encrypt(password.encode())
    return base64.urlsafe_b64encode(salt + token).decode()


def decrypt_password(token_b64: str, passphrase: str) -> str:
    """Decrypt *token_b64* (produced by :func:`encrypt_password`)."""
    data = base64.urlsafe_b64decode(token_b64.encode())
    salt, token = data[:SALT_LEN], data[SALT_LEN:]
    key = _derive_key(passphrase, salt)
    return Fernet(base64.urlsafe_b64encode(key)).decrypt(token).decode()


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:  # noqa: D401 – imperative mood required by CLI
    mode = input('Encrypt (E) or Decrypt (D)? ').strip().lower()
    if mode.startswith('e'):
        plaintext = getpass('Password (or text) to encrypt: ')
        passphrase = getpass('Passphrase: ')
        encrypted = encrypt_password(plaintext, passphrase)
        print('\nEncrypted token:\n', encrypted)
    elif mode.startswith('d'):
        token_b64 = input('Encrypted token: ').strip()
        passphrase = getpass('Passphrase: ')
        try:
            plaintext = decrypt_password(token_b64, passphrase)
            print('\nDecrypted text:', plaintext)
        except Exception as exc:  # pylint: disable=broad-except
            print('[Error] Decryption failed:', exc)
    else:
        print('Aborted – please choose "E" or "D".')


if __name__ == '__main__':
    main()
