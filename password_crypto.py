"""password_crypto.py – v1.0
Encrypt / decrypt strings using a pass‑phrase.
Algorithm: PBKDF2‑HMAC‑SHA256 → 256‑bit key → Fernet (AES‑128‑CBC + HMAC‑SHA256).
"""
from __future__ import annotations

import base64
import os
from hashlib import pbkdf2_hmac
from typing import Final

from cryptography.fernet import Fernet

PBKDF2_ITERS: Final[int] = 200_000
KEY_LEN: Final[int] = 32  # 256‑bit key for Fernet
SALT_LEN: Final[int] = 16  # 128‑bit random salt


# ──────────────────────────────────────────────────────────────────────────────
# Internals
# ──────────────────────────────────────────────────────────────────────────────

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return pbkdf2_hmac("sha256", passphrase.encode(), salt, PBKDF2_ITERS, KEY_LEN)


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def encrypt_password(password: str, passphrase: str) -> str:
    """Return a URL‑safe base64 string containing **salt ‖ ciphertext**."""
    salt = os.urandom(SALT_LEN)
    key = _derive_key(passphrase, salt)
    token = Fernet(base64.urlsafe_b64encode(key)).encrypt(password.encode())
    return base64.urlsafe_b64encode(salt + token).decode()


def decrypt_password(token_b64: str, passphrase: str) -> str:
    data = base64.urlsafe_b64decode(token_b64.encode())
    salt, token = data[:SALT_LEN], data[SALT_LEN:]
    key = _derive_key(passphrase, salt)
    return Fernet(base64.urlsafe_b64encode(key)).decrypt(token).decode()


# ──────────────────────────────────────────────────────────────────────────────
# CLI (optional)
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:  # noqa: D401
    import argparse
    from getpass import getpass

    p = argparse.ArgumentParser(description="Encrypt or decrypt a string")
    p.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation")
    p.add_argument("text", nargs="?", help="Plaintext or token; prompts if omitted")
    args = p.parse_args()

    if args.text is None:
        args.text = input("Text: ")

    passphrase = getpass("Passphrase: ")

    if args.mode == "encrypt":
        print(encrypt_password(args.text, passphrase))
    else:
        try:
            print(decrypt_password(args.text, passphrase))
        except Exception as exc:  # pylint: disable=broad-except
            print("[Error] Decryption failed:", exc)


if __name__ == "__main__":
    main()