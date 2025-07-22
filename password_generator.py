
"""password_generator.py – v1.3

Fixed: *getpass* blocks/hides prompt in some IDEs (e.g. PyCharm Run tool).
If *getpass* fails we now fall back to visible `input()`.

Tip – outside an IDE, you still get hidden input.

Dependencies:  `pip install cryptography`
"""
from __future__ import annotations

import secrets
import string
import sys
import warnings
from typing import List

try:
    from getpass import GetPassWarning, getpass
except ImportError:  # WebAssembly or stripped Python build
    getpass = None  # type: ignore[assignment]

from password_crypto import decrypt_password, encrypt_password

CHAR_POOLS = {
    "letters": string.ascii_letters,
    "digits": string.digits,
    "symbols": "!#$%&()*+",
}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _confirm(prompt: str) -> bool:
    """Return *True* if the user's response begins with "y" or "Y"."""
    return input(prompt).strip().lower().startswith("y")


def _ask_passphrase(prompt: str = "Passphrase: ") -> str:
    """Return a passphrase, falling back to *input()* if getpass is unsupported."""
    if getpass is None:  # getpass could not be imported
        return input(prompt + "(visible) ")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=GetPassWarning)
            return getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        # User aborted with Ctrl‑D/Ctrl‑C
        sys.exit("\n[Aborted]")
    except Exception:  # pragma: no cover – catch‑all for rare console issues
        # getpass failed (common in some IDE consoles). Fallback gracefully.
        return input(prompt + "(visible) ")


def generate_password(length: int) -> str:
    """Generate a random password containing at least one char from every pool."""
    pool_count = len(CHAR_POOLS)
    if length < pool_count:
        raise ValueError(
            f"Length must be at least {pool_count} (one for each pool: {', '.join(CHAR_POOLS)})"
        )

    password_chars: List[str] = [secrets.choice(pool) for pool in CHAR_POOLS.values()]
    all_chars = "".join(CHAR_POOLS.values())
    password_chars.extend(secrets.choice(all_chars) for _ in range(length - pool_count))
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:  # noqa: D401 – imperative mood required by CLI
    print("Welcome to the Password Generator!\n")
    try:
        length = int(input("Desired length (≥3): "))
        plain_pw = generate_password(length)
    except ValueError as exc:
        print(f"[Error] {exc}")
        return

    print("\nGenerated password:", plain_pw)

    # Optional encryption
    if _confirm("\nEncrypt it now? [y/N]: "):
        passphrase = _ask_passphrase("Passphrase (hidden if supported): ")
        if not passphrase:
            print("[Info] Encryption skipped – passphrase was empty.")
            return

        encrypted = encrypt_password(plain_pw, passphrase)
        print("\nEncrypted password (store this string):\n", encrypted)

        if _confirm("\nDecrypt to verify? [y/N]: "):
            try:
                decrypted = decrypt_password(encrypted, passphrase)
                print("\nDecrypted password:", decrypted)
            except Exception as exc:  # pylint: disable=broad-except
                print("[Error] Decryption failed.", exc)
    else:
        print("[Info] Encryption step skipped.")


if __name__ == "__main__":
    main()