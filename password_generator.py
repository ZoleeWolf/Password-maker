"""password_generator.py – v1.5  (Interactive loop)

* Generate unlimited passwords in one run until you choose to quit.
* Each cycle: generate → (optional) encrypt → (optional) save.
* At the end of each cycle you can decide to repeat or exit.
"""
from __future__ import annotations

import secrets
import string
import sys
import warnings
from typing import List

try:
    from getpass import getpass, GetPassWarning
except ImportError:
    getpass = None  # type: ignore[assignment]

from password_crypto import decrypt_password, encrypt_password
from password_store import add_entry, STORE_PATH

CHAR_POOLS = {
    "letters": string.ascii_letters,
    "digits": string.digits,
    "symbols": "!#$%&()*+",
}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _confirm(prompt: str) -> bool:
    return input(prompt).strip().lower().startswith("y")


def _ask_passphrase(prompt: str = "Passphrase") -> str:
    if getpass is None:
        return input(prompt + " (visible): ")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=GetPassWarning)
            return getpass(prompt + ": ")
    except Exception:
        return input(prompt + " (visible): ")


def generate_password(length: int) -> str:
    pool_count = len(CHAR_POOLS)
    if length < pool_count:
        raise ValueError(f"Length must be ≥{pool_count} (one per pool)")

    chars: List[str] = [secrets.choice(p) for p in CHAR_POOLS.values()]
    all_chars = "".join(CHAR_POOLS.values())
    chars.extend(secrets.choice(all_chars) for _ in range(length - pool_count))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ──────────────────────────────────────────────────────────────────────────────
# Main interactive loop
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:  # noqa: D401
    print("★ Secure Password Generator ★\n")

    while True:
        # ─── length prompt ────────────────────────────────────────────────────
        try:
            length = int(input("Desired length (≥3, 0 to quit): "))
        except ValueError:
            print("[Error] Please enter an integer.")
            continue
        if length == 0:
            print("Good‑bye!")
            return

        # ─── generate ─────────────────────────────────────────────────────────
        try:
            password = generate_password(length)
        except ValueError as exc:
            print("[Error]", exc)
            continue

        print("\nGenerated password:", password)

        # ─── encryption ──────────────────────────────────────────────────────
        token = None
        if _confirm("Encrypt it? [y/N]: "):
            passphrase = _ask_passphrase()
            if not passphrase:
                print("[Info] Empty pass‑phrase – skipped encryption.")
            else:
                token = encrypt_password(password, passphrase)
                print("\nEncrypted token:\n", token)

                if _confirm("Decrypt to verify? [y/N]: "):
                    try:
                        plain = decrypt_password(token, passphrase)
                        print("\nDecrypted password:", plain)
                    except Exception as exc:  # pylint: disable=broad-except
                        print("[Error] Decryption failed:", exc)
                        token = None  # avoid saving corrupt token

        # ─── save ────────────────────────────────────────────────────────────
        if token and _confirm("Save encrypted token to vault? [y/N]: "):
            label = input("Label (e.g., gmail): ").strip()
            if label:
                add_entry(label, token)
                print(f"[Saved] → {label} ({STORE_PATH})")
            else:
                print("[Info] Empty label – not saved.")

        # ─── repeat? ──────────────────────────────────────────────────────────
        if not _confirm("\nGenerate another password? [y/N]: "):
            print("Good‑bye!")
            return
        print()


if __name__ == "__main__":
    main()
