"""password_lookup.py – v1.1

• Works both as a CLI **and** as an interactive prompt when launched without
  command‑line arguments (double‑click / Run button).
• Interactive menu:  (L)ist  (S)how <label>  (Q)uit.
"""
from __future__ import annotations

import argparse
import sys
from getpass import getpass

from password_store import fetch_entry, list_labels, STORE_PATH
from password_crypto import decrypt_password


# ──────────────────────────────────────────────────────────────────────────────
# Core helpers
# ──────────────────────────────────────────────────────────────────────────────

def list_entries() -> None:
    labels = list_labels()
    if not labels:
        print("[Info] Vault is empty (", STORE_PATH, ")")
        return
    for lbl in labels:
        print(lbl)


def show_entry(label: str) -> None:
    token = fetch_entry(label)
    if token is None:
        print(f"[Error] Label '{label}' not found.")
        return
    passphrase = getpass("Passphrase: ")
    try:
        print("\nPassword:", decrypt_password(token, passphrase))
    except Exception as exc:  # pylint: disable=broad-except
        print("[Error] Decryption failed:", exc)


# ──────────────────────────────────────────────────────────────────────────────
# Interactive fallback – shows only when no CLI args given
# ──────────────────────────────────────────────────────────────────────────────

def _interactive() -> None:
    print("★ Password Vault Lookup ★\n")
    while True:
        cmd = input("(L)ist  (S)how <label>  (Q)uit → ").strip()
        if not cmd:
            continue
        if cmd.lower().startswith("l"):
            list_entries()
        elif cmd.lower().startswith("s"):
            label = cmd.split(maxsplit=1)[1:]  # grab second word if present
            if not label:
                label = [input("Label: ").strip()]
            show_entry(label[0])
        elif cmd.lower().startswith("q"):
            sys.exit()
        else:
            print("Unknown option. Use L, S <label>, or Q.")
        print()


# ──────────────────────────────────────────────────────────────────────────────
# CLI – keeps previous behaviour
# ──────────────────────────────────────────────────────────────────────────────

def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="Password vault lookup helper",
        epilog="If no sub‑command is given the script starts an interactive menu.",
    )
    sub = parser.add_subparsers(dest="cmd")  # no required=True so it can be empty

    sub.add_parser("list", help="List stored labels")
    p_show = sub.add_parser("show", help="Decrypt and display a password")
    p_show.add_argument("label", help="Entry label")

    args = parser.parse_args()

    if args.cmd == "list":
        list_entries()
    elif args.cmd == "show":
        show_entry(args.label)
    else:
        _interactive()


if __name__ == "__main__":
    _cli()
