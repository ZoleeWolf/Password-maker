"""password_store.py – v2.0
JSON vault for **encrypted** password tokens.
Supports add, list, show (decrypt), update, delete via public functions **and** CLI.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

STORE_PATH = Path.home() / ".password_store.json"


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _load() -> List[Dict[str, str]]:
    if STORE_PATH.exists():
        try:
            return json.loads(STORE_PATH.read_text())  # type: ignore[return-value]
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Corrupted store file: {STORE_PATH}") from exc
    return []


def _save(data: List[Dict[str, str]]) -> None:
    STORE_PATH.write_text(json.dumps(data, indent=2))


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def add_entry(label: str, token: str) -> None:
    store = [e for e in _load() if e["label"] != label]
    store.append({"label": label, "token": token})
    _save(store)


def update_entry(label: str, token: str) -> None:
    store = _load()
    for entry in store:
        if entry["label"] == label:
            entry["token"] = token
            _save(store)
            return
    raise KeyError(f"Label '{label}' not found.")


def delete_entry(label: str) -> None:
    store = _load()
    new_store = [e for e in store if e["label"] != label]
    if len(new_store) == len(store):
        raise KeyError(f"Label '{label}' not found.")
    _save(new_store)


def fetch_entry(label: str) -> str | None:
    for e in _load():
        if e["label"] == label:
            return e["token"]
    return None


def list_labels() -> List[str]:
    return sorted(e["label"] for e in _load())


# ──────────────────────────────────────────────────────────────────────────────
# CLI implementation
# ──────────────────────────────────────────────────────────────────────────────

def _cli_confirm(msg: str) -> bool:
    return input(msg).strip().lower().startswith("y")


def _cmd_add(args):
    add_entry(args.label, args.token)
    print(f"[Saved] → {args.label} ({STORE_PATH})")


def _cmd_list(_):
    for lbl in list_labels():
        print(lbl)


def _cmd_show(args):
    from getpass import getpass
    from password_crypto import decrypt_password

    token = fetch_entry(args.label)
    if token is None:
        print(f"[Error] Label '{args.label}' not found.")
        return
    passphrase = getpass("Passphrase: ")
    try:
        print(decrypt_password(token, passphrase))
    except Exception as exc:  # pylint: disable=broad-except
        print("[Error] Decryption failed:", exc)


def _cmd_update(args):
    try:
        update_entry(args.label, args.token)
        print(f"[Updated] → {args.label}")
    except KeyError as exc:
        print("[Error]", exc)


def _cmd_delete(args):
    if not _cli_confirm(f"Delete '{args.label}'? [y/N]: "):
        print("[Info] Deletion cancelled.")
        return
    try:
        delete_entry(args.label)
        print(f"[Deleted] → {args.label}")
    except KeyError as exc:
        print("[Error]", exc)


def main() -> None:  # noqa: D401 – CLI entry point
    parser = argparse.ArgumentParser(description="Password vault CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # add
    p = sub.add_parser("add", help="Add or overwrite an entry")
    p.add_argument("label")
    p.add_argument("token")
    p.set_defaults(func=_cmd_add)

    # list
    p = sub.add_parser("list", help="List stored labels")
    p.set_defaults(func=_cmd_list)

    # show
    p = sub.add_parser("show", help="Decrypt and show an entry")
    p.add_argument("label")
    p.set_defaults(func=_cmd_show)

    # update
    p = sub.add_parser("update", help="Update an existing entry")
    p.add_argument("label")
    p.add_argument("token")
    p.set_defaults(func=_cmd_update)

    # delete
    p = sub.add_parser("delete", help="Delete an entry")
    p.add_argument("label")
    p.set_defaults(func=_cmd_delete)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
