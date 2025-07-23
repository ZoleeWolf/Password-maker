"""password_store.py – v2.1  (Drive‑sync capable)

• On every **load** we pull the latest vault from your Google Drive file
  `.password_store.json` (ignores errors if offline or first‑run).
• On every **save** we upload/back‑up the file.

Requires:  `drive_sync.py` (see adjacent canvas file) and Google credentials.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from drive_sync import download_file, upload_file

STORE_PATH = Path.home() / ".password_store.json"
REMOTE_NAME = ".password_store.json"  # Google Drive filename

# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _pull_from_drive() -> None:
    try:
        download_file(REMOTE_NAME, STORE_PATH)
    except Exception as exc:  # pragma: no cover – soft‑fail
        # No credentials / offline → continue with local copy.
        pass


def _push_to_drive() -> None:
    try:
        upload_file(REMOTE_NAME, STORE_PATH)
    except Exception:
        pass  # keep working offline; will sync next time


def _load() -> List[Dict[str, str]]:
    _pull_from_drive()
    if STORE_PATH.exists():
        try:
            return json.loads(STORE_PATH.read_text())  # type: ignore[return-value]
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Corrupted store file: {STORE_PATH}") from exc
    return []


def _save(data: List[Dict[str, str]]) -> None:
    STORE_PATH.write_text(json.dumps(data, indent=2))
    _push_to_drive()

# ──────────────────────────────────────────────────────────────────────────────
# Public API – (unchanged signatures)
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
# Optional: CLI remains (list/show/add/update/delete) – unchanged implementations
# ──────────────────────────────────────────────────────────────────────────────

# (Retain previous CLI code here – omitted for brevity…)
