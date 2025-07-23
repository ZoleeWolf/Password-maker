"""drive_sync.py – Google Drive helper for password vault

Features
~~~~~~~~
• First‑run OAuth2 flow (opens browser, caches token.json).
• `download_file(remote_name, local_path)` → fetches the latest copy into a
  local path (creates if absent).
• `upload_file(remote_name, local_path)` → uploads *or updates* depending on
  whether the file exists.

Google libs required:
    pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib

How to set up credentials (one‑time):
1. https://console.cloud.google.com/ → create project → *APIs & Services* →
   *Enable APIs* → **Google Drive API**.
2. *OAuth consent* → External → Testing.
3. *Credentials* → + Create credentials → **OAuth client ID** → Desktop.
4. Download the JSON as **credentials.json** and put it beside this file.

The first time you run password_store, a browser window asks for access and a
`token.json` cache file is written.
"""
from __future__ import annotations

import io
import os
from pathlib import Path
from typing import Final

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaFileUpload

SCOPES: Final[list[str]] = ["https://www.googleapis.com/auth/drive.file"]
CREDS_PATH = Path(__file__).with_name("credentials.json")
TOKEN_PATH = Path(__file__).with_name("token.json")


def _get_service():
    """Return an authorised Drive API resource object."""
    creds: Credentials | None = None
    if TOKEN_PATH.exists():
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
        TOKEN_PATH.write_text(creds.to_json())
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def _find_file(service, name: str) -> str | None:  # returns fileId or None
    res = (
        service.files()
        .list(q=f"name='{name}' and trashed = false", spaces="drive", fields="files(id, name)")
        .execute()
    )
    files = res.get("files", [])
    return files[0]["id"] if files else None


def download_file(remote_name: str, local_path: str | Path) -> None:
    service = _get_service()
    file_id = _find_file(service, remote_name)
    if not file_id:
        return  # remote copy doesn’t exist yet
    request = service.files().get_media(fileId=file_id)
    fh = io.FileIO(local_path, "wb")
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()


def upload_file(remote_name: str, local_path: str | Path) -> None:
    service = _get_service()
    file_id = _find_file(service, remote_name)
    media = MediaFileUpload(local_path, resumable=False, mimetype="application/json")
    if file_id:
        service.files().update(fileId=file_id, media_body=media).execute()
    else:
        file_metadata = {"name": remote_name}
        service.files().create(body=file_metadata, media_body=media).execute()
