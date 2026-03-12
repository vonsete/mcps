#!/usr/bin/env python3
"""
MCP server for Google Drive (read-only, Service Account auth).

Setup:
  1. Create a Service Account in Google Cloud Console (APIs & Services → Credentials)
  2. Enable the Google Drive API for your project
  3. Download the JSON key and save it to ~/.gdrive_key
  4. Share any Drive folders/files with the service account email address

Dependencies:
  pip install google-api-python-client google-auth
"""

import sys
import json
import os
import io

from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from google.oauth2 import service_account


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def respond(id, result):
    send({"jsonrpc": "2.0", "id": id, "result": result})

def error(id, code, message):
    send({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})

def text_result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]

def get_service():
    key_file = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    if not key_file:
        key_file = os.path.expanduser("~/.gdrive_key")

    if not os.path.exists(key_file):
        raise RuntimeError(
            "Google Drive credentials not found. "
            "Set GOOGLE_APPLICATION_CREDENTIALS or create ~/.gdrive_key "
            "with your service account JSON."
        )

    creds = service_account.Credentials.from_service_account_file(key_file, scopes=SCOPES)
    return build("drive", "v3", credentials=creds, cache_discovery=False)


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "gdrive_list_files",
        "description": (
            "List files in Google Drive. Optionally filter by folder ID. "
            "Returns name, id, mimeType, size, modifiedTime and webViewLink."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "folder_id": {
                    "type": "string",
                    "description": "Folder ID to list contents of. Omit for root ('My Drive' shared with service account).",
                },
                "page_size": {
                    "type": "integer",
                    "description": "Max files to return (default 50, max 200).",
                },
            },
        },
    },
    {
        "name": "gdrive_search",
        "description": (
            "Search for files in Google Drive by name, content or MIME type. "
            "Supports Google Drive query syntax (e.g. name contains 'report', fullText contains 'budget')."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query. Examples: \"name contains 'invoice'\", \"mimeType='application/pdf'\", \"fullText contains 'quarterly report'\"",
                },
                "page_size": {
                    "type": "integer",
                    "description": "Max results to return (default 25, max 100).",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "gdrive_get_file",
        "description": "Get metadata for a specific file by its ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": "Google Drive file ID.",
                },
            },
            "required": ["file_id"],
        },
    },
    {
        "name": "gdrive_read_file",
        "description": (
            "Read the text content of a file. "
            "Google Docs/Sheets/Slides are exported as plain text. "
            "Other text files (txt, csv, json, md, py, etc.) are read directly. "
            "Binary files (images, zip, etc.) are not supported."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": "Google Drive file ID.",
                },
                "max_chars": {
                    "type": "integer",
                    "description": "Maximum characters to return (default 20000).",
                },
            },
            "required": ["file_id"],
        },
    },
    {
        "name": "gdrive_list_folders",
        "description": "List all folders in Google Drive visible to the service account.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "parent_id": {
                    "type": "string",
                    "description": "Parent folder ID to list subfolders of. Omit for top-level folders.",
                },
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

GOOGLE_MIME_EXPORT = {
    "application/vnd.google-apps.document":     "text/plain",
    "application/vnd.google-apps.spreadsheet":  "text/csv",
    "application/vnd.google-apps.presentation": "text/plain",
}

TEXT_MIME_PREFIXES = ("text/", "application/json", "application/xml",
                      "application/javascript", "application/x-yaml")

FILE_FIELDS = "id,name,mimeType,size,modifiedTime,webViewLink,parents"


def _format_file(f):
    return {
        "id": f.get("id"),
        "name": f.get("name"),
        "mimeType": f.get("mimeType"),
        "size": int(f["size"]) if f.get("size") else None,
        "modifiedTime": f.get("modifiedTime"),
        "webViewLink": f.get("webViewLink"),
        "parents": f.get("parents", []),
    }


def handle_list_files(args):
    svc = get_service()
    folder_id = args.get("folder_id")
    page_size = min(int(args.get("page_size", 50)), 200)

    q = "trashed = false"
    if folder_id:
        q += f" and '{folder_id}' in parents"

    result = svc.files().list(
        q=q,
        pageSize=page_size,
        fields=f"files({FILE_FIELDS})",
        orderBy="modifiedTime desc",
    ).execute()

    return text_result([_format_file(f) for f in result.get("files", [])])


def handle_search(args):
    svc = get_service()
    query = args["query"]
    page_size = min(int(args.get("page_size", 25)), 100)

    q = f"trashed = false and ({query})"
    result = svc.files().list(
        q=q,
        pageSize=page_size,
        fields=f"files({FILE_FIELDS})",
        orderBy="modifiedTime desc",
    ).execute()

    return text_result([_format_file(f) for f in result.get("files", [])])


def handle_get_file(args):
    svc = get_service()
    f = svc.files().get(fileId=args["file_id"], fields=FILE_FIELDS).execute()
    return text_result(_format_file(f))


def handle_read_file(args):
    svc = get_service()
    file_id = args["file_id"]
    max_chars = int(args.get("max_chars", 20000))

    meta = svc.files().get(fileId=file_id, fields="id,name,mimeType").execute()
    mime = meta.get("mimeType", "")

    buf = io.BytesIO()

    if mime in GOOGLE_MIME_EXPORT:
        # Google Workspace file — export as text
        export_mime = GOOGLE_MIME_EXPORT[mime]
        req = svc.files().export_media(fileId=file_id, mimeType=export_mime)
    elif any(mime.startswith(p) for p in TEXT_MIME_PREFIXES):
        # Plain text file — download directly
        req = svc.files().get_media(fileId=file_id)
    else:
        return text_result({
            "error": f"Cannot read binary file (mimeType: {mime}). "
                     "Only text files and Google Docs/Sheets/Slides are supported."
        })

    downloader = MediaIoBaseDownload(buf, req)
    done = False
    while not done:
        _, done = downloader.next_chunk()

    content = buf.getvalue().decode("utf-8", errors="replace")
    truncated = len(content) > max_chars
    return text_result({
        "file_id": file_id,
        "name": meta.get("name"),
        "mimeType": mime,
        "truncated": truncated,
        "content": content[:max_chars],
    })


def handle_list_folders(args):
    svc = get_service()
    parent_id = args.get("parent_id")

    q = "mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    if parent_id:
        q += f" and '{parent_id}' in parents"

    result = svc.files().list(
        q=q,
        pageSize=100,
        fields="files(id,name,parents,modifiedTime)",
        orderBy="name",
    ).execute()

    return text_result(result.get("files", []))


HANDLERS = {
    "gdrive_list_files":   handle_list_files,
    "gdrive_search":       handle_search,
    "gdrive_get_file":     handle_get_file,
    "gdrive_read_file":    handle_read_file,
    "gdrive_list_folders": handle_list_folders,
}


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        msg_id = msg.get("id")
        method = msg.get("method")

        if method == "initialize":
            respond(msg_id, {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "gdrive", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            })

        elif method == "notifications/initialized":
            pass

        elif method == "tools/list":
            respond(msg_id, {"tools": TOOLS})

        elif method == "tools/call":
            tool_name = msg.get("params", {}).get("name")
            tool_args = msg.get("params", {}).get("arguments", {})
            handler = HANDLERS.get(tool_name)
            if not handler:
                error(msg_id, -32601, f"Unknown tool: {tool_name}")
                continue
            try:
                result = handler(tool_args)
                respond(msg_id, result)
            except Exception as e:
                respond(msg_id, {
                    "content": [{"type": "text", "text": f"Error: {e}"}],
                    "isError": True,
                })
        else:
            error(msg_id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    main()
