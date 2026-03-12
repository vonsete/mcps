#!/usr/bin/env python3
"""
Descarga PDFs de una carpeta de Google Drive y los sube a AnythingLLM,
luego los indexa en un workspace.

Uso:
  python3 sync_gdrive_to_anythingllm.py <folder_id> <workspace_slug>

Ejemplo:
  python3 sync_gdrive_to_anythingllm.py 1j_wkBgugYBBaYBX8qLD5MmNkHUJMImaP libros-seguridad
"""

import sys
import json
import os
import io
import requests
import tempfile

from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from google.oauth2 import service_account

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]


def get_drive_service():
    key_file = os.path.expanduser("~/.gdrive_key")
    creds = service_account.Credentials.from_service_account_file(key_file, scopes=SCOPES)
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def get_anythingllm_config():
    key_file = os.path.expanduser("~/.anythingllm_key")
    with open(key_file) as f:
        cfg = json.load(f)
    return cfg["api_key"], cfg.get("url", "http://localhost:3001")


def list_pdfs(service, folder_id):
    q = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false"
    result = service.files().list(
        q=q, pageSize=100, fields="files(id,name,size)"
    ).execute()
    return result.get("files", [])


def download_pdf(service, file_id):
    buf = io.BytesIO()
    req = service.files().get_media(fileId=file_id)
    downloader = MediaIoBaseDownload(buf, req)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    buf.seek(0)
    return buf


def upload_to_anythingllm(api_key, base_url, filename, file_buf):
    resp = requests.post(
        f"{base_url}/api/v1/document/upload",
        headers={"Authorization": f"Bearer {api_key}"},
        files={"file": (filename, file_buf, "application/pdf")},
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    # Devuelve la ruta del documento subido
    docs = data.get("documents", [])
    if docs:
        return docs[0].get("location")
    return None


def embed_in_workspace(api_key, base_url, workspace_slug, doc_paths):
    resp = requests.post(
        f"{base_url}/api/v1/workspace/{workspace_slug}/update-embeddings",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={"adds": doc_paths, "deletes": []},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 sync_gdrive_to_anythingllm.py <folder_id> <workspace_slug>")
        sys.exit(1)

    folder_id = sys.argv[1]
    workspace_slug = sys.argv[2]

    api_key, base_url = get_anythingllm_config()
    service = get_drive_service()

    print(f"Listando PDFs en carpeta {folder_id}...")
    pdfs = list_pdfs(service, folder_id)
    print(f"Encontrados {len(pdfs)} PDFs\n")

    uploaded_paths = []

    for i, pdf in enumerate(pdfs, 1):
        name = pdf["name"]
        size_mb = int(pdf.get("size", 0)) / 1024 / 1024
        print(f"[{i}/{len(pdfs)}] {name} ({size_mb:.1f} MB)")

        try:
            print(f"  Descargando...")
            buf = download_pdf(service, pdf["id"])

            print(f"  Subiendo a AnythingLLM...")
            doc_path = upload_to_anythingllm(api_key, base_url, name, buf)

            if doc_path:
                uploaded_paths.append(doc_path)
                print(f"  OK -> {doc_path}")
            else:
                print(f"  WARN: subido pero sin ruta devuelta")

        except Exception as e:
            print(f"  ERROR: {e}")

    if uploaded_paths:
        print(f"\nIndexando {len(uploaded_paths)} documentos en workspace '{workspace_slug}'...")
        try:
            embed_in_workspace(api_key, base_url, workspace_slug, uploaded_paths)
            print("Indexacion completada.")
        except Exception as e:
            print(f"ERROR al indexar: {e}")
    else:
        print("\nNo hay documentos para indexar.")

    print(f"\nResumen: {len(uploaded_paths)}/{len(pdfs)} PDFs procesados correctamente.")


if __name__ == "__main__":
    main()
