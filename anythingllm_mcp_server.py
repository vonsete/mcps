#!/usr/bin/env python3
"""
MCP server for AnythingLLM.
API key and base URL loaded from ANYTHINGLLM_API_KEY / ANYTHINGLLM_URL env vars
or ~/.anythingllm_key file (JSON: {"api_key": "...", "url": "http://localhost:3001"}).
"""

import sys
import json
import os
import requests


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
# Auth / config
# ---------------------------------------------------------------------------

def get_config():
    api_key = os.environ.get("ANYTHINGLLM_API_KEY", "").strip()
    base_url = os.environ.get("ANYTHINGLLM_URL", "").strip()

    if not api_key:
        key_file = os.path.expanduser("~/.anythingllm_key")
        if os.path.exists(key_file):
            with open(key_file) as f:
                cfg = json.load(f)
            api_key = cfg.get("api_key", "")
            base_url = base_url or cfg.get("url", "")

    if not api_key:
        raise RuntimeError(
            "AnythingLLM API key not found. "
            "Set ANYTHINGLLM_API_KEY or create ~/.anythingllm_key"
        )

    base_url = (base_url or "http://localhost:3001").rstrip("/")
    return api_key, base_url


def api_get(path, params=None):
    api_key, base_url = get_config()
    resp = requests.get(
        f"{base_url}/api/v1/{path.lstrip('/')}",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        params=params,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def api_post(path, body=None):
    api_key, base_url = get_config()
    resp = requests.post(
        f"{base_url}/api/v1/{path.lstrip('/')}",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        json=body or {},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def api_delete(path):
    api_key, base_url = get_config()
    resp = requests.delete(
        f"{base_url}/api/v1/{path.lstrip('/')}",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json() if resp.content else {"ok": True}


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "anythingllm_list_workspaces",
        "description": "List all AnythingLLM workspaces with their slugs and settings.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "anythingllm_chat",
        "description": (
            "Send a message to an AnythingLLM workspace and get a RAG-powered response. "
            "The workspace will retrieve relevant documents and answer using them."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_slug": {
                    "type": "string",
                    "description": "Workspace slug (from anythingllm_list_workspaces)",
                },
                "message": {
                    "type": "string",
                    "description": "The question or message to send",
                },
                "mode": {
                    "type": "string",
                    "description": "Chat mode: 'chat' (uses history) or 'query' (no history, pure RAG). Default: query",
                    "enum": ["chat", "query"],
                },
            },
            "required": ["workspace_slug", "message"],
        },
    },
    {
        "name": "anythingllm_vector_search",
        "description": (
            "Perform a semantic vector search in an AnythingLLM workspace. "
            "Returns matching document chunks without generating an LLM response."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_slug": {
                    "type": "string",
                    "description": "Workspace slug",
                },
                "query": {
                    "type": "string",
                    "description": "Text to search for semantically",
                },
            },
            "required": ["workspace_slug", "query"],
        },
    },
    {
        "name": "anythingllm_list_documents",
        "description": "List all documents stored in AnythingLLM (across all folders).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "anythingllm_workspace_documents",
        "description": "List documents embedded in a specific workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_slug": {
                    "type": "string",
                    "description": "Workspace slug",
                },
            },
            "required": ["workspace_slug"],
        },
    },
    {
        "name": "anythingllm_workspace_history",
        "description": "Retrieve the chat history for a workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_slug": {
                    "type": "string",
                    "description": "Workspace slug",
                },
            },
            "required": ["workspace_slug"],
        },
    },
    {
        "name": "anythingllm_upload_text",
        "description": "Create a new document in AnythingLLM from a raw text string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Text content to store as a document",
                },
                "title": {
                    "type": "string",
                    "description": "Document title / filename",
                },
                "metadata": {
                    "type": "object",
                    "description": "Optional key-value metadata to attach",
                },
            },
            "required": ["content", "title"],
        },
    },
    {
        "name": "anythingllm_upload_url",
        "description": "Ingest a URL into AnythingLLM (scrapes and embeds the page content).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to scrape and embed",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "anythingllm_add_document_to_workspace",
        "description": "Embed an already-uploaded document into a workspace so it can be queried.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_slug": {
                    "type": "string",
                    "description": "Workspace slug",
                },
                "doc_path": {
                    "type": "string",
                    "description": "Document path as returned by anythingllm_list_documents (e.g. 'custom-documents/my-file.json')",
                },
            },
            "required": ["workspace_slug", "doc_path"],
        },
    },
    {
        "name": "anythingllm_system_info",
        "description": "Get AnythingLLM system settings and status (LLM provider, vector DB, etc.).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def handle_list_workspaces(args):
    data = api_get("workspaces")
    workspaces = data.get("workspaces", data)
    summary = [
        {
            "name": w.get("name"),
            "slug": w.get("slug"),
            "documents": len(w.get("documents", [])),
            "chatMode": w.get("chatMode"),
            "openAiModel": w.get("openAiModel"),
        }
        for w in workspaces
    ]
    return text_result(summary)


def handle_chat(args):
    slug = args["workspace_slug"]
    message = args["message"]
    mode = args.get("mode", "query")

    data = api_post(f"workspace/{slug}/chat", {"message": message, "mode": mode})

    result = {
        "response": data.get("textResponse"),
        "sources": [
            {
                "title": s.get("title"),
                "chunk": s.get("text", "")[:500],
                "score": s.get("score"),
            }
            for s in data.get("sources", [])
        ],
        "close": data.get("close"),
    }
    return text_result(result)


def handle_vector_search(args):
    slug = args["workspace_slug"]
    query = args["query"]
    data = api_post(f"workspace/{slug}/vector-search", {"query": query})
    return text_result(data)


def handle_list_documents(args):
    data = api_get("documents")
    # Flatten folder structure for readability
    folders = data.get("localFiles", {}).get("items", [])
    result = []
    for folder in folders:
        for doc in folder.get("items", []):
            result.append({
                "name": doc.get("name"),
                "path": f"{folder.get('name')}/{doc.get('name')}",
                "type": doc.get("type"),
                "cached": doc.get("cached"),
            })
    return text_result(result)


def handle_workspace_documents(args):
    slug = args["workspace_slug"]
    data = api_get(f"workspace/{slug}")
    workspace = data.get("workspace", {})
    docs = workspace.get("documents", [])
    summary = [
        {
            "filename": d.get("filename"),
            "docpath": d.get("docpath"),
            "pinned": d.get("pinned"),
        }
        for d in docs
    ]
    return text_result(summary)


def handle_workspace_history(args):
    slug = args["workspace_slug"]
    data = api_get(f"workspace/{slug}/chats")
    return text_result(data)


def handle_upload_text(args):
    body = {
        "textContent": args["content"],
        "metadata": {"title": args["title"]},
    }
    if "metadata" in args:
        body["metadata"].update(args["metadata"])
    data = api_post("document/raw-text", body)
    return text_result(data)


def handle_upload_url(args):
    data = api_post("document/upload-link", {"link": args["url"]})
    return text_result(data)


def handle_add_document_to_workspace(args):
    slug = args["workspace_slug"]
    doc_path = args["doc_path"]
    data = api_post(
        f"workspace/{slug}/update-embeddings",
        {"adds": [doc_path], "deletes": []},
    )
    return text_result(data)


def handle_system_info(args):
    data = api_get("system")
    return text_result(data)


HANDLERS = {
    "anythingllm_list_workspaces":        handle_list_workspaces,
    "anythingllm_chat":                   handle_chat,
    "anythingllm_vector_search":          handle_vector_search,
    "anythingllm_list_documents":         handle_list_documents,
    "anythingllm_workspace_documents":    handle_workspace_documents,
    "anythingllm_workspace_history":      handle_workspace_history,
    "anythingllm_upload_text":            handle_upload_text,
    "anythingllm_upload_url":             handle_upload_url,
    "anythingllm_add_document_to_workspace": handle_add_document_to_workspace,
    "anythingllm_system_info":            handle_system_info,
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
                "serverInfo": {"name": "anythingllm", "version": "1.0.0"},
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
