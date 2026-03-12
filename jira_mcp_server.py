#!/usr/bin/env python3
"""
MCP server for Jira REST API v3.
Credentials loaded from environment variables:
  JIRA_INSTANCE_URL, JIRA_USER_EMAIL, JIRA_API_KEY
"""

import sys
import json
import os
import requests
from requests.auth import HTTPBasicAuth


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


def get_config():
    url   = os.environ.get("JIRA_INSTANCE_URL", "").rstrip("/")
    email = os.environ.get("JIRA_USER_EMAIL", "")
    token = os.environ.get("JIRA_API_KEY", "")
    if not all([url, email, token]):
        raise RuntimeError("Missing JIRA_INSTANCE_URL, JIRA_USER_EMAIL or JIRA_API_KEY")
    return url, HTTPBasicAuth(email, token)


def jira_get(path, params=None):
    url, auth = get_config()
    resp = requests.get(
        f"{url}/rest/api/3/{path}",
        auth=auth,
        params=params,
        headers={"Accept": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def jira_post(path, body):
    url, auth = get_config()
    resp = requests.post(
        f"{url}/rest/api/3/{path}",
        auth=auth,
        json=body,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json() if resp.content else {}


def jira_put(path, body):
    url, auth = get_config()
    resp = requests.put(
        f"{url}/rest/api/3/{path}",
        auth=auth,
        json=body,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json() if resp.content else {}


def format_issue(issue):
    f = issue.get("fields", {})
    return {
        "key":      issue.get("key"),
        "summary":  f.get("summary"),
        "status":   f.get("status", {}).get("name"),
        "priority": f.get("priority", {}).get("name"),
        "assignee": (f.get("assignee") or {}).get("displayName"),
        "reporter": (f.get("reporter") or {}).get("displayName"),
        "project":  f.get("project", {}).get("name"),
        "type":     f.get("issuetype", {}).get("name"),
        "created":  f.get("created"),
        "updated":  f.get("updated"),
        "url":      f"{os.environ.get('JIRA_INSTANCE_URL','').rstrip('/')}/browse/{issue.get('key')}",
    }


def text_result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "jira_my_issues",
        "description": "Get issues assigned to the current user.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": "Filter by status (e.g. 'In Progress', 'To Do', 'Done'). Omit for all.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results (default 20).",
                },
            },
        },
    },
    {
        "name": "jira_search",
        "description": "Search issues using JQL (Jira Query Language).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "jql": {
                    "type": "string",
                    "description": "JQL query (e.g. 'project = PROJ AND status = \"In Progress\"')",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results (default 20).",
                },
            },
            "required": ["jql"],
        },
    },
    {
        "name": "jira_get_issue",
        "description": "Get full details of a specific Jira issue.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "issue_key": {
                    "type": "string",
                    "description": "Issue key (e.g. 'PROJ-123')",
                },
            },
            "required": ["issue_key"],
        },
    },
    {
        "name": "jira_create_issue",
        "description": "Create a new Jira issue.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_key": {
                    "type": "string",
                    "description": "Project key (e.g. 'PROJ')",
                },
                "summary": {
                    "type": "string",
                    "description": "Issue title/summary",
                },
                "description": {
                    "type": "string",
                    "description": "Issue description",
                },
                "issue_type": {
                    "type": "string",
                    "description": "Issue type (e.g. 'Bug', 'Task', 'Story'). Default: Task",
                },
                "priority": {
                    "type": "string",
                    "description": "Priority (e.g. 'High', 'Medium', 'Low')",
                },
                "assignee": {
                    "type": "string",
                    "description": "Display name or email of the user to assign (e.g. 'Miguel Angel Tabernero')",
                },
            },
            "required": ["project_key", "summary"],
        },
    },
    {
        "name": "jira_add_comment",
        "description": "Add a comment to a Jira issue.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "issue_key": {
                    "type": "string",
                    "description": "Issue key (e.g. 'PROJ-123')",
                },
                "comment": {
                    "type": "string",
                    "description": "Comment text",
                },
            },
            "required": ["issue_key", "comment"],
        },
    },
    {
        "name": "jira_get_transitions",
        "description": "Get available status transitions for a Jira issue.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "issue_key": {
                    "type": "string",
                    "description": "Issue key (e.g. 'PROJ-123')",
                },
            },
            "required": ["issue_key"],
        },
    },
    {
        "name": "jira_transition_issue",
        "description": "Change the status of a Jira issue.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "issue_key": {
                    "type": "string",
                    "description": "Issue key (e.g. 'PROJ-123')",
                },
                "transition_name": {
                    "type": "string",
                    "description": "Name of the target status (e.g. 'In Progress', 'Closed')",
                },
                "resolution": {
                    "type": "string",
                    "description": "Resolution when closing (e.g. 'Done', 'Fixed', \"Won't Do'). Required when transitioning to Closed.",
                },
            },
            "required": ["issue_key", "transition_name"],
        },
    },
    {
        "name": "jira_get_projects",
        "description": "List all accessible Jira projects.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def handle_my_issues(args):
    status      = args.get("status")
    max_results = args.get("max_results", 20)
    jql = "assignee = currentUser()"
    if status:
        jql += f' AND status = "{status}"'
    jql += " ORDER BY updated DESC"
    data = jira_get("search/jql", {"jql": jql, "maxResults": max_results,
                               "fields": "summary,status,priority,assignee,reporter,project,issuetype,created,updated"})
    issues = [format_issue(i) for i in data.get("issues", [])]
    return {"total": data.get("total"), "issues": issues}


def handle_search(args):
    jql         = args.get("jql")
    max_results = args.get("max_results", 20)
    data = jira_get("search/jql", {"jql": jql, "maxResults": max_results,
                               "fields": "summary,status,priority,assignee,reporter,project,issuetype,created,updated"})
    issues = [format_issue(i) for i in data.get("issues", [])]
    return {"total": data.get("total"), "issues": issues}


def handle_get_issue(args):
    key  = args.get("issue_key")
    data = jira_get(f"issue/{key}")
    f    = data.get("fields", {})
    result = format_issue(data)
    # Include description and comments
    desc = f.get("description")
    if desc:
        result["description"] = _extract_text(desc)
    comments = f.get("comment", {}).get("comments", [])
    result["comments"] = [
        {
            "author":  (c.get("author") or {}).get("displayName"),
            "created": c.get("created"),
            "body":    _extract_text(c.get("body", {})),
        }
        for c in comments[-5:]  # last 5 comments
    ]
    return result


def find_account_id(query):
    """Search for a user by name or email and return their accountId."""
    data = jira_get("user/search", {"query": query, "maxResults": 5})
    if not data:
        raise ValueError(f"User '{query}' not found in Jira")
    # Try exact match first, then return first result
    for user in data:
        display = user.get("displayName", "").lower()
        if query.lower() in display:
            return user["accountId"]
    return data[0]["accountId"]


def handle_create_issue(args):
    body = {
        "fields": {
            "project":   {"key": args.get("project_key")},
            "summary":   args.get("summary"),
            "issuetype": {"name": args.get("issue_type", "Task")},
        }
    }
    if args.get("description"):
        body["fields"]["description"] = {
            "type": "doc", "version": 1,
            "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": args.get("description")}
            ]}]
        }
    if args.get("priority"):
        body["fields"]["priority"] = {"name": args.get("priority")}
    if args.get("assignee"):
        account_id = find_account_id(args.get("assignee"))
        body["fields"]["assignee"] = {"accountId": account_id}
    data = jira_post("issue", body)
    instance_url = os.environ.get("JIRA_INSTANCE_URL", "").rstrip("/")
    return {"key": data.get("key"), "url": f"{instance_url}/browse/{data.get('key')}"}


def handle_add_comment(args):
    key     = args.get("issue_key")
    comment = args.get("comment")
    body = {
        "body": {
            "type": "doc", "version": 1,
            "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": comment}
            ]}]
        }
    }
    data = jira_post(f"issue/{key}/comment", body)
    return {"id": data.get("id"), "created": data.get("created")}


def handle_get_transitions(args):
    key  = args.get("issue_key")
    data = jira_get(f"issue/{key}/transitions")
    return [{"id": t["id"], "name": t["name"]} for t in data.get("transitions", [])]


def handle_transition_issue(args):
    key             = args.get("issue_key")
    transition_name = args.get("transition_name").lower()
    resolution      = args.get("resolution")
    data            = jira_get(f"issue/{key}/transitions")
    transitions     = data.get("transitions", [])
    match = next((t for t in transitions if t["name"].lower() == transition_name), None)
    if not match:
        available = [t["name"] for t in transitions]
        raise ValueError(f"Transition '{transition_name}' not found. Available: {available}")
    body = {"transition": {"id": match["id"]}}
    if resolution:
        body["fields"] = {"resolution": {"name": resolution}}
    jira_post(f"issue/{key}/transitions", body)
    return {"issue": key, "transitioned_to": match["name"]}


def handle_get_projects(args):
    data = jira_get("project")
    return [{"key": p["key"], "name": p["name"], "type": p.get("projectTypeKey")} for p in data]


def _extract_text(node):
    """Extract plain text from Atlassian Document Format."""
    if not node:
        return ""
    if isinstance(node, str):
        return node
    if node.get("type") == "text":
        return node.get("text", "")
    text = ""
    for child in node.get("content", []):
        text += _extract_text(child)
        if node.get("type") in ("paragraph", "heading"):
            text += "\n"
    return text


HANDLERS = {
    "jira_my_issues":       handle_my_issues,
    "jira_search":          handle_search,
    "jira_get_issue":       handle_get_issue,
    "jira_create_issue":    handle_create_issue,
    "jira_add_comment":     handle_add_comment,
    "jira_get_transitions": handle_get_transitions,
    "jira_transition_issue": handle_transition_issue,
    "jira_get_projects":    handle_get_projects,
}


def handle_call(id, name, args):
    handler = HANDLERS.get(name)
    if not handler:
        error(id, -32601, f"Unknown tool: {name}")
        return
    try:
        result = handler(args)
        respond(id, text_result(result))
    except requests.HTTPError as e:
        respond(id, {"content": [{"type": "text", "text": f"[HTTP error]: {e} — {e.response.text[:300]}"}], "isError": True})
    except Exception as e:
        respond(id, {"content": [{"type": "text", "text": f"[error]: {e}"}], "isError": True})


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

        method = msg.get("method")
        id     = msg.get("id")

        if method == "initialize":
            respond(id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "jira-mcp", "version": "1.0.0"},
            })
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            respond(id, {"tools": TOOLS})
        elif method == "tools/call":
            params = msg.get("params", {})
            handle_call(id, params.get("name"), params.get("arguments", {}))
        elif id is not None:
            error(id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    main()
