#!/usr/bin/env python3
"""
MCP server for MISP (Malware Information Sharing Platform).
Credentials loaded from MISP_URL + MISP_KEY env vars or ~/.misp_key (JSON).

~/.misp_key format:
  {"url": "https://misp.example.com", "key": "YOUR_API_KEY", "verify_ssl": true}
"""

import sys
import json
import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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


def get_config():
    url = os.environ.get("MISP_URL", "").strip()
    key = os.environ.get("MISP_KEY", "").strip()
    verify = True

    if not (url and key):
        key_file = os.path.expanduser("~/.misp_key")
        if os.path.exists(key_file):
            with open(key_file) as f:
                cfg = json.load(f)
            url    = cfg.get("url", "").rstrip("/")
            key    = cfg.get("key", "")
            verify = cfg.get("verify_ssl", True)

    if not (url and key):
        raise RuntimeError(
            "MISP credentials not found. Set MISP_URL + MISP_KEY env vars "
            "or create ~/.misp_key with {\"url\":..., \"key\":...}"
        )
    return url.rstrip("/"), key, verify


def misp_get(path, params=None):
    url, key, verify = get_config()
    headers = {"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"}
    resp = requests.get(f"{url}/{path}", headers=headers, params=params, verify=verify, timeout=20)
    resp.raise_for_status()
    return resp.json()


def misp_post(path, payload):
    url, key, verify = get_config()
    headers = {"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"}
    resp = requests.post(f"{url}/{path}", headers=headers, json=payload, verify=verify, timeout=20)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "misp_search_events",
        "description": "Search MISP events by keyword, tag, threat level, or date range.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "value": {
                    "type": "string",
                    "description": "Search term (free text, IOC value, event info field)",
                },
                "tags": {
                    "type": "string",
                    "description": "Comma-separated tag names to filter by (e.g. 'tlp:red,APT28')",
                },
                "threat_level_id": {
                    "type": "integer",
                    "description": "1=High, 2=Medium, 3=Low, 4=Undefined",
                },
                "date_from": {
                    "type": "string",
                    "description": "Start date (YYYY-MM-DD)",
                },
                "date_to": {
                    "type": "string",
                    "description": "End date (YYYY-MM-DD)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max events to return (default 20)",
                },
            },
        },
    },
    {
        "name": "misp_get_event",
        "description": "Get full details of a MISP event by ID, including all attributes and galaxies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event_id": {
                    "type": "string",
                    "description": "MISP event ID or UUID",
                },
            },
            "required": ["event_id"],
        },
    },
    {
        "name": "misp_search_attributes",
        "description": "Search MISP attributes (IOCs) by value, type, or category across all events.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "value": {
                    "type": "string",
                    "description": "IOC value to search (IP, domain, hash, URL, email...)",
                },
                "type": {
                    "type": "string",
                    "description": "Attribute type (e.g. 'ip-dst', 'domain', 'md5', 'url', 'email-src')",
                },
                "category": {
                    "type": "string",
                    "description": "Category (e.g. 'Network activity', 'Payload delivery', 'External analysis')",
                },
                "tags": {
                    "type": "string",
                    "description": "Comma-separated tags to filter by",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max attributes to return (default 50)",
                },
            },
        },
    },
    {
        "name": "misp_lookup_ioc",
        "description": "Quick lookup of a single IOC (IP, domain, hash, URL) across all MISP attributes. Returns matching events.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ioc": {
                    "type": "string",
                    "description": "IOC value to look up (e.g. '1.2.3.4', 'evil.com', 'abc123...')",
                },
            },
            "required": ["ioc"],
        },
    },
    {
        "name": "misp_add_event",
        "description": "Create a new MISP event with a title, threat level and optional attributes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "info": {
                    "type": "string",
                    "description": "Event title / description",
                },
                "threat_level_id": {
                    "type": "integer",
                    "description": "1=High, 2=Medium, 3=Low, 4=Undefined (default 4)",
                },
                "analysis": {
                    "type": "integer",
                    "description": "0=Initial, 1=Ongoing, 2=Complete (default 0)",
                },
                "distribution": {
                    "type": "integer",
                    "description": "0=Organisation only, 1=Community, 2=Connected, 3=All, 5=Inherit (default 0)",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of tags to add to the event",
                },
                "attributes": {
                    "type": "array",
                    "description": "List of attributes to add",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type":     {"type": "string"},
                            "category": {"type": "string"},
                            "value":    {"type": "string"},
                            "comment":  {"type": "string"},
                            "to_ids":   {"type": "boolean"},
                        },
                        "required": ["type", "category", "value"],
                    },
                },
            },
            "required": ["info"],
        },
    },
    {
        "name": "misp_add_attribute",
        "description": "Add a single attribute (IOC) to an existing MISP event.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event_id": {
                    "type": "string",
                    "description": "Event ID or UUID",
                },
                "type": {
                    "type": "string",
                    "description": "Attribute type (e.g. 'ip-dst', 'domain', 'md5', 'url', 'filename')",
                },
                "category": {
                    "type": "string",
                    "description": "Category (e.g. 'Network activity', 'Payload delivery')",
                },
                "value": {
                    "type": "string",
                    "description": "Attribute value",
                },
                "comment": {
                    "type": "string",
                    "description": "Optional comment",
                },
                "to_ids": {
                    "type": "boolean",
                    "description": "Flag for IDS/detection use (default false)",
                },
            },
            "required": ["event_id", "type", "category", "value"],
        },
    },
    {
        "name": "misp_list_tags",
        "description": "List all available tags in MISP, optionally filtered by name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Optional text filter for tag names",
                },
            },
        },
    },
    {
        "name": "misp_list_feeds",
        "description": "List all configured MISP feeds with their status and URL.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "misp_fetch_feeds",
        "description": "Trigger a fetch of all enabled MISP feeds.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "misp_server_info",
        "description": "Get MISP server version and statistics (events, attributes, users, orgs).",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

THREAT_LEVELS = {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}
ANALYSIS_LABELS = {0: "Initial", 1: "Ongoing", 2: "Complete"}


def _format_event(e):
    ev = e.get("Event", e)
    return {
        "id":           ev.get("id"),
        "uuid":         ev.get("uuid"),
        "info":         ev.get("info"),
        "date":         ev.get("date"),
        "threat_level": THREAT_LEVELS.get(int(ev.get("threat_level_id", 4)), "Unknown"),
        "analysis":     ANALYSIS_LABELS.get(int(ev.get("analysis", 0)), "Unknown"),
        "distribution": ev.get("distribution"),
        "published":    ev.get("published"),
        "org":          ev.get("Org", {}).get("name"),
        "orgc":         ev.get("Orgc", {}).get("name"),
        "tags":         [t.get("name") for t in ev.get("Tag", [])],
        "attribute_count": ev.get("attribute_count"),
        "timestamp":    ev.get("timestamp"),
    }


def handle_search_events(args):
    payload = {
        "returnFormat": "json",
        "limit":        args.get("limit", 20),
        "page":         1,
    }
    if args.get("value"):
        payload["value"] = args["value"]
    if args.get("tags"):
        payload["tags"] = [t.strip() for t in args["tags"].split(",")]
    if args.get("threat_level_id"):
        payload["threat_level_id"] = args["threat_level_id"]
    if args.get("date_from"):
        payload["from"] = args["date_from"]
    if args.get("date_to"):
        payload["to"] = args["date_to"]

    data = misp_post("events/restSearch", payload)
    events = data if isinstance(data, list) else data.get("response", [])
    return {
        "count":  len(events),
        "events": [_format_event(e) for e in events],
    }


def handle_get_event(args):
    event_id = args["event_id"]
    data = misp_get(f"events/view/{event_id}")
    ev = data.get("Event", data)

    attrs = []
    for a in ev.get("Attribute", []):
        attrs.append({
            "id":       a.get("id"),
            "type":     a.get("type"),
            "category": a.get("category"),
            "value":    a.get("value"),
            "comment":  a.get("comment"),
            "to_ids":   a.get("to_ids"),
            "tags":     [t.get("name") for t in a.get("Tag", [])],
        })

    galaxies = [
        {
            "name":    g.get("name"),
            "cluster": [c.get("value") for c in g.get("GalaxyCluster", [])],
        }
        for g in ev.get("Galaxy", [])
    ]

    result = _format_event(ev)
    result["attributes"] = attrs
    result["galaxies"]   = galaxies
    return result


def handle_search_attributes(args):
    payload = {
        "returnFormat": "json",
        "limit":        args.get("limit", 50),
    }
    if args.get("value"):
        payload["value"] = args["value"]
    if args.get("type"):
        payload["type"] = args["type"]
    if args.get("category"):
        payload["category"] = args["category"]
    if args.get("tags"):
        payload["tags"] = [t.strip() for t in args["tags"].split(",")]

    data = misp_post("attributes/restSearch", payload)
    attrs = data.get("response", {}).get("Attribute", [])

    return {
        "count": len(attrs),
        "attributes": [
            {
                "event_id": a.get("event_id"),
                "type":     a.get("type"),
                "category": a.get("category"),
                "value":    a.get("value"),
                "comment":  a.get("comment"),
                "to_ids":   a.get("to_ids"),
                "tags":     [t.get("name") for t in a.get("Tag", [])],
                "timestamp": a.get("timestamp"),
            }
            for a in attrs
        ],
    }


def handle_lookup_ioc(args):
    ioc = args["ioc"]
    payload = {"returnFormat": "json", "value": ioc, "limit": 100}
    data = misp_post("attributes/restSearch", payload)
    attrs = data.get("response", {}).get("Attribute", [])

    event_ids = list(dict.fromkeys(a.get("event_id") for a in attrs))
    return {
        "ioc":       ioc,
        "hits":      len(attrs),
        "event_ids": event_ids,
        "matches": [
            {
                "event_id": a.get("event_id"),
                "type":     a.get("type"),
                "category": a.get("category"),
                "value":    a.get("value"),
                "comment":  a.get("comment"),
                "to_ids":   a.get("to_ids"),
                "tags":     [t.get("name") for t in a.get("Tag", [])],
            }
            for a in attrs
        ],
    }


def handle_add_event(args):
    payload = {
        "info":             args["info"],
        "threat_level_id":  str(args.get("threat_level_id", 4)),
        "analysis":         str(args.get("analysis", 0)),
        "distribution":     str(args.get("distribution", 0)),
        "Attribute":        [],
        "Tag":              [],
    }

    for tag in args.get("tags", []):
        payload["Tag"].append({"name": tag})

    for attr in args.get("attributes", []):
        payload["Attribute"].append({
            "type":     attr["type"],
            "category": attr["category"],
            "value":    attr["value"],
            "comment":  attr.get("comment", ""),
            "to_ids":   attr.get("to_ids", False),
        })

    data = misp_post("events/add", {"Event": payload})
    ev = data.get("Event", data)
    return {
        "created": True,
        "id":      ev.get("id"),
        "uuid":    ev.get("uuid"),
        "info":    ev.get("info"),
    }


def handle_add_attribute(args):
    event_id = args["event_id"]
    payload = {
        "type":     args["type"],
        "category": args["category"],
        "value":    args["value"],
        "comment":  args.get("comment", ""),
        "to_ids":   args.get("to_ids", False),
    }
    data = misp_post(f"attributes/add/{event_id}", payload)
    attr = data.get("Attribute", data)
    return {
        "created":  True,
        "id":       attr.get("id"),
        "event_id": attr.get("event_id"),
        "type":     attr.get("type"),
        "value":    attr.get("value"),
    }


def handle_list_tags(args):
    data = misp_get("tags")
    tags = data.get("Tag", [])
    name_filter = args.get("filter", "").lower()
    if name_filter:
        tags = [t for t in tags if name_filter in t.get("name", "").lower()]
    return {
        "count": len(tags),
        "tags": [
            {
                "id":    t.get("id"),
                "name":  t.get("name"),
                "colour": t.get("colour"),
                "count": t.get("count"),
            }
            for t in tags
        ],
    }


def handle_list_feeds(args):
    data = misp_get("feeds")
    feeds = data if isinstance(data, list) else []
    return {
        "count": len(feeds),
        "feeds": [
            {
                "id":      f.get("Feed", {}).get("id"),
                "name":    f.get("Feed", {}).get("name"),
                "url":     f.get("Feed", {}).get("url"),
                "enabled": f.get("Feed", {}).get("enabled"),
                "provider": f.get("Feed", {}).get("provider"),
                "source_format": f.get("Feed", {}).get("source_format"),
            }
            for f in feeds
        ],
    }


def handle_fetch_feeds(args):
    data = misp_post("feeds/fetchFromAllFeeds", {})
    return {"status": "fetch triggered", "response": data}


def handle_server_info(args):
    version = misp_get("servers/getPyMISPVersion")
    stats   = misp_get("users/statistics")
    return {
        "version":    version,
        "statistics": stats,
    }


HANDLERS = {
    "misp_search_events":     handle_search_events,
    "misp_get_event":         handle_get_event,
    "misp_search_attributes": handle_search_attributes,
    "misp_lookup_ioc":        handle_lookup_ioc,
    "misp_add_event":         handle_add_event,
    "misp_add_attribute":     handle_add_attribute,
    "misp_list_tags":         handle_list_tags,
    "misp_list_feeds":        handle_list_feeds,
    "misp_fetch_feeds":       handle_fetch_feeds,
    "misp_server_info":       handle_server_info,
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
                "serverInfo": {"name": "misp-mcp", "version": "1.0.0"},
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
