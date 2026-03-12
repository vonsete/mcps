#!/usr/bin/env python3
"""
MCP server for database exploration — READ ONLY.
Supports: PostgreSQL, MySQL/MariaDB, SQLite, SQL Server, Oracle.

Connection params passed per call:
  engine   : postgresql | mysql | sqlite | sqlserver | oracle
  host     : hostname or IP (not needed for sqlite)
  port     : port (optional, uses defaults)
  database : database name (or file path for sqlite)
  user     : username (not needed for sqlite)
  password : password (not needed for sqlite)
"""

import sys
import json
import sqlite3
import re

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

CONN_PARAMS = {
    "type": "object",
    "properties": {
        "engine":   {"type": "string",  "description": "Database engine: postgresql, mysql, sqlite, sqlserver, oracle"},
        "host":     {"type": "string",  "description": "Host or IP (not needed for sqlite)"},
        "port":     {"type": "integer", "description": "Port (optional, uses engine defaults)"},
        "database": {"type": "string",  "description": "Database name or SQLite file path"},
        "user":     {"type": "string",  "description": "Username (not needed for sqlite)"},
        "password": {"type": "string",  "description": "Password (not needed for sqlite)"},
        "schema":   {"type": "string",  "description": "Default schema/namespace (optional)"},
    },
    "required": ["engine", "database"],
}

DEFAULT_PORTS = {
    "postgresql": 5432,
    "mysql":      3306,
    "sqlserver":  1433,
    "oracle":     1521,
}


def get_connection(args):
    engine   = args["engine"].lower()
    database = args["database"]
    host     = args.get("host", "localhost")
    port     = args.get("port", DEFAULT_PORTS.get(engine))
    user     = args.get("user", "")
    password = args.get("password", "")

    if engine == "postgresql":
        import psycopg2
        return psycopg2.connect(host=host, port=port, dbname=database, user=user, password=password, connect_timeout=10)

    elif engine == "mysql":
        import pymysql
        return pymysql.connect(host=host, port=port, database=database, user=user, password=password,
                               connect_timeout=10, cursorclass=pymysql.cursors.DictCursor)

    elif engine == "sqlite":
        conn = sqlite3.connect(database, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    elif engine == "sqlserver":
        import pyodbc
        dsn = (f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={host},{port};"
               f"DATABASE={database};UID={user};PWD={password};Connection Timeout=10")
        return pyodbc.connect(dsn)

    elif engine == "oracle":
        import oracledb
        return oracledb.connect(user=user, password=password, dsn=f"{host}:{port}/{database}")

    else:
        raise ValueError(f"Unknown engine: {engine}. Use: postgresql, mysql, sqlite, sqlserver, oracle")


def fetchall_as_dicts(cursor, engine):
    """Return cursor results as list of dicts, engine-agnostic."""
    if engine == "sqlite":
        return [dict(row) for row in cursor.fetchall()]
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def is_select(sql):
    """Ensure query is read-only."""
    clean = sql.strip().lstrip("(").upper()
    allowed = ("SELECT", "WITH", "EXPLAIN", "SHOW", "DESCRIBE", "DESC")
    return any(clean.startswith(k) for k in allowed)


# ---------------------------------------------------------------------------
# SQL fragments per engine
# ---------------------------------------------------------------------------

def sql_list_schemas(engine):
    if engine == "postgresql":
        return "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema','pg_toast') ORDER BY schema_name"
    elif engine == "mysql":
        return "SHOW DATABASES"
    elif engine == "sqlite":
        return None  # SQLite has no schemas
    elif engine == "sqlserver":
        return "SELECT name AS schema_name FROM sys.schemas WHERE schema_id < 16384 ORDER BY name"
    elif engine == "oracle":
        return "SELECT username AS schema_name FROM all_users ORDER BY username"


def sql_list_tables(engine, schema):
    if engine == "postgresql":
        s = schema or "public"
        return f"SELECT table_name, table_type FROM information_schema.tables WHERE table_schema = '{s}' ORDER BY table_name"
    elif engine == "mysql":
        s = schema  # schema = database name in MySQL
        where = f"AND table_schema = '{s}'" if s else ""
        return f"SELECT table_name, table_type, table_schema FROM information_schema.tables WHERE 1=1 {where} ORDER BY table_name"
    elif engine == "sqlite":
        return "SELECT name AS table_name, type AS table_type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name"
    elif engine == "sqlserver":
        s = schema or "dbo"
        return f"SELECT TABLE_NAME AS table_name, TABLE_TYPE AS table_type FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = '{s}' ORDER BY TABLE_NAME"
    elif engine == "oracle":
        s = schema
        where = f"AND owner = UPPER('{s}')" if s else ""
        return f"SELECT object_name AS table_name, object_type AS table_type FROM all_objects WHERE object_type IN ('TABLE','VIEW') {where} ORDER BY object_name"


def sql_describe_table(engine, schema, table):
    if engine == "postgresql":
        s = schema or "public"
        return f"""
            SELECT
                c.column_name,
                c.data_type,
                c.character_maximum_length,
                c.numeric_precision,
                c.is_nullable,
                c.column_default,
                CASE WHEN pk.column_name IS NOT NULL THEN 'YES' ELSE 'NO' END AS is_primary_key
            FROM information_schema.columns c
            LEFT JOIN (
                SELECT ku.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage ku
                    ON tc.constraint_name = ku.constraint_name AND tc.table_schema = ku.table_schema
                WHERE tc.constraint_type = 'PRIMARY KEY'
                  AND tc.table_name = '{table}' AND tc.table_schema = '{s}'
            ) pk ON c.column_name = pk.column_name
            WHERE c.table_name = '{table}' AND c.table_schema = '{s}'
            ORDER BY c.ordinal_position
        """
    elif engine == "mysql":
        return f"DESCRIBE `{table}`"
    elif engine == "sqlite":
        return f"PRAGMA table_info('{table}')"
    elif engine == "sqlserver":
        s = schema or "dbo"
        return f"""
            SELECT
                c.COLUMN_NAME AS column_name,
                c.DATA_TYPE AS data_type,
                c.CHARACTER_MAXIMUM_LENGTH AS max_length,
                c.IS_NULLABLE AS is_nullable,
                c.COLUMN_DEFAULT AS column_default,
                CASE WHEN pk.COLUMN_NAME IS NOT NULL THEN 'YES' ELSE 'NO' END AS is_primary_key
            FROM INFORMATION_SCHEMA.COLUMNS c
            LEFT JOIN (
                SELECT ku.COLUMN_NAME FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
                JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE ku ON tc.CONSTRAINT_NAME = ku.CONSTRAINT_NAME
                WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY' AND tc.TABLE_NAME = '{table}' AND tc.TABLE_SCHEMA = '{s}'
            ) pk ON c.COLUMN_NAME = pk.COLUMN_NAME
            WHERE c.TABLE_NAME = '{table}' AND c.TABLE_SCHEMA = '{s}'
            ORDER BY c.ORDINAL_POSITION
        """
    elif engine == "oracle":
        s = schema
        owner_filter = f"AND owner = UPPER('{s}')" if s else ""
        return f"""
            SELECT column_name, data_type, data_length, data_precision, nullable, data_default
            FROM all_tab_columns
            WHERE table_name = UPPER('{table}') {owner_filter}
            ORDER BY column_id
        """


def sql_list_indexes(engine, schema, table):
    if engine == "postgresql":
        s = schema or "public"
        return f"""
            SELECT i.relname AS index_name, ix.indisunique AS is_unique, ix.indisprimary AS is_primary,
                   array_to_string(array_agg(a.attname ORDER BY k.n), ', ') AS columns
            FROM pg_class t
            JOIN pg_index ix ON t.oid = ix.indrelid
            JOIN pg_class i ON i.oid = ix.indexrelid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, n) ON true
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
            WHERE t.relname = '{table}' AND n.nspname = '{s}'
            GROUP BY i.relname, ix.indisunique, ix.indisprimary
            ORDER BY i.relname
        """
    elif engine == "mysql":
        return f"SHOW INDEX FROM `{table}`"
    elif engine == "sqlite":
        return f"PRAGMA index_list('{table}')"
    elif engine == "sqlserver":
        s = schema or "dbo"
        return f"""
            SELECT i.name AS index_name, i.is_unique, i.is_primary_key,
                   STRING_AGG(c.name, ', ') WITHIN GROUP (ORDER BY ic.key_ordinal) AS columns
            FROM sys.indexes i
            JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
            JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
            JOIN sys.tables t ON i.object_id = t.object_id
            JOIN sys.schemas s ON t.schema_id = s.schema_id
            WHERE t.name = '{table}' AND s.name = '{s}'
            GROUP BY i.name, i.is_unique, i.is_primary_key
        """
    elif engine == "oracle":
        s = schema
        owner_filter = f"AND i.owner = UPPER('{s}')" if s else ""
        return f"""
            SELECT i.index_name, i.uniqueness, i.index_type,
                   LISTAGG(ic.column_name, ', ') WITHIN GROUP (ORDER BY ic.column_position) AS columns
            FROM all_indexes i
            JOIN all_ind_columns ic ON i.index_name = ic.index_name AND i.owner = ic.index_owner
            WHERE i.table_name = UPPER('{table}') {owner_filter}
            GROUP BY i.index_name, i.uniqueness, i.index_type
        """


def sql_list_foreign_keys(engine, schema, table):
    if engine == "postgresql":
        s = schema or "public"
        return f"""
            SELECT
                kcu.column_name,
                ccu.table_schema AS foreign_schema,
                ccu.table_name  AS foreign_table,
                ccu.column_name AS foreign_column,
                rc.update_rule, rc.delete_rule
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
            JOIN information_schema.referential_constraints rc
                ON tc.constraint_name = rc.constraint_name
            JOIN information_schema.constraint_column_usage ccu
                ON ccu.constraint_name = rc.unique_constraint_name
            WHERE tc.constraint_type = 'FOREIGN KEY'
              AND tc.table_name = '{table}' AND tc.table_schema = '{s}'
        """
    elif engine == "mysql":
        return f"""
            SELECT COLUMN_NAME, REFERENCED_TABLE_SCHEMA AS foreign_schema,
                   REFERENCED_TABLE_NAME AS foreign_table, REFERENCED_COLUMN_NAME AS foreign_column
            FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
            WHERE TABLE_NAME = '{table}' AND REFERENCED_TABLE_NAME IS NOT NULL
        """
    elif engine == "sqlite":
        return f"PRAGMA foreign_key_list('{table}')"
    elif engine == "sqlserver":
        return f"""
            SELECT
                COL_NAME(fk.parent_object_id, fkc.parent_column_id) AS column_name,
                OBJECT_SCHEMA_NAME(fk.referenced_object_id) AS foreign_schema,
                OBJECT_NAME(fk.referenced_object_id) AS foreign_table,
                COL_NAME(fk.referenced_object_id, fkc.referenced_column_id) AS foreign_column,
                fk.update_referential_action_desc AS update_rule,
                fk.delete_referential_action_desc AS delete_rule
            FROM sys.foreign_keys fk
            JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
            WHERE OBJECT_NAME(fk.parent_object_id) = '{table}'
        """
    elif engine == "oracle":
        s = schema
        owner_filter = f"AND a.owner = UPPER('{s}')" if s else ""
        return f"""
            SELECT a.column_name, c.r_owner AS foreign_schema,
                   c_pk.table_name AS foreign_table, a_pk.column_name AS foreign_column
            FROM all_cons_columns a
            JOIN all_constraints c ON a.owner = c.owner AND a.constraint_name = c.constraint_name
            JOIN all_constraints c_pk ON c.r_owner = c_pk.owner AND c.r_constraint_name = c_pk.constraint_name
            JOIN all_cons_columns a_pk ON c_pk.owner = a_pk.owner AND c_pk.constraint_name = a_pk.constraint_name
            WHERE c.constraint_type = 'R' AND a.table_name = UPPER('{table}') {owner_filter}
        """


def sql_table_stats(engine, schema, table):
    if engine == "postgresql":
        s = schema or "public"
        return f"""
            SELECT
                reltuples::bigint AS estimated_rows,
                pg_size_pretty(pg_total_relation_size('{s}.{table}')) AS total_size,
                pg_size_pretty(pg_relation_size('{s}.{table}')) AS table_size,
                pg_size_pretty(pg_indexes_size('{s}.{table}')) AS indexes_size
            FROM pg_class
            WHERE relname = '{table}'
        """
    elif engine == "mysql":
        return f"""
            SELECT table_rows AS estimated_rows, data_length, index_length,
                   ROUND((data_length + index_length) / 1024 / 1024, 2) AS total_size_mb,
                   engine, table_collation
            FROM information_schema.tables
            WHERE table_name = '{table}'
        """
    elif engine == "sqlite":
        return f"SELECT COUNT(*) AS row_count FROM '{table}'"
    elif engine == "sqlserver":
        return f"""
            SELECT SUM(p.rows) AS row_count,
                   SUM(a.total_pages) * 8 / 1024 AS total_size_mb,
                   SUM(a.used_pages) * 8 / 1024 AS used_size_mb
            FROM sys.tables t
            JOIN sys.partitions p ON t.object_id = p.object_id
            JOIN sys.allocation_units a ON p.partition_id = a.container_id
            WHERE t.name = '{table}' AND p.index_id IN (0, 1)
        """
    elif engine == "oracle":
        return f"SELECT num_rows AS estimated_rows, blocks, avg_row_len FROM all_tables WHERE table_name = UPPER('{table}')"


# ---------------------------------------------------------------------------
# TOOLS
# ---------------------------------------------------------------------------

CONN_FIELDS = {
    "engine":   {"type": "string",  "description": "postgresql | mysql | sqlite | sqlserver | oracle"},
    "host":     {"type": "string",  "description": "Host or IP (not needed for sqlite)"},
    "port":     {"type": "integer", "description": "Port (optional, uses engine defaults)"},
    "database": {"type": "string",  "description": "Database name or SQLite file path"},
    "user":     {"type": "string",  "description": "Username (not needed for sqlite)"},
    "password": {"type": "string",  "description": "Password (not needed for sqlite)"},
}

def conn_schema(extra_props=None, extra_required=None):
    props = dict(CONN_FIELDS)
    if extra_props:
        props.update(extra_props)
    req = ["engine", "database"] + (extra_required or [])
    return {"type": "object", "properties": props, "required": req}


TOOLS = [
    {
        "name": "db_list_schemas",
        "description": "List all schemas/databases available in the server.",
        "inputSchema": conn_schema(),
    },
    {
        "name": "db_list_tables",
        "description": "List all tables and views in a schema/database.",
        "inputSchema": conn_schema({"schema": {"type": "string", "description": "Schema or database name to list tables from"}}),
    },
    {
        "name": "db_describe_table",
        "description": "Show all columns, data types, nullability, defaults and primary keys for a table.",
        "inputSchema": conn_schema(
            {"schema": {"type": "string"}, "table": {"type": "string", "description": "Table name"}},
            extra_required=["table"],
        ),
    },
    {
        "name": "db_list_indexes",
        "description": "Show all indexes (including primary key and unique) for a table.",
        "inputSchema": conn_schema(
            {"schema": {"type": "string"}, "table": {"type": "string"}},
            extra_required=["table"],
        ),
    },
    {
        "name": "db_list_foreign_keys",
        "description": "Show all foreign key relationships for a table.",
        "inputSchema": conn_schema(
            {"schema": {"type": "string"}, "table": {"type": "string"}},
            extra_required=["table"],
        ),
    },
    {
        "name": "db_table_stats",
        "description": "Show row count, table size and index size for a table.",
        "inputSchema": conn_schema(
            {"schema": {"type": "string"}, "table": {"type": "string"}},
            extra_required=["table"],
        ),
    },
    {
        "name": "db_schema_overview",
        "description": "Full schema overview: all tables with their columns, types, PKs, FKs and indexes in one call.",
        "inputSchema": conn_schema({"schema": {"type": "string"}}),
    },
    {
        "name": "db_query",
        "description": "Execute a read-only SQL query (SELECT/WITH/EXPLAIN only). Returns results as a list of rows.",
        "inputSchema": conn_schema(
            {
                "schema": {"type": "string"},
                "sql":    {"type": "string", "description": "SQL query to execute (SELECT/WITH/EXPLAIN only)"},
                "limit":  {"type": "integer", "description": "Maximum rows to return (default 100, max 5000)"},
            },
            extra_required=["sql"],
        ),
    },
    {
        "name": "db_search_column",
        "description": "Find all tables that contain a column with a given name (useful for tracing data across the schema).",
        "inputSchema": conn_schema(
            {
                "schema":      {"type": "string"},
                "column_name": {"type": "string", "description": "Column name to search for (partial match supported)"},
            },
            extra_required=["column_name"],
        ),
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def run_query(args, sql):
    engine = args["engine"].lower()
    conn   = get_connection(args)
    try:
        cur = conn.cursor()
        cur.execute(sql)
        return fetchall_as_dicts(cur, engine)
    finally:
        conn.close()


def handle_db_list_schemas(args):
    engine = args["engine"].lower()
    if engine == "sqlite":
        return {"schemas": ["main"], "note": "SQLite has a single 'main' schema"}
    sql  = sql_list_schemas(engine)
    rows = run_query(args, sql)
    return {"schemas": rows}


def handle_db_list_tables(args):
    engine = args["engine"].lower()
    schema = args.get("schema")
    sql    = sql_list_tables(engine, schema)
    rows   = run_query(args, sql)
    return {"schema": schema, "tables": rows, "total": len(rows)}


def handle_db_describe_table(args):
    engine = args["engine"].lower()
    schema = args.get("schema")
    table  = args["table"]
    sql    = sql_describe_table(engine, schema, table)
    rows   = run_query(args, sql)
    return {"table": table, "schema": schema, "columns": rows, "column_count": len(rows)}


def handle_db_list_indexes(args):
    engine = args["engine"].lower()
    schema = args.get("schema")
    table  = args["table"]
    sql    = sql_list_indexes(engine, schema, table)
    rows   = run_query(args, sql)
    if engine == "sqlite":
        # Also get index info for each
        conn = get_connection(args)
        try:
            details = []
            cur = conn.cursor()
            for row in rows:
                cur.execute(f"PRAGMA index_info('{dict(row)['name']}')")
                cols = [dict(c) for c in cur.fetchall()]
                d = dict(row)
                d["columns"] = [c["name"] for c in cols]
                details.append(d)
            return {"table": table, "indexes": details}
        finally:
            conn.close()
    return {"table": table, "indexes": rows}


def handle_db_list_foreign_keys(args):
    engine = args["engine"].lower()
    schema = args.get("schema")
    table  = args["table"]
    sql    = sql_list_foreign_keys(engine, schema, table)
    rows   = run_query(args, sql)
    return {"table": table, "foreign_keys": rows, "total": len(rows)}


def handle_db_table_stats(args):
    engine = args["engine"].lower()
    schema = args.get("schema")
    table  = args["table"]
    sql    = sql_table_stats(engine, schema, table)
    rows   = run_query(args, sql)
    return {"table": table, "stats": rows[0] if rows else {}}


def handle_db_schema_overview(args):
    engine = args["engine"].lower()
    schema = args.get("schema")

    # Get tables
    tables_sql = sql_list_tables(engine, schema)
    tables     = run_query(args, tables_sql)

    overview = []
    for t in tables:
        # Get table name depending on engine/key
        tname = (t.get("table_name") or t.get("TABLE_NAME") or t.get("name") or
                 t.get("object_name") or t.get("OBJECT_NAME") or "")
        if not tname:
            continue
        entry = {"table": tname, "type": t.get("table_type") or t.get("TABLE_TYPE") or t.get("type")}

        # Columns
        try:
            col_sql = sql_describe_table(engine, schema, tname)
            entry["columns"] = run_query(args, col_sql)
        except Exception as e:
            entry["columns"] = [{"error": str(e)}]

        # Foreign keys
        try:
            fk_sql = sql_list_foreign_keys(engine, schema, tname)
            entry["foreign_keys"] = run_query(args, fk_sql)
        except Exception:
            entry["foreign_keys"] = []

        overview.append(entry)

    return {
        "engine":  engine,
        "schema":  schema,
        "tables":  len(overview),
        "overview": overview,
    }


def handle_db_query(args):
    sql   = args["sql"].strip()
    limit = min(int(args.get("limit", 100)), 5000)

    if not is_select(sql):
        return {"error": "Only SELECT, WITH, EXPLAIN and SHOW queries are allowed (read-only mode)"}

    engine = args["engine"].lower()
    conn   = get_connection(args)
    try:
        # Set search_path for PostgreSQL
        if engine == "postgresql" and args.get("schema"):
            cur = conn.cursor()
            cur.execute(f"SET search_path TO {args['schema']}")

        cur = conn.cursor()
        # Wrap in LIMIT if not already present (PostgreSQL/MySQL/SQLite)
        if engine in ("postgresql", "mysql", "sqlite"):
            if "limit" not in sql.lower():
                sql = f"SELECT * FROM ({sql}) _q LIMIT {limit}"
        cur.execute(sql)
        rows = fetchall_as_dicts(cur, engine)
        return {
            "rows":     rows[:limit],
            "count":    len(rows),
            "limited":  len(rows) >= limit,
            "columns":  list(rows[0].keys()) if rows else [],
        }
    finally:
        conn.close()


def handle_db_search_column(args):
    engine      = args["engine"].lower()
    schema      = args.get("schema")
    column_name = args["column_name"]

    if engine == "postgresql":
        s = schema or "public"
        sql = f"""
            SELECT table_name, column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = '{s}' AND column_name ILIKE '%{column_name}%'
            ORDER BY table_name, column_name
        """
    elif engine == "mysql":
        where_schema = f"AND table_schema = '{schema}'" if schema else ""
        sql = f"""
            SELECT table_name, column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE column_name LIKE '%{column_name}%' {where_schema}
            ORDER BY table_name, column_name
        """
    elif engine == "sqlite":
        # SQLite: iterate all tables
        conn = get_connection(args)
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables  = [r[0] for r in cur.fetchall()]
            matches = []
            for t in tables:
                cur.execute(f"PRAGMA table_info('{t}')")
                for col in cur.fetchall():
                    col = dict(col)
                    if column_name.lower() in col["name"].lower():
                        matches.append({"table_name": t, "column_name": col["name"], "data_type": col["type"]})
            return {"search": column_name, "matches": matches, "total": len(matches)}
        finally:
            conn.close()
    elif engine == "sqlserver":
        where_schema = f"AND TABLE_SCHEMA = '{schema}'" if schema else ""
        sql = f"""
            SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name, DATA_TYPE AS data_type, IS_NULLABLE AS is_nullable
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE COLUMN_NAME LIKE '%{column_name}%' {where_schema}
            ORDER BY TABLE_NAME, COLUMN_NAME
        """
    elif engine == "oracle":
        owner_filter = f"AND owner = UPPER('{schema}')" if schema else ""
        sql = f"""
            SELECT table_name, column_name, data_type, nullable
            FROM all_tab_columns
            WHERE column_name LIKE UPPER('%{column_name}%') {owner_filter}
            ORDER BY table_name, column_name
        """

    rows = run_query(args, sql)
    return {"search": column_name, "matches": rows, "total": len(rows)}


HANDLERS = {
    "db_list_schemas":      handle_db_list_schemas,
    "db_list_tables":       handle_db_list_tables,
    "db_describe_table":    handle_db_describe_table,
    "db_list_indexes":      handle_db_list_indexes,
    "db_list_foreign_keys": handle_db_list_foreign_keys,
    "db_table_stats":       handle_db_table_stats,
    "db_schema_overview":   handle_db_schema_overview,
    "db_query":             handle_db_query,
    "db_search_column":     handle_db_search_column,
}


def handle_call(id, name, args):
    handler = HANDLERS.get(name)
    if not handler:
        error(id, -32601, f"Unknown tool: {name}")
        return
    try:
        result = handler(args)
        respond(id, text_result(result))
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
                "serverInfo": {"name": "db-mcp", "version": "1.0.0"},
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
