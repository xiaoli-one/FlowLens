import json
import os
import sqlite3
import threading
import time

from agent_pass_scan.traffic_model import (
    body_truncated,
    classify_auth,
    extract_query_resources,
    looks_sensitive_endpoint,
    normalize_path,
    parameter_resource_refs,
    semantic_type_for_name,
    stable_hash,
    text_body,
)


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS flows (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  flow_hash TEXT UNIQUE,
  time TEXT,
  duration_ms INTEGER,
  method TEXT,
  scheme TEXT,
  host TEXT,
  path TEXT,
  query TEXT,
  url TEXT,
  normalized_path TEXT,
  status_code INTEGER,
  request_content_type TEXT,
  response_content_type TEXT,
  auth_type TEXT,
  auth_fingerprint TEXT,
  request_headers_json TEXT,
  request_body_text TEXT,
  response_headers_json TEXT,
  response_body_text TEXT,
  body_truncated INTEGER,
  created_at REAL
);
CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT,
  method TEXT,
  normalized_path TEXT,
  first_seen TEXT,
  last_seen TEXT,
  count INTEGER DEFAULT 0,
  last_signature TEXT,
  UNIQUE(host, method, normalized_path)
);
CREATE TABLE IF NOT EXISTS identities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT,
  auth_fingerprint TEXT,
  auth_type TEXT,
  cookie_names TEXT,
  token_hint TEXT,
  first_seen TEXT,
  last_seen TEXT,
  count INTEGER DEFAULT 0,
  UNIQUE(host, auth_fingerprint)
);
CREATE TABLE IF NOT EXISTS flow_identities (
  flow_id INTEGER,
  identity_id INTEGER,
  PRIMARY KEY(flow_id, identity_id)
);
CREATE TABLE IF NOT EXISTS parameters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  flow_id INTEGER,
  place TEXT,
  param_index INTEGER,
  name TEXT,
  value_preview TEXT,
  semantic_type TEXT,
  json_path_json TEXT,
  charset TEXT
);
CREATE TABLE IF NOT EXISTS resource_refs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  flow_id INTEGER,
  name TEXT,
  value TEXT,
  source TEXT,
  semantic_type TEXT
);
CREATE TABLE IF NOT EXISTS analyzed_candidates (
  candidate_key TEXT PRIMARY KEY,
  time TEXT,
  status TEXT
);
CREATE TABLE IF NOT EXISTS logic_findings (
  finding_key TEXT PRIMARY KEY,
  time TEXT,
  type TEXT,
  status TEXT,
  host TEXT,
  endpoint TEXT,
  finding_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_endpoint ON flows(host, method, normalized_path);
CREATE INDEX IF NOT EXISTS idx_flows_auth ON flows(host, auth_fingerprint);
CREATE INDEX IF NOT EXISTS idx_resources_flow ON resource_refs(flow_id);
CREATE INDEX IF NOT EXISTS idx_params_flow ON parameters(flow_id);
"""


class FlowStore:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.lock = threading.Lock()
        self.init_db()

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=20)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.lock:
            with self.connect() as conn:
                conn.executescript(SCHEMA)
                self.ensure_parameter_columns(conn)

    def ensure_parameter_columns(self, conn):
        rows = conn.execute("PRAGMA table_info(parameters)").fetchall()
        existing = {row["name"] for row in rows}
        migrations = {
            "param_index": "ALTER TABLE parameters ADD COLUMN param_index INTEGER",
            "json_path_json": "ALTER TABLE parameters ADD COLUMN json_path_json TEXT",
            "charset": "ALTER TABLE parameters ADD COLUMN charset TEXT",
        }
        for column, statement in migrations.items():
            if column not in existing:
                conn.execute(statement)

    def ingest_context(self, context):
        record = context.record or {}
        request = record.get("request") or {}
        response = record.get("response") or {}
        normalized_path, path_refs = normalize_path(context.path)
        query_refs = extract_query_resources(request.get("query") or "")
        param_refs = parameter_resource_refs(context.parameters)
        resource_refs = path_refs + query_refs + param_refs
        auth = classify_auth(request.get("headers") or {})
        flow_material = {
            "method": context.method,
            "url": context.url,
            "status_code": context.status_code,
            "request_body": text_body(request.get("body")),
            "auth_fingerprint": auth["auth_fingerprint"],
        }
        flow_hash = stable_hash(flow_material, 32)
        now = time.time()

        with self.lock:
            with self.connect() as conn:
                endpoint_id = self.upsert_endpoint(
                    conn,
                    context.host,
                    context.method,
                    normalized_path,
                    record.get("time") or "",
                )
                identity_id = self.upsert_identity(
                    conn,
                    context.host,
                    auth,
                    record.get("time") or "",
                )
                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO flows (
                      flow_hash, time, duration_ms, method, scheme, host, path, query,
                      url, normalized_path, status_code, request_content_type,
                      response_content_type, auth_type, auth_fingerprint,
                      request_headers_json, request_body_text, response_headers_json,
                      response_body_text, body_truncated, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        flow_hash,
                        record.get("time") or "",
                        int(record.get("duration_ms") or 0),
                        context.method,
                        context.scheme,
                        context.host,
                        context.path,
                        request.get("query") or "",
                        context.url,
                        normalized_path,
                        int(context.status_code or 0),
                        context.request_content_type,
                        context.response_content_type,
                        auth["auth_type"],
                        auth["auth_fingerprint"],
                        json.dumps(request.get("headers") or {}, ensure_ascii=False),
                        text_body(request.get("body")),
                        json.dumps(response.get("headers") or {}, ensure_ascii=False),
                        text_body(response.get("body")),
                        1 if body_truncated(response.get("body")) else 0,
                        now,
                    ),
                )
                flow_id = cursor.lastrowid if cursor.rowcount else None
                if flow_id:
                    conn.execute(
                        "INSERT OR IGNORE INTO flow_identities(flow_id, identity_id) VALUES (?, ?)",
                        (flow_id, identity_id),
                    )
                    self.insert_parameters(conn, flow_id, context.parameters)
                    self.insert_resource_refs(conn, flow_id, resource_refs)
                    conn.execute(
                        "UPDATE endpoints SET count = count + 1, last_seen = ? WHERE id = ?",
                        (record.get("time") or "", endpoint_id),
                    )
                    conn.execute(
                        "UPDATE identities SET count = count + 1, last_seen = ? WHERE id = ?",
                        (record.get("time") or "", identity_id),
                    )

                stats = self.endpoint_stats(conn, endpoint_id)
                signature = self.analysis_signature(stats)
                should_analyze = self.should_analyze(conn, endpoint_id, signature)
                return {
                    "endpoint_id": endpoint_id,
                    "normalized_path": normalized_path,
                    "signature": signature,
                    "should_analyze": should_analyze,
                    "flow_id": flow_id,
                    "stats": stats,
                    "sensitive": looks_sensitive_endpoint(
                        context.method,
                        normalized_path,
                        context.parameters,
                    )
                    or bool(resource_refs),
                }

    def upsert_endpoint(self, conn, host, method, normalized_path, seen_time):
        conn.execute(
            """
            INSERT OR IGNORE INTO endpoints(host, method, normalized_path, first_seen, last_seen, count)
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            (host, method, normalized_path, seen_time, seen_time),
        )
        row = conn.execute(
            "SELECT id FROM endpoints WHERE host = ? AND method = ? AND normalized_path = ?",
            (host, method, normalized_path),
        ).fetchone()
        return int(row["id"])

    def upsert_identity(self, conn, host, auth, seen_time):
        conn.execute(
            """
            INSERT OR IGNORE INTO identities(host, auth_fingerprint, auth_type, cookie_names, token_hint, first_seen, last_seen, count)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                host,
                auth["auth_fingerprint"],
                auth["auth_type"],
                auth["cookie_names"],
                auth["token_hint"],
                seen_time,
                seen_time,
            ),
        )
        row = conn.execute(
            "SELECT id FROM identities WHERE host = ? AND auth_fingerprint = ?",
            (host, auth["auth_fingerprint"]),
        ).fetchone()
        return int(row["id"])

    def insert_parameters(self, conn, flow_id, parameters):
        for parameter in parameters or []:
            conn.execute(
                """
                INSERT INTO parameters(
                  flow_id, place, param_index, name, value_preview,
                  semantic_type, json_path_json, charset
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow_id,
                    parameter.get("place", ""),
                    parameter.get("index"),
                    parameter.get("name", ""),
                    str(parameter.get("value", ""))[:200],
                    semantic_type_for_name(parameter.get("name")),
                    json.dumps(parameter.get("json_path"), ensure_ascii=False)
                    if parameter.get("json_path") is not None
                    else "",
                    parameter.get("charset", ""),
                ),
            )

    def insert_resource_refs(self, conn, flow_id, refs):
        seen = set()
        for ref in refs or []:
            key = (
                ref.get("name", ""),
                ref.get("value", ""),
                ref.get("source", ""),
                ref.get("semantic_type", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            conn.execute(
                """
                INSERT INTO resource_refs(flow_id, name, value, source, semantic_type)
                VALUES (?, ?, ?, ?, ?)
                """,
                (flow_id, key[0], key[1], key[2], key[3]),
            )

    def endpoint_stats(self, conn, endpoint_id):
        endpoint = conn.execute("SELECT * FROM endpoints WHERE id = ?", (endpoint_id,)).fetchone()
        flow_rows = conn.execute(
            """
            SELECT id, auth_fingerprint, status_code
            FROM flows
            WHERE host = ? AND method = ? AND normalized_path = ?
            ORDER BY id DESC
            LIMIT 80
            """,
            (endpoint["host"], endpoint["method"], endpoint["normalized_path"]),
        ).fetchall()
        auths = {row["auth_fingerprint"] for row in flow_rows if row["auth_fingerprint"]}
        resource_count = conn.execute(
            """
            SELECT COUNT(*)
            FROM resource_refs r
            JOIN flows f ON f.id = r.flow_id
            WHERE f.host = ? AND f.method = ? AND f.normalized_path = ?
            """,
            (endpoint["host"], endpoint["method"], endpoint["normalized_path"]),
        ).fetchone()[0]
        success_count = sum(1 for row in flow_rows if 200 <= int(row["status_code"] or 0) < 400)
        return {
            "flow_count": int(endpoint["count"] or 0),
            "identity_count": len(auths),
            "resource_count": int(resource_count or 0),
            "success_count": success_count,
        }

    def analysis_signature(self, stats):
        flow_bucket = min(int(stats.get("flow_count", 0)) // 5, 20)
        return "f{flow}:i{ident}:r{res}:s{succ}".format(
            flow=flow_bucket,
            ident=min(int(stats.get("identity_count", 0)), 8),
            res=min(int(stats.get("resource_count", 0)), 20),
            succ=min(int(stats.get("success_count", 0)), 20),
        )

    def should_analyze(self, conn, endpoint_id, signature):
        row = conn.execute("SELECT last_signature FROM endpoints WHERE id = ?", (endpoint_id,)).fetchone()
        if row and row["last_signature"] == signature:
            return False
        conn.execute("UPDATE endpoints SET last_signature = ? WHERE id = ?", (signature, endpoint_id))
        return True

    def load_endpoint_bundle(self, endpoint_id, max_flows=30):
        with self.lock:
            with self.connect() as conn:
                endpoint = conn.execute("SELECT * FROM endpoints WHERE id = ?", (endpoint_id,)).fetchone()
                if not endpoint:
                    return None
                flow_rows = conn.execute(
                    """
                    SELECT *
                    FROM flows
                    WHERE host = ? AND method = ? AND normalized_path = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (
                        endpoint["host"],
                        endpoint["method"],
                        endpoint["normalized_path"],
                        int(max_flows),
                    ),
                ).fetchall()
                flows = []
                for row in flow_rows:
                    flows.append(self.hydrate_flow_row(conn, row))

                identity_flows = self.load_host_identity_flows(conn, endpoint["host"])
                identity_memory = self.build_identity_memory(
                    self.unique_flows(flows + identity_flows)
                )
                return {
                    "endpoint": dict(endpoint),
                    "flows": flows,
                    "identity_flows": identity_flows,
                    "stats": self.endpoint_stats(conn, endpoint_id),
                    "identity_memory": identity_memory,
                }

    def hydrate_flow_row(self, conn, row):
        flow = dict(row)
        flow["request_headers"] = json.loads(flow.pop("request_headers_json") or "{}")
        flow["response_headers"] = json.loads(flow.pop("response_headers_json") or "{}")
        flow["parameters"] = [
            self.hydrate_parameter_row(item)
            for item in conn.execute(
                """
                SELECT place, param_index, name, value_preview, semantic_type,
                       json_path_json, charset
                FROM parameters
                WHERE flow_id = ?
                """,
                (flow["id"],),
            ).fetchall()
        ]
        flow["resource_refs"] = [
            dict(item)
            for item in conn.execute(
                "SELECT name, value, source, semantic_type FROM resource_refs WHERE flow_id = ?",
                (flow["id"],),
            ).fetchall()
        ]
        return flow

    def hydrate_parameter_row(self, row):
        parameter = {
            "place": row["place"] or "",
            "name": row["name"] or "",
            "value_preview": row["value_preview"] or "",
            "value": row["value_preview"] or "",
            "semantic_type": row["semantic_type"] or "",
        }
        if row["param_index"] is not None:
            parameter["index"] = int(row["param_index"])
        if row["charset"]:
            parameter["charset"] = row["charset"]
        if row["json_path_json"]:
            try:
                parameter["json_path"] = json.loads(row["json_path_json"])
            except json.JSONDecodeError:
                pass
        return parameter

    def load_host_identity_flows(self, conn, host, limit=80):
        rows = conn.execute(
            """
            SELECT *
            FROM flows
            WHERE host = ?
              AND auth_fingerprint IS NOT NULL
              AND auth_fingerprint != 'anonymous'
            ORDER BY id DESC
            LIMIT ?
            """,
            (host, int(limit)),
        ).fetchall()
        identity_flows = []
        seen_auths = set()
        for row in rows:
            auth = row["auth_fingerprint"]
            if not auth or auth in seen_auths:
                continue
            seen_auths.add(auth)
            identity_flows.append(self.hydrate_flow_row(conn, row))
        return identity_flows

    def unique_flows(self, flows):
        unique = []
        seen = set()
        for flow in flows or []:
            flow_id = flow.get("id")
            if flow_id in seen:
                continue
            seen.add(flow_id)
            unique.append(flow)
        return unique

    def build_identity_memory(self, flows):
        identities = {}
        resources = {}
        for flow in flows or []:
            auth = flow.get("auth_fingerprint") or "anonymous"
            identity = identities.setdefault(
                auth,
                {
                    "auth_fingerprint": auth,
                    "auth_type": flow.get("auth_type") or "",
                    "flow_ids": [],
                    "status_codes": {},
                    "paths": [],
                    "resource_refs": [],
                },
            )
            identity["flow_ids"].append(flow.get("id"))
            status_key = str(flow.get("status_code") or "")
            identity["status_codes"][status_key] = identity["status_codes"].get(status_key, 0) + 1
            path = flow.get("normalized_path") or flow.get("path") or ""
            if path:
                identity["paths"].append(
                    {
                        "flow_id": flow.get("id"),
                        "method": flow.get("method") or "",
                        "path": path,
                        "status_code": flow.get("status_code"),
                    }
                )

            for ref in flow.get("resource_refs") or []:
                compact_ref = {
                    "flow_id": flow.get("id"),
                    "name": ref.get("name") or "",
                    "value": ref.get("value") or "",
                    "source": ref.get("source") or "",
                    "semantic_type": ref.get("semantic_type") or "",
                }
                identity["resource_refs"].append(compact_ref)
                resource_key = "|".join(
                    [
                        compact_ref["source"],
                        compact_ref["name"],
                        compact_ref["semantic_type"],
                        compact_ref["value"],
                    ]
                )
                resource = resources.setdefault(
                    resource_key,
                    {
                        "source": compact_ref["source"],
                        "name": compact_ref["name"],
                        "semantic_type": compact_ref["semantic_type"],
                        "value": compact_ref["value"],
                        "auth_fingerprints": [],
                        "flow_ids": [],
                    },
                )
                if auth not in resource["auth_fingerprints"]:
                    resource["auth_fingerprints"].append(auth)
                resource["flow_ids"].append(flow.get("id"))

        for identity in identities.values():
            identity["flow_ids"] = identity["flow_ids"][:20]
            identity["paths"] = identity["paths"][:20]
            identity["resource_refs"] = identity["resource_refs"][:20]
        return {
            "identity_count": len(identities),
            "identities": list(identities.values())[:12],
            "resources": list(resources.values())[:30],
        }

    def mark_candidate(self, candidate_key, status):
        with self.lock:
            with self.connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO analyzed_candidates(candidate_key, time, status) VALUES (?, ?, ?)",
                    (candidate_key, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), status),
                )

    def candidate_seen(self, candidate_key):
        with self.lock:
            with self.connect() as conn:
                row = conn.execute(
                    "SELECT candidate_key FROM analyzed_candidates WHERE candidate_key = ?",
                    (candidate_key,),
                ).fetchone()
                return bool(row)

    def load_finding(self, finding_key):
        with self.lock:
            with self.connect() as conn:
                row = conn.execute(
                    "SELECT finding_json FROM logic_findings WHERE finding_key = ?",
                    (finding_key,),
                ).fetchone()
                if not row:
                    return None
                try:
                    return json.loads(row["finding_json"] or "{}")
                except json.JSONDecodeError:
                    return None

    def save_finding(self, finding):
        with self.lock:
            with self.connect() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO logic_findings(finding_key, time, type, status, host, endpoint, finding_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.get("finding_key"),
                        finding.get("time"),
                        finding.get("type"),
                        finding.get("status"),
                        finding.get("host"),
                        finding.get("endpoint"),
                        json.dumps(finding, ensure_ascii=False),
                    ),
                )
