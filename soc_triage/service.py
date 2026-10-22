import ipaddress
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone

from .database import connect, json_details, row_dict
from .triage import build_incidents

ALLOWED_SOURCE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
EVENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
ASSET_IDS = {"lab-workstation-01", "lab-server-01"}
EVENT_TYPES = {
    "authentication_failure", "failed_login", "credential_stuffing",
    "port_scan", "network_scan", "reconnaissance",
    "lateral_movement", "remote_service_login",
    "malware_alert", "ransomware_alert", "malware",
    "suspicious_activity",
}


class ServiceError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_event(event: object) -> dict:
    required = {
        "event_id", "timestamp", "source_ip", "asset_id",
        "event_type", "severity", "description",
    }
    if not isinstance(event, dict) or set(event) != required:
        raise ServiceError(400, f"Each event must contain exactly: {', '.join(sorted(required))}.")
    if not isinstance(event["event_id"], str) or not EVENT_ID_RE.fullmatch(event["event_id"]):
        raise ServiceError(400, "event_id must be 1-100 safe ASCII letters, digits, dots, underscores, colons, or hyphens.")
    try:
        timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError
    except (AttributeError, TypeError, ValueError):
        raise ServiceError(400, "timestamp must be an ISO 8601 date-time with a timezone.")
    try:
        source_ip = ipaddress.ip_address(event["source_ip"])
    except (ValueError, TypeError):
        raise ServiceError(400, "source_ip must be a valid IPv4 address in an RFC 5737 documentation range.")
    if source_ip.version != 4 or not any(source_ip in network for network in ALLOWED_SOURCE_NETWORKS):
        raise ServiceError(400, "Only RFC 5737 documentation-range source IPs are accepted by this simulation.")
    if not isinstance(event["asset_id"], str) or event["asset_id"] not in ASSET_IDS:
        raise ServiceError(400, "asset_id must identify a configured lab-* simulated asset.")
    if not isinstance(event["event_type"], str) or event["event_type"] not in EVENT_TYPES:
        raise ServiceError(400, "event_type is not in the supported event-type list.")
    if type(event["severity"]) is not int or not 1 <= event["severity"] <= 10:
        raise ServiceError(400, "severity must be an integer from 1 to 10.")
    if not isinstance(event["description"], str) or not 1 <= len(event["description"]) <= 500:
        raise ServiceError(400, "description must contain 1 to 500 characters.")
    return {
        **event,
        "timestamp": timestamp.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "source_ip": str(source_ip),
    }


def ingest_events(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"events"} or not isinstance(payload["events"], list):
        raise ServiceError(400, "Request body must be an object with an events array.")
    if not 1 <= len(payload["events"]) <= 500:
        raise ServiceError(400, "Submit between 1 and 500 events.")
    events = [_validate_event(event) for event in payload["events"]]
    ids = [event["event_id"] for event in events]
    if len(ids) != len(set(ids)):
        raise ServiceError(409, "The request contains duplicate event_id values.")
    try:
        with connect() as db:
            db.executemany(
                """INSERT INTO events
                (event_id, timestamp, source_ip, asset_id, event_type, severity, description)
                VALUES (:event_id, :timestamp, :source_ip, :asset_id, :event_type, :severity, :description)""",
                events,
            )
    except sqlite3.IntegrityError as exc:
        if "UNIQUE constraint failed" in str(exc):
            raise ServiceError(409, "An event_id already exists; no events were ingested.")
        raise
    return {"ingested": len(events)}


def list_incidents() -> list[dict]:
    with connect() as db:
        events = [row_dict(row) for row in db.execute("SELECT * FROM events ORDER BY timestamp, event_id")]
        request_rows = db.execute(
            "SELECT request_id, incident_id, status, action, target FROM response_requests"
        ).fetchall()
    incidents = build_incidents(events)
    states: dict[str, list[dict]] = {}
    for row in request_rows:
        states.setdefault(row["incident_id"], []).append(
            {
                "request_id": row["request_id"],
                "status": row["status"],
                "action": row["action"],
                "target": row["target"],
            }
        )
    for incident in incidents:
        incident["response_requests"] = states.get(incident["incident_id"], [])
    return incidents


def get_incident(incident_id: str) -> dict:
    for incident in list_incidents():
        if incident["incident_id"] == incident_id:
            return incident
    raise ServiceError(404, "Incident not found.")


def list_assets() -> list[dict]:
    with connect() as db:
        return [row_dict(row) for row in db.execute(
            "SELECT asset_id, display_name, isolated FROM simulated_assets ORDER BY asset_id"
        )]


def create_response_request(incident_id: str, payload: object) -> dict:
    incident = get_incident(incident_id)
    if not isinstance(payload, dict) or set(payload) != {"action"}:
        raise ServiceError(400, 'Request body must be {"action":"isolate_host"} or {"action":"block_source"}.')
    action = payload["action"]
    if not isinstance(action, str) or action not in {"isolate_host", "block_source"}:
        raise ServiceError(400, "Only isolate_host and block_source simulations are supported.")
    target = incident["asset_ids"][0] if action == "isolate_host" else incident["source_ip"]
    if action == "isolate_host" and target not in ASSET_IDS:
        raise ServiceError(400, "The target is not a configured simulated asset.")
    request_id = "req-" + uuid.uuid4().hex[:12]
    created_at = utc_now()
    with connect() as db:
        db.execute(
            """INSERT INTO response_requests
            (request_id, incident_id, action, target, status, created_at)
            VALUES (?, ?, ?, ?, 'pending', ?)""",
            (request_id, incident_id, action, target, created_at),
        )
        db.execute(
            "INSERT INTO audit_log(occurred_at, event, request_id, incident_id, details) VALUES (?, ?, ?, ?, ?)",
            (created_at, "response_requested", request_id, incident_id, json_details({"action": action, "target": target})),
        )
    return {
        "request_id": request_id,
        "incident_id": incident_id,
        "action": action,
        "target": target,
        "status": "pending",
        "message": "Simulation requested. No action is applied until an analyst approves it.",
    }


def approve_response(request_id: str) -> dict:
    with connect() as db:
        request = db.execute(
            "SELECT * FROM response_requests WHERE request_id = ?", (request_id,)
        ).fetchone()
        if request is None:
            raise ServiceError(404, "Response request not found.")
        if request["status"] != "pending":
            raise ServiceError(409, f"Response request is already {request['status']}.")
        if request["action"] == "isolate_host":
            asset = db.execute(
                "SELECT asset_id FROM simulated_assets WHERE asset_id = ?", (request["target"],)
            ).fetchone()
            if asset is None:
                raise ServiceError(400, "Response target is not a configured simulated asset.")
            db.execute(
                "UPDATE simulated_assets SET isolated = 1 WHERE asset_id = ?", (request["target"],)
            )
        elif request["action"] == "block_source":
            try:
                address = ipaddress.ip_address(request["target"])
            except ValueError:
                raise ServiceError(400, "Stored response target is not a valid IP address.")
            if address.version != 4 or not any(address in network for network in ALLOWED_SOURCE_NETWORKS):
                raise ServiceError(400, "Stored response target is outside simulation-only documentation ranges.")
            db.execute(
                "INSERT OR IGNORE INTO blocked_sources(source_ip, request_id) VALUES (?, ?)",
                (request["target"], request_id),
            )
        else:
            raise ServiceError(400, "Unsupported stored response action.")

        approved_at = utc_now()
        db.execute(
            "UPDATE response_requests SET status = 'approved', approved_at = ? WHERE request_id = ?",
            (approved_at, request_id),
        )
        details = {"action": request["action"], "target": request["target"], "mode": "simulation"}
        db.execute(
            "INSERT INTO audit_log(occurred_at, event, request_id, incident_id, details) VALUES (?, ?, ?, ?, ?)",
            (approved_at, "simulation_applied", request_id, request["incident_id"], json_details(details)),
        )
    return {
        "request_id": request_id,
        "incident_id": request["incident_id"],
        "action": request["action"],
        "target": request["target"],
        "status": "approved",
        "mode": "simulation",
        "approved_at": approved_at,
        "message": "Simulation applied to local mock state only. No system or network controls were changed.",
    }


def list_audit() -> list[dict]:
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM audit_log ORDER BY audit_id DESC LIMIT 100"
        ).fetchall()
    result = []
    for row in rows:
        entry = row_dict(row)
        entry["details"] = json.loads(entry["details"])
        result.append(entry)
    return result
