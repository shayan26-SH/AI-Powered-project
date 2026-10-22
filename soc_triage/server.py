import json
import mimetypes
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit

from .database import initialize
from .service import (
    ServiceError,
    approve_response,
    create_response_request,
    get_incident,
    ingest_events,
    list_assets,
    list_audit,
    list_incidents,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"


class SocTriageHandler(BaseHTTPRequestHandler):
    server_version = "SocTriageMVP/0.1"

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            return self._static("index.html")
        if path in {"/app.js", "/styles.css"}:
            return self._static(path.lstrip("/"))
        if path == "/api/health":
            return self._json(200, {"status": "ok", "mode": "simulation_only"})
        if path == "/api/incidents":
            return self._json(200, {"incidents": list_incidents()})
        if path == "/api/assets":
            return self._json(200, {"assets": list_assets()})
        if path == "/api/audit":
            return self._json(200, {"audit": list_audit()})
        if path.startswith("/api/incidents/"):
            incident_id = path.removeprefix("/api/incidents/")
            return self._json(200, get_incident(incident_id))
        return self._json(404, {"error": "Route not found."})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        try:
            payload = self._read_json()
            if path == "/api/events":
                return self._json(201, ingest_events(payload))
            if path.startswith("/api/incidents/") and path.endswith("/response-requests"):
                incident_id = path.removeprefix("/api/incidents/").removesuffix("/response-requests")
                return self._json(201, create_response_request(incident_id, payload))
            if path.startswith("/api/response-requests/") and path.endswith("/approve"):
                request_id = path.removeprefix("/api/response-requests/").removesuffix("/approve")
                if payload != {}:
                    raise ServiceError(400, "Approval request body must be an empty JSON object.")
                return self._json(200, approve_response(request_id))
            return self._json(404, {"error": "Route not found."})
        except ServiceError as exc:
            return self._json(exc.status, {"error": exc.message})
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._json(400, {"error": "Request body must be valid UTF-8 JSON."})
        except ValueError as exc:
            return self._json(400, {"error": str(exc)})

    def _read_json(self):
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            raise ServiceError(411, "Content-Length is required.")
        try:
            length = int(content_length)
        except ValueError:
            raise ServiceError(400, "Invalid Content-Length.")
        if length < 0 or length > 1_000_000:
            raise ServiceError(413, "Request body must be no larger than 1 MB.")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _json(self, status: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _static(self, filename: str) -> None:
        path = (STATIC_DIR / filename).resolve()
        if path.parent != STATIC_DIR.resolve() or not path.is_file():
            return self._json(404, {"error": "File not found."})
        body = path.read_bytes()
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        print(f"[http] {self.address_string()} {format % args}")


initialize()
