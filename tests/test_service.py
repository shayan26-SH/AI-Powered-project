import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from soc_triage import database, service
from soc_triage.triage import build_incidents


class TriageTests(unittest.TestCase):
    def test_correlates_same_rule_within_window_and_keeps_evidence(self):
        events = [
            {
                "event_id": "a", "timestamp": "2026-10-21T12:00:00Z",
                "source_ip": "198.51.100.1", "asset_id": "lab-workstation-01",
                "event_type": "authentication_failure", "severity": 6, "description": "first",
            },
            {
                "event_id": "b", "timestamp": "2026-10-21T12:10:00Z",
                "source_ip": "198.51.100.1", "asset_id": "lab-workstation-01",
                "event_type": "authentication_failure", "severity": 8, "description": "second",
            },
            {
                "event_id": "c", "timestamp": "2026-10-21T12:30:00Z",
                "source_ip": "198.51.100.1", "asset_id": "lab-workstation-01",
                "event_type": "authentication_failure", "severity": 8, "description": "later",
            },
        ]
        incidents = build_incidents(events)
        self.assertEqual([2, 1], [item["event_count"] for item in incidents])
        self.assertEqual(["a", "b"], incidents[0]["evidence_ids"])
        self.assertEqual(69, incidents[0]["risk_score"])
        self.assertTrue(incidents[0]["knowledge"])


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(database, "DB_PATH", Path(self.temp.name) / "test.db")
        self.db_patch.start()
        database.initialize()

    def tearDown(self):
        self.db_patch.stop()
        self.temp.cleanup()

    def sample_event(self, **overrides):
        event = {
            "event_id": "test-auth-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "198.51.100.12",
            "asset_id": "lab-workstation-01",
            "event_type": "authentication_failure",
            "severity": 7,
            "description": "Synthetic failed authentication",
        }
        event.update(overrides)
        return event

    def test_ingest_rejects_non_documentation_ip(self):
        with self.assertRaises(service.ServiceError) as error:
            service.ingest_events({"events": [self.sample_event(source_ip="8.8.8.8")]})
        self.assertEqual(400, error.exception.status)

    def test_ingest_rejects_wrong_json_field_types_cleanly(self):
        for overrides in ({"asset_id": []}, {"event_type": {"invalid": True}}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(service.ServiceError) as error:
                    service.ingest_events({"events": [self.sample_event(**overrides)]})
                self.assertEqual(400, error.exception.status)

    def test_duplicate_ids_rejected_without_partial_ingest(self):
        event = self.sample_event()
        with self.assertRaises(service.ServiceError):
            service.ingest_events({"events": [event, event]})
        with database.connect() as db:
            self.assertEqual(5, db.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            self.assertIsNone(db.execute(
                "SELECT event_id FROM events WHERE event_id = ?", (event["event_id"],)
            ).fetchone())

    def test_requires_request_then_approval_to_change_mock_state(self):
        service.ingest_events({"events": [self.sample_event()]})
        incident = next(
            item for item in service.list_incidents() if "test-auth-001" in item["evidence_ids"]
        )
        request = service.create_response_request(
            incident["incident_id"], {"action": "isolate_host"}
        )
        self.assertEqual("pending", request["status"])
        self.assertEqual(
            0,
            next(asset for asset in service.list_assets() if asset["asset_id"] == "lab-workstation-01")["isolated"],
        )

        result = service.approve_response(request["request_id"])
        self.assertEqual("simulation", result["mode"])
        self.assertEqual(
            1,
            next(asset for asset in service.list_assets() if asset["asset_id"] == "lab-workstation-01")["isolated"],
        )
        self.assertEqual("simulation_applied", service.list_audit()[0]["event"])

    def test_cannot_approve_same_request_twice(self):
        service.ingest_events({"events": [self.sample_event()]})
        incident = next(
            item for item in service.list_incidents() if "test-auth-001" in item["evidence_ids"]
        )
        request = service.create_response_request(
            incident["incident_id"], {"action": "block_source"}
        )
        service.approve_response(request["request_id"])
        with self.assertRaises(service.ServiceError) as error:
            service.approve_response(request["request_id"])
        self.assertEqual(409, error.exception.status)

    def test_rejects_non_string_response_action(self):
        service.ingest_events({"events": [self.sample_event()]})
        incident = next(
            item for item in service.list_incidents() if "test-auth-001" in item["evidence_ids"]
        )
        with self.assertRaises(service.ServiceError) as error:
            service.create_response_request(incident["incident_id"], {"action": []})
        self.assertEqual(400, error.exception.status)


if __name__ == "__main__":
    unittest.main()
