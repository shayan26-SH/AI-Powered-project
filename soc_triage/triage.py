from datetime import datetime
from hashlib import sha256

RULES = (
    ({"authentication_failure", "failed_login", "credential_stuffing"}, "Credential Abuse"),
    ({"port_scan", "network_scan", "reconnaissance"}, "Network Reconnaissance"),
    ({"lateral_movement", "remote_service_login"}, "Possible Lateral Movement"),
    ({"malware_alert", "ransomware_alert", "malware"}, "Malware Alert"),
)

KNOWLEDGE = (
    {
        "id": "attack-T1110",
        "title": "Brute Force — T1110",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "categories": {"Credential Abuse"},
        "summary": "MITRE ATT&CK describes techniques for repeatedly attempting authentication.",
    },
    {
        "id": "attack-T1046",
        "title": "Network Service Discovery — T1046",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "categories": {"Network Reconnaissance"},
        "summary": "MITRE ATT&CK describes discovery of services on a network.",
    },
    {
        "id": "attack-T1021",
        "title": "Remote Services — T1021",
        "url": "https://attack.mitre.org/techniques/T1021/",
        "categories": {"Possible Lateral Movement"},
        "summary": "MITRE ATT&CK describes use of remote services to access systems.",
    },
    {
        "id": "attack-T1486",
        "title": "Data Encrypted for Impact — T1486",
        "url": "https://attack.mitre.org/techniques/T1486/",
        "categories": {"Malware Alert"},
        "summary": "MITRE ATT&CK describes encrypting data to disrupt availability.",
    },
)


def classify(event_type: str) -> tuple[str, str | None]:
    normalized = event_type.strip().lower()
    for event_types, category in RULES:
        if normalized in event_types:
            return category, category
    return "Suspicious Activity", None


def retrieve_knowledge(category: str) -> list[dict]:
    return [
        {key: value for key, value in entry.items() if key != "categories"}
        for entry in KNOWLEDGE
        if category in entry["categories"]
    ]


def build_incidents(events: list[dict]) -> list[dict]:
    prepared = []
    for event in events:
        category, rule = classify(event["event_type"])
        prepared.append({**event, "_category": category, "_rule": rule})
    prepared.sort(key=lambda item: (item["source_ip"], item["_category"], item["timestamp"]))

    clusters: list[list[dict]] = []
    for event in prepared:
        if clusters:
            current = clusters[-1]
            first = current[0]
            gap = (
                datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                - datetime.fromisoformat(current[-1]["timestamp"].replace("Z", "+00:00"))
            ).total_seconds()
            if (
                event["source_ip"] == first["source_ip"]
                and event["_category"] == first["_category"]
                and event["asset_id"] == first["asset_id"]
                and 0 <= gap <= 15 * 60
            ):
                current.append(event)
                continue
        clusters.append([event])

    incidents = []
    for cluster in clusters:
        event_ids = sorted(event["event_id"] for event in cluster)
        incident_id = "inc-" + sha256("|".join(event_ids).encode("utf-8")).hexdigest()[:16]
        max_severity = max(event["severity"] for event in cluster)
        risk_score = min(100, max_severity * 8 + (len(cluster) - 1) * 5)
        category = cluster[0]["_category"]
        rules_matched = sorted({event["_rule"] for event in cluster if event["_rule"]})
        incidents.append(
            {
                "incident_id": incident_id,
                "category": category,
                "risk_score": risk_score,
                "risk_band": (
                    "Critical" if risk_score >= 85 else
                    "High" if risk_score >= 65 else
                    "Medium" if risk_score >= 40 else "Low"
                ),
                "rule_confidence": 0.85 if rules_matched else 0.55,
                "confidence_note": "Heuristic rule-match indicator; not a calibrated probability.",
                "rules_matched": rules_matched,
                "source_ip": cluster[0]["source_ip"],
                "asset_ids": sorted({event["asset_id"] for event in cluster}),
                "event_count": len(cluster),
                "first_seen": cluster[0]["timestamp"],
                "last_seen": cluster[-1]["timestamp"],
                "evidence_ids": [event["event_id"] for event in cluster],
                "events": [
                    {key: value for key, value in event.items() if not key.startswith("_")}
                    for event in cluster
                ],
                "knowledge": retrieve_knowledge(category),
            }
        )
    incidents.sort(key=lambda incident: (-incident["risk_score"], incident["first_seen"]))
    return incidents
