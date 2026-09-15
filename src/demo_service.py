"""Local, clearly labelled demonstration data for the AEGISFLOW prototype.

This service is intentionally separate from the core detection and response
engines. It gives the hackathon UI a repeatable, local scenario without
claiming that the illustrative values are production model results.
"""

import json
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


DEMO_LABEL = "SIMULATED PROTOTYPE DATA"

SIMULATION_STAGES = [
    "NORMAL",
    "TRAFFIC ANOMALY",
    "MODEL 1 ANALYSIS",
    "MODEL 2 BEHAVIOR ANALYSIS",
    "THREAT FUSION",
    "HIGH RISK ALERT",
    "USER AUTHORIZATION",
    "DEFENSE",
    "VERIFICATION",
    "RESOLVED",
]
ATTACK_REQUESTS = [900, 1100, 1500, 2500, 4000, 6000, 7500, 9000]
ATTACK_OUTBOUND = [80, 100, 150, 260, 480, 700, 950, 1200]
ATTACK_DESTINATIONS = [18, 22, 35, 60, 120, 220, 330, 430]
ATTACK_FAILED = [12, 18, 27, 55, 130, 280, 700, 1200]
DEFENSE_REQUESTS = [9000, 7600, 5800, 4100, 2500, 1500, 700, 400, 200, 100, 50, 21]
DEFENSE_OUTBOUND = [1200, 980, 760, 540, 320, 210, 120, 80, 48, 30, 18, 10]
DEFENSE_DESTINATIONS = [430, 360, 290, 220, 150, 100, 60, 40, 25, 20, 18, 14]
DEFENSE_FAILED = [1200, 980, 760, 550, 320, 180, 95, 60, 35, 22, 14, 8]
BEHAVIOR_RAMP = [10, 18, 27, 41, 58, 72, 85, 94]
VERIFICATION_BEHAVIOR = [94, 81, 67, 51, 38, 24, 12, 5, 5, 5, 5, 5]


class DemoService:
    """Seeded local demo store and deterministic demonstration workflow."""

    def __init__(self, db_path: Optional[str] = None):
        root = Path(__file__).resolve().parent.parent
        self.db_path = Path(db_path or root / "data" / "demo.sqlite3")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.db_path), timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, separators=(",", ":"), default=str)

    @staticmethod
    def _decode(value: Optional[str], fallback: Any = None) -> Any:
        if not value:
            return fallback
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return fallback

    @staticmethod
    def _now() -> datetime:
        return datetime.utcnow().replace(microsecond=0)

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.isoformat() + "Z"

    def _initialize(self) -> None:
        with self._lock, self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS entities (
                    entity_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    baseline_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    is_demo INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS traffic_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    requests_per_minute REAL NOT NULL,
                    outbound_mb_per_minute REAL NOT NULL,
                    unique_destinations INTEGER NOT NULL,
                    failed_connections_per_minute REAL NOT NULL,
                    protocol TEXT NOT NULL,
                    status TEXT NOT NULL,
                    is_baseline INTEGER NOT NULL DEFAULT 0,
                    is_demo INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    attack_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    status TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    known_similarity REAL NOT NULL,
                    behavioral_deviation REAL NOT NULL,
                    assessment TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    is_demo INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS model_outputs (
                    output_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    output_json TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
                );
                CREATE TABLE IF NOT EXISTS risk_assessments (
                    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    explanation TEXT NOT NULL,
                    assessed_at TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
                );
                CREATE TABLE IF NOT EXISTS explanations (
                    explanation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    factor TEXT NOT NULL,
                    contribution REAL NOT NULL,
                    explanation TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
                );
                CREATE TABLE IF NOT EXISTS recommendations (
                    recommendation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    reversible INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
                );
                CREATE TABLE IF NOT EXISTS authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    decision TEXT,
                    countdown_seconds INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
                );
                CREATE TABLE IF NOT EXISTS defense_actions (
                    defense_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
                );
                CREATE TABLE IF NOT EXISTS verification_results (
                    verification_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    before_value REAL NOT NULL,
                    after_value REAL NOT NULL,
                    reduction_percent REAL NOT NULL,
                    label TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    result TEXT NOT NULL,
                    details TEXT NOT NULL,
                    is_demo INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS timeline_events (
                    timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    attack_stage TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    event TEXT NOT NULL,
                    status TEXT NOT NULL,
                    incident_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS demo_state (
                    state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                    mode TEXT NOT NULL,
                    step INTEGER NOT NULL,
                    started_at TEXT,
                    updated_at TEXT NOT NULL
                );
                """
            )
            if db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0:
                self._seed(db)
            if db.execute("SELECT COUNT(*) FROM demo_state").fetchone()[0] == 0:
                db.execute(
                    "INSERT INTO demo_state VALUES (1, 'idle', 0, NULL, ?)",
                    (self._iso(self._now()),),
                )

    def _seed(self, db: sqlite3.Connection) -> None:
        now = self._now()
        baseline = {
            "requests_per_minute": "800-1200",
            "outbound_mb_per_minute": "50-100",
            "unique_destinations": "10-25",
            "failed_connections_per_minute": "5-20",
            "time_of_day": "business-hours profile",
            "protocol_behavior": "HTTP/HTTPS and approved internal services",
            "application_behavior": "normal service-to-service requests",
        }
        entities = [
            "Server-01", "Server-02", "Server-03", "Server-04", "Server-05", "Server-06",
            "Server-07", "Server-08", "Web-Server-02", "API-Gateway-01", "Employee-PC-07", "Employee-PC-12",
        ]
        for entity_id in entities:
            db.execute(
                "INSERT INTO entities VALUES (?, ?, ?, 'MONITORED', 1)",
                (entity_id, entity_id, self._json(baseline)),
            )

        incidents = [
            ("INC-001", "DDoS", "Server-03", "CRITICAL", 97, "RESOLVED", .96, 96, 86, "Known high-volume denial-of-service pattern", "ISOLATE ENDPOINT"),
            ("INC-002", "Port Scan / Reconnaissance", "Server-07", "HIGH", 82, "RESOLVED", .91, 91, 62, "Known reconnaissance pattern with moderate behavior deviation", "RATE LIMIT"),
            ("INC-003", "Botnet", "Employee-PC-12", "HIGH", 88, "CONTAINED", .88, 88, 84, "Known botnet resemblance reinforced by beaconing behavior", "PAUSE SUSPICIOUS PROCESS"),
            ("INC-004", "Credential Attack", "Employee-PC-07", "HIGH", 86, "INVESTIGATING", .82, 82, 81, "Repeated authentication failures and unusual login timing", "PAUSE SUSPICIOUS PROCESS"),
            ("INC-005", "Exploitation", "Web-Server-02", "CRITICAL", 95, "CONTAINED", .94, 94, 90, "Known exploitation signature with high behavioral deviation", "ISOLATE ENDPOINT"),
            ("INC-006", "Normal Traffic", "Server-01", "LOW", 8, "CLOSED", .97, 3, 8, "Traffic matches the trusted behavioral baseline", "CONTINUE MONITORING"),
            ("INC-007", "Previously Unseen Behavioral Activity", "Server-07", "HIGH", 88, "ACTIVE", .89, 12, 94, "Known-pattern resemblance is low while behavioral deviation is high; suspicious activity is not a confirmed zero-day", "PAUSE SUSPICIOUS PROCESS"),
            ("INC-008", "Reconnaissance", "Server-05", "MEDIUM", 64, "RESOLVED", .79, 68, 45, "Destination sweep resembles reconnaissance activity", "RATE LIMIT"),
            ("INC-009", "DDoS", "API-Gateway-01", "CRITICAL", 98, "CONTAINED", .97, 96, 92, "Known denial-of-service pattern detected at the edge", "ISOLATE ENDPOINT"),
            ("INC-010", "Suspicious Outbound Traffic", "Employee-PC-07", "HIGH", 79, "INVESTIGATING", .76, 28, 78, "Outbound traffic and destination diversity exceed the entity baseline", "RATE LIMIT"),
        ]
        for index, incident in enumerate(incidents):
            incident_id, attack_type, entity_id, risk_level, risk_score, status, confidence, known, behavior, assessment, action = incident
            created = self._iso(now - timedelta(hours=7 - min(index, 6), minutes=index * 4))
            db.execute(
                "INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                (incident_id, attack_type, entity_id, risk_level, risk_score, status, confidence, known, behavior, assessment, action, created, created),
            )
            known_scores = {
                "ddos_similarity": known if attack_type == "DDoS" else max(3, known - 30),
                "port_scan_similarity": known if "Recon" in attack_type or "Scan" in attack_type else max(3, known - 25),
                "botnet_similarity": known if attack_type == "Botnet" else max(3, known - 35),
                "credential_similarity": known if "Credential" in attack_type else max(3, known - 42),
                "exploitation_similarity": known if attack_type == "Exploitation" else max(3, known - 45),
                "normal_similarity": 3 if risk_level != "LOW" else 96,
            }
            db.execute("INSERT INTO model_outputs (incident_id, model_name, output_json, evaluated_at) VALUES (?, 'known_pattern', ?, ?)", (incident_id, self._json({"classification": attack_type, "similarity": known, "scores": known_scores, "is_demo": True}), created))
            db.execute("INSERT INTO model_outputs (incident_id, model_name, output_json, evaluated_at) VALUES (?, 'behavioral_anomaly', ?, ?)", (incident_id, self._json({"anomaly_score": behavior, "severity": risk_level, "assessment": assessment, "is_demo": True}), created))
            db.execute("INSERT INTO risk_assessments (incident_id, risk_level, risk_score, explanation, assessed_at) VALUES (?, ?, ?, ?, ?)", (incident_id, risk_level, risk_score, assessment, created))
            factors = [("Traffic volume deviation", 32), ("Destination diversity", 27), ("Connection frequency", 18), ("Time-of-day deviation", 10), ("Protocol deviation", 7)]
            if incident_id != "INC-007":
                factors = [(name, round(value * max(0.25, behavior / 94), 1)) for name, value in factors]
            for factor, contribution in factors:
                db.execute("INSERT INTO explanations (incident_id, factor, contribution, explanation) VALUES (?, ?, ?, ?)", (incident_id, factor, contribution, "Illustrative demonstration contribution; not a trained production weight."))
            db.execute("INSERT INTO recommendations (incident_id, action, rationale, reversible) VALUES (?, ?, ?, 1)", (incident_id, action, assessment))
            if incident_id == "INC-007":
                db.execute("INSERT INTO authorizations VALUES ('AUTH-007', 'INC-007', 'PENDING', NULL, 30, ?, ?)", (created, created))
                db.execute("INSERT INTO defense_actions VALUES ('DEF-007', 'INC-007', 'PAUSE SUSPICIOUS PROCESS', 'PENDING', NULL, NULL)")

        for offset, values in enumerate([(900, 72, 17, 12), (1040, 84, 20, 15), (820, 61, 12, 8), (1160, 93, 24, 19), (980, 78, 16, 11), (9000, 1200, 430, 1200)]):
            requests, outbound, destinations, failed = values
            timestamp = self._iso(now - timedelta(minutes=30 - offset * 5))
            db.execute("INSERT INTO traffic_events (entity_id, timestamp, requests_per_minute, outbound_mb_per_minute, unique_destinations, failed_connections_per_minute, protocol, status, is_baseline) VALUES ('Server-07', ?, ?, ?, ?, ?, 'HTTP/HTTPS', ?, ?)", (timestamp, requests, outbound, destinations, failed, 'SUSPICIOUS' if requests > 3000 else 'NORMAL', 0 if requests > 3000 else 1))

        stages = [
            ("Reconnaissance", "MEDIUM", "External probing observed", "RESOLVED"),
            ("Port Scanning", "MEDIUM", "Destination sweep identified", "RESOLVED"),
            ("Credential Attack", "HIGH", "Repeated authentication failures", "RESOLVED"),
            ("Suspicious Login", "HIGH", "Login outside the behavioral baseline", "RESOLVED"),
            ("Lateral Movement", "HIGH", "New internal service relationship", "RESOLVED"),
            ("Unusual Data Transfer", "HIGH", "Outbound volume exceeded baseline", "RESOLVED"),
            ("Detection", "HIGH", "Model 2 flagged previously unseen behavior", "ACTIVE"),
            ("Response", "HIGH", "Human-authorized pause recommended", "PENDING"),
            ("Verification", "HIGH", "Illustrative verification awaits defense", "PENDING"),
        ]
        for index, (stage, risk, event, status) in enumerate(stages):
            db.execute("INSERT INTO timeline_events (timestamp, entity_id, attack_stage, risk_level, event, status, incident_id) VALUES (?, 'Server-07', ?, ?, ?, ?, 'INC-007')", (self._iso(now - timedelta(minutes=18 - index * 2)), stage, risk, event, status))

        audit = [
            ("Traffic received", "SYSTEM", "RECORDED", "Server-07 telemetry entered local processing"),
            ("Model 1 evaluated", "MODEL-1", "LOW KNOWN-PATTERN SIMILARITY", "Known-pattern classifier returned low resemblance"),
            ("Model 2 evaluated", "MODEL-2", "HIGH DEVIATION", "Behavioral anomaly score returned 94/100"),
            ("Threat fusion completed", "SYSTEM", "VERY SUSPICIOUS", "Low known-pattern similarity plus high behavior deviation"),
            ("Risk assessed", "RISK-ENGINE", "HIGH", "Risk score 88; demonstration assessment"),
            ("Recommendation generated", "POLICY", "PAUSE", "Pause suspicious process; human authorization required"),
            ("Authorization requested", "SYSTEM", "PENDING", "30 second decision window"),
            ("User decision / timeout", "HUMAN", "AWAITING DECISION", "STOP and CONTINUE remain available"),
            ("Defense executed", "RESPONSE-ENGINE", "PENDING", "Will update after user action"),
            ("Verification completed", "VERIFICATION", "ILLUSTRATIVE", "Example before/after result is clearly labelled"),
        ]
        for index, (action, actor, result, details) in enumerate(audit):
            db.execute("INSERT INTO audit_events (timestamp, action, entity_id, actor, result, details) VALUES (?, ?, 'Server-07', ?, ?, ?)", (self._iso(now - timedelta(minutes=16 - index)), action, actor, result, details))

    def _tick(self, db: sqlite3.Connection) -> None:
        state = db.execute("SELECT * FROM demo_state WHERE state_id = 1").fetchone()
        if not state or state["mode"] not in ("running", "defending", "verifying"):
            return
        updated = datetime.fromisoformat(state["updated_at"].replace("Z", ""))
        now_dt = self._now()
        if state["mode"] == "running" and state["step"] >= 7:
            authorization = db.execute("SELECT * FROM authorizations WHERE incident_id = 'INC-007' LIMIT 1").fetchone()
            if authorization and authorization["status"] == "PENDING":
                authorization_updated = datetime.fromisoformat(authorization["updated_at"].replace("Z", ""))
                if (now_dt - authorization_updated).total_seconds() >= authorization["countdown_seconds"]:
                    self._timeout_locked(db, "INC-007")
            return
        if (now_dt - updated).total_seconds() < 2:
            return
        step = state["step"] + 1
        now = self._iso(now_dt)
        mode = state["mode"]
        if mode == "running":
            db.execute("UPDATE demo_state SET step = ?, updated_at = ? WHERE state_id = 1", (min(step, 7), now))
            if step == 7:
                db.execute("UPDATE authorizations SET status = 'PENDING', updated_at = ? WHERE incident_id = 'INC-007'", (now,))
            self._record_stage_audit(db, step, "SYSTEM", "running")
        else:
            next_mode = "verifying" if step >= 11 else mode
            if step >= 18:
                next_mode = "resolved"
                step = 18
            db.execute("UPDATE demo_state SET mode = ?, step = ?, updated_at = ? WHERE state_id = 1", (next_mode, step, now))
            self._record_stage_audit(db, step, "RESPONSE-ENGINE" if next_mode != "verifying" else "VERIFICATION", next_mode)
            if next_mode == "resolved":
                self._finish_verification_locked(db, "INC-007")

    def _record_stage_audit(self, db: sqlite3.Connection, step: int, actor: str, mode: str = "running") -> None:
        stage = self._simulation_snapshot(db, {"mode": mode, "step": step})["stage"]
        details = {
            "NORMAL": "Server-07 is within its trusted behavioral baseline",
            "TRAFFIC ANOMALY": "Requests, outbound traffic, destinations and failed connections are rising",
            "MODEL 1 ANALYSIS": "Known-pattern classifier is analyzing the activity",
            "MODEL 2 BEHAVIOR ANALYSIS": "Behavioral baseline comparison is evaluating deviation",
            "THREAT FUSION": "Low known-pattern resemblance combined with high behavioral deviation",
            "HIGH RISK ALERT": "Risk fusion classified the activity as high risk",
            "USER AUTHORIZATION": "Human decision required before defense execution",
            "DEFENSE": "Authorized response is reducing suspicious traffic",
            "VERIFICATION": "Post-defense verification is measuring recovery toward baseline",
            "RESOLVED": "Defense verified and incident resolved; monitoring continues",
        }[stage]
        self._add_audit(db, f"Simulation stage: {stage}", actor, stage, details)

    def _simulation_snapshot(self, db: sqlite3.Connection, state: Dict[str, Any]) -> Dict[str, Any]:
        mode = state.get("mode", "idle")
        step = int(state.get("step", 0) or 0)
        if mode == "idle":
            stage_index = 0
        elif mode in ("defending",):
            stage_index = 7
        elif mode == "verifying":
            stage_index = 8
        elif mode == "resolved":
            stage_index = 9
        elif mode == "stopped":
            stage_index = 6
        else:
            stage_index = min(step, 5) if mode == "running" and step == 6 else min(step, 6)

        if mode in ("defending", "verifying", "resolved"):
            defense_index = max(0, min(step - 7, len(DEFENSE_REQUESTS) - 1))
            requests = DEFENSE_REQUESTS[defense_index]
            outbound = DEFENSE_OUTBOUND[defense_index]
            destinations = DEFENSE_DESTINATIONS[defense_index]
            failed = DEFENSE_FAILED[defense_index]
            behavior_deviation = VERIFICATION_BEHAVIOR[defense_index]
            traffic_status = "NORMAL" if requests <= 100 else "CONTAINING"
        else:
            attack_index = max(0, min(step, len(ATTACK_REQUESTS) - 1))
            requests = ATTACK_REQUESTS[attack_index]
            outbound = ATTACK_OUTBOUND[attack_index]
            destinations = ATTACK_DESTINATIONS[attack_index]
            failed = ATTACK_FAILED[attack_index]
            behavior_deviation = BEHAVIOR_RAMP[attack_index]
            traffic_status = "SUSPICIOUS" if step >= 5 else "ELEVATED" if step >= 1 else "NORMAL"

        if mode == "idle":
            behavior_deviation = 10
            traffic_status = "NORMAL"

        model_1_similarity = 2 if step == 0 else 6 if step == 1 else 12
        model_1_status = "ANALYZING..." if step < 4 else "LOW known-pattern resemblance"
        model_2_status = "BEHAVIOR DEVIATION DETECTED" if behavior_deviation >= 85 else "BUILDING BEHAVIOR BASELINE"
        if mode in ("verifying", "resolved"):
            model_2_status = "RETURNING TOWARD BASELINE" if behavior_deviation > 5 else "HIGH behavioral deviation resolved"
        risk_score = min(88, 12 + max(0, behavior_deviation - 10))
        risk_level = "HIGH" if step >= 4 or mode in ("defending", "verifying", "resolved") else "LOW"
        assessment = "Low known-pattern resemblance plus high behavioral deviation; suspicious activity is not a confirmed zero-day" if step >= 4 else "Signals are still being evaluated against the trusted baseline"
        return {
            "stage_index": stage_index,
            "stage": SIMULATION_STAGES[stage_index],
            "stage_count": len(SIMULATION_STAGES),
            "traffic": {"requests_per_min": requests, "outbound_mb_per_min": outbound, "unique_destinations": destinations, "failed_connections": failed, "status": traffic_status},
            "model_1": {"similarity": model_1_similarity, "status": model_1_status, "classification": "LOW known-pattern resemblance" if step >= 4 else "ANALYZING..."},
            "model_2": {"deviation": behavior_deviation, "status": model_2_status, "severity": "HIGH" if behavior_deviation >= 85 else "LOW"},
            "fusion": {"risk_score": risk_score, "risk_level": risk_level, "assessment": assessment, "why": "Model 1 found only 12% resemblance to known attack patterns while Model 2 detected a 94/100 behavioral deviation from Server-07's baseline."},
        }

    def _finish_verification_locked(self, db: sqlite3.Connection, incident_id: str) -> None:
        now = self._iso(self._now())
        db.execute("UPDATE defense_actions SET status = 'COMPLETED', completed_at = COALESCE(completed_at, ?) WHERE incident_id = ?", (now, incident_id))
        db.execute("UPDATE incidents SET status = 'RESOLVED', updated_at = ? WHERE incident_id = ?", (now, incident_id))
        db.execute("INSERT OR REPLACE INTO verification_results VALUES (?, ?, 'THREAT_REDUCED', 1842, 21, 98.8, 'Illustrative verification example', ?)", (f"VERIFY-{incident_id}", incident_id, now))
        self._add_audit(db, "Verification completed", "VERIFICATION", "THREAT REDUCED", "Suspicious activity reduced; behavioral deviation returned toward baseline; defense verified")
        self._add_audit(db, "Incident resolved", "SYSTEM", "RESOLVED", "Monitoring continues after the response was verified")

    def _add_audit(self, db: sqlite3.Connection, action: str, actor: str, result: str, details: str, entity: str = "Server-07") -> None:
        db.execute("INSERT INTO audit_events (timestamp, action, entity_id, actor, result, details) VALUES (?, ?, ?, ?, ?, ?)", (self._iso(self._now()), action, entity, actor, result, details))

    def _sync_timeline(self, db: sqlite3.Connection, state: Dict[str, Any]) -> None:
        mode = state.get("mode")
        step = int(state.get("step", 0) or 0)
        active_index = 0 if mode == "idle" else min(step, 6) if mode in ("running", "stopped") else 7 if mode == "defending" else 8
        if mode == "resolved":
            active_index = 8
        rows = db.execute("SELECT timeline_id FROM timeline_events WHERE incident_id = 'INC-007' ORDER BY timestamp").fetchall()
        for index, row in enumerate(rows):
            status = "RESOLVED" if index < active_index else "ACTIVE" if index == active_index else "PENDING"
            db.execute("UPDATE timeline_events SET status = ? WHERE timeline_id = ?", (status, row["timeline_id"]))

    def _state(self, db: sqlite3.Connection) -> Dict[str, Any]:
        self._tick(db)
        row = db.execute("SELECT * FROM demo_state WHERE state_id = 1").fetchone()
        return dict(row) if row else {"mode": "idle", "step": 0}

    def _incident_row(self, db: sqlite3.Connection, incident_id: str) -> Optional[sqlite3.Row]:
        return db.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()

    def _incident_payload(self, db: sqlite3.Connection, row: sqlite3.Row) -> Dict[str, Any]:
        incident = dict(row)
        incident["is_demo"] = True
        incident["demo_label"] = DEMO_LABEL
        incident["confidence_percent"] = round(incident["confidence"] * 100, 1)
        incident["known_pattern_similarity"] = incident.pop("known_similarity")
        incident["behavioral_deviation"] = incident["behavioral_deviation"]
        incident["known_pattern"] = self._decode(db.execute("SELECT output_json FROM model_outputs WHERE incident_id = ? AND model_name = 'known_pattern' ORDER BY output_id DESC LIMIT 1", (row["incident_id"],)).fetchone()[0], {})
        incident["behavior_model"] = self._decode(db.execute("SELECT output_json FROM model_outputs WHERE incident_id = ? AND model_name = 'behavioral_anomaly' ORDER BY output_id DESC LIMIT 1", (row["incident_id"],)).fetchone()[0], {})
        incident["risk"] = {"risk_level": row["risk_level"], "risk_score": row["risk_score"], "assessment": row["assessment"]}
        incident["explanation"] = [dict(item) for item in db.execute("SELECT factor, contribution, explanation FROM explanations WHERE incident_id = ? ORDER BY explanation_id", (row["incident_id"],)).fetchall()]
        recommendation = db.execute("SELECT action, rationale, reversible FROM recommendations WHERE incident_id = ? LIMIT 1", (row["incident_id"],)).fetchone()
        incident["recommendation"] = dict(recommendation) if recommendation else None
        authorization = db.execute("SELECT * FROM authorizations WHERE incident_id = ? LIMIT 1", (row["incident_id"],)).fetchone()
        incident["authorization"] = dict(authorization) if authorization else None
        defense = db.execute("SELECT * FROM defense_actions WHERE incident_id = ? LIMIT 1", (row["incident_id"],)).fetchone()
        incident["defense"] = dict(defense) if defense else None
        verification = db.execute("SELECT * FROM verification_results WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1", (row["incident_id"],)).fetchone()
        incident["verification"] = dict(verification) if verification else None
        if row["incident_id"] == "INC-007":
            state_row = db.execute("SELECT mode, step FROM demo_state WHERE state_id = 1").fetchone()
            snapshot = self._simulation_snapshot(db, dict(state_row) if state_row else {"mode": "idle", "step": 0})
            incident["known_pattern_similarity"] = snapshot["model_1"]["similarity"]
            incident["behavioral_deviation"] = snapshot["model_2"]["deviation"]
            incident["risk_score"] = snapshot["fusion"]["risk_score"]
            incident["risk_level"] = snapshot["fusion"]["risk_level"]
            incident["assessment"] = snapshot["fusion"]["assessment"]
            incident["known_pattern"].update(snapshot["model_1"])
            incident["behavior_model"].update({"anomaly_score": snapshot["model_2"]["deviation"], "status": snapshot["model_2"]["status"], "severity": snapshot["model_2"]["severity"]})
            incident["risk"] = {"risk_level": snapshot["fusion"]["risk_level"], "risk_score": snapshot["fusion"]["risk_score"], "assessment": snapshot["fusion"]["assessment"]}
        return incident

    def incidents(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            self._state(db)
            return [self._incident_payload(db, row) for row in db.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()]

    def incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            self._state(db)
            row = self._incident_row(db, incident_id)
            return self._incident_payload(db, row) if row else None

    def alerts(self) -> List[Dict[str, Any]]:
        records = self.incidents()
        return [item for item in records if item["status"] not in ("CLOSED", "RESOLVED")]

    def _traffic_payload(self, db: sqlite3.Connection, state: Dict[str, Any]) -> Dict[str, Any]:
        snapshot = self._simulation_snapshot(db, state)
        current = {**snapshot["traffic"], "protocol": "HTTP/HTTPS", "stage": snapshot["stage"]}
        current.update({"entity_id": "Server-07", "timestamp": self._iso(self._now()), "requests_per_minute": current["requests_per_min"], "outbound_mb_per_minute": current["outbound_mb_per_min"], "failed_connections_per_minute": current["failed_connections"], "is_demo": True, "demo_label": DEMO_LABEL})
        baseline = [dict(row) for row in db.execute("SELECT timestamp, requests_per_minute AS requests_per_min, outbound_mb_per_minute AS outbound_mb_per_min, unique_destinations, failed_connections_per_minute AS failed_connections FROM traffic_events WHERE entity_id = 'Server-07' AND is_baseline = 1 ORDER BY timestamp").fetchall()]
        stream = baseline[-6:] + [current]
        return {"demo": True, "demo_label": DEMO_LABEL, "entity_id": "Server-07", "current": current, "baseline": baseline, "traffic": stream, "status": current["status"], "simulation_step": state.get("step", 0), "stage": snapshot["stage"], "stage_index": snapshot["stage_index"], "simulation": snapshot}

    def traffic(self) -> Dict[str, Any]:
        with self._lock, self._connect() as db:
            state = self._state(db)
            return self._traffic_payload(db, state)

    def dashboard(self) -> Dict[str, Any]:
        with self._lock, self._connect() as db:
            state = self._state(db)
            snapshot = self._simulation_snapshot(db, state)
            incidents = [self._incident_payload(db, row) for row in db.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()]
            traffic = self._traffic_payload(db, state)
            recent_alerts = [item for item in incidents if item["status"] not in ("CLOSED", "RESOLVED")]
            pending = []
            for row in db.execute("SELECT * FROM authorizations WHERE status = 'PENDING'").fetchall():
                approval = dict(row)
                approval.update({
                    "auth_request_id": approval["authorization_id"],
                    "action_id": "DEF-007",
                    "entity_id": "Server-07",
                    "timeout_seconds": self._countdown_seconds(db, state) or approval["countdown_seconds"],
                    "alert": {"entity": "Server-07", "risk_level": "HIGH", "activity": "PAUSE SUSPICIOUS PROCESS", "threat_assessment": {"risk_level": "HIGH", "suspicion_score": 0.89}},
                    "details": {"recommended_action": "PAUSE SUSPICIOUS PROCESS", "rationale": "Previously unseen / suspicious behavior", "operational_impact": "Medium - process paused, may affect users", "reversible": True},
                })
                pending.append(approval)
            defenses = [dict(row) for row in db.execute("SELECT * FROM defense_actions ORDER BY defense_id").fetchall()]
            verification = [dict(row) for row in db.execute("SELECT * FROM verification_results ORDER BY created_at DESC").fetchall()]
            return {
                "timestamp": self._iso(self._now()), "demo": True, "demo_label": DEMO_LABEL,
                "metrics": {"active_threats": 1 if state.get("mode") in ("running", "defending", "verifying") else 0, "high_risk": 1 if snapshot["fusion"]["risk_level"] == "HIGH" else 0, "critical_risk": 0, "monitoring_entities": 12, "incidents_today": 7, "resolved": 4 if state.get("mode") != "resolved" else 5, "mttd": 42, "mttr": 8, "total_incidents": len(incidents), "risk_distribution": {"critical": 0, "high": 1 if snapshot["fusion"]["risk_level"] == "HIGH" else 0, "medium": 0, "low": 1}},
                "security_posture": {"active_monitoring": True, "entities_monitored": 12, "recent_alerts": len(recent_alerts), "active_defenses": len([d for d in defenses if d["status"] in ("PENDING", "EXECUTING")]), "pending_authorizations": len(pending)},
                "threat_summary": {"total_assessments": len(incidents), "critical_risks": 3, "high_risks": 5, "medium_risks": 1, "low_risks": 1, "status": "DEMO ASSESSMENTS"},
                "defense_summary": {"total_actions": len(defenses), "active_defenses": len([d for d in defenses if d["status"] in ("PENDING", "EXECUTING")]), "completed": len([d for d in defenses if d["status"] == "COMPLETED"])},
                "verification_summary": {"total_responses_verified": len(verification), "average_effectiveness": round(sum(v["reduction_percent"] for v in verification) / len(verification), 1) if verification else 0, "label": "Illustrative verification example"},
                "recent_alerts": recent_alerts[:5], "active_defenses": defenses, "pending_approvals": pending, "traffic": traffic, "demo_state": {**state, "stage": snapshot["stage"], "stage_index": snapshot["stage_index"]}, "simulation": snapshot,
                "policy": self.policy(),
            }

    def timeline(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            state = self._state(db)
            self._sync_timeline(db, state)
            snapshot = self._simulation_snapshot(db, state)
            events = [dict(row) for row in db.execute("SELECT timestamp, entity_id, attack_stage, risk_level, event, status, incident_id FROM timeline_events ORDER BY timestamp").fetchall()]
            events.append({"timestamp": self._iso(self._now()), "entity_id": "Server-07", "attack_stage": snapshot["stage"], "risk_level": snapshot["fusion"]["risk_level"], "event": snapshot["fusion"]["assessment"], "status": "ACTIVE" if state.get("mode") in ("running", "defending", "verifying") else "RESOLVED" if state.get("mode") == "resolved" else "READY", "incident_id": "INC-007", "simulation_stage": True})
            return events

    def audit(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            self._state(db)
            return [dict(row) for row in db.execute("SELECT audit_id AS id, timestamp, action, entity_id, actor, result, details FROM audit_events ORDER BY timestamp").fetchall()]

    def known_pattern(self) -> Dict[str, Any]:
        with self._lock, self._connect() as db:
            state = self._state(db)
            snapshot = self._simulation_snapshot(db, state)
            current = {"classification": snapshot["model_1"]["classification"], "similarity": snapshot["model_1"]["similarity"], "status": snapshot["model_1"]["status"]}
            historical = [dict(row) for row in db.execute("SELECT attack_type, incident_id, known_similarity AS known_pattern_similarity FROM incidents ORDER BY created_at DESC").fetchall()]
            return {"demo": True, "demo_label": DEMO_LABEL, "model": "Known-pattern resemblance classifier", "current_entity": "Server-07", "current": current, "historical_classifications": historical}

    def behavior(self) -> Dict[str, Any]:
        with self._lock, self._connect() as db:
            state = self._state(db)
            snapshot = self._simulation_snapshot(db, state)
            traffic = self._traffic_payload(db, state)
            return {"demo": True, "demo_label": DEMO_LABEL, "model": "Behavioral baseline service", "entity_id": "Server-07", "baseline": {"requests_per_minute": "800-1200", "outbound_mb_per_minute": "50-100", "unique_destinations": "10-25", "failed_connections_per_minute": "5-20", "time_of_day": "business-hours profile", "protocol_behavior": "approved service traffic", "application_behavior": "normal service-to-service requests"}, "current": traffic["current"], "behavioral_deviation": snapshot["model_2"]["deviation"], "status": snapshot["model_2"]["status"], "severity": snapshot["model_2"]["severity"], "assessment": "Previously unseen / suspicious behavior" if snapshot["model_2"]["deviation"] >= 85 else "Within trusted baseline", "stage": snapshot["stage"]}

    def policy(self) -> Dict[str, Any]:
        return {"name": "Default human-authorized response policy", "demo_label": DEMO_LABEL, "require_human_approval": True, "high_risk_timeout_seconds": 30, "fail_safe_action": "PAUSE / RESTRICT / CUT OFF", "raw_telemetry": "remains within the customer's controlled environment", "note": "Illustrative prototype policy; not a production certification."}

    def risk(self) -> Dict[str, Any]:
        with self._lock, self._connect() as db:
            state = self._state(db)
            snapshot = self._simulation_snapshot(db, state)
            return {"demo": True, "demo_label": DEMO_LABEL, "risk_level": snapshot["fusion"]["risk_level"], "risk_score": snapshot["fusion"]["risk_score"], "confidence": 89, "known_pattern_similarity": snapshot["model_1"]["similarity"], "behavioral_deviation": snapshot["model_2"]["deviation"], "assessment": snapshot["fusion"]["assessment"], "recommended_action": "PAUSE SUSPICIOUS PROCESS", "stage": snapshot["stage"]}

    def demo_state(self) -> Dict[str, Any]:
        with self._lock, self._connect() as db:
            state = self._state(db)
            snapshot = self._simulation_snapshot(db, state)
            return {**state, "demo": True, "demo_label": DEMO_LABEL, "stage": snapshot["stage"], "stage_index": snapshot["stage_index"], "stage_count": snapshot["stage_count"], "countdown_seconds": self._countdown_seconds(db, state), "simulation": snapshot}

    def _countdown_seconds(self, db: sqlite3.Connection, state: Dict[str, Any]) -> Optional[int]:
        if state.get("mode") != "running" or state.get("step", 0) < 7:
            return None
        authorization = db.execute("SELECT updated_at, countdown_seconds, status FROM authorizations WHERE incident_id = 'INC-007' LIMIT 1").fetchone()
        if not authorization or authorization["status"] != "PENDING":
            return 0
        updated = datetime.fromisoformat(authorization["updated_at"].replace("Z", ""))
        remaining = authorization["countdown_seconds"] - int((self._now() - updated).total_seconds())
        return max(0, remaining)

    def start_demo(self) -> Dict[str, Any]:
        with self._lock, self._connect() as db:
            now = self._iso(self._now())
            db.execute("UPDATE demo_state SET mode = 'running', step = 0, started_at = ?, updated_at = ? WHERE state_id = 1", (now, now))
            db.execute("UPDATE incidents SET status = 'ACTIVE', updated_at = ? WHERE incident_id = 'INC-007'", (now,))
            db.execute("UPDATE authorizations SET status = 'QUEUED', decision = NULL, updated_at = ? WHERE authorization_id = 'AUTH-007'", (now,))
            db.execute("UPDATE defense_actions SET status = 'PENDING', started_at = NULL, completed_at = NULL WHERE defense_id = 'DEF-007'")
            db.execute("DELETE FROM verification_results WHERE incident_id = 'INC-007'")
            self._add_audit(db, "Demo started", "HUMAN", "RUNNING", "Normal-to-suspicious Server-07 scenario started")
            return {"state_id": 1, "mode": "running", "step": 0, "started_at": now, "updated_at": now, "stage": "NORMAL", "stage_index": 0, "stage_count": len(SIMULATION_STAGES), "demo": True, "demo_label": DEMO_LABEL, "countdown_seconds": None}

    def reset_demo(self) -> Dict[str, Any]:
        with self._lock, self._connect() as db:
            now = self._iso(self._now())
            db.execute("UPDATE demo_state SET mode = 'idle', step = 0, updated_at = ? WHERE state_id = 1", (now,))
            db.execute("UPDATE incidents SET status = CASE incident_id WHEN 'INC-007' THEN 'ACTIVE' ELSE status END, updated_at = ? WHERE incident_id = 'INC-007'", (now,))
            db.execute("UPDATE authorizations SET status = 'QUEUED', decision = NULL, updated_at = ? WHERE authorization_id = 'AUTH-007'", (now,))
            db.execute("UPDATE defense_actions SET status = 'PENDING', started_at = NULL, completed_at = NULL WHERE defense_id = 'DEF-007'")
            db.execute("DELETE FROM verification_results WHERE incident_id = 'INC-007'")
            self._add_audit(db, "Demo reset", "HUMAN", "READY", "Scenario returned to seeded state")
            return {"state_id": 1, "mode": "idle", "step": 0, "started_at": None, "updated_at": now, "stage": "NORMAL", "stage_index": 0, "stage_count": len(SIMULATION_STAGES), "demo": True, "demo_label": DEMO_LABEL, "countdown_seconds": None}

    def authorize(self, incident_id: str, decision: str) -> Dict[str, Any]:
        decision = decision.upper()
        if decision == "CONTINUE":
            return self.continue_incident(incident_id)
        if decision == "TIMEOUT":
            return self.timeout_incident(incident_id)
        return self.stop_incident(incident_id)

    def _timeout_locked(self, db: sqlite3.Connection, incident_id: str) -> Dict[str, Any]:
        now = self._iso(self._now())
        db.execute("UPDATE authorizations SET status = 'TIMED_OUT', decision = 'TIMEOUT', updated_at = ? WHERE incident_id = ?", (now, incident_id))
        db.execute("UPDATE defense_actions SET status = 'EXECUTING', started_at = ?, completed_at = NULL WHERE incident_id = ?", (now, incident_id))
        db.execute("UPDATE incidents SET status = 'CONTAINED', updated_at = ? WHERE incident_id = ?", (now, incident_id))
        db.execute("UPDATE demo_state SET mode = 'defending', step = 7, updated_at = ? WHERE state_id = 1", (now,))
        self._add_audit(db, "Authorization timeout", "POLICY", "TIMEOUT", "No human decision arrived within the 30 second window; fail-safe response applied")
        self._add_audit(db, "Defense executing", "RESPONSE-ENGINE", "EXECUTING", "Suspicious process pause started through the fail-safe timeout policy")
        return self._incident_payload(db, self._incident_row(db, incident_id))

    def timeout_incident(self, incident_id: str) -> Dict[str, Any]:
        with self._lock, self._connect() as db:
            if not self._incident_row(db, incident_id):
                return {"error": "Incident not found"}
            return self._timeout_locked(db, incident_id)

    def continue_incident(self, incident_id: str) -> Dict[str, Any]:
        with self._lock, self._connect() as db:
            if not self._incident_row(db, incident_id):
                return {"error": "Incident not found"}
            now = self._iso(self._now())
            db.execute("UPDATE authorizations SET status = 'APPROVED', decision = 'CONTINUE', updated_at = ? WHERE incident_id = ?", (now, incident_id))
            db.execute("UPDATE defense_actions SET status = 'EXECUTING', started_at = ?, completed_at = NULL WHERE incident_id = ?", (now, incident_id))
            db.execute("UPDATE incidents SET status = 'CONTAINED', updated_at = ? WHERE incident_id = ?", (now, incident_id))
            db.execute("UPDATE demo_state SET mode = 'defending', step = 7, updated_at = ? WHERE state_id = 1", (now,))
            self._add_audit(db, "User decision", "HUMAN", "CONTINUE", "Recommended pause authorized")
            self._add_audit(db, "Authorization granted", "HUMAN", "APPROVED", "Defense response may execute within the bounded policy")
            self._add_audit(db, "Defense executing", "RESPONSE-ENGINE", "EXECUTING", "Suspicious process pause started in the simulation")
            return self._incident_payload(db, self._incident_row(db, incident_id))

    def stop_incident(self, incident_id: str) -> Dict[str, Any]:
        with self._lock, self._connect() as db:
            if not self._incident_row(db, incident_id):
                return {"error": "Incident not found"}
            now = self._iso(self._now())
            db.execute("UPDATE authorizations SET status = 'REJECTED', decision = 'STOP', updated_at = ? WHERE incident_id = ?", (now, incident_id))
            db.execute("UPDATE defense_actions SET status = 'CANCELLED', completed_at = ? WHERE incident_id = ?", (now, incident_id))
            db.execute("UPDATE incidents SET status = 'INVESTIGATING', updated_at = ? WHERE incident_id = ?", (now, incident_id))
            db.execute("UPDATE demo_state SET mode = 'stopped', step = 6, updated_at = ? WHERE state_id = 1", (now,))
            self._add_audit(db, "User decision", "HUMAN", "STOP", "Defense cancelled; monitoring continues")
            self._add_audit(db, "Defense cancelled", "RESPONSE-ENGINE", "CANCELLED", "No response was executed; Server-07 remains under monitoring")
            return self._incident_payload(db, self._incident_row(db, incident_id))

    def verify(self, incident_id: str) -> Dict[str, Any]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM verification_results WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1", (incident_id,)).fetchone()
            if not row:
                now = self._iso(self._now())
                db.execute("INSERT OR REPLACE INTO verification_results VALUES (?, ?, 'THREAT_REDUCED', 1842, 21, 98.8, 'Illustrative verification example', ?)", (f"VERIFY-{incident_id}", incident_id, now))
                self._add_audit(db, "Verification completed", "VERIFICATION", "ILLUSTRATIVE", "Verification result recorded")
                row = db.execute("SELECT * FROM verification_results WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1", (incident_id,)).fetchone()
            return {**dict(row), "demo": True, "demo_label": DEMO_LABEL}
