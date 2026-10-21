"""SQLite policy state with atomic grants and a local tamper-evident audit chain."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import HTTPException

PASSWORD = "Demo@123!"
USERS = [
    {"id": "aisha", "name": "Aisha Verma", "role": "analyst", "department": "Engineering"},
    {"id": "meera", "name": "Meera Rao", "role": "resource_owner", "department": "Engineering"},
    {"id": "rohan", "name": "Rohan Shah", "role": "resource_owner", "department": "Finance"},
    {"id": "kavya", "name": "Kavya Sen", "role": "security_reviewer", "department": "Security"},
    {"id": "vihaan", "name": "Vihaan Kapoor", "role": "department_reviewer", "department": "Engineering"},
]
RESOURCES = [
    {"id": "research-vault", "name": "Research vault", "description": "Model cards, experiment evidence and approved project notes.", "sensitivity": "internal", "owner_id": "meera", "max_duration_hours": 24},
    {"id": "finance-reports", "name": "Finance reports", "description": "Confidential quarterly planning and reconciliation records.", "sensitivity": "confidential", "owner_id": "rohan", "max_duration_hours": 8},
    {"id": "production-logs", "name": "Production logs", "description": "Restricted incident evidence and operational trace samples.", "sensitivity": "restricted", "owner_id": "meera", "max_duration_hours": 4},
]


def now():
    return datetime.now(timezone.utc)


def stamp(value=None):
    return (value or now()).isoformat(timespec="microseconds")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def secret_hash(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310000).hex()
    return f"pbkdf2_sha256$310000${salt}${digest}"


def verify_password(password, encoded):
    _, iterations, salt, expected = encoded.split("$")
    computed = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations)).hex()
    return hmac.compare_digest(computed, expected)


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.dummy_password = hash_password(secrets.token_hex(24))
        with self.connection(write=True) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, department TEXT NOT NULL, password_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS resources (id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, sensitivity TEXT NOT NULL, owner_id TEXT NOT NULL REFERENCES users(id), max_duration_hours REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), token_hash TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, risk_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS challenges (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), code_hash TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, risk_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS auth_failures (user_id TEXT PRIMARY KEY, count INTEGER NOT NULL, window_started TEXT NOT NULL, locked_until TEXT);
                CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, requester_id TEXT NOT NULL REFERENCES users(id), resource_id TEXT NOT NULL REFERENCES resources(id), justification TEXT NOT NULL, duration_hours REAL NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, risk_json TEXT NOT NULL, nlp_json TEXT NOT NULL, reviewers_json TEXT NOT NULL, selection_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS votes (request_id TEXT NOT NULL REFERENCES requests(id), reviewer_id TEXT NOT NULL REFERENCES users(id), approve INTEGER NOT NULL, weight REAL NOT NULL, comment TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (request_id, reviewer_id));
                CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL REFERENCES requests(id), user_id TEXT NOT NULL REFERENCES users(id), resource_id TEXT NOT NULL REFERENCES resources(id), scope TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, event_type TEXT NOT NULL, actor_id TEXT, payload TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit_batches (id INTEGER PRIMARY KEY, start_sequence INTEGER NOT NULL UNIQUE CHECK(start_sequence>0), end_sequence INTEGER NOT NULL UNIQUE CHECK(end_sequence>=start_sequence AND end_sequence-start_sequence<256), root TEXT NOT NULL CHECK(length(root)=64), previous_root TEXT NOT NULL CHECK(length(previous_root)=64), audit_end_hash TEXT NOT NULL CHECK(length(audit_end_hash)=64), created_at TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS audit_batches_no_update BEFORE UPDATE ON audit_batches BEGIN SELECT RAISE(ABORT, 'Audit batches are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS audit_batches_no_delete BEFORE DELETE ON audit_batches BEGIN SELECT RAISE(ABORT, 'Audit batches are append-only'); END;
                CREATE TABLE IF NOT EXISTS blockchain_outbox (kind TEXT NOT NULL, local_id TEXT NOT NULL, status TEXT NOT NULL, transaction_hash TEXT, block_number INTEGER, error TEXT, updated_at TEXT NOT NULL, PRIMARY KEY(kind,local_id));
                CREATE TABLE IF NOT EXISTS session_security (session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL, verified_at TEXT, verification_method TEXT NOT NULL, last_seen_at TEXT NOT NULL, step_up_required INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0);
            """)
            challenge_columns = {row['name'] for row in db.execute('PRAGMA table_info(challenges)')}
            for column, definition in (('fingerprint', "TEXT NOT NULL DEFAULT ''"), ('method', "TEXT NOT NULL DEFAULT 'legacy'")):
                if column not in challenge_columns:
                    db.execute(f'ALTER TABLE challenges ADD COLUMN {column} {definition}')
            if 'authentication_mode' not in {row['name'] for row in db.execute('PRAGMA table_info(session_security)')}:
                db.execute("ALTER TABLE session_security ADD COLUMN authentication_mode TEXT NOT NULL DEFAULT 'legacy'")
            db.execute("CREATE INDEX IF NOT EXISTS audit_actor_event_time ON audit(actor_id,event_type,timestamp)")
            for user in USERS:
                if not db.execute("SELECT id FROM users WHERE id=?", (user["id"],)).fetchone():
                    db.execute("INSERT INTO users VALUES (?,?,?,?,?)", (user["id"], user["name"], user["role"], user["department"], hash_password(PASSWORD)))
            for resource in RESOURCES:
                db.execute("INSERT OR IGNORE INTO resources VALUES (?,?,?,?,?,?)", tuple(resource.values()))
            if not db.execute("SELECT id FROM audit LIMIT 1").fetchone():
                self.audit(db, "system_initialized", None, {"mode": "offline_research_demo", "ledger_type": "local_sha256_hash_chain"})
            db.execute("INSERT OR IGNORE INTO blockchain_outbox (kind,local_id,status,updated_at) SELECT 'grant',id,'pending',created_at FROM grants")

    @contextmanager
    def connection(self, write=False):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def audit(db, event_type, actor_id, payload):
        previous = db.execute("SELECT id, hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        record = {"id": previous["id"]+1 if previous else 1, "timestamp": stamp(), "event_type": event_type, "actor_id": actor_id, "payload": payload, "previous_hash": previous["hash"] if previous else "0"*64}
        digest = hashlib.sha256(canonical(record).encode()).hexdigest()
        db.execute("INSERT INTO audit (id,timestamp,event_type,actor_id,payload,previous_hash,hash) VALUES (?,?,?,?,?,?,?)", (record["id"], record["timestamp"], event_type, actor_id, canonical(payload), record["previous_hash"], digest))
        db.execute("INSERT OR IGNORE INTO blockchain_outbox (kind,local_id,status,updated_at) VALUES ('audit',?,'pending',?)", (str(record["id"]), record["timestamp"]))

    def users(self, db):
        return [dict(row) for row in db.execute("SELECT id,name,role,department FROM users ORDER BY id")]

    def resources(self, db):
        return [dict(row) for row in db.execute("SELECT * FROM resources ORDER BY id")]

    def session(self, token):
        if not token or len(token) > 256:
            raise HTTPException(401, "A valid session is required")
        with self.connection() as db:
            row = db.execute("SELECT s.*,u.name,u.role,u.department FROM sessions s JOIN users u ON s.user_id=u.id WHERE token_hash=?", (secret_hash(token),)).fetchone()
            if not row or row["expires_at"] <= stamp():
                raise HTTPException(401, "Session is invalid or expired")
            security = db.execute("SELECT * FROM session_security WHERE session_id=?", (row["id"],)).fetchone()
            packet = {"id": row["id"], "expires_at": row["expires_at"]}
            if security:
                packet.update({key: security[key] for key in ("verified_at", "verification_method", "step_up_required")})
                packet["step_up_required"] = bool(packet["step_up_required"])
            return {"user": {"id": row["user_id"], "name": row["name"], "role": row["role"], "department": row["department"]}, "session": packet, "risk": json.loads(row["risk_json"])}

    def make_session(self, db, user_id, risk):
        token = secrets.token_urlsafe(32)
        created, expiry = stamp(), stamp(now()+timedelta(minutes=30))
        session_id = secrets.token_hex(16)
        db.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?)", (session_id, user_id, secret_hash(token), created, expiry, canonical(risk)))
        user = db.execute("SELECT id,name,role,department FROM users WHERE id=?", (user_id,)).fetchone()
        return {"status": "authenticated", "token": token, "user": dict(user), "expires_at": expiry, "risk": risk, "session_id": session_id}

    def expire(self, db):
        current = stamp()
        for row in db.execute("SELECT id,requester_id FROM requests WHERE status='pending' AND expires_at<=?", (current,)).fetchall():
            db.execute("UPDATE requests SET status='expired' WHERE id=?", (row["id"],))
            self.audit(db, "request_expired", row["requester_id"], {"request_id": row["id"], "decision": "deny_by_default"})
        for row in db.execute("SELECT id,user_id,resource_id FROM grants WHERE status='active' AND expires_at<=?", (current,)).fetchall():
            db.execute("UPDATE grants SET status='expired' WHERE id=?", (row["id"],))
            self.audit(db, "grant_expired", row["user_id"], {"grant_id": row["id"], "resource_id": row["resource_id"]})

    def active_grant(self, db, user_id, resource_id, blockchain):
        """Use any live read grant; a pending replacement cannot mask an older one."""
        required = bool(blockchain.enabled)
        denied = (None, {"required": required, "allowed": False, "status": "no_local_grant"})
        grants = db.execute("SELECT * FROM grants WHERE user_id=? AND resource_id=? AND scope='read' AND status='active' AND expires_at>? ORDER BY expires_at DESC,id", (user_id, resource_id, stamp())).fetchall()
        for row in grants:
            grant = dict(row)
            if grant["expires_at"] <= stamp():
                continue
            try:
                chain = blockchain.check_grant(grant)
                if (not isinstance(chain, dict) or not isinstance(chain.get("allowed"), bool)
                        or chain.get("required") is not required
                        or chain.get("status") not in ({"confirmed", "pending_or_expired", "unavailable"} if required else {"disabled"})
                        or chain["allowed"] != (chain["status"] == ("confirmed" if required else "disabled"))):
                    raise ValueError("Invalid grant check result")
            except Exception:
                chain = {"required": required, "allowed": False, "status": "unavailable", "reason": "Grant verification unavailable; access denied"}
            if chain["allowed"]:
                if grant["expires_at"] <= stamp():
                    continue
                return grant, chain
            if denied[0] is None:
                denied = grant, chain
            # RPC/checkpoint failures apply to the policy, not just one grant.
            if chain["status"] != "pending_or_expired":
                return grant, chain
        return denied

    def request_dto(self, db, request_id, actor_id):
        row = db.execute("SELECT q.*,u.name requester_name,r.name resource_name FROM requests q JOIN users u ON q.requester_id=u.id JOIN resources r ON q.resource_id=r.id WHERE q.id=?", (request_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Request not found")
        result = dict(row)
        for key in ("risk", "nlp", "reviewers"):
            result[key] = json.loads(result.pop(key+"_json"))
        result["reviewer_selection"] = json.loads(result.pop("selection_json"))
        result["votes"] = [dict(v) for v in db.execute("SELECT v.*,u.name reviewer_name FROM votes v JOIN users u ON v.reviewer_id=u.id WHERE request_id=? ORDER BY created_at", (request_id,))]
        for vote in result["votes"]:
            vote["approve"] = bool(vote["approve"])
        approval = sum(v["weight"] for v in result["votes"] if v["approve"])
        total = sum(r["weight"] for r in result["reviewers"])
        owner_voted = any(v["reviewer_id"] == r["id"] for v in result["votes"] for r in result["reviewers"] if r["is_owner"])
        quorum = len(result["votes"]) >= 2 and owner_voted
        result["consensus"] = {"approval_weight": approval, "total_weight": total, "cast_weight": sum(v["weight"] for v in result["votes"]), "quorum_required": 2, "quorum_reached": quorum, "owner_vote_required": True}
        result["can_vote"] = result["status"] == "pending" and actor_id in {r["id"] for r in result["reviewers"]} and actor_id not in {v["reviewer_id"] for v in result["votes"]} and actor_id != result["requester_id"]
        return result

    def audit_dtos(self, db, limit=200):
        rows = db.execute("SELECT a.*,u.name actor_name FROM audit a LEFT JOIN users u ON a.actor_id=u.id ORDER BY a.id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(row), "payload": json.loads(row["payload"])} for row in rows]

    def verify_audit(self):
        with self.connection() as db:
            rows = db.execute("SELECT * FROM audit ORDER BY id").fetchall()
        previous = "0"*64
        broken = None
        checked = 0
        for index, row in enumerate(rows, 1):
            record = {key: row[key] for key in ("id", "timestamp", "event_type", "actor_id", "previous_hash")}
            try:
                record["payload"] = json.loads(row["payload"])
                digest = hashlib.sha256(canonical(record).encode()).hexdigest()
            except (ValueError, TypeError):
                broken = row["id"]
                break
            checked += 1
            if row["id"] != index or row["previous_hash"] != previous or not hmac.compare_digest(digest, row["hash"]):
                broken = row["id"]
                break
            previous = row["hash"]
        return {"valid": broken is None, "checked_events": checked, "head_hash": previous, "broken_at": broken, "ledger_type": "local_sha256_hash_chain", "limitation": "SQLite verification only; an administrator able to rewrite the full database can recompute it. Consult blockchain status for the optional local Ethereum checkpoint. No distributed production consensus is implemented."}
