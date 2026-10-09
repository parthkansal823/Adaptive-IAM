"""Budgeted optional local LLM suggestion, constrained by deterministic policy."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


class ReviewerSelector:
    def __init__(self):
        self.model = os.getenv("IAM_OLLAMA_MODEL", "").strip()
        self.base_url = os.getenv("IAM_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
        parsed = urlparse(self.base_url)
        self.enabled = bool(self.model and parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"})
        try:
            self.max_calls = min(100, max(0, int(os.getenv("IAM_LLM_MAX_CALLS", "20"))))
        except ValueError:
            self.max_calls = 0
        self.calls = 0
        self.cache = {}
        self.lock = threading.Lock()

    def select(self, requester: dict, resource: dict, users: list[dict]):
        owner = resource["owner_id"]
        eligible = [u for u in users if u["id"] != requester["id"] and u["role"] in {"resource_owner", "security_reviewer", "department_reviewer"}]
        candidates = [u for u in eligible if u["id"] != owner]
        candidates.sort(key=lambda u: (u["department"] != requester["department"], u["role"] != "security_reviewer", u["id"]))
        fallback = [owner] + [u["id"] for u in candidates[:2]]
        fallback = list(dict.fromkeys(fallback))
        # A requester who owns the resource cannot be an eligible owner vote.
        if owner == requester["id"]:
            fallback = [u["id"] for u in candidates[:3]]
        key = hashlib.sha256(json.dumps([requester["department"], requester["id"], resource["id"], sorted(u["id"] for u in eligible)]).encode()).hexdigest()
        with self.lock:
            cached = self.cache.get(key)
            if cached and cached[0] > time.time():
                return cached[1], {"engine": "ollama_cached", "reason": "Cached validated suggestion for identical organizational context; no free text included."}
            can_call = self.enabled and self.calls < self.max_calls
            if can_call:
                self.calls += 1
        if can_call:
            try:
                prompt = {"task": "Select 2 or 3 reviewer IDs from eligible_ids. Include required_owner. Return JSON {\"reviewer_ids\":[...]} only.", "required_owner": owner, "resource": {"id": resource["id"], "sensitivity": resource["sensitivity"]}, "requester_department": requester["department"], "eligible_ids": [u["id"] for u in eligible]}
                body = json.dumps({"model": self.model, "prompt": json.dumps(prompt), "stream": False, "format": "json", "options": {"temperature": 0, "num_predict": 120}}).encode()
                req = urllib.request.Request(self.base_url + "/api/generate", data=body, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=2.0) as response:
                    outer = json.loads(response.read(20000))
                result = json.loads(outer["response"])
                if not isinstance(result, dict):
                    raise ValueError("Reviewer suggestion must be a JSON object")
                ids = result.get("reviewer_ids")
                allowed = {u["id"] for u in eligible}
                if (not isinstance(ids, list) or not 2 <= len(ids) <= 3 or not all(isinstance(i, str) for i in ids)
                        or len(set(ids)) != len(ids) or not set(ids) <= allowed or owner not in ids or requester["id"] in ids):
                    raise ValueError("Reviewer policy rejected suggestion")
                with self.lock:
                    if len(self.cache) >= 128:
                        self.cache.pop(next(iter(self.cache)))
                    self.cache[key] = (time.time()+3600, ids)
                return ids, {"engine": "ollama", "reason": "Local suggestion validated against eligible reviewers and mandatory owner policy."}
            except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, TypeError):
                pass
        return fallback, {"engine": "deterministic_policy", "reason": "Resource owner + eligible department/security reviewers; local LLM optional, advisory and budget bounded."}
