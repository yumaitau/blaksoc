"""blakSOC tuning API client and wire contract.

This is the only module that knows endpoint paths and field names, so the contract can be adjusted in
one place while the server side settles. It speaks plain HTTP(S) through an injectable transport, never
follows redirects, bounds every response, retries only where a retry cannot repeat a write, and never
puts the credential in an exception, log line or return value.

Credential (HERMES_BLAKSOC_TOKEN) is either:
  - a bearer access token, sent as-is (blakSOC access tokens are `bsa_…` and live 15 minutes), or
  - service identity client credentials `<client id>:<client secret>` (`bss_…` secret), exchanged at
    /api/v1/oauth/token with the client_credentials grant at the start of each run and on expiry.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional

# --- Wire contract ------------------------------------------------------------------------------

PATHS = {
    "token": "/api/v1/oauth/token",
    "patterns": "/api/v1/tuning/patterns",
    "annotate": "/api/v1/tuning/patterns/{patternId}/annotations",
    "close": "/api/v1/tuning/patterns/{patternId}/close",
    "noise_rule": "/api/v1/tuning/noise-rules",
    "purge": "/api/v1/tuning/patterns/{patternId}/purge",
    "actions": "/api/v1/tuning/actions",
    "reports": "/api/v1/tuning/reports",
    "memory": "/api/v1/tuning/memory",
}

SEVERITIES = ("informational", "low", "medium", "high", "critical")
DISPOSITION_FIELDS = ("falsePositive", "resolved", "escalated", "open", "passive")

# Allowlists. Anything not named here is dropped (and logged by name) before data reaches the model.
# Values: "int", "num", "str:<regex name>", "iso", "list:<kind>", "obj:<name>", "severity", "nullable:<kind>".
PATTERN_FIELDS = {
    "patternId": "str:id",
    "tenantRef": "str:ref",
    "source": "str:token",
    "ruleId": "str:rule",
    "ruleLevel": "int",
    "ruleGroups": "list:str:token",
    "mitre": "list:str:mitre",
    "severity": "severity",
    "counts": "obj:counts",
    "distinctAssets": "int",
    "distinctUsers": "int",
    "dispositions": "obj:dispositions",
    "incidentsOpened": "int",
    "analystOverrides": "int",
    "medianMinutesToFirstTriage": "nullable:num",
    "firstSeen": "iso",
    "lastSeen": "iso",
    "noiseRule": "nullable:obj:noiseRule",
    "annotations": "list:obj:annotation",
}
COUNTS_FIELDS = {"total": "int", "byDay": "list:int", "byHourOfDay": "list:int"}
NOISE_RULE_FIELDS = {"id": "str:id", "status": "str:token", "expiresAt": "iso", "hitCount": "int"}
# Annotation text is kept only when Hermes wrote it (authorKind "service"); analysts' free text is dropped.
ANNOTATION_FIELDS = {"confidence": "str:token", "createdAt": "iso", "authorKind": "str:token", "text": "text"}
FLEET_FIELDS = {
    "source": "str:token",
    "ruleId": "str:rule",
    "tenantsAffected": "int",
    "total": "int",
    "coFiring": "list:obj:coFiring",
}
CO_FIRING_FIELDS = {"source": "str:token", "ruleId": "str:rule", "count": "int", "tenants": "int"}
ACTION_FIELDS = {
    "id": "str:id",
    "kind": "str:token",
    "patternId": "str:id",
    "tenantRef": "str:ref",
    "source": "str:token",
    "ruleId": "str:rule",
    "createdAt": "iso",
    "affected": "int",
    "undoneAt": "nullable:iso",
    "reopenedCount": "int",
    "status": "str:token",
}
MEMORY_NOTE_FIELDS = {"id": "str:id", "kind": "str:token", "text": "text", "createdAt": "iso", "updatedAt": "iso"}

PATTERNS_TOP = ("patterns", "fleet")
ACTIONS_TOP = ("actions",)
MEMORY_TOP = ("version", "retentionDays", "notes")

ACTION_KINDS = ("annotate", "close", "noise_rule", "purge")
PATTERN_ID = re.compile(r"^[A-Za-z0-9_-]{1,100}$")


# --- Errors -------------------------------------------------------------------------------------


class ApiError(Exception):
    """Base error. `message` is blakSOC's text, bounded; never contains the credential."""

    def __init__(self, status: int, code: str, message: str = ""):
        super().__init__(f"blakSOC {status} {code}".strip())
        self.status = status
        self.code = code
        self.message = message[:300]


class Refused(ApiError):
    """A definitive 4xx answer: blakSOC understood the request and said no."""


class Conflict(Refused):
    """409. On act endpoints this means the "Allow Hermes to act" switch is off; on memory, a stale version."""


class Unavailable(ApiError):
    """Transport failure, timeout or 5xx after the allowed retries. Outcome of a write may be unknown."""


class ConfigError(ValueError):
    pass


# --- Transport ----------------------------------------------------------------------------------

MAX_RESPONSE_BYTES = 5_000_000

# transport(method, url, headers, body, timeout) -> (status, headers(dict, lowercase keys), body bytes)
Transport = Callable[[str, str, dict, Optional[bytes], float], tuple]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - urllib hook
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class TransportError(Exception):
    """Raised by a transport. `sent` is False only when the request certainly never left (connect failed)."""

    def __init__(self, reason: str, sent: bool):
        super().__init__(reason)
        self.sent = sent


def urllib_transport(method, url, headers, body, timeout):
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            return response.status, {k.lower(): v for k, v in response.headers.items()}, raw
    except urllib.error.HTTPError as error:
        raw = error.read(64_000)
        status = error.code
        headers_out = {k.lower(): v for k, v in (error.headers or {}).items()}
        error.close()
        return status, headers_out, raw
    except urllib.error.URLError as error:
        refused = isinstance(error.reason, (ConnectionRefusedError, socket.gaierror))
        raise TransportError(type(error.reason).__name__, sent=not refused) from None
    except (TimeoutError, socket.timeout, ConnectionError, OSError) as error:
        raise TransportError(type(error).__name__, sent=True) from None


# --- Client -------------------------------------------------------------------------------------


def check_base_url(value: str) -> str:
    """HTTPS origin, or plain HTTP only to an in-cluster / loopback name."""
    parsed = urllib.parse.urlsplit(value or "")
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ConfigError("BLAKSOC_API_URL must be an origin such as http://blaksoc-blaksoc-web.blaksoc.svc:80")
    host = parsed.hostname.lower()
    if parsed.scheme == "http":
        internal = "." not in host or host.endswith((".svc", ".svc.cluster.local", ".cluster.local"))
        try:
            internal = internal or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        if not internal and host != "localhost":
            raise ConfigError("BLAKSOC_API_URL may use plain http only for an in-cluster service")
    return value.rstrip("/")


@dataclass
class Credential:
    bearer: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None

    @classmethod
    def parse(cls, value: str) -> "Credential":
        value = (value or "").strip()
        if not value or any(c.isspace() for c in value):
            raise ConfigError("HERMES_BLAKSOC_TOKEN is missing or malformed")
        if ":" in value:
            client_id, secret = value.split(":", 1)
            if not re.fullmatch(r"[0-9a-fA-F-]{36}", client_id) or not secret.startswith("bss_"):
                raise ConfigError("HERMES_BLAKSOC_TOKEN client credentials must be <client id>:bss_…")
            return cls(client_id=client_id, client_secret=secret)
        return cls(bearer=value)

    def __repr__(self) -> str:  # never print the secret
        return "Credential(client_credentials)" if self.client_id else "Credential(bearer)"


class TuningClient:
    def __init__(
        self,
        base_url: str,
        credential: Credential,
        *,
        transport: Transport = urllib_transport,
        timeout: float = 20.0,
        retries: int = 2,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        auth_scheme: str = "Bearer",
    ):
        self.base_url = check_base_url(base_url)
        self._credential = credential
        self._transport = transport
        self.timeout = timeout
        self.retries = max(0, min(int(retries), 5))
        self._sleep = sleep
        self._clock = clock
        if not re.fullmatch(r"[A-Za-z]{1,20}", auth_scheme):
            raise ConfigError("auth scheme must be a single word")
        self._scheme = auth_scheme
        self._token: Optional[str] = credential.bearer
        self._token_expires = float("inf") if credential.bearer else 0.0
        self.calls: list[tuple[str, str]] = []  # (method, path) for tests and run logs; no bodies

    def __repr__(self) -> str:
        return f"TuningClient({self.base_url})"

    # -- auth --

    def _access_token(self, force: bool = False) -> str:
        cred = self._credential
        if cred.bearer:
            return cred.bearer
        if not force and self._token and self._clock() < self._token_expires - 60:
            return self._token
        basic = base64.b64encode(
            (urllib.parse.quote(cred.client_id, safe="") + ":" + urllib.parse.quote(cred.client_secret, safe="")).encode()
        ).decode()
        body = urllib.parse.urlencode({"grant_type": "client_credentials"}).encode()
        status, _, raw = self._send(
            "POST",
            PATHS["token"],
            {"Authorization": "Basic " + basic, "Content-Type": "application/x-www-form-urlencoded"},
            body,
            retry_unsent_only=True,
        )
        data = _json(raw)
        if status != 200 or not isinstance(data, dict) or not isinstance(data.get("access_token"), str):
            raise Refused(status, str((data or {}).get("error", "token_refused")) if isinstance(data, dict) else "token_refused")
        expires = data.get("expires_in", 900)
        self._token = data["access_token"]
        self._token_expires = self._clock() + (expires if isinstance(expires, (int, float)) and expires > 0 else 900)
        return self._token

    # -- transport with retries --

    def _send(self, method, path, headers, body, *, retry_unsent_only):
        """Returns (status, headers, raw). Retries 429 always; transport errors and 5xx only when safe."""
        url = self.base_url + path
        attempt = 0
        while True:
            attempt += 1
            self.calls.append((method, path.split("?", 1)[0]))
            try:
                status, response_headers, raw = self._transport(method, url, headers, body, self.timeout)
            except TransportError as error:
                if attempt <= self.retries and (not retry_unsent_only or not error.sent):
                    self._sleep(min(2 ** attempt, 10))
                    continue
                raise Unavailable(0, "transport_" + str(error)[:40]) from None
            if raw is not None and len(raw) > MAX_RESPONSE_BYTES:
                raise Unavailable(status, "response_too_large")
            if status == 429 and attempt <= self.retries:
                retry_after = (response_headers or {}).get("retry-after", "")
                delay = int(retry_after) if str(retry_after).isdigit() else 2 ** attempt
                self._sleep(min(delay, 30))
                continue
            if status >= 500 and not retry_unsent_only and attempt <= self.retries:
                self._sleep(min(2 ** attempt, 10))
                continue
            return status, response_headers, raw

    def _call(self, method, path, *, query=None, payload=None, idempotency_key=None):
        if query:
            path = path + "?" + urllib.parse.urlencode(query)
        body = json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None
        retry_unsent_only = method == "POST"
        for refresh in (False, True):
            headers = {"Authorization": f"{self._scheme} {self._access_token(force=refresh)}", "Accept": "application/json"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            if idempotency_key:
                headers["Idempotency-Key"] = idempotency_key
            status, _, raw = self._send(method, path, headers, body, retry_unsent_only=retry_unsent_only)
            if status == 401 and not refresh and self._credential.client_id:
                continue  # token expired mid-run: one fresh exchange, then a single retry
            break
        data = _json(raw)
        if 200 <= status < 300:
            return data if data is not None else {}
        code = str(data.get("error", "error"))[:60] if isinstance(data, dict) else "error"
        message = str(data.get("message", "")) if isinstance(data, dict) else ""
        if status == 409:
            raise Conflict(status, code, message)
        if 400 <= status < 500:
            raise Refused(status, code, message)
        raise Unavailable(status, code, message)

    # -- endpoints --

    @staticmethod
    def _pattern_path(key: str, pattern_id: str) -> str:
        if not isinstance(pattern_id, str) or not PATTERN_ID.fullmatch(pattern_id):
            raise ValueError("invalid patternId")
        return PATHS[key].replace("{patternId}", urllib.parse.quote(pattern_id, safe=""))

    def patterns(self, days: int) -> Any:
        return self._call("GET", PATHS["patterns"], query={"days": int(days)})

    def actions(self, since_iso: str) -> Any:
        return self._call("GET", PATHS["actions"], query={"since": since_iso})

    def annotate(self, pattern_id: str, text: str, confidence: str, idempotency_key=None) -> Any:
        return self._call(
            "POST", self._pattern_path("annotate", pattern_id),
            payload={"text": text, "confidence": confidence}, idempotency_key=idempotency_key,
        )

    def close(self, pattern_id: str, reason: str, max_alerts: Optional[int] = None, idempotency_key=None) -> Any:
        payload = {"reason": reason}
        if max_alerts is not None:
            payload["maxAlerts"] = int(max_alerts)
        return self._call("POST", self._pattern_path("close", pattern_id), payload=payload, idempotency_key=idempotency_key)

    def noise_rule(self, pattern_id: str, reason: str, expires_in_days: int, idempotency_key=None) -> Any:
        if not isinstance(pattern_id, str) or not PATTERN_ID.fullmatch(pattern_id):
            raise ValueError("invalid patternId")
        return self._call(
            "POST", PATHS["noise_rule"],
            payload={"patternId": pattern_id, "reason": reason, "expiresInDays": int(expires_in_days)},
            idempotency_key=idempotency_key,
        )

    def purge(self, pattern_id: str, idempotency_key=None) -> Any:
        return self._call("POST", self._pattern_path("purge", pattern_id), payload={}, idempotency_key=idempotency_key)

    def submit_report(self, period_start: str, period_end: str, markdown: str, stats: dict, idempotency_key=None) -> Any:
        return self._call(
            "POST", PATHS["reports"],
            payload={"periodStart": period_start, "periodEnd": period_end, "markdown": markdown, "stats": stats},
            idempotency_key=idempotency_key,
        )

    def reports(self, limit: int = 5) -> Any:
        return self._call("GET", PATHS["reports"], query={"limit": int(limit)})

    def memory(self) -> Any:
        return self._call("GET", PATHS["memory"])

    def put_memory(self, version: int, notes: list) -> Any:
        # Optimistic concurrency: blakSOC answers 409 when `version` is stale, so a retry cannot clobber.
        return self._call("PUT", PATHS["memory"], payload={"version": version, "notes": notes})


def _json(raw: Optional[bytes]):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
