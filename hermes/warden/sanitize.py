"""Defence in depth against PII reaching the model, blakSOC annotations, memory or the report.

blakSOC already serves counts and patterns only. This module still:
  1. aborts the run if any key anywhere in a response looks like it carries identifying data
     (title, hostname, username, ip, email, description, …), before anything is stripped;
  2. keeps only allowlisted fields (api.py) and type-checks them, logging dropped field NAMES only;
  3. aborts if a kept string value looks like an email or IP address;
  4. finds or redacts identifiers in free text (model output, refusal messages, memory notes).
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Iterable

from . import api

# Words that, as a whole key or as one word of a camelCase/snake_case key, mean identifying data.
SUSPICIOUS_WORDS = {
    "title", "titles", "hostname", "hostnames", "username", "usernames", "ip", "ips", "ipv4", "ipv6",
    "email", "emails", "description", "descriptions", "fqdn", "upn", "mac",
}
SUSPICIOUS_KEYS = {
    "host", "hosts", "user", "customer", "customername", "tenantname", "ipaddress", "emailaddress",
    "macaddress", "srcuser", "dstuser", "rawlog", "rawevent", "rawevents", "fulllog", "commandline",
    "cmdline", "userprincipalname", "displayname", "name", "accountname", "account", "payload", "message",
    "subject", "url", "filename", "filepath", "domain", "agentname", "devicename", "computername", "event",
    "events", "rawdata", "data", "summary",
}


class PiiAbort(Exception):
    """The response carried something that must never reach Hermes. `keys` holds key paths, not values."""

    def __init__(self, keys: Iterable[str]):
        self.keys = sorted(set(keys))[:20]
        super().__init__("prohibited fields in blakSOC response: " + ", ".join(self.keys))


class ShapeError(ValueError):
    pass


def _words(key: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if w]


def key_is_suspicious(key: str) -> bool:
    words = _words(str(key))
    return "".join(words) in SUSPICIOUS_KEYS | SUSPICIOUS_WORDS or any(w in SUSPICIOUS_WORDS for w in words)


def suspicious_keys(value: Any, path: str = "") -> list[str]:
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if key_is_suspicious(key):
                found.append(re.sub(r"\[\d+\]", "[]", child_path)[:120])
            found += suspicious_keys(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value[:5000]):
            found += suspicious_keys(child, f"{path}[{index}]")
    return found


# --- free text ---

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Not inside an identifier such as the Wazuh group pci_dss_10.2.4.1, but "from 10.0.0.1." still counts.
IPV4 = re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\.?\w)")
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
URL = re.compile(r"\b(?:https?|ftp|smb|file)://\S+", re.IGNORECASE)
FQDN = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,24})\b")
WINDOWS_HOST = re.compile(r"\b(?:DESKTOP|LAPTOP|WIN|WS|SRV|PC)-[A-Z0-9]{3,15}\b", re.IGNORECASE)
DOMAIN_USER = re.compile(r"\b[A-Za-z0-9_-]{1,30}\\[A-Za-z0-9._$-]{1,64}\b")
UNC = re.compile(r"\\\\[A-Za-z0-9._$-]+")
# Words that look like dotted names but are not identifiers (file extensions in rule prose, ATT&CK ids).
_FQDN_ALLOW = re.compile(r"^(?:e\.g|i\.e|etc|vs)$", re.IGNORECASE)

PATTERNS = (("email", EMAIL), ("url", URL), ("ipv4", IPV4), ("ipv6", IPV6), ("unc", UNC),
            ("domain_user", DOMAIN_USER), ("windows_host", WINDOWS_HOST), ("fqdn", FQDN))


def _is_ipv6(candidate: str) -> bool:
    # Clock times such as 09:30:00 match the loose pattern; only real addresses count.
    if candidate.count(":") < 3:
        return False
    try:
        return ipaddress.ip_address(candidate.rstrip(":")).version == 6
    except ValueError:
        return False


def _hit(kind: str, candidate: str) -> bool:
    if kind == "fqdn":
        return not _FQDN_ALLOW.match(candidate)
    if kind == "ipv6":
        return _is_ipv6(candidate)
    return True


def find_pii(text: str) -> list[str]:
    """Kinds of identifier found in text. Empty means nothing recognisable."""
    return [kind for kind, pattern in PATTERNS if any(_hit(kind, m.group(0)) for m in pattern.finditer(text or ""))]


def scrub(text: str) -> str:
    """Replace anything identifier-shaped with [redacted]."""
    out = text or ""
    for kind, pattern in PATTERNS:
        out = pattern.sub(lambda m, kind=kind: "[redacted]" if _hit(kind, m.group(0)) else m.group(0), out)
    return out


def clean_text(value: Any, limit: int) -> str:
    """Single-line-safe bounded text with control characters removed."""
    text = "".join(ch for ch in str(value) if ch in "\n\t" or ch.isprintable())
    return text.strip()[:limit]


# --- structured responses ---

_STR = {
    "id": re.compile(r"^[A-Za-z0-9_-]{1,100}$"),
    "ref": re.compile(r"^[A-Za-z0-9_-]{1,64}$"),
    "token": re.compile(r"^[A-Za-z0-9_.:-]{1,60}$"),
    "rule": re.compile(r"^[A-Za-z0-9_.:-]{1,80}$"),
    "mitre": re.compile(r"^(?:TA|T)\d{4}(?:\.\d{3})?$"),
}
_OBJECTS = {
    "counts": api.COUNTS_FIELDS,
    "noiseRule": api.NOISE_RULE_FIELDS,
    "annotation": api.ANNOTATION_FIELDS,
    "coFiring": api.CO_FIRING_FIELDS,
}


def _iso(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ShapeError("timestamp")
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


def _int(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10**12:
        raise ShapeError("integer")
    return value


def _coerce(kind: str, value: Any, dropped: set, prefix: str):
    if kind.startswith("nullable:"):
        return None if value is None else _coerce(kind[9:], value, dropped, prefix)
    if kind == "int":
        return _int(value)
    if kind == "num":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise ShapeError("number")
        return value
    if kind == "iso":
        return _iso(value)
    if kind == "text":
        if not isinstance(value, str):
            raise ShapeError("text")
        return value
    if kind.startswith("str:"):
        if not isinstance(value, str) or not _STR[kind[4:]].fullmatch(value):
            raise ShapeError(kind)
        return value
    if kind == "severity":
        if not isinstance(value, dict):
            raise ShapeError("severity")
        out = {}
        for key, count in value.items():
            name = {"info": "informational"}.get(key, key)
            if name in api.SEVERITIES:
                out[name] = _int(count)
            else:
                dropped.add(f"{prefix}.severity.{key}")
        return out
    if kind == "obj:dispositions":
        if not isinstance(value, dict):
            raise ShapeError("dispositions")
        out = {}
        for window, counts in value.items():
            if window not in ("d30", "d90") or not isinstance(counts, dict):
                dropped.add(f"{prefix}.dispositions.{window}")
                continue
            out[window] = {f: _int(counts.get(f, 0)) for f in api.DISPOSITION_FIELDS}
            dropped.update(f"{prefix}.dispositions.{window}.{k}" for k in counts if k not in api.DISPOSITION_FIELDS)
        return out
    if kind.startswith("obj:"):
        name = kind[4:]
        return allow(value, _OBJECTS[name], dropped, f"{prefix}.{name}")
    if kind.startswith("list:"):
        if not isinstance(value, list) or len(value) > 400:
            raise ShapeError("list")
        return [_coerce(kind[5:], item, dropped, prefix) for item in value]
    raise ShapeError(kind)


def allow(record: Any, fields: dict, dropped: set, prefix: str) -> dict:
    if not isinstance(record, dict):
        raise ShapeError("object")
    out = {}
    for key, value in record.items():
        if key not in fields:
            dropped.add(f"{prefix}.{key}")
            continue
        out[key] = _coerce(fields[key], value, dropped, prefix)
    return out


def _value_pii(value: Any, path: str = "") -> list[str]:
    if isinstance(value, str):
        hit = EMAIL.search(value) or IPV4.search(value) or any(_is_ipv6(m.group(0)) for m in IPV6.finditer(value))
        return [path] if hit else []
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in _value_pii(v, f"{path}.{k}" if path else k)]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in _value_pii(v, f"{path}[]")]
    return []


def _records(raw: Any, top: tuple, list_key: str, fields: dict, log, limit: int) -> tuple[dict, list]:
    if not isinstance(raw, dict):
        raise ShapeError("response is not an object")
    found = suspicious_keys(raw)
    if found:
        raise PiiAbort(found)
    dropped: set = set(f"<top>.{k}" for k in raw if k not in top)
    items = raw.get(list_key, [])
    if not isinstance(items, list):
        raise ShapeError(f"{list_key} is not a list")
    kept, invalid = [], 0
    for item in items[:limit]:
        try:
            kept.append(allow(item, fields, dropped, list_key))
        except (ShapeError, ValueError, TypeError):
            invalid += 1
    if len(items) > limit:
        log("records_truncated", list=list_key, received=len(items), kept=limit)
    if invalid:
        log("records_invalid", list=list_key, dropped=invalid)
    return {"dropped": sorted(dropped)}, kept


def patterns_response(raw: Any, log=lambda *a, **k: None) -> dict:
    """Validated {patterns, fleet}. Raises PiiAbort or ShapeError."""
    meta, patterns = _records(raw, api.PATTERNS_TOP, "patterns", api.PATTERN_FIELDS, log, 2000)
    fleet_meta, fleet = _records({"fleet": raw.get("fleet", [])}, ("fleet",), "fleet", api.FLEET_FIELDS, log, 500)
    dropped = meta["dropped"] + fleet_meta["dropped"]
    for pattern in patterns:
        if not {"patternId", "source", "ruleId", "severity", "counts"} <= set(pattern):
            raise ShapeError("pattern missing required fields")
        hours = pattern["counts"].get("byHourOfDay")
        if hours is not None and len(hours) != 24:
            raise ShapeError("byHourOfDay must have 24 entries")
        notes = []
        for note in pattern.get("annotations", []):
            if note.get("authorKind") == "service" and "text" in note:
                note = dict(note, text=scrub(clean_text(note["text"], 300)))
            else:
                note = {k: v for k, v in note.items() if k != "text"}
            notes.append(note)
        if "annotations" in pattern:
            pattern["annotations"] = notes[-10:]
    leaks = _value_pii({"patterns": patterns, "fleet": fleet})
    if leaks:
        raise PiiAbort(leaks)
    if dropped:
        log("fields_stripped", fields=sorted(set(re.sub(r"\[\d+\]", "[]", d) for d in dropped))[:50])
    return {"patterns": patterns, "fleet": fleet, "stripped": len(set(dropped))}


def actions_response(raw: Any, log=lambda *a, **k: None) -> list:
    meta, actions = _records(raw, api.ACTIONS_TOP, "actions", api.ACTION_FIELDS, log, 2000)
    leaks = _value_pii(actions)
    if leaks:
        raise PiiAbort(leaks)
    if meta["dropped"]:
        log("fields_stripped", fields=meta["dropped"][:50])
    return actions


def memory_response(raw: Any, log=lambda *a, **k: None) -> dict:
    if not isinstance(raw, dict):
        raise ShapeError("memory response is not an object")
    version = raw.get("version", 0)
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ShapeError("memory version")
    meta, notes = _records({"notes": raw.get("notes", [])}, ("notes",), "notes", api.MEMORY_NOTE_FIELDS, log, 500)
    clean = []
    for note in notes:
        text = scrub(clean_text(note.get("text", ""), 500))
        if text:
            clean.append({"text": text, "kind": note.get("kind", "model"), "createdAt": note.get("createdAt")})
    return {"version": version, "notes": clean}
