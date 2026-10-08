"""Hermes Warden: blakSOC's in-cluster SOC noise analyst.

A deterministic controller (controller.py) reads anonymised alert patterns from the blakSOC tuning API,
runs one Hermes AIAgent with only its memory tool and the blakSOC tuning toolset (toolset.py), enforces
local guardrails on every write (policy.py), syncs memory with blakSOC (memory.py) and submits a
PII-free run report (report.py). Everything that knows the wire format lives in api.py.
"""
