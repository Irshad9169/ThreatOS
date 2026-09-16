"""
core/attck_kb.py
─────────────────
ATT&CK Knowledge Base service.

Loads the official MITRE ATT&CK STIX 2.1 enterprise bundle,
parses every non-deprecated, non-revoked attack-pattern object,
and caches the results as a dict in memory.

Design decisions:
  - Pure in-memory dict — no Redis dependency in Phase 1.
    The dict is module-level so it persists across requests in
    the same process. Workers and routes share the same cache.
  - Download is lazy: load_attck_bundle() must be called explicitly
    at startup. Tests inject their own technique dict via
    override_attck_cache() without network calls.
  - The ATT&CK bundle has ~700 techniques. Full parse takes ~2s.
    After that, every lookup is O(1).

Public API:
  load_attck_bundle(url)          download + parse + cache
  get_technique(tid)              O(1) lookup
  get_all_technique_ids()         list of all known IDs
  validate_technique_id(tid)      bool
  override_attck_cache(data)      inject test data (tests only)
  get_tactic_order()              canonical kill-chain order list
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

ATTCK_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Canonical kill-chain tactic order (Reconnaissance → Impact)
TACTIC_ORDER: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

_TACTIC_TO_ID: dict[str, str] = {
    "reconnaissance":        "TA0043",
    "resource-development":  "TA0042",
    "initial-access":        "TA0001",
    "execution":             "TA0002",
    "persistence":           "TA0003",
    "privilege-escalation":  "TA0004",
    "defense-evasion":       "TA0005",
    "credential-access":     "TA0006",
    "discovery":             "TA0007",
    "lateral-movement":      "TA0008",
    "collection":            "TA0009",
    "command-and-control":   "TA0011",
    "exfiltration":          "TA0010",
    "impact":                "TA0040",
}


@dataclass
class ATTCKTechnique:
    id:              str                  # e.g. "T1059.001"
    name:            str                  # e.g. "PowerShell"
    tactic:          str                  # shortname: "execution"
    tactic_id:       str                  # "TA0002"
    platforms:       list[str]            # ["windows", "linux"]
    description:     str                  # truncated at 500 chars
    is_subtechnique: bool = False
    parent_id:       str | None = None    # "T1059" for sub-techniques


# ── Module-level cache ────────────────────────────────────────────────────────
_CACHE: dict[str, ATTCKTechnique] = {}


# ── Parsing helpers ───────────────────────────────────────────────────────────

def _extract_tid(stix_obj: Any) -> str | None:
    """Extract T-number from STIX external_references list."""
    for ref in getattr(stix_obj, "external_references", []):
        source = ref.get("source_name", "") if isinstance(ref, dict) else getattr(ref, "source_name", "")
        eid    = ref.get("external_id",  "") if isinstance(ref, dict) else getattr(ref, "external_id",  "")
        if source == "mitre-attack" and re.match(r"^T\d{4}(\.\d{3})?$", eid):
            return eid
    return None


def _extract_tactic(stix_obj: Any) -> tuple[str, str]:
    """Return (tactic_shortname, tactic_id) from kill_chain_phases."""
    phases = getattr(stix_obj, "kill_chain_phases", [])
    for phase in phases:
        kc_name = phase.get("kill_chain_name", "") if isinstance(phase, dict) else getattr(phase, "kill_chain_name", "")
        if kc_name == "mitre-attack":
            shortname = phase.get("phase_name", "") if isinstance(phase, dict) else getattr(phase, "phase_name", "")
            return shortname, _TACTIC_TO_ID.get(shortname, "unknown")
    return "unknown", "unknown"


# ── Public API ────────────────────────────────────────────────────────────────

async def load_attck_bundle(url: str = ATTCK_BUNDLE_URL) -> dict[str, ATTCKTechnique]:
    """
    Download and parse the ATT&CK STIX 2.1 bundle.
    Populates the module-level cache and returns it.
    Raises httpx.HTTPError on download failure.
    """
    import stix2

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        raw_json = resp.text

    bundle = stix2.parse(raw_json, allow_custom=True)
    techniques: dict[str, ATTCKTechnique] = {}

    for obj in bundle.objects:
        if obj.type != "attack-pattern":
            continue
        if getattr(obj, "x_mitre_deprecated", False):
            continue
        if getattr(obj, "revoked", False):
            continue

        tid = _extract_tid(obj)
        if not tid:
            continue

        tactic, tactic_id  = _extract_tactic(obj)
        is_sub   = bool(getattr(obj, "x_mitre_is_subtechnique", False))
        parent   = tid.split(".")[0] if is_sub else None
        desc     = str(getattr(obj, "description", "") or "")

        techniques[tid] = ATTCKTechnique(
            id=tid,
            name=obj.name,
            tactic=tactic,
            tactic_id=tactic_id,
            platforms=list(getattr(obj, "x_mitre_platforms", []) or []),
            description=desc[:500],
            is_subtechnique=is_sub,
            parent_id=parent,
        )

    global _CACHE
    _CACHE = techniques
    return techniques


def get_technique(technique_id: str) -> ATTCKTechnique | None:
    """O(1) lookup. Returns None if the technique is unknown."""
    return _CACHE.get(technique_id)


def get_all_technique_ids() -> list[str]:
    """Return a sorted list of all cached technique IDs."""
    return sorted(_CACHE.keys())


def validate_technique_id(technique_id: str) -> bool:
    """True if technique_id exists in the loaded cache."""
    return technique_id in _CACHE


def get_tactic_order() -> list[str]:
    """Return the canonical ATT&CK kill-chain tactic order."""
    return TACTIC_ORDER.copy()


def override_attck_cache(data: dict[str, ATTCKTechnique]) -> None:
    """
    Replace the module-level cache with test data.
    Call this in test fixtures to avoid network calls.
    Always restore after tests: override_attck_cache({})
    """
    global _CACHE
    _CACHE = data


def get_cache_size() -> int:
    """Return number of techniques currently in cache."""
    return len(_CACHE)
