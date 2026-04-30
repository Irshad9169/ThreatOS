from __future__ import annotations
import json, re
from dataclasses import dataclass
from typing import Any
import httpx
from threatos.core.settings import settings

TACTIC_ORDER: list[str] = [
    "reconnaissance","resource-development","initial-access","execution",
    "persistence","privilege-escalation","defense-evasion","credential-access",
    "discovery","lateral-movement","collection","command-and-control",
    "exfiltration","impact",
]
_TACTIC_TO_ID: dict[str, str] = {
    "reconnaissance":"TA0043","resource-development":"TA0042",
    "initial-access":"TA0001","execution":"TA0002","persistence":"TA0003",
    "privilege-escalation":"TA0004","defense-evasion":"TA0005",
    "credential-access":"TA0006","discovery":"TA0007","lateral-movement":"TA0008",
    "collection":"TA0009","command-and-control":"TA0011",
    "exfiltration":"TA0010","impact":"TA0040",
}

@dataclass
class ATTCKTechnique:
    id: str; name: str; tactic: str; tactic_id: str
    platforms: list[str]; description: str
    is_subtechnique: bool = False; parent_id: str | None = None

_CACHE: dict[str, ATTCKTechnique] = {}

def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Get attribute from either a dict or an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

def _extract_tid(obj: Any) -> str | None:
    refs = _get(obj, "external_references", [])
    for ref in refs:
        src = _get(ref, "source_name", "")
        eid = _get(ref, "external_id", "")
        if src == "mitre-attack" and re.match(r"^T\d{4}(\.\d{3})?$", str(eid)):
            return str(eid)
    return None

def _extract_tactic(obj: Any) -> tuple[str, str]:
    phases = _get(obj, "kill_chain_phases", [])
    for phase in phases:
        kc = _get(phase, "kill_chain_name", "")
        if kc == "mitre-attack":
            sn = _get(phase, "phase_name", "")
            return sn, _TACTIC_TO_ID.get(sn, "unknown")
    return "unknown", "unknown"

async def load_attck_bundle(url: str = "") -> dict[str, ATTCKTechnique]:
    url = url or settings.attck_bundle_url
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        raw = resp.json()   # parse as plain dict — skip stix2 library entirely

    # raw is {"type":"bundle","objects":[...]}
    objects = raw.get("objects", [])
    techniques: dict[str, ATTCKTechnique] = {}

    for obj in objects:
        if _get(obj, "type") != "attack-pattern":
            continue
        if _get(obj, "x_mitre_deprecated", False):
            continue
        if _get(obj, "revoked", False):
            continue

        tid = _extract_tid(obj)
        if not tid:
            continue

        tactic, tactic_id = _extract_tactic(obj)
        is_sub = bool(_get(obj, "x_mitre_is_subtechnique", False))
        name   = _get(obj, "name", tid)
        desc   = str(_get(obj, "description", "") or "")[:500]
        plats  = list(_get(obj, "x_mitre_platforms", []) or [])

        techniques[tid] = ATTCKTechnique(
            id=tid, name=name, tactic=tactic, tactic_id=tactic_id,
            platforms=plats, description=desc,
            is_subtechnique=is_sub,
            parent_id=tid.split(".")[0] if is_sub else None,
        )

    global _CACHE
    _CACHE = techniques
    return techniques

def get_technique(tid: str) -> ATTCKTechnique | None: return _CACHE.get(tid)
def get_all_technique_ids() -> list[str]: return sorted(_CACHE.keys())
def validate_technique_id(tid: str) -> bool: return tid in _CACHE
def get_tactic_order() -> list[str]: return TACTIC_ORDER.copy()
def override_attck_cache(data: dict[str, ATTCKTechnique]) -> None:
    global _CACHE; _CACHE = data
def get_cache_size() -> int: return len(_CACHE)
