"""
scripts/import_sigma_rules.py
Download SigmaHQ rules daily, convert to ThreatOS AST, upsert via API.
"""
from __future__ import annotations
import argparse, hashlib, json, logging, os, re, shutil, sys, tempfile
import urllib.request, zipfile
from pathlib import Path
from typing import Any
import yaml

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger(__name__)

SIGMA_ZIP_URL = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
RULE_DIRS = ["rules/windows","rules/linux","rules/network","rules/cloud","rules/application"]
API_BASE  = os.environ.get("THREATOS_API", "http://localhost:8001")
_api_base = API_BASE

# ── Field name mapping ────────────────────────────────────────────────────────
FIELD_MAP = {
    "CommandLine":"command_line","Image":"process","ParentImage":"parent_process",
    "OriginalFileName":"process","ProcessName":"process","User":"user",
    "SubjectUserName":"user","TargetUserName":"user","ComputerName":"host",
    "Hostname":"host","DestinationIp":"dst_ip","DestinationPort":"dst_port",
    "SourceIp":"src_ip","SourcePort":"src_port","TargetFilename":"file_path",
    "TargetObject":"file_path","FilePath":"file_path","Hashes":"file_hash",
    "md5":"file_hash","sha256":"file_hash","EventID":"event_id",
    "LogonType":"logon_type","ServiceName":"process",
    "ScriptBlockText":"command_line","Payload":"command_line","Message":"message",
}

def norm_field(f: str) -> str:
    return FIELD_MAP.get(f, f.lower())

def value_to_node(field: str, modifier: str, value: Any) -> dict | None:
    v = str(value) if value is not None else ""
    if not v or v in ("null","None","*","'*'"): return None
    mod = modifier.lower()
    if mod in ("contains","contains|all"):
        v2 = v.strip("*")
        return None if not v2 else {"type":"field_match","field":field,"operator":"contains","value":v2}
    if mod == "startswith":
        return {"type":"field_match","field":field,"operator":"starts_with","value":v.rstrip("*")}
    if mod == "endswith":
        return {"type":"field_match","field":field,"operator":"ends_with","value":v.lstrip("*")}
    if mod in ("re","regex"):
        return {"type":"field_match","field":field,"operator":"regex","value":v}
    if mod == "exists":
        return {"type":"field_match","field":field,"operator":"exists"}
    # equals with possible wildcards
    if "*" in v:
        stripped = v.strip("*")
        if not stripped: return None
        if v.startswith("*") and v.endswith("*"):
            return {"type":"field_match","field":field,"operator":"contains","value":stripped}
        if v.startswith("*"):
            return {"type":"field_match","field":field,"operator":"ends_with","value":stripped}
        if v.endswith("*"):
            return {"type":"field_match","field":field,"operator":"starts_with","value":stripped}
    return {"type":"field_match","field":field,"operator":"equals","value":v}

def selection_to_ast(selection: Any) -> dict | None:
    if selection is None: return None
    if isinstance(selection, list):
        nodes = [{"type":"field_match","field":"message","operator":"contains","value":str(v)}
                 for v in selection[:10] if str(v).strip("*")]
        if not nodes: return None
        return {"type":"or","children":nodes} if len(nodes)>1 else nodes[0]
    if not isinstance(selection, dict): return None
    nodes: list[dict] = []
    for field_expr, values in selection.items():
        parts    = field_expr.split("|")
        field    = norm_field(parts[0].strip())
        modifier = parts[1] if len(parts) > 1 else "equals"
        vals     = values if isinstance(values, list) else [values]
        fnodes   = [n for v in vals[:10] if (n := value_to_node(field, modifier, v))]
        if not fnodes: continue
        nodes.append({"type":"or","children":fnodes} if len(fnodes)>1 else fnodes[0])
    if not nodes: return None
    return {"type":"and","children":nodes} if len(nodes)>1 else nodes[0]

def detection_to_ast(detection: dict) -> dict | None:
    if not detection: return None
    condition = str(detection.get("condition","")).strip().lower()
    if any(x in condition for x in [" | ","count(","sum(","near"]): return None
    children = []
    for key, value in detection.items():
        if key in ("condition","timeframe") or key.startswith("filter"): continue
        part = selection_to_ast(value)
        if part: children.append(part)
    if not children: return None
    if "1 of" in condition or (" or " in condition and " and " not in condition):
        return {"type":"or","children":children} if len(children)>1 else children[0]
    return {"type":"and","children":children} if len(children)>1 else children[0]

# ── ATT&CK tag extraction ─────────────────────────────────────────────────────
TACTIC_MAP = {
    "reconnaissance":"reconnaissance","resource_development":"resource-development",
    "initial_access":"initial-access","execution":"execution",
    "persistence":"persistence","privilege_escalation":"privilege-escalation",
    "defense_evasion":"defense-evasion","credential_access":"credential-access",
    "discovery":"discovery","lateral_movement":"lateral-movement",
    "collection":"collection","command_and_control":"command-and-control",
    "exfiltration":"exfiltration","impact":"impact",
}

def extract_attck(tags: list[str]) -> tuple[str | None, str | None]:
    technique_id = None; tactic = None
    for tag in tags:
        tag = tag.lower()
        if tag.startswith("attack.t"):
            raw = tag.replace("attack.","").upper()
            # Normalize T1059_001 → T1059.001
            raw = re.sub(r"T(\d{4})_(\d{3})", r"T\1.\2", raw)
            if re.match(r"^T\d{4}(\.\d{3})?$", raw):
                technique_id = raw
        elif tag.startswith("attack."):
            slug = tag.replace("attack.","").replace(".","_")
            if slug in TACTIC_MAP:
                tactic = TACTIC_MAP[slug]
    return technique_id, tactic

def sigma_level_to_severity(level: str) -> int:
    return {"critical":9,"high":7,"medium":5,"low":3,"informational":2}.get(
        (level or "medium").lower(), 5)

# ── Log source → list ─────────────────────────────────────────────────────────
def logsource_to_list(logsource: dict) -> list[str]:
    parts = []
    for k in ("category","product","service"):
        v = logsource.get(k)
        if v: parts.append(str(v).lower())
    return parts

# ── Parse one Sigma YAML file ─────────────────────────────────────────────────
def parse_sigma_file(path: Path) -> dict | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            doc = yaml.safe_load(f)
        if not isinstance(doc, dict): return None
        if doc.get("status") in ("deprecated","unsupported"): return None

        tags = doc.get("tags") or []
        technique_id, tactic = extract_attck(tags)
        if not technique_id: return None   # skip rules without ATT&CK mapping

        detection = doc.get("detection")
        if not detection: return None
        ast = detection_to_ast(detection)
        if not ast: return None

        logsource  = doc.get("logsource") or {}
        log_srcs   = logsource_to_list(logsource)
        title      = str(doc.get("title","") or path.stem)[:200]
        level      = doc.get("level","medium")
        severity   = sigma_level_to_severity(level)
        confidence = {"critical":0.95,"high":0.85,"medium":0.7,"low":0.5}.get(
            level.lower(), 0.7)

        # Stable unique name: hash of file path relative to sigma root
        rule_name = f"[Sigma] {title}"[:200]

        return {
            "name":         rule_name,
            "technique_id": technique_id,
            "tactic":       tactic or "unknown",
            "severity":     severity,
            "confidence":   confidence,
            "detection_ast":ast,
            "log_sources":  log_srcs,
            "platforms":    [logsource.get("product","").lower()] if logsource.get("product") else [],
            "tags":         [t for t in tags if t.startswith("attack.")],
            "author":       str(doc.get("author","SigmaHQ"))[:100],
            "description":  str(doc.get("description","") or "")[:1000],
            "enabled":      True,
        }
    except Exception as exc:
        log.debug("Skip %s: %s", path.name, exc)
        return None

# ── API helpers ───────────────────────────────────────────────────────────────
def api_post(endpoint: str, data: dict) -> dict | None:
    import urllib.error
    url     = f"{_api_base}{endpoint}"
    payload = json.dumps(data).encode()
    req     = urllib.request.Request(url, data=payload,
                headers={"Content-Type":"application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:200]
        if e.code == 409:
            return {"_conflict": True}
        log.debug("HTTP %d for %s: %s", e.code, endpoint, body)
        return None
    except Exception as exc:
        log.debug("Request failed: %s", exc)
        return None

# ── Download & extract ────────────────────────────────────────────────────────
def download_sigma(dest_dir: Path) -> Path:
    zip_path = dest_dir / "sigma.zip"
    log.info("Downloading SigmaHQ master.zip (~30MB)...")
    urllib.request.urlretrieve(SIGMA_ZIP_URL, zip_path)
    log.info("Extracting...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest_dir)
    # Find extracted root
    roots = [p for p in dest_dir.iterdir() if p.is_dir() and p.name.startswith("sigma")]
    if not roots:
        raise RuntimeError("Could not find extracted sigma directory")
    return roots[0]

# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="Import Sigma rules into ThreatOS")
    parser.add_argument("--dry-run",  action="store_true", help="Parse only, no API calls")
    parser.add_argument("--url",      default=API_BASE,    help="ThreatOS API base URL")
    parser.add_argument("--max",      type=int, default=0, help="Max rules to import (0=all)")
    args = parser.parse_args()

    global _api_base
    _api_base = args.url.rstrip("/")

    tmp = Path(tempfile.mkdtemp(prefix="sigma_"))
    try:
        sigma_root = download_sigma(tmp)

        # Collect all yaml files from target dirs
        yaml_files: list[Path] = []
        for rule_dir in RULE_DIRS:
            rp = sigma_root / rule_dir
            if rp.exists():
                yaml_files.extend(rp.rglob("*.yml"))

        log.info("Found %d rule files across %d directories", len(yaml_files), len(RULE_DIRS))

        parsed   = 0
        imported = 0
        skipped  = 0
        errors   = 0
        no_attck = 0

        for i, yaml_file in enumerate(yaml_files):
            if args.max and imported >= args.max:
                break

            rule = parse_sigma_file(yaml_file)
            if rule is None:
                no_attck += 1
                continue

            parsed += 1

            if args.dry_run:
                imported += 1
                if imported % 100 == 0:
                    log.info("Dry-run: %d rules parsed so far...", imported)
                continue

            result = api_post("/api/rules", rule)
            if result is None:
                errors += 1
            elif result.get("_conflict"):
                skipped += 1   # rule already exists — OK
            else:
                imported += 1
                if imported % 50 == 0:
                    log.info("Imported %d rules...", imported)

        log.info("=" * 50)
        log.info("Done!")
        log.info("  Parsed (ATT&CK-mapped):  %d", parsed)
        log.info("  Imported:                %d", imported)
        log.info("  Already existed (skip):  %d", skipped)
        log.info("  No ATT&CK tag (skip):    %d", no_attck)
        log.info("  Errors:                  %d", errors)

        if not args.dry_run and imported > 0:
            log.info("Triggering coverage refresh...")
            result = api_post("/api/coverage/refresh", {})
            if result:
                log.info("Coverage: %d/%d techniques (%.1f%%)",
                         result.get("covered",0),
                         result.get("total_techniques",0),
                         result.get("coverage_pct",0.0))

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    main()
