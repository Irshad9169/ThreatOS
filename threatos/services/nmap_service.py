from __future__ import annotations
import asyncio, uuid, xml.etree.ElementTree as ET
from datetime import UTC, datetime
from typing import Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.core.settings import settings
from threatos.models.scan_result import ScanResult

SCAN_FLAGS: dict[str, list[str]] = {
    "quick":   ["-T4", "-F"],
    "full":    ["-T4", "-p-"],
    "stealth": ["-sS", "-T2", "-p-"],
    "udp":     ["-sU", "-T3", "--top-ports", "200"],
    "vuln":    ["-T4", "--script", "vuln"],
}

def _parse_nmap_xml(xml_str: str) -> dict[str, Any]:
    try: root = ET.fromstring(xml_str)
    except ET.ParseError: return {"error": "invalid_xml", "hosts_up": 0, "hosts_down": 0, "open_ports": [], "os_guesses": [], "hosts": []}
    hosts_up = 0; hosts_down = 0; open_ports = []; os_guesses = []; hosts_data = []
    for host in root.findall("host"):
        status = host.find("status")
        state  = status.get("state","unknown") if status is not None else "unknown"
        if state == "up": hosts_up += 1
        else: hosts_down += 1; continue
        addr_el = host.find("address[@addrtype='ipv4']") or host.find("address")
        host_ip = addr_el.get("addr","unknown") if addr_el is not None else "unknown"
        host_ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                ps = port_el.find("state")
                if ps is None or ps.get("state") != "open": continue
                svc_el = port_el.find("service")
                svc    = svc_el.get("name","unknown") if svc_el is not None else "unknown"
                info   = {"host": host_ip, "port": int(port_el.get("portid",0)),
                          "protocol": port_el.get("protocol","tcp"), "service": svc, "state": "open"}
                host_ports.append(info); open_ports.append(info)
        os_el = host.find("os")
        if os_el is not None:
            for match in os_el.findall("osmatch"):
                os_guesses.append({"host": host_ip, "os_guess": match.get("name","unknown"),
                                   "accuracy": int(match.get("accuracy",0))})
        hosts_data.append({"host": host_ip, "state": state, "ports": host_ports})
    return {"hosts_up": hosts_up, "hosts_down": hosts_down,
            "open_ports": open_ports, "os_guesses": os_guesses, "hosts": hosts_data}

async def _run_nmap(target: str, scan_type: str, timeout: int) -> tuple[str, str | None]:
    flags = SCAN_FLAGS.get(scan_type, SCAN_FLAGS["quick"])
    cmd   = [settings.nmap_binary_path, "-oX", "-"] + flags + [target]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=float(timeout))
        if proc.returncode != 0:
            return "", f"Nmap exited {proc.returncode}: {stderr.decode()[:300]}"
        return stdout.decode(), None
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        return "", f"Scan timed out after {timeout}s"
    except FileNotFoundError:
        return "", f"Nmap binary not found at {settings.nmap_binary_path}"
    except Exception as exc:
        return "", str(exc)[:300]

async def create_scan(db: AsyncSession, target: str, scan_type: str = "quick",
                      requested_by: str | None = None) -> ScanResult:
    if scan_type not in SCAN_FLAGS:
        raise ValueError(f"Unknown scan_type {scan_type!r}. Must be one of: {list(SCAN_FLAGS)}")
    scan = ScanResult(id=str(uuid.uuid4()), target=target.strip(),
                      scan_type=scan_type, status="pending", requested_by=requested_by)
    db.add(scan); await db.flush(); return scan

async def run_scan(db: AsyncSession, scan_id: str, timeout: int | None = None) -> ScanResult:
    result = await db.execute(select(ScanResult).where(ScanResult.id == scan_id))
    scan   = result.scalar_one_or_none()
    if scan is None: raise ValueError(f"Scan {scan_id!r} not found")
    if scan.status not in ("pending",): raise ValueError(f"Scan status is {scan.status!r} — cannot run")
    t = timeout or settings.nmap_default_timeout
    scan.status = "running"; scan.started_at = datetime.now(UTC); await db.flush()
    xml_out, err = await _run_nmap(scan.target, scan.scan_type, t)
    scan.finished_at = datetime.now(UTC)
    scan.duration_s  = (scan.finished_at - scan.started_at).total_seconds()
    if err:
        scan.status = "failed"; scan.error_detail = err; scan.scan_data = {"error": err}
    else:
        parsed = _parse_nmap_xml(xml_out)
        scan.status = "completed"; scan.hosts_up = parsed.get("hosts_up",0)
        scan.hosts_down = parsed.get("hosts_down",0)
        scan.open_ports = parsed.get("open_ports",[])
        scan.os_guesses = parsed.get("os_guesses",[])
        scan.scan_data  = parsed
    await db.flush(); return scan

async def get_scan(db: AsyncSession, scan_id: str) -> ScanResult | None:
    result = await db.execute(select(ScanResult).where(ScanResult.id == scan_id))
    return result.scalar_one_or_none()

async def list_scans(db: AsyncSession, target: str | None = None,
                     status: str | None = None, limit: int = 50,
                     offset: int = 0) -> list[ScanResult]:
    q = select(ScanResult).order_by(ScanResult.started_at.desc()).limit(limit).offset(offset)
    if target: q = q.where(ScanResult.target == target.strip())
    if status: q = q.where(ScanResult.status == status)
    result = await db.execute(q)
    return list(result.scalars().all())
