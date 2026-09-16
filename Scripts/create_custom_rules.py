"""
create_custom_rules.py
────────────────────────
Creates custom detection rules in ThreatOS via the API.
Covers: RDP, PSExec, Scheduled Tasks, Malicious Services, SSH Lateral Movement,
        Linux Persistence.

Usage:
    python create_custom_rules.py
    python create_custom_rules.py --url http://localhost:8001
"""
import json, urllib.request, urllib.error, argparse

_config = {"api_base": "http://localhost:8001"}

RULES = [

    # ════════════════════════════════════════════════════════════════
    # LATERAL MOVEMENT — RDP
    # ════════════════════════════════════════════════════════════════
    {
        "name": "[Custom] RDP Brute Force — Multiple Failed Logons",
        "technique_id": "T1110.003",
        "tactic": "credential-access",
        "severity": 7,
        "confidence": 0.85,
        "log_sources": ["winlog"],
        "description": "Multiple failed RDP logon attempts (Event 4625, LogonType 10). "
                       "Indicates password spraying or brute force via Remote Desktop.",
        "tags": ["attack.credential-access","attack.t1110.003","rdp","brute-force"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "event_id",   "operator": "equals",   "value": "4625"},
                {"type": "field_match", "field": "logon_type", "operator": "equals",   "value": "10"},
                {"type": "field_match", "field": "auth_result","operator": "equals",   "value": "failure"},
                {"type": "field_match", "field": "dst_port",   "operator": "equals",   "value": "3389"},
            ],
        },
    },

    {
        "name": "[Custom] RDP Lateral Movement — mstsc to Internal Host",
        "technique_id": "T1021.001",
        "tactic": "lateral-movement",
        "severity": 6,
        "confidence": 0.75,
        "log_sources": ["winlog"],
        "description": "mstsc.exe (Remote Desktop Client) connecting to an internal host. "
                       "Normal admin activity but suspicious if from workstations or off-hours.",
        "tags": ["attack.lateral-movement","attack.t1021.001","rdp"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "process",      "operator": "contains", "value": "mstsc"},
                {"type": "field_match", "field": "command_line",  "operator": "contains", "value": "/v:"},
            ],
        },
    },

    {
        "name": "[Custom] RDP Successful Logon After Failed Attempts",
        "technique_id": "T1021.001",
        "tactic": "lateral-movement",
        "severity": 8,
        "confidence": 0.9,
        "log_sources": ["winlog"],
        "description": "Successful RDP logon (Event 4624, LogonType 10). "
                       "High severity when combined with prior failed attempts on same host.",
        "tags": ["attack.lateral-movement","attack.t1021.001","rdp"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "event_id",    "operator": "equals", "value": "4624"},
                {"type": "field_match", "field": "logon_type",  "operator": "equals", "value": "10"},
                {"type": "field_match", "field": "auth_result", "operator": "equals", "value": "success"},
            ],
        },
    },

    # ════════════════════════════════════════════════════════════════
    # LATERAL MOVEMENT — PSExec
    # ════════════════════════════════════════════════════════════════
    {
        "name": "[Custom] PSExec Service Installed on Remote Host",
        "technique_id": "T1569.002",
        "tactic": "lateral-movement",
        "severity": 9,
        "confidence": 0.95,
        "log_sources": ["winlog"],
        "description": "PSEXESVC.exe service installed (Event 7045). "
                       "PSExec creates this service on the target host. "
                       "Almost always malicious unless explicitly authorised.",
        "tags": ["attack.lateral-movement","attack.t1569.002","psexec"],
        "detection_ast": {
            "type": "or",
            "children": [
                {"type": "field_match", "field": "process",   "operator": "contains", "value": "PSEXESVC"},
                {"type": "field_match", "field": "file_path", "operator": "contains", "value": "PSEXESVC"},
                {
                    "type": "and",
                    "children": [
                        {"type": "field_match", "field": "event_id",     "operator": "equals",   "value": "7045"},
                        {"type": "field_match", "field": "command_line", "operator": "contains", "value": "PSEXESVC"},
                    ],
                },
            ],
        },
    },

    {
        "name": "[Custom] PSExec Execution — psexec.exe Launch",
        "technique_id": "T1021.002",
        "tactic": "lateral-movement",
        "severity": 8,
        "confidence": 0.85,
        "log_sources": ["winlog"],
        "description": "psexec.exe executed with remote host target. "
                       "Attacker using Sysinternals PSExec to execute commands on another host.",
        "tags": ["attack.lateral-movement","attack.t1021.002","psexec"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "process",      "operator": "contains", "value": "psexec"},
                {"type": "field_match", "field": "command_line",  "operator": "contains", "value": "\\\\"},
            ],
        },
    },

    {
        "name": "[Custom] Suspicious Command via PSExec (cmd spawned by PSEXESVC)",
        "technique_id": "T1569.002",
        "tactic": "execution",
        "severity": 9,
        "confidence": 0.9,
        "log_sources": ["winlog"],
        "description": "cmd.exe or powershell.exe with PSEXESVC as parent process. "
                       "Commands run via PSExec are often recon or privilege escalation.",
        "tags": ["attack.execution","attack.t1569.002","psexec"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "parent_process", "operator": "contains", "value": "PSEXESVC"},
                {
                    "type": "or",
                    "children": [
                        {"type": "field_match", "field": "process", "operator": "contains", "value": "cmd.exe"},
                        {"type": "field_match", "field": "process", "operator": "contains", "value": "powershell"},
                    ],
                },
            ],
        },
    },

    # ════════════════════════════════════════════════════════════════
    # PERSISTENCE — Scheduled Tasks
    # ════════════════════════════════════════════════════════════════
    {
        "name": "[Custom] Scheduled Task Created via schtasks.exe",
        "technique_id": "T1053.005",
        "tactic": "persistence",
        "severity": 7,
        "confidence": 0.8,
        "log_sources": ["winlog"],
        "description": "schtasks.exe /create detected. Attackers commonly use scheduled "
                       "tasks for persistence. High severity if created under SYSTEM or "
                       "pointing to unusual paths.",
        "tags": ["attack.persistence","attack.t1053.005","scheduled-task"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "process",      "operator": "contains", "value": "schtasks"},
                {"type": "field_match", "field": "command_line",  "operator": "contains", "value": "/create"},
            ],
        },
    },

    {
        "name": "[Custom] Scheduled Task with Hidden PowerShell Payload",
        "technique_id": "T1053.005",
        "tactic": "persistence",
        "severity": 9,
        "confidence": 0.95,
        "log_sources": ["winlog"],
        "description": "Scheduled task created with -WindowStyle Hidden and -EncodedCommand. "
                       "This combination is a strong indicator of malicious intent — "
                       "legitimate software rarely uses both.",
        "tags": ["attack.persistence","attack.t1053.005","powershell","scheduled-task"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "command_line", "operator": "contains", "value": "WindowStyle Hidden"},
                {"type": "field_match", "field": "command_line", "operator": "contains", "value": "EncodedCommand"},
            ],
        },
    },

    {
        "name": "[Custom] Scheduled Task Pointing to Suspicious Path",
        "technique_id": "T1053.005",
        "tactic": "persistence",
        "severity": 8,
        "confidence": 0.85,
        "log_sources": ["winlog"],
        "description": "Scheduled task binary in Users, Temp, AppData, or ProgramData. "
                       "Legitimate scheduled tasks almost never run from user-writable paths.",
        "tags": ["attack.persistence","attack.t1053.005","scheduled-task"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "process", "operator": "contains", "value": "schtasks"},
                {
                    "type": "or",
                    "children": [
                        {"type": "field_match", "field": "command_line", "operator": "contains", "value": "\\Users\\Public"},
                        {"type": "field_match", "field": "command_line", "operator": "contains", "value": "\\Temp\\"},
                        {"type": "field_match", "field": "command_line", "operator": "contains", "value": "\\AppData\\"},
                        {"type": "field_match", "field": "command_line", "operator": "contains", "value": "\\ProgramData\\"},
                    ],
                },
            ],
        },
    },

    # ════════════════════════════════════════════════════════════════
    # PERSISTENCE — Malicious Windows Service
    # ════════════════════════════════════════════════════════════════
    {
        "name": "[Custom] New Service Created via sc.exe",
        "technique_id": "T1543.003",
        "tactic": "persistence",
        "severity": 7,
        "confidence": 0.75,
        "log_sources": ["winlog"],
        "description": "sc.exe create used to install a new Windows service. "
                       "Review the binary path — legitimate services rarely install from "
                       "Temp, Users, or ProgramData.",
        "tags": ["attack.persistence","attack.t1543.003","service"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "process",     "operator": "contains", "value": "sc.exe"},
                {"type": "field_match", "field": "command_line", "operator": "contains", "value": "create"},
            ],
        },
    },

    {
        "name": "[Custom] Service Binary Running from Suspicious Path",
        "technique_id": "T1543.003",
        "tactic": "persistence",
        "severity": 9,
        "confidence": 0.9,
        "log_sources": ["winlog"],
        "description": "A process running with services.exe as parent from a "
                       "user-writable path (Temp, Users, ProgramData). "
                       "Legitimate services run from System32, Program Files, etc.",
        "tags": ["attack.persistence","attack.t1543.003","service"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "parent_process", "operator": "contains", "value": "services.exe"},
                {
                    "type": "or",
                    "children": [
                        {"type": "field_match", "field": "file_path", "operator": "contains", "value": "\\Temp\\"},
                        {"type": "field_match", "field": "file_path", "operator": "contains", "value": "\\Users\\"},
                        {"type": "field_match", "field": "file_path", "operator": "contains", "value": "\\ProgramData\\"},
                        {"type": "field_match", "field": "command_line", "operator": "contains", "value": "\\Temp\\"},
                    ],
                },
            ],
        },
    },

    # ════════════════════════════════════════════════════════════════
    # PERSISTENCE — Linux
    # ════════════════════════════════════════════════════════════════
    {
        "name": "[Custom] Linux Crontab Modified by Non-Root User",
        "technique_id": "T1053.003",
        "tactic": "persistence",
        "severity": 7,
        "confidence": 0.8,
        "log_sources": ["syslog"],
        "description": "crontab -e or crontab modification by a non-privileged user. "
                       "Web application users (www-data, nginx, apache) should never "
                       "modify crontabs.",
        "tags": ["attack.persistence","attack.t1053.003","linux","cron"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "process",      "operator": "equals",   "value": "crontab"},
                {"type": "field_match", "field": "command_line",  "operator": "contains", "value": "crontab"},
            ],
        },
    },

    {
        "name": "[Custom] Linux Reverse Shell via Bash TCP Redirect",
        "technique_id": "T1059.004",
        "tactic": "execution",
        "severity": 10,
        "confidence": 0.98,
        "log_sources": ["syslog"],
        "description": "bash -i >& /dev/tcp/ pattern — classic reverse shell. "
                       "This is almost never legitimate. Immediate investigation required.",
        "tags": ["attack.execution","attack.t1059.004","linux","reverse-shell"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "command_line", "operator": "contains", "value": "/dev/tcp/"},
                {"type": "field_match", "field": "command_line", "operator": "contains", "value": "bash"},
            ],
        },
    },

    {
        "name": "[Custom] SSH Authorized Keys Modified",
        "technique_id": "T1098.004",
        "tactic": "persistence",
        "severity": 8,
        "confidence": 0.9,
        "log_sources": ["syslog"],
        "description": "authorized_keys file written or appended. Attackers add their "
                       "SSH public key for persistent passwordless access. "
                       "Any modification to this file outside of your provisioning tool is suspicious.",
        "tags": ["attack.persistence","attack.t1098.004","linux","ssh"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "file_path",   "operator": "contains", "value": "authorized_keys"},
                {"type": "field_match", "field": "command_line", "operator": "contains", "value": "authorized_keys"},
            ],
        },
    },

    {
        "name": "[Custom] Linux SSH Lateral Movement — SSH from /tmp Key",
        "technique_id": "T1021.004",
        "tactic": "lateral-movement",
        "severity": 8,
        "confidence": 0.85,
        "log_sources": ["syslog"],
        "description": "SSH connection using a key file from /tmp or /dev/shm. "
                       "Legitimate SSH keys are never stored in temp directories. "
                       "This indicates a stolen or planted key being used for lateral movement.",
        "tags": ["attack.lateral-movement","attack.t1021.004","linux","ssh"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "process",      "operator": "equals",   "value": "ssh"},
                {
                    "type": "or",
                    "children": [
                        {"type": "field_match", "field": "command_line", "operator": "contains", "value": "/tmp/"},
                        {"type": "field_match", "field": "command_line", "operator": "contains", "value": "/dev/shm"},
                    ],
                },
            ],
        },
    },

    {
        "name": "[Custom] Post-SSH Recon Commands",
        "technique_id": "T1087.001",
        "tactic": "discovery",
        "severity": 6,
        "confidence": 0.7,
        "log_sources": ["syslog"],
        "description": "Classic post-compromise recon: reading /etc/passwd, /etc/shadow, "
                       "running id, uname. Indicates an attacker mapping a newly compromised host.",
        "tags": ["attack.discovery","attack.t1087.001","linux","recon"],
        "detection_ast": {
            "type": "and",
            "children": [
                {"type": "field_match", "field": "command_line", "operator": "contains", "value": "/etc/passwd"},
                {"type": "field_match", "field": "command_line", "operator": "contains", "value": "/etc/shadow"},
            ],
        },
    },
]

def api_post(endpoint, data):
    url     = f"{_config["api_base"]}{endpoint}"
    payload = json.dumps(data).encode()
    req     = urllib.request.Request(url, data=payload,
                headers={"Content-Type":"application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())
    except Exception as exc:
        return 0, {"error": str(exc)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8001")
    args = parser.parse_args()
    _config["api_base"] = args.url.rstrip("/")

    print(f"Creating {len(RULES)} custom detection rules in ThreatOS...\n")
    created = 0; skipped = 0; errors = 0

    for rule in RULES:
        status, resp = api_post("/api/rules", rule)
        if status == 201:
            print(f"  ✅ {rule['name'][:70]}")
            created += 1
        elif status == 409:
            print(f"  ⏭  {rule['name'][:70]}  (already exists)")
            skipped += 1
        else:
            print(f"  ❌ {rule['name'][:70]}  → {status}: {resp}")
            errors += 1

    print(f"\n{'='*60}")
    print(f"  Created: {created}  |  Skipped: {skipped}  |  Errors: {errors}")
    print(f"\nNext steps:")
    print(f"  1. Run: python simulate_threats.py")
    print(f"  2. Wait 3 seconds")
    print(f"  3. Check: curl -s http://localhost:8001/api/alerts | python -m json.tool")
    print(f"  4. Or open the UI: http://YOUR_SERVER_IP:8080")

if __name__ == "__main__":
    main()

