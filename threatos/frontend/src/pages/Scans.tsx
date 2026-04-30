import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scansApi } from '../lib/api'
import { Badge } from '../components/Badge'

const SCAN_TYPES = ['quick', 'full', 'stealth', 'udp', 'vuln']

export function Scans() {
  const qc    = useQueryClient()
  const scans = useQuery({ queryKey: ['scans'], queryFn: scansApi.list, refetchInterval: 5000 })
  const [target, setTarget] = useState('')
  const [type,   setType]   = useState('quick')
  const [sel,    setSel]    = useState<string | null>(null)

  const run = useMutation({
    mutationFn: () => scansApi.run(target, type),
    onSuccess:  () => { qc.invalidateQueries({ queryKey: ['scans'] }); setTarget('') },
  })

  const selected = scans.data?.find(s => s.id === sel)

  const statusColor = (s: string) =>
    s === 'completed' ? 'var(--green)' : s === 'failed' ? 'var(--red)' :
    s === 'running'   ? 'var(--yellow)' : 'var(--muted)'

  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 16 }}>Nmap Scans</h1>

      <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 16 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>New Scan</h3>
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>Target (IP / CIDR / hostname)</label>
            <input value={target} onChange={e => setTarget(e.target.value)}
              placeholder="e.g. 192.168.1.0/24"
              style={{ width: '100%', background: 'var(--bg3)', border: '1px solid var(--border)',
                borderRadius: 4, padding: '7px 10px', color: 'var(--text)', fontSize: 13 }} />
          </div>
          <div>
            <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>Scan Type</label>
            <select value={type} onChange={e => setType(e.target.value)}
              style={{ background: 'var(--bg3)', border: '1px solid var(--border)',
                color: 'var(--text)', borderRadius: 4, padding: '7px 12px', fontSize: 13 }}>
              {SCAN_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <button onClick={() => target && run.mutate()} disabled={run.isPending || !target}
            style={{ padding: '7px 20px', background: 'var(--accent)', color: 'white',
              border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 600,
              opacity: run.isPending ? 0.7 : 1 }}>
            {run.isPending ? 'Scanning...' : '▶ Run Scan'}
          </button>
        </div>
        {run.isPending && (
          <div style={{ marginTop: 10, fontSize: 12, color: 'var(--yellow)' }}>
            ⏳ Scan running — this may take up to 2 minutes...
          </div>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: sel ? '1fr 1fr' : '1fr', gap: 16 }}>
        <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>{['Target','Type','Status','Hosts Up','Ports','Duration','Time'].map(h => (
                <th key={h} style={{ textAlign: 'left', padding: '8px 12px',
                  borderBottom: '1px solid var(--border)', color: 'var(--muted)',
                  fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {scans.data?.length === 0
                ? <tr><td colSpan={7} style={{ padding: 24, textAlign: 'center', color: 'var(--muted)' }}>No scans yet</td></tr>
                : scans.data?.map(s => (
                  <tr key={s.id} onClick={() => setSel(sel === s.id ? null : s.id)}
                    style={{ borderBottom: '1px solid var(--border)22', cursor: 'pointer',
                      background: sel === s.id ? 'var(--bg3)' : 'transparent' }}>
                    <td style={{ padding: '10px 12px', fontSize: 13, fontFamily: 'monospace' }}>{s.target}</td>
                    <td style={{ padding: '10px 12px' }}><Badge label={s.scan_type} color="var(--accent)" /></td>
                    <td style={{ padding: '10px 12px' }}><Badge label={s.status} color={statusColor(s.status)} /></td>
                    <td style={{ padding: '10px 12px', textAlign: 'center' }}>{s.hosts_up}</td>
                    <td style={{ padding: '10px 12px', textAlign: 'center' }}>{s.open_ports.length}</td>
                    <td style={{ padding: '10px 12px', color: 'var(--muted)', fontSize: 12 }}>{s.duration_s ? `${s.duration_s.toFixed(1)}s` : '—'}</td>
                    <td style={{ padding: '10px 12px', color: 'var(--muted)', fontSize: 11 }}>
                      {s.started_at ? new Date(s.started_at).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>

        {selected && (
          <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
              <h3 style={{ fontSize: 14, fontWeight: 600 }}>{selected.target}</h3>
              <button onClick={() => setSel(null)}
                style={{ background: 'none', border: 'none', color: 'var(--muted)', cursor: 'pointer', fontSize: 16 }}>✕</button>
            </div>
            {selected.error_detail && (
              <div style={{ background: 'var(--red)11', border: '1px solid var(--red)33', borderRadius: 6, padding: 10, marginBottom: 12, fontSize: 12, color: 'var(--red)' }}>
                {selected.error_detail}
              </div>
            )}
            {selected.open_ports.length > 0 && (
              <>
                <h4 style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Open Ports</h4>
                <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 12 }}>
                  <thead>
                    <tr>{['Host','Port','Protocol','Service'].map(h => (
                      <th key={h} style={{ textAlign: 'left', padding: '4px 8px', fontSize: 10,
                        color: 'var(--muted)', borderBottom: '1px solid var(--border)' }}>{h}</th>
                    ))}</tr>
                  </thead>
                  <tbody>
                    {selected.open_ports.map((p, i) => (
                      <tr key={i}>
                        <td style={{ padding: '4px 8px', fontSize: 12, fontFamily: 'monospace' }}>{p.host}</td>
                        <td style={{ padding: '4px 8px', fontSize: 12, color: 'var(--accent)', fontWeight: 700 }}>{p.port}</td>
                        <td style={{ padding: '4px 8px', fontSize: 12 }}>{p.protocol}</td>
                        <td style={{ padding: '4px 8px', fontSize: 12 }}>{p.service}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
            {selected.os_guesses.length > 0 && (
              <>
                <h4 style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>OS Detection</h4>
                {selected.os_guesses.slice(0, 3).map((g, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', fontSize: 12 }}>
                    <span>{g.os_guess}</span>
                    <span style={{ color: 'var(--muted)' }}>{g.accuracy}%</span>
                  </div>
                ))}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
