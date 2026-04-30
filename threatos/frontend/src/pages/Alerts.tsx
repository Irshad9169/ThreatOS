import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { alertsApi } from '../lib/api'
import { Table } from '../components/Table'
import { Badge } from '../components/Badge'

function riskColor(s: number) {
  return s >= 80 ? 'var(--red)' : s >= 60 ? 'var(--orange)' : s >= 40 ? 'var(--yellow)' : 'var(--green)'
}

export function Alerts() {
  const qc     = useQueryClient()
  const [status, setStatus] = useState('')
  const alerts = useQuery({
    queryKey: ['alerts', status],
    queryFn:  () => alertsApi.list({ status: status || undefined, limit: 100 }),
    refetchInterval: 10000,
  })
  const update = useMutation({
    mutationFn: ({ id, s }: { id: string; s: string }) => alertsApi.updateStatus(id, s),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  })

  const rows = (alerts.data ?? []).map(a => [
    <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{a.id.slice(0, 8)}</span>,
    <Badge label={a.technique_id} color="var(--accent)" />,
    a.tactic,
    a.entity_host ?? '—',
    a.entity_user ?? '—',
    <span style={{ fontWeight: 700, color: riskColor(a.risk_score) }}>{a.risk_score}</span>,
    <Badge label={a.status}
      color={a.status === 'open' ? 'var(--red)' : a.status === 'closed' ? 'var(--muted)' : 'var(--yellow)'} />,
    new Date(a.created_at).toLocaleString(),
    <div style={{ display: 'flex', gap: 4 }}>
      {a.status === 'open' && (
        <button onClick={() => update.mutate({ id: a.id, s: 'investigating' })}
          style={{ fontSize: 11, padding: '2px 8px', background: 'var(--yellow)22',
            color: 'var(--yellow)', border: '1px solid var(--yellow)44', borderRadius: 4 }}>
          Investigate
        </button>
      )}
      {a.status !== 'closed' && (
        <button onClick={() => update.mutate({ id: a.id, s: 'closed' })}
          style={{ fontSize: 11, padding: '2px 8px', background: 'var(--green)22',
            color: 'var(--green)', border: '1px solid var(--green)44', borderRadius: 4 }}>
          Close
        </button>
      )}
    </div>,
  ])

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700 }}>Alerts</h1>
        <div style={{ display: 'flex', gap: 8 }}>
          {['', 'open', 'investigating', 'closed'].map(s => (
            <button key={s} onClick={() => setStatus(s)}
              style={{ padding: '5px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                background: status === s ? 'var(--accent)' : 'var(--bg3)',
                color: status === s ? 'white' : 'var(--muted)',
                border: '1px solid var(--border)' }}>
              {s || 'All'}
            </button>
          ))}
        </div>
      </div>
      <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8 }}>
        <Table
          headers={['ID', 'Technique', 'Tactic', 'Host', 'User', 'Risk', 'Status', 'Time', 'Actions']}
          rows={rows}
          empty="No alerts found"
        />
      </div>
    </div>
  )
}
