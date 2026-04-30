import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { chainsApi } from '../lib/api'
import { Badge } from '../components/Badge'

function riskColor(s: number) {
  return s >= 80 ? 'var(--red)' : s >= 60 ? 'var(--orange)' : s >= 40 ? 'var(--yellow)' : 'var(--green)'
}

export function Chains() {
  const qc     = useQueryClient()
  const chains = useQuery({ queryKey: ['chains'], queryFn: () => chainsApi.list(), refetchInterval: 15000 })
  const [host, setHost] = useState('')
  const correlate = useMutation({
    mutationFn: (h: string) => chainsApi.correlate(h),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['chains'] }),
  })
  const updateStatus = useMutation({
    mutationFn: ({ id, s }: { id: string; s: string }) => chainsApi.updateStatus(id, s),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['chains'] }),
  })

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700 }}>Attack Chains</h1>
        <div style={{ display: 'flex', gap: 8 }}>
          <input value={host} onChange={e => setHost(e.target.value)}
            placeholder="hostname to correlate..."
            style={{ background: 'var(--bg3)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '6px 12px', color: 'var(--text)', fontSize: 13, width: 220 }} />
          <button onClick={() => host && correlate.mutate(host)}
            style={{ padding: '7px 16px', background: 'var(--accent)', color: 'white',
              border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 600 }}>
            Correlate
          </button>
        </div>
      </div>

      {correlate.data && (
        <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 12, marginBottom: 12, fontSize: 13 }}>
          {(correlate.data as any).message
            ? <span style={{ color: 'var(--muted)' }}>{(correlate.data as any).message}</span>
            : <span style={{ color: 'var(--green)' }}>
                Chain {(correlate.data as any).created ? 'created' : 'updated'} —
                {(correlate.data as any).tactic_count} tactics,
                risk {(correlate.data as any).risk_score}
              </span>}
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {chains.data?.length === 0
          ? <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 32, textAlign: 'center', color: 'var(--muted)' }}>
              No attack chains yet. Ingest events then click Correlate.
            </div>
          : chains.data?.map(c => (
            <div key={c.id} style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                <div>
                  <div style={{ fontSize: 15, fontWeight: 700 }}>{c.host}</div>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
                    {new Date(c.first_seen).toLocaleString()} → {new Date(c.last_seen).toLocaleString()}
                    {' '}· {Math.round(c.duration_seconds / 60)} min
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  {c.is_multi_stage && <Badge label="MULTI-STAGE" color="var(--red)" />}
                  <Badge label={c.status}
                    color={c.status === 'open' ? 'var(--red)' : c.status === 'investigating' ? 'var(--yellow)' : 'var(--muted)'} />
                  <span style={{ fontSize: 18, fontWeight: 800, color: riskColor(c.risk_score) }}>{c.risk_score}</span>
                </div>
              </div>

              {/* Tactic timeline */}
              <div style={{ display: 'flex', gap: 6, marginBottom: 12, flexWrap: 'wrap' }}>
                {c.tactics_observed.map((t, i) => (
                  <div key={t} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Badge label={t} color="var(--accent)" />
                    {i < c.tactics_observed.length - 1 && <span style={{ color: 'var(--muted)' }}>→</span>}
                  </div>
                ))}
              </div>

              {/* Techniques */}
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 12 }}>
                {c.technique_ids.map(t => (
                  <span key={t} style={{ background: 'var(--bg3)', border: '1px solid var(--border)',
                    borderRadius: 4, padding: '2px 8px', fontSize: 11, fontFamily: 'monospace' }}>{t}</span>
                ))}
              </div>

              <div style={{ display: 'flex', gap: 6 }}>
                {c.status === 'open' && (
                  <button onClick={() => updateStatus.mutate({ id: c.id, s: 'investigating' })}
                    style={{ fontSize: 11, padding: '3px 10px', background: 'var(--yellow)22',
                      color: 'var(--yellow)', border: '1px solid var(--yellow)44', borderRadius: 4 }}>
                    Investigate
                  </button>
                )}
                {c.status !== 'closed' && (
                  <button onClick={() => updateStatus.mutate({ id: c.id, s: 'closed' })}
                    style={{ fontSize: 11, padding: '3px 10px', background: 'var(--green)22',
                      color: 'var(--green)', border: '1px solid var(--green)44', borderRadius: 4 }}>
                    Close
                  </button>
                )}
                <span style={{ fontSize: 11, color: 'var(--muted)', marginLeft: 8 }}>
                  {c.alert_ids.length} alerts
                </span>
              </div>
            </div>
          ))}
      </div>
    </div>
  )
}
