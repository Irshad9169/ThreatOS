import { useQuery } from '@tanstack/react-query'
import { alertsApi, coverageApi, rulesApi, assetsApi, chainsApi } from '../lib/api'
import { StatCard } from '../components/StatCard'
import { Badge } from '../components/Badge'

function riskColor(score: number) {
  if (score >= 80) return 'var(--red)'
  if (score >= 60) return 'var(--orange)'
  if (score >= 40) return 'var(--yellow)'
  return 'var(--green)'
}

export function Dashboard() {
  const alerts   = useQuery({ queryKey: ['alerts'],   queryFn: () => alertsApi.list({ limit: 5 }), refetchInterval: 10000 })
  const coverage = useQuery({ queryKey: ['coverage-summary'], queryFn: coverageApi.summary })
  const rules    = useQuery({ queryKey: ['rules'],    queryFn: rulesApi.list })
  const assets   = useQuery({ queryKey: ['assets'],   queryFn: () => assetsApi.list() })
  const chains   = useQuery({ queryKey: ['chains'],   queryFn: () => chainsApi.list() })

  const openAlerts    = alerts.data?.filter(a => a.status === 'open').length ?? 0
  const criticalAssets= assets.data?.filter(a => a.criticality === 4).length ?? 0
  const multiStage    = chains.data?.filter(c => c.is_multi_stage).length ?? 0

  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 20 }}>Dashboard</h1>

      {/* Stat row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 24 }}>
        <StatCard label="Open Alerts"      value={openAlerts}                          color="var(--red)" />
        <StatCard label="Active Rules"     value={rules.data?.filter(r => r.enabled).length ?? 0} color="var(--accent)" />
        <StatCard label="Coverage"         value={`${coverage.data?.coverage_pct ?? 0}%`}          color="var(--green)" />
        <StatCard label="Critical Assets"  value={criticalAssets}                      color="var(--orange)" />
        <StatCard label="Multi-Stage Chains" value={multiStage}                        color="var(--red)" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Recent alerts */}
        <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Recent Alerts</h2>
          {alerts.data?.length === 0
            ? <p style={{ color: 'var(--muted)', fontSize: 13 }}>No alerts yet</p>
            : alerts.data?.slice(0, 5).map(a => (
              <div key={a.id} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '8px 0', borderBottom: '1px solid var(--border)',
              }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 500 }}>{a.technique_id}</div>
                  <div style={{ fontSize: 11, color: 'var(--muted)' }}>{a.entity_host ?? 'unknown'} · {a.tactic}</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: 16, fontWeight: 700, color: riskColor(a.risk_score) }}>{a.risk_score}</div>
                  <Badge label={a.status} color={a.status === 'open' ? 'var(--red)' : 'var(--green)'} />
                </div>
              </div>
            ))}
        </div>

        {/* Coverage summary */}
        <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>ATT&CK Coverage</h2>
          {coverage.data ? (
            <>
              <div style={{ marginBottom: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span style={{ color: 'var(--muted)', fontSize: 12 }}>Coverage</span>
                  <span style={{ fontWeight: 700, color: 'var(--green)' }}>{coverage.data.coverage_pct}%</span>
                </div>
                <div style={{ background: 'var(--bg3)', borderRadius: 4, height: 8 }}>
                  <div style={{
                    background: 'var(--green)', borderRadius: 4, height: 8,
                    width: `${coverage.data.coverage_pct}%`, transition: 'width 0.5s',
                  }} />
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                <div style={{ background: 'var(--bg3)', borderRadius: 6, padding: '10px 12px', textAlign: 'center' }}>
                  <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text)' }}>{coverage.data.total_techniques}</div>
                  <div style={{ fontSize: 10, color: 'var(--muted)' }}>Total</div>
                </div>
                <div style={{ background: 'var(--bg3)', borderRadius: 6, padding: '10px 12px', textAlign: 'center' }}>
                  <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--green)' }}>{coverage.data.covered}</div>
                  <div style={{ fontSize: 10, color: 'var(--muted)' }}>Covered</div>
                </div>
                <div style={{ background: 'var(--bg3)', borderRadius: 6, padding: '10px 12px', textAlign: 'center' }}>
                  <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--red)' }}>{coverage.data.gaps}</div>
                  <div style={{ fontSize: 10, color: 'var(--muted)' }}>Gaps</div>
                </div>
              </div>
            </>
          ) : (
            <p style={{ color: 'var(--muted)', fontSize: 13 }}>
              Coverage matrix not loaded yet.{' '}
              <button onClick={() => coverageApi.refresh()}
                style={{ background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontSize: 13 }}>
                Load ATT&CK bundle →
              </button>
            </p>
          )}
        </div>

        {/* Attack chains */}
        <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Attack Chains</h2>
          {chains.data?.length === 0
            ? <p style={{ color: 'var(--muted)', fontSize: 13 }}>No chains yet</p>
            : chains.data?.slice(0, 4).map(c => (
              <div key={c.id} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '8px 0', borderBottom: '1px solid var(--border)',
              }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 500 }}>{c.host}</div>
                  <div style={{ fontSize: 11, color: 'var(--muted)' }}>{c.tactic_count} tactics · {c.alert_ids.length} alerts</div>
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  {c.is_multi_stage && <Badge label="MULTI" color="var(--red)" />}
                  <span style={{ fontSize: 14, fontWeight: 700, color: riskColor(c.risk_score) }}>{c.risk_score}</span>
                </div>
              </div>
            ))}
        </div>

        {/* Assets */}
        <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Asset Registry</h2>
          {assets.data?.length === 0
            ? <p style={{ color: 'var(--muted)', fontSize: 13 }}>No assets registered</p>
            : assets.data?.slice(0, 5).map(a => (
              <div key={a.id} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '8px 0', borderBottom: '1px solid var(--border)',
              }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 500 }}>{a.hostname}</div>
                  <div style={{ fontSize: 11, color: 'var(--muted)' }}>{a.environment} · {a.os_type}</div>
                </div>
                <Badge
                  label={`CRIT ${a.criticality}`}
                  color={a.criticality === 4 ? 'var(--red)' : a.criticality === 3 ? 'var(--orange)' : 'var(--blue)'}
                />
              </div>
            ))}
        </div>
      </div>
    </div>
  )
}
