import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiClient } from '../lib/api'
import { getToken } from '../lib/auth'

interface ReportData {
  period_days:        number
  generated_at:       string
  cutoff:             string
  total_alerts:       number
  avg_risk:           number
  max_risk:           number
  alerts_by_status:   Record<string, number>
  top_techniques:     { technique_id:string; tactic:string; count:number; avg_risk:number }[]
  top_hosts:          { host:string; count:number; max_risk:number }[]
  high_risk_alerts:   { technique_id:string; tactic:string; risk_score:number; host:string|null; status:string; created_at:string }[]
  coverage_pct:       number
  covered_techniques: number
  total_techniques:   number
  coverage_gap:       number
  rules_total:        number
  rules_enabled:      number
  events_period:      number
  events_total:       number
  chains:             { id:string; host:string; tactic_count:number; risk_score:number; is_multi_stage:boolean; status:string }[]
  multi_stage_chains: number
  mttd_seconds:       number | null
  mttr_seconds:       number | null
  fp_rate:            number
  total_fp:           number
  total_closed:       number
  ti_total:           number
  ti_malicious:       number
  ti_suspicious:      number
  ti_malicious_iocs:  { ioc_type:string; ioc_value:string; source:string; score:number|null; country:string|null }[]
  critical_assets:    { host:string; alert_count:number; max_risk:number; criticality:number }[]
  audit_entries:      number
  failed_logins:      number
  noisy_rules:        { name:string; technique_id:string; fp_rate:number; total_evals:number }[]
  recommendations:    string[]
}

const PERIODS = [
  { label:'Last 24 hours', value:1  },
  { label:'Last 7 days',   value:7  },
  { label:'Last 14 days',  value:14 },
  { label:'Last 30 days',  value:30 },
  { label:'Last 90 days',  value:90 },
]

function riskColor(s: number) {
  return s >= 80 ? '#f38ba8' : s >= 60 ? '#fab387' : s >= 40 ? '#f9e2af' : '#a6e3a1'
}

function fmtDuration(s: number | null): string {
  if (s === null || s === undefined) return 'N/A'
  if (s < 60)    return `${s.toFixed(0)}s`
  if (s < 3600)  return `${(s/60).toFixed(1)}m`
  if (s < 86400) return `${(s/3600).toFixed(1)}h`
  return `${(s/86400).toFixed(1)}d`
}

function StatBox({ label, value, color = 'var(--accent)', sub = '' }:
  { label:string; value:string|number; color?:string; sub?:string }) {
  return (
    <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
      borderRadius:8, padding:'14px 16px', textAlign:'center' }}>
      <div style={{ fontSize:26, fontWeight:800, color }}>{value}</div>
      <div style={{ fontSize:11, color:'var(--muted)', marginTop:3 }}>{label}</div>
      {sub && <div style={{ fontSize:10, color:'var(--muted)', marginTop:2 }}>{sub}</div>}
    </div>
  )
}

function Section({ title, children }: { title:string; children:React.ReactNode }) {
  return (
    <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
      borderRadius:8, padding:16, marginBottom:16 }}>
      <h3 style={{ fontSize:13, fontWeight:600, marginBottom:12,
        borderBottom:'1px solid var(--border)', paddingBottom:8 }}>{title}</h3>
      {children}
    </div>
  )
}

function TRow({ cells, highlight }: { cells:(string|number|React.ReactNode)[]; highlight?:boolean }) {
  return (
    <tr style={{ background: highlight ? 'var(--accent)11' : undefined }}>
      {cells.map((c,i) => (
        <td key={i} style={{ padding:'6px 10px', fontSize:12,
          borderBottom:'1px solid var(--border)22' }}>{c}</td>
      ))}
    </tr>
  )
}

function THead({ cols }: { cols:string[] }) {
  return (
    <thead>
      <tr>
        {cols.map(c => (
          <th key={c} style={{ padding:'6px 10px', fontSize:10, fontWeight:600,
            color:'var(--muted)', textAlign:'left', textTransform:'uppercase',
            letterSpacing:1, borderBottom:'1px solid var(--border)' }}>{c}</th>
        ))}
      </tr>
    </thead>
  )
}

export function Reports() {
  const [days, setDays]      = useState(7)
  const [downloading, setDL] = useState(false)

  const report = useQuery({
    queryKey: ['report', days],
    queryFn:  () => apiClient.get<ReportData>('/report/data',
      { params: { days } }).then(r => r.data),
  })

  const d = report.data

  const handleDownload = async () => {
    setDL(true)
    try {
      const token = getToken()
      const resp  = await fetch(`/api/report/pdf?days=${days}`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      const blob = await resp.blob()
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `threatos_report_${days}d_${new Date().toISOString().slice(0,10)}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } finally { setDL(false) }
  }

  const statusBanner = () => {
    if (!d) return null
    const isC = d.multi_stage_chains > 0 || d.ti_malicious > 0
    const isW = (d.alerts_by_status['open'] || 0) > 5
    const verdict = isC ? 'CRITICAL' : isW ? 'WARNING' : 'NORMAL'
    const color   = isC ? '#f38ba8'  : isW ? '#fab387' : '#a6e3a1'
    return (
      <div style={{ padding:'12px 20px', borderRadius:8, marginBottom:16,
        background:color+'18', border:`2px solid ${color}`,
        display:'flex', justifyContent:'space-between', alignItems:'center' }}>
        <div>
          <span style={{ fontWeight:800, fontSize:16, color }}>
            Security Status: {verdict}
          </span>
          <span style={{ fontSize:12, color:'var(--muted)', marginLeft:16 }}>
            {d.generated_at}  ·  Last {d.period_days} days
          </span>
        </div>
        <button onClick={handleDownload} disabled={downloading}
          style={{ padding:'8px 18px', background:'var(--accent)', color:'white',
            border:'none', borderRadius:6, fontSize:13, fontWeight:600,
            cursor:'pointer', opacity: downloading ? 0.6 : 1 }}>
          {downloading ? '⏳ Generating...' : '⬇ Download PDF'}
        </button>
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between',
        alignItems:'center', marginBottom:16 }}>
        <h1 style={{ fontSize:20, fontWeight:700 }}>Security Report</h1>
        <div style={{ display:'flex', gap:8 }}>
          {PERIODS.map(p => (
            <button key={p.value} onClick={() => setDays(p.value)}
              style={{ padding:'5px 12px', borderRadius:6, fontSize:12,
                cursor:'pointer', fontWeight: days===p.value ? 700 : 400,
                background: days===p.value ? 'var(--accent)' : 'var(--bg2)',
                color:      days===p.value ? 'white' : 'var(--muted)',
                border: `1px solid ${days===p.value ? 'var(--accent)' : 'var(--border)'}` }}>
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {report.isPending && (
        <div style={{ color:'var(--muted)', textAlign:'center', padding:40 }}>
          Loading report data...
        </div>
      )}

      {report.isError && (
        <div style={{ color:'#f38ba8', textAlign:'center', padding:40 }}>
          Failed to load report. Check API connection.
        </div>
      )}

      {d && <>
        {statusBanner()}

        {/* KPI row */}
        <div style={{ display:'grid', gridTemplateColumns:'repeat(6,1fr)',
          gap:10, marginBottom:16 }}>
          <StatBox label="Total Alerts"    value={d.total_alerts}
            color="#89b4fa" />
          <StatBox label="Open Alerts"     value={d.alerts_by_status['open']||0}
            color={(d.alerts_by_status['open']||0)>0 ? '#f38ba8' : '#a6e3a1'} />
          <StatBox label="Multi-Stage"     value={d.multi_stage_chains}
            color={d.multi_stage_chains>0 ? '#f38ba8' : '#a6e3a1'} />
          <StatBox label="ATT&CK Coverage" value={`${d.coverage_pct}%`}
            color="#a6e3a1" />
          <StatBox label="Malicious IOCs"  value={d.ti_malicious}
            color={d.ti_malicious>0 ? '#f38ba8' : '#a6e3a1'} />
          <StatBox label="FP Rate"         value={`${d.fp_rate}%`}
            color={d.fp_rate>20 ? '#fab387' : '#a6e3a1'} />
        </div>

        {/* Metrics row */}
        <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)',
          gap:10, marginBottom:16 }}>
          <StatBox label="MTTD" value={fmtDuration(d.mttd_seconds)}
            color="#89b4fa" sub="Mean Time to Detect" />
          <StatBox label="MTTR" value={fmtDuration(d.mttr_seconds)}
            color="#89b4fa" sub="Mean Time to Respond" />
          <StatBox label="Events Ingested" value={d.events_period.toLocaleString()}
            color="#cba6f7" sub={`${d.events_total.toLocaleString()} total`} />
          <StatBox label="Rules Enabled"   value={d.rules_enabled.toLocaleString()}
            color="#cba6f7" sub={`${d.rules_total.toLocaleString()} total`} />
        </div>

        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>

          {/* Recommendations */}
          <Section title="🎯 Recommendations">
            {d.recommendations.length === 0
              ? <div style={{ color:'#a6e3a1', fontSize:13 }}>✅ No critical issues found</div>
              : d.recommendations.map((r,i) => (
                <div key={i} style={{ display:'flex', gap:10, padding:'7px 0',
                  borderBottom:'1px solid var(--border)22', alignItems:'flex-start' }}>
                  <span style={{ color:'var(--accent)', fontWeight:700,
                    fontSize:12, minWidth:20 }}>{i+1}.</span>
                  <span style={{ fontSize:12 }}>{r}</span>
                </div>
              ))
            }
          </Section>

          {/* TI Enrichment */}
          <Section title="🔬 Threat Intelligence">
            <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)',
              gap:8, marginBottom:12 }}>
              <StatBox label="IOCs Checked"  value={d.ti_total}     color="#89b4fa" />
              <StatBox label="Malicious"     value={d.ti_malicious} color={d.ti_malicious>0?'#f38ba8':'#a6e3a1'} />
              <StatBox label="Suspicious"    value={d.ti_suspicious}color={d.ti_suspicious>0?'#fab387':'#a6e3a1'} />
            </div>
            {d.ti_malicious_iocs.length > 0 && <>
              <div style={{ fontSize:11, color:'#f38ba8', fontWeight:600,
                marginBottom:6 }}>⚠ Confirmed Malicious IOCs — block at firewall:</div>
              <table style={{ width:'100%', borderCollapse:'collapse' }}>
                <THead cols={['Type','IOC Value','Source','Score','Country']} />
                <tbody>
                  {d.ti_malicious_iocs.map((ioc,i) => (
                    <TRow key={i} cells={[
                      ioc.ioc_type,
                      <span style={{ fontFamily:'monospace', fontSize:11 }}>
                        {ioc.ioc_value.substring(0,30)}
                      </span>,
                      ioc.source,
                      ioc.score ? `${ioc.score}%` : 'N/A',
                      ioc.country || '?',
                    ]} highlight />
                  ))}
                </tbody>
              </table>
            </>}
            {d.ti_malicious_iocs.length === 0 &&
              <div style={{ fontSize:12, color:'#a6e3a1' }}>No malicious IOCs this period</div>
            }
          </Section>

          {/* Critical Assets at Risk */}
          <Section title="🖥 Critical Assets at Risk">
            {d.critical_assets.length === 0
              ? <div style={{ fontSize:12, color:'#a6e3a1' }}>No open alerts on assets</div>
              : <table style={{ width:'100%', borderCollapse:'collapse' }}>
                  <THead cols={['Host','Alerts','Max Risk','Criticality']} />
                  <tbody>
                    {d.critical_assets.map((a,i) => (
                      <TRow key={i} cells={[
                        a.host,
                        a.alert_count,
                        <span style={{ color:riskColor(a.max_risk), fontWeight:700 }}>
                          {a.max_risk}
                        </span>,
                        '★'.repeat(a.criticality),
                      ]} />
                    ))}
                  </tbody>
                </table>
            }
          </Section>

          {/* Attack Chains */}
          <Section title="🔗 Attack Chains">
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr',
              gap:8, marginBottom:12 }}>
              <StatBox label="Multi-Stage Chains" value={d.multi_stage_chains}
                color={d.multi_stage_chains>0?'#f38ba8':'#a6e3a1'} />
              <StatBox label="Total Chains" value={d.chains.length} color="#89b4fa" />
            </div>
            {d.chains.length > 0 &&
              <table style={{ width:'100%', borderCollapse:'collapse' }}>
                <THead cols={['Host','Tactics','Risk','Multi-Stage','Status']} />
                <tbody>
                  {d.chains.map((c,i) => (
                    <TRow key={i} cells={[
                      c.host,
                      c.tactic_count,
                      <span style={{ color:riskColor(c.risk_score), fontWeight:700 }}>
                        {c.risk_score}
                      </span>,
                      c.is_multi_stage
                        ? <span style={{ color:'#f38ba8', fontWeight:700 }}>✓ YES</span>
                        : 'No',
                      c.status,
                    ]} highlight={c.is_multi_stage} />
                  ))}
                </tbody>
              </table>
            }
          </Section>

          {/* Top Techniques */}
          <Section title="📊 Top Detected Techniques">
            {d.top_techniques.length === 0
              ? <div style={{ fontSize:12, color:'var(--muted)' }}>No alerts this period</div>
              : <table style={{ width:'100%', borderCollapse:'collapse' }}>
                  <THead cols={['Technique','Tactic','Count','Avg Risk']} />
                  <tbody>
                    {d.top_techniques.map((t,i) => (
                      <TRow key={i} cells={[
                        <span style={{ fontFamily:'monospace', fontSize:11 }}>{t.technique_id}</span>,
                        t.tactic,
                        t.count,
                        <span style={{ color:riskColor(t.avg_risk) }}>{t.avg_risk}</span>,
                      ]} />
                    ))}
                  </tbody>
                </table>
            }
          </Section>

          {/* High Risk Alerts */}
          <Section title="🚨 High Risk Alerts (≥70)">
            {d.high_risk_alerts.length === 0
              ? <div style={{ fontSize:12, color:'#a6e3a1' }}>No high-risk alerts</div>
              : <table style={{ width:'100%', borderCollapse:'collapse' }}>
                  <THead cols={['Technique','Host','Risk','Status','Time']} />
                  <tbody>
                    {d.high_risk_alerts.map((a,i) => (
                      <TRow key={i} cells={[
                        <span style={{ fontFamily:'monospace', fontSize:11 }}>{a.technique_id}</span>,
                        a.host || '?',
                        <span style={{ color:riskColor(a.risk_score), fontWeight:700 }}>
                          {a.risk_score}
                        </span>,
                        a.status,
                        a.created_at,
                      ]} />
                    ))}
                  </tbody>
                </table>
            }
          </Section>

          {/* Detection Quality */}
          <Section title="🔧 Detection Quality">
            <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)',
              gap:8, marginBottom:12 }}>
              <StatBox label="FP Rate"     value={`${d.fp_rate}%`}
                color={d.fp_rate>20?'#fab387':'#a6e3a1'} />
              <StatBox label="Total FPs"   value={d.total_fp}
                color={d.total_fp>5?'#fab387':'#a6e3a1'} />
              <StatBox label="Noisy Rules" value={d.noisy_rules.length}
                color={d.noisy_rules.length>0?'#fab387':'#a6e3a1'} />
            </div>
            {d.noisy_rules.length > 0 && <>
              <div style={{ fontSize:11, color:'#fab387', marginBottom:6 }}>
                Rules with FP rate &gt; 50% — consider tuning:
              </div>
              <table style={{ width:'100%', borderCollapse:'collapse' }}>
                <THead cols={['Rule','Technique','FP Rate','Evals']} />
                <tbody>
                  {d.noisy_rules.map((r,i) => (
                    <TRow key={i} cells={[r.name, r.technique_id,
                      `${r.fp_rate}%`, r.total_evals]} />
                  ))}
                </tbody>
              </table>
            </>}
            {d.noisy_rules.length === 0 &&
              <div style={{ fontSize:12, color:'#a6e3a1' }}>No noisy rules detected</div>
            }
          </Section>

          {/* Compliance */}
          <Section title="📋 Compliance & Governance">
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr',
              gap:8, marginBottom:8 }}>
              <StatBox label="Audit Entries"    value={d.audit_entries}  color="#cba6f7" />
              <StatBox label="Failed Logins"    value={d.failed_logins}
                color={d.failed_logins>10?'#fab387':'#a6e3a1'} />
            </div>
            {[
              ['ATT&CK Coverage', `${d.coverage_pct}% (${d.covered_techniques}/${d.total_techniques})`],
              ['Coverage Gap',    `${d.coverage_gap} techniques without detection`],
              ['Data Retention',  'Raw events: 90d  |  Audit: 365d  |  Alerts: 365d'],
            ].map(([k,v]) => (
              <div key={k} style={{ display:'flex', justifyContent:'space-between',
                padding:'5px 0', borderBottom:'1px solid var(--border)22', fontSize:12 }}>
                <span style={{ color:'var(--muted)' }}>{k}</span>
                <span>{v}</span>
              </div>
            ))}
          </Section>

        </div>
      </>}
    </div>
  )
}
