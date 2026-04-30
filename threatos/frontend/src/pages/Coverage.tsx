import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { coverageApi } from '../lib/api'

const TACTIC_ORDER = [
  "reconnaissance","resource-development","initial-access","execution",
  "persistence","privilege-escalation","defense-evasion","credential-access",
  "discovery","lateral-movement","collection","command-and-control",
  "exfiltration","impact",
]

export function Coverage() {
  const qc      = useQueryClient()
  const summary = useQuery({ queryKey: ['coverage-summary'], queryFn: coverageApi.summary })
  const matrix  = useQuery({ queryKey: ['coverage-matrix'],  queryFn: () => coverageApi.matrix() })
  const refresh = useMutation({
    mutationFn: coverageApi.refresh,
    onSuccess:  () => {
      qc.invalidateQueries({ queryKey: ['coverage-summary'] })
      qc.invalidateQueries({ queryKey: ['coverage-matrix'] })
    },
  })

  // Group by tactic in kill-chain order
  const grouped: Record<string, typeof matrix.data> = {}
  for (const tactic of TACTIC_ORDER) {
    grouped[tactic] = (matrix.data ?? []).filter(r => r.tactic === tactic)
  }
  // Any unknown tactics at the end
  const unknownRows = (matrix.data ?? []).filter(r => !TACTIC_ORDER.includes(r.tactic ?? ''))
  if (unknownRows.length > 0) grouped['unknown'] = unknownRows

  const totalCount   = matrix.data?.length ?? 0

  return (
    <div>
      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20 }}>
        <h1 style={{ fontSize:20, fontWeight:700 }}>ATT&CK Coverage Heatmap</h1>
        <button onClick={() => refresh.mutate()} disabled={refresh.isPending}
          style={{ padding:'7px 16px', background:'var(--accent)', color:'white',
            border:'none', borderRadius:6, fontSize:13, fontWeight:600,
            opacity: refresh.isPending ? 0.6 : 1 }}>
          {refresh.isPending ? '⏳ Loading...' : '↻ Refresh'}
        </button>
      </div>

      {/* Summary stats */}
      {summary.data && (
        <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12, marginBottom:24 }}>
          {[
            { label:'Total Techniques', value: summary.data.total_techniques, color:'var(--text)' },
            { label:'Covered',          value: summary.data.covered,          color:'#22c55e' },
            { label:'Gaps',             value: summary.data.gaps,             color:'#ef4444' },
            { label:'Coverage',         value: `${summary.data.coverage_pct}%`, color:'var(--accent)' },
          ].map(s => (
            <div key={s.label} style={{ background:'var(--bg2)', border:'1px solid var(--border)',
              borderRadius:8, padding:'14px 16px', textAlign:'center' }}>
              <div style={{ fontSize:26, fontWeight:800, color:s.color }}>{s.value}</div>
              <div style={{ fontSize:11, color:'var(--muted)', marginTop:4 }}>{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Legend */}
      <div style={{ display:'flex', gap:16, marginBottom:16, alignItems:'center' }}>
        <div style={{ fontSize:12, color:'var(--muted)' }}>Legend:</div>
        <div style={{ display:'flex', alignItems:'center', gap:6 }}>
          <div style={{ width:20, height:20, borderRadius:3,
            background:'#22c55e33', border:'1px solid #22c55e' }} />
          <span style={{ fontSize:12, color:'#22c55e' }}>Covered</span>
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:6 }}>
          <div style={{ width:20, height:20, borderRadius:3,
            background:'#ef444422', border:'1px solid #444' }} />
          <span style={{ fontSize:12, color:'var(--muted)' }}>Gap</span>
        </div>
        <div style={{ fontSize:12, color:'var(--muted)', marginLeft:8 }}>
          Hover over a cell to see technique name · (n) = rule count
        </div>
      </div>

      {totalCount === 0 && (
        <div style={{ background:'var(--bg2)', border:'1px solid var(--border)', borderRadius:8,
          padding:40, textAlign:'center', color:'var(--muted)' }}>
          Click "Refresh" to load the ATT&CK bundle and populate the heatmap.
        </div>
      )}

      {/* Heatmap — one row per tactic */}
      {Object.entries(grouped).map(([tactic, rows]) => {
        if (!rows || rows.length === 0) return null
        const tacticCovered = rows.filter(r => r.covered).length
        const tacticPct = rows.length > 0 ? Math.round(tacticCovered / rows.length * 100) : 0

        return (
          <div key={tactic} style={{ marginBottom:16 }}>
            {/* Tactic header */}
            <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:6 }}>
              <span style={{ fontSize:12, fontWeight:700, color:'var(--muted)',
                textTransform:'uppercase', letterSpacing:1, minWidth:180 }}>{tactic}</span>
              <div style={{ flex:1, background:'var(--bg3)', borderRadius:3, height:4 }}>
                <div style={{ background: tacticPct > 50 ? '#22c55e' : tacticPct > 20 ? '#f59e0b' : '#ef4444',
                  borderRadius:3, height:4, width:`${tacticPct}%`, transition:'width 0.3s' }} />
              </div>
              <span style={{ fontSize:11, color:'var(--muted)', minWidth:60, textAlign:'right' }}>
                {tacticCovered}/{rows.length} ({tacticPct}%)
              </span>
            </div>

            {/* Technique cells */}
            <div style={{ display:'flex', flexWrap:'wrap', gap:4, paddingLeft:192 }}>
              {rows.map(r => (
                <div key={r.technique_id}
                  title={`${r.technique_id}: ${r.technique_name ?? 'Unknown'}\nRules: ${r.rule_count}\nPlatforms: ${r.platforms?.join(', ')}`}
                  style={{
                    width: 72, height: 28,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    borderRadius: 4, cursor: 'pointer',
                    fontSize: 10, fontFamily: 'monospace', fontWeight: 600,
                    background: r.covered ? '#22c55e22' : '#1a1d27',
                    border: `1px solid ${r.covered ? '#22c55e66' : '#2e3347'}`,
                    color: r.covered ? '#22c55e' : '#4a5568',
                    transition: 'all 0.1s',
                  }}
                  onMouseEnter={e => {
                    const el = e.currentTarget
                    el.style.transform = 'scale(1.1)'
                    el.style.zIndex = '10'
                    el.style.boxShadow = '0 2px 8px rgba(0,0,0,0.4)'
                  }}
                  onMouseLeave={e => {
                    const el = e.currentTarget
                    el.style.transform = 'scale(1)'
                    el.style.zIndex = '1'
                    el.style.boxShadow = 'none'
                  }}
                  onClick={() => {
                    const base = r.technique_id.includes('.')
                      ? r.technique_id.replace('.', '/')
                      : r.technique_id
                    window.open(`https://attack.mitre.org/techniques/${base}/`, '_blank')
                  }}>
                  {r.technique_id}
                  {r.rule_count > 0 && (
                    <span style={{ marginLeft:2, fontSize:9, opacity:0.8 }}>({r.rule_count})</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}
