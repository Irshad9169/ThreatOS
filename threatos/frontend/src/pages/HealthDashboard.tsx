import { useQuery } from '@tanstack/react-query'
import axios from 'axios'
import { apiClient } from '../lib/api'

interface HealthStatus {
  timestamp:      string
  overall_status: string
  active_alerts:  { level: string; check: string; message: string; value?: number }[]
  components:     Record<string, string>
  metrics: {
    events_last_1h:  number
    events_last_24h: number
    alerts_last_1h:  number
    alerts_last_24h: number
    open_alerts:     number
    rules_loaded:    number
  }
}

interface BasicHealth {
  status:           string
  uptime_seconds:   number
  version:          string
  rules_loaded:     number
  attck_techniques: number
  components:       Record<string, string>
}

function StatusDot({ status }: { status: string }) {
  const color = status === 'ok' ? '#a6e3a1'
    : status === 'warning' ? '#f9e2af'
    : '#f38ba8'
  return (
    <span style={{
      display:'inline-block', width:10, height:10,
      borderRadius:'50%', background:color,
      marginRight:8, flexShrink:0,
      boxShadow:`0 0 6px ${color}`,
    }} />
  )
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m ${seconds % 60}s`
}

// Direct axios calls for public endpoints (no /api/ prefix)
const publicAxios = axios.create()

export function HealthDashboard() {
  const basic = useQuery({
    queryKey: ['health-basic'],
    queryFn:  () => publicAxios.get<BasicHealth>('/health').then(r => r.data),
    refetchInterval: 10000,
  })

  const status = useQuery({
    queryKey: ['health-status'],
    queryFn:  () => publicAxios.get<HealthStatus>('/health/status').then(r => r.data),
    refetchInterval: 15000,
  })

  const retention = useQuery({
    queryKey: ['retention-sizes'],
    queryFn:  () => apiClient.get<Record<string,any>>('/retention/sizes').then(r => r.data),
  })

  const overallColor = status.data?.overall_status === 'ok' ? '#a6e3a1'
    : status.data?.overall_status === 'warning' ? '#f9e2af' : '#f38ba8'

  return (
    <div>
      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between',
        alignItems:'center', marginBottom:20 }}>
        <div>
          <h1 style={{ fontSize:20, fontWeight:700 }}>System Health</h1>
          {status.data && (
            <div style={{ fontSize:12, color:'var(--muted)', marginTop:2 }}>
              Last checked: {new Date(status.data.timestamp).toLocaleString()}
              · auto-refreshes every 15s
            </div>
          )}
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <StatusDot status={status.data?.overall_status || 'ok'} />
          <span style={{ fontSize:16, fontWeight:700, color:overallColor }}>
            {(status.data?.overall_status || 'checking...').toUpperCase()}
          </span>
        </div>
      </div>

      {/* Top stats */}
      {basic.data && (
        <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)',
          gap:12, marginBottom:20 }}>
          {[
            { label:'Uptime',            value:formatUptime(basic.data.uptime_seconds), color:'var(--accent)' },
            { label:'Rules Loaded',      value:basic.data.rules_loaded.toLocaleString(), color:'#a6e3a1' },
            { label:'ATT&CK Techniques', value:basic.data.attck_techniques,              color:'var(--accent)' },
            { label:'Version',           value:basic.data.version,                       color:'var(--muted)' },
          ].map(s => (
            <div key={s.label} style={{ background:'var(--bg2)',
              border:'1px solid var(--border)', borderRadius:8,
              padding:'14px 16px', textAlign:'center' }}>
              <div style={{ fontSize:22, fontWeight:800, color:s.color }}>{s.value}</div>
              <div style={{ fontSize:11, color:'var(--muted)', marginTop:3 }}>{s.label}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>

        {/* Health alerts */}
        <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
          borderRadius:8, padding:16 }}>
          <h3 style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>
            Health Alerts
            {(status.data?.active_alerts.length ?? 0) > 0 && (
              <span style={{ marginLeft:8, background:'#f38ba822',
                color:'#f38ba8', borderRadius:4, padding:'1px 6px', fontSize:11 }}>
                {status.data!.active_alerts.length}
              </span>
            )}
          </h3>
          {status.isPending && (
            <div style={{ color:'var(--muted)', fontSize:12 }}>Loading...</div>
          )}
          {status.data?.active_alerts.length === 0 && (
            <div style={{ display:'flex', alignItems:'center', gap:8, padding:'12px 0' }}>
              <StatusDot status="ok" />
              <span style={{ fontSize:13, color:'#a6e3a1' }}>All systems operational</span>
            </div>
          )}
          {status.data?.active_alerts.map((alert, i) => (
            <div key={i} style={{ padding:'10px 12px', marginBottom:8,
              background: alert.level==='critical' ? '#f38ba811' : '#f9e2af11',
              border:`1px solid ${alert.level==='critical' ? '#f38ba844' : '#f9e2af44'}`,
              borderRadius:6 }}>
              <div style={{ display:'flex', gap:6, marginBottom:4, alignItems:'center' }}>
                <span style={{ fontSize:10, fontWeight:700, textTransform:'uppercase',
                  letterSpacing:1,
                  color:alert.level==='critical' ? '#f38ba8' : '#f9e2af' }}>
                  {alert.level}
                </span>
                <span style={{ fontSize:10, color:'var(--muted)' }}>
                  {alert.check.replace(/_/g,' ')}
                </span>
              </div>
              <div style={{ fontSize:12 }}>{alert.message}</div>
            </div>
          ))}
        </div>

        {/* Component status */}
        <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
          borderRadius:8, padding:16 }}>
          <h3 style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>Components</h3>
          {Object.entries(status.data?.components || {}).map(([name, value]) => {
            const s = value.startsWith('ok') ? 'ok'
              : value.includes('warning') || value==='empty' ? 'warning' : 'error'
            return (
              <div key={name} style={{ display:'flex', alignItems:'center',
                padding:'8px 0', borderBottom:'1px solid var(--border)22', gap:8 }}>
                <StatusDot status={s} />
                <div style={{ flex:1 }}>
                  <div style={{ fontSize:12, fontWeight:600, textTransform:'capitalize' }}>
                    {name.replace(/_/g,' ')}
                  </div>
                  <div style={{ fontSize:11, color:'var(--muted)' }}>{value}</div>
                </div>
              </div>
            )
          })}
        </div>

        {/* Activity metrics */}
        <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
          borderRadius:8, padding:16 }}>
          <h3 style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>Activity</h3>
          {status.data && Object.entries({
            'Events ingested (1h)':  status.data.metrics.events_last_1h,
            'Events ingested (24h)': status.data.metrics.events_last_24h,
            'Alerts fired (1h)':     status.data.metrics.alerts_last_1h,
            'Alerts fired (24h)':    status.data.metrics.alerts_last_24h,
            'Open alerts':           status.data.metrics.open_alerts,
            'Rules loaded':          status.data.metrics.rules_loaded,
          }).map(([label, value]) => (
            <div key={label} style={{ display:'flex', justifyContent:'space-between',
              padding:'7px 0', borderBottom:'1px solid var(--border)22' }}>
              <span style={{ fontSize:12, color:'var(--muted)' }}>{label}</span>
              <span style={{ fontSize:13, fontWeight:600,
                color: label==='Open alerts' && value > 0 ? '#f38ba8' : 'var(--text)' }}>
                {value.toLocaleString()}
              </span>
            </div>
          ))}
        </div>

        {/* Table sizes + monitoring links */}
        <div style={{ display:'flex', flexDirection:'column', gap:16 }}>

          {/* Monitoring links — open raw in new tab */}
          <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
            borderRadius:8, padding:16 }}>
            <h3 style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>
              Monitoring Endpoints
            </h3>
            {[
              { label:'Health Check',    path:'/health',        desc:'Basic health — no auth required' },
              { label:'Platform Status', path:'/health/status', desc:'Full status with health alerts', needsAuth:true },
              { label:'Prometheus',      path:'/metrics',       desc:'Prometheus scrape endpoint' },
              { label:'API Docs',        path:'/docs',          desc:'Interactive API documentation' },
            ].map(link => (
              <div key={link.path} style={{ padding:'7px 0',
                borderBottom:'1px solid var(--border)22',
                display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                <div>
                  <div style={{ fontSize:12, fontWeight:600 }}>{link.label}</div>
                  <div style={{ fontSize:11, color:'var(--muted)' }}>{link.desc}</div>
                </div>
                <a href={link.path} target="_blank" rel="noopener noreferrer"
                  style={{ fontSize:11, color:'var(--accent)',
                    padding:'3px 10px', border:'1px solid var(--accent)44',
                    borderRadius:4, textDecoration:'none' }}>
                  Open ↗
                </a>
              </div>
            ))}
          </div>

          {/* DB table sizes */}
          <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
            borderRadius:8, padding:16 }}>
            <h3 style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>
              Database Tables
            </h3>
            {retention.isPending && (
              <div style={{ color:'var(--muted)', fontSize:12 }}>Loading...</div>
            )}
            {retention.data && Object.entries(retention.data)
              .sort(([,a],[,b]) => (b as any).bytes - (a as any).bytes)
              .slice(0,8)
              .map(([name, info]: [string, any]) => (
                <div key={name} style={{ display:'flex', justifyContent:'space-between',
                  padding:'5px 0', borderBottom:'1px solid var(--border)22' }}>
                  <span style={{ fontSize:11, fontFamily:'monospace' }}>{name}</span>
                  <div style={{ display:'flex', gap:12 }}>
                    <span style={{ fontSize:11, color:'var(--muted)' }}>
                      {info.rows?.toLocaleString()} rows
                    </span>
                    <span style={{ fontSize:11, color:'var(--accent)', minWidth:50, textAlign:'right' }}>
                      {info.size}
                    </span>
                  </div>
                </div>
              ))}
          </div>
        </div>
      </div>
    </div>
  )
}
