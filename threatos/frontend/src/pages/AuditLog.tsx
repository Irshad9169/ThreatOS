import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiClient } from '../lib/api'
import { Badge } from '../components/Badge'

interface AuditEntry {
  id:          string
  timestamp:   string
  username:    string | null
  role:        string | null
  action:      string
  resource:    string
  resource_id: string | null
  detail:      string | null
  ip_address:  string | null
  result:      string
  changes:     Record<string, any> | null
}

const ACTION_COLORS: Record<string, string> = {
  login:              'var(--green)',
  login_failed:       'var(--red)',
  logout:             'var(--muted)',
  password_change:    'var(--yellow)',
  password_reset:     'var(--yellow)',
  user_create:        'var(--accent)',
  user_update:        'var(--accent)',
  user_deactivate:    'var(--red)',
  user_activate:      'var(--green)',
  api_key_generate:   'var(--orange)',
  api_key_revoke:     'var(--red)',
  rule_create:        'var(--accent)',
  rule_toggle:        'var(--yellow)',
  rule_delete:        'var(--red)',
  alert_status_update:'var(--yellow)',
  asset_create:       'var(--accent)',
  asset_update:       'var(--yellow)',
  asset_delete:       'var(--red)',
  chain_correlate:    'var(--accent)',
  chain_status_update:'var(--yellow)',
  coverage_refresh:   'var(--green)',
  purple_validate:    'var(--accent)',
  scan_create:        'var(--accent)',
  scan_run:           'var(--orange)',
  event_ingest:       'var(--muted)',
}

const RESOURCES = ['auth','user','rule','alert','asset','chain','coverage','purple','scan','ingest']
const ACTIONS   = Object.keys(ACTION_COLORS)
const RESULTS   = ['success','failure']

export function AuditLog() {
  const [filters, setFilters] = useState({
    username: '', action: '', resource: '', result: '', limit: '100',
  })
  const [selected, setSelected] = useState<AuditEntry | null>(null)

  const logs = useQuery({
    queryKey: ['audit', filters],
    queryFn:  () => {
      const params: Record<string, string> = { limit: filters.limit }
      if (filters.username) params.username = filters.username
      if (filters.action)   params.action   = filters.action
      if (filters.resource) params.resource  = filters.resource
      if (filters.result)   params.result    = filters.result
      return apiClient.get<AuditEntry[]>('/audit', { params }).then(r => r.data)
    },
    refetchInterval: 15000,
  })

  const setFilter = (k: string, v: string) =>
    setFilters(f => ({ ...f, [k]: v }))

  const resultColor = (r: string) =>
    r === 'success' ? 'var(--green)' : 'var(--red)'

  return (
    <div>
      <div style={{ display:'flex', justifyContent:'space-between',
        alignItems:'center', marginBottom:16 }}>
        <h1 style={{ fontSize:20, fontWeight:700 }}>Audit Log</h1>
        <div style={{ fontSize:12, color:'var(--muted)' }}>
          {logs.data?.length ?? 0} entries · auto-refreshes every 15s
        </div>
      </div>

      {/* Filters */}
      <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
        borderRadius:8, padding:14, marginBottom:14,
        display:'flex', gap:10, flexWrap:'wrap', alignItems:'flex-end' }}>

        <div>
          <label style={{ fontSize:10, color:'var(--muted)', display:'block', marginBottom:3 }}>
            USERNAME
          </label>
          <input value={filters.username}
            onChange={e => setFilter('username', e.target.value)}
            placeholder="filter by user..."
            style={{ background:'var(--bg3)', border:'1px solid var(--border)',
              borderRadius:4, padding:'5px 10px', color:'var(--text)',
              fontSize:12, width:150 }} />
        </div>

        <div>
          <label style={{ fontSize:10, color:'var(--muted)', display:'block', marginBottom:3 }}>
            ACTION
          </label>
          <select value={filters.action} onChange={e => setFilter('action', e.target.value)}
            style={{ background:'var(--bg3)', border:'1px solid var(--border)',
              color:'var(--text)', borderRadius:4, padding:'5px 10px', fontSize:12 }}>
            <option value="">All actions</option>
            {ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
        </div>

        <div>
          <label style={{ fontSize:10, color:'var(--muted)', display:'block', marginBottom:3 }}>
            RESOURCE
          </label>
          <select value={filters.resource} onChange={e => setFilter('resource', e.target.value)}
            style={{ background:'var(--bg3)', border:'1px solid var(--border)',
              color:'var(--text)', borderRadius:4, padding:'5px 10px', fontSize:12 }}>
            <option value="">All resources</option>
            {RESOURCES.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
        </div>

        <div>
          <label style={{ fontSize:10, color:'var(--muted)', display:'block', marginBottom:3 }}>
            RESULT
          </label>
          <select value={filters.result} onChange={e => setFilter('result', e.target.value)}
            style={{ background:'var(--bg3)', border:'1px solid var(--border)',
              color:'var(--text)', borderRadius:4, padding:'5px 10px', fontSize:12 }}>
            <option value="">All results</option>
            {RESULTS.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
        </div>

        <div>
          <label style={{ fontSize:10, color:'var(--muted)', display:'block', marginBottom:3 }}>
            LIMIT
          </label>
          <select value={filters.limit} onChange={e => setFilter('limit', e.target.value)}
            style={{ background:'var(--bg3)', border:'1px solid var(--border)',
              color:'var(--text)', borderRadius:4, padding:'5px 10px', fontSize:12 }}>
            {['50','100','200','500'].map(n =>
              <option key={n} value={n}>{n} rows</option>)}
          </select>
        </div>

        <button onClick={() => setFilters({ username:'', action:'', resource:'', result:'', limit:'100' })}
          style={{ padding:'5px 12px', background:'var(--bg3)', color:'var(--muted)',
            border:'1px solid var(--border)', borderRadius:4, fontSize:12, cursor:'pointer' }}>
          Clear
        </button>
      </div>

      <div style={{ display:'grid', gridTemplateColumns: selected ? '1fr 380px' : '1fr', gap:14 }}>
        {/* Log table */}
        <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
          borderRadius:8, overflowX:'auto' }}>
          <table style={{ width:'100%', borderCollapse:'collapse' }}>
            <thead>
              <tr>
                {['Time','User','Action','Resource','Detail','IP','Result'].map(h => (
                  <th key={h} style={{ textAlign:'left', padding:'8px 12px',
                    borderBottom:'1px solid var(--border)', color:'var(--muted)',
                    fontSize:10, fontWeight:600, textTransform:'uppercase',
                    letterSpacing:1, whiteSpace:'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {logs.data?.length === 0 && (
                <tr><td colSpan={7} style={{ padding:24, textAlign:'center',
                  color:'var(--muted)' }}>No audit logs found</td></tr>
              )}
              {logs.data?.map(entry => (
                <tr key={entry.id}
                  onClick={() => setSelected(selected?.id === entry.id ? null : entry)}
                  style={{
                    borderBottom:'1px solid var(--border)22',
                    cursor:'pointer',
                    background: selected?.id === entry.id
                      ? 'var(--bg3)'
                      : entry.result === 'failure' ? 'var(--red)08' : 'transparent',
                  }}
                  onMouseEnter={e => { if (selected?.id !== entry.id)
                    e.currentTarget.style.background = 'var(--bg3)' }}
                  onMouseLeave={e => { if (selected?.id !== entry.id)
                    e.currentTarget.style.background =
                      entry.result === 'failure' ? 'var(--red)08' : 'transparent' }}>

                  <td style={{ padding:'8px 12px', fontSize:11,
                    color:'var(--muted)', whiteSpace:'nowrap' }}>
                    {new Date(entry.timestamp).toLocaleString()}
                  </td>
                  <td style={{ padding:'8px 12px', whiteSpace:'nowrap' }}>
                    <div style={{ fontSize:12, fontWeight:600 }}>
                      {entry.username || '—'}
                    </div>
                    {entry.role && (
                      <div style={{ fontSize:10, color:'var(--muted)' }}>{entry.role}</div>
                    )}
                  </td>
                  <td style={{ padding:'8px 12px', whiteSpace:'nowrap' }}>
                    <Badge
                      label={entry.action.replace(/_/g,' ')}
                      color={ACTION_COLORS[entry.action] || 'var(--muted)'}
                    />
                  </td>
                  <td style={{ padding:'8px 12px', fontSize:12 }}>
                    {entry.resource}
                    {entry.resource_id && (
                      <span style={{ color:'var(--muted)', fontSize:10,
                        marginLeft:4 }}>
                        {entry.resource_id.slice(0,8)}
                      </span>
                    )}
                  </td>
                  <td style={{ padding:'8px 12px', fontSize:11,
                    color:'var(--muted)', maxWidth:280 }}>
                    <div style={{ overflow:'hidden', textOverflow:'ellipsis',
                      whiteSpace:'nowrap' }}>
                      {entry.detail || '—'}
                    </div>
                  </td>
                  <td style={{ padding:'8px 12px', fontSize:11,
                    color:'var(--muted)', fontFamily:'monospace' }}>
                    {entry.ip_address || '—'}
                  </td>
                  <td style={{ padding:'8px 12px' }}>
                    <Badge
                      label={entry.result.toUpperCase()}
                      color={resultColor(entry.result)}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Detail panel */}
        {selected && (
          <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
            borderRadius:8, padding:16, alignSelf:'start',
            position:'sticky', top:0 }}>
            <div style={{ display:'flex', justifyContent:'space-between',
              marginBottom:14 }}>
              <span style={{ fontWeight:600, fontSize:14 }}>Entry Detail</span>
              <button onClick={() => setSelected(null)}
                style={{ background:'none', border:'none',
                  color:'var(--muted)', cursor:'pointer', fontSize:16 }}>✕</button>
            </div>

            {[
              ['Timestamp',   new Date(selected.timestamp).toLocaleString()],
              ['User',        selected.username || '—'],
              ['Role',        selected.role     || '—'],
              ['Action',      selected.action],
              ['Resource',    selected.resource],
              ['Resource ID', selected.resource_id || '—'],
              ['IP Address',  selected.ip_address  || '—'],
              ['Result',      selected.result],
            ].map(([k, v]) => (
              <div key={k} style={{ display:'flex', justifyContent:'space-between',
                padding:'6px 0', borderBottom:'1px solid var(--border)22' }}>
                <span style={{ fontSize:11, color:'var(--muted)', minWidth:90 }}>{k}</span>
                <span style={{ fontSize:12, fontWeight:500, textAlign:'right',
                  color: k === 'Result'
                    ? resultColor(v as string)
                    : 'var(--text)' }}>
                  {v as string}
                </span>
              </div>
            ))}

            {selected.detail && (
              <div style={{ marginTop:10 }}>
                <div style={{ fontSize:10, color:'var(--muted)',
                  textTransform:'uppercase', letterSpacing:1, marginBottom:4 }}>
                  Detail
                </div>
                <div style={{ fontSize:12, color:'var(--text)',
                  background:'var(--bg3)', borderRadius:4,
                  padding:'8px 10px', lineHeight:1.6 }}>
                  {selected.detail}
                </div>
              </div>
            )}

            {selected.changes && Object.keys(selected.changes).length > 0 && (
              <div style={{ marginTop:10 }}>
                <div style={{ fontSize:10, color:'var(--muted)',
                  textTransform:'uppercase', letterSpacing:1, marginBottom:4 }}>
                  Changes
                </div>
                <div style={{ background:'var(--bg)', borderRadius:4,
                  padding:'8px 10px' }}>
                  {Object.entries(selected.changes).map(([field, change]) => (
                    <div key={field} style={{ fontSize:11, marginBottom:4 }}>
                      <span style={{ color:'var(--accent)', fontWeight:600 }}>
                        {field}
                      </span>
                      {typeof change === 'object' && change !== null &&
                       'from' in change && 'to' in change ? (
                        <span style={{ color:'var(--muted)' }}>
                          {': '}
                          <span style={{ color:'var(--red)' }}>
                            {String(change.from)}
                          </span>
                          {' → '}
                          <span style={{ color:'var(--green)' }}>
                            {String(change.to)}
                          </span>
                        </span>
                      ) : (
                        <span style={{ color:'var(--muted)' }}>
                          {': '}{JSON.stringify(change)}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
