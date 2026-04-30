import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiClient } from '../lib/api'
import { Badge } from '../components/Badge'

interface RawEvent {
  id:          string
  received_at: string
  log_source:  string
  hash:        string
  normalized:  Record<string, any>
}

interface EventStats {
  total_all_time: number
  last_n_hours:   number
  hours_back:     number
  by_log_source:  Record<string, number>
}

const LOG_SOURCES = ['winlog','syslog','cef','json','network']

export function EventSearch() {
  const [filters, setFilters] = useState({
    host:'', process:'', command_line:'', log_source:'',
    user:'', hours_back:'24', limit:'100',
  })
  const [selected, setSelected] = useState<RawEvent | null>(null)
  const [searched, setSearched] = useState(false)

  const setF = (k: string, v: string) => setFilters(f => ({ ...f, [k]: v }))

  const stats = useQuery({
    queryKey: ['event-stats', filters.hours_back],
    queryFn:  () => apiClient.get<EventStats>('/events/stats',
      { params: { hours_back: filters.hours_back } }).then(r => r.data),
  })

  const events = useQuery({
    queryKey: ['events', filters, searched],
    queryFn:  () => {
      const p: Record<string,string> = {
        hours_back: filters.hours_back,
        limit:      filters.limit,
      }
      if (filters.host)         p.host         = filters.host
      if (filters.process)      p.process      = filters.process
      if (filters.command_line) p.command_line  = filters.command_line
      if (filters.log_source)   p.log_source    = filters.log_source
      if (filters.user)         p.user          = filters.user
      return apiClient.get<RawEvent[]>('/events/search', { params: p })
        .then(r => r.data)
    },
    enabled: searched,
  })

  const handleSearch = () => setSearched(true)
  const handleClear  = () => {
    setFilters({ host:'',process:'',command_line:'',log_source:'',user:'',hours_back:'24',limit:'100' })
    setSearched(false)
    setSelected(null)
  }

  return (
    <div>
      <div style={{ display:'flex', justifyContent:'space-between',
        alignItems:'center', marginBottom:16 }}>
        <h1 style={{ fontSize:20, fontWeight:700 }}>Event Search</h1>
        <div style={{ fontSize:12, color:'var(--muted)' }}>
          {stats.data
            ? `${stats.data.total_all_time.toLocaleString()} total events · `
              + `${stats.data.last_n_hours.toLocaleString()} in last ${stats.data.hours_back}h`
            : 'Loading stats...'}
        </div>
      </div>

      {/* Stats cards */}
      {stats.data && (
        <div style={{ display:'flex', gap:8, marginBottom:14, flexWrap:'wrap' }}>
          {Object.entries(stats.data.by_log_source).map(([src, cnt]) => (
            <div key={src} style={{ background:'var(--bg2)',
              border:'1px solid var(--border)', borderRadius:6,
              padding:'6px 12px', display:'flex', gap:8, alignItems:'center' }}>
              <Badge label={src} color="var(--accent)" />
              <span style={{ fontSize:13, fontWeight:600 }}>{cnt}</span>
            </div>
          ))}
        </div>
      )}

      {/* Search form */}
      <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
        borderRadius:8, padding:16, marginBottom:14 }}>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:10, marginBottom:10 }}>
          {[
            ['Host',         'host',         'WIN-DC01'],
            ['Process',      'process',      'powershell.exe'],
            ['Command Line', 'command_line', '-EncodedCommand'],
            ['User',         'user',         'jsmith'],
          ].map(([label, key, ph]) => (
            <div key={key}>
              <label style={{ fontSize:10, color:'var(--muted)',
                display:'block', marginBottom:3, textTransform:'uppercase',
                letterSpacing:1 }}>{label}</label>
              <input value={(filters as any)[key]}
                onChange={e => setF(key, e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSearch()}
                placeholder={ph}
                style={{ width:'100%', background:'var(--bg3)',
                  border:'1px solid var(--border)', borderRadius:4,
                  padding:'6px 10px', color:'var(--text)', fontSize:13 }} />
            </div>
          ))}

          <div>
            <label style={{ fontSize:10, color:'var(--muted)', display:'block',
              marginBottom:3, textTransform:'uppercase', letterSpacing:1 }}>
              Log Source
            </label>
            <select value={filters.log_source}
              onChange={e => setF('log_source', e.target.value)}
              style={{ width:'100%', background:'var(--bg3)',
                border:'1px solid var(--border)', color:'var(--text)',
                borderRadius:4, padding:'6px 10px', fontSize:13 }}>
              <option value="">All sources</option>
              {LOG_SOURCES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>

          <div>
            <label style={{ fontSize:10, color:'var(--muted)', display:'block',
              marginBottom:3, textTransform:'uppercase', letterSpacing:1 }}>
              Time Window
            </label>
            <select value={filters.hours_back}
              onChange={e => setF('hours_back', e.target.value)}
              style={{ width:'100%', background:'var(--bg3)',
                border:'1px solid var(--border)', color:'var(--text)',
                borderRadius:4, padding:'6px 10px', fontSize:13 }}>
              {[['1h','1'],['6h','6'],['12h','12'],['24h','24'],
                ['48h','48'],['7d','168']].map(([label,val]) => (
                <option key={val} value={val}>{label}</option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ display:'flex', gap:8, alignItems:'center' }}>
          <button onClick={handleSearch}
            style={{ padding:'8px 20px', background:'var(--accent)',
              color:'white', border:'none', borderRadius:6,
              fontSize:13, fontWeight:600, cursor:'pointer' }}>
            🔍 Search
          </button>
          <button onClick={handleClear}
            style={{ padding:'8px 14px', background:'var(--bg3)',
              color:'var(--muted)', border:'1px solid var(--border)',
              borderRadius:6, fontSize:13, cursor:'pointer' }}>
            Clear
          </button>
          <select value={filters.limit}
            onChange={e => setF('limit', e.target.value)}
            style={{ background:'var(--bg3)', border:'1px solid var(--border)',
              color:'var(--text)', borderRadius:4,
              padding:'6px 10px', fontSize:12 }}>
            {['50','100','200','500'].map(n =>
              <option key={n} value={n}>{n} results</option>)}
          </select>
          {events.data && (
            <span style={{ fontSize:12, color:'var(--muted)' }}>
              {events.data.length} events found
            </span>
          )}
        </div>
      </div>

      {/* Results */}
      {searched && (
        <div style={{ display:'grid',
          gridTemplateColumns: selected ? '1fr 420px' : '1fr', gap:14 }}>

          {/* Event list */}
          <div style={{ background:'var(--bg2)',
            border:'1px solid var(--border)', borderRadius:8, overflowX:'auto' }}>
            {events.isPending && (
              <div style={{ padding:24, textAlign:'center', color:'var(--muted)' }}>
                Searching...
              </div>
            )}
            {!events.isPending && events.data?.length === 0 && (
              <div style={{ padding:24, textAlign:'center', color:'var(--muted)' }}>
                No events found. Try broadening your search.
              </div>
            )}
            {events.data && events.data.length > 0 && (
              <table style={{ width:'100%', borderCollapse:'collapse' }}>
                <thead>
                  <tr>
                    {['Time','Source','Host','User','Process','Command Line'].map(h => (
                      <th key={h} style={{ textAlign:'left', padding:'8px 12px',
                        borderBottom:'1px solid var(--border)',
                        color:'var(--muted)', fontSize:10,
                        fontWeight:600, textTransform:'uppercase',
                        letterSpacing:1, whiteSpace:'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {events.data.map(e => {
                    const n = e.normalized
                    const isSelected = selected?.id === e.id
                    return (
                      <tr key={e.id}
                        onClick={() => setSelected(isSelected ? null : e)}
                        style={{ borderBottom:'1px solid var(--border)22',
                          cursor:'pointer',
                          background: isSelected ? 'var(--bg3)' : 'transparent' }}
                        onMouseEnter={ev => { if (!isSelected)
                          ev.currentTarget.style.background='var(--bg3)' }}
                        onMouseLeave={ev => { if (!isSelected)
                          ev.currentTarget.style.background='transparent' }}>
                        <td style={{ padding:'8px 12px', fontSize:11,
                          color:'var(--muted)', whiteSpace:'nowrap' }}>
                          {new Date(e.received_at).toLocaleString()}
                        </td>
                        <td style={{ padding:'8px 12px' }}>
                          <Badge label={e.log_source} color="var(--accent)" />
                        </td>
                        <td style={{ padding:'8px 12px', fontSize:12,
                          fontWeight:500 }}>
                          {n.host || '—'}
                        </td>
                        <td style={{ padding:'8px 12px', fontSize:12 }}>
                          {n.user || '—'}
                        </td>
                        <td style={{ padding:'8px 12px', fontSize:12,
                          fontFamily:'monospace' }}>
                          {n.process || '—'}
                        </td>
                        <td style={{ padding:'8px 12px', fontSize:11,
                          color:'var(--muted)', maxWidth:250 }}>
                          <div style={{ overflow:'hidden',
                            textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                            {n.command_line || '—'}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>

          {/* Detail panel */}
          {selected && (
            <div style={{ background:'var(--bg2)',
              border:'1px solid var(--border)', borderRadius:8,
              padding:16, alignSelf:'start', position:'sticky', top:0 }}>
              <div style={{ display:'flex', justifyContent:'space-between',
                marginBottom:12 }}>
                <span style={{ fontWeight:600, fontSize:14 }}>Event Detail</span>
                <button onClick={() => setSelected(null)}
                  style={{ background:'none', border:'none',
                    color:'var(--muted)', cursor:'pointer', fontSize:16 }}>✕</button>
              </div>

              <div style={{ marginBottom:12 }}>
                <div style={{ fontSize:10, color:'var(--muted)',
                  textTransform:'uppercase', letterSpacing:1, marginBottom:4 }}>
                  Metadata
                </div>
                {[
                  ['ID',        selected.id.slice(0,16) + '...'],
                  ['Received',  new Date(selected.received_at).toLocaleString()],
                  ['Source',    selected.log_source],
                  ['Hash',      (selected.hash || '—').slice(0,16) + '...'],
                ].map(([k,v]) => (
                  <div key={k} style={{ display:'flex',
                    justifyContent:'space-between', padding:'4px 0',
                    borderBottom:'1px solid var(--border)22' }}>
                    <span style={{ fontSize:11, color:'var(--muted)' }}>{k}</span>
                    <span style={{ fontSize:11, fontFamily:'monospace' }}>{v}</span>
                  </div>
                ))}
              </div>

              <div>
                <div style={{ fontSize:10, color:'var(--muted)',
                  textTransform:'uppercase', letterSpacing:1, marginBottom:4 }}>
                  Normalized Fields
                </div>
                <div style={{ background:'var(--bg)', borderRadius:4,
                  padding:'10px 12px', maxHeight:400, overflowY:'auto' }}>
                  {Object.entries(selected.normalized)
                    .filter(([_, v]) => v !== null && v !== '' && v !== undefined)
                    .map(([k, v]) => (
                      <div key={k} style={{ display:'flex', gap:8,
                        marginBottom:4, alignItems:'flex-start' }}>
                        <span style={{ fontSize:10, color:'var(--accent)',
                          fontWeight:600, minWidth:100,
                          textAlign:'right', flexShrink:0 }}>{k}</span>
                        <span style={{ fontSize:11,
                          fontFamily: typeof v === 'string' ? 'monospace' : 'inherit',
                          color:'var(--text)', wordBreak:'break-all' }}>
                          {typeof v === 'object'
                            ? JSON.stringify(v, null, 2)
                            : String(v)}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
