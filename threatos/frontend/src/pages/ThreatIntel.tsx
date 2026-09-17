import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '../lib/api'
import { Badge } from '../components/Badge'
import { ApiKeyCard } from '../components/ApiKeyCard'

interface TIStats {
  total_cached:   number
  malicious:      number
  suspicious:     number
  cache_hours:    number
  virustotal_key: boolean
  abuseipdb_key:  boolean
}

interface Enrichment {
  ioc_type:   string
  ioc_value:  string
  source:     string
  verdict:    string
  score:      number | null
  country:    string | null
  asn:        string | null
  tags:       string[]
  enriched_at:string
  expires_at: string
}

interface EnrichResult {
  ioc_type:        string
  ioc_value:       string
  overall_verdict: string
  sources:         Record<string, any>
}

const VERDICT_COLORS: Record<string, string> = {
  malicious:  '#f38ba8',
  suspicious: '#fab387',
  clean:      '#a6e3a1',
  unknown:    '#6c7086',
  no_api_key: '#9399b2',
}

const IOC_EXAMPLES: Record<string, string> = {
  ip:     '8.8.8.8',
  sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  md5:    '44d88612fea8a8f36de82e1278abb02f',
  domain: 'example.com',
}

function VerdictBadge({ verdict }: { verdict: string }) {
  return (
    <span style={{
      padding: '2px 10px', borderRadius: 4, fontSize: 11,
      fontWeight: 700, textTransform: 'uppercase',
      background: (VERDICT_COLORS[verdict] || '#6c7086') + '22',
      color: VERDICT_COLORS[verdict] || '#6c7086',
      border: `1px solid ${(VERDICT_COLORS[verdict] || '#6c7086')}44`,
    }}>
      {verdict.replace('_', ' ')}
    </span>
  )
}

export function ThreatIntel() {
  const qc = useQueryClient()
  const [iocValue, setIocValue]   = useState('')
  const [iocType,  setIocType]    = useState('')
  const [result,   setResult]     = useState<EnrichResult | null>(null)
  const [cacheFilter, setCacheFilter] = useState({ verdict: '', ioc_type: '' })

  const stats = useQuery({
    queryKey: ['ti-stats'],
    queryFn:  () => apiClient.get<TIStats>('/ti/stats').then(r => r.data),
  })

  const cache = useQuery({
    queryKey: ['ti-cache', cacheFilter],
    queryFn:  () => {
      const p: Record<string,string> = {}
      if (cacheFilter.verdict)  p.verdict  = cacheFilter.verdict
      if (cacheFilter.ioc_type) p.ioc_type = cacheFilter.ioc_type
      return apiClient.get<Enrichment[]>('/ti/cache', { params: p })
        .then(r => r.data)
    },
  })

  const enrich = useMutation({
    mutationFn: (data: { ioc_value: string; ioc_type?: string }) =>
      apiClient.post<EnrichResult>('/ti/enrich', data).then(r => r.data),
    onSuccess: (data) => {
      setResult(data)
      qc.invalidateQueries({ queryKey: ['ti-stats'] })
      qc.invalidateQueries({ queryKey: ['ti-cache'] })
    },
  })

  const cleanup = useMutation({
    mutationFn: () => apiClient.delete('/ti/cache/cleanup').then(r => r.data),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['ti-cache'] }),
  })

  const handleEnrich = () => {
    if (!iocValue.trim()) return
    const body: any = { ioc_value: iocValue.trim() }
    if (iocType) body.ioc_type = iocType
    enrich.mutate(body)
  }

  const s = stats.data

  return (
    <div>
      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between',
        alignItems:'center', marginBottom:20 }}>
        <div>
          <h1 style={{ fontSize:20, fontWeight:700 }}>Threat Intelligence</h1>
          <div style={{ fontSize:12, color:'var(--muted)', marginTop:2 }}>
            Enrich alerts with VirusTotal + AbuseIPDB context
          </div>
        </div>
      </div>

      {/* API key status */}
      {s && (
        <div style={{ display:'flex', gap:10, marginBottom:16, flexWrap:'wrap' }}>
          <ApiKeyCard keyName="VIRUSTOTAL_API_KEY" label="VirusTotal" configured={s.virustotal_key}
            signupUrl="https://www.virustotal.com/gui/my-apikey" />
          <ApiKeyCard keyName="ABUSEIPDB_API_KEY" label="AbuseIPDB" configured={s.abuseipdb_key}
            signupUrl="https://www.abuseipdb.com/account/api" />

          {/* Stats */}
          {[
            { label:'Cached IOCs',  value: s.total_cached },
            { label:'Malicious',    value: s.malicious,  color:'#f38ba8' },
            { label:'Suspicious',   value: s.suspicious, color:'#fab387' },
            { label:'Cache TTL',    value: `${s.cache_hours}h` },
          ].map(stat => (
            <div key={stat.label} style={{ background:'var(--bg2)',
              border:'1px solid var(--border)', borderRadius:8,
              padding:'10px 16px', textAlign:'center', minWidth:80 }}>
              <div style={{ fontSize:18, fontWeight:800,
                color: (stat as any).color || 'var(--accent)' }}>
                {stat.value}
              </div>
              <div style={{ fontSize:11, color:'var(--muted)' }}>{stat.label}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>

        {/* IOC Lookup */}
        <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
          borderRadius:8, padding:16 }}>
          <h3 style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>
            IOC Lookup
          </h3>
          <div style={{ marginBottom:10 }}>
            <label style={{ fontSize:11, color:'var(--muted)', display:'block', marginBottom:4 }}>
              IOC VALUE
            </label>
            <input value={iocValue}
              onChange={e => setIocValue(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleEnrich()}
              placeholder="IP address, file hash, or domain..."
              style={{ width:'100%', background:'var(--bg3)',
                border:'1px solid var(--border)', borderRadius:4,
                padding:'8px 12px', color:'var(--text)', fontSize:13 }} />
          </div>

          <div style={{ marginBottom:12 }}>
            <label style={{ fontSize:11, color:'var(--muted)', display:'block', marginBottom:4 }}>
              TYPE (optional — auto-detected)
            </label>
            <select value={iocType} onChange={e => setIocType(e.target.value)}
              style={{ width:'100%', background:'var(--bg3)',
                border:'1px solid var(--border)', color:'var(--text)',
                borderRadius:4, padding:'7px 10px', fontSize:13 }}>
              <option value="">Auto-detect</option>
              <option value="ip">IP Address</option>
              <option value="sha256">SHA256 Hash</option>
              <option value="md5">MD5 Hash</option>
              <option value="sha1">SHA1 Hash</option>
              <option value="domain">Domain</option>
            </select>
          </div>

          {/* Examples */}
          <div style={{ marginBottom:12 }}>
            <div style={{ fontSize:11, color:'var(--muted)', marginBottom:6 }}>
              Try an example:
            </div>
            <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
              {Object.entries(IOC_EXAMPLES).map(([type, val]) => (
                <button key={type}
                  onClick={() => { setIocValue(val); setIocType(type) }}
                  style={{ fontSize:10, padding:'2px 8px', borderRadius:4,
                    background:'var(--bg3)', color:'var(--accent)',
                    border:'1px solid var(--accent)33', cursor:'pointer' }}>
                  {type}
                </button>
              ))}
            </div>
          </div>

          <button onClick={handleEnrich}
            disabled={enrich.isPending || !iocValue.trim()}
            style={{ padding:'8px 20px', background:'var(--accent)',
              color:'white', border:'none', borderRadius:6,
              fontSize:13, fontWeight:600, cursor:'pointer',
              opacity: enrich.isPending || !iocValue.trim() ? 0.6 : 1 }}>
            {enrich.isPending ? '🔍 Checking...' : '🔍 Lookup'}
          </button>

          {enrich.isError && (
            <div style={{ color:'#f38ba8', fontSize:12, marginTop:8 }}>
              {(enrich.error as any)?.response?.data?.detail || 'Lookup failed'}
            </div>
          )}
        </div>

        {/* Result */}
        <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
          borderRadius:8, padding:16 }}>
          <h3 style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>
            Result
          </h3>
          {!result && !enrich.isPending && (
            <div style={{ color:'var(--muted)', fontSize:13, padding:'20px 0' }}>
              Enter an IOC and click Lookup to see results.
            </div>
          )}
          {enrich.isPending && (
            <div style={{ color:'var(--muted)', fontSize:13, padding:'20px 0' }}>
              Querying threat intelligence sources...
            </div>
          )}
          {result && (
            <div>
              <div style={{ display:'flex', justifyContent:'space-between',
                alignItems:'center', marginBottom:12,
                paddingBottom:12, borderBottom:'1px solid var(--border)' }}>
                <div>
                  <div style={{ fontSize:12, color:'var(--muted)' }}>
                    {result.ioc_type.toUpperCase()}
                  </div>
                  <div style={{ fontFamily:'monospace', fontSize:13,
                    fontWeight:600, wordBreak:'break-all' }}>
                    {result.ioc_value}
                  </div>
                </div>
                <VerdictBadge verdict={result.overall_verdict} />
              </div>

              {Object.entries(result.sources).map(([source, data]: [string, any]) => (
                <div key={source} style={{ marginBottom:10,
                  background:'var(--bg3)', borderRadius:6, padding:12 }}>
                  <div style={{ display:'flex', justifyContent:'space-between',
                    marginBottom:6 }}>
                    <span style={{ fontSize:12, fontWeight:600,
                      textTransform:'capitalize' }}>{source}</span>
                    <VerdictBadge verdict={data.verdict || 'unknown'} />
                  </div>

                  {data.message && (
                    <div style={{ fontSize:11, color:'var(--muted)' }}>
                      {data.message}
                    </div>
                  )}

                  <div style={{ display:'flex', gap:16, flexWrap:'wrap', marginTop:4 }}>
                    {data.score != null && (
                      <div style={{ fontSize:11 }}>
                        <span style={{ color:'var(--muted)' }}>Score: </span>
                        <span style={{ fontWeight:600,
                          color: data.score >= 80 ? '#f38ba8'
                            : data.score >= 25 ? '#fab387' : '#a6e3a1' }}>
                          {data.score}%
                        </span>
                      </div>
                    )}
                    {data.malicious_engines != null && (
                      <div style={{ fontSize:11 }}>
                        <span style={{ color:'var(--muted)' }}>Engines: </span>
                        <span style={{ color:'#f38ba8', fontWeight:600 }}>
                          {data.malicious_engines}
                        </span>
                        <span style={{ color:'var(--muted)' }}>
                          /{data.total_engines} malicious
                        </span>
                      </div>
                    )}
                    {data.country && (
                      <div style={{ fontSize:11 }}>
                        <span style={{ color:'var(--muted)' }}>Country: </span>
                        {data.country}
                      </div>
                    )}
                    {data.total_reports != null && (
                      <div style={{ fontSize:11 }}>
                        <span style={{ color:'var(--muted)' }}>Reports: </span>
                        <span style={{ fontWeight:600 }}>{data.total_reports}</span>
                      </div>
                    )}
                    {data.isp && (
                      <div style={{ fontSize:11 }}>
                        <span style={{ color:'var(--muted)' }}>ISP: </span>
                        {data.isp}
                      </div>
                    )}
                    {data.cached && (
                      <div style={{ fontSize:10, color:'var(--muted)',
                        fontStyle:'italic' }}>cached</div>
                    )}
                  </div>

                  {data.tags && data.tags.length > 0 && (
                    <div style={{ display:'flex', gap:4, flexWrap:'wrap', marginTop:6 }}>
                      {data.tags.slice(0,5).map((tag: string, i: number) => (
                        <span key={i} style={{ fontSize:10, padding:'1px 6px',
                          background:'var(--bg)', borderRadius:3,
                          color:'var(--muted)',
                          border:'1px solid var(--border)' }}>
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* TI Cache */}
      <div style={{ background:'var(--bg2)', border:'1px solid var(--border)',
        borderRadius:8, padding:16, marginTop:16 }}>
        <div style={{ display:'flex', justifyContent:'space-between',
          alignItems:'center', marginBottom:12 }}>
          <h3 style={{ fontSize:13, fontWeight:600 }}>
            TI Cache ({cache.data?.length ?? 0} entries)
          </h3>
          <div style={{ display:'flex', gap:8, alignItems:'center' }}>
            <select value={cacheFilter.verdict}
              onChange={e => setCacheFilter(f => ({ ...f, verdict: e.target.value }))}
              style={{ background:'var(--bg3)', border:'1px solid var(--border)',
                color:'var(--text)', borderRadius:4, padding:'4px 8px', fontSize:12 }}>
              <option value="">All verdicts</option>
              {['malicious','suspicious','clean','unknown'].map(v =>
                <option key={v} value={v}>{v}</option>)}
            </select>
            <select value={cacheFilter.ioc_type}
              onChange={e => setCacheFilter(f => ({ ...f, ioc_type: e.target.value }))}
              style={{ background:'var(--bg3)', border:'1px solid var(--border)',
                color:'var(--text)', borderRadius:4, padding:'4px 8px', fontSize:12 }}>
              <option value="">All types</option>
              {['ip','sha256','md5','sha1','domain'].map(v =>
                <option key={v} value={v}>{v}</option>)}
            </select>
            <button onClick={() => cleanup.mutate()}
              disabled={cleanup.isPending}
              style={{ padding:'4px 12px', background:'var(--red)22',
                color:'var(--red)', border:'1px solid var(--red)44',
                borderRadius:4, fontSize:12, cursor:'pointer' }}>
              Clean Expired
            </button>
          </div>
        </div>

        {cache.data?.length === 0 && (
          <div style={{ color:'var(--muted)', fontSize:13, padding:'12px 0' }}>
            No cached enrichments yet. Look up an IOC above.
          </div>
        )}

        {(cache.data?.length ?? 0) > 0 && (
          <table style={{ width:'100%', borderCollapse:'collapse' }}>
            <thead>
              <tr>
                {['Type','IOC Value','Source','Verdict','Score','Country','Cached At'].map(h => (
                  <th key={h} style={{ textAlign:'left', padding:'6px 10px',
                    borderBottom:'1px solid var(--border)',
                    fontSize:10, color:'var(--muted)',
                    fontWeight:600, textTransform:'uppercase', letterSpacing:1 }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {cache.data?.map((row, i) => (
                <tr key={i} style={{ borderBottom:'1px solid var(--border)22' }}>
                  <td style={{ padding:'7px 10px' }}>
                    <Badge label={row.ioc_type} color="var(--accent)" />
                  </td>
                  <td style={{ padding:'7px 10px', fontFamily:'monospace',
                    fontSize:11, maxWidth:200 }}>
                    <div style={{ overflow:'hidden', textOverflow:'ellipsis',
                      whiteSpace:'nowrap' }}>
                      {row.ioc_value}
                    </div>
                  </td>
                  <td style={{ padding:'7px 10px', fontSize:12 }}>{row.source}</td>
                  <td style={{ padding:'7px 10px' }}>
                    <VerdictBadge verdict={row.verdict} />
                  </td>
                  <td style={{ padding:'7px 10px', fontSize:12 }}>
                    {row.score != null ? `${row.score}%` : '—'}
                  </td>
                  <td style={{ padding:'7px 10px', fontSize:12 }}>
                    {row.country || '—'}
                  </td>
                  <td style={{ padding:'7px 10px', fontSize:11, color:'var(--muted)' }}>
                    {new Date(row.enriched_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
