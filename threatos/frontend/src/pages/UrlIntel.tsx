import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { apiClient } from '../lib/api'
import { ApiKeyCard } from '../components/ApiKeyCard'

interface Stats {
  total_cached: number
  urlscan_key:  boolean
  urlhaus_key:  boolean
  safe_browsing_key: boolean
  phishtank_key: boolean
  spamhaus:     string
}

interface SourceResult {
  source:  string
  verdict: string
  message?: string
  score?: number
  cached?: boolean
  [key: string]: any
}

interface InvestigateResult {
  id?: string
  url: string
  domain: string
  overall_verdict: string
  sources?: Record<string, SourceResult>
  report_text: string
  investigated_at: string
  investigated_by?: string | null
}

interface HistoryEntry {
  id: string
  url: string
  domain: string
  overall_verdict: string
  report_text: string
  investigated_by: string | null
  investigated_at: string
}

const VERDICT_COLORS: Record<string, string> = {
  malicious:  '#f38ba8',
  suspicious: '#fab387',
  clean:      '#a6e3a1',
  unknown:    '#6c7086',
  no_api_key: '#9399b2',
}

function VerdictBadge({ verdict }: { verdict: string }) {
  const c = VERDICT_COLORS[verdict] || '#6c7086'
  return (
    <span style={{
      padding: '2px 10px', borderRadius: 4, fontSize: 11,
      fontWeight: 700, textTransform: 'uppercase',
      background: c + '22', color: c, border: `1px solid ${c}44`,
    }}>
      {verdict.replace('_', ' ')}
    </span>
  )
}

function SourceCard({ title, data }: { title: string; data: SourceResult }) {
  return (
    <div style={{ marginBottom: 10, background: 'var(--bg3)', borderRadius: 6, padding: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ fontSize: 12, fontWeight: 600 }}>{title}</span>
        <VerdictBadge verdict={data.verdict} />
      </div>

      {data.message && (
        <div style={{ fontSize: 11, color: 'var(--muted)' }}>{data.message}</div>
      )}

      {data.source === 'virustotal' && data.total_engines != null && (
        <div style={{ fontSize: 11 }}>
          <span style={{ color: 'var(--muted)' }}>Detections: </span>
          <span style={{ fontWeight: 600, color: data.malicious_engines > 0 ? '#f38ba8' : '#a6e3a1' }}>
            {data.malicious_engines}/{data.total_engines}
          </span>
          {data.report_url && (
            <>
              {' · '}
              <a href={data.report_url} target="_blank" rel="noopener noreferrer"
                style={{ color: 'var(--accent)' }}>report ↗</a>
            </>
          )}
        </div>
      )}

      {data.source === 'urlscan' && data.report_url && (
        <div style={{ fontSize: 11, display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          {data.landing_ip && <span><span style={{ color: 'var(--muted)' }}>IP: </span>{data.landing_ip}</span>}
          {data.country && <span><span style={{ color: 'var(--muted)' }}>Country: </span>{data.country}</span>}
          <a href={data.report_url} target="_blank" rel="noopener noreferrer"
            style={{ color: 'var(--accent)' }}>full report ↗</a>
          {data.screenshot_url && (
            <a href={data.screenshot_url} target="_blank" rel="noopener noreferrer"
              style={{ color: 'var(--accent)' }}>screenshot ↗</a>
          )}
          {data.public && (
            <span style={{ color: '#fab387', fontStyle: 'italic' }}>public scan</span>
          )}
        </div>
      )}

      {data.source === 'spamhaus' && (
        <div style={{ fontSize: 11 }}>
          <span style={{ color: 'var(--muted)' }}>Status: </span>
          {data.reason || (data.code ? `listed (${data.code})` : '—')}
        </div>
      )}

      {data.source === 'surbl' && (
        <div style={{ fontSize: 11 }}>
          <span style={{ color: 'var(--muted)' }}>Status: </span>
          {data.code ? `listed (${data.code})` : 'not listed'}
        </div>
      )}

      {data.source === 'urlhaus' && data.threat && (
        <div style={{ fontSize: 11 }}>
          <span style={{ color: 'var(--muted)' }}>Threat: </span>{data.threat}
          {data.tags?.length > 0 && (
            <span> · <span style={{ color: 'var(--muted)' }}>Tags:</span> {data.tags.join(', ')}</span>
          )}
        </div>
      )}

      {data.source === 'rdap' && data.age_days != null && (
        <div style={{ fontSize: 11 }}>
          <span style={{ color: 'var(--muted)' }}>Domain age: </span>
          <span style={{ fontWeight: 600, color: data.age_days < 30 ? '#fab387' : '#a6e3a1' }}>
            {data.age_days} days
          </span>
          {data.registered_at && (
            <span style={{ color: 'var(--muted)' }}>
              {' '}(registered {new Date(data.registered_at).toLocaleDateString()})
            </span>
          )}
        </div>
      )}

      {data.source === 'safe_browsing' && data.threat_types?.length > 0 && (
        <div style={{ fontSize: 11 }}>
          <span style={{ color: 'var(--muted)' }}>Listed as: </span>
          {data.threat_types.join(', ')}
        </div>
      )}

      {data.source === 'phishtank' && data.phish_id && (
        <div style={{ fontSize: 11 }}>
          <span style={{ color: 'var(--muted)' }}>Phish ID: </span>{data.phish_id}
          {data.verified && <span style={{ color: '#a6e3a1' }}> (verified)</span>}
          {data.detail_url && (
            <>
              {' · '}
              <a href={data.detail_url} target="_blank" rel="noopener noreferrer"
                style={{ color: 'var(--accent)' }}>detail ↗</a>
            </>
          )}
        </div>
      )}

      {data.cached && (
        <div style={{ fontSize: 10, color: 'var(--muted)', fontStyle: 'italic', marginTop: 4 }}>
          cached
        </div>
      )}
    </div>
  )
}

export function UrlIntel() {
  const [url, setUrl]         = useState('')
  const [result, setResult]   = useState<InvestigateResult | null>(null)
  const [copied, setCopied]   = useState(false)

  const stats = useQuery({
    queryKey: ['url-intel-stats'],
    queryFn:  () => apiClient.get<Stats>('/url-intel/stats').then(r => r.data),
  })

  const history = useQuery({
    queryKey: ['url-intel-history'],
    queryFn:  () => apiClient.get<HistoryEntry[]>('/url-intel/history').then(r => r.data),
  })

  const investigate = useMutation({
    mutationFn: (u: string) =>
      apiClient.post<InvestigateResult>('/url-intel/investigate', { url: u }).then(r => r.data),
    onSuccess: (data) => {
      setResult(data)
      setCopied(false)
      history.refetch()
    },
  })

  const handleViewHistoryEntry = (entry: HistoryEntry) => {
    setResult({
      id: entry.id, url: entry.url, domain: entry.domain,
      overall_verdict: entry.overall_verdict, report_text: entry.report_text,
      investigated_at: entry.investigated_at, investigated_by: entry.investigated_by,
    })
    setCopied(false)
  }

  const handleInvestigate = () => {
    if (!url.trim()) return
    investigate.mutate(url.trim())
  }

  const handleCopy = async () => {
    if (!result) return
    await navigator.clipboard.writeText(result.report_text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleDownload = () => {
    if (!result) return
    const blob = new Blob([result.report_text], { type: 'text/plain' })
    const objUrl = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = objUrl
    a.download = `url_investigation_${result.domain}_${new Date().toISOString().slice(0,10)}.txt`
    a.click()
    URL.revokeObjectURL(objUrl)
  }

  const mailtoHref = result
    ? `mailto:?subject=${encodeURIComponent(`URL Investigation: ${result.domain}`)}`
      + `&body=${encodeURIComponent(result.report_text)}`
    : undefined

  const s = stats.data

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700 }}>URL Scanner</h1>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
            Investigate a suspicious URL against VirusTotal, urlscan.io, Spamhaus, SURBL,
            URLhaus, domain age (RDAP), Google Safe Browsing, and PhishTank
          </div>
        </div>
      </div>

      {s && (
        <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
          <ApiKeyCard keyName="URLSCAN_API_KEY" label="urlscan.io" configured={s.urlscan_key}
            signupUrl="https://urlscan.io/user/signup" />
          <ApiKeyCard keyName="URLHAUS_AUTH_KEY" label="URLhaus" configured={s.urlhaus_key}
            signupUrl="https://auth.abuse.ch/" />
          <ApiKeyCard keyName="GOOGLE_SAFE_BROWSING_API_KEY" label="Safe Browsing"
            configured={s.safe_browsing_key}
            signupUrl="https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com" />
          <ApiKeyCard keyName="PHISHTANK_APP_KEY" label="PhishTank" configured={s.phishtank_key}
            signupUrl="https://phishtank.org/"
            hint="Works without a key too (stricter rate limit)" />
          <div style={{
            background: 'var(--bg2)', border: '1px solid #a6e3a144',
            borderRadius: 8, padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 10,
          }}>
            <span style={{ fontSize: 16 }}>✅</span>
            <div>
              <div style={{ fontSize: 13, fontWeight: 600 }}>Spamhaus DBL</div>
              <div style={{ fontSize: 11, color: 'var(--muted)' }}>No key required (DNS-based)</div>
            </div>
          </div>
          <div style={{
            background: 'var(--bg2)', border: '1px solid #a6e3a144',
            borderRadius: 8, padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 10,
          }}>
            <span style={{ fontSize: 16 }}>✅</span>
            <div>
              <div style={{ fontSize: 13, fontWeight: 600 }}>SURBL</div>
              <div style={{ fontSize: 11, color: 'var(--muted)' }}>No key required (DNS-based)</div>
            </div>
          </div>
          <div style={{
            background: 'var(--bg2)', border: '1px solid var(--border)',
            borderRadius: 8, padding: '10px 16px', textAlign: 'center', minWidth: 80,
          }}>
            <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--accent)' }}>{s.total_cached}</div>
            <div style={{ fontSize: 11, color: 'var(--muted)' }}>Cached lookups</div>
          </div>
        </div>
      )}

      <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)',
        borderRadius: 8, padding: 16, marginBottom: 16 }}>
        <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Investigate URL</h3>
        <div style={{ display: 'flex', gap: 8 }}>
          <input value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleInvestigate()}
            placeholder="https://suspicious-site.example/login"
            style={{ flex: 1, background: 'var(--bg3)', border: '1px solid var(--border)',
              borderRadius: 4, padding: '8px 12px', color: 'var(--text)', fontSize: 13 }} />
          <button onClick={handleInvestigate}
            disabled={investigate.isPending || !url.trim()}
            style={{ padding: '8px 20px', background: 'var(--accent)', color: 'white',
              border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 600, cursor: 'pointer',
              opacity: investigate.isPending || !url.trim() ? 0.6 : 1 }}>
            {investigate.isPending ? '🔍 Investigating...' : '🔍 Investigate'}
          </button>
        </div>
        {investigate.isPending && (
          <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 8 }}>
            Checking VirusTotal, urlscan.io, Spamhaus, and URLhaus — this can take up to
            ~45 seconds if urlscan.io needs to run a fresh scan.
          </div>
        )}
        {investigate.isError && (
          <div style={{ color: '#f38ba8', fontSize: 12, marginTop: 8 }}>
            {(investigate.error as any)?.response?.data?.detail || 'Investigation failed'}
          </div>
        )}
      </div>

      {result && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
          <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)',
            borderRadius: 8, padding: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              marginBottom: 12, paddingBottom: 12, borderBottom: '1px solid var(--border)' }}>
              <div>
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>{result.domain}</div>
                <div style={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}>
                  {result.url}
                </div>
              </div>
              <VerdictBadge verdict={result.overall_verdict} />
            </div>
            {result.sources ? (
              Object.entries(result.sources).map(([key, data]) => (
                <SourceCard key={key} title={key} data={data} />
              ))
            ) : (
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                Viewing a past investigation — per-source breakdown isn't stored separately,
                see the full technical evidence in the report on the right.
              </div>
            )}
          </div>

          <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)',
            borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <h3 style={{ fontSize: 13, fontWeight: 600 }}>Investigation Report</h3>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={handleCopy}
                  style={{ padding: '5px 12px', background: copied ? '#a6e3a122' : 'var(--bg3)',
                    color: copied ? '#a6e3a1' : 'var(--text)',
                    border: `1px solid ${copied ? '#a6e3a1' : 'var(--border)'}`,
                    borderRadius: 4, fontSize: 12, cursor: 'pointer' }}>
                  {copied ? '✅ Copied!' : '📋 Copy'}
                </button>
                <button onClick={handleDownload}
                  style={{ padding: '5px 12px', background: 'var(--bg3)', color: 'var(--text)',
                    border: '1px solid var(--border)', borderRadius: 4, fontSize: 12, cursor: 'pointer' }}>
                  ⬇ Download .txt
                </button>
                <a href={mailtoHref}
                  style={{ padding: '5px 12px', background: 'var(--bg3)', color: 'var(--text)',
                    border: '1px solid var(--border)', borderRadius: 4, fontSize: 12,
                    textDecoration: 'none' }}>
                  ✉ Email
                </a>
              </div>
            </div>
            <textarea readOnly value={result.report_text}
              style={{ flex: 1, minHeight: 420, width: '100%', background: 'var(--bg3)',
                border: '1px solid var(--border)', borderRadius: 4, padding: 12,
                color: 'var(--text)', fontFamily: 'monospace', fontSize: 11.5,
                lineHeight: 1.5, resize: 'vertical' }} />
          </div>
        </div>
      )}

      <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)',
        borderRadius: 8, padding: 16 }}>
        <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>
          Investigation History ({history.data?.length ?? 0})
        </h3>

        {history.isLoading && (
          <div style={{ color: 'var(--muted)', fontSize: 13, padding: '12px 0' }}>Loading...</div>
        )}
        {history.data?.length === 0 && (
          <div style={{ color: 'var(--muted)', fontSize: 13, padding: '12px 0' }}>
            No investigations yet. Run one above.
          </div>
        )}
        {(history.data?.length ?? 0) > 0 && (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['Domain', 'Verdict', 'Investigated By', 'Investigated At', ''].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '6px 10px',
                    borderBottom: '1px solid var(--border)', fontSize: 10, color: 'var(--muted)',
                    fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {history.data?.map(entry => (
                <tr key={entry.id} style={{ borderBottom: '1px solid var(--border)22' }}>
                  <td style={{ padding: '7px 10px', fontFamily: 'monospace', fontSize: 12 }}>
                    {entry.domain}
                  </td>
                  <td style={{ padding: '7px 10px' }}>
                    <VerdictBadge verdict={entry.overall_verdict} />
                  </td>
                  <td style={{ padding: '7px 10px', fontSize: 12 }}>
                    {entry.investigated_by || '—'}
                  </td>
                  <td style={{ padding: '7px 10px', fontSize: 11, color: 'var(--muted)' }}>
                    {new Date(entry.investigated_at).toLocaleString()}
                  </td>
                  <td style={{ padding: '7px 10px' }}>
                    <button onClick={() => handleViewHistoryEntry(entry)}
                      style={{ fontSize: 11, padding: '3px 10px', background: 'var(--bg3)',
                        border: '1px solid var(--border)', borderRadius: 4, cursor: 'pointer',
                        color: 'var(--accent)' }}>
                      View Report
                    </button>
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
