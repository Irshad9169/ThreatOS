import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { apiClient } from '../lib/api'

interface Stats {
  total_cached: number
  urlscan_key:  boolean
  urlhaus_key:  boolean
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
  url: string
  domain: string
  overall_verdict: string
  sources: Record<string, SourceResult>
  report_text: string
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

      {data.source === 'urlhaus' && data.threat && (
        <div style={{ fontSize: 11 }}>
          <span style={{ color: 'var(--muted)' }}>Threat: </span>{data.threat}
          {data.tags?.length > 0 && (
            <span> · <span style={{ color: 'var(--muted)' }}>Tags:</span> {data.tags.join(', ')}</span>
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

  const investigate = useMutation({
    mutationFn: (u: string) =>
      apiClient.post<InvestigateResult>('/url-intel/investigate', { url: u }).then(r => r.data),
    onSuccess: (data) => { setResult(data); setCopied(false) },
  })

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
            Investigate a suspicious URL against VirusTotal, urlscan.io, Spamhaus, and URLhaus
          </div>
        </div>
      </div>

      {s && (
        <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
          {[
            { name: 'urlscan.io', ok: s.urlscan_key, url: 'https://urlscan.io/user/signup' },
            { name: 'URLhaus',    ok: s.urlhaus_key, url: 'https://auth.abuse.ch/' },
          ].map(api => (
            <div key={api.name} style={{
              background: 'var(--bg2)', border: `1px solid ${api.ok ? '#a6e3a144' : '#f38ba844'}`,
              borderRadius: 8, padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 10,
            }}>
              <span style={{ fontSize: 16 }}>{api.ok ? '✅' : '❌'}</span>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600 }}>{api.name}</div>
                <div style={{ fontSize: 11, color: 'var(--muted)' }}>
                  {api.ok ? 'API key configured' : (
                    <a href={api.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>
                      Get free API key →
                    </a>
                  )}
                </div>
              </div>
            </div>
          ))}
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
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
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
            {Object.entries(result.sources).map(([key, data]) => (
              <SourceCard key={key} title={key} data={data} />
            ))}
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
    </div>
  )
}
