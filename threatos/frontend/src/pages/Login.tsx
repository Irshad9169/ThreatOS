import { useState } from 'react'
import { login } from '../lib/auth'

interface Props { onLogin: () => void }

export function Login({ onLogin }: Props) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  const handleSubmit = async () => {
    if (!username || !password) { setError('Enter username and password'); return }
    setLoading(true); setError('')
    try {
      await login(username, password)
      onLogin()
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh', background: 'var(--bg)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        background: 'var(--bg2)', border: '1px solid var(--border)',
        borderRadius: 12, padding: '40px 48px', width: 380,
      }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ fontSize: 32, color: 'var(--accent)', fontWeight: 800 }}>⬡ ThreatOS</div>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>
            Security Operations Platform
          </div>
        </div>

        {/* Form */}
        <div style={{ marginBottom: 16 }}>
          <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 6 }}>
            USERNAME
          </label>
          <input
            value={username}
            onChange={e => setUsername(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSubmit()}
            autoFocus
            placeholder="admin"
            style={{
              width: '100%', background: 'var(--bg3)',
              border: '1px solid var(--border)', borderRadius: 6,
              padding: '10px 14px', color: 'var(--text)', fontSize: 14,
            }}
          />
        </div>

        <div style={{ marginBottom: 24 }}>
          <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 6 }}>
            PASSWORD
          </label>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSubmit()}
            placeholder="••••••••"
            style={{
              width: '100%', background: 'var(--bg3)',
              border: '1px solid var(--border)', borderRadius: 6,
              padding: '10px 14px', color: 'var(--text)', fontSize: 14,
            }}
          />
        </div>

        {error && (
          <div style={{
            background: 'var(--red)22', border: '1px solid var(--red)44',
            borderRadius: 6, padding: '8px 12px', fontSize: 13,
            color: 'var(--red)', marginBottom: 16,
          }}>
            {error}
          </div>
        )}

        <button
          onClick={handleSubmit}
          disabled={loading}
          style={{
            width: '100%', padding: '11px', background: 'var(--accent)',
            color: 'white', border: 'none', borderRadius: 6,
            fontSize: 14, fontWeight: 700, cursor: 'pointer',
            opacity: loading ? 0.7 : 1,
          }}>
          {loading ? 'Signing in...' : 'Sign In'}
        </button>

        <div style={{ textAlign: 'center', marginTop: 20, fontSize: 11, color: 'var(--muted)' }}>
        </div>
      </div>
    </div>
  )
}
