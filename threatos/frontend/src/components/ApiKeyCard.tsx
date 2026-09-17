import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '../lib/api'
import { hasRole } from '../lib/auth'

interface Props {
  keyName:    string
  label:      string
  configured: boolean
  signupUrl?: string
  hint?:      string
}

export function ApiKeyCard({ keyName, label, configured, signupUrl, hint }: Props) {
  const [editing, setEditing] = useState(false)
  const [value, setValue]     = useState('')
  const qc = useQueryClient()
  const isAdmin = hasRole('admin')

  const save = useMutation({
    mutationFn: () =>
      apiClient.post('/settings/api-keys', { key_name: keyName, value }).then(r => r.data),
    onSuccess: () => {
      setEditing(false)
      setValue('')
      qc.invalidateQueries()
    },
  })

  return (
    <div style={{
      background: 'var(--bg2)', border: `1px solid ${configured ? '#a6e3a144' : '#f38ba844'}`,
      borderRadius: 8, padding: '10px 16px', display: 'flex', flexDirection: 'column',
      gap: 6, minWidth: 220,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ fontSize: 16 }}>{configured ? '✅' : '❌'}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 600 }}>{label}</div>
          <div style={{ fontSize: 11, color: 'var(--muted)' }}>
            {configured
              ? (hint || 'API key configured')
              : (signupUrl ? (
                  <a href={signupUrl} target="_blank" rel="noopener noreferrer"
                    style={{ color: 'var(--accent)' }}>
                    Get free API key →
                  </a>
                ) : (hint || 'Not configured'))}
          </div>
        </div>
        {isAdmin && !editing && (
          <button onClick={() => setEditing(true)}
            style={{ fontSize: 11, padding: '3px 8px', background: 'var(--bg3)',
              border: '1px solid var(--border)', borderRadius: 4, cursor: 'pointer',
              color: 'var(--text)' }}>
            {configured ? 'Change' : 'Add'}
          </button>
        )}
      </div>

      {isAdmin && editing && (
        <div style={{ display: 'flex', gap: 6 }}>
          <input type="password" value={value}
            onChange={e => setValue(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && value.trim() && save.mutate()}
            placeholder="Paste API key..." autoFocus
            style={{ flex: 1, background: 'var(--bg3)', border: '1px solid var(--border)',
              borderRadius: 4, padding: '5px 8px', color: 'var(--text)', fontSize: 12 }} />
          <button onClick={() => value.trim() && save.mutate()}
            disabled={save.isPending || !value.trim()}
            style={{ fontSize: 11, padding: '5px 10px', background: 'var(--accent)',
              color: 'white', border: 'none', borderRadius: 4, cursor: 'pointer',
              opacity: save.isPending || !value.trim() ? 0.6 : 1 }}>
            {save.isPending ? 'Saving...' : 'Save'}
          </button>
          <button onClick={() => { setEditing(false); setValue('') }}
            style={{ fontSize: 11, padding: '5px 10px', background: 'transparent',
              color: 'var(--muted)', border: '1px solid var(--border)', borderRadius: 4,
              cursor: 'pointer' }}>
            Cancel
          </button>
        </div>
      )}

      {save.isError && (
        <div style={{ fontSize: 11, color: '#f38ba8' }}>
          {(save.error as { response?: { data?: { detail?: string } } })?.response?.data?.detail
            || 'Failed to save'}
        </div>
      )}
    </div>
  )
}
