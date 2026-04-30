import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '../lib/api'
import { getCurrentUser, hasRole } from '../lib/auth'
import { Badge } from '../components/Badge'
import { Table } from '../components/Table'

interface User {
  id: string; username: string; email: string
  full_name: string | null; role: string
  is_active: boolean; last_login: string | null
  has_api_key: boolean; created_at: string
}

const ROLE_COLORS: Record<string, string> = {
  admin: 'var(--red)', engineer: 'var(--orange)',
  analyst: 'var(--accent)', ingest: 'var(--muted)',
}

const ROLES = ['analyst','engineer','admin','ingest']

export function Users() {
  const qc      = useQueryClient()
  const me      = getCurrentUser()
  const isAdmin = hasRole('admin')

  const users = useQuery({
    queryKey: ['users'],
    queryFn:  () => apiClient.get<User[]>('/auth/users').then(r => r.data),
  })

  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({
    username: '', email: '', password: '', full_name: '', role: 'analyst',
  })
  const [apiKeyResult, setApiKeyResult] = useState<{id: string; key: string} | null>(null)
  const [resetForm, setResetForm] = useState<{id: string; username: string} | null>(null)
  const [newPassword, setNewPassword] = useState('')

  const createUser = useMutation({
    mutationFn: (data: object) => apiClient.post('/auth/users', data).then(r => r.data),
    onSuccess:  () => { qc.invalidateQueries({ queryKey: ['users'] }); setShowCreate(false);
                        setForm({ username:'',email:'',password:'',full_name:'',role:'analyst' }) },
  })

  const updateRole = useMutation({
    mutationFn: ({ id, role }: { id: string; role: string }) =>
      apiClient.put(`/auth/users/${id}`, { role }).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })

  const toggleActive = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) =>
      apiClient.post(`/auth/users/${id}/${active ? 'activate' : 'deactivate'}`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })

  const generateKey = useMutation({
    mutationFn: (id: string) =>
      apiClient.post(`/auth/users/${id}/generate-api-key`).then(r => r.data),
    onSuccess: (data, id) => setApiKeyResult({ id, key: data.api_key }),
  })

  const revokeKey = useMutation({
    mutationFn: (id: string) =>
      apiClient.delete(`/auth/users/${id}/api-key`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })

  const resetPassword = useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) =>
      apiClient.post(`/auth/users/${id}/reset-password`, { new_password: password }).then(r => r.data),
    onSuccess: () => { setResetForm(null); setNewPassword('') },
  })

  const rows = (users.data ?? []).map(u => [
    <div>
      <div style={{ fontWeight: 600, fontSize: 13 }}>{u.username}</div>
      <div style={{ fontSize: 11, color: 'var(--muted)' }}>{u.full_name || u.email}</div>
    </div>,
    u.email,
    <Badge label={u.role.toUpperCase()} color={ROLE_COLORS[u.role] || 'var(--muted)'} />,
    <Badge label={u.is_active ? 'Active' : 'Inactive'}
      color={u.is_active ? 'var(--green)' : 'var(--muted)'} />,
    u.has_api_key
      ? <Badge label="Has Key" color="var(--green)" />
      : <span style={{ color: 'var(--muted)', fontSize: 11 }}>No key</span>,
    u.last_login
      ? <span style={{ fontSize: 11 }}>{new Date(u.last_login).toLocaleString()}</span>
      : <span style={{ color: 'var(--muted)', fontSize: 11 }}>Never</span>,
    // Actions column — admin only, cannot modify yourself
    isAdmin && u.id !== me?.id ? (
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
        {/* Role selector */}
        <select value={u.role}
          onChange={e => updateRole.mutate({ id: u.id, role: e.target.value })}
          style={{ background: 'var(--bg3)', border: '1px solid var(--border)',
            color: 'var(--text)', borderRadius: 4, padding: '2px 6px', fontSize: 11 }}>
          {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
        </select>

        {/* Activate / Deactivate */}
        <button onClick={() => toggleActive.mutate({ id: u.id, active: !u.is_active })}
          style={{ fontSize: 11, padding: '2px 8px', borderRadius: 4,
            background: u.is_active ? 'var(--red)22' : 'var(--green)22',
            color: u.is_active ? 'var(--red)' : 'var(--green)',
            border: `1px solid ${u.is_active ? 'var(--red)' : 'var(--green)'}44` }}>
          {u.is_active ? 'Deactivate' : 'Activate'}
        </button>

        {/* Reset password */}
        <button onClick={() => setResetForm({ id: u.id, username: u.username })}
          style={{ fontSize: 11, padding: '2px 8px', borderRadius: 4,
            background: 'var(--yellow)22', color: 'var(--yellow)',
            border: '1px solid var(--yellow)44' }}>
          Reset Pwd
        </button>

        {/* API key */}
        {u.has_api_key
          ? <button onClick={() => revokeKey.mutate(u.id)}
              style={{ fontSize: 11, padding: '2px 8px', borderRadius: 4,
                background: 'var(--red)22', color: 'var(--red)',
                border: '1px solid var(--red)44' }}>
              Revoke Key
            </button>
          : <button onClick={() => generateKey.mutate(u.id)}
              style={{ fontSize: 11, padding: '2px 8px', borderRadius: 4,
                background: 'var(--accent)22', color: 'var(--accent)',
                border: '1px solid var(--accent)44' }}>
              Gen API Key
            </button>}
      </div>
    ) : (
      <span style={{ color: 'var(--muted)', fontSize: 11 }}>
        {u.id === me?.id ? '(you)' : '—'}
      </span>
    ),
  ])

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700 }}>User Management</h1>
        {isAdmin && (
          <button onClick={() => setShowCreate(!showCreate)}
            style={{ padding: '7px 16px', background: 'var(--accent)', color: 'white',
              border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 600 }}>
            + New User
          </button>
        )}
      </div>

      {/* Role legend */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
        {[
          { role: 'admin',    desc: 'Full access — manage users, all features' },
          { role: 'engineer', desc: 'Create/edit rules, manage assets, run scans' },
          { role: 'analyst',  desc: 'View alerts, update status, view all data' },
          { role: 'ingest',   desc: 'API key only — push events to /api/ingest/*' },
        ].map(({ role, desc }) => (
          <div key={role} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Badge label={role.toUpperCase()} color={ROLE_COLORS[role]} />
            <span style={{ fontSize: 11, color: 'var(--muted)' }}>{desc}</span>
          </div>
        ))}
      </div>

      {/* Create user form */}
      {showCreate && isAdmin && (
        <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)',
          borderRadius: 8, padding: 20, marginBottom: 16 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Create New User</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            {[
              ['Username',  'username',  'text',     'jsmith'],
              ['Email',     'email',     'email',    'j.smith@company.com'],
              ['Full Name', 'full_name', 'text',     'John Smith'],
              ['Password',  'password',  'password', '••••••••'],
            ].map(([label, key, type, ph]) => (
              <div key={key}>
                <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
                  {label}
                </label>
                <input type={type} value={(form as any)[key]}
                  onChange={e => setForm({ ...form, [key]: e.target.value })}
                  placeholder={ph}
                  style={{ width: '100%', background: 'var(--bg3)',
                    border: '1px solid var(--border)', borderRadius: 4,
                    padding: '7px 10px', color: 'var(--text)', fontSize: 13 }} />
              </div>
            ))}
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
                Role
              </label>
              <select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}
                style={{ width: '100%', background: 'var(--bg3)',
                  border: '1px solid var(--border)', color: 'var(--text)',
                  borderRadius: 4, padding: '7px 10px', fontSize: 13 }}>
                {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
            </div>
          </div>
          {createUser.isError && (
            <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 8 }}>
              {(createUser.error as any)?.response?.data?.detail || 'Create failed'}
            </div>
          )}
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button onClick={() => createUser.mutate(form)}
              disabled={createUser.isPending}
              style={{ padding: '7px 16px', background: 'var(--accent)', color: 'white',
                border: 'none', borderRadius: 6, fontSize: 13, opacity: createUser.isPending ? 0.7 : 1 }}>
              {createUser.isPending ? 'Creating...' : 'Create User'}
            </button>
            <button onClick={() => setShowCreate(false)}
              style={{ padding: '7px 16px', background: 'var(--bg3)', color: 'var(--muted)',
                border: '1px solid var(--border)', borderRadius: 6, fontSize: 13 }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* API key display modal */}
      {apiKeyResult && (
        <div style={{ background: 'var(--bg2)', border: '2px solid var(--green)',
          borderRadius: 8, padding: 16, marginBottom: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontWeight: 600, color: 'var(--green)' }}>
              API Key Generated — Copy now, it won't be shown again
            </span>
            <button onClick={() => { setApiKeyResult(null); qc.invalidateQueries({queryKey:['users']}) }}
              style={{ background: 'none', border: 'none', color: 'var(--muted)', cursor: 'pointer' }}>✕</button>
          </div>
          <div style={{ background: 'var(--bg)', borderRadius: 4, padding: '10px 14px',
            fontFamily: 'monospace', fontSize: 13, color: 'var(--accent)',
            wordBreak: 'break-all', userSelect: 'all' }}>
            {apiKeyResult.key}
          </div>
          <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 8 }}>
            Use as: <code style={{ color: 'var(--accent)' }}>X-API-Key: {apiKeyResult.key}</code>
          </div>
        </div>
      )}

      {/* Reset password modal */}
      {resetForm && (
        <div style={{ background: 'var(--bg2)', border: '1px solid var(--yellow)',
          borderRadius: 8, padding: 16, marginBottom: 16 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>
            Reset password for: <span style={{ color: 'var(--accent)' }}>{resetForm.username}</span>
          </h3>
          <input type="password" value={newPassword}
            onChange={e => setNewPassword(e.target.value)}
            placeholder="New password (min 8 chars)"
            style={{ background: 'var(--bg3)', border: '1px solid var(--border)',
              borderRadius: 4, padding: '7px 10px', color: 'var(--text)',
              fontSize: 13, width: 300, marginRight: 8 }} />
          <button onClick={() => resetPassword.mutate({ id: resetForm.id, password: newPassword })}
            disabled={newPassword.length < 8}
            style={{ padding: '7px 14px', background: 'var(--yellow)', color: 'var(--bg)',
              border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 600,
              opacity: newPassword.length < 8 ? 0.5 : 1, marginRight: 8 }}>
            Reset
          </button>
          <button onClick={() => { setResetForm(null); setNewPassword('') }}
            style={{ padding: '7px 14px', background: 'var(--bg3)', color: 'var(--muted)',
              border: '1px solid var(--border)', borderRadius: 6, fontSize: 13 }}>
            Cancel
          </button>
        </div>
      )}

      {/* Users table */}
      <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8 }}>
        <Table
          headers={['User', 'Email', 'Role', 'Status', 'API Key', 'Last Login', 'Actions']}
          rows={rows}
          empty="No users found"
        />
      </div>

      {/* My account section */}
      <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)',
        borderRadius: 8, padding: 16, marginTop: 16 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>My Account</h3>
        <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 12 }}>
          Logged in as <strong style={{ color: 'var(--accent)' }}>{me?.username}</strong>
          {' '}· Role: <Badge label={(me?.role || '').toUpperCase()} color={ROLE_COLORS[me?.role || ''] || 'var(--muted)'} />
        </div>
        <ChangePasswordForm />
      </div>
    </div>
  )
}

function ChangePasswordForm() {
  const [form, setForm] = useState({ current_password: '', new_password: '', confirm: '' })
  const [msg,  setMsg]  = useState('')
  const [err,  setErr]  = useState('')

  const change = useMutation({
    mutationFn: (data: object) => apiClient.post('/auth/change-password', data).then(r => r.data),
    onSuccess:  () => {
      setMsg('Password changed successfully')
      setErr('')
      setForm({ current_password: '', new_password: '', confirm: '' })
    },
    onError: (e: any) => {
      setErr(e.response?.data?.detail || 'Failed to change password')
      setMsg('')
    },
  })

  const handleSubmit = () => {
    if (form.new_password !== form.confirm) { setErr('Passwords do not match'); return }
    if (form.new_password.length < 8) { setErr('Minimum 8 characters'); return }
    change.mutate({ current_password: form.current_password, new_password: form.new_password })
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        {[
          ['Current Password', 'current_password'],
          ['New Password',     'new_password'],
          ['Confirm New',      'confirm'],
        ].map(([label, key]) => (
          <div key={key}>
            <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
              {label}
            </label>
            <input type="password" value={(form as any)[key]}
              onChange={e => setForm({ ...form, [key]: e.target.value })}
              style={{ background: 'var(--bg3)', border: '1px solid var(--border)',
                borderRadius: 4, padding: '6px 10px', color: 'var(--text)', fontSize: 13, width: 180 }} />
          </div>
        ))}
        <button onClick={handleSubmit} disabled={change.isPending}
          style={{ padding: '7px 14px', background: 'var(--accent)', color: 'white',
            border: 'none', borderRadius: 6, fontSize: 13, height: 34 }}>
          Change Password
        </button>
      </div>
      {err && <div style={{ color: 'var(--red)',   fontSize: 12, marginTop: 6 }}>{err}</div>}
      {msg && <div style={{ color: 'var(--green)', fontSize: 12, marginTop: 6 }}>{msg}</div>}
    </div>
  )
}
