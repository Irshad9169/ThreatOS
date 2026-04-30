import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { assetsApi } from '../lib/api'
import { Table } from '../components/Table'
import { Badge } from '../components/Badge'
import { hasRole } from '../lib/auth'

const CRIT_COLORS: Record<number, string> = {
  1: 'var(--blue)', 2: 'var(--blue)', 3: 'var(--orange)', 4: 'var(--red)',
}
const CRIT_LABELS: Record<number, string> = {
  1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical',
}

export function Assets() {
  const qc       = useQueryClient()
  const canEdit  = hasRole('engineer', 'admin')
  const assets   = useQuery({ queryKey: ['assets'], queryFn: () => assetsApi.list() })
  const [show,   setShow]   = useState(false)
  const [confirm, setConfirm] = useState<string | null>(null)
  const [form,   setForm]   = useState({
    hostname: '', criticality: 2, environment: 'production',
    os_type: 'windows', owner_team: '',
  })

  const create = useMutation({
    mutationFn: (data: object) => assetsApi.create(data),
    onSuccess:  () => { qc.invalidateQueries({ queryKey: ['assets'] }); setShow(false) },
  })
  const updateCrit = useMutation({
    mutationFn: ({ id, c }: { id: string; c: number }) => assetsApi.updateCriticality(id, c),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['assets'] }),
  })
  const deleteAsset = useMutation({
    mutationFn: (id: string) => assetsApi.delete(id),
    onSuccess:  () => { qc.invalidateQueries({ queryKey: ['assets'] }); setConfirm(null) },
  })

  const rows = (assets.data ?? []).map(a => [
    <div>
      <div style={{ fontWeight: 600, fontSize: 13 }}>{a.hostname}</div>
      <div style={{ fontSize: 11, color: 'var(--muted)' }}>{a.ip_addresses?.join(', ') || '—'}</div>
    </div>,
    a.environment,
    a.os_type,
    a.owner_team ?? '—',
    <Badge label={CRIT_LABELS[a.criticality]} color={CRIT_COLORS[a.criticality]} />,
    canEdit ? (
      <select value={a.criticality}
        onChange={e => updateCrit.mutate({ id: a.id, c: +e.target.value })}
        style={{ background: 'var(--bg3)', border: '1px solid var(--border)',
          color: 'var(--text)', borderRadius: 4, padding: '2px 6px', fontSize: 12 }}>
        {[1,2,3,4].map(n => <option key={n} value={n}>{n} – {CRIT_LABELS[n]}</option>)}
      </select>
    ) : <span style={{ color: 'var(--muted)', fontSize: 12 }}>View only</span>,
    canEdit ? (
      <button onClick={() => setConfirm(a.id)}
        style={{ fontSize: 11, padding: '3px 10px', borderRadius: 4,
          background: 'var(--red)22', color: 'var(--red)',
          border: '1px solid var(--red)44', cursor: 'pointer' }}>
        Delete
      </button>
    ) : <span>—</span>,
  ])

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700 }}>Asset Registry</h1>
        {canEdit && (
          <button onClick={() => setShow(!show)}
            style={{ padding: '7px 16px', background: 'var(--accent)', color: 'white',
              border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 600 }}>
            + Add Asset
          </button>
        )}
      </div>

      {/* Delete confirmation modal */}
      {confirm && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.6)', display: 'flex',
          alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)',
            borderRadius: 10, padding: 28, width: 360, textAlign: 'center' }}>
            <div style={{ fontSize: 32, marginBottom: 12 }}>⚠️</div>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 8 }}>Delete Asset?</div>
            <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 20 }}>
              This will permanently remove the asset and its criticality tier.
              Existing alerts referencing this host will not be deleted.
            </div>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
              <button onClick={() => deleteAsset.mutate(confirm)}
                disabled={deleteAsset.isPending}
                style={{ padding: '8px 20px', background: 'var(--red)',
                  color: 'white', border: 'none', borderRadius: 6,
                  fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
                {deleteAsset.isPending ? 'Deleting...' : 'Delete'}
              </button>
              <button onClick={() => setConfirm(null)}
                style={{ padding: '8px 20px', background: 'var(--bg3)',
                  color: 'var(--muted)', border: '1px solid var(--border)',
                  borderRadius: 6, fontSize: 13, cursor: 'pointer' }}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add asset form */}
      {show && canEdit && (
        <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)',
          borderRadius: 8, padding: 20, marginBottom: 16 }}>
          <h3 style={{ marginBottom: 12, fontSize: 14 }}>Register Asset</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            {[['Hostname','hostname'],['Owner Team','owner_team'],['OS Type','os_type']].map(([label,key]) => (
              <div key={key}>
                <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>{label}</label>
                <input value={(form as any)[key]} onChange={e => setForm({ ...form, [key]: e.target.value })}
                  style={{ width: '100%', background: 'var(--bg3)', border: '1px solid var(--border)',
                    borderRadius: 4, padding: '6px 10px', color: 'var(--text)', fontSize: 13 }} />
              </div>
            ))}
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>Criticality</label>
              <select value={form.criticality} onChange={e => setForm({ ...form, criticality: +e.target.value })}
                style={{ width: '100%', background: 'var(--bg3)', border: '1px solid var(--border)',
                  color: 'var(--text)', borderRadius: 4, padding: '6px 10px', fontSize: 13 }}>
                {[1,2,3,4].map(n => <option key={n} value={n}>{n} – {CRIT_LABELS[n]}</option>)}
              </select>
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>Environment</label>
              <select value={form.environment} onChange={e => setForm({ ...form, environment: e.target.value })}
                style={{ width: '100%', background: 'var(--bg3)', border: '1px solid var(--border)',
                  color: 'var(--text)', borderRadius: 4, padding: '6px 10px', fontSize: 13 }}>
                {['production','staging','development','dmz','ot','cloud','unknown'].map(e =>
                  <option key={e} value={e}>{e}</option>)}
              </select>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button onClick={() => create.mutate(form)}
              style={{ padding: '7px 16px', background: 'var(--accent)', color: 'white',
                border: 'none', borderRadius: 6, fontSize: 13 }}>
              Register
            </button>
            <button onClick={() => setShow(false)}
              style={{ padding: '7px 16px', background: 'var(--bg3)', color: 'var(--muted)',
                border: '1px solid var(--border)', borderRadius: 6, fontSize: 13 }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8 }}>
        <Table
          headers={['Host', 'Environment', 'OS', 'Owner', 'Criticality', 'Update', 'Delete']}
          rows={rows} empty="No assets registered" />
      </div>
    </div>
  )
}
