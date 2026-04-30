import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rulesApi } from '../lib/api'
import { Table } from '../components/Table'
import { Badge } from '../components/Badge'

export function Rules() {
  const qc    = useQueryClient()
  const rules = useQuery({ queryKey: ['rules'], queryFn: rulesApi.list })
  const toggle = useMutation({
    mutationFn: (id: string) => rulesApi.toggle(id),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
  const [show, setShow] = useState(false)
  const [form, setForm] = useState({
    name: '', technique_id: '', tactic: 'execution',
    severity: 5, confidence: 0.8,
    detection_ast: '{"type":"field_match","field":"process","operator":"contains","value":""}',
  })
  const create = useMutation({
    mutationFn: (data: object) => rulesApi.create(data),
    onSuccess:  () => { qc.invalidateQueries({ queryKey: ['rules'] }); setShow(false) },
  })

  const rows = (rules.data ?? []).map(r => [
    r.name,
    <Badge label={r.technique_id} color="var(--accent)" />,
    r.tactic,
    r.severity,
    `${(r.confidence * 100).toFixed(0)}%`,
    r.trigger_count,
    <Badge label={r.enabled ? 'ON' : 'OFF'} color={r.enabled ? 'var(--green)' : 'var(--muted)'} />,
    <button onClick={() => toggle.mutate(r.id)}
      style={{ fontSize: 11, padding: '2px 8px',
        background: r.enabled ? 'var(--red)22' : 'var(--green)22',
        color: r.enabled ? 'var(--red)' : 'var(--green)',
        border: `1px solid ${r.enabled ? 'var(--red)' : 'var(--green)'}44`, borderRadius: 4 }}>
      {r.enabled ? 'Disable' : 'Enable'}
    </button>,
  ])

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700 }}>Detection Rules</h1>
        <button onClick={() => setShow(!show)}
          style={{ padding: '7px 16px', background: 'var(--accent)', color: 'white',
            border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 600 }}>
          + New Rule
        </button>
      </div>

      {show && (
        <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 20, marginBottom: 16 }}>
          <h3 style={{ marginBottom: 12, fontSize: 14 }}>Create Rule</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            {[['Name', 'name'], ['Technique ID', 'technique_id'], ['Tactic', 'tactic']].map(([label, key]) => (
              <div key={key}>
                <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>{label}</label>
                <input value={(form as any)[key]} onChange={e => setForm({ ...form, [key]: e.target.value })}
                  style={{ width: '100%', background: 'var(--bg3)', border: '1px solid var(--border)',
                    borderRadius: 4, padding: '6px 10px', color: 'var(--text)', fontSize: 13 }} />
              </div>
            ))}
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>Severity (1-10)</label>
              <input type="number" min={1} max={10} value={form.severity}
                onChange={e => setForm({ ...form, severity: +e.target.value })}
                style={{ width: '100%', background: 'var(--bg3)', border: '1px solid var(--border)',
                  borderRadius: 4, padding: '6px 10px', color: 'var(--text)', fontSize: 13 }} />
            </div>
          </div>
          <div style={{ marginTop: 12 }}>
            <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>Detection AST (JSON)</label>
            <textarea value={form.detection_ast}
              onChange={e => setForm({ ...form, detection_ast: e.target.value })}
              rows={3} style={{ width: '100%', background: 'var(--bg3)', border: '1px solid var(--border)',
                borderRadius: 4, padding: '6px 10px', color: 'var(--text)', fontSize: 12,
                fontFamily: 'monospace', resize: 'vertical' }} />
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button onClick={() => {
              try {
                create.mutate({ ...form, detection_ast: JSON.parse(form.detection_ast) })
              } catch { alert('Invalid JSON in detection AST') }
            }} style={{ padding: '7px 16px', background: 'var(--accent)', color: 'white',
              border: 'none', borderRadius: 6, fontSize: 13 }}>
              Create
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
          headers={['Name', 'Technique', 'Tactic', 'Sev', 'Conf', 'Triggers', 'Status', 'Action']}
          rows={rows} empty="No rules yet" />
      </div>
    </div>
  )
}
