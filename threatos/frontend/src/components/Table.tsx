interface Props {
  headers: string[]
  rows: (string | number | React.ReactNode)[][]
  empty?: string
}
import React from 'react'
export function Table({ headers, rows, empty = 'No data' }: Props) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            {headers.map(h => (
              <th key={h} style={{
                textAlign: 'left', padding: '8px 12px',
                borderBottom: '1px solid var(--border)',
                color: 'var(--muted)', fontSize: 11,
                fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1,
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0
            ? <tr><td colSpan={headers.length} style={{ padding: 24, textAlign: 'center', color: 'var(--muted)' }}>{empty}</td></tr>
            : rows.map((row, i) => (
              <tr key={i} style={{ borderBottom: '1px solid var(--border)22' }}
                onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg3)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                {row.map((cell, j) => (
                  <td key={j} style={{ padding: '10px 12px', fontSize: 13 }}>{cell}</td>
                ))}
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  )
}
