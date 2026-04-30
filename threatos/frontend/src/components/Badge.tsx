interface Props { label: string; color?: string }
export function Badge({ label, color = 'var(--accent)' }: Props) {
  return (
    <span style={{
      background: color + '22', color, border: `1px solid ${color}44`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
    }}>{label}</span>
  )
}
