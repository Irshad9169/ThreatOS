import { getCurrentUser, hasRole, logout } from '../lib/auth'

interface Props { active: string; onNav: (page: string) => void; onLogout: () => void }

const NAV = [
  { id: 'dashboard',  icon: '⬡', label: 'Dashboard',   roles: [] },
  { id: 'alerts',     icon: '🔔', label: 'Alerts',      roles: [] },
  { id: 'rules',      icon: '📋', label: 'Rules',       roles: [] },
  { id: 'assets',     icon: '🖥',  label: 'Assets',      roles: [] },
  { id: 'chains',     icon: '🔗', label: 'Chains',      roles: [] },
  { id: 'coverage',   icon: '🛡',  label: 'Coverage',    roles: [] },
  { id: 'purple',     icon: '🟣', label: 'Purple Team', roles: [] },
  { id: 'scans',      icon: '📡', label: 'Scans',       roles: [] },
  { id: 'users',      icon: '👥', label: 'Users',       roles: ['admin'] },
  { id: 'audit',      icon: '📜', label: 'Audit Log',   roles: ['engineer','admin'] },
  { id: 'events',     icon: '🔎', label: 'Event Search', roles: ['analyst','engineer','admin'] },
  { id: 'reports',    icon: '📊', label: 'Reports',      roles: ['analyst','engineer','admin'] },
  { id: 'health',     icon: '💚', label: 'System Health', roles: ['engineer','admin'] },
  { id: 'ti',         icon: '🔬', label: 'Threat Intel',  roles: [] },
]

const ROLE_COLORS: Record<string, string> = {
  admin: '#ef4444', engineer: '#f97316', analyst: '#89b4fa', ingest: '#6c7086',
}

export function Sidebar({ active, onNav, onLogout }: Props) {
  const me = getCurrentUser()

  const handleLogout = async () => {
    await logout()
    onLogout()
  }

  return (
    <aside style={{
      width: 200, minHeight: '100vh', background: 'var(--bg2)',
      borderRight: '1px solid var(--border)', display: 'flex',
      flexDirection: 'column', padding: '20px 0', flexShrink: 0,
    }}>
      {/* Logo */}
      <div style={{ padding: '0 20px 20px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--accent)' }}>⬡ ThreatOS</div>
        <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 2 }}>Security Operations</div>
      </div>

      {/* Nav items */}
      <nav style={{ marginTop: 12, flex: 1 }}>
        {NAV.map(item => {
          // Hide role-restricted items
          if (item.roles.length > 0 && !hasRole(...item.roles)) return null
          const isActive = active === item.id
          return (
            <button key={item.id} onClick={() => onNav(item.id)}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                padding: '10px 20px',
                background: isActive ? 'var(--bg3)' : 'transparent',
                border: 'none',
                borderLeft: isActive ? '2px solid var(--accent)' : '2px solid transparent',
                color: isActive ? 'var(--text)' : 'var(--muted)',
                fontSize: 13, fontWeight: isActive ? 600 : 400,
                cursor: 'pointer', transition: 'all 0.15s', textAlign: 'left',
              }}>
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </button>
          )
        })}
      </nav>

      {/* Current user + logout */}
      <div style={{ borderTop: '1px solid var(--border)', padding: '12px 16px' }}>
        {me && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                width: 28, height: 28, borderRadius: '50%',
                background: ROLE_COLORS[me.role] + '33',
                border: `1px solid ${ROLE_COLORS[me.role]}66`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 12, fontWeight: 700, color: ROLE_COLORS[me.role],
              }}>
                {me.username.charAt(0).toUpperCase()}
              </div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>
                  {me.username}
                </div>
                <div style={{ fontSize: 10, color: ROLE_COLORS[me.role] }}>
                  {me.role}
                </div>
              </div>
            </div>
          </div>
        )}
        <button onClick={handleLogout}
          style={{
            width: '100%', padding: '6px 10px',
            background: 'var(--red)11', color: 'var(--red)',
            border: '1px solid var(--red)33', borderRadius: 6,
            fontSize: 12, fontWeight: 600, cursor: 'pointer',
          }}>
          Sign Out
        </button>
        <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 8, textAlign: 'center' }}>
          v0.1.0 · OL8
        </div>
      </div>
    </aside>
  )
}
