import { useState, useEffect } from 'react'
import { Sidebar }   from './components/Sidebar'
import { Login }     from './pages/Login'
import { Dashboard } from './pages/Dashboard'
import { Alerts }    from './pages/Alerts'
import { Rules }     from './pages/Rules'
import { Assets }    from './pages/Assets'
import { Chains }    from './pages/Chains'
import { Coverage }  from './pages/Coverage'
import { Purple }    from './pages/Purple'
import { Scans }     from './pages/Scans'
import { Users }     from './pages/Users'
import { AuditLog }   from './pages/AuditLog'
import { EventSearch } from './pages/EventSearch'
import { Reports }        from './pages/Reports'
import { HealthDashboard }  from './pages/HealthDashboard'
import { ThreatIntel }      from './pages/ThreatIntel'
import { isAuthenticated } from './lib/auth'

const PAGES: Record<string, React.ReactNode> = {
  dashboard: <Dashboard />,
  alerts:    <Alerts />,
  rules:     <Rules />,
  assets:    <Assets />,
  chains:    <Chains />,
  coverage:  <Coverage />,
  purple:    <Purple />,
  scans:     <Scans />,
  users:     <Users />,
  audit:     <AuditLog />,
  events:    <EventSearch />,
  reports:   <Reports />,
  health:    <HealthDashboard />,
  ti:        <ThreatIntel />,
}

export default function App() {
  const [authed,  setAuthed]  = useState(false)
  const [page,    setPage]    = useState('dashboard')
  const [loading, setLoading] = useState(true)

  // On mount — try to refresh token silently
  // (tokens are in-memory so this only works within the same tab session)
  useEffect(() => {
    const init = async () => {
      if (isAuthenticated()) {
        setAuthed(true)
      }
      setLoading(false)
    }
    init()
  }, [])

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh', background: 'var(--bg)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        <div style={{ color: 'var(--accent)', fontSize: 18, fontWeight: 700 }}>
          ⬡ ThreatOS
        </div>
      </div>
    )
  }

  if (!authed) {
    return <Login onLogin={() => setAuthed(true)} />
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <Sidebar
        active={page}
        onNav={setPage}
        onLogout={() => { setAuthed(false); setPage('dashboard') }}
      />
      <main style={{
        flex: 1, padding: 24, overflowY: 'auto',
        maxHeight: '100vh', background: 'var(--bg)',
      }}>
        {PAGES[page] ?? <Dashboard />}
      </main>
    </div>
  )
}
