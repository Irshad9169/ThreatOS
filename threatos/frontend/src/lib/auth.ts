import axios from 'axios'

export interface AuthUser {
  id:          string
  username:    string
  email:       string
  full_name:   string | null
  role:        string
  is_active:   boolean
  last_login:  string | null
  has_api_key: boolean
}

export interface AuthState {
  user:          AuthUser | null
  access_token:  string | null
  refresh_token: string | null
}

const SS_KEY = 'threatos_auth'

// ── Persist to sessionStorage (tab-scoped, cleared on tab close) ──────────────
function saveToSession(state: AuthState): void {
  try {
    sessionStorage.setItem(SS_KEY, JSON.stringify(state))
  } catch { /* ignore */ }
}

function loadFromSession(): AuthState {
  try {
    const raw = sessionStorage.getItem(SS_KEY)
    if (raw) return JSON.parse(raw)
  } catch { /* ignore */ }
  return { user: null, access_token: null, refresh_token: null }
}

function clearSession(): void {
  try { sessionStorage.removeItem(SS_KEY) } catch { /* ignore */ }
}

// ── In-memory state (initialised from sessionStorage on load) ─────────────────
let _auth: AuthState = loadFromSession()

// Re-attach token to axios immediately on module load
if (_auth.access_token) {
  axios.defaults.headers.common['Authorization'] = `Bearer ${_auth.access_token}`
}

export function getAuth():        AuthState      { return _auth }
export function getToken():       string | null  { return _auth.access_token }
export function getCurrentUser(): AuthUser | null { return _auth.user }
export function isAuthenticated():boolean { return !!_auth.access_token && !!_auth.user }
export function hasRole(...roles: string[]): boolean {
  return !!_auth.user && roles.includes(_auth.user.role)
}

export function setAuth(state: AuthState): void {
  _auth = state
  if (state.access_token) {
    axios.defaults.headers.common['Authorization'] = `Bearer ${state.access_token}`
  } else {
    delete axios.defaults.headers.common['Authorization']
  }
  saveToSession(state)
}

export function clearAuth(): void {
  _auth = { user: null, access_token: null, refresh_token: null }
  delete axios.defaults.headers.common['Authorization']
  clearSession()
}

export async function login(username: string, password: string): Promise<AuthUser> {
  const resp = await axios.post('/api/auth/login', { username, password })
  setAuth({
    user:          resp.data.user,
    access_token:  resp.data.access_token,
    refresh_token: resp.data.refresh_token,
  })
  return resp.data.user
}

export async function logout(): Promise<void> {
  // Tell the server (fire and forget)
  try {
    await axios.post('/api/auth/logout')
  } catch { /* ignore */ }
  clearAuth()
}

export async function refreshAccessToken(): Promise<boolean> {
  const refresh_token = _auth.refresh_token
  if (!refresh_token) return false
  try {
    const resp = await axios.post('/api/auth/refresh', { refresh_token })
    setAuth({
      user:          resp.data.user,
      access_token:  resp.data.access_token,
      refresh_token: resp.data.refresh_token,
    })
    return true
  } catch {
    clearAuth()
    return false
  }
}

// ── Axios interceptor — auto-refresh on 401 ───────────────────────────────────
axios.interceptors.response.use(
  r => r,
  async error => {
    const original = error.config
    if (error.response?.status === 401 && !original._retry &&
        !original.url?.includes('/auth/login') &&
        !original.url?.includes('/auth/refresh')) {
      original._retry = true
      const ok = await refreshAccessToken()
      if (ok) {
        original.headers['Authorization'] = `Bearer ${getToken()}`
        return axios(original)
      }
      clearAuth()
      window.location.href = '/'
    }
    return Promise.reject(error)
  }
)
