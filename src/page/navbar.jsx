import { useNavigate, NavLink } from 'react-router-dom'

export default function Navbar({ username, realRole, onLogout }) {
  const navigate = useNavigate()

  function logout() {
    localStorage.clear()
    if (onLogout) onLogout()
    else navigate('/')
  }

  return (
    <nav className="flex justify-between items-center bg-slate-800 px-5 py-3.5 rounded-xl mb-5">
      {/* Logo */}
      <div className="flex items-center gap-6">
        <h2 className="text-lg font-bold text-white">
          📡 <span className="text-sky-400">Packet Dashboard</span>
        </h2>

        {/* Nav Links */}
        <div className="flex gap-1">
          <NavLink
            to="/dashboard"
            className={({ isActive }) =>
              `px-4 py-1.5 rounded-lg text-sm transition-colors ${
                isActive
                  ? 'bg-sky-400 text-slate-900 font-bold'
                  : 'text-slate-400 hover:bg-slate-700 hover:text-white'
              }`
            }
          >
            📊 Dashboard
          </NavLink>

          {realRole === 'admin' && (
            <NavLink
              to="/users"
              className={({ isActive }) =>
                `px-4 py-1.5 rounded-lg text-sm transition-colors ${
                  isActive
                    ? 'bg-violet-500 text-white font-bold'
                    : 'text-slate-400 hover:bg-slate-700 hover:text-white'
                }`
              }
            >
              👥 User Manager
            </NavLink>
          )}
        </div>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-3">
        <span className="text-slate-400 text-sm">{username}</span>
        {realRole && (
          <span
            className={`px-3 py-1 rounded-full text-xs font-bold ${
              realRole === 'admin' ? 'bg-violet-700 text-white' : 'bg-sky-800 text-white'
            }`}
          >
            {realRole.toUpperCase()}
          </span>
        )}
        <button
          onClick={logout}
          className="px-4 py-1.5 bg-red-500 text-white rounded-lg text-sm cursor-pointer hover:bg-red-400 transition-colors"
        >
          Logout
        </button>
      </div>
    </nav>
  )
}
