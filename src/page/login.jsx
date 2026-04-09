import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [msg, setMsg] = useState({ text: '', ok: true })
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  async function handleAuth() {
    if (!username.trim() || !password.trim())
      return setMsg({ text: 'กรุณากรอกข้อมูล', ok: false })

    setLoading(true)
    setMsg({ text: '', ok: true })
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password: password.trim() })
      })
      const data = await res.json()
      if (res.ok) {
        localStorage.setItem('token', data.token)
        localStorage.setItem('username', data.username)
        navigate('/dashboard')
      } else {
        setMsg({ text: '❌ ' + data.message, ok: false })
      }
    } catch {
      setMsg({ text: '❌ ไม่สามารถเชื่อมต่อ server', ok: false })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 flex items-center justify-center">
      <div className="bg-slate-800 p-10 rounded-2xl w-96 shadow-2xl">
        <h2 className="text-sky-400 text-2xl font-bold text-center mb-1">
          🛡️ Packet Monitor
        </h2>
        <p className="text-slate-500 text-xs text-center mb-6">
          Real-time Encrypted Packet Visualization
        </p>
        <input
          className="w-full px-4 py-2.5 bg-slate-900 border border-slate-700 rounded-lg text-white text-sm mb-3 outline-none focus:border-sky-400"
          placeholder="Username"
          value={username}
          onChange={e => setUsername(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAuth()}
        />
        <input
          type="password"
          className="w-full px-4 py-2.5 bg-slate-900 border border-slate-700 rounded-lg text-white text-sm mb-4 outline-none focus:border-sky-400"
          placeholder="Password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAuth()}
        />
        <button
          onClick={handleAuth}
          disabled={loading}
          className="w-full py-2.5 bg-sky-400 text-slate-900 font-bold rounded-lg text-sm hover:bg-sky-300 disabled:opacity-60 cursor-pointer transition-colors"
        >
          {loading ? 'Loading...' : 'Sign In'}
        </button>
        {msg.text && (
          <p className={`text-center text-xs mt-3 ${msg.ok ? 'text-green-400' : 'text-red-400'}`}>
            {msg.text}
          </p>
        )}
        <p className="text-center text-xs text-slate-500 mt-4">
          ยังไม่มีบัญชี?{' '}
          <Link to="/register" className="text-sky-400 hover:underline">
            Register
          </Link>
        </p>
      </div>
    </div>
  )
}
