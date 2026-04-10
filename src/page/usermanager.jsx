import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import Navbar from './navbar'
import { Users, RefreshCw, ShieldCheck, UserCog, Trash2, ArrowUpCircle, ArrowDownCircle } from 'lucide-react'

const ROLE_RANK = { admin: 2, user: 1 }
function canActOn(myRole, targetRole, isMe) {
  if (isMe) return false
  return ROLE_RANK[myRole] > ROLE_RANK[targetRole]
}

export default function UserManager() {
  const navigate = useNavigate()
  const token    = localStorage.getItem('token')

  const [realRole, setRealRole] = useState('')
  const [username, setUsername] = useState('')
  const [users, setUsers]       = useState([])
  const [loading, setLoading]   = useState(true)
  const [msg, setMsg]           = useState('')

  // ตรวจสอบ role จาก DB
  useEffect(() => {
    fetch('/api/me', { headers: { Authorization: 'Bearer ' + token } })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!data?.user) return navigate('/')
        if (data.user.role !== 'admin') return navigate('/dashboard')
        setRealRole(data.user.role)
        setUsername(data.user.username)
      })
  }, [token, navigate])

  const loadUsers = useCallback(async () => {
    setLoading(true)
    const res = await fetch('/api/admin/users', {
      headers: { Authorization: 'Bearer ' + token },
      cache: 'no-store'
    })
    if (res.ok) setUsers(await res.json())
    setLoading(false)
  }, [token])

  useEffect(() => {
    if (realRole === 'admin') loadUsers()
  }, [realRole, loadUsers])

  async function changeRole(id, newRole) {
    const res = await fetch(`/api/admin/users/${id}/role`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
      body: JSON.stringify({ role: newRole })
    })
    if (res.ok) {
      setUsers(prev => prev.map(u => u.id === id ? { ...u, role: newRole } : u))
      showMsg('✅ เปลี่ยน role สำเร็จ')
    } else {
      const err = await res.json().catch(() => ({}))
      showMsg('❌ ' + (err.message || 'เปลี่ยน role ไม่ได้'))
    }
  }

  async function deleteUser(id) {
    if (!confirm('ยืนยันการลบ user นี้?')) return
    const res = await fetch(`/api/admin/users/${id}`, {
      method: 'DELETE',
      headers: { Authorization: 'Bearer ' + token }
    })
    if (res.ok) {
      setUsers(prev => prev.filter(u => u.id !== id))
      showMsg('✅ ลบ user สำเร็จ')
    }
  }

  function showMsg(text) {
    setMsg(text)
    setTimeout(() => setMsg(''), 3000)
  }

  if (!realRole) return null // รอ auth check

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200 p-5">
      <Navbar username={username} realRole={realRole} />

      <div className="bg-slate-800 rounded-xl p-5">
        <div className="flex justify-between items-center mb-5">
          <h3 className="text-white font-bold text-base flex items-center gap-2"><Users size={16} /> User Management</h3>
          <div className="flex items-center gap-3">
            {msg && (
              <span className={`text-xs ${msg.startsWith('✅') ? 'text-green-400' : 'text-red-400'}`}>
                {msg}
              </span>
            )}
            <button
              onClick={loadUsers}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-sky-700 text-white rounded-lg text-xs hover:bg-sky-600 cursor-pointer transition-colors"
            >
              <RefreshCw size={12} /> Refresh
            </button>
          </div>
        </div>

        {loading ? (
          <p className="text-slate-500 text-sm text-center py-8">Loading...</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr>
                  {['ID', 'Username', 'Role', 'Actions'].map(h => (
                    <th key={h} className="text-left text-slate-500 text-xs pb-3 pr-4">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.map(u => {
                    const isMe = u.username === username
                    const allowed = canActOn(realRole, u.role, isMe)
                    return (
                  <tr key={u.id} className="border-t border-slate-700/40 hover:bg-slate-700/20 transition-colors">
                    <td className="py-3 pr-4 text-slate-500 text-xs">{u.id}</td>
                    <td className="py-3 pr-4 font-mono">
                      {u.username}
                      {isMe && <span className="ml-2 text-xs text-sky-400">(คุณ)</span>}
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                        u.role === 'admin'
                          ? 'bg-violet-900/60 text-violet-300'
                          : 'bg-sky-900/60 text-sky-300'
                      }`}>
                        {u.role}
                      </span>
                    </td>
                    <td className="py-3">
                      <div className="flex gap-2">
                        {allowed && (
                          <>
                            <button
                              onClick={() => changeRole(u.id, u.role === 'admin' ? 'user' : 'admin')}
                              className="inline-flex items-center gap-1.5 px-3 py-1 bg-amber-700/60 text-amber-300 rounded text-xs hover:bg-amber-700 cursor-pointer transition-colors"
                            >
                              {u.role === 'admin'
                                ? <><ArrowDownCircle size={12} /> Set User</>
                                : <><ArrowUpCircle size={12} /> Set Admin</>}
                            </button>
                            <button
                              onClick={() => deleteUser(u.id)}
                              className="inline-flex items-center gap-1.5 px-3 py-1 bg-red-900/60 text-red-400 rounded text-xs hover:bg-red-800 cursor-pointer transition-colors"
                            >
                              <Trash2 size={12} /> Delete
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                    )
                  })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
