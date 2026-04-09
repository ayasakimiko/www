import { useState, useEffect, useCallback } from 'react'

const PROTO_BADGE = {
  tcp:   'bg-blue-900/60 text-blue-400',
  udp:   'bg-purple-900/60 text-purple-300',
  http:  'bg-yellow-900/60 text-yellow-400',
  https: 'bg-emerald-900/60 text-emerald-400',
  dns:   'bg-pink-900/60 text-pink-300',
  ssh:   'bg-teal-900/60 text-teal-300',
}

export default function AdminDashboard({ token }) {
  const [users, setUsers]               = useState([])
  const [adminPackets, setAdminPackets] = useState([])

  const loadUsers = useCallback(async () => {
    const res = await fetch('/api/admin/users', {
      headers: { Authorization: 'Bearer ' + token },
      cache: 'no-store'
    })
    if (res.ok) setUsers(await res.json())
  }, [token])

  const loadAdminPackets = useCallback(async () => {
    const res = await fetch('/api/admin/packets', {
      headers: { Authorization: 'Bearer ' + token }
    })
    if (res.ok) setAdminPackets(await res.json())
  }, [token])

  useEffect(() => {
    loadUsers()
    loadAdminPackets()
  }, [loadUsers, loadAdminPackets])

  async function changeRole(id, newRole) {
    const res = await fetch(`/api/admin/users/${id}/role`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
      body: JSON.stringify({ role: newRole })
    })
    if (res.ok) {
      setUsers(prev => prev.map(u => u.id === id ? { ...u, role: newRole } : u))
    } else {
      const err = await res.json().catch(() => ({}))
      alert('❌ เปลี่ยน role ไม่ได้: ' + (err.message || res.status))
    }
  }

  async function deleteUser(id) {
    if (!confirm('ยืนยันการลบ user นี้?')) return
    await fetch(`/api/admin/users/${id}`, {
      method: 'DELETE',
      headers: { Authorization: 'Bearer ' + token }
    })
    loadUsers()
  }

  return (
    <div>
      {/* ── User Management ── */}
      <div className="bg-slate-800 rounded-xl p-5 mb-5">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-slate-400 text-sm">👥 User Management</h3>
          <button
            onClick={loadUsers}
            className="px-3 py-1 bg-sky-700 text-white rounded-lg text-xs hover:bg-sky-600 cursor-pointer transition-colors"
          >
            🔄 Refresh
          </button>
        </div>
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
              {users.map(u => (
                <tr key={u.id} className="border-t border-slate-700/40 hover:bg-slate-700/20 transition-colors">
                  <td className="py-2.5 pr-4 text-slate-400">{u.id}</td>
                  <td className="py-2.5 pr-4 font-medium">{u.username}</td>
                  <td className="py-2.5 pr-4">
                    <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                      u.role === 'admin' ? 'bg-violet-800/70 text-violet-300' : 'bg-sky-900/60 text-sky-400'
                    }`}>
                      {u.role.toUpperCase()}
                    </span>
                  </td>
                  <td className="py-2.5">
                    <button
                      onClick={() => changeRole(u.id, u.role === 'admin' ? 'user' : 'admin')}
                      className="px-2.5 py-1 bg-yellow-500 text-slate-900 rounded text-xs font-bold mr-2 cursor-pointer hover:bg-yellow-400 transition-colors"
                    >
                      {u.role === 'admin' ? '⬇️ Set User' : '⬆️ Set Admin'}
                    </button>
                    <button
                      onClick={() => deleteUser(u.id)}
                      className="px-2.5 py-1 bg-red-500 text-white rounded text-xs font-bold cursor-pointer hover:bg-red-400 transition-colors"
                    >
                      🗑️ Delete
                    </button>
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-4 text-slate-500 text-sm text-center">ไม่มี user</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Admin Packet History ── */}
      <div className="bg-slate-800 rounded-xl p-5">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-slate-400 text-sm">📋 Packet History (100 รายการล่าสุด)</h3>
          <button
            onClick={loadAdminPackets}
            className="px-3 py-1 bg-sky-700 text-white rounded-lg text-xs hover:bg-sky-600 cursor-pointer transition-colors"
          >
            🔄 Refresh
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr>
                {['Time', 'Source IP', 'Protocol', 'Port', 'Size', 'Encryption'].map(h => (
                  <th key={h} className="text-left text-slate-500 text-xs pb-3 pr-4">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {adminPackets.map((p, i) => {
                const proto    = (p.protocol || '').toLowerCase()
                const badgeCls = PROTO_BADGE[proto] || 'bg-slate-700 text-slate-300'
                return (
                  <tr key={i} className="border-t border-slate-700/40 hover:bg-slate-700/20 transition-colors">
                    <td className="py-2 pr-4 text-slate-400 text-xs">
                      {new Date(p.timestamp).toLocaleString('th-TH')}
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs">{p.source_ip}</td>
                    <td className="py-2 pr-4">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${badgeCls}`}>{p.protocol}</span>
                    </td>
                    <td className="py-2 pr-4">{p.port}</td>
                    <td className="py-2 pr-4">{p.size} B</td>
                    <td className="py-2">
                      {p.is_encrypted
                        ? <span className="px-2 py-0.5 bg-emerald-900/60 text-emerald-400 rounded-full text-xs font-bold">🔐 {p.encryption_type}</span>
                        : <span className="px-2 py-0.5 bg-red-900/60 text-red-400 rounded-full text-xs font-bold">🔓 Plain</span>
                      }
                    </td>
                  </tr>
                )
              })}
              {adminPackets.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-4 text-slate-500 text-sm text-center">ยังไม่มีข้อมูล</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
