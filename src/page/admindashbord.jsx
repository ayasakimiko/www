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
  const [adminPackets, setAdminPackets] = useState([])

  const loadAdminPackets = useCallback(async () => {
    const res = await fetch('/api/admin/packets', {
      headers: { Authorization: 'Bearer ' + token }
    })
    if (res.ok) setAdminPackets(await res.json())
  }, [token])

  useEffect(() => {
    loadAdminPackets()
  }, [loadAdminPackets])

  return (
    <div>

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
