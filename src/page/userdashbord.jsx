import { useState, useEffect, useReducer, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { io } from 'socket.io-client'
import {
  PieChart, Pie, Cell, Legend, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer
} from 'recharts'
import AdminDashboard from './admindashbord'
import Navbar from './navbar'

const MAX_PACKETS = 20

const PROTO_COLORS = {
  TCP: '#60a5fa', UDP: '#a78bfa', HTTP: '#fbbf24',
  HTTPS: '#34d399', DNS: '#f0abfc', SSH: '#6ee7b7'
}

const PROTO_BADGE = {
  tcp:   'bg-blue-900/60 text-blue-400',
  udp:   'bg-purple-900/60 text-purple-300',
  http:  'bg-yellow-900/60 text-yellow-400',
  https: 'bg-emerald-900/60 text-emerald-400',
  dns:   'bg-pink-900/60 text-pink-300',
  ssh:   'bg-teal-900/60 text-teal-300',
}

const initLive = {
  packets: [],
  stats: { enc: 0, plain: 0, total: 0 },
  protoCnt: { TCP: 0, UDP: 0, HTTP: 0, HTTPS: 0, DNS: 0, SSH: 0 },
}

function liveReducer(state, p) {
  return {
    packets: [p, ...state.packets].slice(0, MAX_PACKETS),
    stats: {
      total: state.stats.total + 1,
      enc:   p.is_encrypted ? state.stats.enc + 1 : state.stats.enc,
      plain: !p.is_encrypted ? state.stats.plain + 1 : state.stats.plain,
    },
    protoCnt: { ...state.protoCnt, [p.protocol]: (state.protoCnt[p.protocol] || 0) + 1 },
  }
}

export default function UserDashboard() {
  const navigate  = useNavigate()
  const username   = localStorage.getItem('username') || ''
  const token      = localStorage.getItem('token')

  const [tab, setTab]           = useState('live')
  const [live, dispatchLive]    = useReducer(liveReducer, initLive)
  const [pps, setPps]           = useState(0)
  const [history, setHistory]   = useState([])
  const [realRole, setRealRole] = useState('')
  const [scanning, setScanning] = useState(false)
  const [delay, setDelay]       = useState(0)
  const [filterIp, setFilterIp] = useState('')
  const [filterProtos, setFilterProtos] = useState([])
  const [showModal, setShowModal] = useState(false)
  const socketRef               = useRef(null)
  const delayRef                = useRef(0)

  useEffect(() => {
    fetch('/api/me', { headers: { Authorization: 'Bearer ' + token } })
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data?.user?.role) setRealRole(data.user.role) })
  }, [])

  useEffect(() => {
    const socket = io()
    socketRef.current = socket
    socket.on('scan-status', (active) => setScanning(active))
    socket.on('packet-stream', (p) => {
      const d = delayRef.current
      if (d > 0) setTimeout(() => dispatchLive(p), d)
      else dispatchLive(p)
    })
    socket.on('packets-per-sec', (count) => setPps(count))
    return () => { socket.disconnect(); socketRef.current = null }
  }, [])

  function handleDelayChange(val) {
    setDelay(val)
    delayRef.current = val
  }

  async function loadHistory() {
    const res = await fetch('/api/packets', {
      headers: { Authorization: 'Bearer ' + token }
    })
    if (res.ok) setHistory(await res.json())
  }

  function logout() {
    localStorage.clear()
    navigate('/')
  }

  function toggleScan() {
    if (!socketRef.current) return
    if (scanning) {
      socketRef.current.emit('stop-scan')
    } else {
      setShowModal(true)
    }
  }

  function confirmStartScan() {
    if (!socketRef.current) return
    socketRef.current.emit('start-scan', {
      protocols: filterProtos,
      ip: filterIp.trim(),
    })
    setShowModal(false)
  }

  function toggleProto(proto) {
    setFilterProtos(prev =>
      prev.includes(proto) ? prev.filter(p => p !== proto) : [...prev, proto]
    )
  }

  const { packets, stats, protoCnt } = live

  const pieData = [
    { name: 'Encrypted', value: stats.enc },
    { name: 'Plain Text', value: stats.plain }
  ]
  const barData = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH'].map(k => ({
    name: k, value: protoCnt[k] || 0
  }))

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200 p-4">

      <Navbar username={username} realRole={realRole} onLogout={logout} />

      {/* ── Tabs + Scan button ── */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
        <div className="flex flex-wrap gap-2">
          <TabBtn active={tab === 'live'} onClick={() => setTab('live')}>📡 Live Monitor</TabBtn>
          <TabBtn active={tab === 'history'} onClick={() => { setTab('history'); loadHistory() }}>
            🗂️ Packet History
          </TabBtn>
          {realRole === 'admin' && (
            <TabBtn active={tab === 'admin'} onClick={() => setTab('admin')}>👑 Admin Panel</TabBtn>
          )}
        </div>

        {tab === 'live' && (
          <div className="flex items-center gap-3">
            {scanning && (
              <div className="flex items-center gap-2 text-xs text-slate-400 bg-slate-800 px-3 py-1.5 rounded-lg">
                {filterProtos.length > 0 && <span className="text-sky-400">{filterProtos.join(', ')}</span>}
                {filterIp && <span className="text-emerald-400 font-mono">{filterIp}</span>}
                {delay > 0 && <span className="text-yellow-400">⏱ {delay}ms</span>}
                {filterProtos.length === 0 && !filterIp && delay === 0 && <span>ทุก protocol</span>}
              </div>
            )}
            <button
              onClick={toggleScan}
              className={`flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-bold cursor-pointer transition-colors ${
                scanning
                  ? 'bg-red-500 hover:bg-red-400 text-white'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white'
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${scanning ? 'bg-white animate-pulse' : 'bg-white/60'}`} />
              {scanning ? '⏹ Stop Scan' : '▶️ Start Scan'}
            </button>
          </div>
        )}
      </div>

      {/* ══ PAGE: LIVE ══ */}
      {tab === 'live' && (
        <div>
          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-5">
            <StatCard label="Total Packets"  value={stats.total} />
            <StatCard label="Encrypted"      value={stats.enc} color="text-sky-400" />
            <StatCard label="Plain Text"     value={stats.plain} color="text-red-400" />
            <StatCard label="Packets / sec"  value={pps} color="text-green-400" />
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-5">
            <div className="bg-slate-800 rounded-xl p-5">
              <h3 className="text-slate-400 text-sm mb-4">🔐 Encryption Ratio</h3>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={pieData} innerRadius={50} outerRadius={80} dataKey="value" isAnimationActive={false}>
                    <Cell fill="#38bdf8" />
                    <Cell fill="#ef4444" />
                  </Pie>
                  <Legend wrapperStyle={{ color: '#e2e8f0', fontSize: 12 }} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: 'none', color: '#e2e8f0', borderRadius: 8 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-slate-800 rounded-xl p-5 md:col-span-2">
              <h3 className="text-slate-400 text-sm mb-4">📊 Protocol Distribution</h3>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={barData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: 'none', color: '#e2e8f0', borderRadius: 8 }} />
                  <Bar dataKey="value" isAnimationActive={false}>
                    {barData.map(entry => (
                      <Cell key={entry.name} fill={PROTO_COLORS[entry.name]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Live Packet Table */}
          <div className="bg-slate-800 rounded-xl p-5">
            <h3 className="text-slate-400 text-sm mb-4">📋 Live Packets (20 รายการล่าสุด)</h3>
            <PacketTable packets={packets} />
          </div>
        </div>
      )}

      {/* ══ PAGE: HISTORY ══ */}
      {tab === 'history' && (
        <div className="bg-slate-800 rounded-xl p-5">
          <h3 className="text-slate-400 text-sm mb-4">🗂️ Packet History (50 รายการล่าสุด)</h3>
          <PacketTable packets={history} showDate />
        </div>
      )}

      {/* ══ PAGE: ADMIN ══ */}
      {tab === 'admin' && realRole === 'admin' && <AdminDashboard token={token} />}

      {/* ══ MODAL: Scan Filter ══ */}
      {showModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
          onClick={() => setShowModal(false)}
        >
          <div
            className="bg-slate-800 rounded-2xl p-6 w-full max-w-md shadow-2xl"
            onClick={e => e.stopPropagation()}
          >
            <h2 className="text-white font-bold text-lg mb-5">▶️ Capture Settings</h2>

            {/* Protocol */}
            <div className="mb-5">
              <p className="text-slate-400 text-xs mb-2">Protocol <span className="text-slate-500">(ไม่เลือก = ทุกตัว)</span></p>
              <div className="flex flex-wrap gap-2">
                {['TCP','UDP','HTTP','HTTPS','DNS','SSH'].map(proto => (
                  <button
                    key={proto}
                    onClick={() => toggleProto(proto)}
                    className={`px-3 py-1.5 rounded-lg text-sm font-bold border transition-colors cursor-pointer ${
                      filterProtos.includes(proto)
                        ? 'bg-sky-500 border-sky-400 text-white'
                        : 'bg-slate-700 border-slate-600 text-slate-300 hover:border-sky-500'
                    }`}
                  >
                    {proto}
                  </button>
                ))}
              </div>
            </div>

            {/* IP Filter */}
            <div className="mb-5">
              <p className="text-slate-400 text-xs mb-2">IP Filter <span className="text-slate-500">(เว้นว่าง = ทุก IP)</span></p>
              <input
                type="text"
                placeholder="เช่น 192.168.1.1"
                value={filterIp}
                onChange={e => setFilterIp(e.target.value)}
                className="w-full bg-slate-700 text-slate-200 text-sm px-3 py-2 rounded-lg outline-none border border-slate-600 focus:border-sky-500"
              />
            </div>

            {/* Delay */}
            <div className="mb-6">
              <p className="text-slate-400 text-xs mb-2">⏱ Packet Delay <span className="text-sky-400 font-mono">{delay} ms</span></p>
              <input
                type="range"
                min={0}
                max={3000}
                step={100}
                value={delay}
                onChange={e => handleDelayChange(Number(e.target.value))}
                className="w-full accent-sky-400 cursor-pointer"
              />
              <div className="flex justify-between text-xs text-slate-500 mt-1">
                <span>0 ms</span><span>3000 ms</span>
              </div>
            </div>

            {/* Buttons */}
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setShowModal(false)}
                className="px-5 py-2 rounded-lg text-sm bg-slate-700 text-slate-300 hover:bg-slate-600 cursor-pointer transition-colors"
              >
                ยกเลิก
              </button>
              <button
                onClick={confirmStartScan}
                className="px-5 py-2 rounded-lg text-sm font-bold bg-emerald-600 hover:bg-emerald-500 text-white cursor-pointer transition-colors"
              >
                ▶️ เริ่ม Capture
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Sub-components ───────────────────────────────────────────

function TabBtn({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      className={`px-5 py-2 rounded-lg text-sm cursor-pointer border-none transition-colors ${
        active
          ? 'bg-sky-400 text-slate-900 font-bold'
          : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
      }`}
    >
      {children}
    </button>
  )
}

function StatCard({ label, value, color = 'text-sky-400' }) {
  return (
    <div className="bg-slate-800 rounded-xl p-5">
      <div className="text-xs text-slate-500 mb-1.5">{label}</div>
      <div className={`text-3xl font-bold ${color}`}>{value}</div>
    </div>
  )
}

function PacketTable({ packets, showDate = false }) {
  if (!packets.length)
    return <p className="text-slate-500 text-sm text-center py-4">ยังไม่มีข้อมูล...</p>

  return (
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
          {packets.map((p, i) => <PacketRow key={i} packet={p} showDate={showDate} />)}
        </tbody>
      </table>
    </div>
  )
}

function PacketRow({ packet: p, showDate }) {
  const time = p.timestamp
    ? showDate
      ? new Date(p.timestamp).toLocaleString('th-TH')
      : new Date(p.timestamp).toLocaleTimeString('th-TH')
    : new Date().toLocaleTimeString('th-TH')
  const proto    = (p.protocol || '').toLowerCase()
  const badgeCls = PROTO_BADGE[proto] || 'bg-slate-700 text-slate-300'

  return (
    <tr className="border-t border-slate-700/40 hover:bg-slate-700/20 transition-colors">
      <td className="py-2 pr-4 text-slate-400 text-xs">{time}</td>
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
}
