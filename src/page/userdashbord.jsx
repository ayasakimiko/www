import { useState, useEffect, useReducer, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { io } from 'socket.io-client'
import {
  Radio, FolderOpen, ShieldCheck, Plug, Play, Square,
  AlertTriangle, Lock, Unlock, BarChart2, ClipboardList,
  Timer, Network, X, Info, Globe, Cpu, Key, Calendar,
  ArrowRightLeft, FileText, Search
} from 'lucide-react'
import {
  PieChart, Pie, Cell, Legend, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer
} from 'recharts'
import Navbar from './navbar'

const MAX_PACKETS = 20
const PPS_THRESHOLD = 500

// ─── Alert Colors ─────────────────────────────────────────────
const ALERT_COLOR = {
  critical: 'bg-red-900/70 text-red-300',
  warn:     'bg-orange-900/70 text-orange-300',
}

// ─── Rule 1+2+4: stateless per-packet ─────────────────────────
function detectStaticAlert(p) {
  // Rule 1: Unencrypted communication (High)
  if (p.port === 23)                          return { label: 'Telnet Detected',    level: 'critical' }
  if (p.port === 20 || p.port === 21)         return { label: 'FTP Detected',       level: 'critical' }
  if (p.protocol === 'HTTP' || p.port === 80) return { label: 'Unencrypted HTTP',   level: 'critical' }

  // Rule 2: Vulnerable protocol (High)
  if (p.tls_version === '0x0300' || p.encryption_type === 'SSL 3.0')
    return { label: 'SSL 3.0 Detected', level: 'critical' }
  if (p.tls_version === '0x0301')
    return { label: 'TLS 1.0 Detected', level: 'critical' }

  // Rule 4: Certificate expiry (Medium)
  if (p.cert_expiry) {
    const ms = Date.parse(p.cert_expiry)
    if (!isNaN(ms)) {
      const daysLeft = (ms - Date.now()) / 86400000
      if (daysLeft < 0)  return { label: 'Certificate Expired',    level: 'warn' }
      if (daysLeft < 30) return { label: 'Cert Expiring Soon',     level: 'warn' }
    }
  }
  return null
}

// ─── Rule 3: stateful attack detection ────────────────────────
function detectAttack(p, tracker) {
  const now = Date.now()
  const src = p.source_ip

  // Port Scan: >10 unique dst ports from same src in 10s
  if (!tracker.portScan[src]) tracker.portScan[src] = { ports: new Set(), ts: now }
  const ps = tracker.portScan[src]
  if (now - ps.ts > 10000) { ps.ports = new Set(); ps.ts = now }
  if (p.port) ps.ports.add(p.port)
  if (ps.ports.size > 10) return { label: 'Port Scan', level: 'warn' }

  // DoS: >200 packets from same src in 1s
  if (!tracker.dos[src]) tracker.dos[src] = { count: 0, ts: now }
  const ds = tracker.dos[src]
  if (now - ds.ts > 1000) { ds.count = 0; ds.ts = now }
  ds.count++
  if (ds.count > 200) return { label: 'DoS Attempt', level: 'warn' }

  // Brute Force: >15 hits to SSH(22)/RDP(3389) from same src in 30s
  if (p.port === 22 || p.port === 3389) {
    if (!tracker.brute[src]) tracker.brute[src] = { count: 0, ts: now }
    const bf = tracker.brute[src]
    if (now - bf.ts > 30000) { bf.count = 0; bf.ts = now }
    bf.count++
    if (bf.count > 15) return { label: 'Brute Force', level: 'warn' }
  }
  return null
}

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

function shortIfaceName(name) {
  const n = name.toLowerCase()
  if (n.includes('loopback') || n.includes('lo ')) return 'lo'
  if (n.includes('bluetooth'))     return 'bt0'
  if (n.includes('vethernet') || n.includes('veth')) {
    const wsl = n.includes('wsl') ? '-wsl' : ''
    return `veth${wsl}`
  }
  const wifiM = name.match(/wi[\s-]?fi\s*(\d*)/i)
  if (wifiM) return `wlan${wifiM[1] ? parseInt(wifiM[1]) - 1 : 0}`
  const lanM = name.match(/(local area|lan).*?(\d+)$/i)
  if (lanM) return `eth${lanM[2]}`
  if (n.includes('ethernet')) return 'eth0'
  return name.replace(/\s+/g, '').slice(0, 8).toLowerCase()
}

const initLive = {
  packets: [],
  stats: { enc: 0, plain: 0, total: 0, alerts: 0 },
  protoCnt: { TCP: 0, UDP: 0, HTTP: 0, HTTPS: 0, DNS: 0, SSH: 0 },
  alertCnt: {},
}

function liveReducer(state, p) {
  const alert = p.alert
  const alertCnt = { ...state.alertCnt }
  if (alert) alertCnt[alert.label] = (alertCnt[alert.label] || 0) + 1
  return {
    packets: [p, ...state.packets].slice(0, MAX_PACKETS),
    stats: {
      total: state.stats.total + 1,
      enc:   p.is_encrypted ? state.stats.enc + 1 : state.stats.enc,
      plain: !p.is_encrypted ? state.stats.plain + 1 : state.stats.plain,
      alerts: alert ? state.stats.alerts + 1 : state.stats.alerts,
    },
    protoCnt: { ...state.protoCnt, [p.protocol]: (state.protoCnt[p.protocol] || 0) + 1 },
    alertCnt,
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
  const [interfaces, setInterfaces] = useState([])
  const [selectedIface, setSelectedIface] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [highTraffic, setHighTraffic] = useState(false)
  const [selectedPacket, setSelectedPacket] = useState(null)
  const [liveSearch, setLiveSearch] = useState('')
  const [histSearch, setHistSearch] = useState('')
  const socketRef      = useRef(null)
  const delayRef       = useRef(0)
  const attackTracker  = useRef({ portScan: {}, dos: {}, brute: {} })

  useEffect(() => {
    fetch('/api/me', { headers: { Authorization: 'Bearer ' + token } })
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data?.user?.role) setRealRole(data.user.role) })
  }, [])

  useEffect(() => {
    const socket = io()
    socketRef.current = socket
    socket.on('connect', () => {
      socket.emit('get-interfaces', (ifaces) => {
        if (ifaces) setInterfaces(ifaces)
      })
    })
    socket.on('scan-status', (active) => setScanning(active))
    socket.on('packet-stream', (p) => {
      const alert = detectStaticAlert(p) || detectAttack(p, attackTracker.current)
      const pkt = { ...p, alert }
      const d = delayRef.current
      if (d > 0) setTimeout(() => dispatchLive(pkt), d)
      else dispatchLive(pkt)
    })
    socket.on('packets-per-sec', (count) => setPps(count))
    return () => { socket.disconnect(); socketRef.current = null }
  }, [])

  // Rule 5: High Traffic alert
  useEffect(() => { setHighTraffic(pps > PPS_THRESHOLD) }, [pps])

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
      interfaces: selectedIface ? [selectedIface] : [],
    })
    setShowModal(false)
  }

  function toggleProto(proto) {
    setFilterProtos(prev =>
      prev.includes(proto) ? prev.filter(p => p !== proto) : [...prev, proto]
    )
  }

  const { packets, stats, protoCnt, alertCnt } = live

  const alertLevelMap = {}
  packets.forEach(p => { if (p.alert) alertLevelMap[p.alert.label] = p.alert.level })

  const top10Alerts = Object.entries(alertCnt)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([label, count]) => ({
      label,
      count,
      level: alertLevelMap[label] || 'warn',
    }))

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
          <TabBtn active={tab === 'live'} onClick={() => setTab('live')}><Radio size={14} /> Live Monitor</TabBtn>
          <TabBtn active={tab === 'history'} onClick={() => { setTab('history'); loadHistory() }}>
            <FolderOpen size={14} /> Packet History
          </TabBtn>
        </div>

        {tab === 'live' && (
          <div className="flex items-center gap-3">
            {scanning && (
              <div className="flex items-center gap-2 text-xs text-slate-400 bg-slate-800 px-3 py-1.5 rounded-lg">
                {selectedIface && <span className="text-violet-400 flex items-center gap-1"><Plug size={12} /> {shortIfaceName(interfaces.find(i => i.id === selectedIface)?.name || selectedIface)}</span>}
                {filterProtos.length > 0 && <span className="text-sky-400">{filterProtos.join(', ')}</span>}
                {filterIp && <span className="text-emerald-400 font-mono">{filterIp}</span>}
                {delay > 0 && <span className="text-yellow-400 flex items-center gap-1"><Timer size={12} /> {delay}ms</span>}
                {!selectedIface && filterProtos.length === 0 && !filterIp && delay === 0 && <span>ทุก interface / protocol</span>}
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
              {scanning ? <><Square size={13} fill="white" /> Stop Scan</> : <><Play size={13} fill="white" /> Start Scan</>}
            </button>
          </div>
        )}
      </div>

      {/* ══ PAGE: LIVE ══ */}
      {tab === 'live' && (
        <div>
          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-5">
            <StatCard label="Total Packets"  value={stats.total} />
            <StatCard label="Encrypted"      value={stats.enc} color="text-sky-400" />
            <StatCard label="Plain Text"     value={stats.plain} color="text-red-400" />
            <StatCard label="Alerts"         value={stats.alerts} color="text-yellow-400" />
            <StatCard label="Packets / sec"  value={pps} color={highTraffic ? 'text-red-400 animate-pulse' : 'text-green-400'} />
          </div>

          {/* Rule 5: High Traffic banner */}
          {highTraffic && (
            <div className="flex items-center gap-2 bg-orange-900/40 border border-orange-500/50 text-orange-300 text-sm px-4 py-2.5 rounded-lg mb-5">
              <AlertTriangle size={16} />
              <span className="font-bold">High Traffic Alert</span>
              <span className="text-orange-400/80">— Packets/sec เกิน {PPS_THRESHOLD} ({pps} pps) อาจเกิด DoS หรือ traffic flood</span>
            </div>
          )}

          {/* Charts */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-5 mb-5">
            <div className="bg-slate-800 rounded-xl p-5">
              <h3 className="text-slate-400 text-sm mb-4 flex items-center gap-2"><Lock size={14} /> Encryption Ratio</h3>
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
              <h3 className="text-slate-400 text-sm mb-4 flex items-center gap-2"><BarChart2 size={14} /> Protocol Distribution</h3>
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
            <div className="bg-slate-800 rounded-xl p-5">
              <h3 className="text-slate-400 text-sm mb-4 flex items-center gap-2"><AlertTriangle size={14} /> Top 10 Alerts</h3>
              {top10Alerts.length === 0
                ? <p className="text-slate-500 text-sm text-center py-8">ยังไม่มี alert...</p>
                : <div className="flex flex-col gap-2">
                    {top10Alerts.map(({ label, count, level }) => (
                      <div key={label} className="flex items-center justify-between gap-2">
                        <span className={`px-2 py-1 rounded text-xs font-bold truncate ${ALERT_COLOR[level]}`}>{label}</span>
                        <span className="text-slate-300 text-sm font-mono font-bold shrink-0">{count}</span>
                      </div>
                    ))}
                  </div>
              }
            </div>
          </div>

          {/* Live Packet Table */}
          <div className="bg-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between gap-3 mb-4">
              <h3 className="text-slate-400 text-sm flex items-center gap-2"><ClipboardList size={14} /> Live Packets (20 รายการล่าสุด)</h3>
              <div className="relative">
                <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                <input
                  type="text"
                  placeholder="ค้นหา IP, Protocol, Port..."
                  value={liveSearch}
                  onChange={e => setLiveSearch(e.target.value)}
                  className="bg-slate-700 text-slate-200 text-xs pl-8 pr-3 py-1.5 rounded-lg outline-none border border-slate-600 focus:border-sky-500 w-56"
                />
              </div>
            </div>
            <PacketTable
              packets={packets.filter(p => {
                const q = liveSearch.toLowerCase()
                if (!q) return true
                return (
                  (p.source_ip || '').includes(q) ||
                  (p.dest_ip || '').includes(q) ||
                  (p.protocol || '').toLowerCase().includes(q) ||
                  String(p.port || '').includes(q) ||
                  (p.alert?.label || '').toLowerCase().includes(q)
                )
              })}
              onSelect={setSelectedPacket}
            />
          </div>
        </div>
      )}

      {/* ══ PAGE: HISTORY ══ */}
      {tab === 'history' && (
        <div className="bg-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between gap-3 mb-4">
            <h3 className="text-slate-400 text-sm flex items-center gap-2"><FolderOpen size={14} /> Packet History (50 รายการล่าสุด)</h3>
            <div className="relative">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
              <input
                type="text"
                placeholder="ค้นหา IP, Protocol, Port..."
                value={histSearch}
                onChange={e => setHistSearch(e.target.value)}
                className="bg-slate-700 text-slate-200 text-xs pl-8 pr-3 py-1.5 rounded-lg outline-none border border-slate-600 focus:border-sky-500 w-56"
              />
            </div>
          </div>
          <PacketTable
            packets={history.filter(p => {
              const q = histSearch.toLowerCase()
              if (!q) return true
              return (
                (p.source_ip || '').includes(q) ||
                (p.dest_ip || '').includes(q) ||
                (p.protocol || '').toLowerCase().includes(q) ||
                String(p.port || '').includes(q) ||
                (p.alert?.label || '').toLowerCase().includes(q)
              )
            })}
            showDate
            onSelect={setSelectedPacket}
          />
        </div>
      )}

      {/* ══ MODAL: Packet Detail ══ */}
      {selectedPacket && (
        <PacketDetailModal packet={selectedPacket} onClose={() => setSelectedPacket(null)} />
      )}

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
            <h2 className="text-white font-bold text-lg mb-5 flex items-center gap-2"><Play size={16} fill="white" /> Capture Settings</h2>

            {/* Interface */}
            {interfaces.length > 0 && (
              <div className="mb-5">
                <p className="text-slate-400 text-xs mb-2 flex items-center gap-1"><Plug size={12} /> Interface <span className="text-slate-500">(ไม่เลือก = ทุก interface)</span></p>
                <select
                  value={selectedIface}
                  onChange={e => setSelectedIface(e.target.value)}
                  className="w-full bg-slate-700 text-slate-200 text-sm px-3 py-2 rounded-lg outline-none border border-slate-600 focus:border-violet-500 cursor-pointer"
                >
                  <option value="">— ทุก interface —</option>
                  {interfaces.map(iface => (
                    <option key={iface.id} value={iface.id}>{shortIfaceName(iface.name)}</option>
                  ))}
                </select>
              </div>
            )}

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
              <p className="text-slate-400 text-xs mb-2 flex items-center gap-1"><Timer size={12} /> Packet Delay <span className="text-sky-400 font-mono">{delay} ms</span></p>
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
                className="flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-bold bg-emerald-600 hover:bg-emerald-500 text-white cursor-pointer transition-colors"
              >
                <Play size={13} fill="white" /> เริ่ม Capture
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

function PacketTable({ packets, showDate = false, onSelect }) {
  if (!packets.length)
    return <p className="text-slate-500 text-sm text-center py-4">ยังไม่มีข้อมูล...</p>

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr>
            {['Time', 'Source IP', 'Destination IP', 'Protocol', 'Port', 'Size', 'Encryption', 'Alert'].map(h => (
              <th key={h} className="text-left text-slate-500 text-xs pb-3 pr-4">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {packets.map((p, i) => <PacketRow key={i} packet={p} showDate={showDate} onSelect={onSelect} />)}
        </tbody>
      </table>
    </div>
  )
}

function PacketRow({ packet: p, showDate, onSelect }) {
  const time = p.timestamp
    ? showDate
      ? new Date(p.timestamp).toLocaleString('th-TH')
      : new Date(p.timestamp).toLocaleTimeString('th-TH')
    : new Date().toLocaleTimeString('th-TH')
  const proto    = (p.protocol || '').toLowerCase()
  const badgeCls = PROTO_BADGE[proto] || 'bg-slate-700 text-slate-300'

  return (
    <tr
      className="border-t border-slate-700/40 hover:bg-slate-700/30 transition-colors cursor-pointer"
      onClick={() => onSelect?.(p)}
    >
      <td className="py-2 pr-4 text-slate-400 text-xs">{time}</td>
      <td className="py-2 pr-4 font-mono text-xs">{p.source_ip}</td>
      <td className="py-2 pr-4 font-mono text-xs text-slate-400">{p.dest_ip || '—'}</td>
      <td className="py-2 pr-4">
        <span className={`px-2 py-0.5 rounded text-xs font-bold ${badgeCls}`}>{p.protocol}</span>
      </td>
      <td className="py-2 pr-4">{p.port}</td>
      <td className="py-2 pr-4">{p.size} B</td>
      <td className="py-2">
        {p.is_encrypted
          ? <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-emerald-900/60 text-emerald-400 rounded-full text-xs font-bold"><Lock size={10} /> {p.encryption_type}</span>
          : <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-red-900/60 text-red-400 rounded-full text-xs font-bold"><Unlock size={10} /> Plain</span>
        }
      </td>
      <td className="py-2">
        {p.alert
          ? <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${ALERT_COLOR[p.alert.level]}`}>{p.alert.label}</span>
          : <span className="text-slate-600 text-xs">—</span>
        }
      </td>
    </tr>
  )
}

// ── Packet Detail Modal ──────────────────────────────────────

function PacketDetailModal({ packet: p, onClose }) {
  const time = p.timestamp
    ? new Date(p.timestamp).toLocaleString('th-TH')
    : '—'

  const rows = [
    { icon: <Globe size={13} />,          label: 'Source IP',       value: p.source_ip },
    { icon: <Globe size={13} />,          label: 'Destination IP',  value: p.dest_ip || '—' },
    { icon: <Network size={13} />,        label: 'Protocol',        value: p.protocol },
    { icon: <ArrowRightLeft size={13} />, label: 'Port',            value: p.port ?? '—' },
    { icon: <FileText size={13} />,       label: 'Size',            value: p.size != null ? `${p.size} B` : '—' },
    { icon: <Cpu size={13} />,            label: 'TLS Version',     value: p.tls_version || '—' },
    { icon: <Key size={13} />,            label: 'Encryption Type', value: p.encryption_type || '—' },
    { icon: <Calendar size={13} />,       label: 'Cert Expiry',     value: p.cert_expiry || '—' },
    { icon: <Info size={13} />,           label: 'Payload',         value: p.payload || '—' },
  ]

  return (
    <div
      className="fixed inset-0 z-60 flex items-center justify-center bg-black/70"
      onClick={onClose}
    >
      <div
        className="bg-slate-800 rounded-2xl p-6 w-full max-w-lg shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-white font-bold text-base flex items-center gap-2">
            <ClipboardList size={16} /> Packet Detail
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors cursor-pointer">
            <X size={18} />
          </button>
        </div>

        {/* Time */}
        <p className="text-slate-500 text-xs mb-4">{time}</p>

        {/* Src → Dst */}
        <div className="flex items-center gap-2 bg-slate-700/60 px-4 py-3 rounded-xl mb-4">
          <Globe size={13} className="text-sky-400 shrink-0" />
          <span className="text-sky-300 font-mono text-xs">{p.source_ip || '—'}</span>
          <ArrowRightLeft size={13} className="text-slate-500 shrink-0" />
          <Globe size={13} className="text-emerald-400 shrink-0" />
          <span className="text-emerald-300 font-mono text-xs">{p.dest_ip || '—'}</span>
        </div>

        {/* Fields */}
        <div className="flex flex-col gap-2">
          {rows.map(({ icon, label, value }) => (
            <div key={label} className="flex items-start gap-3 bg-slate-700/40 px-3 py-2 rounded-lg">
              <span className="text-slate-400 mt-0.5 shrink-0">{icon}</span>
              <span className="text-slate-400 text-xs w-32 shrink-0">{label}</span>
              <span className="text-slate-200 text-xs font-mono break-all">{String(value)}</span>
            </div>
          ))}

          {/* Encryption */}
          <div className="flex items-center gap-3 bg-slate-700/40 px-3 py-2 rounded-lg">
            <span className="text-slate-400 shrink-0">{p.is_encrypted ? <Lock size={13} /> : <Unlock size={13} />}</span>
            <span className="text-slate-400 text-xs w-32 shrink-0">Encrypted</span>
            {p.is_encrypted
              ? <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-emerald-900/60 text-emerald-400 rounded-full text-xs font-bold"><Lock size={10} /> Yes</span>
              : <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-red-900/60 text-red-400 rounded-full text-xs font-bold"><Unlock size={10} /> No</span>
            }
          </div>

          {/* Alert */}
          {p.alert && (
            <div className="flex items-center gap-3 bg-slate-700/40 px-3 py-2 rounded-lg">
              <span className="text-orange-400 shrink-0"><AlertTriangle size={13} /></span>
              <span className="text-slate-400 text-xs w-32 shrink-0">Alert</span>
              <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${ALERT_COLOR[p.alert.level]}`}>
                {p.alert.label}
              </span>
            </div>
          )}
        </div>

        {/* Close button */}
        <div className="flex justify-end mt-5">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-lg text-sm bg-slate-700 text-slate-300 hover:bg-slate-600 cursor-pointer transition-colors"
          >
            ปิด
          </button>
        </div>
      </div>
    </div>
  )
}

