import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import { spawn, execFileSync } from "child_process";
import { networkInterfaces } from "os";
import cors from "cors";
import { packetsStore } from "./server/db.js";
import authRoutes from "./server/routes/authRoutes.js";
import { config } from "dotenv";

config();

const app = express();
const server = createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use(express.static("public"));
app.use("/api", authRoutes);

// Global error handler — ป้องกัน unhandled error ส่งออก 500 แบบ silent
app.use((err, req, res, next) => {
  console.error('[Express Error]', err.message);
  res.status(500).json({ message: err.message });
});

const ENCRYPTION_MAP = {
  443: "TLS 1.3",
  8443: "TLS 1.2",
  22: "SSH 2.0",
  993: "TLS 1.2",
  465: "SSL 3.0",
  636: "TLS 1.2",
};

function getProtocol(protos, port) {
  const p = (protos || "").toLowerCase();
  if (port === 443 || port === 8443) return "HTTPS";
  if (port === 80 || port === 8080) return "HTTP";
  if (port === 22) return "SSH";
  if (port === 53 || p.includes("dns")) return "DNS";
  if (p.includes("udp")) return "UDP";
  return "TCP";
}

// คืน IP จริงทุกตัวของเครื่อง (ข้าม loopback)
function getMachineIps() {
  const ips = [];
  for (const iface of Object.values(networkInterfaces())) {
    for (const net of iface) {
      if (net.family === "IPv4" && !net.internal) ips.push(net.address);
    }
  }
  return ips.length ? ips : ["127.0.0.1"];
}

const MACHINE_IPS = getMachineIps();
console.log("Machine IPs:", MACHINE_IPS);

function resolveClientIps(raw) {
  const ip = (raw || "").replace("::ffff:", "").trim();
  return ip === "127.0.0.1" || ip === "::1" ? MACHINE_IPS : [ip];
}

function detectAllInterfaces() {
  if (process.env.CAPTURE_IFACE) {
    return [{ id: process.env.CAPTURE_IFACE, name: process.env.CAPTURE_IFACE }];
  }

  // Linux/Mac: 'any' จับทุก interface ในคำสั่งเดียว
  if (process.platform !== "win32") return [{ id: "any", name: "any" }];

  const TSHARK_BIN =
    process.env.TSHARK_PATH ||
    "C:\\Program Files\\Wireshark\\tshark.exe";
  try {
    const out = execFileSync(TSHARK_BIN, ["-D"], {
      encoding: "utf8",
      timeout: 5000,
    });
    const lines = out.trim().split("\n");

    const ifaces = [];
    for (const line of lines) {
      const match = line.match(/^(\d+)\.\s*(.+)/);
      if (!match) continue;
      const id = match[1];
      const raw = match[2].trim();
      // ดึง friendly name จากวงเล็บท้ายสุด รองรับ nested parens เช่น (vEthernet (WSL))
      const parenMatch = raw.match(/\((.+)\)\s*$/);
      const name = parenMatch ? parenMatch[1].trim() : raw;
      // ข้ามเฉพาะ ETW ที่ไม่ใช่ network interface จริงๆ
      if (name.toLowerCase().includes("event tracing") || raw.toLowerCase().startsWith("etw")) continue;
      console.log(`Interface found: [${id}] ${name}`);
      ifaces.push({ id, name });
    }
    return ifaces.length ? ifaces : [{ id: "1", name: "Interface 1" }];
  } catch {}
  return [{ id: "1", name: "Interface 1" }];
}

const clients = new Map();

io.on("connection", (socket) => {
  const ips = resolveClientIps(socket.handshake.address);
  clients.set(socket.id, { socket, ips, pps: 0, filter: {} });
  console.log(`Client connected: ${ips.join(", ")}`);

  // ส่ง status ปัจจุบันให้ client ใหม่
  socket.emit("scan-status", isCapturing);

  // ส่งรายการ interface ให้ client
  socket.on("get-interfaces", (cb) => {
    if (typeof cb === "function") cb(ALL_IFACES);
  });

  socket.on("start-scan", (filter) => {
    const c = clients.get(socket.id);
    if (c) c.filter = filter || {};
    startCapture(filter?.interfaces);
  });
  socket.on("stop-scan", () => stopCapture());
  socket.on("disconnect", () => {
    clients.delete(socket.id);
  });
});

setInterval(() => {
  for (const [, c] of clients) {
    c.socket.emit("packets-per-sec", c.pps);
    c.pps = 0;
  }
}, 1000);

function matchFilter(pkt, filter = {}) {
  // กรอง protocol
  if (filter.protocols && filter.protocols.length > 0) {
    if (!filter.protocols.includes(pkt.protocol)) return false;
  }
  // กรอง IP
  if (filter.ip && filter.ip.trim()) {
    const ip = filter.ip.trim();
    if (pkt.source_ip !== ip && pkt.dest_ip !== ip) return false;
  }
  return true;
}

function routePacket(pkt) {
  for (const [, c] of clients) {
    if (c.ips.includes(pkt.source_ip) || c.ips.includes(pkt.dest_ip)) {
      if (matchFilter(pkt, c.filter)) {
        c.socket.emit("packet-stream", pkt);
        c.pps++;
      }
    }
  }
}

const TSHARK =
  process.env.TSHARK_PATH ||
  (process.platform === "win32"
    ? "C:\\Program Files\\Wireshark\\tshark.exe"
    : "tshark");
const ALL_IFACES = detectAllInterfaces();
console.log(`Interfaces: ${ALL_IFACES.map((i) => `${i.id}(${i.name})`).join(", ")}`);

let tsharkProc = null;
let isCapturing = false;

function startCapture(selectedIfaces) {
  if (isCapturing) return;
  isCapturing = true;
  io.emit("scan-status", true);

  // ใช้ interface ที่ client เลือก ถ้าไม่เลือก = ทุก interface
  const ifaceIds =
    selectedIfaces && selectedIfaces.length > 0
      ? selectedIfaces
      : ALL_IFACES.map((i) => i.id);

  // BPF capture filter: เฉพาะ IPv4 และต้องมี IP ของเครื่องเราเป็น src หรือ dst
  const hostFilter = MACHINE_IPS.map((ip) => `host ${ip}`).join(" or ");
  const captureFilter = `ip and (${hostFilter})`;
  console.log("Capture filter:", captureFilter);
  console.log("Capturing on:", ifaceIds.join(", "));

  const ifaceArgs = ifaceIds.flatMap((i) => ["-i", i]);
  tsharkProc = spawn(TSHARK, [
    ...ifaceArgs,
    "-f",
    captureFilter,
    "-T",
    "fields",
    "-e",
    "ip.src",
    "-e",
    "ip.dst",
    "-e",
    "tcp.dstport",
    "-e",
    "udp.dstport",
    "-e",
    "frame.protocols",
    "-e",
    "frame.len",
    "-e",
    "tls.handshake.version",
    "-e",
    "x509af.notAfter",
    "-E",
    "separator=|",
    "-E",
    "occurrence=f",
    "-l",
  ]);

  let buf = "";
  tsharkProc.stdout.on("data", (chunk) => {
    buf += chunk.toString();
    const lines = buf.split("\n");
    buf = lines.pop();
    for (const line of lines) {
      const p = line.trim().split("|");
      if (!p[0] || !p[1]) continue; // ต้องมี src+dst IP
      const port = parseInt(p[2] || p[3]) || 0;
      const enc = ENCRYPTION_MAP[port] || null;
      const tlsVer = p[6] || "";
      const certExpiry = p[7] || "";
      routePacket({
        source_ip: p[0],
        dest_ip: p[1],
        protocol: getProtocol(p[4] || "", port),
        port,
        is_encrypted: enc ? 1 : 0,
        encryption_type: enc || "None",
        size: parseInt(p[5]) || 0,
        tls_version: tlsVer,
        cert_expiry: certExpiry,
        timestamp: new Date().toISOString(),
      });
    }
  });

  tsharkProc.stderr.on("data", (d) => {
    const msg = d.toString().trim();
    if (msg && !msg.toLowerCase().includes("capturing on"))
      console.error("[tshark]", msg);
  });

  tsharkProc.on("error", (e) => {
    console.error("tshark error:", e.message);
    isCapturing = false;
    io.emit("scan-status", false);
  });

  tsharkProc.on("close", (code) => {
    tsharkProc = null;
    isCapturing = false;
    io.emit("scan-status", false);
    console.log(`tshark stopped (exit ${code})`);
  });

  console.log(`tshark capturing on interfaces: ${ifaceIds.join(", ")}`);
}

function stopCapture() {
  if (!tsharkProc) return;
  tsharkProc.stdout.removeAllListeners();
  tsharkProc.stderr.removeAllListeners();
  tsharkProc.removeAllListeners("close");
  tsharkProc.kill();
  tsharkProc = null;
  isCapturing = false;
  io.emit("scan-status", false);
  console.log("tshark stopped by user");
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () =>
  console.log(`Server ready at http://localhost:${PORT}`),
);
