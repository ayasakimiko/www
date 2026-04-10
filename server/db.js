
 import { readFileSync, writeFileSync, existsSync, mkdirSync, writeFile } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, '../data');

if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

function readJSON(file) {
  const path = join(DATA_DIR, file);
  if (!existsSync(path)) return [];
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return []; }
}

function writeJSON(file, data) {
  writeFileSync(join(DATA_DIR, file), JSON.stringify(data, null, 2), 'utf8');
}

// ─── Users ───────────────────────────────────────────────────

const usersStore = {
  getAll() {
    return readJSON('users.json').map(({ password, ...u }) => u);
  },
  getById(id) {
    return readJSON('users.json').find(u => u.id === Number(id)) ?? null;
  },
  getByUsername(username) {
    return readJSON('users.json').find(u => u.username === username) ?? null;
  },
  insert(username, password, role = 'user') {
    const users = readJSON('users.json');
    if (users.find(u => u.username === username)) {
      throw new Error('UNIQUE constraint failed: users.username');
    }
    const id = users.length ? Math.max(...users.map(u => u.id)) + 1 : 1;
    users.push({ id, username, password, role });
    writeJSON('users.json', users);
    return id;
  },
  delete(id) {
    writeJSON('users.json', readJSON('users.json').filter(u => u.id !== Number(id)));
  },
  updateRole(id, role) {
    const users = readJSON('users.json');
    const u = users.find(u => u.id === Number(id));
    if (u) u.role = role;
    writeJSON('users.json', users);
  },
};

// ─── Packets ─────────────────────────────────────────────────

const MAX_PACKETS = 50;

// in-memory buffer — ไม่แตะ disk จนกว่าจะ flush
let packetBuffer = null;
let flushTimer = null;

function getBuffer() {
  if (packetBuffer === null) {
    packetBuffer = readJSON('packets.json');
  }
  return packetBuffer;
}

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    if (packetBuffer === null) return;
    const data = JSON.stringify(packetBuffer, null, 2);
    writeFile(join(DATA_DIR, 'packets.json'), data, 'utf8', (err) => {
      if (err) console.error('[db] flush error:', err.message);
    });
  }, 1000); // เขียนทุก 1 วินาที ไม่ว่าจะรับกี่ packet
}

const packetsStore = {
  insert(pkt) {
    const packets = getBuffer();
    const id = packets.length ? packets[0].id + 1 : 1;
    packets.unshift({ id, ...pkt, timestamp: new Date().toISOString() });
    if (packets.length > MAX_PACKETS) packets.length = MAX_PACKETS;
    scheduleFlush();
  },
  getAll(limit = 100) {
    return getBuffer().slice(0, limit);
  },
  getByIp(ip, limit = 50) {
    return getBuffer()
      .filter(p => p.source_ip === ip || p.dest_ip === ip)
      .slice(0, limit);
  },
};

export { usersStore, packetsStore };


