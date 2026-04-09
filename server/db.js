
 import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
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

const packetsStore = {
  insert(pkt) {
    const packets = readJSON('packets.json');
    const id = packets.length ? Math.max(...packets.map(p => p.id)) + 1 : 1;
    packets.unshift({ id, ...pkt, timestamp: new Date().toISOString() });
    if (packets.length > MAX_PACKETS) packets.splice(MAX_PACKETS);
    writeJSON('packets.json', packets);
  },
  getAll(limit = 100) {
    return readJSON('packets.json').slice(0, limit);
  },
  getByIp(ip, limit = 50) {
    return readJSON('packets.json')
      .filter(p => p.source_ip === ip || p.dest_ip === ip)
      .slice(0, limit);
  },
};

export { usersStore, packetsStore };


