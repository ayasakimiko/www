import express from 'express';
import bcrypt from 'bcryptjs';
import { usersStore, packetsStore } from '../db.js';
import { generateToken, verifyToken } from '../auth.js';

const router = express.Router();

// Middleware เช็ค Admin
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin only' });
  }
  next();
}

// POST /api/register
router.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบ' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    const userId = usersStore.insert(username, hashed, role || 'user');
    res.json({ message: 'สมัครสมาชิกสำเร็จ', userId });
  } catch (err) {
    if (err.message.includes('UNIQUE'))
      return res.status(409).json({ message: 'Username นี้มีแล้ว' });
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = usersStore.getByUsername(username);
  if (!user) return res.status(401).json({ message: 'ไม่พบ username นี้' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ message: 'Password ไม่ถูกต้อง' });

  const token = generateToken(user);
  res.json({ token, role: user.role, username: user.username });
});

// GET /api/me
router.get('/me', verifyToken, (req, res) => {
  try {
    const user = usersStore.getById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    const { password, ...safe } = user;
    res.json({ user: safe });
  } catch (err) {
    res.status(500).json({ message: 'Server error', detail: err.message });
  }
});

// ─── Admin Routes ───────────────────────────────────────────

// GET /api/admin/users
router.get('/admin/users', verifyToken, requireAdmin, (req, res) => {
  try {
    res.json(usersStore.getAll());
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE /api/admin/users/:id
router.delete('/admin/users/:id', verifyToken, requireAdmin, (req, res) => {
  try {
    usersStore.delete(req.params.id);
    res.json({ message: 'ลบ user สำเร็จ' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// PUT /api/admin/users/:id/role
router.put('/admin/users/:id/role', verifyToken, requireAdmin, (req, res) => {
  try {
    const { role } = req.body;
    if (!['admin', 'user'].includes(role))
      return res.status(400).json({ message: 'role ไม่ถูกต้อง' });
    usersStore.updateRole(req.params.id, role);
    res.json({ message: 'เปลี่ยน role สำเร็จ' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/admin/packets
router.get('/admin/packets', verifyToken, requireAdmin, (req, res) => {
  res.json(packetsStore.getAll(100));
});

// GET /api/packets
router.get('/packets', verifyToken, (req, res) => {
  if (req.user.role === 'admin') {
    return res.json(packetsStore.getAll(50));
  }
  const raw = (req.ip || req.socket?.remoteAddress || '').replace('::ffff:', '').trim();
  // localhost → ใช้ MACHINE_IPS เหมือนฝั่ง server
  const isLocal = raw === '127.0.0.1' || raw === '::1' || !raw;
  const packets = isLocal
    ? packetsStore.getAll(50)
    : packetsStore.getByIp(raw, 50);
  res.json(packets);
});

export default router;

