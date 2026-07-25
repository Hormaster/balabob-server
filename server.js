const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Uploads
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, 'player-' + Date.now() + path.extname(file.originalname))
});
const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ok = /jpeg|jpg|png|gif|webp/.test(path.extname(file.originalname).toLowerCase());
        cb(ok ? null : new Error('Только изображения'), ok);
    }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: process.env.SESSION_SECRET || 'balabob-secret-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// Database
const dbPath = path.join(__dirname, 'database.sqlite');
const db = new Database(dbPath);

db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user')`);
db.exec(`CREATE TABLE IF NOT EXISTS players (id INTEGER PRIMARY KEY, slot INTEGER UNIQUE, name TEXT, position TEXT, mmr INTEGER DEFAULT 0, photo TEXT)`);
db.exec(`CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, name TEXT, text TEXT, created_at TEXT DEFAULT (datetime('now')))`);
db.exec(`CREATE TABLE IF NOT EXISTS applications (id INTEGER PRIMARY KEY, name TEXT, email TEXT, position TEXT, mmr INTEGER, message TEXT, created_at TEXT DEFAULT (datetime('now')))`);

const adminHash = bcrypt.hashSync('penishole', 10);
db.prepare(`INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`).run('hoorma', adminHash, 'admin');

const defaultPlayers = [
    [1, 'Игрок 1', 'Carry (1)', 8000, ''],
    [2, 'Игрок 2', 'Midlane (2)', 8200, ''],
    [3, 'Игрок 3', 'Offlane (3)', 7900, ''],
    [4, 'Игрок 4', 'Support 4', 7600, ''],
    [5, 'Игрок 5', 'Support 5', 7800, '']
];
const insertPlayer = db.prepare(`INSERT OR IGNORE INTO players (slot, name, position, mmr, photo) VALUES (?, ?, ?, ?, ?)`);
defaultPlayers.forEach(p => insertPlayer.run(...p));

function requireAuth(req, res, next) {
    if (!req.session.userId) return res.status(401).json({ error: 'Требуется авторизация' });
    next();
}
function requireAdmin(req, res, next) {
    if (!req.session.userId || req.session.role !== 'admin') return res.status(403).json({ error: 'Нет прав' });
    next();
}

// ========== AUTH ==========
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });
    if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
    if (username.toLowerCase() === 'hoorma') return res.status(400).json({ error: 'Ник зарезервирован' });
    try {
        const info = db.prepare(`INSERT INTO users (username, password, role) VALUES (?, ?, 'user')`).run(username, bcrypt.hashSync(password, 10));
        req.session.userId = info.lastInsertRowid;
        req.session.username = username;
        req.session.role = 'user';
        res.json({ success: true, username, role: 'user' });
    } catch (e) {
        res.status(400).json({ error: e.message.includes('UNIQUE') ? 'Пользователь уже есть' : 'Ошибка сервера' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });
    const user = db.prepare(`SELECT * FROM users WHERE username = ?`).get(username);
    if (!user || !bcrypt.compareSync(password, user.password))
        return res.status(401).json({ error: 'Неверный логин или пароль' });
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    res.json({ success: true, username: user.username, role: user.role });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/session', (req, res) => res.json(req.session.userId ? { loggedIn: true, username: req.session.username, role: req.session.role } : { loggedIn: false }));

// ========== PLAYERS ==========
app.get('/api/players', (req, res) => res.json(db.prepare(`SELECT * FROM players ORDER BY slot ASC`).all()));
app.post('/api/upload-photo', requireAdmin, upload.single('photo'), (req, res) => !req.file ? res.status(400).json({ error: 'Файл не загружен' }) : res.json({ success: true, photoUrl: '/uploads/' + req.file.filename }));
app.put('/api/players/:slot', requireAdmin, (req, res) => {
    const slot = parseInt(req.params.slot);
    if (slot < 1 || slot > 5) return res.status(400).json({ error: 'Неверный слот' });
    const { name, position, mmr, photo } = req.body;
    db.prepare(`UPDATE players SET name=?, position=?, mmr=?, photo=? WHERE slot=?`).run(name || '', position || '', mmr || 0, photo || '', slot);
    res.json({ success: true });
});

// ========== USERS (admin only) ==========
app.get('/api/users', requireAdmin, (req, res) => {
    const rows = db.prepare(`SELECT id, username, role, created_at FROM users ORDER BY id DESC`).all();
    res.json(rows);
});

// ========== COMMENTS ==========
app.get('/api/comments', (req, res) => {
    const rows = db.prepare(`SELECT * FROM comments ORDER BY id DESC LIMIT 50`).all();
    res.json(rows);
});

app.post('/api/comments', (req, res) => {
    const { name, text } = req.body;
    if (!name || !text) return res.status(400).json({ error: 'Заполните имя и текст' });
    if (text.length > 500) return res.status(400).json({ error: 'Максимум 500 символов' });
    const info = db.prepare(`INSERT INTO comments (name, text) VALUES (?, ?)`).run(name, text);
    res.json({ success: true, id: info.lastInsertRowid });
});

// ========== APPLICATIONS ==========
app.get('/api/applications', requireAdmin, (req, res) => {
    const rows = db.prepare(`SELECT * FROM applications ORDER BY id DESC`).all();
    res.json(rows);
});

app.post('/api/applications', (req, res) => {
    const { name, email, position, mmr, message } = req.body;
    if (!name || !email || !message) return res.status(400).json({ error: 'Заполните обязательные поля' });
    const info = db.prepare(`INSERT INTO applications (name, email, position, mmr, message) VALUES (?, ?, ?, ?, ?)`)
        .run(name, email, position || '', parseInt(mmr) || 0, message);
    res.json({ success: true, id: info.lastInsertRowid });
});

app.delete('/api/applications/:id', requireAdmin, (req, res) => {
    db.prepare(`DELETE FROM applications WHERE id = ?`).run(req.params.id);
    res.json({ success: true });
});

// ========== SPA CATCH-ALL ==========
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((err, req, res, next) => res.status(400).json({ error: err instanceof multer.MulterError ? 'Файл слишком большой' : err.message }));
app.listen(PORT, '0.0.0.0', () => console.log(`🔥 BALABOB TEAM Server on port ${PORT}`));
