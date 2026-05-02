require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
    secret: process.env.SESSION_SECRET || "secret123",
    resave: false,
    saveUninitialized: false
}));

// 🔥 БАЗА
const db = new Database("database.db");

// таблицы
db.prepare(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    avatar TEXT,
    banner TEXT
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    nickname TEXT,
    age TEXT,
    department TEXT,
    experience TEXT,
    reason TEXT,
    status TEXT DEFAULT 'pending'
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS topics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    text TEXT,
    author_id INTEGER
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    topic_id INTEGER,
    author_id INTEGER,
    text TEXT
)
`).run();

// 🔥 админ
const admin = db.prepare("SELECT * FROM users WHERE login = ?").get("admin");

if (!admin) {
    const hash = bcrypt.hashSync("admin", 10);
    db.prepare("INSERT INTO users (login, password, role) VALUES (?, ?, ?)")
      .run("admin", hash, "admin");
}

// 🔒 middleware
function requireAuth(req, res, next) {
    if (!req.session.user) return res.status(401).json({ message: "Не авторизован" });
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.user || req.session.user.role !== "admin")
        return res.status(403).json({ message: "Нет доступа" });
    next();
}

// 🔥 РЕГИСТРАЦИЯ
app.post("/api/register", async (req, res) => {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.json({ success: false, message: "Заполни поля" });
    }

    const hash = await bcrypt.hash(password, 10);

    try {
        db.prepare("INSERT INTO users (login, password) VALUES (?, ?)")
          .run(login, hash);

        res.json({ success: true, message: "Аккаунт создан" });
    } catch {
        res.json({ success: false, message: "Логин занят" });
    }
});

// 🔥 ЛОГИН
app.post("/api/login", async (req, res) => {
    const { login, password } = req.body;

    const user = db.prepare("SELECT * FROM users WHERE login = ?").get(login);

    if (!user) {
        return res.json({ success: false, message: "Неверный логин или пароль" });
    }

    const ok = await bcrypt.compare(password, user.password);

    if (!ok) {
        return res.json({ success: false, message: "Неверный логин или пароль" });
    }

    req.session.user = {
        id: user.id,
        login: user.login,
        role: user.role
    };

    res.json({ success: true, user: req.session.user });
});

// 🔥 ПРОФИЛЬ
app.get("/api/profile", requireAuth, (req, res) => {
    const user = db.prepare("SELECT * FROM users WHERE id = ?")
        .get(req.session.user.id);

    res.json(user);
});

// 🔥 АВАТАР
app.post("/api/profile/avatar", requireAuth, (req, res) => {
    db.prepare("UPDATE users SET avatar = ? WHERE id = ?")
      .run(req.body.avatar, req.session.user.id);

    res.json({ success: true });
});

// 🔥 БАННЕР
app.post("/api/profile/banner", requireAuth, (req, res) => {
    db.prepare("UPDATE users SET banner = ? WHERE id = ?")
      .run(req.body.banner, req.session.user.id);

    res.json({ success: true });
});

// 🔥 ЗАЯВКА
app.post("/api/apply", requireAuth, (req, res) => {
    const { nickname, age, department, experience, reason } = req.body;

    db.prepare(`
        INSERT INTO applications 
        (user_id, nickname, age, department, experience, reason)
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(
        req.session.user.id,
        nickname,
        age,
        department,
        experience,
        reason
    );

    res.json({ success: true });
});

// 🔥 СТАТУС ЗАЯВКИ
app.get("/api/application", requireAuth, (req, res) => {
    const appData = db.prepare(`
        SELECT * FROM applications 
        WHERE user_id = ? 
        ORDER BY id DESC LIMIT 1
    `).get(req.session.user.id);

    res.json(appData || null);
});

// 🔥 РОЛИ (админ)
app.post("/api/users/role", requireAdmin, (req, res) => {
    const { login, role } = req.body;

    const result = db.prepare("UPDATE users SET role=? WHERE login=?")
        .run(role, login);

    if (result.changes === 0) {
        return res.json({ success: false, message: "Пользователь не найден" });
    }

    res.json({ success: true });
});

// 🔥 ТЕМЫ
app.get("/api/topics", (req, res) => {
    const topics = db.prepare(`
        SELECT topics.*, users.login as author 
        FROM topics 
        JOIN users ON users.id = topics.author_id
        ORDER BY topics.id DESC
    `).all();

    res.json(topics);
});

app.post("/api/topics", requireAuth, (req, res) => {
    const { title, text } = req.body;

    db.prepare("INSERT INTO topics (title, text, author_id) VALUES (?, ?, ?)")
      .run(title, text, req.session.user.id);

    res.json({ success: true });
});

// 🔥 КОММЕНТЫ
app.get("/api/comments/:id", (req, res) => {
    const comments = db.prepare(`
        SELECT comments.*, users.login as author 
        FROM comments 
        JOIN users ON users.id = comments.author_id
        WHERE topic_id = ?
    `).all(req.params.id);

    res.json(comments);
});

app.post("/api/comments", requireAuth, (req, res) => {
    const { topic_id, text } = req.body;

    db.prepare("INSERT INTO comments (topic_id, author_id, text) VALUES (?, ?, ?)")
      .run(topic_id, req.session.user.id, text);

    res.json({ success: true });
});

app.listen(PORT, () => {
    console.log("Server started on port " + PORT);
});
