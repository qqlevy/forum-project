require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
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

const db = new sqlite3.Database("./database.db");

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            avatar TEXT,
            banner TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            nickname TEXT,
            age TEXT,
            department TEXT,
            experience TEXT,
            reason TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            text TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    bcrypt.hash("admin", 10).then(hash => {
        db.run(
            `INSERT OR IGNORE INTO users (login, password, role) VALUES (?, ?, ?)`,
            ["admin", hash, "admin"]
        );
    });
});

function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Не авторизован" });
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.user || req.session.user.role !== "admin") {
        return res.status(403).json({ success: false, message: "Нет доступа" });
    }
    next();
}

app.post("/api/register", async (req, res) => {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.json({ success: false, message: "Заполни логин и пароль" });
    }

    const hash = await bcrypt.hash(password, 10);

    db.run(
        `INSERT INTO users (login, password, role) VALUES (?, ?, ?)`,
        [login, hash, "user"],
        function(err) {
            if (err) {
                return res.json({ success: false, message: "Такой пользователь уже существует" });
            }

            res.json({ success: true, message: "Аккаунт создан" });
        }
    );
});

app.post("/api/login", (req, res) => {
    const { login, password } = req.body;

    db.get(`SELECT * FROM users WHERE login = ?`, [login], async (err, user) => {
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

        res.json({
            success: true,
            user: req.session.user
        });
    });
});

app.post("/api/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

app.get("/api/profile", requireAuth, (req, res) => {
    db.get(
        `SELECT id, login, role, avatar, banner, created_at FROM users WHERE id = ?`,
        [req.session.user.id],
        (err, user) => {
            res.json(user);
        }
    );
});

app.post("/api/profile/avatar", requireAuth, (req, res) => {
    const { avatar } = req.body;

    db.run(
        `UPDATE users SET avatar = ? WHERE id = ?`,
        [avatar, req.session.user.id],
        () => {
            res.json({ success: true, message: "Аватар сохранён" });
        }
    );
});

app.post("/api/profile/banner", requireAuth, (req, res) => {
    const { banner } = req.body;

    db.run(
        `UPDATE users SET banner = ? WHERE id = ?`,
        [banner, req.session.user.id],
        () => {
            res.json({ success: true, message: "Баннер сохранён" });
        }
    );
});

app.post("/api/apply", requireAuth, (req, res) => {
    const { nickname, age, department, experience, reason } = req.body;

    if (!nickname || !age || !department || !experience || !reason) {
        return res.json({ success: false, message: "Заполни все поля" });
    }

    db.run(
        `
        INSERT INTO applications 
        (user_id, nickname, age, department, experience, reason, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        `,
        [req.session.user.id, nickname, age, department, experience, reason, "pending"],
        function() {
            res.json({ success: true, message: "Заявка отправлена" });
        }
    );
});

app.get("/api/application", requireAuth, (req, res) => {
    db.get(
        `
        SELECT * FROM applications
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 1
        `,
        [req.session.user.id],
        (err, application) => {
            res.json(application || null);
        }
    );
});

app.get("/api/users", requireAdmin, (req, res) => {
    db.all(
        `SELECT id, login, role, created_at FROM users ORDER BY id ASC`,
        [],
        (err, users) => {
            res.json(users);
        }
    );
});

app.post("/api/users/role", requireAdmin, (req, res) => {
    const { login, role } = req.body;

    if (!["user", "moderator", "admin"].includes(role)) {
        return res.json({ success: false, message: "Неверная роль" });
    }

    db.run(
        `UPDATE users SET role = ? WHERE login = ?`,
        [role, login],
        function() {
            if (this.changes === 0) {
                return res.json({ success: false, message: "Пользователь не найден" });
            }

            res.json({ success: true, message: "Роль изменена" });
        }
    );
});

app.get("/api/topics", (req, res) => {
    db.all(
        `
        SELECT topics.id, topics.title, topics.text, topics.created_at, users.login AS author
        FROM topics
        JOIN users ON topics.author_id = users.id
        ORDER BY topics.id DESC
        `,
        [],
        (err, topics) => {
            res.json(topics || []);
        }
    );
});

app.post("/api/topics", requireAuth, (req, res) => {
    const { title, text } = req.body;

    if (!title || !text) {
        return res.json({ success: false, message: "Заполни название и текст темы" });
    }

    db.run(
        `INSERT INTO topics (title, text, author_id) VALUES (?, ?, ?)`,
        [title, text, req.session.user.id],
        function() {
            res.json({ success: true, message: "Тема создана" });
        }
    );
});

app.delete("/api/topics/:id", requireAuth, (req, res) => {
    const role = req.session.user.role;

    if (role !== "admin" && role !== "moderator") {
        return res.status(403).json({ success: false, message: "Нет прав удалять темы" });
    }

    db.run(`DELETE FROM comments WHERE topic_id = ?`, [req.params.id], () => {
        db.run(`DELETE FROM topics WHERE id = ?`, [req.params.id], () => {
            res.json({ success: true, message: "Тема удалена" });
        });
    });
});

app.get("/api/comments/:topicId", (req, res) => {
    db.all(
        `
        SELECT comments.id, comments.text, comments.created_at, users.login AS author
        FROM comments
        JOIN users ON comments.author_id = users.id
        WHERE comments.topic_id = ?
        ORDER BY comments.id ASC
        `,
        [req.params.topicId],
        (err, comments) => {
            res.json(comments || []);
        }
    );
});

app.post("/api/comments", requireAuth, (req, res) => {
    const { topic_id, text } = req.body;

    if (!topic_id || !text) {
        return res.json({ success: false, message: "Заполни комментарий" });
    }

    db.run(
        `INSERT INTO comments (topic_id, author_id, text) VALUES (?, ?, ?)`,
        [topic_id, req.session.user.id, text],
        function() {
            res.json({ success: true, message: "Комментарий добавлен" });
        }
    );
});

app.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
});