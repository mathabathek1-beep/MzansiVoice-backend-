// ===============================
// 🇿🇦 MZANSIVOICE - FINAL BACKEND (FIXED)
// ===============================

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// ===============================
// 🔧 MIDDLEWARE
// ===============================
app.use(express.json());

app.use(cors({
  origin: "*", // later replace with frontend URL
  methods: ["GET", "POST", "DELETE"],
}));

// ===============================
// ✅ ROOT ROUTE (FIXED)
// ===============================
app.get('/', (req, res) => {
  res.json({
    status: "OK",
    message: "MzansiVoice API is running 🚀"
  });
});

// ===============================
// ❤️ HEALTH CHECK
// ===============================
app.get('/health', (req, res) => {
  res.json({ status: "healthy" });
});

// ===============================
// 🔗 DATABASE
// ===============================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Connect safely
pool.connect()
  .then(() => {
    console.log("✅ PostgreSQL Connected");
    createTables();
  })
  .catch(err => {
    console.error("❌ Database connection error:", err.message);
  });

// ===============================
// 📦 CREATE TABLES
// ===============================
const createTables = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        surname VARCHAR(255) NOT NULL,
        "idNumber" VARCHAR(50) UNIQUE NOT NULL,
        phone VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        "isAdmin" BOOLEAN DEFAULT FALSE
      );

      CREATE TABLE IF NOT EXISTS polls (
        id SERIAL PRIMARY KEY,
        question TEXT NOT NULL,
        "optionA" TEXT NOT NULL,
        "optionB" TEXT NOT NULL,
        "votesA" INTEGER DEFAULT 0,
        "votesB" INTEGER DEFAULT 0,
        "startDate" TIMESTAMP NOT NULL,
        "endDate" TIMESTAMP NOT NULL
      );

      CREATE TABLE IF NOT EXISTS anonymous_votes (
        id SERIAL PRIMARY KEY,
        "voteHash" VARCHAR(255) UNIQUE NOT NULL,
        choice CHAR(1) NOT NULL,
        "pollId" INTEGER NOT NULL,
        timestamp TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS reset_tokens (
        id SERIAL PRIMARY KEY,
        phone VARCHAR(50) NOT NULL,
        token VARCHAR(50) NOT NULL,
        expires TIMESTAMP NOT NULL
      );
    `);

    console.log("✅ Tables ready");
  } catch (err) {
    console.error("❌ Table creation error:", err.message);
  }
};

// ===============================
// 🔐 AUTH MIDDLEWARE
// ===============================
function auth(req, res, next) {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(400).json({ error: "Invalid token" });
  }
}

async function adminAuth(req, res, next) {
  const result = await pool.query(
    'SELECT "isAdmin" FROM users WHERE id = $1',
    [req.user.userId]
  );

  if (!result.rows[0]?.isAdmin) {
    return res.status(403).json({ error: "Admin only" });
  }

  next();
}

// ===============================
// 👤 AUTH ROUTES
// ===============================
app.post('/api/register', async (req, res) => {
  try {
    const { name, surname, idNumber, phone, password } = req.body;

    const existing = await pool.query(
      'SELECT * FROM users WHERE "idNumber" = $1 OR phone = $2',
      [idNumber, phone]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ error: "User exists" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (name, surname, "idNumber", phone, password) VALUES ($1,$2,$3,$4,$5)',
      [name, surname, idNumber, phone, hashed]
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;

    const result = await pool.query(
      'SELECT * FROM users WHERE phone = $1',
      [phone]
    );

    if (result.rows.length === 0)
      return res.status(400).json({ error: "Invalid credentials" });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid)
      return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({ success: true, token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===============================
// 🗳️ POLLS
// ===============================
app.get('/api/polls/active', async (req, res) => {
  try {
    const now = new Date();

    const result = await pool.query(
      'SELECT * FROM polls WHERE "startDate" <= $1 AND "endDate" >= $1 LIMIT 1',
      [now]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ error: "No active poll" });

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===============================
// 🗳️ VOTING
// ===============================
app.post('/api/vote', auth, async (req, res) => {
  try {
    const { pollId, choice } = req.body;
    const userId = req.user.userId;

    const hash = crypto
      .createHash('sha256')
      .update(process.env.VOTE_SALT + userId + pollId)
      .digest('hex');

    const exists = await pool.query(
      'SELECT * FROM anonymous_votes WHERE "voteHash"=$1',
      [hash]
    );

    if (exists.rows.length > 0)
      return res.status(400).json({ error: "Already voted" });

    await pool.query(
      'INSERT INTO anonymous_votes ("voteHash", choice, "pollId") VALUES ($1,$2,$3)',
      [hash, choice, pollId]
    );

    if (choice === 'A') {
      await pool.query('UPDATE polls SET "votesA"="votesA"+1 WHERE id=$1', [pollId]);
    } else {
      await pool.query('UPDATE polls SET "votesB"="votesB"+1 WHERE id=$1', [pollId]);
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===============================
// 🚀 START SERVER
// ===============================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
