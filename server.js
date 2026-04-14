// ===============================
// 🇿🇦 MZANSIVOICE - POSTGRESQL BACKEND
// ===============================

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// ===============================
// 🔗 DATABASE (PostgreSQL)
// ===============================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect((err) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('PostgreSQL Connected');
    createTables();
  }
});

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
    console.log("Tables ready");
  } catch (err) {
    console.error("Error creating tables:", err);
  }
};

function auth(req, res, next) {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(400).json({ error: "Invalid token" });
  }
}

async function adminAuth(req, res, next) {
  const result = await pool.query('SELECT "isAdmin" FROM users WHERE id = $1', [req.user.userId]);
  if (result.rows.length === 0 || !result.rows[0].isAdmin) {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

app.post('/api/register', async (req, res) => {
  try {
    const { name, surname, idNumber, phone, password } = req.body;
    const existing = await pool.query('SELECT * FROM users WHERE "idNumber" = $1 OR phone = $2', [idNumber, phone]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: "ID or phone already registered" });
    }
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (name, surname, "idNumber", phone, password) VALUES ($1, $2, $3, $4, $5)',
      [name, surname, idNumber, phone, hashed]
    );
    res.json({ success: true, message: "User registered" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (result.rows.length === 0) return res.status(400).json({ error: "Invalid credentials" });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });
    const token = jwt.sign({ userId: user.id, phone: user.phone }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ success: true, token, user: { name: user.name, surname: user.surname, idNumber: user.idNumber, isAdmin: user.isAdmin } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { phone } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    await pool.query('DELETE FROM reset_tokens WHERE phone = $1', [phone]);
    const token = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 15 * 60 * 1000);
    await pool.query('INSERT INTO reset_tokens (phone, token, expires) VALUES ($1, $2, $3)', [phone, token, expires]);
    res.json({ success: true, message: "Reset token generated", token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const result = await pool.query('SELECT * FROM reset_tokens WHERE token = $1', [token]);
    if (result.rows.length === 0) return res.status(400).json({ error: "Invalid token" });
    const resetEntry = result.rows[0];
    if (new Date() > resetEntry.expires) {
      await pool.query('DELETE FROM reset_tokens WHERE token = $1', [token]);
      return res.status(400).json({ error: "Token expired" });
    }
    const userResult = await pool.query('SELECT * FROM users WHERE phone = $1', [resetEntry.phone]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: "User not found" });
    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE phone = $2', [hashed, resetEntry.phone]);
    await pool.query('DELETE FROM reset_tokens WHERE token = $1', [token]);
    res.json({ success: true, message: "Password reset successful" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/polls/active', async (req, res) => {
  try {
    const now = new Date();
    const result = await pool.query(
      'SELECT * FROM polls WHERE "startDate" <= $1 AND "endDate" >= $1 ORDER BY id DESC LIMIT 1',
      [now]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "No active poll" });
    res.json({ poll: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/vote', auth, async (req, res) => {
  try {
    const { pollId, choice } = req.body;
    const userId = req.user.userId;
    const pollResult = await pool.query('SELECT * FROM polls WHERE id = $1', [pollId]);
    if (pollResult.rows.length === 0) return res.status(404).json({ error: "Poll not found" });
    const poll = pollResult.rows[0];
    const now = new Date();
    if (now < poll.startDate || now > poll.endDate) return res.status(400).json({ error: "Poll not active" });
    const voteHash = crypto.createHash('sha256').update(process.env.VOTE_SALT + userId + pollId).digest('hex');
    const existing = await pool.query('SELECT * FROM anonymous_votes WHERE "voteHash" = $1', [voteHash]);
    if (existing.rows.length > 0) return res.status(400).json({ error: "Already voted" });
    await pool.query('INSERT INTO anonymous_votes ("voteHash", choice, "pollId", timestamp) VALUES ($1, $2, $3, $4)', [voteHash, choice, pollId, now]);
    if (choice === 'A') {
      await pool.query('UPDATE polls SET "votesA" = "votesA" + 1 WHERE id = $1', [pollId]);
    } else if (choice === 'B') {
      await pool.query('UPDATE polls SET "votesB" = "votesB" + 1 WHERE id = $1', [pollId]);
    } else {
      return res.status(400).json({ error: "Invalid choice" });
    }
    res.json({ success: true, message: "Vote recorded anonymously" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/polls', auth, adminAuth, async (req, res) => {
  try {
    const { question, optionA, optionB, startDate, endDate } = req.body;
    const result = await pool.query(
      'INSERT INTO polls (question, "optionA", "optionB", "startDate", "endDate") VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [question, optionA, optionB, new Date(startDate), new Date(endDate)]
    );
    res.json({ success: true, poll: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/polls', auth, adminAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM polls ORDER BY id DESC');
    res.json({ polls: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/polls/:id', auth, adminAuth, async (req, res) => {
  try {
    const pollId = req.params.id;
    await pool.query('DELETE FROM anonymous_votes WHERE "pollId" = $1', [pollId]);
    await pool.query('DELETE FROM polls WHERE id = $1', [pollId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/polls/:id/export', auth, adminAuth, async (req, res) => {
  try {
    const pollId = req.params.id;
    const result = await pool.query('SELECT * FROM polls WHERE id = $1', [pollId]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Poll not found" });
    const poll = result.rows[0];
    const csvRows = [
      ['Poll Question:', poll.question],
      ['Option A:', poll.optionA, `Votes: ${poll.votesA}`],
      ['Option B:', poll.optionB, `Votes: ${poll.votesB}`],
      ['Total Votes:', poll.votesA + poll.votesB],
      ['Export Date:', new Date().toISOString()]
    ];
    const csvContent = csvRows.map(row => row.join(',')).join('\n');
    res.setHeader('Content-Disposition', `attachment; filename=poll_${pollId}_totals.csv`);
    res.setHeader('Content-Type', 'text/csv');
    res.send(csvContent);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
