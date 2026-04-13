// ===============================
// 🇿🇦 MZANSIVOICE - COMPLETE BACKEND
// ===============================

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// -----------------------------
// Database connection
// -----------------------------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// -----------------------------
// Models
// -----------------------------
const User = mongoose.model('User', {
  name: String,
  surname: String,
  idNumber: { type: String, unique: true },
  phone: { type: String, unique: true },
  password: String,
  isAdmin: { type: Boolean, default: false }
});

const Poll = mongoose.model('Poll', {
  question: String,
  optionA: String,
  optionB: String,
  votesA: { type: Number, default: 0 },
  votesB: { type: Number, default: 0 },
  startDate: Date,
  endDate: Date
});

const AnonymousVote = mongoose.model('AnonymousVote', {
  voteHash: { type: String, unique: true },
  choice: String,
  pollId: String,
  timestamp: Date
});

const ResetToken = mongoose.model('ResetToken', {
  phone: String,
  token: String,
  expires: Date
});

// -----------------------------
// Middleware
// -----------------------------
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
  const user = await User.findById(req.user.userId);
  if (!user || !user.isAdmin) return res.status(403).json({ error: "Admin access required" });
  next();
}

// -----------------------------
// Auth routes
// -----------------------------
app.post('/api/register', async (req, res) => {
  try {
    const { name, surname, idNumber, phone, password } = req.body;
    const existing = await User.findOne({ $or: [{ idNumber }, { phone }] });
    if (existing) return res.status(400).json({ error: "ID or phone already registered" });
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ name, surname, idNumber, phone, password: hashed });
    await user.save();
    res.json({ success: true, message: "User registered" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const user = await User.findOne({ phone });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });
    const token = jwt.sign({ userId: user._id, phone: user.phone }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ success: true, token, user: { name: user.name, surname: user.surname, idNumber: user.idNumber, isAdmin: user.isAdmin } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { phone } = req.body;
    const user = await User.findOne({ phone });
    if (!user) return res.status(404).json({ error: "User not found" });
    await ResetToken.deleteMany({ phone });
    const token = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 15 * 60 * 1000);
    await new ResetToken({ phone, token, expires }).save();
    res.json({ success: true, message: "Reset token generated", token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const resetEntry = await ResetToken.findOne({ token });
    if (!resetEntry) return res.status(400).json({ error: "Invalid token" });
    if (new Date() > resetEntry.expires) {
      await ResetToken.deleteOne({ token });
      return res.status(400).json({ error: "Token expired" });
    }
    const user = await User.findOne({ phone: resetEntry.phone });
    if (!user) return res.status(404).json({ error: "User not found" });
    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;
    await user.save();
    await ResetToken.deleteOne({ token });
    res.json({ success: true, message: "Password reset successful" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -----------------------------
// Poll & voting routes
// -----------------------------
app.get('/api/polls/active', async (req, res) => {
  try {
    const now = new Date();
    const poll = await Poll.findOne({ startDate: { $lte: now }, endDate: { $gte: now } });
    if (!poll) return res.status(404).json({ error: "No active poll" });
    res.json({ poll });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/vote', auth, async (req, res) => {
  try {
    const { pollId, choice } = req.body;
    const userId = req.user.userId;
    const poll = await Poll.findById(pollId);
    if (!poll) return res.status(404).json({ error: "Poll not found" });
    const now = new Date();
    if (now < poll.startDate || now > poll.endDate) return res.status(400).json({ error: "Poll not active" });
    const voteHash = crypto.createHash('sha256').update(process.env.VOTE_SALT + userId + pollId).digest('hex');
    const existing = await AnonymousVote.findOne({ voteHash });
    if (existing) return res.status(400).json({ error: "Already voted" });
    await new AnonymousVote({ voteHash, choice, pollId, timestamp: now }).save();
    if (choice === 'A') poll.votesA += 1;
    else if (choice === 'B') poll.votesB += 1;
    else return res.status(400).json({ error: "Invalid choice" });
    await poll.save();
    res.json({ success: true, message: "Vote recorded anonymously" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -----------------------------
// Admin routes
// -----------------------------
app.post('/api/admin/polls', auth, adminAuth, async (req, res) => {
  try {
    const { question, optionA, optionB, startDate, endDate } = req.body;
    const poll = new Poll({ question, optionA, optionB, startDate: new Date(startDate), endDate: new Date(endDate) });
    await poll.save();
    res.json({ success: true, poll });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/polls', auth, adminAuth, async (req, res) => {
  try {
    const polls = await Poll.find().sort({ createdAt: -1 });
    res.json({ polls });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/polls/:id', auth, adminAuth, async (req, res) => {
  try {
    await Poll.findByIdAndDelete(req.params.id);
    await AnonymousVote.deleteMany({ pollId: req.params.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/polls/:id/export', auth, adminAuth, async (req, res) => {
  try {
    const poll = await Poll.findById(req.params.id);
    if (!poll) return res.status(404).json({ error: "Poll not found" });
    const csvRows = [
      ['Poll Question:', poll.question],
      ['Option A:', poll.optionA, `Votes: ${poll.votesA}`],
      ['Option B:', poll.optionB, `Votes: ${poll.votesB}`],
      ['Total Votes:', poll.votesA + poll.votesB],
      ['Export Date:', new Date().toISOString()]
    ];
    const csvContent = csvRows.map(row => row.join(',')).join('\n');
    res.setHeader('Content-Disposition', `attachment; filename=poll_${poll._id}_totals.csv`);
    res.setHeader('Content-Type', 'text/csv');
    res.send(csvContent);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -----------------------------
// Start server
// -----------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
