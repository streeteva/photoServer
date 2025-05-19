require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
//const users = [];

const SECRET_KEY = process.env.SECRET_KEY;
const db = require('./db');

const validateUserId = (userId) => {
  // 4-20 chars, letters, numbers, underscores only
  const userIdRegex = /^[a-zA-Z0-9_]{4,20}$/;
  return userIdRegex.test(userId);
};

const validatePassword = (password) => {
  // At least 8 chars, uppercase, lowercase, number, special char
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
  return passwordRegex.test(password);
};

// Enable CORS for your mobile app
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Server is up and running!');
});

// -------------------- Register Endpoint --------------------
app.post('/register', async (req, res) => {
  const { userId, password } = req.body;
  console.log('Attempting registration...')
  if (!userId || !password) {
    return res.status(400).json({ message: 'Missing userId or password' });
  }

  //const existingUser = users.find(user => user.userId === userId);
  const existingUser = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }

  if (!validateUserId(userId)) {
    return res.status(400).json({ message: 'userId must be 4-20 characters long, alphanumeric or underscore only' });
  }

  if (!validatePassword(password)) {
    return res.status(400).json({ 
      message: 'Password must be at least 8 characters long, with uppercase, lowercase, number, and special character'
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  //users.push({ userId, password: hashedPassword });
  db.prepare('INSERT INTO users (userId, password) VALUES (?, ?)').run(userId, hashedPassword);

  const token = jwt.sign({ userId }, SECRET_KEY, { expiresIn: '1h' });

  res.json({ message: 'Registration successful', token });
});

// -------------------- Login Endpoint --------------------
app.post('/login', async (req, res) => {
  const { userId, password } = req.body;

  if (!validateUserId(userId)) {
    return res.status(400).json({ message: 'Invalid userId format' });
  }

  //const user = users.find(user => user.userId === userId);
  const user = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);

  if (!user) {
    return res.status(400).json({ message: 'User not found' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ message: 'Incorrect password' });
  }

  const token = jwt.sign({ userId }, SECRET_KEY, { expiresIn: '7d' });
  res.json({ message: 'Login successful', token });
});

// -------------------- File Upload ------------------------
const uploadsDir = path.join(__dirname, 'uploads');
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);

const logFilePath = path.join(logsDir, 'upload_log.txt');

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const userId = req.body.userId || 'anonymous';
    const timestamp = Date.now();
    const row1Label = req.body.row1Selection || 'row1_unselected';
    const row2Label = req.body.row2Selection || 'row2_unselected';
    const ext = path.extname(file.originalname);
    file.row1Label = row1Label;
    file.row2Label = row2Label;
    file.userId = userId;
    cb(null, `${row1Label}_${row2Label}_${userId}_${timestamp}${ext}`);
  }
});

const upload = multer({ storage });

app.post('/uploads', upload.array('photos[]', 5), (req, res) => {
  if (!req.files || req.files.length === 0 || !req.body.userId) {
    return res.status(400).json({ message: 'Missing userId or photos' });
  }

  const logEntries = req.files.map(file => `[${new Date().toISOString()}] UserID: ${file.userId}, Label1: ${file.row1Label}, Label2: ${file.row2Label} , Filename: ${file.filename}\n`);
  fs.appendFile(logFilePath, logEntries.join(''), err => { if (err) console.error('Failed to write log:', err); });

  res.json({ message: 'Upload successful', files: req.files.map(file => file.filename) });
});

// Error handling for multer
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: err.message });
  }
  next(err);
});

app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));
