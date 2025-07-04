require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const db = require('./db');

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const sessionSecret = process.env.SESSION_SECRET || 'fallback_secret_for_dev_only';

const session = require('express-session');

app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

// Enable CORS for your mobile app
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Validation functions
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

// Hardcoded login
const HARD_CODED_USER = 'admin';
const HARD_CODED_PASS = 'password123';

function requireLogin(req, res, next) {
  if (req.session.user === HARD_CODED_USER) {
    next();
  } else {
    res.redirect('/mainLogin');
  }
}

// Create necessary folders
const uploadsDir = path.join(__dirname, 'uploads');
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);
const logFilePath = path.join(logsDir, 'upload_log.txt');

// Login page
app.get('/mainLogin', (req, res) => {
  const html = `
    <html>
    <head><title>Login</title></head>
    <body>
      <h2>Login</h2>
      <form method="POST" action="/mainLogin">
        <input type="text" name="userId" placeholder="User ID" required />
        <input type="password" name="password" placeholder="Password" required />
        <button type="submit">Login</button>
      </form>
    </body>
    </html>
  `;
  res.send(html);
});

// Handle login
app.post('/mainLogin', (req, res) => {
  const { userId, password } = req.body;

  if (userId === HARD_CODED_USER && password === HARD_CODED_PASS) {
    req.session.user = userId;
    res.redirect('/dashboard');
  } else {
    res.status(401).send('Invalid credentials. <a href="/mainLogin">Try again</a>');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) res.status(500).send('Could not log out');
    else res.redirect('/mainLogin');
  });
});

// -------------------- Register Endpoint --------------------
app.post('/register', async (req, res) => {
  const { userId, password } = req.body;
  console.log('Attempting registration...')
  if (!userId || !password) {
    return res.status(400).json({ message: 'Missing userId or password' });
  }

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

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const userId = req.body.userId || 'anonymous';
    const timestamp = Date.now();
    const row1Label = req.body.row1Selection || 'row1_unselected';
    const row2Label = req.body.row2Selection || 'row2_unselected';
    const totalScore = req.body.totalScore;
    // Extract symptom labels from body (those extra checkboxes)
    const extraFields = ['pain', 'swelling', 'crust', 'redness', 'secretion'];
    const extraData = extraFields.map(field => `${field.charAt(0).toUpperCase() + field.slice(1)}: ${req.body[field] || 'N/A'}`).join(', ');
    const ext = path.extname(file.originalname);
    file.row1Label = row1Label;
    file.row2Label = row2Label;
    file.userId = userId;
    file.totalScore = totalScore;
    file.extraData = extraData
    cb(null, `${userId}_${row1Label}_${totalScore}_${row2Label}_${timestamp}${ext}`);
  }
});

const upload = multer({ storage });

app.post('/uploads', upload.array('photos[]', 5), (req, res) => {
  if (!req.files || req.files.length === 0 || !req.body.userId) {
    return res.status(400).json({ message: 'Missing userId or photos' });
  }

  const logEntries = req.files.map(file => {
    const timestamp = new Date().toISOString();
    return `[${timestamp}] UserID: ${file.userId}, Infection: ${file.row1Label}, Score: ${file.totalScore}, ImageType: ${file.row2Label}, ${file.extraData}, Filename: ${file.filename}\n`;
  });
  fs.appendFile(logFilePath, logEntries.join(''), err => { if (err) console.error('Failed to write log:', err); });

  res.json({ message: 'Upload successful', files: req.files.map(file => file.filename) });
});


// ---------- Gallery Route ----------
app.get('/gallery', requireLogin,(req, res) => {
  fs.readdir(uploadsDir, (err, files) => {
    if (err) return res.status(500).send('Unable to load images');

    const imageFiles = files.filter(file => /\.(jpg|jpeg|png|gif)$/i.test(file));

    const html = `
      <html>
      <head>
        <title>Photo Gallery</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 20px; }
            .top-bar {
              display: flex;
              justify-content: space-between;
              align-items: center;
              margin-bottom: 20px;
            }
          .download-btn {
            background: #007BFF;
            color: white;
            padding: 10px 16px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 14px;
          }
          .gallery { display: flex; flex-wrap: wrap; gap: 16px; }
          .photo { border: 1px solid #ccc; padding: 8px; width: 200px; }
          img { max-width: 100%; height: auto; display: block; }
          .filename { margin-top: 8px; font-size: 14px; word-break: break-all; }
          a { text-decoration: none; display: block; margin-top: 4px; text-align: center; color: #007BFF; }
        </style>
      </head>
      <body>
            <div class="top-bar">
              <h1>Uploaded Photos</h1>
              <a class="download-btn" href="/download-all">⬇ Download All Photos</a>
            </div>
          <div class="gallery">
          ${imageFiles.map(file => `
            <div class="photo">
              <img src="/uploads/${file}" alt="${file}" />
              <div class="filename">${file}</div>
              <a href="/uploads/${file}" download>Download</a>
            </div>
          `).join('')}
          </div>
      </body>
      </html>
    `;

    res.send(html);
  });
});

// ---------- Download all photos ----------
const archiver = require('archiver');

app.get('/download-all',requireLogin, (req, res) => {
  const archive = archiver('zip', { zlib: { level: 9 } });

  res.attachment('all_photos.zip');
  archive.pipe(res);

  fs.readdir(uploadsDir, (err, files) => {
    if (err) {
      console.error('Error reading uploads directory:', err);
      return res.status(500).send('Could not read uploads directory');
    }

    files.forEach(file => {
      const filePath = path.join(uploadsDir, file);
      archive.file(filePath, { name: file });
    });

    archive.finalize();
  });
});


// ---------- View Users ----------
app.get('/view-users', requireLogin,(req, res) => {
  const users = db.prepare('SELECT userId FROM users').all();
  const rows = users.map(user => `<tr><td>${user.userId}</td></tr>`).join('');

  res.send(`
    <html>
    <head>
      <title>Users</title>
      <style>
        table { border-collapse: collapse; width: 50%; margin: auto; }
        th, td { border: 1px solid #ccc; padding: 8px; }
      </style>
    </head>
    <body>
      <h1 style="text-align:center;">Registered Users</h1>
      <table><tr><th>User ID</th></tr>${rows}</table>
    </body>
    </html>
  `);
});

// ---------- Log Routes ----------
app.get('/download-log',requireLogin, (req, res) => {
  if (fs.existsSync(logFilePath)) {
    res.download(logFilePath, 'upload_log.txt');
  } else {
    res.status(404).send('Log file not found.');
  }
});

app.get('/view-log', (req, res) => {
  fs.readFile(logFilePath, 'utf-8', (err, data) => {
    if (err) return res.status(500).send('Could not read log file.');
    res.send(`
      <html>
      <head><title>Upload Log</title></head>
      <body><h1>Upload Log</h1><pre>${data}</pre></body>
      </html>
    `);
  });
});


// ---------- Dashboard ----------
app.get('/dashboard', requireLogin, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Dashboard</title>
      <style>
        body { font-family: Arial; padding: 40px; background: #f4f4f4; text-align: center; }
        .btn {
          display: block;
          width: 250px;
          margin: 10px auto;
          padding: 12px;
          background-color: #007BFF;
          color: white;
          text-decoration: none;
          font-size: 16px;
          border-radius: 8px;
        }
        .btn:hover { background-color: #0056b3; }
      </style>
    </head>
    <body>
      <h1>Admin Dashboard</h1>
      <a class="btn" href="/gallery" target="_blank">📷 View Uploaded Photos</a>
      <a class="btn" href="/view-users" target="_blank">👥 View Users</a>
      <a class="btn" href="/download-log">⬇️ Download Log File</a>
      <a class="btn" href="/view-log" target="_blank">📄 View Log File</a>
    </body>
    </html>
  `);
});

// ---------- Error Handler ----------
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: err.message });
  }
  next(err);
});

// ---------- Start Server ----------
app.get('/', (req, res) => {
  res.send('Server is up and running!');
});
app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));
