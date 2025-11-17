require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const archiver = require('archiver');
const { Storage } = require('@google-cloud/storage');
const bodyParser = require('body-parser');

// --- 2FA deps ---
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

//const db = require('./db');
global.db = null;
const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 8080;
const SECRET_KEY = process.env.SECRET_KEY || 'dev_only_change_me';
const sessionSecret = process.env.SESSION_SECRET || 'fallback_secret_for_dev_only';
const TOTP_ISSUER = process.env.TOTP_ISSUER || 'CatheUpload';

// ---------------- Google Cloud Storage ----------------
const storage = new Storage();
const bucketName = process.env.GCS_BUCKET || 'cathe-uploads';
const localDbPath = './users.db';
const bucket = storage.bucket(bucketName);

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Missing or invalid Authorization header' });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

// ---------- Database Init & Startup ----------
const { loadDatabase,saveDatabase } = require('./dbManager');


// -----------Helper functions--------------------
function getUserSecurity(userId) {
  return db.prepare('SELECT * FROM user_security WHERE userId = ?').get(userId);
}

async function setUserSecurityState(userId, fields) {
  const cur = getUserSecurity(userId) || {};
  const upd = { ...cur, userId, ...fields };
  db.prepare(`
    INSERT OR REPLACE INTO user_security
    (userId, role, failedLoginAttempts, isLocked, forceChangePassword, passwordChangedAt, twofaEnabled, twofaSecret, twofaFailedAttempts, twofaLocked, twofaLockedUntil)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    upd.userId,
    upd.role ?? cur.role ?? 'user',
    upd.failedLoginAttempts ?? cur.failedLoginAttempts ?? 0,
    upd.isLocked ?? cur.isLocked ?? 0,
    upd.forceChangePassword ?? cur.forceChangePassword ?? 0,
    upd.passwordChangedAt ?? cur.passwordChangedAt ?? new Date().toISOString(),
    upd.twofaEnabled ?? cur.twofaEnabled ?? 0,
    upd.twofaSecret ?? cur.twofaSecret ?? null,
    upd.twofaFailedAttempts ?? cur.twofaFailedAttempts ?? 0,
    upd.twofaLocked ?? cur.twofaLocked ?? 0,
    upd.twofaLockedUntil ?? cur.twofaLockedUntil ?? null
  );
    await saveDatabase();
}

function ensureUsersTableHasRole() {
  const cols = db.prepare("PRAGMA table_info(users)").all();
  const hasRole = cols.some(c => c.name === 'role');
  if (!hasRole) {
    db.prepare("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'").run();
    console.log("✅ Added missing 'role' column to users table.");
  }
}

function addPasswordHistory(userId, hashedPassword) {
  db.prepare(`INSERT INTO password_history (userId, password, changedAt) VALUES (?, ?, ?)`)
    .run(userId, hashedPassword, new Date().toISOString());

  const rows = db.prepare(`SELECT rowid FROM password_history WHERE userId = ? ORDER BY changedAt DESC`).all(userId);
  if (rows.length > 5) {
    const oldIds = rows.slice(5).map(r => r.rowid);
    db.prepare(`DELETE FROM password_history WHERE rowid IN (${oldIds.map(() => '?').join(',')})`).run(...oldIds);
  }
}

function isPasswordInHistory(userId, newPassword) {
  const past = db.prepare(`SELECT password FROM password_history WHERE userId = ?`).all(userId);
  return past.some(p => bcrypt.compareSync(newPassword, p.password));
}


// ------------------Main DB init---------------------------
async function initDatabase() {
  // 1️⃣ Load existing DB (local/cloud)
  global.db = await loadDatabase();
  //console.log('Users in DB:', db.prepare('SELECT userId FROM users').all());

  // 2️⃣ Create tables if missing
  db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      userId TEXT PRIMARY KEY,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user'
    )
  `).run();
  const users = db.prepare('SELECT userId FROM users').all();
  console.log('Users in DB:', users);
  ensureUsersTableHasRole();

  db.prepare(`
    CREATE TABLE IF NOT EXISTS user_security (
      userId TEXT PRIMARY KEY,
      role TEXT DEFAULT 'user',
      failedLoginAttempts INTEGER DEFAULT 0,
      isLocked INTEGER DEFAULT 0,
      forceChangePassword INTEGER DEFAULT 0,
      passwordChangedAt TEXT,
      twofaEnabled INTEGER DEFAULT 0,
      twofaSecret TEXT,
      twofaFailedAttempts INTEGER DEFAULT 0,
      twofaLocked INTEGER DEFAULT 0,
      twofaLockedUntil TEXT
    )
  `).run();

  db.prepare(`
    CREATE TABLE IF NOT EXISTS password_history (
      userId TEXT,
      password TEXT,
      changedAt TEXT
    )
  `).run();
  let hashedPassword = null;
  // 3️⃣ Seed default admin if missing
  const adminUser = db.prepare('SELECT * FROM users WHERE userId = ?').get('admin');
  if (!adminUser) {
    const hashedPassword = bcrypt.hashSync('Admin@12345', 12);
    db.prepare('INSERT INTO users (userId, password, role) VALUES (?, ?, ?)').run('admin', hashedPassword, 'admin');
    //await saveDatabase();
    console.log('✅ Default admin created in users table.');
  }

  const adminSec = getUserSecurity('admin');
  if (!adminSec) {
    await setUserSecurityState('admin', {
      role: 'admin',
      failedLoginAttempts: 0,
      isLocked: 0,
      forceChangePassword: 1,
      twofaEnabled: 0
    });
    addPasswordHistory('admin', adminUser?.password || hashedPassword);
    console.log('✅ Admin user_security record created.');
  }

  // 4️⃣ Ensure all existing users have security & password history
  const existingUsers = db.prepare('SELECT userId, role, password FROM users').all();
  for (const u of existingUsers) {
    if (!getUserSecurity(u.userId)) {
      await setUserSecurityState(u.userId, {
        role: u.role || 'user',
        failedLoginAttempts: 0,
        isLocked: 0,
        forceChangePassword: 0
      });
      addPasswordHistory(u.userId, u.password);
    }
  }

  console.log('✅ Database initialization complete.');
}


// ---------- Startup ----------
(async () => {
  await initDatabase();       // create tables & seed admin
})();

// ---------------- Middleware ----------------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ---------------- Local Directories ----------------
const uploadsDir = path.join(__dirname, 'uploads');
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);
const logFilePath = path.join(logsDir, 'upload_log.txt');

// ---------------- Helpers ----------------
const escapeHtml = (str = '') =>
  String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

// ---------------- Session ----------------
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));


// ---------------- Password Policy ----------------
const validateUserId = (userId) => /^[a-zA-Z0-9_]{4,20}$/.test(userId);

const validatePassword = (password, role = 'user', userId = '') => {
  if (!password) return false;
  if (password.toLowerCase() === String(userId).toLowerCase()) return false; // not same as userId
  const minLen = role === 'admin' ? 15 : 12;
  if (password.length < minLen) return false;
  let cats = 0;
  if (/[A-Z]/.test(password)) cats++;
  if (/[a-z]/.test(password)) cats++;
  if (/[0-9]/.test(password)) cats++;
  if (/[^A-Za-z0-9]/.test(password)) cats++;
  return cats >= 2;
};


// ---------------- Auth Middleware ----------------
function requireLogin(req, res, next) {
  if (req.session?.userId) return next();
  res.redirect('/mainLogin');
}

function requireAdmin(req, res, next) {
  const sec = getUserSecurity(req.session.userId);
  if (sec?.role === 'admin') return next();
  return res.status(403).send('Admin access required.');
}

function requirePasswordChange(req, res, next) {
  const sec = getUserSecurity(req.session.userId);
  if (sec?.forceChangePassword) return res.redirect('/change-password');
  next();
}

// Helper to see if a 2FA challenge is pending
const isPending2FA = (req) => Boolean(req.session?.pending2FAUserId);

// ===================================================================
//                   ADMIN LOGIN UI + 2FA FLOW
// ===================================================================
app.get('/mainLogin', (req, res) => {
  res.send(`
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
  `);
});

app.post('/mainLogin', async (req, res) => {
  const { userId, password } = req.body;
  if (!validateUserId(userId)) return res.status(400).send('Invalid userId format.');

  const user = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  if (!user) return res.status(401).send('User not found.');

  const sec = getUserSecurity(userId);
  if (sec?.isLocked) return res.status(423).send('Account locked. Contact admin.');

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    const newFailures = (sec?.failedLoginAttempts || 0) + 1;
    const lock = newFailures >= 5 ? 1 : 0;
    await setUserSecurityState(userId, { failedLoginAttempts: newFailures, isLocked: lock });
    return res.status(401).send(lock ? 'Account locked. Contact admin.' : 'Invalid credentials.');
  }

  // password ok -> clear failures
  await setUserSecurityState(userId, { failedLoginAttempts: 0 });

  // If password change required -> send change form BEFORE 2FA
  if (sec?.forceChangePassword) {
    req.session.pendingPwChangeUserId = userId; // track for form
    return res.redirect('/change-password');
  }

  // // If admin + 2FA enabled -> stage 2FA challenge
  // if ((sec?.role || user.role) === 'admin' && sec?.twofaEnabled) {
  //   req.session.pending2FAUserId = userId;
  //   req.session.pending2FARole = sec.role || user.role || 'admin';
  //   return res.redirect('/admin-2fa');
  // }

    // Check role from user or sec (fallback)
  const role = sec?.role || user.role || 'user';

  // AUTO ENABLE 2FA for admin if not enabled
  if (role === 'admin') {
    // FIRST TIME 2FA setup: not enabled yet
    if (!sec?.twofaEnabled) {
      // Generate temp secret for setup (store in session only)
      const tempSecret = speakeasy.generateSecret({ length: 20, name: `${TOTP_ISSUER}:${userId}`, issuer: TOTP_ISSUER });
      req.session.temp2FASecret = tempSecret.base32;
      req.session.temp2FAUserId = userId;

      // Generate QR code data URL and pass it via redirect or render page
      const qrCodeDataUrl = await QRCode.toDataURL(tempSecret.otpauth_url);
      req.session.temp2FAQrCodeDataUrl = qrCodeDataUrl;

      return res.redirect('/admin-2fa-setup-first-time');
    }

    // Set session pending 2FA and redirect to 2FA challenge
    req.session.pending2FAUserId = userId;
    req.session.pending2FARole = role;
    return res.redirect('/admin-2fa');
  }

  // else login direct
  req.session.regenerate(err => {
    if (err) return res.status(500).send('Session error.');
    req.session.userId = userId;
    req.session.role = sec?.role || user.role || 'user';
    res.redirect('/dashboard');
  });
});

// --- Admin 2FA challenge ---
app.get('/admin-2fa', (req, res) => {
  if (!isPending2FA(req)) return res.redirect('/mainLogin');
  res.send(`
    <html><body>
      <h2>Two-Factor Authentication</h2>
      <p>Enter the 6-digit code from your authenticator app.</p>
      <form method="POST" action="/admin-2fa">
        <input type="text" name="token" pattern="\\d{6}" maxlength="6" required />
        <button type="submit">Verify</button>
      </form>
      <p><a href="/mainLogin">Cancel</a></p>
    </body></html>
  `);
});

app.post('/admin-2fa', async (req, res) => {
  if (!isPending2FA(req)) return res.redirect('/mainLogin');
  const { token } = req.body;
  const userId = req.session.pending2FAUserId;
  const sec = getUserSecurity(userId);
  if (!sec) return res.status(404).send('Security record missing.');

  if (sec.twofaLocked) return res.status(423).send('2FA locked. Contact another admin.');

  const verified = speakeasy.totp.verify({
    secret: sec.twofaSecret,
    encoding: 'base32',
    token,
    window: 1
  });

  if (!verified) {
    const attempts = (sec.twofaFailedAttempts || 0) + 1;
    const lock = attempts >= 5 ? 1 : 0;
    await setUserSecurityState(userId, {
      twofaFailedAttempts: attempts,
      twofaLocked: lock,
      twofaLockedUntil: lock ? new Date().toISOString() : sec.twofaLockedUntil
    });
    return res.status(401).send(lock ? 'Too many invalid codes. 2FA locked.' : 'Invalid code. <a href="/admin-2fa">Try again</a>');
  }

  // success -> reset counts & login
  await setUserSecurityState(userId, { twofaFailedAttempts: 0, twofaLocked: 0 });
  req.session.regenerate(err => {
    if (err) return res.status(500).send('Session error.');
    req.session.userId = userId;
    req.session.role = sec.role || 'admin';
    delete req.session.pending2FAUserId;
    delete req.session.pending2FARole;
    res.redirect('/dashboard');
  });
});


app.get('/admin-2fa-setup-first-time', (req, res) => {
  const userId = req.session.temp2FAUserId;
  const qrCodeDataUrl = req.session.temp2FAQrCodeDataUrl;
  const tempSecret = req.session.temp2FASecret;
  if (!userId || !tempSecret || !qrCodeDataUrl) {
    return res.redirect('/mainLogin');
  }

  res.send(`
    <html><body>
      <h1>Set up Two-Factor Authentication (First Time)</h1>
      <p>Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)</p>
      <img src="${qrCodeDataUrl}" alt="QR Code" />
      <p>Or enter this secret manually: <code>${tempSecret}</code></p>
      <form method="POST" action="/admin-2fa-setup-first-time">
        <label>Enter 6-digit code from your authenticator app:</label><br />
        <input type="text" name="token" pattern="\\d{6}" maxlength="6" required />
        <button type="submit">Verify & Enable 2FA</button>
      </form>
      <p><a href="/mainLogin">Cancel</a></p>
    </body></html>
  `);
});

app.post('/admin-2fa-setup-first-time', async (req, res) => {
  const userId = req.session.temp2FAUserId;
  const tempSecret = req.session.temp2FASecret;
  if (!userId || !tempSecret) {
    return res.status(400).send('No pending 2FA setup session.');
  }

  const { token } = req.body;

  const verified = speakeasy.totp.verify({
    secret: tempSecret,
    encoding: 'base32',
    token,
    window: 1,
  });

  if (!verified) {
    return res.status(401).send('Invalid token. <a href="/admin-2fa-setup-first-time">Try again</a>');
  }

  // Save 2FA secret and enable 2FA permanently in security state
  await setUserSecurityState(userId, {
    twofaSecret: tempSecret,
    twofaEnabled: 1,
    twofaFailedAttempts: 0,
    twofaLocked: 0,
  });

  // Clear temp session secrets
  delete req.session.temp2FASecret;
  delete req.session.temp2FAUserId;
  delete req.session.temp2FAQrCodeDataUrl;

  // Redirect to dashboard or force 2FA token input again
  // Here we can log them in directly since verified
  req.session.regenerate(err => {
    if (err) return res.status(500).send('Session error.');
    req.session.userId = userId;
    req.session.role = 'admin';
    res.redirect('/dashboard');
  });
});

// ===================================================================
//                   ADMIN PASSWORD CHANGE UI (forced)
// ===================================================================
app.get('/change-password', (req, res) => {
  const userId = req.session.pendingPwChangeUserId || req.session.userId || '';
  if (!userId) return res.redirect('/mainLogin');
  res.send(`
    <html><body>
      <h2>Change Password</h2>
      <form method="POST" action="/change-password">
        <input type="hidden" name="userId" value="${escapeHtml(userId)}" />
        <input type="password" name="newPassword" placeholder="New Password" required />
        <button type="submit">Change</button>
      </form>
    </body></html>`);
});

app.post('/change-password', async (req, res) => {
  const { userId, newPassword } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  const sec = getUserSecurity(userId);
  if (!user || !sec) return res.status(404).send('User not found.');

  if (!validatePassword(newPassword, sec.role, userId)) return res.status(400).send('Password does not meet policy.');
  if (await bcrypt.compare(newPassword, user.password)) return res.status(400).send('Password same as old.');
  if (isPasswordInHistory(userId, newPassword)) return res.status(400).send('Recently used password.');

  const hashed = await bcrypt.hash(newPassword, 12);
  db.prepare('UPDATE users SET password = ? WHERE userId = ?').run(hashed, userId);
  await saveDatabase();
  await setUserSecurityState(userId, { forceChangePassword: 0, passwordChangedAt: new Date().toISOString() });
  addPasswordHistory(userId, hashed);
  delete req.session.pendingPwChangeUserId;
  res.send('Password changed. <a href="/mainLogin">Login</a>');
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) res.status(500).send('Could not log out');
    else res.redirect('/mainLogin');
  });
});

// ===================================================================
//                   MOBILE / API: REGISTER & LOGIN
// ===================================================================
app.post('/register', async (req, res) => {
  const { userId, password, role = 'user' } = req.body;
  if (!userId || !password) return res.status(400).json({ message: 'Missing userId or password' });
  if (!validateUserId(userId)) return res.status(400).json({ message: 'Invalid userId format' });
  if (!validatePassword(password, role, userId)) return res.status(400).json({ message: 'Password does not meet policy.' });

  const existing = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  if (existing) return res.status(400).json({ message: 'User already exists' });

  const hashedPassword = await bcrypt.hash(password, 12);
  db.prepare('INSERT INTO users (userId, password, role) VALUES (?, ?, ?)').run(userId, hashedPassword, role);
  await saveDatabase();
  // Force first login change per policy (can disable if you don't want)
  await setUserSecurityState(userId, { role, failedLoginAttempts: 0, isLocked: 0, forceChangePassword: 1 });
  addPasswordHistory(userId, hashedPassword);

  const token = jwt.sign({ userId, role }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ message: 'Registration successful', token, role });
});

app.post('/login', async (req, res) => {
  const { userId, password } = req.body;
  if (!validateUserId(userId)) return res.status(400).json({ message: 'Invalid userId format' });

  const user = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  if (!user) return res.status(400).json({ message: 'User not found' });

  const sec = getUserSecurity(userId);
  if (!sec) return res.status(500).json({ message: 'Security record missing for user.' });
  if (sec.isLocked) return res.status(423).json({ message: 'Account locked.', locked: true });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    const newFailures = (sec.failedLoginAttempts || 0) + 1;
    const lock = newFailures >= 5 ? 1 : 0;
    await setUserSecurityState(userId, { failedLoginAttempts: newFailures, isLocked: lock });
    return res.status(401).json({ message: lock ? 'Account locked.' : 'Incorrect password.', attempts: newFailures, locked: !!lock });
  }

  await setUserSecurityState(userId, { failedLoginAttempts: 0 });

  const token = jwt.sign({ userId, role: sec.role }, SECRET_KEY, { expiresIn: '7d' });
  if (sec.forceChangePassword) {
    return res.json({ message: 'Password change required.', needPasswordChange: true, token, role: sec.role });
  }
  res.json({ message: 'Login successful', token, role: sec.role });
});

// -------------------- Mobile Change Password --------------------
app.post('/change-password-mobile', async (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Missing token' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const { userId } = decoded;
    const { newPassword } = req.body;

    const user = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
    const sec = getUserSecurity(userId);
    if (!user || !sec) return res.status(404).json({ message: 'User not found' });

    if (!validatePassword(newPassword, sec.role, userId)) return res.status(400).json({ message: 'Password does not meet policy.' });
    if (await bcrypt.compare(newPassword, user.password)) return res.status(400).json({ message: 'Password same as old.' });
    if (isPasswordInHistory(userId, newPassword)) return res.status(400).json({ message: 'Recently used password.' });

    const hashed = await bcrypt.hash(newPassword, 12);
    db.prepare('UPDATE users SET password = ? WHERE userId = ?').run(hashed, userId);
    await saveDatabase();
    await setUserSecurityState(userId, { forceChangePassword: 0, passwordChangedAt: new Date().toISOString() });
    addPasswordHistory(userId, hashed);

    res.json({ success: true, message: 'Password changed successfully.' });
  } catch (err) {
    res.status(401).json({ message: 'Invalid or expired token', error: err.message });
  }
});


// ===================================================================
//                           FILE UPLOAD (NO AUTH YET)
// ===================================================================
const upload = multer({ dest: '/tmp/' });
app.post('/uploads',  authenticateJWT, upload.array('photos[]', 5), async (req, res) => {
  if (!req.files || req.files.length === 0 || !req.body.userId) {
    return res.status(400).json({ message: 'Missing userId or photos' });
  }

  const userId = req.user.userId || 'anonymous';
  const row1Label = req.body.row1Selection || 'row1_unselected';
  const row2Label = req.body.row2Selection || 'row2_unselected';
  const totalScore = req.body.totalScore || '0';

  const extraFields = ['pain', 'swelling', 'crust', 'redness', 'secretion'];
  const extraData = extraFields.map(f => `${f}: ${req.body[f] || 'N/A'}`).join(', ');

  const logEntries = [];
  try {
    for (const file of req.files) {
      const ext = path.extname(file.originalname);
      const filename = `${userId}_${row1Label}_${totalScore}_${row2Label}_${Date.now()}${ext}`;
      await bucket.upload(file.path, { destination: filename, metadata: { contentType: file.mimetype } });
      fs.unlinkSync(file.path);
      logEntries.push(`[${new Date().toLocaleString("sv-SE").replace(" ", "T")}] UserID: ${userId}, Infection: ${row1Label}, Score: ${totalScore}, ImageType: ${row2Label}, ${extraData}, Filename: ${filename}\n`);
    }

      const logText = logEntries.join('');
      const logGCSName = `logs/upload_log_${Date.now()}.txt`;
      await bucket.file(logGCSName).save(logText);

    res.json({ message: 'Upload successful to GCS', files: logEntries.length });
  } catch (err) {
    console.error('Upload failed:', err);
    res.status(500).json({ message: 'Upload failed', error: err.message });
  }
});

// ===================================================================
//                           ROLE MANAGEMENT
// ===================================================================
app.post('/set-role', requireLogin, requireAdmin, async (req, res) => {
  const { userId, role } = req.body;
  if (!['admin', 'user'].includes(role)) {
    return res.status(400).json({ message: 'Invalid role. Use admin or user.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  if (!user) return res.status(404).json({ message: 'User not found' });

  db.prepare('UPDATE users SET role = ? WHERE userId = ?').run(role, userId);
  await saveDatabase();
  await setUserSecurityState(userId, { role });

  if (req.session.userId === userId) req.session.role = role;

  res.json({ message: `Role for ${userId} updated to ${role}` });
});

// ===================================================================
//                           GALLERY
// ===================================================================
app.get('/gallery', requireLogin, requireAdmin, async (req, res) => {
  try {
    const [files] = await bucket.getFiles();
    const imageFiles = files.filter(f => /\.(jpg|jpeg|png|gif)$/i.test(f.name));

    const signedUrls = await Promise.all(imageFiles.map(file =>
      file.getSignedUrl({ version: 'v4', action: 'read', expires: Date.now() + 15 * 60 * 1000 })
          .then(([url]) => ({ name: file.name, url }))
    ));

    const html = `
      <html>
      <head>
        <title>Photo Gallery</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 20px; }
          .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
          .download-btn { background: #007BFF; color: white; padding: 10px 16px; border-radius: 6px; text-decoration: none; font-size: 14px; }
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
          ${signedUrls.map(file => `
            <div class="photo">
              <img src="${file.url}" alt="${escapeHtml(file.name)}" />
              <div class="filename">${escapeHtml(file.name)}</div>
              <a href="/download/${encodeURIComponent(file.name)}">Download</a>
            </div>
          `).join('')}
        </div>
      </body>
      </html>`;
    res.send(html);
  } catch (err) {
    console.error('Error loading gallery:', err);
    res.status(500).send('Error loading gallery.');
  }
});

// ===================================================================
//                   SINGLE / BULK DOWNLOADS
// ===================================================================
app.get('/download/:filename', requireLogin, requireAdmin, async (req, res) => {
  try {
    const file = bucket.file(req.params.filename);
    const [exists] = await file.exists();
    if (!exists) return res.status(404).send('File not found');

    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(req.params.filename)}"`);
    file.createReadStream().pipe(res);
  } catch (err) {
    console.error('Error downloading file:', err);
    res.status(500).send('Error downloading file.');
  }
});

app.get('/download-all', requireLogin, requireAdmin, async (req, res) => {
  try {
    const [files] = await bucket.getFiles();
    const imageFiles = files.filter(f => /\.(jpg|jpeg|png|gif)$/i.test(f.name));

    res.attachment('all_photos.zip');
    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);
    for (const file of imageFiles) archive.append(file.createReadStream(), { name: file.name });
    await archive.finalize();
  } catch (err) {
    console.error('Error zipping GCS files:', err);
    res.status(500).send('Failed to zip and download files.');
  }
});

// ===================================================================
//                           LOGS
// ===================================================================

// Download all combined logs as one file
app.get('/download-log', requireLogin, requireAdmin, async (req, res) => {
  try {
    const [files] = await bucket.getFiles({ prefix: 'logs/' });
    const logFiles = files.filter(f => f.name.endsWith('.txt'));

    if (!logFiles.length) {
      return res.status(404).send('No log files found.');
    }

    // Sort by filename (timestamp)
    logFiles.sort((a, b) => a.name.localeCompare(b.name));

    // Read and combine all log contents
    let combinedLogs = '';
    for (const file of logFiles) {
      const [content] = await file.download();
      combinedLogs += content.toString('utf8') + '\n';
    }

    // Send as downloadable text file
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="combined_upload_logs.txt"'
    );
    res.setHeader('Content-Type', 'text/plain');
    res.send(combinedLogs);
  } catch (err) {
    console.error('Error downloading combined logs:', err);
    res.status(500).send('Could not download log files.');
  }
});


// View all combined logs in browser
app.get('/view-log', requireLogin, requireAdmin, async (req, res) => {
  try {
    const [files] = await bucket.getFiles({ prefix: 'logs/' });
    const logFiles = files.filter(f => f.name.endsWith('.txt'));

    if (!logFiles.length) {
      return res.send('<html><body><h2>No logs found.</h2></body></html>');
    }

    // Sort by filename (timestamp)
    logFiles.sort((a, b) => a.name.localeCompare(b.name));

    // Combine all logs
    let combinedLogs = '';
    for (const file of logFiles) {
      const [content] = await file.download();
      combinedLogs += content.toString('utf8') + '\n';
    }

    // Display safely in browser
    res.send(`
      <html>
        <head>
          <title>Upload Logs</title>
          <style>
            body { font-family: monospace; background: #fafafa; color: #333; }
            pre { white-space: pre-wrap; word-wrap: break-word; }
          </style>
        </head>
        <body>
          <h1>Combined Upload Logs</h1>
          <pre>${escapeHtml(combinedLogs)}</pre>
        </body>
      </html>
    `);
  } catch (err) {
    console.error('Error reading combined logs from GCS:', err);
    res.status(500).send('Could not read log files.');
  }
});

// ===================================================================
//                           VIEW USERS
// ===================================================================
app.get('/view-users', requireLogin, requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.userId, COALESCE(us.role, u.role, 'user') AS role,
           us.twofaEnabled AS twofaEnabled
    FROM users u
    LEFT JOIN user_security us ON u.userId = us.userId
    ORDER BY u.userId
  `).all();

  const rows = users.map(u => `
    <tr>
      <td>${escapeHtml(u.userId)}</td>
      <td>${escapeHtml(u.role)}</td>
      <td>${u.twofaEnabled ? '✅' : ''}</td>
      <td>
        <form method="POST" action="/set-role" style="display:inline;">
          <input type="hidden" name="userId" value="${escapeHtml(u.userId)}" />
          <select name="role">
            <option value="user"${u.role === 'user' ? ' selected' : ''}>User</option>
            <option value="admin"${u.role === 'admin' ? ' selected' : ''}>Admin</option>
          </select>
          <button type="submit">Update</button>
        </form>
      </td>
      <td>
  ${u.role !== 'admin' ? `
    <form method="POST" action="/unlock-user" style="display:inline;">
      <input type="hidden" name="userId" value="${escapeHtml(u.userId)}" />
      <button type="submit">Unlock</button>
    </form>
  ` : ''}
</td>
    </tr>
  `).join('');

  res.send(`
    <html>
    <head>
      <title>Users</title>
      <style>
        table { border-collapse: collapse; width: 80%; margin: auto; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align:left; }
        th { background: #f0f0f0; }
      </style>
    </head>
    <body>
      <h1 style="text-align:center;">Registered Users</h1>
      <table>
        <tr><th>User ID</th><th>Role</th><th>2FA</th><th>Change Role</th></tr>
        ${rows}
      </table>
      <div style="text-align:center;margin-top:20px;">
        <a href="/dashboard">Back to Dashboard</a>
      </div>
    </body>
    </html>
  `);
});
// ===================================================================
//                          UNLOCK USERS
// ===================================================================
app.post('/unlock-user', requireLogin, requireAdmin, async (req, res) => {
  const { userId } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  if (!user) return res.status(404).json({ message: 'User not found' });
  await setUserSecurityState(userId, {
    isLocked: 0,
    failedLoginAttempts: 0,
    twofaLocked: 0,
    twofaFailedAttempts: 0,
    twofaLockedUntil: null
  });

  res.json({ message: `User ${userId} has been unlocked.` });
});
// ===================================================================
//                           DASHBOARD
// ===================================================================
app.get('/dashboard', requireLogin, requireAdmin, requirePasswordChange, (req, res) => {
  const userId = req.session.userId;
  const sec = getUserSecurity(userId);
  const twofaLink = sec?.twofaEnabled
    ? '<a class="btn" href="/admin-2fa-setup" target="_blank">🔐 2FA Settings</a>'
    : '<a class="btn" href="/admin-2fa-setup" target="_blank">🔐 Enable 2FA</a>';
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Dashboard</title>
      <style>
        body { font-family: Arial; padding: 40px; background: #f4f4f4; text-align: center; }
        .btn { display: block; width: 250px; margin: 10px auto; padding: 12px; background-color: #007BFF; color: white; text-decoration: none; font-size: 16px; border-radius: 8px; }
        .btn:hover { background-color: #0056b3; }
      </style>
    </head>
    <body>
      <h1>Admin Dashboard</h1>

      <a class="btn" href="/gallery" target="_blank">📷 View Uploaded Photos</a>
      <a class="btn" href="/view-users" target="_blank">👥 View Users & Roles</a>
      <a class="btn" href="/download-log">⬇️ Download Log File</a>
      <a class="btn" href="/view-log" target="_blank">📄 View Log File</a>
      <a class="btn" href="/logout">Logout</a>
    </body>
    </html>
  `);
});

// ===================================================================
//                           ROOT
// ===================================================================
app.get('/', (req, res) => res.send('Server is up and running!'));
// Save DB on shutdown
  process.on('SIGTERM', async () => {
    console.log('SIGTERM received, saving DB...');
    await saveDatabase();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    console.log('SIGINT received, saving DB...');
    await saveDatabase();
    process.exit(0);
  });

// ===================================================================
//                           START SERVER
// ===================================================================
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
