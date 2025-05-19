const fs = require('fs');
const path = require('path');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir);
}

const Database = require('better-sqlite3');
const db = new Database(path.join(dataDir, 'users.db'));

// Create users table if it doesn't exist
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    userId TEXT PRIMARY KEY,
    password TEXT NOT NULL
  )
`).run();

module.exports = db;
