// dbManager.js
const { Storage } = require('@google-cloud/storage');
const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const storage = new Storage();
const bucketName = process.env.DB_BUCKET || 'cathe-uploads';
const dbFile = path.join(__dirname, 'users.db');
let db;

// Download DB file from GCS bucket
async function loadDatabase() {
  const file = storage.bucket(bucketName).file('users.db');
  const [exists] = await file.exists();

  if (exists) {
    await file.download({ destination: dbFile });
    console.log('✅ users.db downloaded from Cloud Storage');
  } else {
    console.log('⚠️ No users.db found in bucket, starting fresh.');
  }

  db = new Database(dbFile);
  createUsersTable();
}

// Create table if missing
function createUsersTable() {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT
    )
  `).run();
}

// Save DB file back to Cloud Storage
async function saveDatabase() {
  await storage.bucket(bucketName).upload(dbFile, {
    destination: 'users.db',
    metadata: { cacheControl: 'no-cache' },
  });
  console.log('✅ users.db uploaded to Cloud Storage');
}

// Expose functions
module.exports = {
  loadDatabase,
  saveDatabase,
  getDB: () => db,
};
