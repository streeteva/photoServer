const Database = require('better-sqlite3'); // or sqlite3
const fs = require('fs');
const { Storage } = require('@google-cloud/storage');

const storage = new Storage();
const bucketName = process.env.GCS_BUCKET || 'cathe-uploads';
const bucket = storage.bucket(bucketName);
const localDbPath = './users.db';

let db;

async function loadDatabase() {
  // 1️⃣ Download DB from GCS if exists
  const [files] = await bucket.getFiles({ prefix: 'backups/users.db' });
  if (files.length) {
    await files[0].download({ destination: localDbPath });
    console.log('✅ DB downloaded from GCS');
  } else {
    console.log('⚠️ No backup DB found on GCS, using local DB');
  }

  // 2️⃣ Load into memory
  db = new Database(localDbPath);
  return db;
}

async function saveDatabase() {
  if (!db) return;
  //db.close(); // better-sqlite3 requires closing before uploading
  await bucket.upload(localDbPath, { destination: 'backups/users.db' });
  console.log('✅ DB saved to GCS');
}

function getDb() {
  if (!db) throw new Error('DB not loaded yet. Call loadDatabase first.');
  return db;
}

module.exports = { loadDatabase, getDb, saveDatabase };
