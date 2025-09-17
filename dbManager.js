const fs = require('fs');
const path = require('path');
const os = require('os');
const { Storage } = require('@google-cloud/storage');

const storage = new Storage();
const bucketName = process.env.GCS_BUCKET || 'cathe-uploads';
const bucket = storage.bucket(bucketName);

// Always use a temp path inside container (ephemeral, safe to overwrite)
const localDbPath = path.join(os.tmpdir(), 'users.db');
const gcsDbPath = 'backups/users.db'; // main DB location in GCS

// --- Load DB from GCS (always fetch latest) ---
async function loadDatabase() {
  const file = bucket.file(gcsDbPath);
  const [exists] = await file.exists();

  if (exists) {
    await file.download({ destination: localDbPath });
    console.log(`✅ DB loaded from GCS: ${gcsDbPath}`);
  } else {
    console.log('⚠️ No DB found in GCS, creating new empty one...');
    fs.writeFileSync(localDbPath, '');
    await saveDatabase(); // upload empty DB to GCS
  }

  return localDbPath; // return local path for app to use
}

// --- Save DB to GCS (overwrite main copy + keep backups) ---
async function saveDatabase() {
  if (!fs.existsSync(localDbPath)) {
    console.error('❌ No local DB file to save.');
    return;
  }

  // Upload main DB
  await bucket.upload(localDbPath, { destination: gcsDbPath });
  console.log(`✅ DB saved to GCS: ${gcsDbPath}`);

  // Also store a timestamped backup
  const backupName = `backups/users_${Date.now()}.db`;
  await bucket.upload(localDbPath, { destination: backupName });
  console.log(`📦 Backup created: ${backupName}`);

  // Keep only latest 5 backups
  const [backups] = await bucket.getFiles({ prefix: 'backups/' });
  if (backups.length > 5) {
    const oldBackups = backups
      .sort((a, b) => a.name.localeCompare(b.name))
      .slice(0, backups.length - 5);
    for (const f of oldBackups) {
      await f.delete();
      console.log(`🗑️ Deleted old backup: ${f.name}`);
    }
  }
}

module.exports = { loadDatabase, saveDatabase, localDbPath };
