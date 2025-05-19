const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Enable CORS for your mobile app
app.use(cors());

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const userId = req.body.userId || 'anonymous';
    const timestamp = Date.now();
    const ext = path.extname(file.originalname);
    cb(null, `${userId}_${timestamp}${ext}`);
  }
});
const upload = multer({ storage });

// Upload endpoint
app.post('/upload', upload.single('photo'), (req, res) => {
  const userId = req.body.userId;
  if (!req.file || !userId) {
    return res.status(400).json({ message: 'Missing userId or photo' });
  }

  console.log(`Received upload from user: ${userId}`);
  res.json({ message: 'Upload successful', file: req.file.filename });
});

// Optional: serve uploaded files
app.use('/uploads', express.static('uploads'));

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
