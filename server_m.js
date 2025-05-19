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

// Accept an array of files from the 'photos[]' field
const upload = multer({ storage });

// Handle multiple image uploads with 'photos[]'
app.post('/uploads', upload.array('photos[]', 5), (req, res) => {  // Max 5 files per request
  if (!req.files || req.files.length === 0 || !req.body.userId) {
    return res.status(400).json({ message: 'Missing userId or photos' });
  }

  console.log(`Received upload from user: ${req.body.userId}`);
  console.log('Uploaded files:', req.files);

  // Send response with filenames of uploaded files
  res.json({
    message: 'Upload successful',
    files: req.files.map(file => file.filename),
  });
});

// Optional: serve uploaded files
app.use('/uploads', express.static('uploads'));

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
