# 📷 Photo Upload Server

This is a Node.js Express server for uploading, viewing, and downloading images. It supports user registration and login (with JWT), stores credentials securely in a SQLite database, and logs upload actions to a log file.

---

## 🚀 Features

- ✅ User registration and login with JWT authentication
- ✅ Passwords hashed using bcrypt
- ✅ Upload up to 5 photos per request using multer
- ✅ Label each photo with custom selections and userId
- ✅ View uploaded photos in a gallery
- ✅ Download individual photos or all photos as a ZIP file
- ✅ View and download log file of all uploads
- ✅ Stores user data in SQLite `.db` file

---

## 📦 Tech Stack

- Node.js
- Express
- Multer (for file upload)
- JWT (authentication)
- Bcrypt (password hashing)
- SQLite (user storage)
- Archiver (zip download)
- fs / path

---

## 📂 Folder Structure

project-root/
├── uploads/           ← Uploaded images  
├── logs/              ← Upload log file  
├── db.js              ← SQLite database setup  
├── server.js          ← Main Express server  
├── .env               ← Environment variables  
├── package.json  
└── README.md

---

## ⚙️ Setup Instructions

1. Clone the repository

   git clone https://github.com/your-username/photoServer.git  
   cd photoServer

2. Install dependencies

   npm install

3. Create folders if not present

   mkdir uploads logs

4. Create a `.env` file

   PORT=3000  
   SECRET_KEY=your_jwt_secret

5. Run the server

   node server.js

> Server will be running at http://localhost:3000

---

## 🔐 API Endpoints

### POST /register
- Register a new user
- Body: { "userId": "john_doe", "password": "Secure@123" }

### POST /login
- Login user and receive a token
- Body: { "userId": "john_doe", "password": "Secure@123" }

### POST /uploads
- Upload up to 5 photos with labels
- Form data: userId, row1Selection, row2Selection, photos[]

### GET /gallery
- View uploaded photos with download links
