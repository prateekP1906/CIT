const express = require('express');
const path = require('path');
const multer = require('multer');

const app = express();
const PORT = 3000;

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// File upload setup
const storage = multer.diskStorage({
  destination: './uploads',
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

// Upload route
app.post('/upload', upload.single('file'), (req, res) => {
  res.send('✅ File uploaded successfully!');
});

// Start server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
