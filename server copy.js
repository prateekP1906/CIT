const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const FormData = require('form-data');
const app = express();
const PORT = 3000;


const app = express();
const PORT = 3000;


// Serve static files

const VIRUSTOTAL_API_KEY = 'YOUR_API_KEY_HERE'; // ⬅️ Replace with your key
// File upload setup
const storage = multer.diskStorage({
    destination: './uploads',
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

app.use(express.static(path.join(__dirname, 'public')));
// Upload route
app.post('/analyze', upload.single('file'), (req, res) => {
  const uploadedFilePath = req.file.path;
  res.send('✅ File uploaded successfully!');
  const result = {
    result: "clean", // or "malicious"
    source: "MockEngine v1.0"
  };
  fs.unlinkSync(uploadedFilePath);
  res.json(result);
});

// Start server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
