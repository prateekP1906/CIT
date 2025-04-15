const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const FormData = require('form-data');
const app = express();
const PORT = 3000;
const { OpenAI } = require('openai');
const bodyParser = require('body-parser');


// Serve static files

const VIRUSTOTAL_API_KEY = 'd06c7178865aa945b82950e8f723d72fc34f04698be4dea5624118314c2fe728'; // ⬅️ Replace with your key
// File upload setup
const storage = multer.diskStorage({
    destination: './uploads',
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

app.use(express.static(path.join(__dirname, 'public')));
// Upload route
app.post('/analyze', upload.single('file'), async (req, res) => {
    try {
      const form = new FormData();
      form.append('file', fs.createReadStream(req.file.path));
  
      const uploadRes = await axios.post('https://www.virustotal.com/api/v3/files', form, {
        headers: {
          'x-apikey': VIRUSTOTAL_API_KEY,
          ...form.getHeaders()
        }
      });
  
      fs.unlinkSync(req.file.path);
  
      const analysisId = uploadRes.data.data.id;
  
      // ⏳ Polling until scan is finished
      let resultRes;
      let status = 'queued';
      for (let i = 0; i < 10; i++) {
        await new Promise(resolve => setTimeout(resolve, 3000)); // wait 3s
  
        resultRes = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          headers: {
            'x-apikey': VIRUSTOTAL_API_KEY
          }
        });
  
        status = resultRes.data.data.attributes.status;
        if (status === 'completed') break;
      }
  
      if (status !== 'completed') {
        return res.json({
          result: 'unknown',
          source: 'VirusTotal',
          message: '⚠️ Scan not completed. Try again later.'
        });
      }
  
      const stats = resultRes.data.data.attributes.stats;
      const malicious = stats.malicious;
      const harmless = stats.harmless;
      const suspicious = stats.suspicious;
  
      const finalStatus = malicious > 0 || suspicious > 0 ? "malicious" : "clean";
  
      const maliciousEngines = [];

        const results = resultRes.data.data.attributes.results;
        for (const engine in results) {
        if (results[engine].category === 'malicious') {
            maliciousEngines.push(`${engine} → ${results[engine].result}`);
        }
        }

        res.json({
        result: finalStatus,
        source: "VirusTotal",
        message: `✅ Scan completed: ${finalStatus.toUpperCase()} | Malicious: ${malicious}, Suspicious: ${suspicious}, Harmless: ${harmless}`,
        maliciousEngines
        });
  
    } catch (err) {
      console.error("VirusTotal Error:", err.message);
      res.status(500).json({
        result: 'error',
        source: 'VirusTotal',
        message: '❌ Failed to scan or retrieve results.'
      });
    }
  });
  
  
  app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));