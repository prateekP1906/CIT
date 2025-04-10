require('dotenv').config();
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const app = express();

const upload = multer({ dest: 'uploads/' });
app.use(express.static('public'));

app.post('/analyze', upload.single('file'), async (req, res) => {
  const filePath = req.file.path;

  try {
    // 1. Send file to VirusTotal
    const vtRes = await axios.post('https://www.virustotal.com/api/v3/files', fs.createReadStream(filePath), {
      headers: {
        'x-apikey': process.env.VIRUSTOTAL_API_KEY,
        'Content-Type': 'application/octet-stream'
      }
    });

    const analysisId = vtRes.data.data.id;

    // 2. Wait briefly and fetch analysis result
    await new Promise(resolve => setTimeout(resolve, 8000)); // Wait 8 seconds

    const analysisRes = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
    });

    const malicious = analysisRes.data.data.attributes.stats.malicious;

    // Return result
    const result = malicious > 0 ? "infected" : "clean";
    res.json({ result, source: "VirusTotal" });

  } catch (err) {
    console.error("VirusTotal failed:", err.message);

    // Optional: fallback to MetaDefender
    try {
      const mdRes = await axios.post('https://api.metadefender.com/v4/file', fs.createReadStream(filePath), {
        headers: { apikey: process.env.METADEFENDER_API_KEY }
      });

      const dataId = mdRes.data.data_id;
      await new Promise(resolve => setTimeout(resolve, 6000)); // wait

      const scanRes = await axios.get(`https://api.metadefender.com/v4/file/${dataId}`, {
        headers: { apikey: process.env.METADEFENDER_API_KEY }
      });

      const infected = Object.values(scanRes.data.scan_results.scan_details).some(d => d.threat_found);
      res.json({ result: infected ? "infected" : "clean", source: "MetaDefender" });

    } catch (fallbackError) {
      console.error("MetaDefender also failed:", fallbackError.message);
      res.status(500).json({ result: "error", message: "Analysis failed." });
    }
  } finally {
    fs.unlinkSync(filePath); // Clean up temp file
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));