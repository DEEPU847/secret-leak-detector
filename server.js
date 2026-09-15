const express = require('express');
const cors = require('cors');
const { scanCode } = require('./scanner');

const app = express();
app.use(express.json());
app.use(cors());

// API Endpoint to scan code snippets for secrets
app.post('/api/scan', (req, res) => {
    const { code } = req.body;
    if (!code) {
        return res.status(400).json({ error: "No code provided for scanning." });
    }
    
    const results = scanCode(code);
    res.json(results);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Secret Leak Detector server running on port ${PORT}`);
});