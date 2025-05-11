require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
app.use(cors({ origin: 'https://isectech.org' }));
app.use(express.json());

app.post('/scan', async (req, res) => {
  const { target, profile } = req.body;

  if (!target || typeof target !== 'string') {
    return res.status(400).json({ error: 'Invalid or missing target' });
  }

  try {
    const result = await axios.post('https://YOUR-REAL-API-ENDPOINT.com/scan', {
      target,
      profile
    }, {
      headers: { Authorization: `Bearer ${process.env.API_KEY}` }
    });

    res.json(result.data);
  } catch (error) {
    console.error('API call failed:', error.message);
    res.status(500).json({ error: 'Scan failed. Please try again later.' });
  }
});

app.listen(3000, () => {
  console.log('Proxy running on port 3000');
});

