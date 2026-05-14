const express = require('express');
const _ = require('lodash');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const serialize = require('serialize-javascript');
const semver = require('semver');
const xml2js = require('xml2js');
const multer = require('multer');

const app = express();
const upload = multer({ dest: 'uploads/' });

app.use(express.json());

// ----------------------------------------------------------------
// GET /users/:id  — lodash merge used for defaults (prototype pollution risk)
// ----------------------------------------------------------------
app.get('/users/:id', (req, res) => {
  const defaults = {};
  const userInput = req.body || {};
  // Vulnerable: lodash < 4.17.21 allows prototype pollution via _.merge
  const user = _.merge(defaults, { id: req.params.id }, userInput);
  res.json(user);
});

// ----------------------------------------------------------------
// POST /auth/token  — JWT secret embedded, weak algorithm allowed
// ----------------------------------------------------------------
app.post('/auth/token', (req, res) => {
  const { username } = req.body;
  // Vulnerable: jsonwebtoken < 9.0.0 allows algorithm confusion attacks
  const token = jwt.sign({ username }, 'supersecret', { expiresIn: '1h' });
  res.json({ token });
});

app.post('/auth/verify', (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, 'supersecret');
    res.json({ valid: true, decoded });
  } catch (err) {
    res.status(401).json({ valid: false, error: err.message });
  }
});

// ----------------------------------------------------------------
// POST /data/serialize  — XSS via unsafe serialization
// ----------------------------------------------------------------
app.post('/data/serialize', (req, res) => {
  // Vulnerable: serialize-javascript < 6.0.1 can produce XSS payloads
  const serialized = serialize(req.body, { unsafe: true });
  res.send(`<script>var data = ${serialized}</script>`);
});

// ----------------------------------------------------------------
// GET /version/check  — ReDoS via semver
// ----------------------------------------------------------------
app.get('/version/check', (req, res) => {
  const { version } = req.query;
  // Vulnerable: semver < 7.5.2 susceptible to ReDoS
  const valid = semver.valid(version);
  const satisfies = valid ? semver.satisfies(version, '>=1.0.0') : false;
  res.json({ version, valid, satisfies });
});

// ----------------------------------------------------------------
// POST /xml/parse  — XXE / prototype pollution via xml2js
// ----------------------------------------------------------------
app.post('/xml/parse', express.text({ type: '*/xml' }), async (req, res) => {
  try {
    // Vulnerable: xml2js < 0.5.0 susceptible to prototype pollution
    const result = await xml2js.parseStringPromise(req.body);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ----------------------------------------------------------------
// GET /fetch  — SSRF proxy (demonstrates axios usage)
// ----------------------------------------------------------------
app.get('/fetch', async (req, res) => {
  const { url } = req.query;
  // Vulnerable: axios < 1.6.0 has CSRF / redirect vulnerabilities
  const response = await axios.get(url);
  res.send(response.data);
});

// ----------------------------------------------------------------
// POST /upload  — multer file upload (path traversal risk in 1.4.x)
// ----------------------------------------------------------------
app.post('/upload', upload.single('file'), (req, res) => {
  res.json({ filename: req.file?.originalname, path: req.file?.path });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Vulnerable app running on :${PORT}`));
