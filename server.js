const express = require('express');
const path = require('path');
const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'LotusCyber API', payments: 'not_configured', accountProvisioning: 'not_configured' });
});

// Fail closed: do not create bills until verified callback handling and persistent account activation exist.
app.post('/api/create-payment', (_req, res) => {
  res.status(503).json({
    status: 'unavailable',
    message: 'Pembayaran belum diaktifkan. Pengesahan transaksi dan pengaktifan akaun automatik masih dalam pembangunan.'
  });
});

// No demo API key or hard-coded secret is shipped. Enterprise API is disabled until secure key issuance/storage is implemented.
app.post('/api/v1/scan', (_req, res) => {
  res.status(503).json({
    status: 'unavailable',
    message: 'Enterprise API belum diaktifkan. Kunci API pelanggan belum boleh dikeluarkan dengan selamat.'
  });
});

app.use(express.static(ROOT, { index: 'index.html', etag: true, maxAge: '1h' }));
app.get('*', (_req, res) => res.sendFile(path.join(ROOT, 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`LotusCyber running on port ${PORT}`);
});
