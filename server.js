const express = require('express');
const path = require('path');
const crypto = require('crypto');
const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'LotusCyber API', payments: process.env.PAYHIP_PRODUCT_SECRET_KEY ? 'payhip_license_verification_configured' : 'not_configured', singleScan: 'one_use_license' });
});

// OWNER access is protected by a Render environment variable; never store the passphrase in source code.
const ownerPassphrase = process.env.OWNER_PASSPHRASE || '';
const ownerTokenSecret = ownerPassphrase
  ? crypto.createHash('sha256').update(`LotusCyber OWNER token:${ownerPassphrase}`).digest()
  : null;
const ownerLoginAttempts = new Map();

function signOwnerToken(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', ownerTokenSecret).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function verifyOwnerToken(token) {
  if (!ownerTokenSecret || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const expected = crypto.createHmac('sha256', ownerTokenSecret).update(parts[0]).digest();
  let supplied;
  try { supplied = Buffer.from(parts[1], 'base64url'); } catch { return false; }
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return false;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    return payload.sub === 'owner' && Number.isFinite(payload.exp) && payload.exp > Date.now();
  } catch { return false; }
}

function isOwnerRequest(req) {
  const authorization = req.get('authorization') || '';
  return authorization.startsWith('Bearer ') && verifyOwnerToken(authorization.slice(7));
}

app.post('/api/owner/login', (req, res) => {
  if (!ownerPassphrase) {
    return res.status(503).json({ status: 'unavailable', message: 'Akses OWNER belum dikonfigurasi. Tetapkan OWNER_PASSPHRASE dalam Render Environment Variables.' });
  }
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const attempt = ownerLoginAttempts.get(ip) || { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (attempt.resetAt <= now) { attempt.count = 0; attempt.resetAt = now + 15 * 60 * 1000; }
  if (attempt.count >= 5) return res.status(429).json({ status: 'error', message: 'Terlalu banyak percubaan. Cuba lagi selepas 15 minit.' });

  const suppliedHash = crypto.createHash('sha256').update(String(req.body?.passphrase || '')).digest();
  const expectedHash = crypto.createHash('sha256').update(ownerPassphrase).digest();
  if (!crypto.timingSafeEqual(suppliedHash, expectedHash)) {
    attempt.count += 1;
    ownerLoginAttempts.set(ip, attempt);
    return res.status(401).json({ status: 'error', message: 'Kata laluan OWNER tidak tepat.' });
  }
  ownerLoginAttempts.delete(ip);
  const token = signOwnerToken({ sub: 'owner', exp: now + 12 * 60 * 60 * 1000 });
  return res.json({ status: 'ok', token, expires_in: 43200 });
});

app.get('/api/owner/status', (req, res) => {
  if (!isOwnerRequest(req)) return res.status(401).json({ status: 'unauthorized' });
  return res.json({ status: 'ok', role: 'OWNER', unlimited_scans: true });
});

// Payhip Single Scan: each purchase receives a unique Payhip software license key.
// Keep PAYHIP_PRODUCT_SECRET_KEY in Render Environment Variables only; never expose it to the browser.
const PAYHIP_PRODUCT_SECRET_KEY = process.env.PAYHIP_PRODUCT_SECRET_KEY || '';
const PAYHIP_PRODUCT_LINK = process.env.PAYHIP_PRODUCT_LINK || '';
const singleScanLocks = new Set();

app.post('/api/payhip/consume-single-scan', async (req, res) => {
  const licenseKey = String(req.body?.licenseKey || '').trim();
  if (!PAYHIP_PRODUCT_SECRET_KEY) {
    return res.status(503).json({ status: 'unavailable', message: 'Pengesahan lesen Payhip belum dikonfigurasi pada pelayan.' });
  }
  if (!licenseKey || licenseKey.length > 100 || !/^[A-Za-z0-9-]+$/.test(licenseKey)) {
    return res.status(400).json({ status: 'error', message: 'Kod lesen tidak sah.' });
  }
  if (singleScanLocks.has(licenseKey)) {
    return res.status(409).json({ status: 'error', message: 'Kod lesen sedang diproses. Cuba sebentar lagi.' });
  }
  singleScanLocks.add(licenseKey);
  try {
    const verifyUrl = new URL('https://payhip.com/api/v2/license/verify');
    verifyUrl.searchParams.set('license_key', licenseKey);
    const verifyResponse = await fetch(verifyUrl, {
      method: 'GET',
      headers: { 'product-secret-key': PAYHIP_PRODUCT_SECRET_KEY, 'Accept': 'application/json' }
    });
    if (!verifyResponse.ok) throw new Error(`Payhip verification HTTP ${verifyResponse.status}`);
    const verifyJson = await verifyResponse.json();
    const license = verifyJson?.data;
    if (!license || license.enabled !== true) {
      return res.status(403).json({ status: 'error', message: 'Lesen tidak sah atau telah dinyahaktifkan.' });
    }
    if (PAYHIP_PRODUCT_LINK && license.product_link !== PAYHIP_PRODUCT_LINK) {
      return res.status(403).json({ status: 'error', message: 'Lesen ini bukan untuk produk LotusCyber Single Scan.' });
    }
    if (Number(license.uses) >= 1) {
      return res.status(409).json({ status: 'used', message: 'Fail akses ini telah digunakan. Satu fail hanya sah untuk satu semakan.' });
    }

    const usageResponse = await fetch('https://payhip.com/api/v2/license/usage', {
      method: 'PUT',
      headers: { 'product-secret-key': PAYHIP_PRODUCT_SECRET_KEY, 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: new URLSearchParams({ license_key: licenseKey })
    });
    if (!usageResponse.ok) throw new Error(`Payhip usage HTTP ${usageResponse.status}`);
    const usageJson = await usageResponse.json();
    if (!usageJson?.data || Number(usageJson.data.uses) < 1) {
      throw new Error('Payhip did not confirm license usage update');
    }
    return res.json({ status: 'ok', message: 'Fail akses disahkan. Satu semakan telah digunakan.' });
  } catch (error) {
    console.error('[PAYHIP_SINGLE_SCAN]', error.message);
    return res.status(502).json({ status: 'error', message: 'Payhip tidak dapat mengesahkan atau menggunakan kod lesen sekarang. Tiada akses diberikan.' });
  } finally {
    singleScanLocks.delete(licenseKey);
  }
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
