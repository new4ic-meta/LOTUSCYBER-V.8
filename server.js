const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;

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

// Payhip Single Scan configuration (declared once)
const PAYHIP_PRODUCT_SECRET_KEY = process.env.PAYHIP_PRODUCT_SECRET_KEY || '';
const PAYHIP_PRODUCT_LINK = process.env.PAYHIP_PRODUCT_LINK || 'kSQUN';

// Stable server signing secret (persists across restarts via env var or file storage)
function getStableSecret() {
  if (process.env.CREDIT_SECRET) return process.env.CREDIT_SECRET;
  if (process.env.PAYHIP_PRODUCT_SECRET_KEY) return process.env.PAYHIP_PRODUCT_SECRET_KEY;
  const secretFile = path.join(ROOT, '.credit_secret');
  try {
    if (fs.existsSync(secretFile)) {
      return fs.readFileSync(secretFile, 'utf8').trim();
    }
    const generated = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(secretFile, generated, { encoding: 'utf8', mode: 0o600 });
    return generated;
  } catch {
    return 'lotuscyber_default_scan_secret_key_v8';
  }
}

const CREDIT_SECRET = getStableSecret();
const singleScanLocks = new Set();

// Persistent storage for redeemed licenses and consumed credit nonces
const DATA_FILE = path.join(ROOT, '.credit_state.json');
let creditState = { redeemedLicenses: [], consumedNonces: [] };

try {
  if (fs.existsSync(DATA_FILE)) {
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (Array.isArray(parsed.redeemedLicenses)) creditState.redeemedLicenses = parsed.redeemedLicenses;
    if (Array.isArray(parsed.consumedNonces)) creditState.consumedNonces = parsed.consumedNonces;
  }
} catch (e) {
  console.warn('Could not load persistent credit state, using memory:', e.message);
}

const redeemedLicenses = new Set(creditState.redeemedLicenses);
const consumedCreditNonces = new Set(creditState.consumedNonces);

function persistCreditState() {
  try {
    const data = {
      redeemedLicenses: Array.from(redeemedLicenses),
      consumedNonces: Array.from(consumedCreditNonces)
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(data), { encoding: 'utf8', mode: 0o600 });
  } catch (e) {
    console.warn('Could not persist credit state:', e.message);
  }
}

function signCreditToken(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', CREDIT_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function verifyCreditToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const expected = crypto.createHmac('sha256', CREDIT_SECRET).update(parts[0]).digest();
  let supplied;
  try { supplied = Buffer.from(parts[1], 'base64url'); } catch { return null; }
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    if (typeof payload.credits !== 'number' || payload.credits < 0) return null;
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'LotusCyber API',
    payments: PAYHIP_PRODUCT_SECRET_KEY ? 'payhip_license_verification_configured' : 'not_configured',
    singleScan: 'one_use_license',
    productLink: PAYHIP_PRODUCT_LINK
  });
});

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

// Payhip Single Scan Redeem:
// 1. Verifies Payhip license with Payhip API
// 2. Marks usage on Payhip
// 3. Issues cryptographically signed scan credit token
app.post('/api/payhip/redeem', async (req, res) => {
  const licenseKey = String(req.body?.licenseKey || '').trim();
  if (!PAYHIP_PRODUCT_SECRET_KEY) {
    return res.status(503).json({ status: 'unavailable', message: 'Pengesahan lesen Payhip belum dikonfigurasi pada pelayan.' });
  }
  if (!licenseKey || licenseKey.length > 100 || !/^[A-Za-z0-9-]+$/.test(licenseKey)) {
    return res.status(400).json({ status: 'error', message: 'Format kod lesen tidak sah.' });
  }
  if (singleScanLocks.has(licenseKey)) {
    return res.status(409).json({ status: 'error', message: 'Kod lesen sedang diproses. Sila tunggu sebentar.' });
  }
  if (redeemedLicenses.has(licenseKey)) {
    return res.status(409).json({ status: 'used', message: 'Kod lesen ini telah ditebus sebelum ini.' });
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

    if (PAYHIP_PRODUCT_LINK && license.product_link && license.product_link !== PAYHIP_PRODUCT_LINK) {
      return res.status(403).json({ status: 'error', message: 'Lesen ini bukan untuk produk LotusCyber Single Scan.' });
    }

    if (Number(license.uses) >= 1) {
      redeemedLicenses.add(licenseKey);
      persistCreditState();
      return res.status(409).json({ status: 'used', message: 'Fail akses ini telah digunakan. Satu pembelian hanya sah untuk satu semakan.' });
    }

    const usageResponse = await fetch('https://payhip.com/api/v2/license/usage', {
      method: 'PUT',
      headers: {
        'product-secret-key': PAYHIP_PRODUCT_SECRET_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: new URLSearchParams({ license_key: licenseKey })
    });
    if (!usageResponse.ok) throw new Error(`Payhip usage HTTP ${usageResponse.status}`);
    const usageJson = await usageResponse.json();
    if (!usageJson?.data || Number(usageJson.data.uses) < 1) {
      throw new Error('Payhip did not confirm license usage update');
    }

    redeemedLicenses.add(licenseKey);
    persistCreditState();

    let existingCredits = 0;
    const existingToken = req.body?.creditToken;
    if (existingToken) {
      const parsed = verifyCreditToken(existingToken);
      if (parsed && typeof parsed.credits === 'number') {
        existingCredits = parsed.credits;
      }
    }

    const newCredits = existingCredits + 1;
    const payload = {
      sub: 'credit_session',
      credits: newCredits,
      nonce: crypto.randomBytes(16).toString('hex'),
      iat: Date.now(),
      exp: Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days
    };
    const token = signCreditToken(payload);

    return res.json({
      status: 'ok',
      message: 'Lesen berjaya ditebus! 1 kredit imbasan telah ditambah.',
      credits: newCredits,
      creditToken: token
    });
  } catch (error) {
    console.error('[PAYHIP_REDEEM]', error.message);
    return res.status(502).json({ status: 'error', message: 'Payhip tidak dapat mengesahkan atau menebus kod lesen sekarang. Tiada kredit diberikan.' });
  } finally {
    singleScanLocks.delete(licenseKey);
  }
});

// Scan Credit Consumption Endpoint:
// Deducts 1 credit only when an authorized scan has succeeded.
app.post('/api/scan/consume', (req, res) => {
  if (isOwnerRequest(req)) {
    return res.json({ status: 'ok', owner: true, credits: Infinity });
  }

  const token = req.body?.creditToken;
  const payload = verifyCreditToken(token);
  if (!payload || payload.credits <= 0) {
    return res.status(403).json({ status: 'no_credit', message: 'Tiada baki kredit imbasan yang sah.' });
  }

  if (consumedCreditNonces.has(payload.nonce)) {
    return res.status(409).json({ status: 'conflict', message: 'Kredit ini telah digunakan atau dikemas kini.' });
  }

  consumedCreditNonces.add(payload.nonce);
  persistCreditState();

  const remainingCredits = payload.credits - 1;
  const nextPayload = {
    sub: 'credit_session',
    credits: remainingCredits,
    nonce: crypto.randomBytes(16).toString('hex'),
    iat: Date.now(),
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000
  };
  const nextToken = signCreditToken(nextPayload);

  return res.json({
    status: 'ok',
    message: '1 kredit imbasan telah digunakan.',
    remainingCredits,
    creditToken: nextToken
  });
});

// Verify Credit Token status (read-only)
app.post('/api/scan/balance', (req, res) => {
  if (isOwnerRequest(req)) {
    return res.json({ status: 'ok', owner: true, credits: 'UNLIMITED' });
  }
  const token = req.body?.creditToken;
  const payload = verifyCreditToken(token);
  if (!payload) {
    return res.json({ status: 'ok', credits: 0 });
  }
  return res.json({ status: 'ok', credits: payload.credits });
});

// Legacy backward-compatible endpoint
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
  if (redeemedLicenses.has(licenseKey)) {
    return res.status(409).json({ status: 'used', message: 'Fail akses ini telah digunakan. Satu fail hanya sah untuk satu semakan.' });
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
    if (PAYHIP_PRODUCT_LINK && license.product_link && license.product_link !== PAYHIP_PRODUCT_LINK) {
      return res.status(403).json({ status: 'error', message: 'Lesen ini bukan untuk produk LotusCyber Single Scan.' });
    }
    if (Number(license.uses) >= 1) {
      redeemedLicenses.add(licenseKey);
      persistCreditState();
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
    redeemedLicenses.add(licenseKey);
    persistCreditState();
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

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`LotusCyber running on port ${PORT}`);
  });
}

module.exports = {
  app,
  signCreditToken,
  verifyCreditToken,
  redeemedLicenses,
  consumedCreditNonces,
  singleScanLocks
};
