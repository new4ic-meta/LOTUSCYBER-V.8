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

// Exactly one declaration of Payhip Single Scan configuration
const PAYHIP_PRODUCT_SECRET_KEY = process.env.PAYHIP_PRODUCT_SECRET_KEY || '';
const PAYHIP_PRODUCT_LINK = process.env.PAYHIP_PRODUCT_LINK || 'kSQUN';

// Exactly one declaration of concurrency locks
const singleScanLocks = new Set();

// CREDIT_SECRET: Stable server secret from Render environment variable.
// In production, fails safely if required secret is missing. Never generates random production secret on startup.
const IS_PROD = process.env.NODE_ENV === 'production';
const CREDIT_SECRET = process.env.CREDIT_SECRET || process.env.PAYHIP_PRODUCT_SECRET_KEY || (!IS_PROD ? 'lotuscyber_dev_credit_secret_key_v8' : '');

function isCreditConfigured() {
  return Boolean(CREDIT_SECRET);
}

// Optional PostgreSQL integration if DATABASE_URL or PG* variables are provided on Render.
// If PostgreSQL is not configured, safely persists using local atomic file storage.
let pgPool = null;
const DATABASE_URL = process.env.DATABASE_URL || process.env.PG_CONNECTION_STRING || '';

if (DATABASE_URL) {
  try {
    const { Pool } = require('pg');
    pgPool = new Pool({
      connectionString: DATABASE_URL,
      ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false }
    });
    // Create tables if not exist
    pgPool.query(`
      CREATE TABLE IF NOT EXISTS lotus_redeemed_licenses (
        license_key VARCHAR(120) PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS lotus_consumed_nonces (
        nonce VARCHAR(120) PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `).catch(err => console.warn('[PG_INIT_WARN]', err.message));
  } catch {
    pgPool = null;
  }
}

// Fallback persistent atomic file storage
const DATA_FILE = path.join(ROOT, '.credit_state.json');
let creditState = { redeemedLicenses: [], consumedNonces: [] };

try {
  if (fs.existsSync(DATA_FILE)) {
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (Array.isArray(parsed.redeemedLicenses)) creditState.redeemedLicenses = parsed.redeemedLicenses;
    if (Array.isArray(parsed.consumedNonces)) creditState.consumedNonces = parsed.consumedNonces;
  }
} catch (e) {
  console.warn('Could not read credit state file:', e.message);
}

const redeemedLicenses = new Set(creditState.redeemedLicenses);
const consumedCreditNonces = new Set(creditState.consumedNonces);

function persistCreditState() {
  try {
    const data = {
      redeemedLicenses: Array.from(redeemedLicenses),
      consumedNonces: Array.from(consumedCreditNonces)
    };
    const tmp = `${DATA_FILE}.tmp.${Date.now()}`;
    fs.writeFileSync(tmp, JSON.stringify(data), { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmp, DATA_FILE);
  } catch (e) {
    console.warn('Could not persist credit state:', e.message);
  }
}

async function isLicenseRedeemed(licenseKey) {
  if (redeemedLicenses.has(licenseKey)) return true;
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT 1 FROM lotus_redeemed_licenses WHERE license_key = $1 LIMIT 1', [licenseKey]);
      if (res.rowCount > 0) {
        redeemedLicenses.add(licenseKey);
        return true;
      }
    } catch (e) {
      console.warn('[PG_QUERY]', e.message);
    }
  }
  return false;
}

async function markLicenseRedeemed(licenseKey) {
  redeemedLicenses.add(licenseKey);
  persistCreditState();
  if (pgPool) {
    try {
      await pgPool.query('INSERT INTO lotus_redeemed_licenses (license_key) VALUES ($1) ON CONFLICT DO NOTHING', [licenseKey]);
    } catch (e) {
      console.warn('[PG_INSERT]', e.message);
    }
  }
}

async function isNonceConsumed(nonce) {
  if (consumedCreditNonces.has(nonce)) return true;
  if (pgPool) {
    try {
      const res = await pgPool.query('SELECT 1 FROM lotus_consumed_nonces WHERE nonce = $1 LIMIT 1', [nonce]);
      if (res.rowCount > 0) {
        consumedCreditNonces.add(nonce);
        return true;
      }
    } catch (e) {
      console.warn('[PG_QUERY]', e.message);
    }
  }
  return false;
}

async function markNonceConsumed(nonce) {
  consumedCreditNonces.add(nonce);
  persistCreditState();
  if (pgPool) {
    try {
      await pgPool.query('INSERT INTO lotus_consumed_nonces (nonce) VALUES ($1) ON CONFLICT DO NOTHING', [nonce]);
    } catch (e) {
      console.warn('[PG_INSERT]', e.message);
    }
  }
}

function signCreditToken(payload) {
  if (!CREDIT_SECRET) throw new Error('CREDIT_SECRET not configured');
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', CREDIT_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function verifyCreditToken(token) {
  if (!CREDIT_SECRET || !token || typeof token !== 'string') return null;
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
    creditSecurity: isCreditConfigured() ? 'credit_secret_configured' : 'credit_secret_missing',
    singleScan: 'one_use_license',
    productLink: PAYHIP_PRODUCT_LINK,
    database: pgPool ? 'postgresql' : 'file_persistence'
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
  if (!isCreditConfigured()) {
    return res.status(503).json({ status: 'unavailable', message: 'Pengurusan kredit belum dikonfigurasi dengan selamat pada pelayan (CREDIT_SECRET diperlukan).' });
  }
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
  if (await isLicenseRedeemed(licenseKey)) {
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
      await markLicenseRedeemed(licenseKey);
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

    await markLicenseRedeemed(licenseKey);

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
app.post('/api/scan/consume', async (req, res) => {
  if (isOwnerRequest(req)) {
    return res.json({ status: 'ok', owner: true, credits: Infinity });
  }

  if (!isCreditConfigured()) {
    return res.status(503).json({ status: 'unavailable', message: 'Sistem pengesahan kredit belum dikonfigurasi.' });
  }

  const token = req.body?.creditToken;
  const payload = verifyCreditToken(token);
  if (!payload || payload.credits <= 0) {
    return res.status(403).json({ status: 'no_credit', message: 'Tiada baki kredit imbasan yang sah.' });
  }

  if (await isNonceConsumed(payload.nonce)) {
    return res.status(409).json({ status: 'conflict', message: 'Kredit ini telah digunakan atau dikemas kini.' });
  }

  await markNonceConsumed(payload.nonce);

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

// Payhip Webhook endpoint (preserves webhook payment / refund handling)
app.post('/api/payhip/webhook', async (req, res) => {
  try {
    const event = req.body;
    const eventType = event?.event_type || event?.type || '';
    const licenseKey = event?.license_key || event?.data?.license_key;

    if (eventType === 'refund' || eventType === 'dispute') {
      if (licenseKey) {
        await markLicenseRedeemed(licenseKey); // Revoke further redemptions
      }
      return res.json({ status: 'ok', action: 'revoked' });
    }

    return res.json({ status: 'ok', received: true });
  } catch (err) {
    return res.status(400).json({ status: 'error', message: err.message });
  }
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
  if (await isLicenseRedeemed(licenseKey)) {
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
      await markLicenseRedeemed(licenseKey);
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
    await markLicenseRedeemed(licenseKey);
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

// Exactly ONE app.listen call
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
  singleScanLocks,
  isLicenseRedeemed,
  markLicenseRedeemed,
  isNonceConsumed,
  markNonceConsumed,
  isCreditConfigured
};
