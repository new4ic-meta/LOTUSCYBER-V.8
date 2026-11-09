const express = require(‘express’);
const path = require(‘path’);
const crypto = require(‘crypto’);

const app = express();

app.disable(‘x-powered-by’);

app.use(express.json({ limit: ‘32kb’ }));
app.use(express.urlencoded({ extended: false, limit: ‘32kb’ }));

const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;

const OWNER_SESSION_DURATION = 12 * 60 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW = 15 * 60 * 1000;

const ownerPassphrase = process.env.OWNER_PASSPHRASE || ‘’;

const ownerTokenSecret = ownerPassphrase
? crypto.createHash(‘sha256’)
.update(LotusCyber OWNER token:${ownerPassphrase})
.digest()
: null;

const ownerLoginAttempts = new Map();

// HEALTH CHECK
app.get(’/api/health’, (_req, res) => {
res.json({
status: ‘ok’,
service: ‘LotusCyber API’,
payments: ‘not_configured’,
accountProvisioning: ‘not_configured’
});
});

// OWNER TOKEN SECURITY
function signOwnerToken(payload) {
const encoded = Buffer
.from(JSON.stringify(payload))
.toString(‘base64url’);

const signature = crypto
.createHmac(‘sha256’, ownerTokenSecret)
.update(encoded)
.digest(‘base64url’);

return ${encoded}.${signature};
}

function verifyOwnerToken(token) {
if (!ownerTokenSecret || typeof token !== ‘string’) {
return false;
}

const parts = token.split(’.’);

if (parts.length !== 2) {
return false;
}

const expected = crypto
.createHmac(‘sha256’, ownerTokenSecret)
.update(parts[0])
.digest();

let supplied;

try {
supplied = Buffer.from(parts[1], ‘base64url’);
} catch {
return false;
}

if (
supplied.length !== expected.length ||
!crypto.timingSafeEqual(supplied, expected)
) {
return false;
}

try {
const payload = JSON.parse(
Buffer.from(parts[0], ‘base64url’).toString(‘utf8’)
);

return (
  payload.sub === 'owner' &&
  Number.isFinite(payload.exp) &&
  payload.exp > Date.now()
);

} catch {
return false;
}
}

function isOwnerRequest(req) {
const authorization = req.get(‘authorization’) || ‘’;

return (
authorization.startsWith(’Bearer ’) &&
verifyOwnerToken(authorization.slice(7))
);
}

// OWNER LOGIN
app.post(’/api/owner/login’, (req, res) => {
if (!ownerPassphrase) {
return res.status(503).json({
status: ‘unavailable’,
message: ‘Akses OWNER belum dikonfigurasi dalam Render.’
});
}

const ip = req.ip || req.socket.remoteAddress || ‘unknown’;
const now = Date.now();

const attempt = ownerLoginAttempts.get(ip) || {
count: 0,
resetAt: now + LOGIN_WINDOW
};

if (attempt.resetAt <= now) {
attempt.count = 0;
attempt.resetAt = now + LOGIN_WINDOW;
}

if (attempt.count >= MAX_LOGIN_ATTEMPTS) {
return res.status(429).json({
status: ‘error’,
message: ‘Terlalu banyak percubaan. Cuba lagi selepas 15 minit.’
});
}

const suppliedHash = crypto
.createHash(‘sha256’)
.update(String(req.body?.passphrase || ‘’))
.digest();

const expectedHash = crypto
.createHash(‘sha256’)
.update(ownerPassphrase)
.digest();

if (!crypto.timingSafeEqual(suppliedHash, expectedHash)) {
attempt.count += 1;
ownerLoginAttempts.set(ip, attempt);

return res.status(401).json({
  status: 'error',
  message: 'Kata laluan OWNER tidak tepat.'
});

}

ownerLoginAttempts.delete(ip);

const token = signOwnerToken({
sub: ‘owner’,
exp: now + OWNER_SESSION_DURATION
});

return res.json({
status: ‘ok’,
token,
expires_in: OWNER_SESSION_DURATION / 1000
});
});

// OWNER STATUS
app.get(’/api/owner/status’, (req, res) => {
if (!isOwnerRequest(req)) {
return res.status(401).json({
status: ‘unauthorized’
});
}

return res.json({
status: ‘ok’,
role: ‘OWNER’,
unlimited_scans: true
});
});

// PAYMENT - NOT YET ENABLED
app.post(’/api/create-payment’, (_req, res) => {
return res.status(503).json({
status: ‘unavailable’,
message: ‘Pembayaran belum diaktifkan.’
});
});

// ENTERPRISE API - NOT YET ENABLED
app.post(’/api/v1/scan’, (_req, res) => {
return res.status(503).json({
status: ‘unavailable’,
message: ‘Enterprise API belum diaktifkan.’
});
});

// STATIC FRONTEND
app.use(express.static(ROOT, {
index: ‘index.html’,
etag: true,
maxAge: ‘1h’
}));

// FRONTEND FALLBACK
app.get(’*’, (_req, res) => {
res.sendFile(path.join(ROOT, ‘index.html’));
});

// START SERVER
app.listen(PORT, ‘0.0.0.0’, () => {
console.log(LotusCyber running on port ${PORT});
});
