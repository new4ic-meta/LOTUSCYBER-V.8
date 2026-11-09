const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuration (To be set via Environment Variables on deployment)
const TOYYIBPAY_SECRET_KEY = process.env.TOYYIBPAY_SECRET_KEY || '';
const TOYYIBPAY_CATEGORY_CODE = process.env.TOYYIBPAY_CATEGORY_CODE || '';
// Do not place production secrets or demo API keys in source code.

// In-Memory Database Store for Enterprise Keys (Replace with Redis/MongoDB in production)
const apiKeysDatabase = new Map(); // Populate only with securely issued keys from a persistent database.

// -------------------------------------------------------------
// 1. TOYYIBPAY PAYMENT INTEGRATION (PAYMENT BILL CREATION)
// -------------------------------------------------------------
app.post('/api/create-payment', async (req, res) => {
    const { plan, userEmail } = req.body;
    
    if (!TOYYIBPAY_SECRET_KEY) {
        return res.status(400).json({ 
            status: 'error', 
            message: 'Kunci Secret Gateway Pembayaran (ToyyibPay) belum dikonfigurasi pada pelayan.' 
        });
    }

    const paymentPlans = { SCAN: 1090, MONTHLY: 3990, YEARLY: 9900 }; // sen
    const amount = paymentPlans[plan] || 0;
    if (amount === 0) return res.status(400).json({ status: 'error', message: 'Pelan tidak sah.' });

    try {
        const formData = new URLSearchParams();
        formData.append('userSecretKey', TOYYIBPAY_SECRET_KEY);
        formData.append('categoryCode', TOYYIBPAY_CATEGORY_CODE);
        formData.append('billName', `LotusCyber ${plan}`);
        formData.append('billDescription', plan === 'SCAN' ? 'Satu semakan tambahan LotusCyber' : `Langganan LotusCyber ${plan}`);
        formData.append('billPriceSetting', 1);
        formData.append('billPayorInfo', 1);
        formData.append('billAmount', amount.toString());
        formData.append('billReturnUrl', `${req.protocol}://${req.get('host')}/payment-success.html`);
        formData.append('billCallbackUrl', `${req.protocol}://${req.get('host')}/api/payment-callback`);
        formData.append('billExternalReferenceNo', `LOTUS-${Date.now()}`);
        formData.append('billTo', userEmail || 'Pelanggan LotusCyber');
        formData.append('billEmail', userEmail || 'user@lotuscyber.my');
        formData.append('billPhone', '0123456789');

        const fetch = (await import('node-fetch')).default;
        const response = await fetch('https://toyyibpay.com/index.php/api/createBill', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        if (data && data[0] && data[0].BillCode) {
            return res.json({
                status: 'success',
                paymentUrl: `https://toyyibpay.com/${data[0].BillCode}`
            });
        } else {
            return res.status(500).json({ status: 'error', message: 'Gagal menjana bil ToyyibPay.' });
        }
    } catch (err) {
        return res.status(500).json({ status: 'error', message: err.message });
    }
});

// Callback/Webhook endpoint for payment validation
app.post('/api/payment-callback', (req, res) => {
    const { refno, status_id, billcode, order_id } = req.body;
    // status_id = 1 indicates payment successful in ToyyibPay
    if (status_id === '1') {
        console.log(`[PAYMENT VERIFIED SUCCESS] Ref: ${refno}, BillCode: ${billcode}`);
        // PENTING: Callback ini belum mengaktifkan pelan atau kredit. Pengesahan transaksi server-side dan rekod pesanan masih perlu dibina sebelum jualan sebenar.
    }
    res.send('OK');
});

// -------------------------------------------------------------
// 2. ENTERPRISE REST API SCANNER ENDPOINT (10,000 QUOTA ENGINE)
// -------------------------------------------------------------
const OFFICIAL_HOSTNAMES = ["maybank2u.com.my", "cimbclicks.com.my", "rhbgroup.com", "publicbank.com.my", "hlb.com.my", "pos.com.my"];
const SCAM_PATTERNS = [
    { pattern: /bit\.ly|tinyurl\.com|t\.me|cutt\.ly|is\.gd|goo\.gl|\.top|\.xyz|\.click|\.online/i, score: 35, label: "Penggunaan pemendek pautan / domain berisiko tinggi (.top, .xyz)" },
    { pattern: /\.apk|\.exe|download-app/i, score: 45, label: "Cubaan muat turun fail APK / Malware" },
    { pattern: /akaun anda (telah disekat|dibatalkan|tergantung|dibekukan)/i, score: 25, label: "Tektik amaran akaun disekat" },
    { pattern: /kod tac|kod otp|tac anda|otp anda/i, score: 20, label: "Permintaan Kod TAC / OTP" },
    { pattern: /tuntut (hadiah|sedekah|pelaburan|dividen|bantuan|wang)/i, score: 20, label: "Umpan ganjaran wang / dividen" }
];

app.post('/api/v1/scan', (req, res) => {
    const apiKey = req.headers['x-lotus-api-key'];
    if (!apiKey || !apiKeysDatabase.has(apiKey)) {
        return res.status(401).json({ status: 'error', message: 'Kunci API (X-Lotus-API-Key) tidak sah atau tidak diberikan.' });
    }

    const keyData = apiKeysDatabase.get(apiKey);
    if (keyData.quotaRemaining <= 0) {
        return res.status(429).json({ status: 'error', message: 'Had panggilan API bulanan telah dicapai (10,000 / 10,000).' });
    }

    const { message } = req.body;
    if (!message) return res.status(400).json({ status: 'error', message: 'Parameter "message" diperlukan.' });

    // Deduct quota
    keyData.quotaRemaining -= 1;

    // Scan Algorithm
    let totalScore = 0;
    let triggeredIndicators = [];

    const urlRegex = /(https?:\/\/[^\s]+)/gi;
    const extractedUrls = message.match(urlRegex) || [];

    extractedUrls.forEach(urlStr => {
        try {
            const parsedUrl = new URL(urlStr);
            const hostname = parsedUrl.hostname.toLowerCase();
            let isOfficial = false;
            OFFICIAL_HOSTNAMES.forEach(official => {
                if (hostname === official || hostname.endsWith('.' + official)) isOfficial = true;
            });
            if (!isOfficial) {
                totalScore += 40;
                triggeredIndicators.push(`Pautan bukan domain rasmi berdaftar: ${hostname}`);
            }
        } catch(e) {
            totalScore += 25;
            triggeredIndicators.push(`Format URL tidak sah: ${urlStr}`);
        }
    });

    SCAM_PATTERNS.forEach(item => {
        if (item.pattern.test(message)) {
            totalScore += item.score;
            if (!triggeredIndicators.includes(item.label)) triggeredIndicators.push(item.label);
        }
    });

    const scorePercentage = Math.min(totalScore, 100);
    const riskLevel = scorePercentage >= 60 ? "TINGGI" : (scorePercentage >= 30 ? "SEDERHANA" : "RENDAH");

    res.json({
        status: 'success',
        threat_score: scorePercentage,
        risk_level: riskLevel,
        indicators: triggeredIndicators,
        disclaimer: 'Analisis ini adalah penilaian heuristik peranti/server tempatan, bukan pengesahan mutlak.',
        api_quota_remaining: keyData.quotaRemaining
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`LotusCyber Secure Server Running on Port ${PORT}`);
});
