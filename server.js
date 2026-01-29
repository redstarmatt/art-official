const express = require('express');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const Stripe = require('stripe');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Stripe setup
const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;
if (stripe) console.log('Stripe payments enabled');

// Stripe webhook — must be before express.json() for raw body signature verification
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    if (!stripe) return res.status(400).json({ error: 'Stripe not configured' });

    const sig = req.headers['stripe-signature'];
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send('Webhook Error: ' + err.message);
    }

    const db = loadDB();

    switch (event.type) {
        case 'invoice.paid': {
            const invoice = event.data.object;
            const artist = Object.values(db.artists).find(a => a.stripeCustomerId === invoice.customer);
            if (artist) {
                artist.plan = 'creator';
                artist.planStatus = 'active';
                artist.planExpiresAt = null;
                saveDB(db);
            }
            break;
        }
        case 'customer.subscription.updated': {
            const subscription = event.data.object;
            const artist = Object.values(db.artists).find(a => a.stripeCustomerId === subscription.customer);
            if (artist) {
                if (subscription.cancel_at_period_end) {
                    artist.planStatus = 'canceling';
                    artist.planExpiresAt = new Date(subscription.current_period_end * 1000).toISOString();
                } else {
                    artist.planStatus = 'active';
                    artist.planExpiresAt = null;
                }
                saveDB(db);
            }
            break;
        }
        case 'customer.subscription.deleted': {
            const subscription = event.data.object;
            const artist = Object.values(db.artists).find(a => a.stripeCustomerId === subscription.customer);
            if (artist) {
                artist.plan = 'free';
                artist.planStatus = 'expired';
                artist.stripeSubscriptionId = null;
                saveDB(db);
            }
            break;
        }
    }

    res.json({ received: true });
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Ensure directories exist
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
if (!fs.existsSync('data')) fs.mkdirSync('data');

// Simple JSON file database
const DB_FILE = 'data/db.json';
function loadDB() {
    if (!fs.existsSync(DB_FILE)) {
        return { artists: {}, certificates: {} };
    }
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveDB(db) {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// File upload config
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } });
const artworkUpload = upload.fields([
    { name: 'artworkImage', maxCount: 1 },
    { name: 'evidence', maxCount: 10 }
]);

// Generate certificate ID: AO-YYYY-XXXXXX
function generateCertificateId() {
    const year = new Date().getFullYear();
    const random = Math.random().toString(36).substring(2, 8).toUpperCase();
    return `AO-${year}-${random}`;
}

// Calculate certification tier based on evidence
function calculateTier(fileCount, description, hasProcessNotes) {
    let score = 0;
    if (description && description.length > 50) score += 1;
    if (description && description.length > 200) score += 1;
    if (hasProcessNotes) score += 1;
    if (fileCount >= 1) score += 1;
    if (fileCount >= 3) score += 1;
    if (fileCount >= 5) score += 2;

    if (score >= 5) return { tier: 'gold', label: 'Gold', strength: 100 };
    if (score >= 3) return { tier: 'silver', label: 'Silver', strength: 70 };
    return { tier: 'bronze', label: 'Bronze', strength: 40 };
}

// Plan helpers — determine effective subscription tier
function getEffectivePlan(artist) {
    if (!artist.plan || artist.plan === 'free') return 'free';
    if (artist.plan === 'creator') {
        if (artist.planStatus === 'expired') return 'free';
        if (artist.planStatus === 'canceling' && artist.planExpiresAt && new Date(artist.planExpiresAt) < new Date()) {
            return 'free';
        }
        return 'creator';
    }
    return 'free';
}

function isCreator(artist) {
    return getEffectivePlan(artist) === 'creator';
}

// Get public evidence files from a certificate (handles old and new format)
function getPublicEvidence(cert) {
    if (!cert.evidenceFiles || cert.evidenceFiles.length === 0) return [];
    if (typeof cert.evidenceFiles[0] === 'string') {
        return cert.evidenceFiles; // old format: treat all as public
    }
    return cert.evidenceFiles.filter(f => f.public).map(f => f.filename);
}

// Get thumbnail file for a certificate (handles old and new format)
function getCertThumbnail(cert) {
    if (cert.artworkImage) return cert.artworkImage;
    if (!cert.evidenceFiles || cert.evidenceFiles.length === 0) return null;
    if (typeof cert.evidenceFiles[0] === 'string') return cert.evidenceFiles[0];
    return cert.evidenceFiles[0].filename;
}

// Email config (set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS env vars to enable)
let mailTransporter = null;
if (process.env.SMTP_HOST) {
    mailTransporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT) || 587,
        secure: (process.env.SMTP_PORT === '465'),
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        }
    });
    console.log('Email enabled via ' + process.env.SMTP_HOST);
}

async function sendCertificateEmail(artist, certificate, host) {
    if (!mailTransporter) return;

    const verifyUrl = `${host}/verify.html?code=${certificate.id}`;
    const tierColors = { gold: '#b7960b', silver: '#718096', bronze: '#9c6b30' };
    const tierColor = tierColors[certificate.tier] || tierColors.bronze;
    const tierLabel = certificate.tierLabel || certificate.tier || 'Bronze';

    let qrDataUrl = '';
    try {
        qrDataUrl = await QRCode.toDataURL(verifyUrl, {
            width: 200, margin: 2,
            color: { dark: '#1a365d', light: '#fffef0' }
        });
    } catch (e) { /* skip QR if it fails */ }

    const html = `
    <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#fffef0;">
        <div style="background:#1a365d;color:#fffef0;padding:2rem;text-align:center;">
            <div style="font-family:Georgia,serif;font-size:1.75rem;font-weight:bold;">Art-<span style="color:#d4af37;">Official</span></div>
            <div style="font-size:0.8rem;text-transform:uppercase;letter-spacing:0.12em;opacity:0.8;margin-top:0.25rem;">Certificate of Human Creation</div>
        </div>
        <div style="padding:2rem;">
            <p style="color:#4a5568;margin-bottom:1.5rem;">Hi ${artist.name},</p>
            <p style="color:#4a5568;margin-bottom:1.5rem;">Your work has been certified as authentically human-made. Here are your certificate details:</p>
            <div style="background:#fff;border:1px solid rgba(26,54,93,0.1);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;">
                <h2 style="font-family:Georgia,serif;color:#1a365d;margin:0 0 0.5rem;font-size:1.4rem;">${certificate.title}</h2>
                <p style="color:#718096;margin:0 0 1rem;font-size:0.9rem;">${certificate.medium}</p>
                <div style="display:inline-block;padding:0.3rem 1rem;border-radius:100px;font-size:0.75rem;font-weight:bold;text-transform:uppercase;letter-spacing:0.06em;color:#fff;background:${tierColor};">${tierLabel} Certification</div>
                <div style="margin-top:1.25rem;padding-top:1rem;border-top:1px solid rgba(26,54,93,0.08);">
                    <p style="color:#a0aec0;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 0.2rem;">Certificate ID</p>
                    <p style="font-family:monospace;color:#1a365d;font-size:1.1rem;font-weight:600;margin:0;letter-spacing:0.08em;">${certificate.id}</p>
                </div>
                ${qrDataUrl ? `<div style="margin-top:1.25rem;text-align:center;"><img src="${qrDataUrl}" alt="QR Code" style="width:150px;height:150px;border-radius:8px;"></div>` : ''}
            </div>
            <div style="text-align:center;margin-bottom:1.5rem;">
                <a href="${verifyUrl}" style="display:inline-block;padding:0.75rem 2rem;background:#1a365d;color:#fffef0;text-decoration:none;border-radius:6px;font-weight:600;font-size:0.9rem;">View Your Certificate</a>
            </div>
            <p style="color:#718096;font-size:0.82rem;">You can share your certificate by sending the verification link or using the embed code on your website.</p>
        </div>
        <div style="background:#f7f5e6;padding:1.25rem;text-align:center;font-size:0.75rem;color:#a0aec0;border-top:1px solid rgba(26,54,93,0.06);">
            <p style="margin:0;">All rights reserved by the original creator. Registration does not transfer copyright.</p>
            <p style="margin:0.5rem 0 0;">&copy; 2026 Art-Official</p>
        </div>
    </div>`;

    try {
        await mailTransporter.sendMail({
            from: process.env.SMTP_FROM || process.env.SMTP_USER,
            to: artist.email,
            subject: `Your Art-Official Certificate: ${certificate.title} (${certificate.id})`,
            html
        });
    } catch (err) {
        console.error('Failed to send certificate email:', err.message);
    }
}

// API Routes

// Sanitise artist for client (strip password hash)
function safeArtist(artist) {
    const { passwordHash, stripeCustomerId, stripeSubscriptionId, ...safe } = artist;
    return safe;
}

// Register artist
app.post('/api/artist/register', async (req, res) => {
    const { name, email, password, portfolio, bio, location } = req.body;

    if (!password || password.length < 6) {
        return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    }

    const db = loadDB();

    const existingArtist = Object.values(db.artists).find(a => a.email === email);
    if (existingArtist) {
        return res.status(409).json({ success: false, message: 'An account with this email already exists. Please sign in.' });
    }

    const artistId = uuidv4();
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
    const passwordHash = await bcrypt.hash(password, 10);
    const artist = {
        id: artistId,
        name,
        email,
        portfolio: portfolio && portfolio.trim() && !/^https?:\/\//i.test(portfolio.trim()) ? 'https://' + portfolio.trim() : (portfolio || '').trim(),
        bio: bio || '',
        location: location || '',
        slug,
        passwordHash,
        plan: 'free',
        stripeCustomerId: null,
        stripeSubscriptionId: null,
        planStatus: 'active',
        planExpiresAt: null,
        createdAt: new Date().toISOString()
    };
    db.artists[artistId] = artist;
    saveDB(db);
    res.json({ success: true, artist: safeArtist(artist) });
});

// Sign in artist
app.post('/api/artist/login', async (req, res) => {
    const { email, password } = req.body;
    const db = loadDB();
    const artist = Object.values(db.artists).find(a => a.email === email);

    if (!artist) {
        return res.json({ success: false, message: 'No account found with that email.' });
    }

    // Backward compat: old accounts without passwords
    if (!artist.passwordHash) {
        return res.json({ success: true, artist: safeArtist(artist) });
    }

    const match = await bcrypt.compare(password, artist.passwordHash);
    if (!match) {
        return res.json({ success: false, message: 'Incorrect password.' });
    }

    res.json({ success: true, artist: safeArtist(artist) });
});

// Get artist public profile by slug
app.get('/api/artist/profile/:slug', (req, res) => {
    const { slug } = req.params;
    const db = loadDB();
    const artist = Object.values(db.artists).find(a => a.slug === slug);
    if (!artist) {
        return res.json({ success: false, message: 'Artist not found' });
    }

    const certificates = Object.values(db.certificates)
        .filter(c => c.artistId === artist.id)
        .sort((a, b) => new Date(b.registeredAt) - new Date(a.registeredAt));

    res.json({
        success: true,
        artist: {
            name: artist.name,
            bio: artist.bio,
            location: artist.location,
            portfolio: artist.portfolio,
            slug: artist.slug,
            memberSince: artist.createdAt,
            totalCertificates: certificates.length
        },
        certificates: certificates.map(c => ({
            id: c.id,
            title: c.title,
            medium: c.medium,
            tier: c.tier,
            creationDate: c.creationDate,
            registeredAt: c.registeredAt,
            thumbnailFile: getCertThumbnail(c)
        }))
    });
});

// Submit artwork for certification
app.post('/api/artwork/submit', artworkUpload, async (req, res) => {
    const { artistId, title, description, medium, creationDate, declaration, processNotes } = req.body;

    if (declaration !== 'true') {
        return res.status(400).json({ success: false, message: 'Declaration required' });
    }

    const db = loadDB();
    const artist = db.artists[artistId];

    if (!artist) {
        return res.status(404).json({ success: false, message: 'Artist not found' });
    }

    // Check work limit for Free tier
    if (!isCreator(artist)) {
        const existingCerts = Object.values(db.certificates).filter(c => c.artistId === artistId);
        if (existingCerts.length >= 3) {
            return res.status(403).json({
                success: false,
                message: 'Free plan limited to 3 works. Upgrade to Creator for unlimited certificates.',
                limitReached: true
            });
        }
    }

    // Artwork image (single file)
    const artworkImage = req.files && req.files['artworkImage'] && req.files['artworkImage'][0]
        ? req.files['artworkImage'][0].filename : null;

    // Evidence files with per-file visibility
    const rawEvidence = req.files && req.files['evidence'] ? req.files['evidence'] : [];
    let visibility = [];
    try {
        visibility = JSON.parse(req.body.evidenceVisibility || '[]');
    } catch (e) { /* default to empty */ }

    const evidenceFiles = rawEvidence.map((f, i) => ({
        filename: f.filename,
        public: visibility[i] === true
    }));

    const fileCount = (artworkImage ? 1 : 0) + rawEvidence.length;
    const tierResult = calculateTier(fileCount, description, !!processNotes);
    const certificateId = generateCertificateId();

    const certificate = {
        id: certificateId,
        artistId,
        artistName: artist.name,
        artistSlug: artist.slug,
        title,
        description,
        medium,
        creationDate,
        processNotes: processNotes || '',
        artworkImage,
        evidenceFiles,
        tier: tierResult.tier,
        tierLabel: tierResult.label,
        evidenceStrength: tierResult.strength,
        registeredAt: new Date().toISOString(),
        status: 'verified'
    };

    db.certificates[certificateId] = certificate;
    saveDB(db);

    // Send certificate email (non-blocking)
    const host = `${req.protocol}://${req.get('host')}`;
    sendCertificateEmail(artist, certificate, host);

    res.json({ success: true, certificate });
});

// Get certificates for an artist
app.get('/api/artist/:artistId/certificates', (req, res) => {
    const { artistId } = req.params;
    const db = loadDB();

    const certificates = Object.values(db.certificates)
        .filter(c => c.artistId === artistId)
        .sort((a, b) => new Date(b.registeredAt) - new Date(a.registeredAt));

    res.json({ success: true, certificates });
});

// Verify certificate (public)
app.get('/api/verify/:certificateId', (req, res) => {
    const { certificateId } = req.params;
    const db = loadDB();
    const certificate = db.certificates[certificateId.toUpperCase()];

    if (certificate) {
        res.json({
            success: true,
            verified: true,
            certificate: {
                id: certificate.id,
                artistName: certificate.artistName,
                artistSlug: certificate.artistSlug,
                title: certificate.title,
                description: certificate.description,
                medium: certificate.medium,
                creationDate: certificate.creationDate,
                registeredAt: certificate.registeredAt,
                status: certificate.status,
                tier: certificate.tier,
                tierLabel: certificate.tierLabel,
                evidenceStrength: certificate.evidenceStrength,
                evidenceCount: certificate.evidenceFiles ? certificate.evidenceFiles.length : 0,
                hasProcessNotes: !!certificate.processNotes,
                artworkImage: certificate.artworkImage || null,
                publicEvidenceFiles: getPublicEvidence(certificate),
                processNotes: certificate.processNotes || ''
            }
        });
    } else {
        res.json({ success: true, verified: false, message: 'Certificate not found' });
    }
});

// Generate QR code for certificate
app.get('/api/qr/:certificateId', async (req, res) => {
    const { certificateId } = req.params;
    const verifyUrl = `${req.protocol}://${req.get('host')}/verify.html?code=${certificateId}`;

    try {
        const qrDataUrl = await QRCode.toDataURL(verifyUrl, {
            width: 200,
            margin: 2,
            color: { dark: '#1a365d', light: '#fffef0' }
        });
        res.json({ success: true, qrCode: qrDataUrl, verifyUrl });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to generate QR code' });
    }
});

// Embeddable badge — returns an SVG badge for a certificate
app.get('/api/badge/:certificateId', (req, res) => {
    const { certificateId } = req.params;
    const db = loadDB();
    const cert = db.certificates[certificateId.toUpperCase()];

    if (!cert) {
        return res.status(404).send('Certificate not found');
    }

    const tierColors = {
        gold: { bg: '#b7960b', text: '#fffef0' },
        silver: { bg: '#718096', text: '#fffef0' },
        bronze: { bg: '#9c6b30', text: '#fffef0' }
    };
    const colors = tierColors[cert.tier] || tierColors.bronze;

    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="36" viewBox="0 0 200 36">
  <rect width="200" height="36" rx="4" fill="${colors.bg}"/>
  <rect x="1" y="1" width="198" height="34" rx="3" fill="none" stroke="${colors.text}" stroke-opacity="0.3"/>
  <text x="28" y="22" font-family="Georgia,serif" font-size="11" fill="${colors.text}" font-weight="bold">Art-Official</text>
  <text x="115" y="22" font-family="monospace" font-size="9" fill="${colors.text}" opacity="0.85">${cert.id}</text>
  <circle cx="14" cy="18" r="8" fill="${colors.text}" opacity="0.2"/>
  <text x="14" y="22" font-family="Georgia,serif" font-size="10" fill="${colors.text}" text-anchor="middle" font-weight="bold">AO</text>
</svg>`;

    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.send(svg);
});

// Embeddable widget — serves a self-contained HTML card
app.get('/api/widget/:certificateId', (req, res) => {
    const { certificateId } = req.params;
    const db = loadDB();
    const cert = db.certificates[certificateId.toUpperCase()];

    if (!cert) {
        res.setHeader('Content-Type', 'text/html');
        return res.send('<html><body style="margin:0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100%;color:#718096;font-size:14px;">Certificate not found</body></html>');
    }

    const host = `${req.protocol}://${req.get('host')}`;
    const verifyUrl = `${host}/verify.html?code=${cert.id}`;
    const tierColors = { gold: '#b7960b', silver: '#718096', bronze: '#9c6b30' };
    const tierBgs = { gold: '#f5efd0', silver: '#e8edf2', bronze: '#f0e6d8' };
    const tc = tierColors[cert.tier] || tierColors.bronze;
    const tb = tierBgs[cert.tier] || tierBgs.bronze;
    const tierLabel = cert.tierLabel || cert.tier || 'Bronze';
    const thumbnail = cert.artworkImage ? `${host}/uploads/${cert.artworkImage}` : null;

    const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:transparent}
a{text-decoration:none;color:inherit}
.card{border:1px solid rgba(26,54,93,0.12);border-radius:10px;overflow:hidden;background:#fff;max-width:340px;box-shadow:0 1px 4px rgba(0,0,0,0.06)}
.card:hover{box-shadow:0 2px 8px rgba(0,0,0,0.1)}
.header{background:#1a365d;color:#fffef0;padding:0.6rem 1rem;display:flex;align-items:center;justify-content:space-between}
.logo{font-family:Georgia,serif;font-weight:700;font-size:0.95rem}
.logo span{color:#d4af37}
.check{background:rgba(255,254,240,0.15);border-radius:100px;padding:0.15rem 0.6rem;font-size:0.65rem;letter-spacing:0.04em}
.body{padding:1rem;display:flex;gap:0.85rem;align-items:flex-start}
.thumb{width:64px;height:64px;border-radius:6px;object-fit:cover;background:#f7f5e6;flex-shrink:0}
.thumb-placeholder{width:64px;height:64px;border-radius:6px;background:#f7f5e6;flex-shrink:0;display:flex;align-items:center;justify-content:center;color:#a0aec0;font-family:Georgia,serif;font-size:1.2rem;font-weight:700}
.info{flex:1;min-width:0}
.title{font-weight:600;color:#1a365d;font-size:0.88rem;line-height:1.3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.artist{color:#718096;font-size:0.78rem;margin-top:0.15rem}
.meta{display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem}
.tier{padding:0.15rem 0.55rem;border-radius:100px;font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.04em}
.cert-id{font-family:monospace;font-size:0.68rem;color:#a0aec0;letter-spacing:0.04em}
.footer{border-top:1px solid rgba(26,54,93,0.06);padding:0.5rem 1rem;text-align:center;font-size:0.65rem;color:#a0aec0}
</style></head>
<body><a href="${verifyUrl}" target="_blank" rel="noopener">
<div class="card">
  <div class="header">
    <div class="logo">Art-<span>Official</span></div>
    <div class="check">&#10003; Verified</div>
  </div>
  <div class="body">
    ${thumbnail
      ? `<img class="thumb" src="${thumbnail}" alt="">`
      : `<div class="thumb-placeholder">AO</div>`}
    <div class="info">
      <div class="title">${cert.title || 'Untitled'}</div>
      <div class="artist">by ${cert.artistName || 'Unknown'}</div>
      <div class="meta">
        <span class="tier" style="background:${tb};color:${tc}">${tierLabel}</span>
        <span class="cert-id">${cert.id}</span>
      </div>
    </div>
  </div>
  <div class="footer">Click to verify &middot; Certified Human Creation</div>
</div>
</a></body></html>`;

    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(html);
});

// Embed code endpoint
app.get('/api/embed/:certificateId', (req, res) => {
    const { certificateId } = req.params;
    const host = `${req.protocol}://${req.get('host')}`;
    const badgeUrl = `${host}/api/badge/${certificateId}`;
    const verifyUrl = `${host}/verify.html?code=${certificateId}`;
    const widgetUrl = `${host}/api/widget/${certificateId}`;

    res.json({
        success: true,
        html: `<a href="${verifyUrl}" target="_blank" rel="noopener"><img src="${badgeUrl}" alt="Verified Art-Official" style="height:36px"></a>`,
        markdown: `[![Verified Art-Official](${badgeUrl})](${verifyUrl})`,
        widget: `<iframe src="${widgetUrl}" width="340" height="160" style="border:none;border-radius:10px;" loading="lazy"></iframe>`,
        badgeUrl,
        verifyUrl,
        widgetUrl
    });
});

// Stripe config (publishable key for frontend)
app.get('/api/config', (req, res) => {
    res.json({
        stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY || null
    });
});

// Get artist plan info
app.get('/api/artist/plan/:artistId', (req, res) => {
    const { artistId } = req.params;
    const db = loadDB();
    const artist = db.artists[artistId];
    if (!artist) return res.status(404).json({ success: false, message: 'Artist not found' });

    const certCount = Object.values(db.certificates).filter(c => c.artistId === artistId).length;
    const plan = getEffectivePlan(artist);

    res.json({
        success: true,
        plan,
        planStatus: artist.planStatus || 'active',
        planExpiresAt: artist.planExpiresAt || null,
        certificateCount: certCount,
        certificateLimit: plan === 'creator' ? null : 3
    });
});

// Create Stripe subscription
app.post('/api/stripe/create-subscription', async (req, res) => {
    if (!stripe) return res.status(400).json({ success: false, message: 'Payments not configured' });

    const { artistId } = req.body;
    const db = loadDB();
    const artist = db.artists[artistId];
    if (!artist) return res.status(404).json({ success: false, message: 'Artist not found' });

    try {
        let customerId = artist.stripeCustomerId;
        if (!customerId) {
            const customer = await stripe.customers.create({
                email: artist.email,
                name: artist.name,
                metadata: { artistId: artist.id }
            });
            customerId = customer.id;
            artist.stripeCustomerId = customerId;
            saveDB(db);
        }

        const subscription = await stripe.subscriptions.create({
            customer: customerId,
            items: [{ price: process.env.STRIPE_CREATOR_PRICE_ID }],
            payment_behavior: 'default_incomplete',
            payment_settings: { save_default_payment_method: 'on_subscription' },
            expand: ['latest_invoice.payment_intent']
        });

        artist.stripeSubscriptionId = subscription.id;
        saveDB(db);

        res.json({
            success: true,
            subscriptionId: subscription.id,
            clientSecret: subscription.latest_invoice.payment_intent.client_secret
        });
    } catch (err) {
        console.error('Stripe create subscription error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to create subscription: ' + err.message });
    }
});

// Cancel Stripe subscription
app.post('/api/stripe/cancel-subscription', async (req, res) => {
    if (!stripe) return res.status(400).json({ success: false, message: 'Payments not configured' });

    const { artistId } = req.body;
    const db = loadDB();
    const artist = db.artists[artistId];
    if (!artist || !artist.stripeSubscriptionId) {
        return res.status(400).json({ success: false, message: 'No active subscription found' });
    }

    try {
        const subscription = await stripe.subscriptions.update(artist.stripeSubscriptionId, {
            cancel_at_period_end: true
        });

        artist.planStatus = 'canceling';
        artist.planExpiresAt = new Date(subscription.current_period_end * 1000).toISOString();
        saveDB(db);

        res.json({
            success: true,
            message: 'Subscription will cancel at end of billing period',
            planExpiresAt: artist.planExpiresAt
        });
    } catch (err) {
        console.error('Stripe cancel error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to cancel subscription' });
    }
});

// Stats endpoint
app.get('/api/stats', (req, res) => {
    const db = loadDB();
    const artists = Object.keys(db.artists).length;
    const certificates = Object.keys(db.certificates).length;
    const tiers = { gold: 0, silver: 0, bronze: 0 };
    Object.values(db.certificates).forEach(c => {
        if (tiers[c.tier] !== undefined) tiers[c.tier]++;
    });
    res.json({ success: true, artists, certificates, tiers });
});

app.listen(PORT, () => {
    console.log(`Art-Official server running at http://localhost:${PORT}`);
});
