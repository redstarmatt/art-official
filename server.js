const express = require('express');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

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

// API Routes

// Register artist
app.post('/api/artist/register', (req, res) => {
    const { name, email, portfolio, bio, location } = req.body;
    const db = loadDB();

    const existingArtist = Object.values(db.artists).find(a => a.email === email);
    if (existingArtist) {
        return res.json({ success: true, artist: existingArtist });
    }

    const artistId = uuidv4();
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
    const artist = {
        id: artistId,
        name,
        email,
        portfolio,
        bio: bio || '',
        location: location || '',
        slug,
        createdAt: new Date().toISOString()
    };
    db.artists[artistId] = artist;
    saveDB(db);
    res.json({ success: true, artist });
});

// Get artist by email
app.get('/api/artist/lookup', (req, res) => {
    const { email } = req.query;
    const db = loadDB();
    const artist = Object.values(db.artists).find(a => a.email === email);
    if (artist) {
        res.json({ success: true, artist });
    } else {
        res.json({ success: false, message: 'Artist not found' });
    }
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

// Embed code endpoint
app.get('/api/embed/:certificateId', (req, res) => {
    const { certificateId } = req.params;
    const host = `${req.protocol}://${req.get('host')}`;
    const badgeUrl = `${host}/api/badge/${certificateId}`;
    const verifyUrl = `${host}/verify.html?code=${certificateId}`;

    res.json({
        success: true,
        html: `<a href="${verifyUrl}" target="_blank" rel="noopener"><img src="${badgeUrl}" alt="Verified Art-Official" style="height:36px"></a>`,
        markdown: `[![Verified Art-Official](${badgeUrl})](${verifyUrl})`,
        badgeUrl,
        verifyUrl
    });
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
