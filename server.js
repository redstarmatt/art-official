process.on('uncaughtException', (err) => { console.error('UNCAUGHT:', err); process.exit(1); });

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const Stripe = require('stripe');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const session = require('express-session');
const SqliteStore = require('better-sqlite3-session-store')(session);
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

const app = express();
const PORT = process.env.PORT || 3000;

// Railway handles HTTPS at the proxy level — trust the forwarded proto header
app.set('trust proxy', true);

// Persistent storage — use /app/persist on Railway, local dirs for dev
const PERSIST_DIR = fs.existsSync('/app/persist') ? '/app/persist' : '.';
const DATA_DIR = path.join(PERSIST_DIR, 'data');
const UPLOADS_DIR = path.join(PERSIST_DIR, 'uploads');

const BACKUPS_DIR = path.join(PERSIST_DIR, 'backups');

// Ensure directories exist
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR, { recursive: true });

// ============================================================
// Phase 1: SQLite Database
// ============================================================
const DB_PATH = path.join(DATA_DIR, 'officallyhuman.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
CREATE TABLE IF NOT EXISTS artists (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  bio TEXT DEFAULT '',
  location TEXT DEFAULT '',
  portfolio TEXT DEFAULT '',
  slug TEXT NOT NULL,
  plan TEXT DEFAULT 'free',
  plan_status TEXT DEFAULT 'active',
  plan_expires_at TEXT,
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  certificate_credits INTEGER DEFAULT 0,
  reset_token TEXT,
  reset_token_expires TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
  id TEXT PRIMARY KEY,
  artist_id TEXT NOT NULL REFERENCES artists(id),
  artist_name TEXT NOT NULL,
  artist_slug TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  medium TEXT,
  creation_date TEXT,
  process_notes TEXT DEFAULT '',
  artwork_image TEXT,
  tier TEXT NOT NULL,
  tier_label TEXT NOT NULL,
  evidence_strength INTEGER,
  status TEXT DEFAULT 'verified',
  report_count INTEGER DEFAULT 0,
  registered_at TEXT NOT NULL,
  FOREIGN KEY (artist_id) REFERENCES artists(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  certificate_id TEXT NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  is_public INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS certificate_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  certificate_id TEXT NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  fields TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  certificate_id TEXT NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  reporter_email TEXT,
  status TEXT DEFAULT 'pending',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT NOT NULL,
  timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  sid TEXT NOT NULL PRIMARY KEY,
  sess JSON NOT NULL,
  expire TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS newsletter_subscribers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  source TEXT DEFAULT 'website',
  subscribed_at TEXT NOT NULL,
  unsubscribed_at TEXT
);

CREATE TABLE IF NOT EXISTS page_views (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  page TEXT NOT NULL,
  referrer TEXT DEFAULT '',
  date TEXT NOT NULL
);
`);

// Add columns for email verification, retention, reports — safe to re-run (ALTER TABLE IF NOT EXISTS pattern)
const addColumnIfMissing = (table, column, type) => {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
    if (!cols.includes(column)) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
    }
};
addColumnIfMissing('artists', 'email_verified', 'INTEGER DEFAULT 0');
addColumnIfMissing('artists', 'verification_token', 'TEXT');
addColumnIfMissing('artists', 'last_login_at', 'TEXT');
addColumnIfMissing('artists', 'deletion_warning_sent_at', 'TEXT');
addColumnIfMissing('artists', 'banned', 'INTEGER DEFAULT 0');
addColumnIfMissing('artists', 'ban_reason', 'TEXT');
addColumnIfMissing('reports', 'resolution', 'TEXT');
addColumnIfMissing('reports', 'resolved_at', 'TEXT');
addColumnIfMissing('reports', 'type', "TEXT DEFAULT 'dispute'");
addColumnIfMissing('artists', 'certificate_credits', 'INTEGER DEFAULT 0');

// Create indexes (IF NOT EXISTS)
db.exec(`
CREATE INDEX IF NOT EXISTS idx_artists_email ON artists(email);
CREATE INDEX IF NOT EXISTS idx_artists_slug ON artists(slug);
CREATE INDEX IF NOT EXISTS idx_certificates_artist ON certificates(artist_id);
CREATE INDEX IF NOT EXISTS idx_evidence_cert ON evidence_files(certificate_id);
CREATE INDEX IF NOT EXISTS idx_history_cert ON certificate_history(certificate_id);
CREATE INDEX IF NOT EXISTS idx_reports_cert ON reports(certificate_id);
CREATE INDEX IF NOT EXISTS idx_rate_key_time ON rate_limits(key, timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(expire);
CREATE INDEX IF NOT EXISTS idx_newsletter_email ON newsletter_subscribers(email);
CREATE INDEX IF NOT EXISTS idx_page_views_date ON page_views(date);
CREATE INDEX IF NOT EXISTS idx_page_views_page ON page_views(page);
`);

// ============================================================
// JSON -> SQLite Migration
// ============================================================
const JSON_DB_FILE = path.join(DATA_DIR, 'db.json');
if (fs.existsSync(JSON_DB_FILE)) {
    const artistCount = db.prepare('SELECT COUNT(*) as n FROM artists').get().n;
    if (artistCount === 0) {
        console.log('Migrating data from db.json to SQLite...');
        const jsonDb = JSON.parse(fs.readFileSync(JSON_DB_FILE, 'utf8'));
        if (!jsonDb.reports) jsonDb.reports = {};

        const migrateAll = db.transaction(() => {
            // Migrate artists
            const insertArtist = db.prepare(`INSERT OR IGNORE INTO artists
                (id, name, email, password_hash, bio, location, portfolio, slug, plan, plan_status, plan_expires_at, stripe_customer_id, stripe_subscription_id, reset_token, reset_token_expires, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
            for (const artist of Object.values(jsonDb.artists)) {
                insertArtist.run(
                    artist.id, artist.name, artist.email, artist.passwordHash || null,
                    artist.bio || '', artist.location || '', artist.portfolio || '',
                    artist.slug || '', artist.plan || 'free', artist.planStatus || 'active',
                    artist.planExpiresAt || null, artist.stripeCustomerId || null,
                    artist.stripeSubscriptionId || null, artist.resetToken || null,
                    artist.resetTokenExpires || null, artist.createdAt || new Date().toISOString()
                );
            }

            // Migrate certificates
            const insertCert = db.prepare(`INSERT OR IGNORE INTO certificates
                (id, artist_id, artist_name, artist_slug, title, description, medium, creation_date, process_notes, artwork_image, tier, tier_label, evidence_strength, status, report_count, registered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
            const insertEvidence = db.prepare(`INSERT INTO evidence_files (certificate_id, filename, is_public) VALUES (?, ?, ?)`);
            const insertHistory = db.prepare(`INSERT INTO certificate_history (certificate_id, type, fields, created_at) VALUES (?, ?, ?, ?)`);

            for (const cert of Object.values(jsonDb.certificates)) {
                insertCert.run(
                    cert.id, cert.artistId, cert.artistName, cert.artistSlug || '',
                    cert.title, cert.description || '', cert.medium || '', cert.creationDate || '',
                    cert.processNotes || '', cert.artworkImage || null,
                    cert.tier || 'bronze', cert.tierLabel || 'Bronze', cert.evidenceStrength || 40,
                    cert.status || 'verified', cert.reportCount || 0, cert.registeredAt || new Date().toISOString()
                );

                // Migrate evidence files
                if (cert.evidenceFiles && cert.evidenceFiles.length > 0) {
                    for (const ef of cert.evidenceFiles) {
                        if (typeof ef === 'string') {
                            insertEvidence.run(cert.id, ef, 1); // old format: treat as public
                        } else {
                            insertEvidence.run(cert.id, ef.filename, ef.public ? 1 : 0);
                        }
                    }
                }

                // Migrate history
                if (cert.history && cert.history.length > 0) {
                    for (const h of cert.history) {
                        insertHistory.run(cert.id, h.type, h.fields ? JSON.stringify(h.fields) : null, h.at || new Date().toISOString());
                    }
                }
            }

            // Migrate reports
            const insertReport = db.prepare(`INSERT OR IGNORE INTO reports (id, certificate_id, reason, reporter_email, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`);
            for (const report of Object.values(jsonDb.reports)) {
                insertReport.run(
                    report.id, report.certificateId, report.reason,
                    report.reporterEmail || null, report.status || 'pending',
                    report.createdAt || new Date().toISOString()
                );
            }
        });

        migrateAll();
        // Rename old JSON file as backup
        fs.renameSync(JSON_DB_FILE, JSON_DB_FILE + '.migrated');
        console.log('Migration complete. Old db.json renamed to db.json.migrated');
    }
}

// ============================================================
// Prepared statements
// ============================================================
const stmts = {
    getArtistById: db.prepare('SELECT * FROM artists WHERE id = ?'),
    getArtistByEmail: db.prepare('SELECT * FROM artists WHERE email = ?'),
    getArtistBySlug: db.prepare('SELECT * FROM artists WHERE slug = ?'),
    getArtistByStripeCustomer: db.prepare('SELECT * FROM artists WHERE stripe_customer_id = ?'),
    getArtistByResetToken: db.prepare('SELECT * FROM artists WHERE reset_token = ? AND reset_token_expires > ?'),
    insertArtist: db.prepare(`INSERT INTO artists (id, name, email, password_hash, bio, location, portfolio, slug, plan, plan_status, plan_expires_at, stripe_customer_id, stripe_subscription_id, reset_token, reset_token_expires, created_at)
        VALUES (@id, @name, @email, @password_hash, @bio, @location, @portfolio, @slug, @plan, @plan_status, @plan_expires_at, @stripe_customer_id, @stripe_subscription_id, @reset_token, @reset_token_expires, @created_at)`),
    updateArtistProfile: db.prepare('UPDATE artists SET name = ?, bio = ?, location = ?, portfolio = ?, slug = ? WHERE id = ?'),
    updateArtistPlan: db.prepare('UPDATE artists SET plan = ?, plan_status = ?, plan_expires_at = ? WHERE id = ?'),
    updateArtistStripeCustomer: db.prepare('UPDATE artists SET stripe_customer_id = ? WHERE id = ?'),
    updateArtistStripeSubscription: db.prepare('UPDATE artists SET stripe_subscription_id = ? WHERE id = ?'),
    updateArtistResetToken: db.prepare('UPDATE artists SET reset_token = ?, reset_token_expires = ? WHERE id = ?'),
    updateArtistPassword: db.prepare('UPDATE artists SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?'),
    deleteArtist: db.prepare('DELETE FROM artists WHERE id = ?'),

    getCertById: db.prepare('SELECT * FROM certificates WHERE id = ?'),
    getCertsByArtist: db.prepare('SELECT * FROM certificates WHERE artist_id = ? ORDER BY registered_at DESC'),
    countCertsByArtist: db.prepare('SELECT COUNT(*) as n FROM certificates WHERE artist_id = ?'),
    insertCert: db.prepare(`INSERT INTO certificates (id, artist_id, artist_name, artist_slug, title, description, medium, creation_date, process_notes, artwork_image, tier, tier_label, evidence_strength, status, report_count, registered_at)
        VALUES (@id, @artist_id, @artist_name, @artist_slug, @title, @description, @medium, @creation_date, @process_notes, @artwork_image, @tier, @tier_label, @evidence_strength, @status, @report_count, @registered_at)`),
    updateCert: db.prepare('UPDATE certificates SET title = ?, description = ?, process_notes = ?, tier = ?, tier_label = ?, evidence_strength = ?, artist_name = ? WHERE id = ?'),
    updateCertReportCount: db.prepare('UPDATE certificates SET report_count = report_count + 1 WHERE id = ?'),
    deleteCert: db.prepare('DELETE FROM certificates WHERE id = ?'),
    deleteCertsByArtist: db.prepare('DELETE FROM certificates WHERE artist_id = ?'),

    getEvidenceFiles: db.prepare('SELECT * FROM evidence_files WHERE certificate_id = ?'),
    insertEvidence: db.prepare('INSERT INTO evidence_files (certificate_id, filename, is_public) VALUES (?, ?, ?)'),
    deleteEvidenceByArtist: db.prepare('DELETE FROM evidence_files WHERE certificate_id IN (SELECT id FROM certificates WHERE artist_id = ?)'),

    getHistory: db.prepare('SELECT * FROM certificate_history WHERE certificate_id = ? ORDER BY created_at ASC'),
    insertHistory: db.prepare('INSERT INTO certificate_history (certificate_id, type, fields, created_at) VALUES (?, ?, ?, ?)'),
    deleteHistoryByArtist: db.prepare('DELETE FROM certificate_history WHERE certificate_id IN (SELECT id FROM certificates WHERE artist_id = ?)'),

    insertReport: db.prepare('INSERT INTO reports (id, certificate_id, reason, reporter_email, status, created_at) VALUES (?, ?, ?, ?, ?, ?)'),
    deleteReportsByArtist: db.prepare('DELETE FROM reports WHERE certificate_id IN (SELECT id FROM certificates WHERE artist_id = ?)'),

    // Browse queries
    browseCerts: db.prepare('SELECT * FROM certificates WHERE status = ? ORDER BY registered_at DESC'),
    browseCertsFilterMedium: db.prepare('SELECT * FROM certificates WHERE status = ? AND medium = ? ORDER BY registered_at DESC'),
    browseCertsFilterTier: db.prepare('SELECT * FROM certificates WHERE status = ? AND tier = ? ORDER BY registered_at DESC'),
    browseCertsFilterBoth: db.prepare('SELECT * FROM certificates WHERE status = ? AND medium = ? AND tier = ? ORDER BY registered_at DESC'),
    allMediums: db.prepare('SELECT DISTINCT medium FROM certificates WHERE medium IS NOT NULL AND medium != \'\' ORDER BY medium'),

    // Stats
    countArtists: db.prepare('SELECT COUNT(*) as n FROM artists'),
    countCerts: db.prepare('SELECT COUNT(*) as n FROM certificates'),
    countTiers: db.prepare('SELECT tier, COUNT(*) as n FROM certificates GROUP BY tier'),

    // Find certificate by artwork image or evidence filename
    findCertByArtworkImage: db.prepare('SELECT * FROM certificates WHERE artwork_image = ?'),
    findEvidenceFile: db.prepare('SELECT ef.*, c.artist_id FROM evidence_files ef JOIN certificates c ON ef.certificate_id = c.id WHERE ef.filename = ?'),

    // Email verification
    updateArtistVerification: db.prepare('UPDATE artists SET email_verified = ?, verification_token = ? WHERE id = ?'),
    getArtistByVerificationToken: db.prepare('SELECT * FROM artists WHERE verification_token = ?'),

    // Login tracking
    updateLastLogin: db.prepare('UPDATE artists SET last_login_at = ? WHERE id = ?'),

    // Data retention
    getInactiveAccounts: db.prepare(`SELECT a.* FROM artists a LEFT JOIN certificates c ON c.artist_id = a.id WHERE a.last_login_at < ? AND c.id IS NULL GROUP BY a.id`),

    // Admin: reports
    getAllReports: db.prepare(`SELECT r.*, c.title AS cert_title, c.artist_id, c.artist_name FROM reports r JOIN certificates c ON r.certificate_id = c.id ORDER BY r.created_at DESC`),
    getReportById: db.prepare('SELECT * FROM reports WHERE id = ?'),
    updateReportResolution: db.prepare('UPDATE reports SET resolution = ?, resolved_at = ?, status = ? WHERE id = ?'),

    // Admin: certificate revocation
    updateCertStatus: db.prepare('UPDATE certificates SET status = ? WHERE id = ?'),

    // Certificate credits
    incrementCertificateCredits: db.prepare('UPDATE artists SET certificate_credits = certificate_credits + 1 WHERE id = ?'),

    // Admin: list all artists with cert counts
    getAllArtists: db.prepare(`
        SELECT a.*, COUNT(c.id) as cert_count
        FROM artists a
        LEFT JOIN certificates c ON c.artist_id = a.id
        GROUP BY a.id
        ORDER BY a.created_at DESC
    `),

    // Admin: list all certificates
    getAllCerts: db.prepare('SELECT * FROM certificates ORDER BY registered_at DESC'),
};

// Helper: convert DB row to artist object with camelCase
function rowToArtist(row) {
    if (!row) return null;
    return {
        id: row.id, name: row.name, email: row.email, passwordHash: row.password_hash,
        bio: row.bio, location: row.location, portfolio: row.portfolio, slug: row.slug,
        plan: row.plan, planStatus: row.plan_status, planExpiresAt: row.plan_expires_at,
        stripeCustomerId: row.stripe_customer_id, stripeSubscriptionId: row.stripe_subscription_id,
        resetToken: row.reset_token, resetTokenExpires: row.reset_token_expires,
        createdAt: row.created_at,
        emailVerified: row.email_verified === 1,
        verificationToken: row.verification_token,
        lastLoginAt: row.last_login_at,
        deletionWarningSentAt: row.deletion_warning_sent_at,
        banned: row.banned === 1,
        banReason: row.ban_reason || null,
        certificateCredits: row.certificate_credits || 0
    };
}

// Helper: convert DB row to certificate object with camelCase
function rowToCert(row) {
    if (!row) return null;
    return {
        id: row.id, artistId: row.artist_id, artistName: row.artist_name, artistSlug: row.artist_slug,
        title: row.title, description: row.description, medium: row.medium,
        creationDate: row.creation_date, processNotes: row.process_notes,
        artworkImage: row.artwork_image, tier: row.tier, tierLabel: row.tier_label,
        evidenceStrength: row.evidence_strength, status: row.status,
        reportCount: row.report_count, registeredAt: row.registered_at
    };
}

// Helper: get evidence files for a cert, returning the camelCase format
function getEvidenceForCert(certId) {
    const rows = stmts.getEvidenceFiles.all(certId);
    return rows.map(r => ({ filename: r.filename, public: r.is_public === 1 }));
}

// Helper: get public evidence filenames
function getPublicEvidence(certId) {
    return stmts.getEvidenceFiles.all(certId)
        .filter(r => r.is_public === 1)
        .map(r => r.filename);
}

// Helper: get thumbnail for cert
function getCertThumbnail(cert) {
    if (cert.artworkImage || cert.artwork_image) return cert.artworkImage || cert.artwork_image;
    const files = stmts.getEvidenceFiles.all(cert.id);
    return files.length > 0 ? files[0].filename : null;
}

// ============================================================
// Phase 4: Persistent Rate Limiting
// ============================================================
function rateLimit(key, maxAttempts, windowMs) {
    const cutoff = Date.now() - windowMs;
    db.prepare('DELETE FROM rate_limits WHERE key = ? AND timestamp < ?').run(key, cutoff);
    const count = db.prepare('SELECT COUNT(*) as n FROM rate_limits WHERE key = ? AND timestamp >= ?').get(key, cutoff).n;
    if (count >= maxAttempts) return false;
    db.prepare('INSERT INTO rate_limits (key, timestamp) VALUES (?, ?)').run(key, Date.now());
    return true;
}

// Periodic cleanup of expired rate limit entries (every 15 minutes)
setInterval(() => {
    db.prepare('DELETE FROM rate_limits WHERE timestamp < ?').run(Date.now() - 3600000);
}, 900000);

// ============================================================
// Basic auth gate — set SITE_PASSWORD env var to enable
// ============================================================
if (process.env.SITE_PASSWORD) {
    app.use((req, res, next) => {
        if (req.path === '/api/webhooks/stripe') return next();
        if (req.path.startsWith('/api/badge/') || req.path.startsWith('/api/widget/')) return next();

        const auth = req.headers.authorization;
        if (auth) {
            const [scheme, encoded] = auth.split(' ');
            if (scheme === 'Basic') {
                const [user, pass] = Buffer.from(encoded, 'base64').toString().split(':');
                if (pass === process.env.SITE_PASSWORD) return next();
            }
        }
        res.setHeader('WWW-Authenticate', 'Basic realm="Officially Human Art (Preview)"');
        res.status(401).send('Authentication required');
    });
    console.log('Site password protection enabled');
}

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://js.stripe.com", "https://www.googletagmanager.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "blob:"],
            mediaSrc: ["'self'"],
            fontSrc: ["'self'"],
            connectSrc: ["'self'", "https://api.stripe.com", "https://www.google-analytics.com", "https://www.googletagmanager.com", "https://analytics.google.com"],
            frameSrc: ["'self'", "https://js.stripe.com"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Common weak passwords (top 50)
const COMMON_PASSWORDS = new Set([
    'password', '123456', '12345678', '123456789', '1234567890', 'qwerty', 'abc123',
    'password1', '111111', 'iloveyou', 'sunshine', 'princess', 'football', 'charlie',
    'shadow', 'michael', 'master', 'letmein', 'dragon', 'monkey', 'trustno1',
    'baseball', 'access', 'hello', 'welcome', 'qwerty123', 'password123', '1q2w3e4r',
    '1234', '12345', 'admin', 'login', 'passw0rd', 'starwars', '654321', 'batman',
    'qwerty1', 'ashley', 'mustang', 'bailey', 'passpass', 'buster', 'andrew',
    'jordan', 'thomas', 'hockey', 'ranger', 'daniel', 'hunter', 'superman'
]);

function validatePassword(password) {
    if (!password || password.length < 8) {
        return 'Password must be at least 8 characters.';
    }
    if (COMMON_PASSWORDS.has(password.toLowerCase())) {
        return 'That password is too common. Please choose a stronger password.';
    }
    return null;
}

// Input length limits
const MAX_LENGTHS = {
    name: 100, email: 254, bio: 1000, location: 100, portfolio: 500,
    title: 200, description: 5000, processNotes: 5000, reportReason: 2000
};

function truncate(str, max) {
    if (!str) return str;
    return str.length > max ? str.slice(0, max) : str;
}

// Stripe setup
const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;
if (stripe) console.log('Stripe payments enabled');

// ============================================================
// Stripe webhook — must be before express.json()
// ============================================================
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

    switch (event.type) {
        case 'invoice.paid': {
            const invoice = event.data.object;
            const artist = rowToArtist(stmts.getArtistByStripeCustomer.get(invoice.customer));
            if (artist) {
                stmts.updateArtistPlan.run('creator', 'active', null, artist.id);
            }
            break;
        }
        case 'customer.subscription.updated': {
            const subscription = event.data.object;
            const artist = rowToArtist(stmts.getArtistByStripeCustomer.get(subscription.customer));
            if (artist) {
                if (subscription.cancel_at_period_end) {
                    const periodEnd = subscription.current_period_end
                        ? new Date(subscription.current_period_end * 1000).toISOString()
                        : null;
                    stmts.updateArtistPlan.run('creator', 'canceling', periodEnd, artist.id);
                } else {
                    stmts.updateArtistPlan.run('creator', 'active', null, artist.id);
                }
            }
            break;
        }
        case 'customer.subscription.deleted': {
            const subscription = event.data.object;
            const artist = rowToArtist(stmts.getArtistByStripeCustomer.get(subscription.customer));
            if (artist) {
                stmts.updateArtistPlan.run('free', 'expired', null, artist.id);
                stmts.updateArtistStripeSubscription.run(null, artist.id);
                // Notify the artist their subscription has ended
                if (emailEnabled) {
                    const certCount = stmts.countCertsByArtist.get(artist.id).n;
                    sendEmail({
                        from: process.env.SMTP_FROM || process.env.SMTP_USER,
                        to: artist.email,
                        subject: 'Your Officially Human Art subscription has ended',
                        html: `<div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#f5f0e8;">
                            <div style="background:#2a2520;color:#fafafa;padding:2rem;text-align:center;">
                                <div style="font-family:Inter,-apple-system,sans-serif;font-size:1.2rem;font-weight:600;"><span style="font-weight:300;color:#999;">officially</span><span style="font-weight:600;">human</span><span style="font-weight:700;font-size:1.5rem;">.art</span></div>
                            </div>
                            <div style="padding:2rem;">
                                <p style="color:#666666;margin-bottom:1rem;">Hi ${artist.name},</p>
                                <p style="color:#666666;margin-bottom:1rem;">Your Creator subscription has ended. Your account has been moved to the Free plan.</p>
                                <p style="color:#666666;margin-bottom:1rem;"><strong>Your ${certCount} existing certificate${certCount !== 1 ? 's remain' : ' remains'} fully active.</strong> All badges, QR codes, and verification pages continue to work as normal. Nothing has been removed.</p>
                                <p style="color:#666666;margin-bottom:1rem;">On the Free plan, you can maintain up to 3 certified works. To certify unlimited works again, you can resubscribe at any time from your dashboard.</p>
                                <div style="text-align:center;margin:2rem 0;">
                                    <a href="${process.env.BASE_URL || 'https://officiallyhuman.art'}/register.html" style="display:inline-block;padding:0.75rem 2rem;background:#2a2520;color:#fafafa;text-decoration:none;border-radius:6px;font-weight:600;font-size:0.9rem;">Go to Dashboard</a>
                                </div>
                                <p style="color:#888888;font-size:0.85rem;">Thanks for supporting Officially Human Art. We hope to see you back.</p>
                            </div>
                            <div style="background:#ebe5da;padding:1rem;text-align:center;font-size:0.75rem;color:#a0aec0;border-top:1px solid rgba(26,26,26,0.06);">
                                <p style="margin:0;">&copy; 2026 Officially Human Art</p>
                            </div>
                        </div>`
                    }).catch(err => console.error('Failed to send subscription ended email:', err.message));
                }
            }
            break;
        }
        case 'checkout.session.completed': {
            const session = event.data.object;
            if (session.metadata && session.metadata.type === 'certificate_credit' && session.payment_status === 'paid') {
                const artistId = session.metadata.artistId;
                stmts.incrementCertificateCredits.run(artistId);
                console.log(`Certificate credit added for artist ${artistId}`);
            }
            // Handle subscription checkout
            if (session.mode === 'subscription' && session.metadata && session.metadata.artistId) {
                const artistId = session.metadata.artistId;
                const subscriptionId = session.subscription;
                if (subscriptionId) {
                    stmts.updateArtistStripeSubscription.run(subscriptionId, artistId);
                    stmts.updateArtistPlan.run('creator', 'active', null, artistId);
                    console.log(`Creator subscription activated for artist ${artistId} via Checkout`);

                    // Send confirmation email
                    const artist = rowToArtist(stmts.getArtistById.get(artistId));
                    if (artist && emailEnabled) {
                        sendEmail({
                            from: process.env.SMTP_FROM || process.env.SMTP_USER,
                            to: artist.email,
                            subject: 'Welcome to the Creator Plan — Officially Human Art',
                            html: `
                            <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#f5f0e8;">
                                <div style="background:#2a2520;color:#fafafa;padding:2rem;text-align:center;">
                                    <div style="font-family:Inter,-apple-system,sans-serif;font-size:1.2rem;font-weight:600;"><span style="font-weight:300;color:#999;">officially</span><span style="font-weight:600;">human</span><span style="font-weight:700;font-size:1.5rem;">.art</span></div>
                                </div>
                                <div style="padding:2rem;">
                                    <p style="color:#666666;margin-bottom:1.5rem;">Hi ${artist.name},</p>
                                    <p style="color:#666666;margin-bottom:1.5rem;">Your Creator plan is now active. You have <strong>unlimited certificates</strong> for as long as your subscription is active.</p>
                                    <p style="color:#666666;margin-bottom:1.5rem;">You can manage your subscription from your dashboard at any time.</p>
                                    <div style="text-align:center;margin-bottom:1.5rem;">
                                        <a href="${req.protocol}://${req.get('host')}/register.html#dashboard" style="display:inline-block;padding:0.75rem 2rem;background:#2a2520;color:#fafafa;text-decoration:none;border-radius:6px;font-weight:600;font-size:0.9rem;">Go to Dashboard</a>
                                    </div>
                                    <p style="color:#888888;font-size:0.82rem;">Thank you for supporting Officially Human Art.</p>
                                </div>
                                <div style="background:#ebe5da;padding:1.25rem;text-align:center;font-size:0.75rem;color:#a0aec0;border-top:1px solid rgba(26,26,26,0.06);">
                                    <p style="margin:0;">&copy; 2026 Officially Human Art</p>
                                </div>
                            </div>`
                        }).catch(err => console.error('Failed to send subscription confirmation email:', err.message));
                    }
                }
            }
            break;
        }
        case 'invoice.payment_failed': {
            const invoice = event.data.object;
            const artist = rowToArtist(stmts.getArtistByStripeCustomer.get(invoice.customer));
            if (artist && emailEnabled) {
                sendEmail({
                    from: process.env.SMTP_FROM || process.env.SMTP_USER,
                    to: artist.email,
                    subject: 'Payment failed for your Officially Human Art subscription',
                    html: `<div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#f5f0e8;">
                        <div style="background:#2a2520;color:#fafafa;padding:2rem;text-align:center;">
                            <div style="font-family:Inter,-apple-system,sans-serif;font-size:1.2rem;font-weight:600;"><span style="font-weight:300;color:#999;">officially</span><span style="font-weight:600;">human</span><span style="font-weight:700;font-size:1.5rem;">.art</span></div>
                        </div>
                        <div style="padding:2rem;">
                            <p style="color:#666666;margin-bottom:1rem;">Hi ${artist.name},</p>
                            <p style="color:#666666;margin-bottom:1rem;">We weren't able to process your latest payment for the Creator plan. This can happen if your card has expired or has insufficient funds.</p>
                            <p style="color:#666666;margin-bottom:1rem;">Please update your payment method to keep your subscription active. Stripe will automatically retry the payment, but if it continues to fail your subscription will be cancelled.</p>
                            <p style="color:#666666;margin-bottom:1rem;"><strong>Your certificates remain active while we retry.</strong> No changes have been made to your account yet.</p>
                            <p style="color:#888888;font-size:0.85rem;">If you believe this is an error, please check with your bank or card provider.</p>
                        </div>
                        <div style="background:#ebe5da;padding:1rem;text-align:center;font-size:0.75rem;color:#a0aec0;border-top:1px solid rgba(26,26,26,0.06);">
                            <p style="margin:0;">&copy; 2026 Officially Human Art</p>
                        </div>
                    </div>`
                }).catch(err => console.error('Failed to send payment failed email:', err.message));
            }
            break;
        }
    }

    res.json({ received: true });
});

// ============================================================
// Middleware
// ============================================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ============================================================
// Phase 2: Server-Side Sessions
// ============================================================
app.use(session({
    store: new SqliteStore({ client: db, expired: { clear: true, intervalMs: 900000 } }),
    secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    name: 'oh.sid',
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        sameSite: 'lax'
    }
}));

// ============================================================
// Phase 3: CSRF Protection
// ============================================================
const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
    getSecret: () => process.env.SESSION_SECRET || 'dev-secret-change-in-production',
    getSessionIdentifier: (req) => req.session && req.session.id ? req.session.id : '',
    cookieName: '__csrf',
    cookieOptions: { sameSite: 'lax', path: '/', secure: process.env.NODE_ENV === 'production', httpOnly: true },
    getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token']
});

// Slow request logging
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        if (duration > 1000) {
            console.log(`[SLOW] ${req.method} ${req.path} took ${duration}ms`);
        }
        if (res.statusCode >= 500) {
            errorCount5xx++;
        }
    });
    next();
});

// CSRF token endpoint (exempt from CSRF protection itself)
app.get('/api/csrf-token', (req, res) => {
    // Ensure session is persisted so the session ID stays stable for CSRF HMAC
    if (!req.session.csrfInit) req.session.csrfInit = true;
    res.json({ token: generateCsrfToken(req, res) });
});

// Auth middleware
function requireAuth(req, res, next) {
    if (!req.session.artistId) {
        return res.status(401).json({ success: false, message: 'Not authenticated' });
    }
    next();
}

// Verify page with Open Graph meta tags for social sharing
app.get('/verify.html', (req, res, next) => {
    const code = req.query.code;
    if (!code) return next();

    const row = stmts.getCertById.get(code.toUpperCase());
    const cert = rowToCert(row);
    if (!cert) return next();

    // Don't inject OG tags for revoked certs or banned artists
    const certArtist = rowToArtist(stmts.getArtistById.get(cert.artistId));
    if (cert.status === 'revoked' || (certArtist && certArtist.banned)) return next();

    const host = `${req.protocol}://${req.get('host')}`;
    const verifyUrl = `${host}/verify.html?code=${encodeURIComponent(cert.id)}`;
    const imageUrl = cert.artworkImage ? `${host}/uploads/${cert.artworkImage}` : null;

    const escAttr = s => (s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

    const ogTags = [
        `<meta property="og:type" content="article">`,
        `<meta property="og:title" content="${escAttr(cert.title)} — Officially Human Art Certificate">`,
        `<meta property="og:description" content="Certified human-made work by ${escAttr(cert.artistName)}. ${escAttr(cert.tierLabel || cert.tier || 'Bronze')} tier certification.">`,
        `<meta property="og:url" content="${escAttr(verifyUrl)}">`,
        `<meta name="twitter:card" content="${imageUrl ? 'summary_large_image' : 'summary'}">`,
        `<meta name="twitter:title" content="${escAttr(cert.title)} — Officially Human Art Certificate">`,
        `<meta name="twitter:description" content="Certified human-made work by ${escAttr(cert.artistName)}.">`
    ];
    if (imageUrl) {
        ogTags.push(`<meta property="og:image" content="${escAttr(imageUrl)}">`);
        ogTags.push(`<meta name="twitter:image" content="${escAttr(imageUrl)}">`);
    }

    let html = fs.readFileSync(path.join(__dirname, 'public', 'verify.html'), 'utf8');
    html = html.replace('</head>', ogTags.join('\n    ') + '\n</head>');
    html = html.replace(
        '<title>Verify Certificate — Officially Human Art</title>',
        `<title>${escAttr(cert.title)} by ${escAttr(cert.artistName)} — Officially Human Art</title>`
    );

    res.send(html);
});

// Dynamic sitemap
app.get('/sitemap.xml', (req, res) => {
    const host = `${req.protocol}://${req.get('host')}`;
    const now = new Date().toISOString().split('T')[0];

    const staticPages = [
        { url: '/', changefreq: 'weekly', priority: '1.0' },
        { url: '/verify.html', changefreq: 'monthly', priority: '0.8' },

        { url: '/register.html', changefreq: 'monthly', priority: '0.7' },
        { url: '/legal.html', changefreq: 'yearly', priority: '0.3' },
    ];

    // Add blog posts
    const blogDir = path.join(__dirname, 'content', 'blog');
    if (fs.existsSync(blogDir)) {
        fs.readdirSync(blogDir).filter(f => f.endsWith('.json')).forEach(f => {
            const slug = f.replace('.json', '');
            staticPages.push({ url: `/blog/${slug}`, changefreq: 'monthly', priority: '0.6' });
        });
    }

    // Add artist profiles
    const artists = db.prepare('SELECT slug FROM artists WHERE slug IS NOT NULL AND slug != \'\'').all();
    artists.forEach(a => {
        staticPages.push({ url: `/profile.html?artist=${encodeURIComponent(a.slug)}`, changefreq: 'weekly', priority: '0.5' });
    });

    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
    staticPages.forEach(p => {
        xml += `  <url>\n    <loc>${host}${p.url}</loc>\n    <lastmod>${now}</lastmod>\n    <changefreq>${p.changefreq}</changefreq>\n    <priority>${p.priority}</priority>\n  </url>\n`;
    });
    xml += '</urlset>';

    res.set('Content-Type', 'application/xml');
    res.send(xml);
});

// Blog system — serves posts from content/blog/*.json
const BLOG_DIR = path.join(__dirname, 'content', 'blog');

function getBlogPosts() {
    if (!fs.existsSync(BLOG_DIR)) return [];
    return fs.readdirSync(BLOG_DIR)
        .filter(f => f.endsWith('.json'))
        .map(f => {
            try {
                const data = JSON.parse(fs.readFileSync(path.join(BLOG_DIR, f), 'utf8'));
                data.slug = f.replace('.json', '');
                return data;
            } catch { return null; }
        })
        .filter(p => p && p.published !== false)
        .sort((a, b) => new Date(b.date) - new Date(a.date));
}

function blogTemplate(title, content, { description, isIndex, keywords, slug } = {}) {
    const esc = s => (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    const baseUrl = process.env.BASE_URL || 'https://officiallyhuman.art';
    const pageUrl = slug ? `${baseUrl}/blog/${slug}` : `${baseUrl}/blog`;
    const fullTitle = `${esc(title)} — Officially Human Art`;
    const desc = esc(description || title);
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Google tag (gtag.js) -->
    <script async src="https://www.googletagmanager.com/gtag/js?id=G-N1HS7C9R8N"></script>
    <script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-N1HS7C9R8N');</script>
    <title>${fullTitle}</title>
    <meta name="description" content="${desc}">
${keywords ? `    <meta name="keywords" content="${esc(keywords)}">` : ''}
    <link rel="canonical" href="${pageUrl}">
    <meta property="og:type" content="${slug ? 'article' : 'website'}">
    <meta property="og:title" content="${fullTitle}">
    <meta property="og:description" content="${desc}">
    <meta property="og:url" content="${pageUrl}">
    <meta property="og:site_name" content="Officially Human Art">
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="${fullTitle}">
    <meta name="twitter:description" content="${desc}">
    <link rel="stylesheet" href="/fonts/fonts.css">
    <link rel="icon" type="image/svg+xml" href="/fingerprint-favicon.svg">
    <style>
        :root{--navy:#2a2520;--navy-light:#3d3630;--cream:#f5f0e8;--cream-dark:#ebe5da;--gold:#3d3427;--gold-light:#4a4035;--ink:#1a1a1a;--ink-light:#555555;--ink-faint:#888888;}
        *{margin:0;padding:0;box-sizing:border-box;}
        body{font-family:'Inter',sans-serif;background:var(--cream);color:var(--ink);line-height:1.6;-webkit-font-smoothing:antialiased;}
        .container{max-width:760px;margin:0 auto;padding:0 2rem;}
        header{padding:1rem 0;border-bottom:1px solid rgba(26,26,26,0.06);margin-bottom:3rem;}
        .header-inner{display:flex;justify-content:space-between;align-items:center;max-width:760px;margin:0 auto;padding:0 2rem;}
        .logo{font-family:'Inter',sans-serif;font-size:1.5rem;font-weight:700;color:var(--navy);text-decoration:none;}
        .logo span{color:var(--gold);}
        nav a{color:var(--ink-light);text-decoration:none;font-size:0.9rem;font-weight:500;margin-left:1.5rem;}
        nav a:hover{color:var(--navy);}
        .blog-content{padding-bottom:5rem;}
        .blog-content h1{font-family:'Fraunces',serif;font-size:clamp(2rem,4vw,2.75rem);color:var(--navy);margin-bottom:0.5rem;line-height:1.15;}
        .blog-content h2{font-family:'Fraunces',serif;font-size:1.5rem;color:var(--navy);margin:2.5rem 0 0.75rem;}
        .blog-content h3{font-size:1.15rem;color:var(--navy);margin:2rem 0 0.5rem;}
        .blog-meta{font-size:0.85rem;color:var(--ink-faint);margin-bottom:2.5rem;}
        .blog-content p{margin-bottom:1.25rem;line-height:1.8;color:var(--ink-light);font-size:1.02rem;}
        .blog-content blockquote{border-left:3px solid var(--gold);padding:0.5rem 0 0.5rem 1.5rem;margin:1.5rem 0;font-family:'Fraunces',serif;font-size:1.3rem;color:var(--navy);font-style:italic;line-height:1.5;}
        .blog-content ul,.blog-content ol{margin:0 0 1.25rem 1.5rem;color:var(--ink-light);}
        .blog-content li{margin-bottom:0.4rem;line-height:1.7;}
        .blog-content a{color:var(--navy);font-weight:600;}
        .blog-content a:hover{color:var(--gold);}
        .blog-content img{max-width:100%;border-radius:8px;margin:1.5rem 0;}
        .blog-content hr{border:none;border-top:1px solid rgba(26,26,26,0.08);margin:2.5rem 0;}
        .post-list{list-style:none;padding:0;}
        .post-item{padding:1.75rem 0;border-bottom:1px solid rgba(26,26,26,0.06);}
        .post-item:first-child{padding-top:0;}
        .post-item h2{font-family:'Fraunces',serif;font-size:1.5rem;margin-bottom:0.3rem;}
        .post-item h2 a{color:var(--navy);text-decoration:none;}
        .post-item h2 a:hover{color:var(--gold);}
        .post-item .post-date{font-size:0.82rem;color:var(--ink-faint);margin-bottom:0.5rem;}
        .post-item .post-excerpt{color:var(--ink-light);font-size:0.95rem;line-height:1.65;}
        .back-link{display:inline-block;margin-bottom:2rem;font-size:0.9rem;color:var(--ink-faint);text-decoration:none;}
        .back-link:hover{color:var(--navy);}
        footer{padding:2rem 0;border-top:1px solid rgba(26,26,26,0.06);text-align:center;}
        footer p{color:var(--ink-faint);font-size:0.82rem;}
    </style>
</head>
<body>
    <header>
        <div class="header-inner">
            <a href="/" class="logo" style="display:flex;align-items:center;gap:8px;text-decoration:none;font-family:'Inter',sans-serif;"><svg viewBox="0 0 70 85" fill="none" stroke="currentColor" stroke-width="1.2" xmlns="http://www.w3.org/2000/svg" style="width:28px;height:34px;color:#1a1a1a;"><path d="M35 5 C15 5 5 22 5 42 C5 62 15 80 35 80" stroke-linecap="round"/><path d="M35 12 C20 12 12 26 12 42 C12 58 20 72 35 72 C50 72 58 58 58 42" stroke-linecap="round"/><path d="M35 19 C24 19 18 30 18 42 C18 54 24 65 35 65 C46 65 52 54 52 42 C52 30 46 19 35 19" stroke-linecap="round"/><path d="M35 26 C28 26 24 33 24 42 C24 51 28 58 35 58 C42 58 46 51 46 42" stroke-linecap="round"/><path d="M35 33 C31 33 29 37 29 42 C29 47 31 51 35 51 C39 51 41 47 41 42 C41 37 39 33 35 33" stroke-linecap="round"/><path d="M65 42 C65 22 55 5 35 5" stroke-linecap="round"/><path d="M58 42 C58 26 50 12 35 12" stroke-linecap="round"/></svg><span style="display:flex;flex-direction:column;line-height:1.1;"><span style="font-size:11px;"><span style="font-weight:300;color:#666;">officially</span><span style="font-weight:600;color:#1a1a1a;">human</span></span><span style="font-size:18px;font-weight:700;color:#1a1a1a;margin-top:-2px;">.art</span></span></a>
            <nav>
                <a href="/blog">Blog</a>
                <a href="/verify.html">Verify</a>
                <a href="/register.html">Register</a>
            </nav>
        </div>
    </header>
    <main class="container blog-content">
        ${content}
    </main>
    <footer>
        <div class="container">
            <p>&copy; 2026 Officially Human Art</p>
        </div>
    </footer>
</body>
</html>`;
}

// Simple markdown-like rendering (no external dependency)
function renderBlogBody(body) {
    if (Array.isArray(body)) {
        return body.map(block => {
            if (typeof block === 'string') return `<p>${block}</p>`;
            if (block.type === 'heading') return `<h2>${block.text}</h2>`;
            if (block.type === 'h3') return `<h3>${block.text}</h3>`;
            if (block.type === 'quote') return `<blockquote>${block.text}</blockquote>`;
            if (block.type === 'list') return `<ul>${block.items.map(i => `<li>${i}</li>`).join('')}</ul>`;
            if (block.type === 'ol') return `<ol>${block.items.map(i => `<li>${i}</li>`).join('')}</ol>`;
            if (block.type === 'hr') return '<hr>';
            if (block.type === 'html') return block.content;
            return `<p>${block.text || ''}</p>`;
        }).join('\n');
    }
    return `<p>${body}</p>`;
}

// Blog index
app.get('/blog', (req, res) => {
    const posts = getBlogPosts();
    let content = '<h1>Blog</h1>\n<p style="color:var(--ink-light);margin-bottom:2rem;">Thoughts on authenticity, creator rights, and human creativity in the age of AI.</p>\n';
    if (posts.length === 0) {
        content += '<p>No posts yet. Check back soon.</p>';
    } else {
        content += '<ul class="post-list">';
        posts.forEach(p => {
            content += `<li class="post-item">
                <h2><a href="/blog/${p.slug}">${p.title}</a></h2>
                <div class="post-date">${new Date(p.date).toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' })}</div>
                <div class="post-excerpt">${p.excerpt || ''}</div>
            </li>`;
        });
        content += '</ul>';
    }
    res.send(blogTemplate('Blog', content, { description: 'Articles about authenticity, creator rights, and human creativity.', isIndex: true }));
});

// Blog post
app.get('/blog/:slug', (req, res) => {
    const filePath = path.join(BLOG_DIR, `${req.params.slug}.json`);
    if (!fs.existsSync(filePath)) return res.status(404).send(blogTemplate('Not Found', '<h1>Post not found</h1><p><a href="/blog">Back to blog</a></p>'));
    try {
        const post = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (post.published === false) return res.status(404).send(blogTemplate('Not Found', '<h1>Post not found</h1><p><a href="/blog">Back to blog</a></p>'));
        const dateStr = new Date(post.date).toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' });
        const content = `<a href="/blog" class="back-link">&larr; All posts</a>
            <h1>${post.title}</h1>
            <div class="blog-meta">${dateStr}${post.author ? ' &middot; ' + post.author : ''}</div>
            ${renderBlogBody(post.body)}`;
        res.send(blogTemplate(post.title, content, { description: post.excerpt, keywords: post.keywords, slug: req.params.slug }));
    } catch {
        res.status(500).send(blogTemplate('Error', '<h1>Error loading post</h1><p><a href="/blog">Back to blog</a></p>'));
    }
});

app.use(express.static('public'));

// Controlled file serving — public artwork/evidence served freely, private evidence requires session ownership
app.get('/uploads/:filename', (req, res) => {
    const { filename } = req.params;
    const filePath = path.join(UPLOADS_DIR, path.basename(filename));

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ success: false, message: 'File not found' });
    }

    // Check if artwork image (always public)
    const certRow = stmts.findCertByArtworkImage.get(filename);
    if (certRow) {
        // Block serving if certificate is revoked or artist is banned
        if (certRow.status === 'revoked') return res.status(403).json({ success: false, message: 'This content has been removed.' });
        const fileArtist = rowToArtist(stmts.getArtistById.get(certRow.artist_id));
        if (fileArtist && fileArtist.banned) return res.status(403).json({ success: false, message: 'This content has been removed.' });
        return res.sendFile(filePath);
    }

    // Check evidence files
    const efRow = stmts.findEvidenceFile.get(filename);
    if (efRow) {
        // Block serving if associated certificate is revoked or artist is banned
        const efCert = stmts.getCertById.get(efRow.certificate_id);
        if (efCert && efCert.status === 'revoked') return res.status(403).json({ success: false, message: 'This content has been removed.' });
        const efArtist = rowToArtist(stmts.getArtistById.get(efRow.artist_id));
        if (efArtist && efArtist.banned) return res.status(403).json({ success: false, message: 'This content has been removed.' });

        if (efRow.is_public === 1) {
            return res.sendFile(filePath);
        }
        // Private evidence — require session match
        const sessionArtistId = req.session && req.session.artistId;
        if (sessionArtistId && sessionArtistId === efRow.artist_id) {
            return res.sendFile(filePath);
        }
        return res.status(403).json({ success: false, message: 'This file is private.' });
    }

    return res.status(403).json({ success: false, message: 'Access denied.' });
});

// File upload config
const ALLOWED_MIME_TYPES = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'video/mp4', 'video/webm', 'video/quicktime'
];
const MIME_TO_EXT = {
    'image/jpeg': '.jpg', 'image/png': '.png', 'image/gif': '.gif', 'image/webp': '.webp',
    'video/mp4': '.mp4', 'video/webm': '.webm', 'video/quicktime': '.mov'
};

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
        const ext = MIME_TO_EXT[file.mimetype] || path.extname(file.originalname).toLowerCase();
        cb(null, uuidv4() + ext);
    }
});
const upload = multer({
    storage,
    limits: { fileSize: 100 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
            return cb(new Error('Only image and video files are allowed (JPEG, PNG, GIF, WebP, MP4, WebM, MOV).'));
        }
        cb(null, true);
    }
});
const artworkUpload = upload.fields([
    { name: 'artworkImage', maxCount: 1 },
    { name: 'evidence', maxCount: 10 }
]);

// Generate certificate ID: OH-YYYY-XXXXXX
function generateCertificateId() {
    const year = new Date().getFullYear();
    const random = Math.random().toString(36).substring(2, 8).toUpperCase();
    return `OH-${year}-${random}`;
}

// Calculate certification tier
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

// Plan helpers
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

// Sanitise artist for client (strip password hash and internal fields)
function safeArtist(artist) {
    const { passwordHash, stripeCustomerId, stripeSubscriptionId, resetToken, resetTokenExpires, verificationToken, deletionWarningSentAt, banReason, ...safe } = artist;
    return safe;
}

// Email config
let emailEnabled = false;
let mailTransporter = null;
const useResendApi = process.env.SMTP_HOST === 'smtp.resend.com' && process.env.SMTP_PASS;

if (useResendApi) {
    emailEnabled = true;
    console.log('Email enabled via Resend API');
} else if (process.env.SMTP_HOST) {
    const smtpPort = parseInt(process.env.SMTP_PORT) || 587;
    mailTransporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        socketTimeout: 15000
    });
    emailEnabled = true;
    console.log('Email enabled via ' + process.env.SMTP_HOST);
}

async function sendEmail({ from, to, subject, html, text, replyTo }) {
    if (useResendApi) {
        const payload = {
            from: from || process.env.SMTP_FROM || process.env.SMTP_USER,
            to: Array.isArray(to) ? to : [to],
            subject,
            ...(html ? { html } : { text })
        };
        if (replyTo) payload.reply_to = replyTo;
        const res = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${process.env.SMTP_PASS}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        if (!res.ok) {
            const body = await res.text();
            throw new Error(`Resend API error ${res.status}: ${body}`);
        }
        return await res.json();
    } else if (mailTransporter) {
        const opts = { from, to, subject, html, text };
        if (replyTo) opts.replyTo = replyTo;
        return mailTransporter.sendMail(opts);
    }
}

async function sendCertificateEmail(artist, certificate, host) {
    if (!emailEnabled) return;

    const verifyUrl = `${host}/verify.html?code=${certificate.id}`;
    const tierColors = { gold: '#a08530', silver: '#6b7280', bronze: '#a0764a' };
    const tierColor = tierColors[certificate.tier] || tierColors.bronze;
    const tierLabel = certificate.tierLabel || certificate.tier || 'Bronze';

    const baseUrl = process.env.BASE_URL || host;
    const qrImageUrl = `${baseUrl}/api/qr/${certificate.id}/image`;

    const html = `
    <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#f5f0e8;">
        <div style="background:#2a2520;color:#fafafa;padding:2rem;text-align:center;">
            <div style="font-family:Inter,-apple-system,sans-serif;font-size:1.2rem;font-weight:600;"><span style="font-weight:300;color:#999;">officially</span><span style="font-weight:600;">human</span><span style="font-weight:700;font-size:1.5rem;">.art</span></div>
            <div style="font-size:0.8rem;text-transform:uppercase;letter-spacing:0.12em;opacity:0.8;margin-top:0.25rem;">Certificate of Human Creation</div>
        </div>
        <div style="padding:2rem;">
            <p style="color:#666666;margin-bottom:1.5rem;">Hi ${artist.name},</p>
            <p style="color:#666666;margin-bottom:1.5rem;">Your work has been certified as authentically human-made. Here are your certificate details:</p>
            <div style="background:#fff;border:1px solid rgba(26,26,26,0.1);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;">
                <h2 style="font-family:Inter,-apple-system,sans-serif;color:#1a1a1a;margin:0 0 0.5rem;font-size:1.4rem;">${certificate.title}</h2>
                <p style="color:#888888;margin:0 0 1rem;font-size:0.9rem;">${certificate.medium}</p>
                <div style="display:inline-block;padding:0.3rem 1rem;border-radius:100px;font-size:0.75rem;font-weight:bold;text-transform:uppercase;letter-spacing:0.06em;color:#fff;background:${tierColor};">${tierLabel} Certification</div>
                <div style="margin-top:1.25rem;padding-top:1rem;border-top:1px solid rgba(26,26,26,0.08);">
                    <p style="color:#a0aec0;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 0.2rem;">Certificate ID</p>
                    <p style="font-family:monospace;color:#1a1a1a;font-size:1.1rem;font-weight:600;margin:0;letter-spacing:0.08em;">${certificate.id}</p>
                </div>
                <div style="margin-top:1.25rem;text-align:center;"><img src="${qrImageUrl}" alt="QR Code" width="150" height="150" style="width:150px;height:150px;border-radius:8px;"></div>
            </div>
            <div style="text-align:center;margin-bottom:1.5rem;">
                <a href="${verifyUrl}" style="display:inline-block;padding:0.75rem 2rem;background:#2a2520;color:#fafafa;text-decoration:none;border-radius:6px;font-weight:600;font-size:0.9rem;">View Your Certificate</a>
            </div>
            <p style="color:#888888;font-size:0.82rem;">You can share your certificate by sending the verification link or using the embed code on your website.</p>
        </div>
        <div style="background:#ebe5da;padding:1.25rem;text-align:center;font-size:0.75rem;color:#a0aec0;border-top:1px solid rgba(26,26,26,0.06);">
            <p style="margin:0;">All rights reserved by the original creator. Registration does not transfer copyright.</p>
            <p style="margin:0.5rem 0 0;">&copy; 2026 Officially Human Art</p>
        </div>
    </div>`;

    try {
        await sendEmail({
            from: process.env.SMTP_FROM || process.env.SMTP_USER,
            to: artist.email,
            subject: `Your Officially Human Art Certificate: ${certificate.title} (${certificate.id})`,
            html
        });
    } catch (err) {
        console.error('Failed to send certificate email:', err.message);
    }
}

async function sendVerificationEmail(artist, token, host) {
    if (!emailEnabled) return;
    const verifyUrl = `${host}/api/artist/verify-email?token=${encodeURIComponent(token)}`;
    try {
        await sendEmail({
            from: process.env.SMTP_FROM || process.env.SMTP_USER,
            to: artist.email,
            subject: 'Verify your email — Officially Human Art',
            html: `
            <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#f5f0e8;">
                <div style="background:#2a2520;color:#fafafa;padding:2rem;text-align:center;">
                    <div style="font-family:Inter,-apple-system,sans-serif;font-size:1.2rem;font-weight:600;"><span style="font-weight:300;color:#999;">officially</span><span style="font-weight:600;">human</span><span style="font-weight:700;font-size:1.5rem;">.art</span></div>
                </div>
                <div style="padding:2rem;">
                    <p style="color:#666666;margin-bottom:1.5rem;">Hi ${artist.name},</p>
                    <p style="color:#666666;margin-bottom:1.5rem;">Please verify your email address to start submitting artwork for certification.</p>
                    <div style="text-align:center;margin-bottom:1.5rem;">
                        <a href="${verifyUrl}" style="display:inline-block;padding:0.75rem 2rem;background:#2a2520;color:#fafafa;text-decoration:none;border-radius:6px;font-weight:600;font-size:0.9rem;">Verify Email</a>
                    </div>
                    <p style="color:#888888;font-size:0.82rem;">If you didn't create an account, you can safely ignore this email.</p>
                </div>
                <div style="background:#ebe5da;padding:1.25rem;text-align:center;font-size:0.75rem;color:#a0aec0;border-top:1px solid rgba(26,26,26,0.06);">
                    <p style="margin:0;">&copy; 2026 Officially Human Art</p>
                </div>
            </div>`
        });
    } catch (err) {
        console.error('Failed to send verification email:', err.message);
    }
}

async function sendRetentionWarningEmail(artist) {
    if (!emailEnabled) return;
    try {
        await sendEmail({
            from: process.env.SMTP_FROM || process.env.SMTP_USER,
            to: artist.email,
            subject: 'Your Officially Human Art account will be deleted',
            html: `
            <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#f5f0e8;">
                <div style="background:#2a2520;color:#fafafa;padding:2rem;text-align:center;">
                    <div style="font-family:Inter,-apple-system,sans-serif;font-size:1.2rem;font-weight:600;"><span style="font-weight:300;color:#999;">officially</span><span style="font-weight:600;">human</span><span style="font-weight:700;font-size:1.5rem;">.art</span></div>
                </div>
                <div style="padding:2rem;">
                    <p style="color:#666666;margin-bottom:1.5rem;">Hi ${artist.name},</p>
                    <p style="color:#666666;margin-bottom:1.5rem;">Your account has been inactive for over 24 months and has no certificates. It will be permanently deleted in 30 days unless you log in.</p>
                    <p style="color:#888888;font-size:0.82rem;">If you'd like to keep your account, simply log in before the deletion date.</p>
                </div>
                <div style="background:#ebe5da;padding:1.25rem;text-align:center;font-size:0.75rem;color:#a0aec0;border-top:1px solid rgba(26,26,26,0.06);">
                    <p style="margin:0;">&copy; 2026 Officially Human Art</p>
                </div>
            </div>`
        });
    } catch (err) {
        console.error('Failed to send retention warning email:', err.message);
    }
}

// Structured audit logging
function audit(event, details = {}) {
    const entry = { timestamp: new Date().toISOString(), event, ...details };
    console.log('[AUDIT]', JSON.stringify(entry));
}

// ============================================================
// Automated Backup
// ============================================================
function backupDatabase() {
    try {
        db.pragma('wal_checkpoint(TRUNCATE)');
        const dateStr = new Date().toISOString().slice(0, 10);
        const backupPath = path.join(BACKUPS_DIR, `backup-${dateStr}.db`);
        fs.copyFileSync(DB_PATH, backupPath);

        // Prune backups older than 7 days
        const files = fs.readdirSync(BACKUPS_DIR).filter(f => f.startsWith('backup-') && f.endsWith('.db'));
        const cutoff = new Date();
        cutoff.setDate(cutoff.getDate() - 7);
        for (const file of files) {
            const dateMatch = file.match(/backup-(\d{4}-\d{2}-\d{2})\.db/);
            if (dateMatch && new Date(dateMatch[1]) < cutoff) {
                fs.unlinkSync(path.join(BACKUPS_DIR, file));
            }
        }

        audit('backup_completed', { backupPath, date: dateStr });
    } catch (err) {
        console.error('Backup failed:', err.message);
    }
}

// Run backup on startup and every 24 hours
backupDatabase();
setInterval(backupDatabase, 24 * 60 * 60 * 1000);

// ============================================================
// Data Retention Cleanup
// ============================================================
function runRetentionCleanup() {
    try {
        const cutoff24Months = new Date();
        cutoff24Months.setMonth(cutoff24Months.getMonth() - 24);
        const cutoffStr = cutoff24Months.toISOString();

        const inactive = stmts.getInactiveAccounts.all(cutoffStr);

        for (const row of inactive) {
            const artist = rowToArtist(row);
            if (!artist.deletionWarningSentAt) {
                // Send warning, set timestamp
                db.prepare('UPDATE artists SET deletion_warning_sent_at = ? WHERE id = ?')
                    .run(new Date().toISOString(), artist.id);
                sendRetentionWarningEmail(artist);
                audit('retention_warning_sent', { artistId: artist.id, email: artist.email });
            } else {
                // Check if 30 days have passed since warning
                const warnDate = new Date(artist.deletionWarningSentAt);
                const gracePeriod = new Date(warnDate);
                gracePeriod.setDate(gracePeriod.getDate() + 30);

                if (new Date() > gracePeriod) {
                    // Delete the account
                    const deleteAll = db.transaction(() => {
                        db.prepare('DELETE FROM reports WHERE certificate_id IN (SELECT id FROM certificates WHERE artist_id = ?)').run(artist.id);
                        db.prepare('DELETE FROM certificate_history WHERE certificate_id IN (SELECT id FROM certificates WHERE artist_id = ?)').run(artist.id);
                        db.prepare('DELETE FROM evidence_files WHERE certificate_id IN (SELECT id FROM certificates WHERE artist_id = ?)').run(artist.id);
                        db.prepare('DELETE FROM certificates WHERE artist_id = ?').run(artist.id);
                        db.prepare('DELETE FROM artists WHERE id = ?').run(artist.id);
                    });
                    deleteAll();
                    audit('retention_account_deleted', { artistId: artist.id, email: artist.email });
                }
            }
        }
    } catch (err) {
        console.error('Retention cleanup error:', err.message);
    }
}

// Run retention cleanup daily (alongside backup)
runRetentionCleanup();
setInterval(runRetentionCleanup, 24 * 60 * 60 * 1000);

// ============================================================
// Admin Auth Middleware
// ============================================================
function requireAdmin(req, res, next) {
    const adminKey = process.env.ADMIN_KEY;
    if (!adminKey) {
        return res.status(503).json({ success: false, message: 'Admin not configured' });
    }
    const provided = req.headers['x-admin-key'] || req.query.adminKey;
    if (provided !== adminKey) {
        return res.status(403).json({ success: false, message: 'Invalid admin key' });
    }
    next();
}

// ============================================================
// Monitoring: Error count and slow request tracking
// ============================================================
let errorCount5xx = 0;

// ============================================================
// API Routes
// ============================================================

// ---- Health / Monitoring ----
app.get('/api/health', (req, res) => {
    let dbStatus = 'connected';
    try {
        db.prepare('SELECT 1').get();
    } catch (e) {
        dbStatus = 'error';
    }

    // Disk usage of data + uploads
    let diskUsage = 0;
    try {
        const sumDir = (dir) => {
            if (!fs.existsSync(dir)) return 0;
            return fs.readdirSync(dir).reduce((sum, f) => {
                const fp = path.join(dir, f);
                try { return sum + fs.statSync(fp).size; } catch (e) { return sum; }
            }, 0);
        };
        diskUsage = sumDir(DATA_DIR) + sumDir(UPLOADS_DIR);
    } catch (e) { /* ignore */ }

    // Last backup
    let lastBackup = null;
    try {
        const backups = fs.readdirSync(BACKUPS_DIR).filter(f => f.startsWith('backup-') && f.endsWith('.db')).sort();
        if (backups.length > 0) {
            const match = backups[backups.length - 1].match(/backup-(\d{4}-\d{2}-\d{2})\.db/);
            if (match) lastBackup = match[1];
        }
    } catch (e) { /* ignore */ }

    const artistCount = stmts.countArtists.get().n;
    const certificateCount = stmts.countCerts.get().n;

    const status = dbStatus === 'connected' ? 'ok' : 'degraded';

    res.json({
        status,
        uptime: Math.floor(process.uptime()),
        database: dbStatus,
        diskUsage,
        lastBackup,
        artistCount,
        certificateCount,
        errorCount5xx
    });
});

// ---- Admin: Manual Backup ----
app.get('/api/admin/backup', requireAdmin, (req, res) => {
    try {
        backupDatabase();
        res.json({ success: true, message: 'Backup completed' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Backup failed: ' + err.message });
    }
});

// ---- Admin: Stats ----
app.get('/api/admin/stats', requireAdmin, (req, res) => {
    const artists = stmts.countArtists.get().n;
    const certificates = stmts.countCerts.get().n;
    const pendingReports = db.prepare("SELECT COUNT(*) as n FROM reports WHERE status = 'pending'").get().n;
    const totalReports = db.prepare('SELECT COUNT(*) as n FROM reports').get().n;
    const tiers = { gold: 0, silver: 0, bronze: 0 };
    stmts.countTiers.all().forEach(r => {
        if (tiers[r.tier] !== undefined) tiers[r.tier] = r.n;
    });

    res.json({ success: true, artists, certificates, tiers, pendingReports, totalReports });
});

// ---- Admin: List Reports ----
app.get('/api/admin/reports', requireAdmin, (req, res) => {
    const reports = stmts.getAllReports.all();
    res.json({
        success: true,
        reports: reports.map(r => ({
            id: r.id,
            certificateId: r.certificate_id,
            certTitle: r.cert_title,
            artistId: r.artist_id,
            artistName: r.artist_name,
            reason: r.reason,
            reporterEmail: r.reporter_email,
            type: r.type || 'dispute',
            status: r.status,
            resolution: r.resolution,
            resolvedAt: r.resolved_at,
            createdAt: r.created_at
        }))
    });
});

// ---- Admin: Resolve Report ----
app.put('/api/admin/reports/:reportId', requireAdmin, express.json(), (req, res) => {
    const { reportId } = req.params;
    const { resolution } = req.body;

    const report = stmts.getReportById.get(reportId);
    if (!report) {
        return res.status(404).json({ success: false, message: 'Report not found' });
    }

    const status = resolution === 'dismissed' ? 'dismissed' : 'resolved';
    stmts.updateReportResolution.run(resolution, new Date().toISOString(), status, reportId);
    audit('report_resolved', { reportId, resolution, status });

    res.json({ success: true, message: 'Report updated' });
});

// ---- Admin: Revoke Certificate ----
app.put('/api/admin/certificates/:certId/revoke', requireAdmin, (req, res) => {
    const { certId } = req.params;
    const cert = stmts.getCertById.get(certId.toUpperCase());
    if (!cert) {
        return res.status(404).json({ success: false, message: 'Certificate not found' });
    }

    stmts.updateCertStatus.run('revoked', certId.toUpperCase());
    stmts.insertHistory.run(certId.toUpperCase(), 'revoked', null, new Date().toISOString());
    audit('certificate_revoked', { certificateId: certId.toUpperCase() });

    res.json({ success: true, message: 'Certificate revoked' });
});

// ---- Admin: Ban Artist ----
app.put('/api/admin/artists/:artistId/ban', requireAdmin, express.json(), (req, res) => {
    const { artistId } = req.params;
    const { reason } = req.body;
    const artist = rowToArtist(stmts.getArtistById.get(artistId));
    if (!artist) {
        return res.status(404).json({ success: false, message: 'Artist not found' });
    }

    db.prepare('UPDATE artists SET banned = 1, ban_reason = ? WHERE id = ?').run(reason || 'Violation of terms of service', artistId);

    // Revoke all their certificates
    const certs = stmts.getCertsByArtist.all(artistId);
    const revokeAll = db.transaction(() => {
        for (const cert of certs) {
            if (cert.status !== 'revoked') {
                stmts.updateCertStatus.run('revoked', cert.id);
                stmts.insertHistory.run(cert.id, 'revoked_account_ban', null, new Date().toISOString());
            }
        }
    });
    revokeAll();

    audit('artist_banned', { artistId, reason: reason || 'Violation of terms of service', certificatesRevoked: certs.length });
    res.json({ success: true, message: `Artist banned. ${certs.length} certificate(s) revoked.` });
});

// ---- Admin: Unban Artist ----
app.put('/api/admin/artists/:artistId/unban', requireAdmin, (req, res) => {
    const { artistId } = req.params;
    const artist = rowToArtist(stmts.getArtistById.get(artistId));
    if (!artist) {
        return res.status(404).json({ success: false, message: 'Artist not found' });
    }

    db.prepare('UPDATE artists SET banned = 0, ban_reason = NULL WHERE id = ?').run(artistId);
    // Note: certificates are NOT automatically un-revoked — admin must manually reinstate if appropriate
    audit('artist_unbanned', { artistId });
    res.json({ success: true, message: 'Artist unbanned. Certificates remain revoked and must be reinstated individually if appropriate.' });
});

// ---- Admin: List All Artists ----
app.get('/api/admin/artists', requireAdmin, (req, res) => {
    const rows = stmts.getAllArtists.all();
    const artists = rows.map(row => {
        const a = rowToArtist(row);
        return {
            id: a.id, name: a.name, email: a.email, slug: a.slug,
            plan: a.plan, planStatus: a.planStatus,
            emailVerified: a.emailVerified, banned: a.banned, banReason: a.banReason,
            createdAt: a.createdAt, lastLoginAt: a.lastLoginAt,
            certCount: row.cert_count || 0
        };
    });
    res.json({ success: true, artists });
});

// ---- Admin: Get Artist Details ----
app.get('/api/admin/artists/:artistId', requireAdmin, (req, res) => {
    const artist = rowToArtist(stmts.getArtistById.get(req.params.artistId));
    if (!artist) return res.status(404).json({ success: false, message: 'Artist not found' });

    const certs = stmts.getCertsByArtist.all(req.params.artistId).map(row => {
        const c = rowToCert(row);
        return {
            id: c.id, title: c.title, medium: c.medium,
            tier: c.tier, tierLabel: c.tierLabel, status: c.status,
            registeredAt: c.registeredAt, artworkImage: c.artworkImage,
            reportCount: c.reportCount
        };
    });

    res.json({
        success: true,
        artist: {
            id: artist.id, name: artist.name, email: artist.email, slug: artist.slug,
            bio: artist.bio, location: artist.location, portfolio: artist.portfolio,
            plan: artist.plan, planStatus: artist.planStatus,
            emailVerified: artist.emailVerified, banned: artist.banned, banReason: artist.banReason,
            createdAt: artist.createdAt, lastLoginAt: artist.lastLoginAt,
            certificateCredits: artist.certificateCredits
        },
        certificates: certs
    });
});

// ---- Admin: List All Certificates ----
app.get('/api/admin/certificates', requireAdmin, (req, res) => {
    const rows = stmts.getAllCerts.all();
    const certificates = rows.map(row => {
        const c = rowToCert(row);
        return {
            id: c.id, title: c.title, artistId: c.artistId, artistName: c.artistName,
            medium: c.medium, tier: c.tier, tierLabel: c.tierLabel, status: c.status,
            registeredAt: c.registeredAt, artworkImage: c.artworkImage, reportCount: c.reportCount
        };
    });
    res.json({ success: true, certificates });
});

// Session restore endpoint
app.get('/api/artist/me', (req, res) => {
    if (!req.session.artistId) {
        return res.json({ success: false });
    }
    const artist = rowToArtist(stmts.getArtistById.get(req.session.artistId));
    if (!artist || artist.banned) {
        req.session.destroy(() => {});
        return res.json({ success: false });
    }
    res.json({ success: true, artist: safeArtist(artist) });
});

// Logout
app.post('/api/artist/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Logout failed' });
        }
        res.clearCookie('oh.sid');
        res.json({ success: true });
    });
});

// Register artist
app.post('/api/artist/register', doubleCsrfProtection, async (req, res) => {
    const { password } = req.body;
    const name = truncate(req.body.name, MAX_LENGTHS.name);
    const email = truncate(req.body.email, MAX_LENGTHS.email);
    const portfolio = truncate(req.body.portfolio, MAX_LENGTHS.portfolio);
    const bio = truncate(req.body.bio, MAX_LENGTHS.bio);
    const location = truncate(req.body.location, MAX_LENGTHS.location);

    const ip = req.ip || req.connection.remoteAddress;
    if (!rateLimit('register:' + ip, 5, 3600000)) {
        return res.status(429).json({ success: false, message: 'Too many registration attempts. Please try again later.' });
    }

    const pwError = validatePassword(password);
    if (pwError) {
        return res.status(400).json({ success: false, message: pwError });
    }

    const existing = stmts.getArtistByEmail.get(email);
    if (existing) {
        return res.status(409).json({ success: false, message: 'An account with this email already exists. Please sign in.' });
    }

    const artistId = uuidv4();
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
    const passwordHash = await bcrypt.hash(password, 10);
    const portfolioVal = portfolio && portfolio.trim() && !/^https?:\/\//i.test(portfolio.trim()) ? 'https://' + portfolio.trim() : (portfolio || '').trim();

    const verificationToken = uuidv4();

    stmts.insertArtist.run({
        id: artistId, name, email, password_hash: passwordHash,
        bio: bio || '', location: location || '', portfolio: portfolioVal,
        slug, plan: 'free', plan_status: 'active', plan_expires_at: null,
        stripe_customer_id: null, stripe_subscription_id: null,
        reset_token: null, reset_token_expires: null,
        created_at: new Date().toISOString()
    });

    // Set email verification fields
    stmts.updateArtistVerification.run(0, verificationToken, artistId);
    stmts.updateLastLogin.run(new Date().toISOString(), artistId);

    const artist = rowToArtist(stmts.getArtistById.get(artistId));
    req.session.artistId = artistId;
    audit('registration', { artistId, email });

    // Send verification email (non-blocking)
    const host = `${req.protocol}://${req.get('host')}`;
    sendVerificationEmail(artist, verificationToken, host);

    res.json({ success: true, artist: safeArtist(artist) });
});

// Sign in artist
app.post('/api/artist/login', doubleCsrfProtection, async (req, res) => {
    const { email, password } = req.body;

    const ip = req.ip || req.connection.remoteAddress;
    if (!rateLimit('login:' + ip, 10, 900000)) {
        return res.status(429).json({ success: false, message: 'Too many login attempts. Please wait 15 minutes.' });
    }

    const artist = rowToArtist(stmts.getArtistByEmail.get(email));

    if (!artist) {
        audit('login_failed', { email, reason: 'not_found' });
        return res.json({ success: false, message: 'No account found with that email.' });
    }

    if (artist.banned) {
        audit('login_failed', { artistId: artist.id, reason: 'banned' });
        return res.json({ success: false, message: 'This account has been suspended. Please contact support if you believe this is an error.' });
    }

    if (!artist.passwordHash) {
        audit('login_failed', { artistId: artist.id, reason: 'no_password' });
        return res.json({ success: false, message: 'This account needs a password. Please use "Forgot password" to set one.' });
    }

    const match = await bcrypt.compare(password, artist.passwordHash);
    if (!match) {
        audit('login_failed', { artistId: artist.id, reason: 'wrong_password' });
        return res.json({ success: false, message: 'Incorrect password.' });
    }

    req.session.artistId = artist.id;
    stmts.updateLastLogin.run(new Date().toISOString(), artist.id);
    audit('login_success', { artistId: artist.id });
    res.json({ success: true, artist: safeArtist(artist) });
});

// Verify email
app.get('/api/artist/verify-email', (req, res) => {
    const { token } = req.query;
    if (!token) {
        return res.status(400).json({ success: false, message: 'Missing verification token' });
    }

    const row = stmts.getArtistByVerificationToken.get(token);
    if (!row) {
        return res.status(400).json({ success: false, message: 'Invalid or expired verification token' });
    }

    stmts.updateArtistVerification.run(1, null, row.id);
    audit('email_verified', { artistId: row.id });

    // Redirect to register page with success indicator
    res.redirect('/register.html#email-verified');
});

// Resend verification email
app.post('/api/artist/resend-verification', doubleCsrfProtection, requireAuth, async (req, res) => {
    const artist = rowToArtist(stmts.getArtistById.get(req.session.artistId));
    if (!artist) {
        return res.status(404).json({ success: false, message: 'Artist not found' });
    }
    if (artist.emailVerified) {
        return res.json({ success: true, message: 'Email already verified' });
    }

    const ip = req.ip || req.connection.remoteAddress;
    if (!rateLimit('resend-verification:' + ip, 3, 3600000)) {
        return res.status(429).json({ success: false, message: 'Too many requests. Please try again later.' });
    }

    const token = uuidv4();
    stmts.updateArtistVerification.run(0, token, artist.id);
    const host = `${req.protocol}://${req.get('host')}`;
    await sendVerificationEmail(artist, token, host);

    res.json({ success: true, message: 'Verification email sent' });
});

// Update artist profile (session-protected)
app.put('/api/artist/:artistId', doubleCsrfProtection, requireAuth, (req, res) => {
    const { artistId } = req.params;
    if (req.session.artistId !== artistId) {
        return res.status(403).json({ success: false, message: 'Not authorized' });
    }

    const artist = rowToArtist(stmts.getArtistById.get(artistId));
    if (!artist) {
        return res.status(404).json({ success: false, message: 'Artist not found' });
    }

    const { name, bio, location, portfolio } = req.body;

    let newName = artist.name;
    let newBio = artist.bio;
    let newLocation = artist.location;
    let newPortfolio = artist.portfolio;
    let newSlug = artist.slug;

    if (name !== undefined) {
        const trimmed = truncate(name, MAX_LENGTHS.name).trim();
        if (!trimmed) return res.status(400).json({ success: false, message: 'Name cannot be empty.' });
        newName = trimmed;
        newSlug = trimmed.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
    }
    if (bio !== undefined) newBio = truncate(bio, MAX_LENGTHS.bio).trim();
    if (location !== undefined) newLocation = truncate(location, MAX_LENGTHS.location).trim();
    if (portfolio !== undefined) {
        let p = truncate(portfolio, MAX_LENGTHS.portfolio).trim();
        if (p && !/^https?:\/\//i.test(p)) p = 'https://' + p;
        newPortfolio = p;
    }

    stmts.updateArtistProfile.run(newName, newBio, newLocation, newPortfolio, newSlug, artistId);
    const updated = rowToArtist(stmts.getArtistById.get(artistId));
    audit('profile_updated', { artistId });
    res.json({ success: true, artist: safeArtist(updated) });
});

// Get artist public profile by slug (public)
app.get('/api/artist/profile/:slug', (req, res) => {
    const { slug } = req.params;
    const artist = rowToArtist(stmts.getArtistBySlug.get(slug));
    if (!artist || artist.banned) {
        return res.json({ success: false, message: 'Artist not found' });
    }

    const certRows = stmts.getCertsByArtist.all(artist.id);
    const certificates = certRows.map(rowToCert).filter(c => c.status === 'verified');

    res.json({
        success: true,
        artist: {
            name: artist.name, bio: artist.bio, location: artist.location,
            portfolio: artist.portfolio, slug: artist.slug,
            memberSince: artist.createdAt, totalCertificates: certificates.length
        },
        certificates: certificates.map(c => ({
            id: c.id, title: c.title, medium: c.medium, tier: c.tier,
            creationDate: c.creationDate, registeredAt: c.registeredAt,
            thumbnailFile: getCertThumbnail(c)
        }))
    });
});

// Data export (GDPR Art. 15/20)
app.get('/api/artist/:artistId/export', requireAuth, (req, res) => {
    const { artistId } = req.params;
    if (req.session.artistId !== artistId) {
        return res.status(403).json({ success: false, message: 'Not authorized' });
    }

    const artist = rowToArtist(stmts.getArtistById.get(artistId));
    if (!artist) {
        return res.status(404).json({ success: false, message: 'Artist not found' });
    }

    const certRows = stmts.getCertsByArtist.all(artistId);
    const certificates = certRows.map(row => {
        const cert = rowToCert(row);
        cert.evidenceFiles = getEvidenceForCert(cert.id);
        cert.history = stmts.getHistory.all(cert.id).map(h => ({
            type: h.type,
            fields: h.fields ? JSON.parse(h.fields) : null,
            createdAt: h.created_at
        }));
        return cert;
    });

    // Reports against this artist's certificates
    const reports = [];
    for (const cert of certificates) {
        const reportRows = db.prepare('SELECT * FROM reports WHERE certificate_id = ?').all(cert.id);
        for (const r of reportRows) {
            reports.push({
                id: r.id,
                certificateId: r.certificate_id,
                reason: r.reason,
                reporterEmail: r.reporter_email,
                type: r.type,
                status: r.status,
                resolution: r.resolution,
                resolvedAt: r.resolved_at,
                createdAt: r.created_at
            });
        }
    }

    const exportData = {
        exportDate: new Date().toISOString(),
        artist: {
            id: artist.id,
            name: artist.name,
            email: artist.email,
            bio: artist.bio,
            location: artist.location,
            portfolio: artist.portfolio,
            slug: artist.slug,
            plan: artist.plan,
            planStatus: artist.planStatus,
            emailVerified: artist.emailVerified,
            createdAt: artist.createdAt,
            lastLoginAt: artist.lastLoginAt
        },
        certificates,
        reports
    };

    audit('data_export', { artistId });

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="data-export.json"');
    res.json(exportData);
});

// Submit artwork for certification (session-protected)
app.post('/api/artwork/submit', requireAuth, (req, res, next) => {
    artworkUpload(req, res, (err) => {
        if (err) {
            return res.status(400).json({ success: false, message: err.message });
        }
        next();
    });
}, doubleCsrfProtection, async (req, res) => {
    const artistId = req.session.artistId;
    const { creationDate, declaration } = req.body;
    const title = truncate(req.body.title, MAX_LENGTHS.title);
    const description = truncate(req.body.description, MAX_LENGTHS.description);
    const medium = truncate(req.body.medium, MAX_LENGTHS.title);
    const processNotes = truncate(req.body.processNotes, MAX_LENGTHS.processNotes);

    if (declaration !== 'true') {
        return res.status(400).json({ success: false, message: 'Declaration required' });
    }

    const artist = rowToArtist(stmts.getArtistById.get(artistId));
    if (!artist) {
        return res.status(404).json({ success: false, message: 'Artist not found' });
    }

    // Check email verification
    if (!artist.emailVerified) {
        return res.status(403).json({ success: false, message: 'Please verify your email address before submitting artwork.' });
    }

    // Check work limit for Free tier
    if (!isCreator(artist)) {
        const certCount = stmts.countCertsByArtist.get(artistId).n;
        const limit = 3 + (artist.certificateCredits || 0);
        if (certCount >= limit) {
            return res.status(403).json({
                success: false,
                message: 'You\'ve reached your certificate limit. Buy a single certificate (£2) or upgrade to Creator for unlimited.',
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
    try { visibility = JSON.parse(req.body.evidenceVisibility || '[]'); } catch (e) { /* default */ }

    const fileCount = (artworkImage ? 1 : 0) + rawEvidence.length;
    const tierResult = calculateTier(fileCount, description, !!processNotes);
    const certificateId = generateCertificateId();

    // Insert certificate + evidence in a transaction
    const insertAll = db.transaction(() => {
        stmts.insertCert.run({
            id: certificateId, artist_id: artistId, artist_name: artist.name,
            artist_slug: artist.slug, title, description: description || '',
            medium: medium || '', creation_date: creationDate || '',
            process_notes: processNotes || '', artwork_image: artworkImage,
            tier: tierResult.tier, tier_label: tierResult.label,
            evidence_strength: tierResult.strength, status: 'verified',
            report_count: 0, registered_at: new Date().toISOString()
        });

        for (let i = 0; i < rawEvidence.length; i++) {
            stmts.insertEvidence.run(certificateId, rawEvidence[i].filename, visibility[i] === true ? 1 : 0);
        }
    });
    insertAll();

    audit('certificate_created', { artistId, certificateId, tier: tierResult.tier });

    // Build response certificate object
    const cert = rowToCert(stmts.getCertById.get(certificateId));
    cert.evidenceFiles = getEvidenceForCert(certificateId);

    // Send certificate email (non-blocking)
    const host = `${req.protocol}://${req.get('host')}`;
    sendCertificateEmail(artist, cert, host);

    res.json({ success: true, certificate: cert });
});

// Get certificates for current session artist (session-protected)
app.get('/api/artist/:artistId/certificates', requireAuth, (req, res) => {
    const artistId = req.session.artistId;
    const certRows = stmts.getCertsByArtist.all(artistId);
    const certificates = certRows.map(row => {
        const cert = rowToCert(row);
        cert.evidenceFiles = getEvidenceForCert(cert.id);
        return cert;
    });
    res.json({ success: true, certificates });
});

// Verify certificate (public)
app.get('/api/verify/:certificateId', (req, res) => {
    const { certificateId } = req.params;
    const row = stmts.getCertById.get(certificateId.toUpperCase());
    const certificate = rowToCert(row);

    if (certificate) {
        // Check if certificate is revoked or artist is banned
        const artist = rowToArtist(stmts.getArtistById.get(certificate.artistId));
        if (certificate.status === 'revoked' || (artist && artist.banned)) {
            return res.json({
                success: true,
                verified: false,
                revoked: true,
                message: 'This certificate has been revoked and is no longer valid.'
            });
        }

        const evidenceFiles = getEvidenceForCert(certificate.id);
        res.json({
            success: true,
            verified: true,
            certificate: {
                id: certificate.id, artistName: certificate.artistName,
                artistSlug: certificate.artistSlug, title: certificate.title,
                description: certificate.description, medium: certificate.medium,
                creationDate: certificate.creationDate, registeredAt: certificate.registeredAt,
                status: certificate.status, tier: certificate.tier,
                tierLabel: certificate.tierLabel, evidenceStrength: certificate.evidenceStrength,
                evidenceCount: evidenceFiles.length,
                hasProcessNotes: !!certificate.processNotes,
                artworkImage: certificate.artworkImage || null,
                publicEvidenceFiles: getPublicEvidence(certificate.id),
                processNotes: certificate.processNotes || ''
            }
        });
    } else {
        res.json({ success: true, verified: false, message: 'Certificate not found' });
    }
});

// Generate QR code for certificate (JSON response)
app.get('/api/qr/:certificateId', async (req, res) => {
    const { certificateId } = req.params;
    const verifyUrl = `${req.protocol}://${req.get('host')}/verify.html?code=${certificateId}`;

    try {
        const qrDataUrl = await QRCode.toDataURL(verifyUrl, {
            width: 200, margin: 2,
            color: { dark: '#2a2520', light: '#f5f0e8' }
        });
        res.json({ success: true, qrCode: qrDataUrl, verifyUrl });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to generate QR code' });
    }
});

// Generate QR code as PNG image (for use in emails and external embeds)
app.get('/api/qr/:certificateId/image', async (req, res) => {
    const { certificateId } = req.params;
    const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
    const verifyUrl = `${baseUrl}/verify.html?code=${certificateId}`;

    try {
        const buffer = await QRCode.toBuffer(verifyUrl, {
            width: 200, margin: 2,
            color: { dark: '#2a2520', light: '#f5f0e8' }
        });
        res.set('Content-Type', 'image/png');
        res.set('Cache-Control', 'public, max-age=86400');
        res.send(buffer);
    } catch (err) {
        res.status(500).send('Failed to generate QR code');
    }
});

// Embeddable badge (public)
app.get('/api/badge/:certificateId', (req, res) => {
    const { certificateId } = req.params;
    const cert = rowToCert(stmts.getCertById.get(certificateId.toUpperCase()));

    if (!cert) {
        return res.status(404).send('Certificate not found');
    }

    // Block badges for revoked certs or banned artists
    const badgeArtist = rowToArtist(stmts.getArtistById.get(cert.artistId));
    if (cert.status === 'revoked' || (badgeArtist && badgeArtist.banned)) {
        return res.status(404).send('Certificate not found');
    }

    const tierColors = {
        gold: { bg: '#a08530', text: '#fafafa' },
        silver: { bg: '#9ca3af', text: '#fafafa' },
        bronze: { bg: '#c4935a', text: '#fafafa' }
    };
    const colors = tierColors[cert.tier] || tierColors.bronze;

    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="36" viewBox="0 0 200 36">
  <rect width="200" height="36" rx="4" fill="${colors.bg}"/>
  <rect x="1" y="1" width="198" height="34" rx="3" fill="none" stroke="${colors.text}" stroke-opacity="0.3"/>
  <text x="28" y="22" font-family="Inter,-apple-system,sans-serif" font-size="11" fill="${colors.text}" font-weight="bold">officiallyhuman.art</text>
  <text x="115" y="22" font-family="monospace" font-size="9" fill="${colors.text}" opacity="0.85">${cert.id}</text>
  <circle cx="14" cy="18" r="8" fill="${colors.text}" opacity="0.2"/>
  <text x="14" y="22" font-family="Inter,-apple-system,sans-serif" font-size="10" fill="${colors.text}" text-anchor="middle" font-weight="bold">OH</text>
</svg>`;

    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.send(svg);
});

// Embeddable widget (public)
app.get('/api/widget/:certificateId', (req, res) => {
    const { certificateId } = req.params;
    const cert = rowToCert(stmts.getCertById.get(certificateId.toUpperCase()));

    const widgetNotFound = '<html><body style="margin:0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100%;color:#888888;font-size:14px;">Certificate not found</body></html>';
    if (!cert) {
        res.setHeader('Content-Type', 'text/html');
        return res.send(widgetNotFound);
    }

    // Block widgets for revoked certs or banned artists
    const widgetArtist = rowToArtist(stmts.getArtistById.get(cert.artistId));
    if (cert.status === 'revoked' || (widgetArtist && widgetArtist.banned)) {
        res.setHeader('Content-Type', 'text/html');
        return res.send(widgetNotFound);
    }

    const host = `${req.protocol}://${req.get('host')}`;
    const verifyUrl = `${host}/verify.html?code=${cert.id}`;
    const tierColors = { gold: '#a08530', silver: '#6b7280', bronze: '#a0764a' };
    const tierBgs = { gold: '#faf3e0', silver: '#edf0f4', bronze: '#f5ebe0' };
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
.card{border:1px solid rgba(26,26,26,0.12);border-radius:10px;overflow:hidden;background:#fff;max-width:340px;box-shadow:0 1px 4px rgba(0,0,0,0.06)}
.card:hover{box-shadow:0 2px 8px rgba(0,0,0,0.1)}
.header{background:#2a2520;color:#fafafa;padding:0.6rem 1rem;display:flex;align-items:center;justify-content:space-between}
.logo{font-family:Inter,-apple-system,sans-serif;font-weight:700;font-size:0.95rem}
.logo span{color:#999}
.check{background:rgba(250,250,250,0.15);border-radius:100px;padding:0.15rem 0.6rem;font-size:0.65rem;letter-spacing:0.04em}
.body{padding:1rem;display:flex;gap:0.85rem;align-items:flex-start}
.thumb{width:64px;height:64px;border-radius:6px;object-fit:cover;background:#ebe5da;flex-shrink:0}
.thumb-placeholder{width:64px;height:64px;border-radius:6px;background:#ebe5da;flex-shrink:0;display:flex;align-items:center;justify-content:center;color:#a0aec0;font-family:Inter,-apple-system,sans-serif;font-size:1.2rem;font-weight:700}
.info{flex:1;min-width:0}
.title{font-weight:600;color:#1a1a1a;font-size:0.88rem;line-height:1.3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.artist{color:#888888;font-size:0.78rem;margin-top:0.15rem}
.meta{display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem}
.tier{padding:0.15rem 0.55rem;border-radius:100px;font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.04em}
.cert-id{font-family:monospace;font-size:0.68rem;color:#a0aec0;letter-spacing:0.04em}
.footer{border-top:1px solid rgba(26,26,26,0.06);padding:0.5rem 1rem;text-align:center;font-size:0.65rem;color:#a0aec0}
</style></head>
<body><a href="${verifyUrl}" target="_blank" rel="noopener">
<div class="card">
  <div class="header">
    <div class="logo"><span>officially</span>human.art</div>
    <div class="check">&#10003; Verified</div>
  </div>
  <div class="body">
    ${thumbnail
      ? `<img class="thumb" src="${thumbnail}" alt="">`
      : `<div class="thumb-placeholder">OH</div>`}
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

// Embed code endpoint (public)
app.get('/api/embed/:certificateId', (req, res) => {
    const { certificateId } = req.params;
    const host = `${req.protocol}://${req.get('host')}`;
    const badgeUrl = `${host}/api/badge/${certificateId}`;
    const verifyUrl = `${host}/verify.html?code=${certificateId}`;
    const widgetUrl = `${host}/api/widget/${certificateId}`;

    res.json({
        success: true,
        html: `<a href="${verifyUrl}" target="_blank" rel="noopener"><img src="${badgeUrl}" alt="Verified Officially Human Art" style="height:36px"></a>`,
        markdown: `[![Verified Officially Human Art](${badgeUrl})](${verifyUrl})`,
        widget: `<iframe src="${widgetUrl}" width="340" height="160" style="border:none;border-radius:10px;" loading="lazy"></iframe>`,
        badgeUrl, verifyUrl, widgetUrl
    });
});

// Stripe config (public)
app.get('/api/config', (req, res) => {
    res.json({ stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY || null });
});

// Get artist plan info (session-protected)
app.get('/api/artist/plan/:artistId', requireAuth, (req, res) => {
    const artistId = req.session.artistId;
    const artist = rowToArtist(stmts.getArtistById.get(artistId));
    if (!artist) return res.status(404).json({ success: false, message: 'Artist not found' });

    const certCount = stmts.countCertsByArtist.get(artistId).n;
    const plan = getEffectivePlan(artist);

    res.json({
        success: true, plan,
        planStatus: artist.planStatus || 'active',
        planExpiresAt: artist.planExpiresAt || null,
        certificateCount: certCount,
        certificateCredits: artist.certificateCredits || 0,
        certificateLimit: plan === 'creator' ? null : 3 + (artist.certificateCredits || 0)
    });
});

// Create Stripe subscription (session-protected)
app.post('/api/stripe/create-subscription', doubleCsrfProtection, requireAuth, async (req, res) => {
    if (!stripe) return res.status(400).json({ success: false, message: 'Payments not configured' });
    if (!process.env.STRIPE_CREATOR_PRICE_ID) return res.status(400).json({ success: false, message: 'Creator price not configured. Set STRIPE_CREATOR_PRICE_ID.' });

    const artistId = req.session.artistId;
    const artist = rowToArtist(stmts.getArtistById.get(artistId));
    if (!artist) return res.status(404).json({ success: false, message: 'Artist not found' });

    try {
        let customerId = artist.stripeCustomerId;
        if (!customerId) {
            const customer = await stripe.customers.create({
                email: artist.email, name: artist.name,
                metadata: { artistId: artist.id }
            });
            customerId = customer.id;
            stmts.updateArtistStripeCustomer.run(customerId, artistId);
        }

        const subscription = await stripe.subscriptions.create({
            customer: customerId,
            items: [{ price: process.env.STRIPE_CREATOR_PRICE_ID }],
            payment_behavior: 'default_incomplete',
            payment_settings: { save_default_payment_method: 'on_subscription' },
            expand: ['latest_invoice.payment_intent']
        });

        stmts.updateArtistStripeSubscription.run(subscription.id, artistId);

        console.log('Stripe sub created:', { status: subscription.status, invoiceStatus: subscription.latest_invoice?.status, piStatus: subscription.latest_invoice?.payment_intent?.status, amount: subscription.latest_invoice?.amount_due });

        // If subscription is already active (e.g. free trial, £0 invoice), no payment needed
        if (subscription.status === 'active') {
            stmts.updateArtistPlan.run('creator', 'active', null, artistId);
            return res.json({ success: true, subscriptionId: subscription.id, active: true });
        }

        const paymentIntent = subscription.latest_invoice && subscription.latest_invoice.payment_intent;
        if (!paymentIntent || !paymentIntent.client_secret) {
            // Cancel the incomplete subscription before redirecting to Checkout
            try { await stripe.subscriptions.cancel(subscription.id); } catch (e) { console.log('Could not cancel incomplete sub:', e.message); }
            stmts.updateArtistStripeSubscription.run(null, artistId);

            // Fallback: use Stripe Checkout instead
            const checkoutSession = await stripe.checkout.sessions.create({
                customer: customerId,
                mode: 'subscription',
                line_items: [{ price: process.env.STRIPE_CREATOR_PRICE_ID, quantity: 1 }],
                success_url: `${req.protocol}://${req.get('host')}/register.html?subscribed=1`,
                cancel_url: `${req.protocol}://${req.get('host')}/register.html`,
                metadata: { artistId }
            });
            return res.json({ success: true, checkoutUrl: checkoutSession.url });
        }

        res.json({
            success: true,
            subscriptionId: subscription.id,
            clientSecret: paymentIntent.client_secret
        });
    } catch (err) {
        console.error('Stripe create subscription error:', err.type, err.message, err.code);
        res.status(500).json({ success: false, message: 'Subscription error: ' + (err.message || 'Unknown error') });
    }
});

// Cancel Stripe subscription (session-protected)
app.post('/api/stripe/cancel-subscription', doubleCsrfProtection, requireAuth, async (req, res) => {
    if (!stripe) return res.status(400).json({ success: false, message: 'Payments not configured' });

    const artistId = req.session.artistId;
    const artist = rowToArtist(stmts.getArtistById.get(artistId));
    if (!artist || !artist.stripeSubscriptionId) {
        return res.status(400).json({ success: false, message: 'No active subscription found' });
    }

    try {
        const subscription = await stripe.subscriptions.update(artist.stripeSubscriptionId, {
            cancel_at_period_end: true
        });

        const periodEnd = subscription.current_period_end
            ? new Date(subscription.current_period_end * 1000).toISOString()
            : null;

        stmts.updateArtistPlan.run('creator', 'canceling', periodEnd, artistId);

        // Send cancellation confirmation email
        if (emailEnabled) {
            const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
            const periodEndFormatted = periodEnd
                ? new Date(subscription.current_period_end * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })
                : 'the end of your billing period';
            sendEmail({
                from: process.env.SMTP_FROM || process.env.SMTP_USER,
                to: artist.email,
                subject: 'Your Creator plan cancellation — Officially Human Art',
                html: `
                <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#f5f0e8;">
                    <div style="background:#2a2520;color:#fafafa;padding:2rem;text-align:center;">
                        <div style="font-family:Inter,-apple-system,sans-serif;font-size:1.2rem;font-weight:600;"><span style="font-weight:300;color:#999;">officially</span><span style="font-weight:600;">human</span><span style="font-weight:700;font-size:1.5rem;">.art</span></div>
                    </div>
                    <div style="padding:2rem;">
                        <p style="color:#666666;margin-bottom:1.5rem;">Hi ${artist.name},</p>
                        <p style="color:#666666;margin-bottom:1.5rem;">Your Creator plan has been set to cancel. You'll continue to have full access to unlimited certificates until <strong>${periodEndFormatted}</strong>.</p>
                        <p style="color:#666666;margin-bottom:1.5rem;">After that, your account will move to the Free plan. <strong>All your existing certificates will remain fully active</strong> — badges, QR codes, and verification pages will continue to work as normal.</p>
                        <p style="color:#666666;margin-bottom:1.5rem;">Changed your mind? You can resubscribe at any time from your dashboard.</p>
                        <div style="text-align:center;margin-bottom:1.5rem;">
                            <a href="${baseUrl}/register.html#dashboard" style="display:inline-block;padding:0.75rem 2rem;background:#2a2520;color:#fafafa;text-decoration:none;border-radius:6px;font-weight:600;font-size:0.9rem;">Go to Dashboard</a>
                        </div>
                        <p style="color:#888888;font-size:0.82rem;">Thank you for supporting Officially Human Art.</p>
                    </div>
                    <div style="background:#ebe5da;padding:1.25rem;text-align:center;font-size:0.75rem;color:#a0aec0;border-top:1px solid rgba(26,26,26,0.06);">
                        <p style="margin:0;">&copy; 2026 Officially Human Art</p>
                    </div>
                </div>`
            }).catch(err => console.error('Failed to send cancellation email:', err.message));
        }

        res.json({
            success: true,
            message: 'Subscription will cancel at end of billing period',
            planExpiresAt: periodEnd
        });
    } catch (err) {
        console.error('Stripe cancel error:', err.type, err.message, err.code);
        res.status(500).json({ success: false, message: 'Cancel error: ' + (err.message || 'Unknown error') });
    }
});

// Buy a single certificate credit (one-time £2 payment via Stripe Checkout)
app.post('/api/stripe/buy-credit', doubleCsrfProtection, requireAuth, async (req, res) => {
    if (!stripe) return res.status(400).json({ success: false, message: 'Payments not configured' });

    const artistId = req.session.artistId;
    const artist = rowToArtist(stmts.getArtistById.get(artistId));
    if (!artist) return res.status(404).json({ success: false, message: 'Artist not found' });

    try {
        let customerId = artist.stripeCustomerId;
        if (!customerId) {
            const customer = await stripe.customers.create({
                email: artist.email, name: artist.name,
                metadata: { artistId: artist.id }
            });
            customerId = customer.id;
            stmts.updateArtistStripeCustomer.run(customerId, artistId);
        }

        const host = `${req.protocol}://${req.get('host')}`;
        const session = await stripe.checkout.sessions.create({
            customer: customerId,
            mode: 'payment',
            line_items: [{
                price_data: {
                    currency: 'gbp',
                    product_data: { name: 'Single Certificate Credit', description: 'One additional certified work on Officially Human Art' },
                    unit_amount: 200 // £2.00
                },
                quantity: 1
            }],
            metadata: { artistId: artist.id, type: 'certificate_credit' },
            success_url: `${host}/register.html?credit_purchased=1`,
            cancel_url: `${host}/register.html`
        });

        res.json({ success: true, url: session.url });
    } catch (err) {
        console.error('Stripe buy credit error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to create payment. Please try again.' });
    }
});

// Delete certificate (session-protected)
app.delete('/api/artwork/:certificateId', doubleCsrfProtection, requireAuth, (req, res) => {
    const { certificateId } = req.params;
    const artistId = req.session.artistId;

    const cert = rowToCert(stmts.getCertById.get(certificateId.toUpperCase()));
    if (!cert) {
        return res.status(404).json({ success: false, message: 'Certificate not found' });
    }
    if (cert.artistId !== artistId) {
        return res.status(403).json({ success: false, message: 'Not authorized' });
    }

    // Delete associated files
    if (cert.artworkImage) {
        const artPath = path.join(UPLOADS_DIR, cert.artworkImage);
        if (fs.existsSync(artPath)) fs.unlinkSync(artPath);
    }
    const evidenceFiles = getEvidenceForCert(cert.id);
    evidenceFiles.forEach(ef => {
        const fPath = path.join(UPLOADS_DIR, ef.filename);
        if (fs.existsSync(fPath)) fs.unlinkSync(fPath);
    });

    stmts.deleteCert.run(certificateId.toUpperCase());
    audit('certificate_deleted', { artistId, certificateId: certificateId.toUpperCase() });
    res.json({ success: true, message: 'Certificate deleted' });
});

// Edit certificate (session-protected)
app.put('/api/artwork/:certificateId', doubleCsrfProtection, requireAuth, (req, res) => {
    const { certificateId } = req.params;
    const artistId = req.session.artistId;
    const title = req.body.title !== undefined ? truncate(req.body.title, MAX_LENGTHS.title) : undefined;
    const description = req.body.description !== undefined ? truncate(req.body.description, MAX_LENGTHS.description) : undefined;
    const processNotes = req.body.processNotes !== undefined ? truncate(req.body.processNotes, MAX_LENGTHS.processNotes) : undefined;

    const cert = rowToCert(stmts.getCertById.get(certificateId.toUpperCase()));
    if (!cert) {
        return res.status(404).json({ success: false, message: 'Certificate not found' });
    }
    if (cert.artistId !== artistId) {
        return res.status(403).json({ success: false, message: 'Not authorized' });
    }

    // Track changes
    const changes = [];
    if (title !== undefined && title.trim() && title.trim() !== cert.title) changes.push('title');
    if (description !== undefined && description.trim() !== (cert.description || '')) changes.push('description');
    if (processNotes !== undefined && processNotes.trim() !== (cert.processNotes || '')) changes.push('process notes');

    if (changes.length > 0) {
        stmts.insertHistory.run(cert.id, 'edited', JSON.stringify(changes), new Date().toISOString());
    }

    // Update fields
    let newTitle = cert.title;
    let newDescription = cert.description;
    let newProcessNotes = cert.processNotes;
    let newArtistName = cert.artistName;

    if (title !== undefined && title.trim()) {
        newTitle = title.trim();
        const artist = rowToArtist(stmts.getArtistById.get(artistId));
        newArtistName = artist ? artist.name : cert.artistName;
    }
    if (description !== undefined) newDescription = description.trim();
    if (processNotes !== undefined) newProcessNotes = processNotes.trim();

    // Recalculate tier
    const evidenceFiles = getEvidenceForCert(cert.id);
    const fileCount = (cert.artworkImage ? 1 : 0) + evidenceFiles.length;
    const tierResult = calculateTier(fileCount, newDescription, !!newProcessNotes);

    stmts.updateCert.run(newTitle, newDescription, newProcessNotes, tierResult.tier, tierResult.label, tierResult.strength, newArtistName, cert.id);
    audit('certificate_edited', { artistId, certificateId: certificateId.toUpperCase(), fields: changes });

    const updated = rowToCert(stmts.getCertById.get(cert.id));
    updated.evidenceFiles = evidenceFiles;
    res.json({ success: true, certificate: updated });
});

// Report/dispute a certificate (public, CSRF-protected)
app.post('/api/report/:certificateId', doubleCsrfProtection, (req, res) => {
    const { certificateId } = req.params;
    const reason = truncate(req.body.reason, MAX_LENGTHS.reportReason);
    const email = truncate(req.body.email, MAX_LENGTHS.email);

    if (!reason || reason.trim().length < 10) {
        return res.status(400).json({ success: false, message: 'Please provide a reason (at least 10 characters).' });
    }

    const cert = rowToCert(stmts.getCertById.get(certificateId.toUpperCase()));
    if (!cert) {
        return res.status(404).json({ success: false, message: 'Certificate not found' });
    }

    const reportId = uuidv4();
    stmts.insertReport.run(reportId, certificateId.toUpperCase(), reason.trim(), email || null, 'pending', new Date().toISOString());
    stmts.insertHistory.run(certificateId.toUpperCase(), 'reported', null, new Date().toISOString());
    stmts.updateCertReportCount.run(certificateId.toUpperCase());

    audit('certificate_reported', { certificateId: certificateId.toUpperCase(), reportId });

    // Notify admin via email
    if (emailEnabled) {
        sendEmail({
            from: process.env.SMTP_FROM || process.env.SMTP_USER,
            to: process.env.ADMIN_EMAIL || 'matt@mattlewsey.com',
            subject: `Certificate Report: ${certificateId.toUpperCase()}`,
            text: `A certificate has been reported.\n\nCertificate: ${certificateId.toUpperCase()}\nTitle: ${cert.title}\nArtist: ${cert.artistName}\nReason: ${reason.trim()}\nReporter email: ${email || 'Not provided'}\n\nReview at: /admin.html`
        }).catch(err => console.error('Failed to send report notification:', err.message));
    }

    res.json({ success: true, message: 'Report submitted. We will review this certificate.' });
});

// Get certificate history/timeline (public)
app.get('/api/artwork/:certificateId/history', (req, res) => {
    const { certificateId } = req.params;
    const cert = rowToCert(stmts.getCertById.get(certificateId.toUpperCase()));
    if (!cert) {
        return res.status(404).json({ success: false, message: 'Certificate not found' });
    }

    const historyRows = stmts.getHistory.all(certificateId.toUpperCase());
    const timeline = [{ type: 'issued', at: cert.registeredAt }];
    historyRows.forEach(h => {
        const entry = { type: h.type, at: h.created_at };
        if (h.fields) {
            try { entry.fields = JSON.parse(h.fields); } catch (e) {}
        }
        timeline.push(entry);
    });
    timeline.sort((a, b) => new Date(a.at) - new Date(b.at));

    res.json({ success: true, timeline });
});

// Browse all certificates (public)
app.get('/api/browse', (req, res) => {
    const { medium, tier, page } = req.query;
    const pageNum = parseInt(page) || 1;
    const perPage = 24;

    let certs;
    const hasMedium = medium && medium !== 'all';
    const hasTier = tier && tier !== 'all';

    if (hasMedium && hasTier) {
        certs = stmts.browseCertsFilterBoth.all('verified', medium, tier);
    } else if (hasMedium) {
        certs = stmts.browseCertsFilterMedium.all('verified', medium);
    } else if (hasTier) {
        certs = stmts.browseCertsFilterTier.all('verified', tier);
    } else {
        certs = stmts.browseCerts.all('verified');
    }

    const total = certs.length;
    const totalPages = Math.ceil(total / perPage);
    const paginated = certs.slice((pageNum - 1) * perPage, pageNum * perPage);
    const mediums = stmts.allMediums.all().map(r => r.medium);

    res.json({
        success: true,
        certificates: paginated.map(c => ({
            id: c.id, title: c.title, artistName: c.artist_name,
            artistSlug: c.artist_slug, medium: c.medium, tier: c.tier,
            registeredAt: c.registered_at, artworkImage: c.artwork_image || null
        })),
        mediums, page: pageNum, totalPages, total
    });
});

// Password reset — request token (CSRF-protected)
// No CSRF needed — rate-limited, only sends an email, no state change risk
app.post('/api/artist/forgot-password', async (req, res) => {
    const { email } = req.body;

    const ip = req.ip || req.connection.remoteAddress;
    if (!rateLimit('forgot:' + ip, 3, 3600000)) {
        return res.status(429).json({ success: false, message: 'Too many reset requests. Please try again later.' });
    }

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    const artist = rowToArtist(stmts.getArtistByEmail.get(email));
    if (!artist) {
        return res.json({ success: true, message: 'If an account exists with that email, a reset link has been sent.' });
    }

    const token = uuidv4();
    stmts.updateArtistResetToken.run(token, new Date(Date.now() + 3600000).toISOString(), artist.id);

    if (emailEnabled) {
        const host = `${req.protocol}://${req.get('host')}`;
        const resetUrl = `${host}/register.html#reset=${token}`;
        try {
            await sendEmail({
                from: process.env.SMTP_FROM || process.env.SMTP_USER,
                to: artist.email,
                subject: 'Officially Human Art — Password Reset',
                html: `
                <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#f5f0e8;">
                    <div style="background:#2a2520;color:#fafafa;padding:2rem;text-align:center;">
                        <div style="font-family:Inter,-apple-system,sans-serif;font-size:1.2rem;font-weight:600;"><span style="font-weight:300;color:#999;">officially</span><span style="font-weight:600;">human</span><span style="font-weight:700;font-size:1.5rem;">.art</span></div>
                    </div>
                    <div style="padding:2rem;">
                        <p style="color:#666666;margin-bottom:1.5rem;">Hi ${artist.name},</p>
                        <p style="color:#666666;margin-bottom:1.5rem;">We received a request to reset your password. Click the button below to choose a new password:</p>
                        <div style="text-align:center;margin-bottom:1.5rem;">
                            <a href="${resetUrl}" style="display:inline-block;padding:0.75rem 2rem;background:#2a2520;color:#fafafa;text-decoration:none;border-radius:6px;font-weight:600;font-size:0.9rem;">Reset Password</a>
                        </div>
                        <p style="color:#888888;font-size:0.82rem;">This link expires in 1 hour. If you didn't request a password reset, you can safely ignore this email.</p>
                    </div>
                    <div style="background:#ebe5da;padding:1.25rem;text-align:center;font-size:0.75rem;color:#a0aec0;border-top:1px solid rgba(26,26,26,0.06);">
                        <p style="margin:0;">&copy; 2026 Officially Human Art</p>
                    </div>
                </div>`
            });
        } catch (err) {
            console.error('Failed to send reset email:', err.message);
        }
    }

    res.json({ success: true, message: 'If an account exists with that email, a reset link has been sent.' });
});

// Password reset — set new password (CSRF-protected)
// No CSRF needed — requires valid one-time reset token, rate-limited by forgot-password
app.post('/api/artist/reset-password', async (req, res) => {
    const { token, password } = req.body;

    if (!token || !password) {
        return res.status(400).json({ success: false, message: 'Token and password are required.' });
    }
    const pwError = validatePassword(password);
    if (pwError) {
        return res.status(400).json({ success: false, message: pwError });
    }

    const artist = rowToArtist(stmts.getArtistByResetToken.get(token, new Date().toISOString()));
    if (!artist) {
        return res.status(400).json({ success: false, message: 'Invalid or expired reset link. Please request a new one.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    stmts.updateArtistPassword.run(passwordHash, artist.id);
    audit('password_reset', { artistId: artist.id });

    res.json({ success: true, message: 'Password updated successfully. You can now sign in.' });
});

// Stats endpoint (public)
app.get('/api/stats', (req, res) => {
    const artists = stmts.countArtists.get().n;
    const certificates = stmts.countCerts.get().n;
    const tiers = { gold: 0, silver: 0, bronze: 0 };
    stmts.countTiers.all().forEach(r => {
        if (tiers[r.tier] !== undefined) tiers[r.tier] = r.n;
    });
    res.json({ success: true, artists, certificates, tiers });
});

// Delete account (session-protected)
app.delete('/api/artist/:artistId', doubleCsrfProtection, requireAuth, async (req, res) => {
    const { artistId } = req.params;
    if (req.session.artistId !== artistId) {
        return res.status(403).json({ success: false, message: 'Not authorized' });
    }

    const { password } = req.body;
    if (!password) {
        return res.status(400).json({ success: false, message: 'Password is required to delete your account.' });
    }

    const artist = rowToArtist(stmts.getArtistById.get(artistId));
    if (!artist) {
        return res.status(404).json({ success: false, message: 'Account not found.' });
    }

    if (artist.passwordHash) {
        const match = await bcrypt.compare(password, artist.passwordHash);
        if (!match) {
            return res.status(403).json({ success: false, message: 'Incorrect password.' });
        }
    }

    // Cancel Stripe subscription if active
    if (stripe && artist.stripeSubscriptionId) {
        try { await stripe.subscriptions.cancel(artist.stripeSubscriptionId); } catch (err) {
            console.error('Stripe cancel on account delete:', err.message);
        }
    }

    // Delete files from disk
    const certRows = stmts.getCertsByArtist.all(artistId);
    certRows.forEach(row => {
        if (row.artwork_image) {
            const artPath = path.join(UPLOADS_DIR, row.artwork_image);
            if (fs.existsSync(artPath)) fs.unlinkSync(artPath);
        }
        const evidenceFiles = stmts.getEvidenceFiles.all(row.id);
        evidenceFiles.forEach(ef => {
            const fPath = path.join(UPLOADS_DIR, ef.filename);
            if (fs.existsSync(fPath)) fs.unlinkSync(fPath);
        });
    });

    // Delete all data in a transaction (cascading)
    const deleteAll = db.transaction(() => {
        stmts.deleteReportsByArtist.run(artistId);
        stmts.deleteHistoryByArtist.run(artistId);
        stmts.deleteEvidenceByArtist.run(artistId);
        stmts.deleteCertsByArtist.run(artistId);
        stmts.deleteArtist.run(artistId);
    });
    deleteAll();

    audit('account_deleted', { artistId, certificatesDeleted: certRows.length });

    req.session.destroy(() => {});
    res.clearCookie('oh.sid');
    res.json({ success: true, message: 'Account and all associated data have been permanently deleted.' });
});

// Lightweight page view tracking (no cookies, no personal data)
app.post('/api/pageview', (req, res) => {
    const { page, referrer } = req.body;
    if (!page || typeof page !== 'string') return res.status(400).json({ success: false });
    const cleanPage = page.split('?')[0].substring(0, 200);
    const cleanReferrer = (referrer || '').substring(0, 500);
    const date = new Date().toISOString().split('T')[0];
    db.prepare('INSERT INTO page_views (page, referrer, date) VALUES (?, ?, ?)').run(cleanPage, cleanReferrer, date);
    res.json({ success: true });
});

// Admin: analytics summary
app.get('/api/admin/analytics', requireAdmin, (req, res) => {
    const days = parseInt(req.query.days) || 30;
    const since = new Date(Date.now() - days * 86400000).toISOString().split('T')[0];

    const totalViews = db.prepare('SELECT COUNT(*) as n FROM page_views WHERE date >= ?').get(since).n;
    const byPage = db.prepare('SELECT page, COUNT(*) as views FROM page_views WHERE date >= ? GROUP BY page ORDER BY views DESC LIMIT 20').all(since);
    const byDay = db.prepare('SELECT date, COUNT(*) as views FROM page_views WHERE date >= ? GROUP BY date ORDER BY date').all(since);
    const topReferrers = db.prepare("SELECT referrer, COUNT(*) as views FROM page_views WHERE date >= ? AND referrer != '' GROUP BY referrer ORDER BY views DESC LIMIT 10").all(since);
    const subscribers = db.prepare('SELECT COUNT(*) as n FROM newsletter_subscribers WHERE unsubscribed_at IS NULL').get().n;

    res.json({ success: true, days, totalViews, byPage, byDay, topReferrers, subscribers });
});

// Newsletter subscribe
app.post('/api/newsletter/subscribe', doubleCsrfProtection, (req, res) => {
    const { email, source } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
    }

    const ip = req.ip || req.connection.remoteAddress;
    if (!rateLimit('newsletter:' + ip, 5, 3600000)) {
        return res.status(429).json({ success: false, message: 'Too many requests. Please try again later.' });
    }

    const existing = db.prepare('SELECT * FROM newsletter_subscribers WHERE email = ?').get(email.toLowerCase().trim());
    if (existing) {
        if (existing.unsubscribed_at) {
            db.prepare('UPDATE newsletter_subscribers SET unsubscribed_at = NULL, subscribed_at = ? WHERE email = ?')
                .run(new Date().toISOString(), email.toLowerCase().trim());
            return res.json({ success: true, message: 'Welcome back! You\'ve been re-subscribed.' });
        }
        return res.json({ success: true, message: 'You\'re already subscribed!' });
    }

    db.prepare('INSERT INTO newsletter_subscribers (email, source, subscribed_at) VALUES (?, ?, ?)')
        .run(email.toLowerCase().trim(), source || 'website', new Date().toISOString());

    res.json({ success: true, message: 'Thanks for subscribing! We\'ll keep you updated.' });
});

// Newsletter unsubscribe
app.get('/api/newsletter/unsubscribe', (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).send('Missing email.');
    db.prepare('UPDATE newsletter_subscribers SET unsubscribed_at = ? WHERE email = ?')
        .run(new Date().toISOString(), email.toLowerCase().trim());
    res.send('<html><body style="font-family:sans-serif;text-align:center;padding:4rem;"><h2>You\'ve been unsubscribed.</h2><p>You will no longer receive emails from Officially Human Art.</p></body></html>');
});

// Copyright takedown request
app.post('/api/takedown', doubleCsrfProtection, (req, res) => {
    const { claimantName, claimantEmail, copyrightedWork, certificateId, swornStatement } = req.body;

    if (!claimantName || !claimantEmail || !copyrightedWork || !certificateId || !swornStatement) {
        return res.status(400).json({ success: false, message: 'All fields are required for a takedown request.' });
    }

    const ip = req.ip || req.connection.remoteAddress;
    if (!rateLimit('takedown:' + ip, 3, 3600000)) {
        return res.status(429).json({ success: false, message: 'Too many takedown requests. Please try again later.' });
    }

    const cert = stmts.getCertById.get(certificateId.toUpperCase());
    if (!cert) {
        return res.status(404).json({ success: false, message: 'Certificate not found.' });
    }

    const reportId = uuidv4();
    const reason = `COPYRIGHT TAKEDOWN\nClaimant: ${claimantName} (${claimantEmail})\nCopyrighted Work: ${copyrightedWork}\nSworn Statement: ${swornStatement}`;

    db.prepare('INSERT INTO reports (id, certificate_id, reason, reporter_email, status, type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(reportId, certificateId.toUpperCase(), reason, claimantEmail, 'pending', 'copyright_takedown', new Date().toISOString());

    stmts.insertHistory.run(certificateId.toUpperCase(), 'copyright_takedown', null, new Date().toISOString());

    audit('copyright_takedown_filed', { reportId, certificateId: certificateId.toUpperCase(), claimantEmail });

    // Notify admin via email if configured
    if (emailEnabled && process.env.ADMIN_EMAIL) {
        sendEmail({
            from: process.env.SMTP_FROM || process.env.SMTP_USER,
            to: process.env.ADMIN_EMAIL,
            subject: `Copyright Takedown Request: ${certificateId}`,
            text: `A copyright takedown request has been filed.\n\nClaimant: ${claimantName}\nEmail: ${claimantEmail}\nCertificate: ${certificateId}\nCopyrighted Work: ${copyrightedWork}\nSworn Statement: ${swornStatement}`
        }).catch(err => console.error('Failed to send takedown notification:', err.message));
    }

    res.json({ success: true, message: 'Takedown request submitted. We will review it promptly.' });
});

// Contact form
// Share certificate by email
app.post('/api/certificate/share', doubleCsrfProtection, (req, res) => {
    const { recipientEmail, certificateId, senderName } = req.body;

    if (!recipientEmail || !certificateId) {
        return res.status(400).json({ success: false, message: 'Recipient email and certificate ID are required.' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(recipientEmail)) {
        return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
    }

    const ip = req.ip || req.connection.remoteAddress;
    if (!rateLimit('share:' + ip, 10, 3600000)) {
        return res.status(429).json({ success: false, message: 'Too many shares. Please try again later.' });
    }

    const cert = stmts.getCertById.get(certificateId);
    if (!cert) {
        return res.status(404).json({ success: false, message: 'Certificate not found.' });
    }

    const artist = rowToArtist(stmts.getArtistById.get(cert.artist_id));
    const host = `${req.protocol}://${req.get('host')}`;
    const verifyUrl = `${host}/verify.html?code=${encodeURIComponent(certificateId)}`;
    const fromName = senderName ? senderName.trim() : 'Someone';

    if (emailEnabled) {
        sendEmail({
            from: process.env.SMTP_FROM || process.env.SMTP_USER,
            to: recipientEmail.trim(),
            subject: `${fromName} shared a certificate: ${cert.title}`,
            html: `
            <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#f5f0e8;">
                <div style="background:#2a2520;color:#fafafa;padding:2rem;text-align:center;">
                    <div style="font-family:Inter,-apple-system,sans-serif;font-size:1.2rem;font-weight:600;"><span style="font-weight:300;color:#999;">officially</span><span style="font-weight:600;">human</span><span style="font-weight:700;font-size:1.5rem;">.art</span></div>
                </div>
                <div style="padding:2rem;">
                    <p style="color:#666666;margin-bottom:1.5rem;">${fromName} wanted to share this certified human-made artwork with you:</p>
                    <div style="background:white;border:1px solid #e2ddd5;border-radius:8px;padding:1.5rem;margin-bottom:1.5rem;">
                        <h2 style="margin:0 0 0.5rem;color:#2a2520;font-size:1.1rem;">${cert.title}</h2>
                        <p style="margin:0 0 0.25rem;color:#666;font-size:0.9rem;">by ${artist ? artist.name : 'Unknown Artist'}</p>
                        <p style="margin:0;color:#888;font-size:0.82rem;">Certificate: ${certificateId}</p>
                    </div>
                    <div style="text-align:center;margin-bottom:1.5rem;">
                        <a href="${verifyUrl}" style="display:inline-block;padding:0.75rem 2rem;background:#2a2520;color:#fafafa;text-decoration:none;border-radius:6px;font-weight:600;font-size:0.9rem;">View Certificate</a>
                    </div>
                    <p style="color:#888888;font-size:0.82rem;">This certificate verifies that the artwork was registered as authentically human-made on Officially Human Art.</p>
                </div>
                <div style="background:#ebe5da;padding:1.25rem;text-align:center;font-size:0.75rem;color:#a0aec0;border-top:1px solid rgba(26,26,26,0.06);">
                    <p style="margin:0;">&copy; 2026 Officially Human Art</p>
                </div>
            </div>`
        }).catch(err => console.error('Failed to send share email:', err.message));
    }

    audit('certificate_shared', { certificateId, recipientEmail: recipientEmail.trim() });
    res.json({ success: true, message: 'Certificate shared successfully.' });
});

app.post('/api/contact', doubleCsrfProtection, (req, res) => {
    const { name, email, message } = req.body;

    if (!name || !email || !message) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    if (message.trim().length < 10) {
        return res.status(400).json({ success: false, message: 'Please include a bit more detail in your message.' });
    }

    const ip = req.ip || req.connection.remoteAddress;
    if (!rateLimit('contact:' + ip, 3, 3600000)) {
        return res.status(429).json({ success: false, message: 'Too many messages. Please try again later.' });
    }

    const adminEmail = process.env.ADMIN_EMAIL || 'matt@mattlewsey.com';

    if (emailEnabled) {
        sendEmail({
            from: process.env.SMTP_FROM || process.env.SMTP_USER,
            to: adminEmail,
            subject: `Contact form: ${name.trim()}`,
            text: `New message from the contact form.\n\nName: ${name.trim()}\nEmail: ${email.trim()}\n\nMessage:\n${message.trim()}`,
            replyTo: email.trim()
        }).catch(err => console.error('Failed to send contact email:', err.message));
    }

    audit('contact_form_submitted', { name: name.trim(), email: email.trim() });

    res.json({ success: true, message: 'Message sent. We\'ll get back to you soon.' });
});

// Global error handler — return JSON for API errors (including CSRF failures)
app.use((err, req, res, next) => {
    if (req.path.startsWith('/api/')) {
        const status = err.status || err.statusCode || 500;
        console.error(`[API Error] ${req.method} ${req.path}: ${err.message}`);
        return res.status(status).json({ success: false, message: err.message || 'Internal server error' });
    }
    next(err);
});

// Export for testing — only listen when run directly
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Officially Human Art server running at http://localhost:${PORT}`);
    });
}

module.exports = { app, db };
