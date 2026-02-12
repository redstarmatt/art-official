-- Supabase Migration: SQLite → Postgres
-- Run this in the Supabase SQL editor to create the schema

-- ============================================================
-- Artists
-- ============================================================
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
  email_verified BOOLEAN DEFAULT FALSE,
  verification_token TEXT,
  last_login_at TEXT,
  deletion_warning_sent_at TEXT,
  banned BOOLEAN DEFAULT FALSE,
  ban_reason TEXT,
  created_at TEXT NOT NULL
);

-- ============================================================
-- Certificates
-- ============================================================
CREATE TABLE IF NOT EXISTS certificates (
  id TEXT PRIMARY KEY,
  artist_id TEXT NOT NULL REFERENCES artists(id) ON DELETE CASCADE,
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
  registered_at TEXT NOT NULL
);

-- ============================================================
-- Evidence Files
-- ============================================================
CREATE TABLE IF NOT EXISTS evidence_files (
  id SERIAL PRIMARY KEY,
  certificate_id TEXT NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  is_public BOOLEAN DEFAULT FALSE
);

-- ============================================================
-- Certificate History
-- ============================================================
CREATE TABLE IF NOT EXISTS certificate_history (
  id SERIAL PRIMARY KEY,
  certificate_id TEXT NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  fields TEXT,
  created_at TEXT NOT NULL
);

-- ============================================================
-- Reports
-- ============================================================
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  certificate_id TEXT NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  reporter_email TEXT,
  status TEXT DEFAULT 'pending',
  type TEXT DEFAULT 'dispute',
  resolution TEXT,
  resolved_at TEXT,
  created_at TEXT NOT NULL
);

-- ============================================================
-- Rate Limits
-- ============================================================
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT NOT NULL,
  timestamp BIGINT NOT NULL
);

-- ============================================================
-- Sessions (for connect-pg-simple)
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
  sid VARCHAR NOT NULL PRIMARY KEY,
  sess JSON NOT NULL,
  expire TIMESTAMP(6) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions (expire);

-- ============================================================
-- Newsletter Subscribers
-- ============================================================
CREATE TABLE IF NOT EXISTS newsletter_subscribers (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  source TEXT DEFAULT 'website',
  subscribed_at TEXT NOT NULL,
  unsubscribed_at TEXT
);

-- ============================================================
-- Page Views
-- ============================================================
CREATE TABLE IF NOT EXISTS page_views (
  id SERIAL PRIMARY KEY,
  page TEXT NOT NULL,
  referrer TEXT DEFAULT '',
  date TEXT NOT NULL
);

-- ============================================================
-- Indexes
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_artists_email ON artists(email);
CREATE INDEX IF NOT EXISTS idx_artists_slug ON artists(slug);
CREATE INDEX IF NOT EXISTS idx_certificates_artist ON certificates(artist_id);
CREATE INDEX IF NOT EXISTS idx_evidence_cert ON evidence_files(certificate_id);
CREATE INDEX IF NOT EXISTS idx_history_cert ON certificate_history(certificate_id);
CREATE INDEX IF NOT EXISTS idx_reports_cert ON reports(certificate_id);
CREATE INDEX IF NOT EXISTS idx_rate_key_time ON rate_limits(key, timestamp);
CREATE INDEX IF NOT EXISTS idx_newsletter_email ON newsletter_subscribers(email);
CREATE INDEX IF NOT EXISTS idx_page_views_date ON page_views(date);
CREATE INDEX IF NOT EXISTS idx_page_views_page ON page_views(page);

-- ============================================================
-- RPC: Cascading artist deletion (replaces SQLite transaction)
-- ============================================================
CREATE OR REPLACE FUNCTION delete_artist_cascade(p_artist_id TEXT)
RETURNS VOID AS $$
BEGIN
  DELETE FROM reports WHERE certificate_id IN (SELECT id FROM certificates WHERE artist_id = p_artist_id);
  DELETE FROM certificate_history WHERE certificate_id IN (SELECT id FROM certificates WHERE artist_id = p_artist_id);
  DELETE FROM evidence_files WHERE certificate_id IN (SELECT id FROM certificates WHERE artist_id = p_artist_id);
  DELETE FROM certificates WHERE artist_id = p_artist_id;
  DELETE FROM artists WHERE id = p_artist_id;
END;
$$ LANGUAGE plpgsql;
