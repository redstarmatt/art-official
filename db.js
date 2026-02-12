// Database abstraction layer — Supabase (Postgres)
// Replaces all direct better-sqlite3 prepared statements with async Supabase queries.

const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// Helper: unwrap Supabase response, throw on error
function unwrap(result) {
    if (result.error) throw new Error(result.error.message);
    return result.data;
}

// Helper: get single row or null
function single(result) {
    if (result.error) {
        if (result.error.code === 'PGRST116') return null; // no rows
        throw new Error(result.error.message);
    }
    return result.data;
}

// ============================================================
// Artists
// ============================================================

async function getArtistById(id) {
    const result = await supabase.from('artists').select('*').eq('id', id).maybeSingle();
    return single(result);
}

async function getArtistByEmail(email) {
    const result = await supabase.from('artists').select('*').eq('email', email).maybeSingle();
    return single(result);
}

async function getArtistBySlug(slug) {
    const result = await supabase.from('artists').select('*').eq('slug', slug).maybeSingle();
    return single(result);
}

async function getArtistByStripeCustomer(stripeCustomerId) {
    const result = await supabase.from('artists').select('*').eq('stripe_customer_id', stripeCustomerId).maybeSingle();
    return single(result);
}

async function getArtistByResetToken(token, now) {
    const result = await supabase.from('artists').select('*')
        .eq('reset_token', token).gt('reset_token_expires', now).maybeSingle();
    return single(result);
}

async function getArtistByVerificationToken(token) {
    const result = await supabase.from('artists').select('*').eq('verification_token', token).maybeSingle();
    return single(result);
}

async function insertArtist(artist) {
    const result = await supabase.from('artists').insert(artist);
    unwrap(result);
}

async function updateArtistProfile(name, bio, location, portfolio, slug, id) {
    const result = await supabase.from('artists')
        .update({ name, bio, location, portfolio, slug }).eq('id', id);
    unwrap(result);
}

async function updateArtistPlan(plan, planStatus, planExpiresAt, id) {
    const result = await supabase.from('artists')
        .update({ plan, plan_status: planStatus, plan_expires_at: planExpiresAt }).eq('id', id);
    unwrap(result);
}

async function updateArtistStripeCustomer(stripeCustomerId, id) {
    const result = await supabase.from('artists')
        .update({ stripe_customer_id: stripeCustomerId }).eq('id', id);
    unwrap(result);
}

async function updateArtistStripeSubscription(subscriptionId, id) {
    const result = await supabase.from('artists')
        .update({ stripe_subscription_id: subscriptionId }).eq('id', id);
    unwrap(result);
}

async function updateArtistResetToken(token, expires, id) {
    const result = await supabase.from('artists')
        .update({ reset_token: token, reset_token_expires: expires }).eq('id', id);
    unwrap(result);
}

async function updateArtistPassword(passwordHash, id) {
    const result = await supabase.from('artists')
        .update({ password_hash: passwordHash, reset_token: null, reset_token_expires: null }).eq('id', id);
    unwrap(result);
}

async function updateArtistVerification(emailVerified, verificationToken, id) {
    const result = await supabase.from('artists')
        .update({ email_verified: emailVerified, verification_token: verificationToken }).eq('id', id);
    unwrap(result);
}

async function updateLastLogin(lastLoginAt, id) {
    const result = await supabase.from('artists')
        .update({ last_login_at: lastLoginAt }).eq('id', id);
    unwrap(result);
}

async function deleteArtist(id) {
    const result = await supabase.from('artists').delete().eq('id', id);
    unwrap(result);
}

async function getInactiveAccounts(cutoff) {
    // Artists with last_login_at before cutoff and no certificates
    const result = await supabase.rpc('get_inactive_accounts', { cutoff_date: cutoff });
    // Fallback: if the RPC doesn't exist, use a query
    if (result.error) {
        // Use a workaround: get all artists, then filter
        const artists = await supabase.from('artists').select('*').lt('last_login_at', cutoff);
        if (artists.error) throw new Error(artists.error.message);
        // Filter out those with certificates
        const filtered = [];
        for (const a of artists.data) {
            const certCount = await supabase.from('certificates').select('id', { count: 'exact', head: true }).eq('artist_id', a.id);
            if (!certCount.error && certCount.count === 0) filtered.push(a);
        }
        return filtered;
    }
    return result.data;
}

async function getAllArtists() {
    // Artists with cert count — use a left join via Supabase
    const result = await supabase.from('artists')
        .select('*, certificates(id)')
        .order('created_at', { ascending: false });
    if (result.error) throw new Error(result.error.message);
    return result.data.map(a => ({
        ...a,
        cert_count: a.certificates ? a.certificates.length : 0,
        certificates: undefined
    }));
}

async function countArtists() {
    const result = await supabase.from('artists').select('*', { count: 'exact', head: true });
    if (result.error) throw new Error(result.error.message);
    return { n: result.count };
}

// ============================================================
// Certificates
// ============================================================

async function getCertById(id) {
    const result = await supabase.from('certificates').select('*').eq('id', id).maybeSingle();
    return single(result);
}

async function getCertsByArtist(artistId) {
    const result = await supabase.from('certificates').select('*')
        .eq('artist_id', artistId).order('registered_at', { ascending: false });
    return unwrap(result);
}

async function countCertsByArtist(artistId) {
    const result = await supabase.from('certificates').select('*', { count: 'exact', head: true })
        .eq('artist_id', artistId);
    if (result.error) throw new Error(result.error.message);
    return { n: result.count };
}

async function insertCert(cert) {
    const result = await supabase.from('certificates').insert(cert);
    unwrap(result);
}

async function updateCert(title, description, processNotes, tier, tierLabel, evidenceStrength, artistName, id) {
    const result = await supabase.from('certificates')
        .update({
            title, description, process_notes: processNotes,
            tier, tier_label: tierLabel, evidence_strength: evidenceStrength,
            artist_name: artistName
        }).eq('id', id);
    unwrap(result);
}

async function updateCertReportCount(id) {
    // Increment report_count by 1
    const cert = await getCertById(id);
    if (!cert) return;
    const result = await supabase.from('certificates')
        .update({ report_count: (cert.report_count || 0) + 1 }).eq('id', id);
    unwrap(result);
}

async function updateCertStatus(status, id) {
    const result = await supabase.from('certificates').update({ status }).eq('id', id);
    unwrap(result);
}

async function deleteCert(id) {
    const result = await supabase.from('certificates').delete().eq('id', id);
    unwrap(result);
}

async function deleteCertsByArtist(artistId) {
    const result = await supabase.from('certificates').delete().eq('artist_id', artistId);
    unwrap(result);
}

async function countCerts() {
    const result = await supabase.from('certificates').select('*', { count: 'exact', head: true });
    if (result.error) throw new Error(result.error.message);
    return { n: result.count };
}

async function countTiers() {
    // Group by tier — Supabase doesn't do GROUP BY easily, so query all and aggregate
    const result = await supabase.from('certificates').select('tier');
    if (result.error) throw new Error(result.error.message);
    const counts = {};
    for (const row of result.data) {
        counts[row.tier] = (counts[row.tier] || 0) + 1;
    }
    return Object.entries(counts).map(([tier, n]) => ({ tier, n }));
}

async function findCertByArtworkImage(filename) {
    const result = await supabase.from('certificates').select('*').eq('artwork_image', filename).maybeSingle();
    return single(result);
}

// Browse queries
async function browseCerts(status) {
    const result = await supabase.from('certificates').select('*')
        .eq('status', status).order('registered_at', { ascending: false });
    return unwrap(result);
}

async function browseCertsFilterMedium(status, medium) {
    const result = await supabase.from('certificates').select('*')
        .eq('status', status).eq('medium', medium).order('registered_at', { ascending: false });
    return unwrap(result);
}

async function browseCertsFilterTier(status, tier) {
    const result = await supabase.from('certificates').select('*')
        .eq('status', status).eq('tier', tier).order('registered_at', { ascending: false });
    return unwrap(result);
}

async function browseCertsFilterBoth(status, medium, tier) {
    const result = await supabase.from('certificates').select('*')
        .eq('status', status).eq('medium', medium).eq('tier', tier)
        .order('registered_at', { ascending: false });
    return unwrap(result);
}

async function allMediums() {
    const result = await supabase.from('certificates').select('medium')
        .not('medium', 'is', null).neq('medium', '');
    if (result.error) throw new Error(result.error.message);
    const unique = [...new Set(result.data.map(r => r.medium))].sort();
    return unique.map(m => ({ medium: m }));
}

async function getAllCerts() {
    const result = await supabase.from('certificates').select('*')
        .order('registered_at', { ascending: false });
    return unwrap(result);
}

// ============================================================
// Evidence Files
// ============================================================

async function getEvidenceFiles(certificateId) {
    const result = await supabase.from('evidence_files').select('*').eq('certificate_id', certificateId);
    return unwrap(result);
}

async function insertEvidence(certificateId, filename, isPublic) {
    const result = await supabase.from('evidence_files')
        .insert({ certificate_id: certificateId, filename, is_public: isPublic });
    unwrap(result);
}

async function findEvidenceFile(filename) {
    const result = await supabase.from('evidence_files').select('*, certificates!inner(artist_id)')
        .eq('filename', filename).maybeSingle();
    if (result.error) {
        if (result.error.code === 'PGRST116') return null;
        throw new Error(result.error.message);
    }
    if (!result.data) return null;
    // Flatten the join
    return {
        ...result.data,
        artist_id: result.data.certificates?.artist_id,
        certificates: undefined
    };
}

async function deleteEvidenceByArtist(artistId) {
    // Delete evidence files for all certs by this artist
    const certs = await supabase.from('certificates').select('id').eq('artist_id', artistId);
    if (certs.error) throw new Error(certs.error.message);
    const certIds = certs.data.map(c => c.id);
    if (certIds.length === 0) return;
    const result = await supabase.from('evidence_files').delete().in('certificate_id', certIds);
    unwrap(result);
}

// ============================================================
// Certificate History
// ============================================================

async function getHistory(certificateId) {
    const result = await supabase.from('certificate_history').select('*')
        .eq('certificate_id', certificateId).order('created_at', { ascending: true });
    return unwrap(result);
}

async function insertHistory(certificateId, type, fields, createdAt) {
    const result = await supabase.from('certificate_history')
        .insert({ certificate_id: certificateId, type, fields, created_at: createdAt });
    unwrap(result);
}

async function deleteHistoryByArtist(artistId) {
    const certs = await supabase.from('certificates').select('id').eq('artist_id', artistId);
    if (certs.error) throw new Error(certs.error.message);
    const certIds = certs.data.map(c => c.id);
    if (certIds.length === 0) return;
    const result = await supabase.from('certificate_history').delete().in('certificate_id', certIds);
    unwrap(result);
}

// ============================================================
// Reports
// ============================================================

async function insertReport(id, certificateId, reason, reporterEmail, status, createdAt) {
    const result = await supabase.from('reports')
        .insert({ id, certificate_id: certificateId, reason, reporter_email: reporterEmail, status, created_at: createdAt });
    unwrap(result);
}

async function getReportById(id) {
    const result = await supabase.from('reports').select('*').eq('id', id).maybeSingle();
    return single(result);
}

async function getAllReports() {
    const result = await supabase.from('reports')
        .select('*, certificates!inner(title, artist_id, artist_name)')
        .order('created_at', { ascending: false });
    if (result.error) throw new Error(result.error.message);
    return result.data.map(r => ({
        ...r,
        cert_title: r.certificates?.title,
        artist_id: r.certificates?.artist_id,
        artist_name: r.certificates?.artist_name,
        certificates: undefined
    }));
}

async function updateReportResolution(resolution, resolvedAt, status, id) {
    const result = await supabase.from('reports')
        .update({ resolution, resolved_at: resolvedAt, status }).eq('id', id);
    unwrap(result);
}

async function deleteReportsByArtist(artistId) {
    const certs = await supabase.from('certificates').select('id').eq('artist_id', artistId);
    if (certs.error) throw new Error(certs.error.message);
    const certIds = certs.data.map(c => c.id);
    if (certIds.length === 0) return;
    const result = await supabase.from('reports').delete().in('certificate_id', certIds);
    unwrap(result);
}

// ============================================================
// Rate Limits
// ============================================================

async function rateLimitCheck(key, maxAttempts, windowMs) {
    const cutoff = Date.now() - windowMs;
    // Clean old entries
    await supabase.from('rate_limits').delete().eq('key', key).lt('timestamp', cutoff);
    // Count recent
    const countResult = await supabase.from('rate_limits')
        .select('*', { count: 'exact', head: true })
        .eq('key', key).gte('timestamp', cutoff);
    if (countResult.error) throw new Error(countResult.error.message);
    if (countResult.count >= maxAttempts) return false;
    // Insert new entry
    await supabase.from('rate_limits').insert({ key, timestamp: Date.now() });
    return true;
}

async function cleanupRateLimits() {
    await supabase.from('rate_limits').delete().lt('timestamp', Date.now() - 3600000);
}

// ============================================================
// Newsletter
// ============================================================

async function getNewsletterSubscriber(email) {
    const result = await supabase.from('newsletter_subscribers').select('*')
        .eq('email', email).maybeSingle();
    return single(result);
}

async function insertNewsletterSubscriber(email, source, subscribedAt) {
    const result = await supabase.from('newsletter_subscribers')
        .insert({ email, source, subscribed_at: subscribedAt });
    unwrap(result);
}

async function resubscribeNewsletter(subscribedAt, email) {
    const result = await supabase.from('newsletter_subscribers')
        .update({ unsubscribed_at: null, subscribed_at: subscribedAt }).eq('email', email);
    unwrap(result);
}

async function unsubscribeNewsletter(unsubscribedAt, email) {
    const result = await supabase.from('newsletter_subscribers')
        .update({ unsubscribed_at: unsubscribedAt }).eq('email', email);
    unwrap(result);
}

async function countActiveSubscribers() {
    const result = await supabase.from('newsletter_subscribers')
        .select('*', { count: 'exact', head: true }).is('unsubscribed_at', null);
    if (result.error) throw new Error(result.error.message);
    return result.count;
}

// ============================================================
// Page Views
// ============================================================

async function insertPageView(page, referrer, date) {
    await supabase.from('page_views').insert({ page, referrer, date });
}

async function getPageViewStats(since) {
    const totalResult = await supabase.from('page_views')
        .select('*', { count: 'exact', head: true }).gte('date', since);
    const totalViews = totalResult.error ? 0 : totalResult.count;

    // By page
    const pageResult = await supabase.from('page_views').select('page').gte('date', since);
    const byPageMap = {};
    if (!pageResult.error) {
        for (const r of pageResult.data) {
            byPageMap[r.page] = (byPageMap[r.page] || 0) + 1;
        }
    }
    const byPage = Object.entries(byPageMap)
        .map(([page, views]) => ({ page, views }))
        .sort((a, b) => b.views - a.views).slice(0, 20);

    // By day
    const dayResult = await supabase.from('page_views').select('date').gte('date', since);
    const byDayMap = {};
    if (!dayResult.error) {
        for (const r of dayResult.data) {
            byDayMap[r.date] = (byDayMap[r.date] || 0) + 1;
        }
    }
    const byDay = Object.entries(byDayMap)
        .map(([date, views]) => ({ date, views }))
        .sort((a, b) => a.date.localeCompare(b.date));

    // Top referrers
    const refResult = await supabase.from('page_views').select('referrer')
        .gte('date', since).neq('referrer', '');
    const refMap = {};
    if (!refResult.error) {
        for (const r of refResult.data) {
            refMap[r.referrer] = (refMap[r.referrer] || 0) + 1;
        }
    }
    const topReferrers = Object.entries(refMap)
        .map(([referrer, views]) => ({ referrer, views }))
        .sort((a, b) => b.views - a.views).slice(0, 10);

    return { totalViews, byPage, byDay, topReferrers };
}

// ============================================================
// Sitemap helper
// ============================================================

async function getAllArtistSlugs() {
    const result = await supabase.from('artists').select('slug')
        .not('slug', 'is', null).neq('slug', '');
    return unwrap(result);
}

// ============================================================
// Increment certificate credits
// ============================================================

async function incrementCertificateCredits(artistId) {
    const artist = await getArtistById(artistId);
    if (!artist) return;
    const result = await supabase.from('artists')
        .update({ certificate_credits: (artist.certificate_credits || 0) + 1 }).eq('id', artistId);
    unwrap(result);
}

// ============================================================
// Ban/unban
// ============================================================

async function banArtist(artistId, reason) {
    const result = await supabase.from('artists')
        .update({ banned: true, ban_reason: reason }).eq('id', artistId);
    unwrap(result);
}

async function unbanArtist(artistId) {
    const result = await supabase.from('artists')
        .update({ banned: false, ban_reason: null }).eq('id', artistId);
    unwrap(result);
}

// ============================================================
// Retention cleanup helper
// ============================================================

async function setDeletionWarning(artistId, timestamp) {
    const result = await supabase.from('artists')
        .update({ deletion_warning_sent_at: timestamp }).eq('id', artistId);
    unwrap(result);
}

// ============================================================
// Cascading delete via RPC
// ============================================================

async function deleteArtistCascade(artistId) {
    const result = await supabase.rpc('delete_artist_cascade', { p_artist_id: artistId });
    if (result.error) throw new Error(result.error.message);
}

// ============================================================
// Insert takedown report (with type)
// ============================================================

async function insertReportWithType(id, certificateId, reason, reporterEmail, status, type, createdAt) {
    const result = await supabase.from('reports')
        .insert({ id, certificate_id: certificateId, reason, reporter_email: reporterEmail, status, type, created_at: createdAt });
    unwrap(result);
}

// ============================================================
// Pending reports count
// ============================================================

async function countPendingReports() {
    const result = await supabase.from('reports')
        .select('*', { count: 'exact', head: true }).eq('status', 'pending');
    if (result.error) throw new Error(result.error.message);
    return result.count;
}

async function countTotalReports() {
    const result = await supabase.from('reports')
        .select('*', { count: 'exact', head: true });
    if (result.error) throw new Error(result.error.message);
    return result.count;
}

// ============================================================
// Health check
// ============================================================

async function healthCheck() {
    const result = await supabase.from('artists').select('id', { count: 'exact', head: true });
    return !result.error;
}

// ============================================================
// Exports
// ============================================================

module.exports = {
    supabase,

    // Artists
    getArtistById,
    getArtistByEmail,
    getArtistBySlug,
    getArtistByStripeCustomer,
    getArtistByResetToken,
    getArtistByVerificationToken,
    insertArtist,
    updateArtistProfile,
    updateArtistPlan,
    updateArtistStripeCustomer,
    updateArtistStripeSubscription,
    updateArtistResetToken,
    updateArtistPassword,
    updateArtistVerification,
    updateLastLogin,
    deleteArtist,
    getInactiveAccounts,
    getAllArtists,
    countArtists,
    incrementCertificateCredits,
    banArtist,
    unbanArtist,
    setDeletionWarning,
    deleteArtistCascade,

    // Certificates
    getCertById,
    getCertsByArtist,
    countCertsByArtist,
    insertCert,
    updateCert,
    updateCertReportCount,
    updateCertStatus,
    deleteCert,
    deleteCertsByArtist,
    countCerts,
    countTiers,
    findCertByArtworkImage,
    browseCerts,
    browseCertsFilterMedium,
    browseCertsFilterTier,
    browseCertsFilterBoth,
    allMediums,
    getAllCerts,

    // Evidence
    getEvidenceFiles,
    insertEvidence,
    findEvidenceFile,
    deleteEvidenceByArtist,

    // History
    getHistory,
    insertHistory,
    deleteHistoryByArtist,

    // Reports
    insertReport,
    getReportById,
    getAllReports,
    updateReportResolution,
    deleteReportsByArtist,
    insertReportWithType,
    countPendingReports,
    countTotalReports,

    // Rate limits
    rateLimitCheck,
    cleanupRateLimits,

    // Newsletter
    getNewsletterSubscriber,
    insertNewsletterSubscriber,
    resubscribeNewsletter,
    unsubscribeNewsletter,
    countActiveSubscribers,

    // Page views
    insertPageView,
    getPageViewStats,

    // Sitemap
    getAllArtistSlugs,

    // Health
    healthCheck,
};
