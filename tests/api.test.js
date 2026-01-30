const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');

// Override env vars before requiring server
process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-secret-key-for-testing';
process.env.ADMIN_KEY = 'test-admin-key';

let server;
let baseUrl;
let cookies = '';
let csrfToken = '';

// Test email — use unique email to avoid collisions with existing data
const TEST_EMAIL = `test-${Date.now()}@example.com`;
const TEST_PASSWORD = 'SecurePass123!';

function request(method, urlPath, { body, headers = {}, rawBody } = {}) {
    return new Promise((resolve, reject) => {
        const url = new URL(urlPath, baseUrl);
        const opts = {
            method,
            hostname: url.hostname,
            port: url.port,
            path: url.pathname + url.search,
            headers: {
                ...headers,
                ...(cookies ? { Cookie: cookies } : {})
            }
        };

        let payload = null;
        if (rawBody) {
            payload = rawBody;
        } else if (body && typeof body === 'object') {
            payload = JSON.stringify(body);
            opts.headers['Content-Type'] = 'application/json';
            opts.headers['Content-Length'] = Buffer.byteLength(payload);
        }

        if (method !== 'GET' && csrfToken && !opts.headers['X-CSRF-Token']) {
            opts.headers['X-CSRF-Token'] = csrfToken;
        }

        const req = http.request(opts, (res) => {
            if (res.headers['set-cookie']) {
                const newCookies = res.headers['set-cookie'].map(c => c.split(';')[0]);
                const existing = cookies ? cookies.split('; ').filter(Boolean) : [];
                for (const nc of newCookies) {
                    const name = nc.split('=')[0];
                    const idx = existing.findIndex(e => e.startsWith(name + '='));
                    if (idx >= 0) existing[idx] = nc;
                    else existing.push(nc);
                }
                cookies = existing.join('; ');
            }

            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                let json = null;
                try { json = JSON.parse(data); } catch (e) {}
                resolve({ status: res.statusCode, headers: res.headers, data, json });
            });
        });

        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
    });
}

async function refreshCsrf() {
    const res = await request('GET', '/api/csrf-token');
    csrfToken = res.json.token;
}

function multipartRequest(urlPath, fields, files) {
    return new Promise((resolve, reject) => {
        const boundary = '----TestBoundary' + Date.now();
        let bodyParts = [];

        for (const [key, value] of Object.entries(fields)) {
            bodyParts.push(Buffer.from(
                `--${boundary}\r\nContent-Disposition: form-data; name="${key}"\r\n\r\n${value}\r\n`
            ));
        }

        for (const { fieldName, filename, content, contentType } of files) {
            bodyParts.push(Buffer.from(
                `--${boundary}\r\nContent-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\nContent-Type: ${contentType}\r\n\r\n`
            ));
            bodyParts.push(Buffer.isBuffer(content) ? content : Buffer.from(content));
            bodyParts.push(Buffer.from('\r\n'));
        }

        bodyParts.push(Buffer.from(`--${boundary}--\r\n`));
        const body = Buffer.concat(bodyParts);

        const url = new URL(urlPath, baseUrl);
        const hdrs = {
            'Content-Type': `multipart/form-data; boundary=${boundary}`,
            'Content-Length': body.length,
            ...(cookies ? { Cookie: cookies } : {}),
            ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {})
        };

        const req = http.request({
            method: 'POST', hostname: url.hostname, port: url.port,
            path: url.pathname, headers: hdrs
        }, (res) => {
            if (res.headers['set-cookie']) {
                const newCookies = res.headers['set-cookie'].map(c => c.split(';')[0]);
                const existing = cookies ? cookies.split('; ').filter(Boolean) : [];
                for (const nc of newCookies) {
                    const name = nc.split('=')[0];
                    const idx = existing.findIndex(e => e.startsWith(name + '='));
                    if (idx >= 0) existing[idx] = nc;
                    else existing.push(nc);
                }
                cookies = existing.join('; ');
            }

            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                let json = null;
                try { json = JSON.parse(data); } catch (e) {}
                resolve({ status: res.statusCode, headers: res.headers, data, json });
            });
        });

        req.on('error', reject);
        req.write(body);
        req.end();
    });
}

describe('Officially Human Art API', () => {
    let registeredArtist = null;
    let testCertId = null;

    before(async () => {
        const { app, db } = require('../server');

        // Clear rate limits from previous test runs
        db.prepare('DELETE FROM rate_limits').run();

        await new Promise((resolve) => {
            server = app.listen(0, () => {
                const addr = server.address();
                baseUrl = `http://127.0.0.1:${addr.port}`;
                resolve();
            });
        });
        await refreshCsrf();
    });

    after(async () => {
        if (server) {
            await new Promise((resolve) => server.close(resolve));
        }
        // Force exit to prevent dangling timers from keeping process open
        setTimeout(() => process.exit(0), 200);
    });

    // ---- Health ----
    describe('Health endpoint', () => {
        it('returns health status', async () => {
            const res = await request('GET', '/api/health');
            assert.equal(res.status, 200);
            assert.equal(res.json.status, 'ok');
            assert.equal(res.json.database, 'connected');
            assert.equal(typeof res.json.uptime, 'number');
            assert.equal(typeof res.json.diskUsage, 'number');
            assert.equal(typeof res.json.artistCount, 'number');
            assert.equal(typeof res.json.certificateCount, 'number');
        });
    });

    // ---- Registration ----
    describe('Registration', () => {
        it('registers a new artist', async () => {
            const res = await request('POST', '/api/artist/register', {
                body: { name: 'Test Artist', email: TEST_EMAIL, password: TEST_PASSWORD }
            });
            assert.equal(res.status, 200, 'Register status: ' + res.status + ' body: ' + JSON.stringify(res.json));
            assert.ok(res.json.success);
            assert.equal(res.json.artist.name, 'Test Artist');
            assert.equal(res.json.artist.emailVerified, false);
            registeredArtist = res.json.artist;
        });

        it('rejects duplicate email', async () => {
            await refreshCsrf();
            const res = await request('POST', '/api/artist/register', {
                body: { name: 'Dupe', email: TEST_EMAIL, password: 'AnotherPass456!' }
            });
            assert.equal(res.status, 409);
        });

        it('rejects weak password', async () => {
            await refreshCsrf();
            const res = await request('POST', '/api/artist/register', {
                body: { name: 'Weak', email: `weak-${Date.now()}@example.com`, password: 'password' }
            });
            assert.equal(res.status, 400);
        });
    });

    // ---- Session ----
    describe('Session restore', () => {
        it('returns current artist when logged in', async () => {
            const res = await request('GET', '/api/artist/me');
            assert.equal(res.status, 200);
            assert.ok(res.json.success);
            assert.equal(res.json.artist.email, TEST_EMAIL);
        });
    });

    // ---- Logout + Login ----
    describe('Logout and Login', () => {
        it('signs out', async () => {
            const res = await request('POST', '/api/artist/logout');
            assert.equal(res.status, 200);
            assert.ok(res.json.success);

            const me = await request('GET', '/api/artist/me');
            assert.ok(!me.json.success);
        });

        it('needs fresh CSRF after logout', async () => {
            await refreshCsrf();
        });

        it('rejects wrong email', async () => {
            await refreshCsrf();
            const res = await request('POST', '/api/artist/login', {
                body: { email: 'wrong@example.com', password: TEST_PASSWORD }
            });
            assert.ok(!res.json.success);
        });

        it('rejects wrong password', async () => {
            await refreshCsrf();
            const res = await request('POST', '/api/artist/login', {
                body: { email: TEST_EMAIL, password: 'WrongPassword!' }
            });
            assert.ok(!res.json.success);
        });

        it('succeeds with correct credentials', async () => {
            await refreshCsrf();
            const res = await request('POST', '/api/artist/login', {
                body: { email: TEST_EMAIL, password: TEST_PASSWORD }
            });
            assert.equal(res.status, 200, 'Login body: ' + JSON.stringify(res.json));
            assert.ok(res.json.success, 'Login should succeed: ' + JSON.stringify(res.json));
            registeredArtist = res.json.artist;
            // Refresh CSRF after new session
            await refreshCsrf();
        });
    });

    // ---- CSRF Protection ----
    describe('CSRF protection', () => {
        it('rejects POST without CSRF token', async () => {
            const saved = csrfToken;
            csrfToken = '';
            // Use a CSRF-protected endpoint (login is protected by doubleCsrfProtection)
            const res = await request('POST', '/api/artist/login', {
                body: { email: TEST_EMAIL, password: TEST_PASSWORD }
            });
            assert.ok(res.status >= 400, 'Should reject without CSRF, got: ' + res.status);
            csrfToken = saved;
        });
    });

    // ---- Artwork Submission ----
    describe('Artwork submission', () => {
        it('blocks unverified email', async () => {
            const pngBuf = Buffer.from(
                'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==',
                'base64'
            );
            const res = await multipartRequest('/api/artwork/submit', {
                title: 'Test', medium: 'Painting',
                description: 'A description that is definitely more than fifty characters long for testing purposes here',
                processNotes: 'Hand painted', declaration: 'true', evidenceVisibility: '[]'
            }, [{ fieldName: 'artworkImage', filename: 'test.png', content: pngBuf, contentType: 'image/png' }]);
            assert.equal(res.status, 403, 'Should block unverified: ' + JSON.stringify(res.json));
        });

        it('allows after email verification', async () => {
            const { db } = require('../server');
            db.prepare('UPDATE artists SET email_verified = 1 WHERE email = ?').run(TEST_EMAIL);

            const pngBuf = Buffer.from(
                'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==',
                'base64'
            );
            const res = await multipartRequest('/api/artwork/submit', {
                title: 'Test Artwork', medium: 'Painting',
                description: 'A detailed description of the test artwork that is definitely more than fifty characters long for evidence',
                processNotes: 'Hand painted using oils on canvas', declaration: 'true', evidenceVisibility: '[]'
            }, [{ fieldName: 'artworkImage', filename: 'test.png', content: pngBuf, contentType: 'image/png' }]);
            assert.equal(res.status, 200, 'Submit should work: ' + JSON.stringify(res.json));
            assert.ok(res.json.success);
            assert.ok(res.json.certificate.id);
            testCertId = res.json.certificate.id;
        });
    });

    // ---- Certificate Verification ----
    describe('Certificate verification', () => {
        it('verifies an existing certificate', async () => {
            assert.ok(testCertId, 'Need a test cert ID');
            const res = await request('GET', `/api/verify/${testCertId}`);
            assert.equal(res.status, 200);
            assert.ok(res.json.verified);
            assert.equal(res.json.certificate.id, testCertId);
        });

        it('returns not found for invalid certificate', async () => {
            const res = await request('GET', '/api/verify/INVALID-ID');
            assert.equal(res.status, 200);
            assert.ok(!res.json.verified);
        });
    });

    // ---- Data Export ----
    describe('Data export', () => {
        it('exports artist data', async () => {
            assert.ok(registeredArtist, 'Need registered artist');
            const res = await request('GET', `/api/artist/${registeredArtist.id}/export`);
            assert.equal(res.status, 200);
            assert.ok(res.json.artist);
            assert.equal(res.json.artist.email, TEST_EMAIL);
            assert.ok(Array.isArray(res.json.certificates));
            assert.ok(res.json.exportDate);
            assert.ok(res.headers['content-disposition']);
        });

        it('rejects export for other users', async () => {
            const res = await request('GET', '/api/artist/other-user-id/export');
            // Returns 403 (authorized but not owner)
            assert.equal(res.status, 403);
        });
    });

    // ---- Admin ----
    describe('Admin API', () => {
        it('rejects without admin key', async () => {
            const res = await request('GET', '/api/admin/stats');
            assert.equal(res.status, 403);
        });

        it('returns stats with admin key', async () => {
            const res = await request('GET', '/api/admin/stats', {
                headers: { 'X-Admin-Key': 'test-admin-key' }
            });
            assert.equal(res.status, 200);
            assert.ok(res.json.success);
            assert.equal(typeof res.json.artists, 'number');
            assert.ok(res.json.artists >= 1);
        });

        it('returns reports', async () => {
            const res = await request('GET', '/api/admin/reports', {
                headers: { 'X-Admin-Key': 'test-admin-key' }
            });
            assert.equal(res.status, 200);
            assert.ok(Array.isArray(res.json.reports));
        });

        it('triggers manual backup', async () => {
            const res = await request('GET', '/api/admin/backup?adminKey=test-admin-key');
            assert.equal(res.status, 200);
            assert.ok(res.json.success);
        });
    });

    // ---- Takedown ----
    describe('Takedown', () => {
        it('submits a takedown request', async () => {
            assert.ok(testCertId, 'Need a cert ID');
            const res = await request('POST', '/api/takedown', {
                body: {
                    claimantName: 'Copyright Owner',
                    claimantEmail: 'owner@example.com',
                    copyrightedWork: 'My original painting',
                    certificateId: testCertId,
                    swornStatement: 'true'
                }
            });
            assert.equal(res.status, 200, 'Takedown: ' + JSON.stringify(res.json));
            assert.ok(res.json.success);
        });

        it('rejects incomplete request', async () => {
            const res = await request('POST', '/api/takedown', {
                body: { claimantName: 'Test', claimantEmail: 'a@b.com' }
            });
            assert.equal(res.status, 400);
        });
    });

    // ---- Public endpoints ----
    describe('Public endpoints', () => {
        it('GET /api/browse', async () => {
            const res = await request('GET', '/api/browse');
            assert.equal(res.status, 200);
            assert.ok(Array.isArray(res.json.certificates));
        });

        it('GET /api/stats', async () => {
            const res = await request('GET', '/api/stats');
            assert.equal(res.status, 200);
            assert.equal(typeof res.json.artists, 'number');
        });
    });
});
