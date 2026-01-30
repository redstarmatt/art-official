# Officially Human Art — General Risk Assessment

**Date:** 30 January 2026
**Service:** Officially Human Art — AI-free art certification platform
**Status:** Pre-production prototype

---

## 1. Overview

This risk assessment covers legal, operational, security, reputational, financial, and intellectual property risks for the Officially Human Art platform. Each risk is scored using a Likelihood x Impact matrix.

### Scoring Key

**Likelihood:**
| Score | Label | Description |
|---|---|---|
| 1 | Rare | Unlikely to occur in normal operation |
| 2 | Unlikely | Could occur but not expected |
| 3 | Possible | Reasonable chance of occurring |
| 4 | Likely | Expected to occur at some point |
| 5 | Almost certain | Will occur without mitigation |

**Impact:**
| Score | Label | Description |
|---|---|---|
| 1 | Negligible | Minimal effect on operations or users |
| 2 | Minor | Limited disruption; easily recoverable |
| 3 | Moderate | Notable disruption; requires effort to resolve |
| 4 | Major | Serious harm to users, reputation, or operations |
| 5 | Severe | Existential threat; potential legal action or total data loss |

**Risk Rating = Likelihood x Impact:**
| Rating | Range | Action Required |
|---|---|---|
| **Critical** | 16–25 | Immediate action required before production launch |
| **High** | 10–15 | Must be addressed before or shortly after launch |
| **Medium** | 5–9 | Should be addressed within defined timeframe |
| **Low** | 1–4 | Accept or address as resources allow |

---

## 2. Legal & Regulatory Risks

### L1. GDPR / UK DPA 2018 Compliance Gaps

| | |
|---|---|
| **Description** | The platform processes personal data (names, emails, passwords, IP addresses, uploaded files) but lacks several UK GDPR compliance requirements: no data processing agreements with processors (Stripe, SMTP provider, Railway), no formal DSAR process, no data retention policy, incomplete privacy notice (no controller contact details published). |
| **Likelihood** | 4 — Likely |
| **Impact** | 4 — Major (ICO enforcement, fines up to £17.5m or 4% turnover) |
| **Risk Score** | **16 — Critical** |
| **Mitigation** | Execute DPAs with all processors. Publish complete controller details. Implement DSAR process and data export. Define and publish retention policy. Complete data protection assessment mitigations. |

### L2. No Formal Verification Process — Self-Declaration Only

| | |
|---|---|
| **Description** | Certificates are issued based solely on the artist's self-declaration that work is human-made. There is no independent verification, AI detection scanning, expert review, or evidence authentication. The platform issues certificates that carry an implicit stamp of authority. |
| **Likelihood** | 5 — Almost certain (false declarations will occur) |
| **Impact** | 3 — Moderate (misleading certificates undermine service value) |
| **Risk Score** | **15 — High** |
| **Mitigation** | Clearly communicate that certification is based on self-declaration, not independent verification. Include prominent disclaimers on certificates and the verification page. Consider adding community reporting and review mechanisms. Explore AI detection tools as a supplementary check. |

### L3. Liability if Certificates Relied Upon for Purchase Decisions

| | |
|---|---|
| **Description** | Buyers may rely on Officially Human Art certificates when making purchasing decisions. If a certified work is later found to be AI-generated, the platform could face claims for misrepresentation or negligence, particularly under the Consumer Rights Act 2015 or common law negligent misstatement. |
| **Likelihood** | 3 — Possible |
| **Impact** | 4 — Major (legal claims, financial liability) |
| **Risk Score** | **12 — High** |
| **Mitigation** | Include clear disclaimers in Terms of Service that certificates represent self-declaration, not a guarantee. Add disclaimers to certificate displays and verification pages. Obtain professional indemnity insurance. Consider limiting liability through contractual terms. |

### L4. No Independent Audit or Accreditation

| | |
|---|---|
| **Description** | The certification service has no external audit, accreditation body oversight, or industry standard compliance (e.g. ISO). This limits the credibility and legal standing of certificates. |
| **Likelihood** | 4 — Likely (will be questioned) |
| **Impact** | 2 — Minor (credibility gap, not legal liability per se) |
| **Risk Score** | **8 — Medium** |
| **Mitigation** | Seek accreditation from relevant arts or standards bodies. Publish methodology transparently. Consider independent audit of processes. Build credibility through partnerships with established art institutions. |

### L5. Terms of Service and Legal Page Gaps

| | |
|---|---|
| **Description** | A legal page exists (`legal.html`) but the Terms, Privacy Notice, and Disclaimer may not fully cover platform-specific risks such as the self-declaration model, limitation of liability for false certificates, or IP disputes between users. |
| **Likelihood** | 3 — Possible |
| **Impact** | 3 — Moderate (weak legal position in disputes) |
| **Risk Score** | **9 — Medium** |
| **Mitigation** | Engage a solicitor to review and strengthen Terms of Service, Privacy Notice, and Disclaimer. Ensure they address self-declaration liability, IP disputes, certificate revocation rights, and platform limitations. |

---

## 3. Operational Risks

### O1. Single JSON File Database — Data Loss & Corruption

| | |
|---|---|
| **Description** | All application data is stored in a single `db.json` file using synchronous `fs.readFileSync`/`fs.writeFileSync`. Concurrent writes could corrupt the file. A failed write (e.g. disk full, crash mid-write) could destroy all data. There is no write-ahead log, no transactions, no integrity checks. |
| **Likelihood** | 4 — Likely (concurrent requests are normal in web applications) |
| **Impact** | 5 — Severe (total loss of all user accounts, certificates, and reports) |
| **Risk Score** | **20 — Critical** |
| **Mitigation** | Migrate to a proper database (PostgreSQL, SQLite with WAL mode, or MongoDB). Implement atomic writes with temporary file + rename pattern as an interim measure. Add database integrity checks on startup. |

### O2. No Backup Strategy

| | |
|---|---|
| **Description** | No automated or manual backup process exists for the database file or uploaded files. Railway persistent volumes do not include automatic backups. A single deletion, corruption event, or infrastructure failure would result in permanent data loss. |
| **Likelihood** | 4 — Likely (over time, some failure will occur) |
| **Impact** | 5 — Severe (irrecoverable data loss) |
| **Risk Score** | **20 — Critical** |
| **Mitigation** | Implement automated daily backups of `db.json` and the uploads directory. Use off-site storage (e.g. S3, Backblaze B2). Test backup restoration regularly. Consider Railway's snapshot features or database add-ons. |

### O3. No Monitoring or Alerting

| | |
|---|---|
| **Description** | No application monitoring, uptime checks, error tracking, or alerting is configured. Server errors are logged to `console.error` only. Disk space, memory, and CPU are unmonitored. The operator would not know if the service went down or experienced errors until users reported issues. |
| **Likelihood** | 5 — Almost certain (issues will go undetected) |
| **Impact** | 3 — Moderate (extended downtime, silent failures) |
| **Risk Score** | **15 — High** |
| **Mitigation** | Implement uptime monitoring (e.g. UptimeRobot, Better Stack). Add application error tracking (e.g. Sentry). Set up disk space and memory alerts. Configure email or Slack notifications for critical events. Add structured logging. |

### O4. Railway Platform Dependency

| | |
|---|---|
| **Description** | The entire service is hosted on Railway with no documented disaster recovery plan. Railway outages, pricing changes, or service discontinuation would affect availability. No infrastructure-as-code or documented deployment process for migration to alternative hosting. |
| **Likelihood** | 2 — Unlikely (Railway is a stable platform) |
| **Impact** | 4 — Major (extended downtime; complex migration) |
| **Risk Score** | **8 — Medium** |
| **Mitigation** | Document the deployment process. Maintain a `Dockerfile` or deployment script for portability. Identify alternative hosting platforms. Ensure all environment variables and configuration are documented. |

### O5. Single-Developer Bus Factor

| | |
|---|---|
| **Description** | The platform appears to be developed and operated by a single person. If the developer becomes unavailable, there is no one to maintain the service, respond to incidents, handle DSARs, or manage disputes. |
| **Likelihood** | 3 — Possible |
| **Impact** | 4 — Major (service abandonment; user data stranded) |
| **Risk Score** | **12 — High** |
| **Mitigation** | Document all operational procedures, credentials, and architecture. Ensure at least one other trusted person has access to Railway, Stripe, DNS, and email accounts. Consider a succession plan for the service and its data. |

### O6. No Automated Testing

| | |
|---|---|
| **Description** | The `package.json` shows no test framework configured (`"test": "echo \"Error: no test specified\" && exit 1"`). No unit, integration, or end-to-end tests exist. Changes to the codebase risk introducing regressions without detection. |
| **Likelihood** | 4 — Likely (bugs will be introduced with changes) |
| **Impact** | 2 — Minor (service degradation; user-facing bugs) |
| **Risk Score** | **8 — Medium** |
| **Mitigation** | Add automated tests for critical paths: registration, login, artwork submission, certificate verification, account deletion. Use a test framework (e.g. Jest, Mocha). Implement CI/CD pipeline with test gates. |

---

## 4. Security Risks

### S1. No Server-Side Authentication

| | |
|---|---|
| **Description** | API endpoints accept a client-supplied `artistId` as the sole authorisation mechanism. There are no session tokens, JWTs, or cookies. Anyone who obtains or guesses an artist's UUID can impersonate them — viewing, editing, and deleting their certificates, cancelling their Stripe subscription, or deleting their account. |
| **Likelihood** | 4 — Likely (UUIDs may leak via logs, URLs, or client-side code) |
| **Impact** | 5 — Severe (full account takeover; data destruction) |
| **Risk Score** | **20 — Critical** |
| **Mitigation** | Implement server-side session management using signed HTTP-only cookies or JWT tokens. Validate session on every authenticated request. See data protection assessment for full details. |

### S2. No HTTPS Enforcement

| | |
|---|---|
| **Description** | The server does not enforce HTTPS. No redirect from HTTP to HTTPS. No HSTS header. If Railway's proxy does not enforce HTTPS (or during development), all data including passwords and reset tokens is transmitted in cleartext. |
| **Likelihood** | 3 — Possible (depends on Railway configuration) |
| **Impact** | 5 — Severe (credential interception; session hijacking) |
| **Risk Score** | **15 — High** |
| **Mitigation** | Configure Railway for HTTPS-only. Add HSTS header. Redirect all HTTP requests to HTTPS at the application level. |

### S3. Private Files Publicly Accessible

| | |
|---|---|
| **Description** | The `/uploads` directory is served as public static files. Evidence files marked as `public: false` are excluded from API responses but remain accessible via direct URL if the filename is known. Filenames are predictable (timestamp + original name). |
| **Likelihood** | 3 — Possible |
| **Impact** | 3 — Moderate (exposure of private WIP materials) |
| **Risk Score** | **9 — Medium** |
| **Mitigation** | Serve private files through an authenticated endpoint. Use randomised filenames. Remove static serving of the uploads directory. |

### S4. No File Type Validation on Upload

| | |
|---|---|
| **Description** | Multer accepts any file type without server-side validation of MIME type or magic bytes. Malicious files (HTML, SVG with scripts, executables) could be uploaded and served from the platform's domain. |
| **Likelihood** | 3 — Possible |
| **Impact** | 4 — Major (stored XSS; malware distribution from trusted domain) |
| **Risk Score** | **12 — High** |
| **Mitigation** | Validate file MIME type and magic bytes on upload. Restrict to image formats (JPEG, PNG, GIF, WebP). Set `Content-Disposition: attachment` for downloads. Add `X-Content-Type-Options: nosniff` header. |

### S5. Missing Security Headers

| | |
|---|---|
| **Description** | No Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, or Permissions-Policy headers are set. The application is vulnerable to clickjacking, MIME sniffing, and inline script injection. |
| **Likelihood** | 3 — Possible |
| **Impact** | 3 — Moderate (clickjacking; XSS amplification) |
| **Risk Score** | **9 — Medium** |
| **Mitigation** | Add security headers via middleware (e.g. `helmet` npm package). Configure CSP to restrict script sources. Set X-Frame-Options to DENY. |

### S6. In-Memory Rate Limiting

| | |
|---|---|
| **Description** | Rate limit counters are stored in a JavaScript object in server memory. Any server restart (deployment, crash, scaling) resets all counters, allowing attackers to retry brute-force attempts immediately. |
| **Likelihood** | 4 — Likely (deployments are frequent) |
| **Impact** | 3 — Moderate (brute-force window after each restart) |
| **Risk Score** | **12 — High** |
| **Mitigation** | Use Redis or a persistent store for rate limit counters. Alternatively, use Railway's Redis add-on or a file-backed rate limiter. |

---

## 5. Reputational Risks

### R1. False Declarations by Creators

| | |
|---|---|
| **Description** | Artists may falsely declare AI-generated work as human-made and receive certification. The existing report/dispute mechanism is reactive and has no resolution workflow — reports are stored but never actioned (no admin panel). |
| **Likelihood** | 5 — Almost certain |
| **Impact** | 4 — Major (trust erosion; media criticism; service credibility destroyed) |
| **Risk Score** | **20 — Critical** |
| **Mitigation** | Build an admin panel for dispute resolution. Define a clear investigation and revocation process. Implement certificate suspension pending review. Consider requiring more substantial evidence for higher tiers. Publish a transparency report on disputes. |

### R2. Trust Erosion if Certificates Are Unreliable

| | |
|---|---|
| **Description** | If the public perceives certificates as unreliable (due to false declarations, no verification, or technical vulnerabilities), the entire value proposition collapses. Media coverage of even one high-profile false certificate could severely damage the brand. |
| **Likelihood** | 4 — Likely |
| **Impact** | 5 — Severe (existential threat to the service) |
| **Risk Score** | **20 — Critical** |
| **Mitigation** | Invest in dispute resolution infrastructure. Be transparent about the self-declaration model. Build community trust through active moderation. Partner with established art institutions for credibility. Develop a public response plan for disputes. |

### R3. Public Disputes Between Artists

| | |
|---|---|
| **Description** | Artists may dispute each other's certificates publicly (e.g. plagiarism claims, AI use accusations). Without a formal resolution process, disputes could play out on social media, damaging the platform's reputation. |
| **Likelihood** | 3 — Possible |
| **Impact** | 3 — Moderate (negative publicity; user attrition) |
| **Risk Score** | **9 — Medium** |
| **Mitigation** | Implement a formal dispute resolution process with defined timelines and outcomes. Consider an appeals mechanism. Establish community guidelines and enforce them consistently. |

### R4. Service Unavailability or Data Loss

| | |
|---|---|
| **Description** | If the platform goes offline or loses data, artists who rely on it for certification proof lose their credentials. Buyers who previously verified certificates can no longer confirm authenticity. |
| **Likelihood** | 3 — Possible |
| **Impact** | 4 — Major (broken verification links; user trust destroyed) |
| **Risk Score** | **12 — High** |
| **Mitigation** | Implement backups and disaster recovery (see O2). Provide artists with downloadable certificate proof (already partially implemented via downloadable certificate cards). Consider issuing certificates with standalone verification data. |

---

## 6. Financial Risks

### F1. Stripe Integration Issues

| | |
|---|---|
| **Description** | Stripe is not yet configured for production (TODO item). Webhook handling exists but has not been tested with real transactions. Failed payment processing could prevent Creator tier upgrades, lock users out of paid features, or create billing discrepancies. |
| **Likelihood** | 3 — Possible |
| **Impact** | 3 — Moderate (revenue loss; user frustration) |
| **Risk Score** | **9 — Medium** |
| **Mitigation** | Thoroughly test Stripe integration in test mode before production. Implement webhook retry handling. Monitor failed payments and subscription events. Set up Stripe dashboard alerts. |

### F2. Refund Liability

| | |
|---|---|
| **Description** | If a Creator subscriber's certificates are revoked (e.g. due to false declarations) or the service is discontinued, users may demand refunds. Stripe chargebacks and refund disputes could incur fees. |
| **Likelihood** | 2 — Unlikely |
| **Impact** | 3 — Moderate (financial loss; Stripe account standing) |
| **Risk Score** | **6 — Medium** |
| **Mitigation** | Define a clear refund policy in Terms of Service. Set subscriber expectations about certificate revocation scenarios. Monitor chargeback rates to maintain Stripe account health. |

### F3. Hosting Costs Scaling

| | |
|---|---|
| **Description** | Railway charges based on usage. If the platform gains significant traction, hosting costs for compute, storage (uploaded files), and bandwidth could escalate. The JSON file database will also become a performance bottleneck with scale. |
| **Likelihood** | 2 — Unlikely (early stage) |
| **Impact** | 2 — Minor (cost management issue) |
| **Risk Score** | **4 — Low** |
| **Mitigation** | Monitor Railway usage and costs. Set billing alerts. Plan migration to a more scalable architecture (proper database, CDN for static assets, object storage for uploads) before scaling becomes critical. |

### F4. Revenue Concentration on Single Payment Processor

| | |
|---|---|
| **Description** | All payment processing relies on Stripe. A Stripe account suspension (e.g. due to chargeback rates or policy violations) would immediately halt all revenue and prevent new subscriptions. |
| **Likelihood** | 1 — Rare |
| **Impact** | 4 — Major (complete revenue halt) |
| **Risk Score** | **4 — Low** |
| **Mitigation** | Maintain good standing with Stripe. Monitor chargeback and dispute rates. Have a contingency plan for alternative payment processing (e.g. PayPal, GoCardless). |

---

## 7. Intellectual Property Risks

### IP1. Hosting Copyrighted Work

| | |
|---|---|
| **Description** | The platform stores and publicly displays artwork images and evidence files uploaded by users. Users may upload work they do not own, or third parties may claim copyright over displayed works. The platform could be liable as a host of infringing content. |
| **Likelihood** | 3 — Possible |
| **Impact** | 4 — Major (takedown demands; legal action; hosting provider terms violation) |
| **Risk Score** | **12 — High** |
| **Mitigation** | Implement a clear copyright/takedown policy (DMCA-equivalent for UK: Copyright, Designs and Patents Act 1988). Provide a reporting mechanism for rights holders. Respond promptly to takedown requests. Include IP warranties in Terms of Service. |

### IP2. Takedown Obligations

| | |
|---|---|
| **Description** | Under the UK Online Safety Act 2023 and E-Commerce Regulations, hosting platforms have obligations to act on notice of illegal content. The platform currently has a report/dispute button but no admin panel or process to review and act on reports. |
| **Likelihood** | 3 — Possible |
| **Impact** | 3 — Moderate (regulatory non-compliance; legal exposure) |
| **Risk Score** | **9 — Medium** |
| **Mitigation** | Build an admin/moderation panel. Define a content removal process with clear timelines. Document the complaints handling procedure. Designate a responsible person for takedown requests. |

### IP3. Limited Licence Scope

| | |
|---|---|
| **Description** | The platform displays user-uploaded artwork publicly (on verification pages, browse page, profile pages, embeddable widgets, OG tags for social sharing). The current Terms of Service may not clearly define the licence granted by uploading artists, creating ambiguity about the platform's right to display, cache, and redistribute their work. |
| **Likelihood** | 3 — Possible |
| **Impact** | 2 — Minor (disputes with artists; need to remove content) |
| **Risk Score** | **6 — Medium** |
| **Mitigation** | Define a clear content licence in Terms of Service granting the platform the right to display, cache, and distribute uploaded works for the purpose of certification and verification. Allow artists to revoke this licence by deleting their certificates. |

### IP4. Artist Impersonation

| | |
|---|---|
| **Description** | There is no email verification or identity verification on registration. Anyone could register an account using a real artist's name and email, then certify work under their identity. |
| **Likelihood** | 3 — Possible |
| **Impact** | 4 — Major (reputational damage to impersonated artists; legal claims) |
| **Risk Score** | **12 — High** |
| **Mitigation** | Implement email verification on registration. Consider additional identity verification for high-profile accounts. Add a mechanism for artists to claim and verify their identity. Include impersonation as grounds for account suspension in Terms of Service. |

---

## 8. Risk Matrix Summary

### Critical (16–25) — Immediate Action Required

| ID | Risk | Score |
|---|---|---|
| L1 | GDPR / UK DPA 2018 compliance gaps | 16 |
| O1 | Single JSON file database — data loss & corruption | 20 |
| O2 | No backup strategy | 20 |
| S1 | No server-side authentication | 20 |
| R1 | False declarations by creators | 20 |
| R2 | Trust erosion if certificates are unreliable | 20 |

### High (10–15) — Address Before or Shortly After Launch

| ID | Risk | Score |
|---|---|---|
| L2 | No formal verification — self-declaration only | 15 |
| L3 | Liability if certificates relied upon for purchases | 12 |
| O3 | No monitoring or alerting | 15 |
| O5 | Single-developer bus factor | 12 |
| S2 | No HTTPS enforcement | 15 |
| S4 | No file type validation on upload | 12 |
| S6 | In-memory rate limiting | 12 |
| R4 | Service unavailability or data loss | 12 |
| IP1 | Hosting copyrighted work | 12 |
| IP4 | Artist impersonation | 12 |

### Medium (5–9) — Address Within Defined Timeframe

| ID | Risk | Score |
|---|---|---|
| L4 | No independent audit or accreditation | 8 |
| L5 | Terms of Service gaps | 9 |
| O4 | Railway platform dependency | 8 |
| O6 | No automated testing | 8 |
| S3 | Private files publicly accessible | 9 |
| S5 | Missing security headers | 9 |
| R3 | Public disputes between artists | 9 |
| F1 | Stripe integration issues | 9 |
| F2 | Refund liability | 6 |
| IP2 | Takedown obligations | 9 |
| IP3 | Limited licence scope | 6 |

### Low (1–4) — Accept or Address as Resources Allow

| ID | Risk | Score |
|---|---|---|
| F3 | Hosting costs scaling | 4 |
| F4 | Revenue concentration on single payment processor | 4 |

---

## 9. Prioritised Action Plan

### Phase 1 — Before Production Launch

1. **Migrate database** from JSON file to SQLite or PostgreSQL (O1)
2. **Implement server-side authentication** with session tokens (S1)
3. **Implement automated backups** for data and uploads (O2)
4. **Enforce HTTPS** and add security headers (S2, S5)
5. **Execute data processing agreements** with Stripe, email provider, Railway (L1)
6. **Add legal disclaimers** about self-declaration model to certificates and verification pages (L2, L3)
7. **Have Terms of Service reviewed** by a solicitor (L5)
8. **Implement email verification** on registration (IP4)

### Phase 2 — Within 3 Months of Launch

9. **Build admin/moderation panel** for dispute resolution and content takedown (R1, IP1, IP2)
10. **Implement monitoring and alerting** (O3)
11. **Validate uploaded file types** server-side (S4)
12. **Persist rate limiting** in Redis or equivalent (S6)
13. **Restrict private file access** through authenticated endpoints (S3)
14. **Add CSRF protection** to state-changing endpoints
15. **Document operational procedures** and share access credentials (O5)

### Phase 3 — Ongoing

16. **Implement automated testing** for critical paths (O6)
17. **Develop copyright/takedown policy** and publish it (IP1, IP2)
18. **Define content licence** in Terms of Service (IP3)
19. **Implement DSAR process** and data export (L1)
20. **Explore AI detection tools** as supplementary verification (L2, R1)
21. **Seek accreditation** from arts or standards bodies (L4)
22. **Self-host fonts** to eliminate Google Fonts dependency
23. **Establish community guidelines** and public dispute resolution process (R3)

---

## 10. Review Schedule

This risk assessment should be reviewed:

- **Before production launch** — validate all Phase 1 mitigations are complete
- **Quarterly** for the first year of operation
- **After any security incident or significant service change**
- **Annually** thereafter

---

*This document complements the Data Protection Risk Assessment (`data-protection-assessment.md`) which covers personal data handling, security measures, and UK GDPR compliance in detail.*
