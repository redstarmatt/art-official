# Officially Human Art — TODO

## Completed
- [x] Fix registration API response mismatch
- [x] Fix portfolio URL field name mismatch (portfolioUrl -> portfolio)
- [x] Fix portfolio URL input to accept bare domains
- [x] Separate artwork image from WIP evidence uploads
- [x] Per-file visibility controls for evidence
- [x] Writing-specific evidence guidance
- [x] Copyright notice on submission form
- [x] CSS watermark on displayed images
- [x] Downloadable certificate card (replaces QR on verify page)
- [x] Legal page (Terms, Privacy, Disclaimer, Copyright)
- [x] Password authentication for artist login
- [x] Certificate email on artwork registration
- [x] Embeddable website widget/badge for creators
- [x] Set up GitHub repo
- [x] Free/Creator pricing tiers with Stripe payment integration
- [x] "Our Story" section on landing page
- [x] Changed hero example to digital illustration (more relevant to AI risk)
- [x] Evidence visibility prompting (explain public vs private WIP files)
- [x] Increased watermark visibility on certificate images
- [x] Delete/withdraw certificates from dashboard
- [x] Edit certificate text (title, description, process notes)
- [x] Open Graph meta tags on verify page for social sharing previews
- [x] Live community stats counter on landing page
- [x] Log In button on homepage nav
- [x] Persistent storage (Railway volume) for data and uploads
- [x] Dispute/report button on certificate verify pages
- [x] Certificate timeline (issued, edited, reported history)
- [x] Public browse/explore page with filters and pagination
- [x] Password reset flow (forgot password + email reset link)
- [x] Rate limiting on login, registration, and password reset endpoints
- [x] Account deletion on demand (password-confirmed, deletes all data + files + Stripe sub)

## Pending
- [ ] Review "Date of Creation" label — consider "Date Created" or "Date Completed"
- [ ] Configure Stripe for production (set STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_CREATOR_PRICE_ID on Railway)
  - Create Product + £5/month Price in Stripe dashboard, set up webhook endpoint
- [ ] Add custom domain and verify in Resend so emails send from @officiallyhuman.art (or similar)
  - Buy domain, add DNS records (SPF, DKIM), update SMTP_FROM env var on Railway
- [x] Data protection risk assessment
- [x] General risk assessment
