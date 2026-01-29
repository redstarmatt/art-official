# Art-Official — TODO

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

## Pending
- [ ] Configure Stripe for production (set STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_CREATOR_PRICE_ID on Railway)
  - Create Product + £5/month Price in Stripe dashboard, set up webhook endpoint
- [ ] Add custom domain and verify in Resend so emails send from @art-official.com (or similar)
  - Buy domain, add DNS records (SPF, DKIM), update SMTP_FROM env var on Railway
