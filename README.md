# Officially Human Art — AI-Free Art Certification

A prototype service where artists can register their work as created without AI assistance. Artists pay for verification, receive a certificate with QR code, and buyers can verify authenticity via public lookup.

## Quick Start

```bash
cd humanmade
npm install
node server.js
```

Then open http://localhost:3000

## Features

### For Artists
- **Register Account** — Create a profile with name, email, portfolio link
- **Submit Artwork** — Register works with title, medium, date, description
- **Upload Evidence** — Optional process photos/videos as supporting documentation  
- **Sign Declaration** — Legally-binding statement that work is human-made
- **Receive Certificate** — Unique ID (format: `OH-2026-X7K9M2`) with QR code
- **Dashboard** — View all registered certificates

### For Buyers/Verifiers
- **Public Verification** — Enter certificate code to confirm authenticity
- **QR Code Support** — Scan from physical certificates or embedded badges
- **Full Details** — See artist, artwork info, registration date, status

## Pricing Tiers (Display Only)

| Plan | Price | Description |
|------|-------|-------------|
| Single Work | £25 | One certification |
| Portfolio | £99 | 5 works |
| Annual | £299 | Unlimited |

## Tech Stack

- **Backend**: Express.js
- **Database**: JSON file storage (simple, no build dependencies)
- **QR Codes**: `qrcode` package
- **File Uploads**: `multer`
- **Frontend**: Vanilla HTML/CSS/JS

## Project Structure

```
humanmade/
├── server.js           # Express API server
├── public/
│   ├── index.html      # Landing page
│   ├── register.html   # Artist portal (register, submit, dashboard)
│   └── verify.html     # Public verification page
├── data/
│   └── db.json         # Database (auto-created)
├── uploads/            # Evidence files (auto-created)
└── package.json
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/artist/register` | Create artist account |
| GET | `/api/artist/lookup?email=` | Find artist by email |
| POST | `/api/artwork/submit` | Submit artwork for certification |
| GET | `/api/artist/:id/certificates` | List artist's certificates |
| GET | `/api/verify/:code` | Verify certificate (public) |
| GET | `/api/qr/:code` | Generate QR code for certificate |

## Design Notes

The UI uses a "Digital Notary" aesthetic:
- Navy (#1a365d) and cream (#fffef0) palette
- Gold (#b7960b) accents for authenticity markers
- Cormorant Garamond serif for gravitas
- DM Sans for readable body text
- Subtle paper texture for tactile feel
- Certificate styling with seals and borders

## What's Not Included (Prototype Scope)

- Actual payment processing (Stripe, etc.)
- Email verification
- AI detection scanning
- Admin moderation panel
- User password authentication (uses email lookup only)

## Next Steps for Production

1. Add proper authentication (passwords, OAuth)
2. Integrate Stripe for payments
3. Add email notifications
4. Build admin panel for dispute handling
5. Add embeddable badges for artist websites
6. Consider blockchain timestamping for extra verification
