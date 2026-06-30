# Secure portfolio deployment

This package requires a Node.js server and must not be deployed as a static
GitHub Pages site. GitHub Pages cannot enforce server-side authentication.

Set `PORTFOLIO_PASSWORD` and `SESSION_SECRET` using the hosting provider's
encrypted environment-secret settings. Never commit real values to Git.

Production requirements:

- Node.js 20 or newer
- HTTPS enforced by the hosting provider
- `npm start` as the start command
- `HOST=0.0.0.0`
- A unique password of at least 16 characters
- A cryptographically random session secret of at least 32 bytes

The application provides password hashing, signed server-side sessions,
progressive brute-force lockouts, protected static assets, security headers,
and automatic logout after five minutes of inactivity.
