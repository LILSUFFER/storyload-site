# Storyload

Video publishing platform — publish videos to TikTok and YouTube via official APIs.
Multi-profile system (up to 100 profiles per user), each with its own TikTok/YouTube channel.
Includes a REST API for programmatic publishing.

## Features

- Sign in with Google
- Create up to 100 profile cards per account
- Connect TikTok and YouTube per profile
- Publish videos via web dashboard or REST API
- PostgreSQL session store (survives server restarts)
- Developer API with API key auth (`sl_live_*`)

---

## Production Deploy (VPS + PM2 + Nginx)

### Prerequisites

- Ubuntu 20.04+ VPS (DigitalOcean, Hetzner, etc.)
- Domain `storyload.ru` pointing to server IP (A record)
- Node.js 18+
- PM2: `npm install -g pm2`
- Nginx: `apt install nginx`
- Neon.tech PostgreSQL account (free tier works)

### 1. Clone the repo

```bash
git clone https://github.com/LILSUFFER/storyload.git /var/www/storyload
cd /var/www/storyload
npm install --production
```

### 2. Configure environment

Copy the example and fill in your values:

```bash
cp .env.example .env
nano .env
```

| Variable | Description |
|---|---|
| `APP_URL` | `https://storyload.ru` |
| `PORT` | `3001` |
| `SESSION_SECRET` | **Required** — generate with `openssl rand -base64 48` before first start |
| `GOOG_CLIENT_ID` | Google OAuth2 Client ID |
| `GOOG_CLIENT_SECRET` | Google OAuth2 Client Secret |
| `TIKTOK_CLIENT_KEY` | TikTok App Client Key |
| `TIKTOK_CLIENT_SECRET` | TikTok App Client Secret |
| `NEON_DATABASE_URL` | `postgresql://user:pass@host/db?sslmode=require` |

Or edit `ecosystem.config.js` directly (recommended for PM2).

### 3. Start with PM2

```bash
pm2 start ecosystem.config.js
pm2 save
pm2 startup   # follow the printed command to enable autostart
```

### 4. Configure Nginx

Create `/etc/nginx/sites-available/storyload`:

```nginx
server {
    listen 80;
    server_name storyload.ru www.storyload.ru;

    client_max_body_size 600M;

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 300s;
    }
}
```

Enable and reload:

```bash
ln -s /etc/nginx/sites-available/storyload /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

### 5. SSL with Let's Encrypt

```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d storyload.ru -d www.storyload.ru
```

### 6. OAuth Redirect URIs

Add these to your Google Cloud Console and TikTok Developer Portal:

| Service | Callback URL |
|---|---|
| Google (login) | `https://storyload.ru/auth/google/callback` |
| YouTube | `https://storyload.ru/auth/youtube/callback` |
| TikTok | `https://storyload.ru/auth/tiktok/callback` |

### 7. Update

```bash
cd /var/www/storyload
git pull
npm install --production
pm2 restart storyload
```

---

## Developer REST API

Base URL: `https://storyload.ru/v1`

Generate API keys at `/account/api-keys`. Full documentation at `/docs`.

```bash
# List profiles
curl https://storyload.ru/v1/profiles \
  -H "Authorization: Bearer sl_live_your_key"

# Publish video to TikTok
curl -X POST https://storyload.ru/v1/profiles/PROFILE_ID/publish \
  -H "Authorization: Bearer sl_live_your_key" \
  -F "platform=tiktok" \
  -F "title=My video" \
  -F "video=@video.mp4"
```

---

## Local Development

```bash
npm install
cp .env.example .env
# Edit .env
npm run dev
```

---

## Tech Stack

- **Backend**: Node.js + Express
- **Database**: PostgreSQL (Neon.tech)
- **Auth**: Google OAuth 2.0
- **Video APIs**: TikTok Content Posting API, YouTube Data API v3
- **Sessions**: `connect-pg-simple` (stored in PostgreSQL)
