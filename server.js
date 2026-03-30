"use strict";
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { google } = require("googleapis");
const multer = require("multer");
const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = parseInt(process.env.PORT || "3000", 10);
const APP_URL = (process.env.APP_URL || "http://localhost:3000").replace(/\/$/, "");

const GOOGLE_CLIENT_ID = process.env.GOOG_CLIENT_ID || process.env.GOOGLE_CLIENT_ID || process.env.YOUTUBE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOG_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET || process.env.YOUTUBE_CLIENT_SECRET || "";
const TIKTOK_CLIENT_KEY = process.env.TIKTOK_CLIENT_KEY || "";
const TIKTOK_CLIENT_SECRET = process.env.TIKTOK_CLIENT_SECRET || "";

// ── Auth security ─────────────────────────────────────────────────────────────
// Allowlist of valid platform names for OAuth routes
const ALLOWED_PLATFORMS = new Set(["tiktok", "youtube"]);
// UUID v4 pattern — only accept this for profile_id params
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
// Returns a hardcoded internal redirect path — never trusts raw string from request
function safeBack(profileId) {
  if (profileId && UUID_RE.test(String(profileId))) return `/profiles/${profileId}`;
  return "/dashboard";
}
// Validates a platform param against the allowlist
function isValidPlatform(p) {
  return typeof p === "string" && ALLOWED_PLATFORMS.has(p);
}

// DB — prefer Neon (external, 24/7) over Replit-managed DB
const DB_URL = (process.env.NEON_DATABASE_URL || process.env.DATABASE_URL || "")
  .replace("sslmode=require", "sslmode=verify-full")
  .replace("channel_binding=require", "channel_binding=prefer");
const db = new Pool({
  connectionString: DB_URL,
  ssl: { rejectUnauthorized: !!process.env.NEON_DATABASE_URL },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});
async function query(sql, params) { const r = await db.query(sql, params); return r.rows; }
async function ensureTables() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS sl_users (
      id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
      email TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
      google_id TEXT UNIQUE, avatar TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sl_profiles (
      id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
      user_id VARCHAR NOT NULL REFERENCES sl_users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sl_user_channels (
      id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
      user_id VARCHAR NOT NULL, platform TEXT NOT NULL,
      access_token TEXT NOT NULL, refresh_token TEXT,
      account_name TEXT, account_id TEXT,
      expires_at BIGINT, scope TEXT, extra JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  // Migration: add profile_id to existing sl_user_channels table
  await db.query(`
    ALTER TABLE sl_user_channels
      ADD COLUMN IF NOT EXISTS profile_id VARCHAR REFERENCES sl_profiles(id) ON DELETE CASCADE;
  `);
  // API keys table
  await db.query(`
    CREATE TABLE IF NOT EXISTS sl_api_keys (
      id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
      user_id VARCHAR NOT NULL REFERENCES sl_users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      key_prefix VARCHAR(16) NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      created_at TIMESTAMP DEFAULT NOW(),
      last_used_at TIMESTAMP
    );
  `);
}

// API key auth middleware
async function requireApiKey(req, res, next) {
  const auth = req.headers["authorization"] || "";
  const key = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!key.startsWith("sl_live_")) return res.status(401).json({ error: "unauthorized", message: "Missing or invalid API key. Pass: Authorization: Bearer sl_live_..." });
  const hash = crypto.createHash("sha256").update(key).digest("hex");
  const rows = await query("SELECT * FROM sl_api_keys WHERE key_hash=$1", [hash]);
  if (!rows[0]) return res.status(401).json({ error: "unauthorized", message: "API key not found or revoked" });
  await query("UPDATE sl_api_keys SET last_used_at=NOW() WHERE id=$1", [rows[0].id]).catch(() => {});
  req.apiUserId = rows[0].user_id;
  req.apiKeyId = rows[0].id;
  next();
}

// Middleware
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// Security headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Content-Security-Policy",
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https://p16-sign-va.tiktokcdn.com https://p19-sign.tiktokcdn-us.com https://yt3.ggpht.com https://lh3.googleusercontent.com https://*.googleusercontent.com https://*.tiktokcdn.com https://*.tiktokcdn-us.com; " +
    "font-src 'self'; " +
    "connect-src 'self'; " +
    "frame-ancestors 'none';"
  );
  next();
});

// robots.txt
app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send("User-agent: *\nAllow: /\nDisallow: /dashboard\nDisallow: /account\nDisallow: /api\nDisallow: /auth\nSitemap: https://storyload.ru/sitemap.xml\n");
});

// sitemap.xml
app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml");
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://storyload.ru/</loc><changefreq>monthly</changefreq><priority>1.0</priority></url>
  <url><loc>https://storyload.ru/about</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>https://storyload.ru/privacy</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>
  <url><loc>https://storyload.ru/terms</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>
  <url><loc>https://storyload.ru/docs</loc><changefreq>monthly</changefreq><priority>0.6</priority></url>
</urlset>`);
});

app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new pgSession({
    pool: db,
    tableName: "sl_sessions",
    createTableIfMissing: true,
  }),
  secret: process.env.SESSION_SECRET || "storyload-dev-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 }, // 30 days
}));

const upload = multer({ dest: uploadDir, limits: { fileSize: 500 * 1024 * 1024 } });

// All /auth/* routes: no caching, no indexing — prevents Safe Browsing from scanning auth URLs
app.use("/auth", (req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
  next();
});

function getGoogleClient(redirectUri) {
  return new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, redirectUri);
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  next();
}
async function getUser(id) {
  const r = await query("SELECT * FROM sl_users WHERE id=$1", [id]);
  return r[0] || null;
}
async function getProfiles(userId) {
  return query("SELECT * FROM sl_profiles WHERE user_id=$1 ORDER BY created_at", [userId]);
}
async function getProfileChannels(profileId) {
  return query("SELECT * FROM sl_user_channels WHERE profile_id=$1 ORDER BY platform", [profileId]);
}

function profileInitials(name) {
  return name.trim().split(/\s+/).map(w => w[0]).join("").toUpperCase().slice(0, 2) || "?";
}

const AVATAR_COLORS = ["#6366f1","#8b5cf6","#ec4899","#f59e0b","#10b981","#3b82f6","#ef4444","#14b8a6"];
function avatarColor(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) & 0xffffffff;
  return AVATAR_COLORS[Math.abs(h) % AVATAR_COLORS.length];
}

// ============= HTML Templates =============

const LOGO_SVG = `<img src="/logo.svg" alt="Storyload" style="height:52px;width:auto;display:block;">`;

function layout(title, content, user) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} — Storyload</title>
<link rel="stylesheet" href="/style.css">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
</head>
<body>
<header class="header">
  <div class="header-inner">
    <a href="/" class="logo-link">
      ${LOGO_SVG}
    </a>
    <nav class="header-nav">
      <a href="/about">About</a>
      <a href="/privacy">Privacy</a>
      <a href="/terms">Terms</a>
    </nav>
    <div class="header-right">
      ${user ? `
        ${user.avatar ? `<img src="${user.avatar}" class="avatar" alt="${user.name}">` : ""}
        <span class="user-name">${user.name}</span>
        <a href="/logout" class="btn-outline" style="padding:6px 16px;font-size:13px">Sign out</a>
      ` : `
        <a href="/login" class="btn-primary">Sign in</a>
      `}
    </div>
  </div>
</header>
<main class="main">${content}</main>
<footer class="footer">
  <a href="/about">About</a> · <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a> · <span>© 2026 Storyload</span>
</footer>
</body></html>`;
}

// ============= Routes =============

app.get("/", (req, res) => {
  if (req.session.userId) return res.redirect("/dashboard");

  const bars = Array.from({length: 28}, (_, i) => {
    const h = 80 + Math.random() * 320;
    const dur = (2.5 + Math.random() * 2.5).toFixed(1);
    const delay = (Math.random() * 2.5).toFixed(1);
    return `<div class="hero-bar" style="height:${h}px;--dur:${dur}s;--delay:${delay}s"></div>`;
  }).join("");

  res.send(layout("Publish Videos to TikTok & YouTube", `
  <div class="landing">
    <div class="hero-wrap">
      <div class="hero-glow"></div>
      <div class="hero-bars">${bars}</div>
      <div class="hero-inner">
        <div class="hero-badge">
          <span class="dot"></span>
          TikTok Content Posting API · Sandbox ready
        </div>
        <h1 class="hero-title">Publish videos<br>to TikTok &amp;<br>YouTube</h1>
        <p class="hero-sub">Connect your channels and publish short-form videos directly from a web dashboard — no app switching, no manual upload.</p>
        <div class="hero-cta">
          <a href="/login" class="btn-primary lg">Get started free</a>
          <a href="/about" class="btn-outline lg">Learn more</a>
        </div>
      </div>
    </div>
    <div class="features-wrap">
      <div class="features-inner">
        <div class="section-label"><span class="dot"></span> Features</div>
        <h2 class="section-title">Everything you need<br>to publish at scale</h2>
        <p class="section-sub">Built on official TikTok and YouTube APIs. Secure OAuth connections. No browser extensions, no workarounds.</p>
        <div class="features-grid">
          <div class="feature-card">
            <div class="feature-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="#34D59A"><path d="M19.59 6.69a4.83 4.83 0 0 1-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 0 1-2.88 2.5 2.89 2.89 0 0 1-2.89-2.89 2.89 2.89 0 0 1 2.89-2.89c.28 0 .54.04.79.1V9.01a6.33 6.33 0 0 0-.79-.05 6.34 6.34 0 0 0-6.34 6.34 6.34 6.34 0 0 0 6.34 6.34 6.34 6.34 0 0 0 6.33-6.34V8.69a8.18 8.18 0 0 0 4.78 1.52V6.77a4.85 4.85 0 0 1-1.01-.08z"/></svg>
            </div>
            <h3>TikTok Publishing</h3>
            <p>Upload and publish videos using the official TikTok Content Posting API.</p>
          </div>
          <div class="feature-card">
            <div class="feature-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="#34D59A"><path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/></svg>
            </div>
            <h3>YouTube Upload</h3>
            <p>Connect your YouTube channel via Google OAuth and upload videos directly.</p>
          </div>
          <div class="feature-card">
            <div class="feature-icon">
              <svg width="20" height="20" fill="none" stroke="#34D59A" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
            </div>
            <h3>Secure OAuth</h3>
            <p>Your accounts are connected via OAuth 2.0. We never store your passwords.</p>
          </div>
        </div>
      </div>
    </div>
    <div class="steps-wrap">
      <div class="steps-inner">
        <div class="section-label"><span class="dot"></span> How it works</div>
        <h2 class="section-title">From sign-in to published<br>in under 2 minutes</h2>
        <div class="steps-grid">
          <div class="step">
            <div class="step-num">Step 01</div>
            <h4>Sign in with Google</h4>
            <p>Create your Storyload account using your Google account.</p>
          </div>
          <div class="step">
            <div class="step-num">Step 02</div>
            <h4>Create profile cards</h4>
            <p>Create up to 100 profile cards — each one is a separate project or idea with its own TikTok and YouTube channel.</p>
          </div>
          <div class="step">
            <div class="step-num">Step 03</div>
            <h4>Upload &amp; publish</h4>
            <p>Drag and drop your video, add a title, and hit Publish. Storyload handles the upload automatically.</p>
          </div>
        </div>
      </div>
    </div>
    <div class="cta-wrap">
      <div class="cta-inner">
        <div class="section-label"><span class="dot"></span> Get started</div>
        <h2>Start publishing<br>your videos today</h2>
        <p>Free during the TikTok API review phase. Connect your channel and publish your first video in minutes.</p>
        <div class="cta-btns">
          <a href="/login" class="btn-primary lg">Get started free</a>
          <a href="/about" class="btn-outline lg">About Storyload</a>
        </div>
      </div>
    </div>
  </div>
  `));
});

app.get("/login", (req, res) => {
  if (req.session.userId) return res.redirect("/dashboard");
  res.send(layout("Sign In", `
  <div class="center-page">
    <div class="login-card">
      <h1>Welcome to Storyload</h1>
      <p class="subtitle">Connect your channels and publish content with ease</p>
      <div class="feature-pills">
        <span class="pill">🎬 Video publishing</span>
        <span class="pill">📱 TikTok & YouTube</span>
        <span class="pill">✅ Sandbox ready</span>
      </div>
      <a href="/auth/google" class="btn-google">
        <svg width="20" height="20" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
        Continue with Google
      </a>
      <div class="sandbox-note">
        <span class="dot green"></span>
        <span>TikTok Sandbox environment — safe for testing</span>
      </div>
    </div>
  </div>
  `));
});

// Google OAuth (login)
app.get("/auth/google", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  const client = getGoogleClient(`${APP_URL}/auth/google/callback`);
  const url = client.generateAuthUrl({ access_type: "offline", scope: ["openid", "email", "profile"], state, prompt: "select_account" });
  res.redirect(url);
});

app.get("/auth/google/callback", async (req, res) => {
  // Harden: no session state = reject immediately (prevents Safe Browsing crawler false-positive)
  const expectedState = req.session.oauthState;
  if (!expectedState) return res.redirect("/login");
  // Only extract code and state — ignore all other params (iss, scope, etc.)
  const code = typeof req.query.code === "string" ? req.query.code : "";
  const state = typeof req.query.state === "string" ? req.query.state : "";
  // Constant-time state comparison + clear after use to prevent replay
  const stateMatch = crypto.timingSafeEqual(Buffer.from(state.padEnd(64, "0")), Buffer.from(expectedState.padEnd(64, "0")));
  req.session.oauthState = null;
  if (!code || !stateMatch) return res.redirect("/login?error=state");
  try {
    const client = getGoogleClient(`${APP_URL}/auth/google/callback`);
    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: "v2", auth: client });
    const { data } = await oauth2.userinfo.get();
    const { id: googleId, email, name, picture: avatar } = data;
    let users = await query("SELECT * FROM sl_users WHERE google_id=$1", [googleId]);
    let user = users[0];
    if (!user) {
      const byEmail = await query("SELECT * FROM sl_users WHERE email=$1", [email]);
      if (byEmail[0]) {
        await query("UPDATE sl_users SET google_id=$1, avatar=$2, name=$3 WHERE id=$4", [googleId, avatar, name, byEmail[0].id]);
        user = { ...byEmail[0], google_id: googleId, avatar, name };
      } else {
        const ins = await query("INSERT INTO sl_users(email,name,google_id,avatar) VALUES($1,$2,$3,$4) RETURNING *", [email, name, googleId, avatar]);
        user = ins[0];
      }
    }
    req.session.userId = user.id;
    res.redirect("/dashboard");
  } catch (e) { console.error("[google-cb]", e.message); res.redirect("/login?error=auth"); }
});

// TikTok OAuth — per profile
app.get("/auth/tiktok", requireAuth, (req, res) => {
  const raw = req.query.profile_id;
  const profileId = (typeof raw === "string" && UUID_RE.test(raw)) ? raw : "";
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  req.session.oauthProfileId = profileId;
  const params = new URLSearchParams({
    client_key: TIKTOK_CLIENT_KEY,
    scope: "user.info.basic,video.upload,video.publish",
    response_type: "code",
    redirect_uri: `${APP_URL}/auth/tiktok/callback`,
    state,
  });
  res.redirect(`https://www.tiktok.com/v2/auth/authorize/?${params}`);
});

app.get("/auth/tiktok/callback", async (req, res) => {
  const profileId = req.session.oauthProfileId || null;
  const back = safeBack(profileId);
  const expectedTT = req.session.oauthState;
  const ttCode = typeof req.query.code === "string" ? req.query.code : "";
  const ttState = typeof req.query.state === "string" ? req.query.state : "";
  const ttErr = typeof req.query.error === "string" ? req.query.error : "";
  if (!expectedTT || !req.session.userId) return res.redirect("/login");
  const ttMatch = expectedTT.length === ttState.length && crypto.timingSafeEqual(Buffer.from(ttState), Buffer.from(expectedTT));
  req.session.oauthState = null;
  try {
    if (ttErr) return res.redirect(`${back}?error=${encodeURIComponent(ttErr)}`);
    if (!ttCode || !ttMatch) return res.redirect(`${back}?error=state`);
    const code = ttCode;

    const tokenRes = await fetch("https://open.tiktokapis.com/v2/oauth/token/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_key: TIKTOK_CLIENT_KEY, client_secret: TIKTOK_CLIENT_SECRET, code, grant_type: "authorization_code", redirect_uri: `${APP_URL}/auth/tiktok/callback` }),
    });
    const td = await tokenRes.json();
    if (td.error) return res.redirect(`${back}?error=${encodeURIComponent(td.error_description || td.error)}`);

    const userRes = await fetch("https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name,avatar_url", { headers: { Authorization: `Bearer ${td.access_token}` } });
    const ud = await userRes.json();
    const ttUser = ud?.data?.user || {};
    const accountName = ttUser.display_name || td.open_id;

    const existing = await query(
      "SELECT id FROM sl_user_channels WHERE user_id=$1 AND platform='tiktok' AND profile_id IS NOT DISTINCT FROM $2",
      [req.session.userId, profileId]
    );
    if (existing[0]) {
      await query("UPDATE sl_user_channels SET access_token=$1,refresh_token=$2,account_name=$3,account_id=$4,expires_at=$5,scope=$6 WHERE id=$7",
        [td.access_token, td.refresh_token, accountName, td.open_id, td.expires_in ? Date.now() + td.expires_in * 1000 : null, td.scope, existing[0].id]);
    } else {
      await query("INSERT INTO sl_user_channels(user_id,platform,profile_id,access_token,refresh_token,account_name,account_id,expires_at,scope) VALUES($1,'tiktok',$2,$3,$4,$5,$6,$7,$8)",
        [req.session.userId, profileId, td.access_token, td.refresh_token, accountName, td.open_id, td.expires_in ? Date.now() + td.expires_in * 1000 : null, td.scope]);
    }
    res.redirect(`${back}?connected=tiktok`);
  } catch (e) { console.error(e); res.redirect(`${back}?error=tiktok_auth`); }
});

// YouTube OAuth — per profile
app.get("/auth/youtube", requireAuth, (req, res) => {
  const rawYT = req.query.profile_id;
  const profileId = (typeof rawYT === "string" && UUID_RE.test(rawYT)) ? rawYT : "";
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  req.session.oauthProfileId = profileId;
  const client = getGoogleClient(`${APP_URL}/auth/youtube/callback`);
  const url = client.generateAuthUrl({ access_type: "offline", scope: ["https://www.googleapis.com/auth/youtube.upload", "https://www.googleapis.com/auth/youtube.readonly"], state, prompt: "consent" });
  res.redirect(url);
});

app.get("/auth/youtube/callback", async (req, res) => {
  const profileId = req.session.oauthProfileId || null;
  const back = safeBack(profileId);
  const expectedYT = req.session.oauthState;
  const ytCode = typeof req.query.code === "string" ? req.query.code : "";
  const ytState = typeof req.query.state === "string" ? req.query.state : "";
  const ytErr = typeof req.query.error === "string" ? req.query.error : "";
  if (!expectedYT || !req.session.userId) return res.redirect("/login");
  const ytMatch = expectedYT.length === ytState.length && crypto.timingSafeEqual(Buffer.from(ytState), Buffer.from(expectedYT));
  req.session.oauthState = null;
  try {
    if (ytErr) return res.redirect(`${back}?error=${encodeURIComponent(ytErr)}`);
    if (!ytCode || !ytMatch) return res.redirect(`${back}?error=state`);
    const code = ytCode;
    const client = getGoogleClient(`${APP_URL}/auth/youtube/callback`);
    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);
    const yt = google.youtube({ version: "v3", auth: client });
    const ch = await yt.channels.list({ part: ["snippet"], mine: true });
    const channel = ch.data.items?.[0];
    const accountName = channel?.snippet?.title || "YouTube Channel";
    const accountId = channel?.id || "";
    const existing = await query(
      "SELECT id FROM sl_user_channels WHERE user_id=$1 AND platform='youtube' AND profile_id IS NOT DISTINCT FROM $2",
      [req.session.userId, profileId]
    );
    if (existing[0]) {
      await query("UPDATE sl_user_channels SET access_token=$1,refresh_token=$2,account_name=$3,account_id=$4,expires_at=$5 WHERE id=$6",
        [tokens.access_token, tokens.refresh_token, accountName, accountId, tokens.expiry_date, existing[0].id]);
    } else {
      await query("INSERT INTO sl_user_channels(user_id,platform,profile_id,access_token,refresh_token,account_name,account_id,expires_at) VALUES($1,'youtube',$2,$3,$4,$5,$6,$7)",
        [req.session.userId, profileId, tokens.access_token, tokens.refresh_token, accountName, accountId, tokens.expiry_date]);
    }
    res.redirect(`${back}?connected=youtube`);
  } catch (e) { console.error(e); res.redirect(`${back}?error=youtube_auth`); }
});

app.get("/auth/disconnect/:platform", requireAuth, async (req, res) => {
  // Validate platform against strict allowlist — reject unknown values entirely
  const platform = req.params.platform;
  if (!isValidPlatform(platform)) return res.redirect("/dashboard");
  // Validate profile_id as UUID — reject any other format (prevents path traversal + CRLF)
  const rawPid = req.query.profile_id;
  const profileId = (typeof rawPid === "string" && UUID_RE.test(rawPid)) ? rawPid : null;
  if (profileId) {
    await query("DELETE FROM sl_user_channels WHERE user_id=$1 AND platform=$2 AND profile_id=$3", [req.session.userId, platform, profileId]);
    return res.redirect(`/profiles/${profileId}`);
  }
  await query("DELETE FROM sl_user_channels WHERE user_id=$1 AND platform=$2 AND profile_id IS NULL", [req.session.userId, platform]);
  res.redirect("/dashboard");
});

app.get("/logout", (req, res) => { req.session.destroy(() => {}); res.redirect("/login"); });

// ============= Dashboard — profile cards grid =============

app.get("/dashboard", requireAuth, async (req, res) => {
  try {
  const user = await getUser(req.session.userId);
  if (!user) { req.session.destroy(() => {}); return res.redirect("/login"); }

  const profiles = await getProfiles(user.id);

  // load channels for all profiles in one query
  let channelMap = {};
  if (profiles.length) {
    const ids = profiles.map(p => p.id);
    const allCh = await query(
      `SELECT * FROM sl_user_channels WHERE profile_id = ANY($1::text[])`,
      [ids]
    );
    for (const ch of allCh) {
      if (!channelMap[ch.profile_id]) channelMap[ch.profile_id] = {};
      channelMap[ch.profile_id][ch.platform] = ch;
    }
  }

  const profileCard = (p) => {
    const chs = channelMap[p.id] || {};
    const hasTT = !!chs.tiktok;
    const hasYT = !!chs.youtube;
    const initials = profileInitials(p.name);
    const color = avatarColor(p.name);
    return `
    <a href="/profiles/${p.id}" class="pcard" data-id="${p.id}">
      <div class="pcard-head">
        <div class="pcard-avatar" style="background:${color}">${initials}</div>
        <div class="pcard-name">${escHtml(p.name)}</div>
        <button class="pcard-menu" onclick="event.preventDefault();event.stopPropagation();deleteProfile('${p.id}','${escHtml(p.name)}')" title="Delete">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
        </button>
      </div>
      <div class="pcard-preview"></div>
      <div class="pcard-foot">
        <span class="pcard-ch ${hasTT ? "active" : ""}">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M19.59 6.69a4.83 4.83 0 0 1-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 0 1-2.88 2.5 2.89 2.89 0 0 1-2.89-2.89 2.89 2.89 0 0 1 2.89-2.89c.28 0 .54.04.79.1V9.01a6.33 6.33 0 0 0-.79-.05 6.34 6.34 0 0 0-6.34 6.34 6.34 6.34 0 0 0 6.34 6.34 6.34 6.34 0 0 0 6.33-6.34V8.69a8.18 8.18 0 0 0 4.78 1.52V6.77a4.85 4.85 0 0 1-1.01-.08z"/></svg>
          TikTok
        </span>
        <span class="pcard-ch ${hasYT ? "active" : ""}">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/></svg>
          YouTube
        </span>
      </div>
    </a>`;
  };

  const canCreate = profiles.length < 100;

  res.send(layout("Dashboard", `
  <div class="page-wrap">
  <div class="page-content">
    <div class="dash-header">
      <div>
        <h1 class="page-title">My Profiles</h1>
        <p class="page-sub">${profiles.length} of 100 profiles · Each profile has its own TikTok and YouTube channel</p>
      </div>
      ${canCreate ? `<button class="btn-primary" id="new-profile-btn" onclick="openNewProfile()">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/></svg>
        New Profile
      </button>` : `<span class="badge-disconnected">100 / 100 profiles</span>`}
    </div>

    <div class="pcards-grid" id="pcards-grid">
      ${profiles.map(profileCard).join("")}
      ${profiles.length === 0 ? `<div class="pcards-empty">
        <svg width="48" height="48" fill="none" stroke="rgba(255,255,255,.2)" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/></svg>
        <p>No profiles yet. Create your first one!</p>
      </div>` : ""}
    </div>
  </div>
  </div>

  <!-- Developer API hint -->
  <div class="page-wrap" style="border-top:1px solid var(--border);margin-top:0;padding-top:32px;padding-bottom:40px">
    <div class="page-content" style="max-width:900px">
      <div class="api-hint-box">
        <div class="api-hint-icon">
          <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>
        </div>
        <div class="api-hint-body">
          <div class="api-hint-title">Developer API</div>
          <div class="api-hint-desc">Publish videos to any profile programmatically — from bots, scripts, or automations. Supports TikTok via REST API with your personal API keys.</div>
        </div>
        <div class="api-hint-actions">
          <a href="/account/api-keys" class="btn-outline sm">API Keys</a>
          <a href="/docs" class="btn-outline sm">Docs</a>
        </div>
      </div>
    </div>
  </div>

  <!-- New Profile Modal -->
  <div class="modal-overlay" id="modal-overlay" style="display:none" onclick="closeModal()">
    <div class="modal" onclick="event.stopPropagation()">
      <h2 class="modal-title">New Profile</h2>
      <p class="modal-sub">Give your profile a name — it can be a brand, project, or channel idea.</p>
      <input type="text" id="profile-name-input" class="modal-input" placeholder="e.g. Travel Vlogs, Tech Reviews..." maxlength="60" autofocus>
      <div class="modal-actions">
        <button class="btn-outline" onclick="closeModal()">Cancel</button>
        <button class="btn-primary" onclick="createProfile()">Create Profile</button>
      </div>
    </div>
  </div>

  <script>
  function openNewProfile() {
    document.getElementById("modal-overlay").style.display = "flex";
    setTimeout(() => document.getElementById("profile-name-input").focus(), 50);
  }
  function closeModal() {
    document.getElementById("modal-overlay").style.display = "none";
    document.getElementById("profile-name-input").value = "";
  }
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });
  document.getElementById("profile-name-input")?.addEventListener("keydown", e => { if (e.key === "Enter") createProfile(); });

  function createProfile() {
    const name = document.getElementById("profile-name-input").value.trim();
    if (!name) return;
    document.getElementById("create-profile-name").value = name;
    document.getElementById("create-profile-form").submit();
  }

  function deleteProfile(id, name) {
    if (!confirm('Delete profile "' + name + '"? This will also disconnect any channels linked to it.')) return;
    const form = document.createElement("form");
    form.method = "POST";
    form.action = "/profiles/" + id + "/delete";
    document.body.appendChild(form);
    form.submit();
  }
  </script>
  <form id="create-profile-form" action="/profiles/create" method="POST" style="display:none">
    <input type="hidden" id="create-profile-name" name="name">
  </form>
  `, user));
  } catch (e) { console.error("[dashboard]", e.message); res.redirect("/login"); }
});

// Create profile (form POST — avoids /api/* routing conflict)
app.post("/profiles/create", requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) return res.redirect("/dashboard?error=name_required");
    const count = await query("SELECT COUNT(*) FROM sl_profiles WHERE user_id=$1", [req.session.userId]);
    if (parseInt(count[0].count) >= 100) return res.redirect("/dashboard?error=limit");
    const r = await query("INSERT INTO sl_profiles(user_id,name) VALUES($1,$2) RETURNING *", [req.session.userId, name.trim().slice(0, 60)]);
    res.redirect(`/profiles/${r[0].id}`);
  } catch (e) { console.error(e); res.redirect("/dashboard?error=create_failed"); }
});

// Delete profile (POST with _method override)
app.post("/profiles/:id/delete", requireAuth, async (req, res) => {
  try {
    const r = await query("SELECT id FROM sl_profiles WHERE id=$1 AND user_id=$2", [req.params.id, req.session.userId]);
    if (!r[0]) return res.redirect("/dashboard");
    await query("DELETE FROM sl_user_channels WHERE profile_id=$1", [req.params.id]);
    await query("DELETE FROM sl_profiles WHERE id=$1", [req.params.id]);
    res.redirect("/dashboard");
  } catch (e) { console.error(e); res.redirect("/dashboard?error=delete_failed"); }
});

// Profile detail page
app.get("/profiles/:id", requireAuth, async (req, res) => {
  try {
  const user = await getUser(req.session.userId);
  if (!user) { req.session.destroy(() => {}); return res.redirect("/login"); }

  const profiles = await query("SELECT * FROM sl_profiles WHERE id=$1 AND user_id=$2", [req.params.id, req.session.userId]);
  const profile = profiles[0];
  if (!profile) return res.redirect("/dashboard");

  const channels = await getProfileChannels(profile.id);
  const tiktok = channels.find(c => c.platform === "tiktok");
  const youtube = channels.find(c => c.platform === "youtube");
  // Only accept known values for flash params — never render raw query input in HTML
  const KNOWN_CONNECTED = new Set(["tiktok", "youtube"]);
  const KNOWN_ERRORS = new Set(["state", "tiktok_auth", "youtube_auth", "auth", "name_required", "limit", "create_failed"]);
  const connectedRaw = typeof req.query.connected === "string" ? req.query.connected : "";
  const errorRaw = typeof req.query.error === "string" ? req.query.error : "";
  const connected = KNOWN_CONNECTED.has(connectedRaw) ? connectedRaw : "";
  const error = KNOWN_ERRORS.has(errorRaw) ? errorRaw : (errorRaw ? "unknown_error" : "");

  const channelCard = (platform, ch) => {
    const isTT = platform === "tiktok";
    const label = isTT ? "TikTok" : "YouTube";
    const icon = isTT
      ? `<svg width="22" height="22" viewBox="0 0 24 24" fill="white"><path d="M19.59 6.69a4.83 4.83 0 0 1-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 0 1-2.88 2.5 2.89 2.89 0 0 1-2.89-2.89 2.89 2.89 0 0 1 2.89-2.89c.28 0 .54.04.79.1V9.01a6.33 6.33 0 0 0-.79-.05 6.34 6.34 0 0 0-6.34 6.34 6.34 6.34 0 0 0 6.34 6.34 6.34 6.34 0 0 0 6.33-6.34V8.69a8.18 8.18 0 0 0 4.78 1.52V6.77a4.85 4.85 0 0 1-1.01-.08z"/></svg>`
      : `<svg width="22" height="22" viewBox="0 0 24 24" fill="#FF0000"><path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/></svg>`;
    if (ch) {
      return `<div class="channel-card connected">
        <div class="channel-info">
          <div class="channel-icon ${isTT ? "tt-bg" : "yt-bg"}">${icon}</div>
          <div><div class="channel-label">${label}</div><div class="channel-account">@${escHtml(ch.account_name)}</div></div>
          <span class="badge-connected">Connected</span>
        </div>
        <div class="channel-actions">
          <a href="/profiles/${profile.id}/publish?platform=${platform}" class="btn-primary">Publish Video</a>
          <a href="/auth/disconnect/${platform}?profile_id=${profile.id}" class="btn-danger">Disconnect</a>
        </div>
      </div>`;
    }
    return `<div class="channel-card">
      <div class="channel-info">
        <div class="channel-icon ${isTT ? "tt-bg" : "yt-bg"}">${icon}</div>
        <div><div class="channel-label">${label}</div><div class="channel-account">Not connected</div></div>
        <span class="badge-disconnected">Not connected</span>
      </div>
      <a href="/auth/${platform}?profile_id=${profile.id}" class="btn-outline">Connect ${label}</a>
    </div>`;
  };

  const initials = profileInitials(profile.name);
  const color = avatarColor(profile.name);

  res.send(layout(profile.name, `
  <div class="page-wrap">
  <div class="page-content">
    ${connected === "tiktok" ? `<div class="alert alert-success">TikTok connected successfully!</div>` : connected === "youtube" ? `<div class="alert alert-success">YouTube connected successfully!</div>` : ""}
    ${error === "tiktok_auth" ? `<div class="alert alert-error">TikTok connection failed. Please try again.</div>` : error === "youtube_auth" ? `<div class="alert alert-error">YouTube connection failed. Please try again.</div>` : error === "state" ? `<div class="alert alert-error">Session expired. Please try again.</div>` : error ? `<div class="alert alert-error">Something went wrong. Please try again.</div>` : ""}

    <a href="/dashboard" class="back-link">← All Profiles</a>

    <div class="profile-hero">
      <div class="profile-avatar-lg" style="background:${color}">${initials}</div>
      <div>
        <h1 class="page-title">${escHtml(profile.name)}</h1>
        <p class="page-sub">Manage channels for this profile</p>
      </div>
    </div>

    <div class="channels-list">
      ${channelCard("tiktok", tiktok)}
      ${channelCard("youtube", youtube)}
    </div>

    ${(tiktok || youtube) ? `
    <div class="publish-cta">
      <div class="publish-cta-icon">
        <svg width="24" height="24" fill="none" stroke="#00E87A" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
      </div>
      <div>
        <h3>Ready to publish</h3>
        <p>Upload a video and post it to your connected channels.</p>
        <a href="/profiles/${profile.id}/publish" class="btn-primary">Upload &amp; Publish</a>
      </div>
    </div>` : ""}

    <div class="sandbox-info">
      <span class="dot yellow"></span>
      <p><strong>TikTok Sandbox Mode:</strong> Videos published will only be visible to your TikTok test account and won't appear publicly.</p>
    </div>
  </div>
  </div>
  `, user));
  } catch (e) { console.error("[profile]", e.message); res.redirect("/dashboard"); }
});

// Publish page for profile
app.get("/profiles/:id/publish", requireAuth, async (req, res) => {
  try {
  const user = await getUser(req.session.userId);
  const profiles = await query("SELECT * FROM sl_profiles WHERE id=$1 AND user_id=$2", [req.params.id, req.session.userId]);
  const profile = profiles[0];
  if (!profile) return res.redirect("/dashboard");

  const channels = await getProfileChannels(profile.id);
  const tiktok = channels.find(c => c.platform === "tiktok");
  const youtube = channels.find(c => c.platform === "youtube");
  const defaultPlatform = req.query.platform || (tiktok ? "tiktok" : "youtube");

  if (!tiktok && !youtube) return res.redirect(`/profiles/${profile.id}`);

  const opts = [
    tiktok ? `<option value="tiktok" ${defaultPlatform === "tiktok" ? "selected" : ""}>TikTok (@${escHtml(tiktok.account_name)})</option>` : "",
    youtube ? `<option value="youtube" ${defaultPlatform === "youtube" ? "selected" : ""}>YouTube (@${escHtml(youtube.account_name)})</option>` : "",
  ].join("");

  res.send(layout("Publish Video", `
  <div class="publish-wrap">
    <a href="/profiles/${profile.id}" class="back-link">← ${escHtml(profile.name)}</a>
    <h1 class="page-title">Publish Video</h1>
    <div id="result-box" style="display:none"></div>
    <form id="publish-form" enctype="multipart/form-data">
      <input type="hidden" name="profile_id" value="${profile.id}">
      <div class="form-group">
        <label>Platform</label>
        <select name="platform" id="platform-select">${opts}</select>
      </div>
      <div class="form-group">
        <label>Video title</label>
        <input type="text" name="title" placeholder="Enter video title..." maxlength="150">
      </div>
      <div class="form-group">
        <label>Video file</label>
        <div class="dropzone" id="dropzone" onclick="document.getElementById('video-input').click()">
          <input type="file" name="video" id="video-input" accept="video/*" style="display:none" onchange="showFile(this)">
          <div id="dz-content">
            <svg width="40" height="40" fill="none" stroke="#555" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
            <p>Drop video here or <span class="green">browse</span></p>
            <small>MP4, MOV, AVI — max 500MB</small>
          </div>
        </div>
      </div>
      <div id="progress-wrap" style="display:none">
        <div class="progress-label"><span>Uploading...</span><span id="progress-pct">0%</span></div>
        <div class="progress-bar"><div id="progress-fill"></div></div>
      </div>
      <button type="submit" class="btn-primary full" id="submit-btn">Publish Video</button>
      <p class="terms-note">By publishing you agree to <a href="https://www.tiktok.com/legal/page/global/terms-of-service/en" target="_blank">TikTok's Terms of Service</a></p>
    </form>
  </div>
  <script src="/publish.js"></script>
  `, user));
  } catch (e) { console.error("[publish-page]", e.message); res.redirect("/dashboard"); }
});

// API: publish (with profile_id)
app.post("/api/publish", requireAuth, upload.single("video"), async (req, res) => {
  try {
    const { platform, title, profile_id } = req.body;
    if (!req.file) return res.status(400).json({ error: "No video file" });

    let ch;
    if (profile_id) {
      const chs = await getProfileChannels(profile_id);
      ch = chs.find(c => c.platform === platform && c.user_id === req.session.userId) ||
           chs.find(c => c.platform === platform);
    } else {
      const channels = await query("SELECT * FROM sl_user_channels WHERE user_id=$1 AND platform=$2 AND profile_id IS NULL", [req.session.userId, platform]);
      ch = channels[0];
    }
    if (!ch) { fs.unlinkSync(req.file.path); return res.status(400).json({ error: `${platform} not connected` }); }

    if (platform === "tiktok") {
      const fileSize = req.file.size;
      const TARGET_CHUNK = 10 * 1024 * 1024;
      const chunkSize = fileSize <= TARGET_CHUNK ? fileSize : TARGET_CHUNK;
      const totalChunks = Math.ceil(fileSize / chunkSize);
      const safeTitle = (title || req.file.originalname || "My video").substring(0, 150);

      const initRes = await fetch("https://open.tiktokapis.com/v2/post/publish/video/init/", {
        method: "POST",
        headers: { Authorization: `Bearer ${ch.access_token}`, "Content-Type": "application/json; charset=UTF-8" },
        body: JSON.stringify({
          post_info: { title: safeTitle, privacy_level: "SELF_ONLY", disable_duet: false, disable_comment: false, disable_stitch: false, video_cover_timestamp_ms: 1000 },
          source_info: { source: "FILE_UPLOAD", video_size: fileSize, chunk_size: chunkSize, total_chunk_count: totalChunks },
        }),
      });
      const initData = await initRes.json();
      console.log("[tiktok-init] response:", JSON.stringify(initData));
      if (initData.error?.code !== "ok") {
        fs.unlinkSync(req.file.path);
        const errCode = initData.error?.code || "unknown";
        const errMsg = initData.error?.message || "TikTok init failed";
        let hint = "";
        if (errCode === "access_token_invalid" || errCode === "scope_not_authorized") {
          hint = " Try disconnecting and reconnecting your TikTok account to refresh the token.";
        }
        return res.status(400).json({ error: `[${errCode}] ${errMsg}${hint}`, raw: initData });
      }

      const { publish_id, upload_url } = initData.data;
      const fileBuffer = fs.readFileSync(req.file.path);
      let offset = 0;
      for (let i = 0; i < totalChunks; i++) {
        const chunk = fileBuffer.slice(offset, offset + chunkSize);
        const end = Math.min(offset + chunkSize - 1, fileSize - 1);
        const uploadRes = await fetch(upload_url, {
          method: "PUT",
          headers: { "Content-Type": "video/mp4", "Content-Range": `bytes ${offset}-${end}/${fileSize}`, "Content-Length": String(chunk.length) },
          body: chunk,
        });
        console.log(`[tiktok-chunk] ${i+1}/${totalChunks} status=${uploadRes.status}`);
        offset += chunkSize;
      }
      fs.unlinkSync(req.file.path);
      return res.json({ ok: true, publishId: publish_id, platform: "tiktok", message: "Video uploaded to TikTok for processing" });
    }

    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: "Unsupported platform" });
  } catch (e) {
    if (req.file?.path) try { fs.unlinkSync(req.file.path); } catch {}
    console.error("[publish]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// Static pages
app.get("/privacy", (req, res) => {
  res.send(layout("Privacy Policy", `
  <div class="page-wrap"><div class="page-content narrow text-page">
    <h1>Privacy Policy</h1>
    <p>Last updated: March 2026</p>
    <p>This Privacy Policy describes how Storyload ("we", "us", or "our") collects, uses, and protects information about users of the Storyload web application at <strong>storyload.ru</strong>.</p>
    <h2>1. Information We Collect</h2>
    <h3>1.1 Account Information</h3>
    <p>When you sign in with Google, we receive: your full name, email address, Google account ID, and profile photo URL.</p>
    <h3>1.2 Usage Data</h3>
    <p>We may collect non-personal technical data such as IP address, browser type, and session information for security purposes.</p>
    <h2>2. Using the TikTok API</h2>
    <p>We request: <code>user.info.basic</code>, <code>video.upload</code>, <code>video.publish</code>. We store your TikTok OAuth tokens, open_id, and display name solely to provide the publishing service.</p>
    <h2>3. Using the YouTube API</h2>
    <p>We store YouTube channel name, channel ID, and OAuth tokens. Used exclusively to upload videos at your explicit request. You can revoke access at <a href="https://security.google.com/settings/security/permissions" target="_blank">Google Security Settings</a>.</p>
    <h2>4. Data Storage and Security</h2>
    <p>All data is stored in a secure PostgreSQL database. We do not share, sell, or transfer your data to third parties.</p>
    <h2>5. Contact</h2>
    <p>Questions? <a href="mailto:privacy@storyload.ru">privacy@storyload.ru</a></p>
  </div></div>
  `));
});

app.get("/terms", (req, res) => {
  res.send(layout("Terms of Service", `
  <div class="page-wrap"><div class="page-content narrow text-page">
    <h1>Terms of Service</h1>
    <p>Last updated: March 2026</p>
    <p>These Terms govern your use of Storyload at <strong>storyload.ru</strong>.</p>
    <h2>1. Description of Service</h2>
    <p>Storyload is a video publishing platform connecting creators to TikTok and YouTube via official APIs. You can create profile cards (up to 100), connect channels per profile, and publish videos.</p>
    <h2>2. Account Registration</h2>
    <p>You must sign in with a valid Google account. You must be at least 13 years old.</p>
    <h2>3. Connecting Third-Party Platforms</h2>
    <p><strong>TikTok:</strong> You authorize Storyload to publish videos on your behalf. You must comply with <a href="https://www.tiktok.com/legal/page/global/terms-of-service/en" target="_blank">TikTok's Terms of Service</a>.</p>
    <p><strong>YouTube:</strong> You must comply with <a href="https://www.youtube.com/t/terms" target="_blank">YouTube's Terms of Service</a>. Revoke access via <a href="https://security.google.com/settings/security/permissions" target="_blank">Google Account permissions</a>.</p>
    <h2>4. TikTok Sandbox Mode</h2>
    <p>During development, Storyload operates in TikTok's Sandbox. Published videos are visible only to authorized test accounts.</p>
    <h2>5. Limitation of Liability</h2>
    <p>The Service is provided "as is". Storyload is not liable for indirect or consequential damages.</p>
    <h2>6. Contact</h2>
    <p><a href="mailto:support@storyload.ru">support@storyload.ru</a></p>
  </div></div>
  `));
});

app.get("/about", (req, res) => {
  res.send(layout("About Storyload", `
  <div class="page-wrap"><div class="page-content narrow text-page">
    <h1>About Storyload</h1>
    <p>Storyload is a video publishing platform built for content creators, agencies, and social media managers who need to publish videos to multiple accounts efficiently.</p>

    <h2>What is Storyload?</h2>
    <p>Storyload is a legitimate web service that allows you to manage multiple TikTok and YouTube accounts from a single dashboard. We use only official APIs provided by TikTok and Google — we never ask for your social media passwords.</p>

    <h2>How it works</h2>
    <ul class="legal-list">
      <li><strong>Sign in with your Google account</strong> — we use Google OAuth 2.0, the same secure login used by millions of apps</li>
      <li><strong>Create profile cards</strong> — each profile represents a separate brand, channel, or project (up to 100 profiles)</li>
      <li><strong>Connect your channels</strong> — authorize TikTok and YouTube access using their official OAuth flows</li>
      <li><strong>Upload and publish</strong> — upload a video file and publish it to connected channels with one click</li>
    </ul>

    <h2>Why we ask for Google login</h2>
    <p>We use Google Sign-In (<code>accounts.google.com</code>) only to create and authenticate your Storyload account. We do not request access to your Gmail, Google Drive, or any other Google services unless you explicitly connect a YouTube channel.</p>

    <h2>Our use of TikTok API</h2>
    <p>We use the official <strong>TikTok Content Posting API</strong>. When you click "Connect TikTok", you are redirected to TikTok's own authorization page at <code>open.tiktokapis.com</code>. We request only three scopes:</p>
    <ul class="legal-list">
      <li><code>user.info.basic</code> — to display your TikTok username and avatar</li>
      <li><code>video.upload</code> — to upload video files to TikTok</li>
      <li><code>video.publish</code> — to publish the uploaded video to your profile</li>
    </ul>
    <p>We never store your TikTok password. Access can be revoked at any time from your TikTok account settings.</p>

    <h2>Our use of YouTube API</h2>
    <p>We use <strong>YouTube Data API v3</strong> provided by Google. When you connect a YouTube channel, you authorize us via Google's secure OAuth 2.0 flow. We only request permission to upload videos on your behalf. You can revoke access at <a href="https://security.google.com/settings/security/permissions" target="_blank" rel="noopener noreferrer">Google Account permissions</a>.</p>

    <h2>Data we store</h2>
    <ul class="legal-list">
      <li>Your name and email (from Google login)</li>
      <li>Your profile cards and their names</li>
      <li>OAuth access tokens for connected TikTok and YouTube channels (encrypted in our database)</li>
    </ul>
    <p>We do not sell, share, or transfer your data to third parties. Full details are in our <a href="/privacy">Privacy Policy</a>.</p>

    <h2>Contact</h2>
    <p>Questions or concerns? Email us: <a href="mailto:support@storyload.ru">support@storyload.ru</a></p>
    <p>Storyload is operated by an independent developer. This is not affiliated with TikTok, YouTube, or Google.</p>
  </div></div>
  `));
});

app.get("/terms", (req, res) => {
  res.send(layout("Terms of Service — Storyload", `
  <div class="page-wrap"><div class="page-content narrow text-page">
    <h1>Terms of Service</h1>
    <p><em>Last updated: March 30, 2026</em></p>
    <p>By using Storyload ("the Service", available at storyload.ru), you agree to these Terms of Service. Please read them carefully.</p>

    <h2>1. Description of Service</h2>
    <p>Storyload is a video publishing platform that lets you upload and publish videos to TikTok and YouTube via their official APIs. The Service is provided as-is for content creators, social media managers, and developers.</p>

    <h2>2. Account Registration</h2>
    <p>You must sign in using a Google account to use Storyload. You are responsible for maintaining the security of your account and all activity under it. You must be at least 13 years old to use this Service.</p>

    <h2>3. Acceptable Use</h2>
    <p>You agree to use Storyload only for lawful purposes. You must not use the Service to:</p>
    <ul class="legal-list">
      <li>Publish content that violates TikTok's or YouTube's Terms of Service</li>
      <li>Upload content that is illegal, harmful, or infringes on third-party rights</li>
      <li>Attempt to reverse-engineer, abuse, or overload the Service</li>
      <li>Use the Service to spam, harass, or deceive other users</li>
    </ul>

    <h2>4. Third-Party Services</h2>
    <p>Storyload integrates with TikTok and YouTube using their official APIs. Your use of those platforms is governed by their own terms:</p>
    <ul class="legal-list">
      <li><a href="https://www.tiktok.com/legal/terms-of-service" target="_blank" rel="noopener noreferrer">TikTok Terms of Service</a></li>
      <li><a href="https://www.youtube.com/t/terms" target="_blank" rel="noopener noreferrer">YouTube Terms of Service</a></li>
      <li><a href="https://policies.google.com/terms" target="_blank" rel="noopener noreferrer">Google Terms of Service</a></li>
    </ul>
    <p>Storyload is not affiliated with, endorsed by, or sponsored by TikTok, YouTube, or Google.</p>

    <h2>5. API Keys</h2>
    <p>If you generate Storyload API keys, you are responsible for keeping them confidential. Do not share API keys in public repositories or with untrusted parties. We reserve the right to revoke keys that are used abusively.</p>

    <h2>6. Data and Privacy</h2>
    <p>We collect and process your data as described in our <a href="/privacy">Privacy Policy</a>. We do not sell your data to third parties.</p>

    <h2>7. Disclaimer of Warranties</h2>
    <p>The Service is provided "as is" without warranties of any kind. We do not guarantee uninterrupted access, and we are not liable for any loss resulting from service downtime, API changes by TikTok or YouTube, or other events outside our control.</p>

    <h2>8. Limitation of Liability</h2>
    <p>To the maximum extent permitted by law, Storyload and its operators shall not be liable for any indirect, incidental, or consequential damages arising from your use of the Service.</p>

    <h2>9. Changes to Terms</h2>
    <p>We may update these Terms from time to time. Continued use of the Service after changes constitutes acceptance of the new Terms.</p>

    <h2>10. Contact</h2>
    <p>Questions about these Terms: <a href="mailto:support@storyload.ru">support@storyload.ru</a></p>
  </div></div>
  `));
});

// ============= API KEY MANAGEMENT (dashboard section) =============

app.get("/account/api-keys", requireAuth, async (req, res) => {
  try {
    const user = await getUser(req.session.userId);
    if (!user) { req.session.destroy(() => {}); return res.redirect("/login"); }
    const keys = await query("SELECT id, name, key_prefix, created_at, last_used_at FROM sl_api_keys WHERE user_id=$1 ORDER BY created_at DESC", [req.session.userId]);
    const newKey = req.query.new_key || "";
    const error = req.query.error || "";

    const keyRows = keys.map(k => `
      <div class="apikey-row">
        <div class="apikey-info">
          <div class="apikey-name">${escHtml(k.name)}</div>
          <div class="apikey-meta">
            <code class="apikey-prefix">sl_live_${k.key_prefix}••••••••••••••••</code>
            <span class="apikey-date">Created ${new Date(k.created_at).toLocaleDateString("ru-RU")}</span>
            ${k.last_used_at ? `<span class="apikey-date">· Last used ${new Date(k.last_used_at).toLocaleDateString("ru-RU")}</span>` : `<span class="apikey-date">· Never used</span>`}
          </div>
        </div>
        <form method="POST" action="/account/api-keys/${k.id}/delete" style="display:inline" onsubmit="return confirm('Revoke this API key?')">
          <button class="btn-danger sm" type="submit">Revoke</button>
        </form>
      </div>
    `).join("");

    res.send(layout("API Keys", `
    <div class="page-wrap"><div class="page-content">
      <a href="/dashboard" class="back-link">← Dashboard</a>
      <h1 class="page-title">API Keys</h1>
      <p class="page-sub">Use API keys to publish videos programmatically. <a href="/docs">View API documentation →</a></p>

      ${newKey ? `<div class="alert alert-success apikey-new-box">
        <strong>API key created. Copy it now — it won't be shown again:</strong>
        <div class="apikey-reveal-wrap">
          <code class="apikey-reveal" id="new-key-code">${escHtml(newKey)}</code>
          <button class="btn-outline sm" onclick="navigator.clipboard.writeText('${escHtml(newKey)}');this.textContent='Copied!'">Copy</button>
        </div>
      </div>` : ""}
      ${error ? `<div class="alert alert-error">${escHtml(error)}</div>` : ""}

      <form action="/account/api-keys/create" method="POST" class="apikey-create-form">
        <input type="text" name="name" placeholder="Key name, e.g. Production, My Bot..." maxlength="60" required class="modal-input" style="max-width:320px;margin-bottom:0">
        <button class="btn-primary" type="submit">Generate Key</button>
      </form>

      <div class="apikeys-list">
        ${keys.length ? keyRows : `<div class="pcards-empty" style="padding:40px 0"><p>No API keys yet. Generate your first one above.</p></div>`}
      </div>

      <div class="docs-hint">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
        API keys grant full access to publish videos to your profiles. Keep them secret and never share them in public code.
        <a href="/docs">Read the API documentation →</a>
      </div>
    </div></div>
    `, user));
  } catch (e) { console.error("[api-keys]", e.message); res.redirect("/dashboard"); }
});

app.post("/account/api-keys/create", requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) return res.redirect("/account/api-keys?error=Name+required");
    const count = await query("SELECT COUNT(*) FROM sl_api_keys WHERE user_id=$1", [req.session.userId]);
    if (parseInt(count[0].count) >= 10) return res.redirect("/account/api-keys?error=Max+10+API+keys");
    const rawKey = "sl_live_" + crypto.randomBytes(24).toString("hex");
    const hash = crypto.createHash("sha256").update(rawKey).digest("hex");
    const prefix = rawKey.slice(8, 16); // 8 chars after "sl_live_"
    await query("INSERT INTO sl_api_keys(user_id,name,key_prefix,key_hash) VALUES($1,$2,$3,$4)", [req.session.userId, name.trim(), prefix, hash]);
    res.redirect(`/account/api-keys?new_key=${encodeURIComponent(rawKey)}`);
  } catch (e) { console.error("[create-key]", e.message); res.redirect("/account/api-keys?error=Create+failed"); }
});

app.post("/account/api-keys/:id/delete", requireAuth, async (req, res) => {
  try {
    await query("DELETE FROM sl_api_keys WHERE id=$1 AND user_id=$2", [req.params.id, req.session.userId]);
    res.redirect("/account/api-keys");
  } catch (e) { res.redirect("/account/api-keys"); }
});

// ============= EXTERNAL REST API v1 =============

// GET /v1/profiles — list all profiles with channel status
app.get("/v1/profiles", requireApiKey, async (req, res) => {
  try {
    const profiles = await query("SELECT * FROM sl_profiles WHERE user_id=$1 ORDER BY created_at", [req.apiUserId]);
    const result = [];
    for (const p of profiles) {
      const chs = await query("SELECT platform, account_name, account_id, created_at FROM sl_user_channels WHERE profile_id=$1", [p.id]);
      result.push({
        id: p.id,
        name: p.name,
        created_at: p.created_at,
        channels: chs.map(c => ({ platform: c.platform, account_name: c.account_name, account_id: c.account_id, connected_at: c.created_at })),
      });
    }
    res.json({ profiles: result, total: result.length });
  } catch (e) { res.status(500).json({ error: "server_error", message: e.message }); }
});

// GET /v1/profiles/:id — single profile
app.get("/v1/profiles/:id", requireApiKey, async (req, res) => {
  try {
    const rows = await query("SELECT * FROM sl_profiles WHERE id=$1 AND user_id=$2", [req.params.id, req.apiUserId]);
    if (!rows[0]) return res.status(404).json({ error: "not_found", message: "Profile not found" });
    const p = rows[0];
    const chs = await query("SELECT platform, account_name, account_id, created_at FROM sl_user_channels WHERE profile_id=$1", [p.id]);
    res.json({ id: p.id, name: p.name, created_at: p.created_at, channels: chs.map(c => ({ platform: c.platform, account_name: c.account_name, account_id: c.account_id, connected_at: c.created_at })) });
  } catch (e) { res.status(500).json({ error: "server_error", message: e.message }); }
});

// POST /v1/profiles/:id/publish — publish video to a profile channel
app.post("/v1/profiles/:id/publish", requireApiKey, upload.single("video"), async (req, res) => {
  try {
    const { platform, title } = req.body;
    if (!platform) { if (req.file) fs.unlinkSync(req.file.path); return res.status(400).json({ error: "bad_request", message: "platform is required (tiktok or youtube)" }); }
    if (!req.file) return res.status(400).json({ error: "bad_request", message: "video file is required (multipart/form-data field: video)" });

    const rows = await query("SELECT * FROM sl_profiles WHERE id=$1 AND user_id=$2", [req.params.id, req.apiUserId]);
    if (!rows[0]) { fs.unlinkSync(req.file.path); return res.status(404).json({ error: "not_found", message: "Profile not found" }); }

    const chs = await query("SELECT * FROM sl_user_channels WHERE profile_id=$1 AND platform=$2", [req.params.id, platform]);
    const ch = chs[0];
    if (!ch) { fs.unlinkSync(req.file.path); return res.status(400).json({ error: "channel_not_connected", message: `${platform} channel is not connected to this profile` }); }

    if (platform === "tiktok") {
      const fileSize = req.file.size;
      const TARGET_CHUNK = 10 * 1024 * 1024;
      const chunkSize = fileSize <= TARGET_CHUNK ? fileSize : TARGET_CHUNK;
      const totalChunks = Math.ceil(fileSize / chunkSize);
      const safeTitle = (title || req.file.originalname || "My video").substring(0, 150);

      const initRes = await fetch("https://open.tiktokapis.com/v2/post/publish/video/init/", {
        method: "POST",
        headers: { Authorization: `Bearer ${ch.access_token}`, "Content-Type": "application/json; charset=UTF-8" },
        body: JSON.stringify({ post_info: { title: safeTitle, privacy_level: "SELF_ONLY", disable_duet: false, disable_comment: false, disable_stitch: false, video_cover_timestamp_ms: 1000 }, source_info: { source: "FILE_UPLOAD", video_size: fileSize, chunk_size: chunkSize, total_chunk_count: totalChunks } }),
      });
      const initData = await initRes.json();
      if (initData.error?.code !== "ok") { fs.unlinkSync(req.file.path); return res.status(400).json({ error: "tiktok_error", message: initData.error?.message || "TikTok init failed", raw: initData }); }

      const { publish_id, upload_url } = initData.data;
      const fileBuffer = fs.readFileSync(req.file.path);
      let offset = 0;
      for (let i = 0; i < totalChunks; i++) {
        const chunk = fileBuffer.slice(offset, offset + chunkSize);
        const end = Math.min(offset + chunkSize - 1, fileSize - 1);
        await fetch(upload_url, { method: "PUT", headers: { "Content-Type": "video/mp4", "Content-Range": `bytes ${offset}-${end}/${fileSize}`, "Content-Length": String(chunk.length) }, body: chunk });
        offset += chunkSize;
      }
      fs.unlinkSync(req.file.path);
      return res.json({ ok: true, publish_id, platform: "tiktok", message: "Video submitted to TikTok for processing" });
    }

    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: "unsupported_platform", message: `${platform} publishing via API is not yet supported` });
  } catch (e) {
    if (req.file?.path) try { fs.unlinkSync(req.file.path); } catch {}
    console.error("[v1/publish]", e.message);
    res.status(500).json({ error: "server_error", message: e.message });
  }
});

// ============= DOCUMENTATION PAGE =============

app.get("/docs", (req, res) => {
  const baseUrl = APP_URL || "https://storyload.ru";
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>API Documentation — Storyload</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/style.css">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
.docs-layout { display: flex; min-height: 100vh; padding-top: 64px; }
.docs-sidebar { width: 240px; flex-shrink: 0; position: sticky; top: 64px; height: calc(100vh - 64px); overflow-y: auto; border-right: 1px solid var(--border); padding: 32px 0; }
.docs-sidebar-inner { padding: 0 20px; }
.docs-nav-section { font-size: 11px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); margin: 24px 0 8px; }
.docs-nav-section:first-child { margin-top: 0; }
.docs-nav-link { display: block; font-size: 13.5px; color: var(--sub); padding: 5px 8px; border-radius: 6px; margin: 1px 0; transition: color .1s, background .1s; }
.docs-nav-link:hover, .docs-nav-link.active { color: #fff; background: rgba(255,255,255,.06); opacity: 1; }
.docs-nav-link.active { color: var(--green); }
.docs-content { flex: 1; min-width: 0; padding: 48px 64px 120px; max-width: 860px; }
.docs-section { margin-bottom: 72px; padding-top: 8px; }
.docs-h1 { font-size: 32px; font-weight: 800; letter-spacing: -1px; margin-bottom: 12px; }
.docs-h2 { font-size: 22px; font-weight: 700; letter-spacing: -.5px; margin-bottom: 12px; margin-top: 0; border-top: 1px solid var(--border); padding-top: 48px; }
.docs-h3 { font-size: 15px; font-weight: 600; margin: 24px 0 8px; color: #fff; }
.docs-p { color: var(--sub); font-size: 15px; line-height: 1.75; margin-bottom: 16px; }
.docs-p a { color: var(--green); }
.docs-badge { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; background: var(--green-dim); color: var(--green); border: 1px solid var(--green-border); border-radius: 99px; padding: 3px 10px; margin-bottom: 20px; }
.endpoint { background: var(--card); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; margin-bottom: 24px; }
.endpoint-head { display: flex; align-items: center; gap: 12px; padding: 16px 20px; border-bottom: 1px solid var(--border); }
.method { font-size: 12px; font-weight: 700; padding: 3px 10px; border-radius: 6px; letter-spacing: .04em; font-family: 'JetBrains Mono', monospace; }
.method.get { background: rgba(59,130,246,.15); color: #60a5fa; }
.method.post { background: rgba(52,213,154,.12); color: var(--green); }
.endpoint-path { font-family: 'JetBrains Mono', monospace; font-size: 14px; color: #fff; }
.endpoint-desc { color: var(--muted); font-size: 13px; margin-left: auto; }
.endpoint-body { padding: 20px; }
.param-table { width: 100%; border-collapse: collapse; margin-bottom: 0; }
.param-table th { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); padding: 0 12px 10px 0; text-align: left; }
.param-table td { font-size: 13.5px; padding: 8px 12px 8px 0; vertical-align: top; border-top: 1px solid var(--border); color: var(--sub); }
.param-table td:first-child { font-family: 'JetBrains Mono', monospace; color: #fff; white-space: nowrap; }
.param-table td .req { color: var(--red); font-size: 10px; margin-left: 4px; }
.param-table td .opt { color: var(--muted); font-size: 10px; margin-left: 4px; }
.code-block { background: #0d0d0d; border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin: 16px 0; }
.code-block-head { display: flex; align-items: center; justify-content: space-between; padding: 10px 16px; border-bottom: 1px solid var(--border); }
.code-lang { font-size: 12px; font-weight: 500; color: var(--muted); font-family: 'JetBrains Mono', monospace; }
.copy-btn { font-size: 11px; color: var(--muted); background: none; border: none; cursor: pointer; padding: 2px 8px; border-radius: 4px; transition: color .15s; font-family: inherit; }
.copy-btn:hover { color: #fff; }
.code-block pre { margin: 0; padding: 16px 20px; overflow-x: auto; font-family: 'JetBrains Mono', monospace; font-size: 13px; line-height: 1.65; color: #e2e8f0; }
.hl-key { color: #60a5fa; }
.hl-str { color: #a7ddff; }
.hl-num { color: #34D59A; }
.hl-method { color: #f59e0b; }
.hl-comment { color: rgba(255,255,255,.3); }
.hl-keyword { color: #c084fc; }
.docs-alert { display: flex; gap: 12px; background: rgba(167,221,255,.06); border: 1px solid rgba(167,221,255,.15); border-radius: 10px; padding: 14px 16px; margin: 20px 0; font-size: 14px; color: var(--sub); }
.docs-alert svg { flex-shrink: 0; margin-top: 1px; }
.resp-block { background: rgba(52,213,154,.04); border: 1px solid var(--green-border); border-radius: 10px; overflow: hidden; margin: 12px 0; }
.resp-block pre { margin: 0; padding: 16px 20px; font-family: 'JetBrains Mono', monospace; font-size: 12.5px; line-height: 1.65; color: #e2e8f0; overflow-x: auto; }
.error-table td:first-child { color: #f87171; }
@media (max-width: 768px) {
  .docs-sidebar { display: none; }
  .docs-content { padding: 32px 24px 80px; }
}
</style>
</head>
<body>
<header class="header">
  <div class="header-inner">
    <a href="/" class="logo-link">
      ${LOGO_SVG}
    </a>
    <nav class="header-nav">
      <a href="/dashboard">Dashboard</a>
      <a href="/account/api-keys">API Keys</a>
      <a href="/docs" style="color:#fff">Docs</a>
    </nav>
  </div>
</header>

<div class="docs-layout">
  <aside class="docs-sidebar">
    <div class="docs-sidebar-inner">
      <div class="docs-nav-section">Getting Started</div>
      <a href="#overview" class="docs-nav-link">Overview</a>
      <a href="#auth" class="docs-nav-link">Authentication</a>
      <a href="#errors" class="docs-nav-link">Errors</a>
      <div class="docs-nav-section">Endpoints</div>
      <a href="#list-profiles" class="docs-nav-link">List profiles</a>
      <a href="#get-profile" class="docs-nav-link">Get profile</a>
      <a href="#publish" class="docs-nav-link">Publish video</a>
      <div class="docs-nav-section">Examples</div>
      <a href="#ex-curl" class="docs-nav-link">cURL</a>
      <a href="#ex-js" class="docs-nav-link">JavaScript</a>
      <a href="#ex-python" class="docs-nav-link">Python</a>
    </div>
  </aside>

  <main class="docs-content">

    <!-- OVERVIEW -->
    <div class="docs-section" id="overview">
      <div class="docs-badge"><span class="dot"></span> REST API v1</div>
      <h1 class="docs-h1">Storyload API</h1>
      <p class="docs-p">The Storyload API lets you publish videos to TikTok and YouTube programmatically — from your own code, bots, or automations. No manual uploads, no browser required.</p>
      <p class="docs-p"><strong>Base URL:</strong></p>
      <div class="code-block"><div class="code-block-head"><span class="code-lang">base url</span></div><pre>${escHtml(baseUrl)}/v1</pre></div>
      <p class="docs-p">All requests and responses use JSON. Video uploads use <code>multipart/form-data</code>.</p>
    </div>

    <!-- AUTH -->
    <div class="docs-section" id="auth">
      <h2 class="docs-h2">Authentication</h2>
      <p class="docs-p">Every API request must include your API key in the <code>Authorization</code> header as a Bearer token. Generate your keys on the <a href="/account/api-keys">API Keys page</a>.</p>
      <div class="code-block">
        <div class="code-block-head"><span class="code-lang">header</span><button class="copy-btn" onclick="copyCode(this)">Copy</button></div>
        <pre>Authorization: Bearer sl_live_<span class="hl-str">your_api_key_here</span></pre>
      </div>
      <div class="docs-alert">
        <svg width="16" height="16" fill="none" stroke="#A7DDFF" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
        Keep your API key secret. Never include it in client-side JavaScript or public repositories. If a key is compromised, revoke it immediately on the API Keys page.
      </div>
    </div>

    <!-- ERRORS -->
    <div class="docs-section" id="errors">
      <h2 class="docs-h2">Errors</h2>
      <p class="docs-p">The API uses standard HTTP status codes. All error responses return a JSON object with an <code>error</code> code and a <code>message</code> field.</p>
      <div class="code-block">
        <div class="code-block-head"><span class="code-lang">error response</span></div>
        <pre>{
  <span class="hl-key">"error"</span>: <span class="hl-str">"channel_not_connected"</span>,
  <span class="hl-key">"message"</span>: <span class="hl-str">"tiktok channel is not connected to this profile"</span>
}</pre>
      </div>
      <table class="param-table" style="margin-top:16px">
        <thead><tr><th>Status</th><th>Error code</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td>401</td><td>unauthorized</td><td>Missing or invalid API key</td></tr>
          <tr><td>400</td><td>bad_request</td><td>Missing required fields</td></tr>
          <tr><td>404</td><td>not_found</td><td>Profile not found or doesn't belong to you</td></tr>
          <tr><td>400</td><td>channel_not_connected</td><td>The requested platform is not connected to this profile</td></tr>
          <tr><td>400</td><td>tiktok_error</td><td>TikTok API rejected the upload</td></tr>
          <tr><td>500</td><td>server_error</td><td>Internal server error</td></tr>
        </tbody>
      </table>
    </div>

    <!-- LIST PROFILES -->
    <div class="docs-section" id="list-profiles">
      <h2 class="docs-h2">List profiles</h2>
      <p class="docs-p">Returns all profiles in your account, including connected channels for each.</p>
      <div class="endpoint">
        <div class="endpoint-head">
          <span class="method get">GET</span>
          <span class="endpoint-path">/v1/profiles</span>
          <span class="endpoint-desc">No request body</span>
        </div>
        <div class="endpoint-body">
          <div class="docs-h3">Response</div>
          <div class="resp-block"><pre>{
  <span class="hl-key">"profiles"</span>: [
    {
      <span class="hl-key">"id"</span>: <span class="hl-str">"abc123"</span>,
      <span class="hl-key">"name"</span>: <span class="hl-str">"Travel Vlogs"</span>,
      <span class="hl-key">"created_at"</span>: <span class="hl-str">"2026-03-01T12:00:00.000Z"</span>,
      <span class="hl-key">"channels"</span>: [
        {
          <span class="hl-key">"platform"</span>: <span class="hl-str">"tiktok"</span>,
          <span class="hl-key">"account_name"</span>: <span class="hl-str">"my_travel_acc"</span>,
          <span class="hl-key">"account_id"</span>: <span class="hl-str">"tt_open_id_xxx"</span>,
          <span class="hl-key">"connected_at"</span>: <span class="hl-str">"2026-03-02T10:00:00.000Z"</span>
        }
      ]
    }
  ],
  <span class="hl-key">"total"</span>: <span class="hl-num">1</span>
}</pre></div>
        </div>
      </div>
    </div>

    <!-- GET PROFILE -->
    <div class="docs-section" id="get-profile">
      <h2 class="docs-h2">Get profile</h2>
      <p class="docs-p">Returns a single profile by ID with its connected channels.</p>
      <div class="endpoint">
        <div class="endpoint-head">
          <span class="method get">GET</span>
          <span class="endpoint-path">/v1/profiles/:id</span>
        </div>
        <div class="endpoint-body">
          <div class="docs-h3">Path parameters</div>
          <table class="param-table"><thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
          <tbody><tr><td>id<span class="req">required</span></td><td>string</td><td>Profile ID (from List profiles)</td></tr></tbody></table>
        </div>
      </div>
    </div>

    <!-- PUBLISH -->
    <div class="docs-section" id="publish">
      <h2 class="docs-h2">Publish video</h2>
      <p class="docs-p">Upload and publish a video to a TikTok or YouTube channel connected to a profile. The request must be <code>multipart/form-data</code>.</p>
      <div class="endpoint">
        <div class="endpoint-head">
          <span class="method post">POST</span>
          <span class="endpoint-path">/v1/profiles/:id/publish</span>
        </div>
        <div class="endpoint-body">
          <div class="docs-h3">Path parameters</div>
          <table class="param-table"><thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
          <tbody><tr><td>id<span class="req">required</span></td><td>string</td><td>Profile ID</td></tr></tbody></table>

          <div class="docs-h3" style="margin-top:20px">Body (multipart/form-data)</div>
          <table class="param-table"><thead><tr><th>Field</th><th>Type</th><th>Description</th></tr></thead>
          <tbody>
            <tr><td>video<span class="req">required</span></td><td>file</td><td>Video file to publish. MP4, MOV, AVI. Max 500 MB.</td></tr>
            <tr><td>platform<span class="req">required</span></td><td>string</td><td><code>tiktok</code> or <code>youtube</code></td></tr>
            <tr><td>title<span class="opt">optional</span></td><td>string</td><td>Video title. Max 150 characters. Default: file name.</td></tr>
          </tbody></table>

          <div class="docs-h3" style="margin-top:20px">Response</div>
          <div class="resp-block"><pre>{
  <span class="hl-key">"ok"</span>: <span class="hl-num">true</span>,
  <span class="hl-key">"publish_id"</span>: <span class="hl-str">"v_pub_xxxxxxxxxxxx"</span>,
  <span class="hl-key">"platform"</span>: <span class="hl-str">"tiktok"</span>,
  <span class="hl-key">"message"</span>: <span class="hl-str">"Video submitted to TikTok for processing"</span>
}</pre></div>
          <div class="docs-alert">
            <svg width="16" height="16" fill="none" stroke="#A7DDFF" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
            Storyload is currently in <strong>TikTok Sandbox mode</strong>. Published videos are visible only to your TikTok test account and won't appear publicly until production API access is approved.
          </div>
        </div>
      </div>
    </div>

    <!-- EXAMPLES: cURL -->
    <div class="docs-section" id="ex-curl">
      <h2 class="docs-h2">cURL examples</h2>
      <div class="docs-h3">List profiles</div>
      <div class="code-block">
        <div class="code-block-head"><span class="code-lang">bash</span><button class="copy-btn" onclick="copyCode(this)">Copy</button></div>
        <pre>curl ${escHtml(baseUrl)}/v1/profiles \\
  -H <span class="hl-str">"Authorization: Bearer sl_live_your_key"</span></pre>
      </div>

      <div class="docs-h3">Publish a video to TikTok</div>
      <div class="code-block">
        <div class="code-block-head"><span class="code-lang">bash</span><button class="copy-btn" onclick="copyCode(this)">Copy</button></div>
        <pre>curl -X POST ${escHtml(baseUrl)}/v1/profiles/<span class="hl-str">PROFILE_ID</span>/publish \\
  -H <span class="hl-str">"Authorization: Bearer sl_live_your_key"</span> \\
  -F <span class="hl-str">"platform=tiktok"</span> \\
  -F <span class="hl-str">"title=My awesome video"</span> \\
  -F <span class="hl-str">"video=@/path/to/video.mp4"</span></pre>
      </div>
    </div>

    <!-- EXAMPLES: JS -->
    <div class="docs-section" id="ex-js">
      <h2 class="docs-h2">JavaScript example</h2>
      <div class="code-block">
        <div class="code-block-head"><span class="code-lang">javascript (Node.js)</span><button class="copy-btn" onclick="copyCode(this)">Copy</button></div>
        <pre><span class="hl-keyword">import</span> fs <span class="hl-keyword">from</span> <span class="hl-str">"fs"</span>;
<span class="hl-keyword">import</span> FormData <span class="hl-keyword">from</span> <span class="hl-str">"form-data"</span>;

<span class="hl-keyword">const</span> API_KEY = <span class="hl-str">"sl_live_your_key"</span>;
<span class="hl-keyword">const</span> BASE = <span class="hl-str">"${escHtml(baseUrl)}/v1"</span>;

<span class="hl-comment">// 1. Get your profiles</span>
<span class="hl-keyword">const</span> profiles = <span class="hl-keyword">await</span> fetch(<span class="hl-str">\`\${BASE}/profiles\`</span>, {
  headers: { <span class="hl-key">Authorization</span>: <span class="hl-str">\`Bearer \${API_KEY}\`</span> }
}).then(r => r.json());

<span class="hl-keyword">const</span> profileId = profiles.profiles[<span class="hl-num">0</span>].id;

<span class="hl-comment">// 2. Publish a video</span>
<span class="hl-keyword">const</span> form = <span class="hl-keyword">new</span> FormData();
form.append(<span class="hl-str">"platform"</span>, <span class="hl-str">"tiktok"</span>);
form.append(<span class="hl-str">"title"</span>, <span class="hl-str">"My video title"</span>);
form.append(<span class="hl-str">"video"</span>, fs.createReadStream(<span class="hl-str">"./video.mp4"</span>));

<span class="hl-keyword">const</span> result = <span class="hl-keyword">await</span> fetch(<span class="hl-str">\`\${BASE}/profiles/\${profileId}/publish\`</span>, {
  method: <span class="hl-str">"POST"</span>,
  headers: { <span class="hl-key">Authorization</span>: <span class="hl-str">\`Bearer \${API_KEY}\`</span>, ...form.getHeaders() },
  body: form,
}).then(r => r.json());

console.log(result); <span class="hl-comment">// { ok: true, publish_id: "...", platform: "tiktok" }</span></pre>
      </div>
    </div>

    <!-- EXAMPLES: Python -->
    <div class="docs-section" id="ex-python">
      <h2 class="docs-h2">Python example</h2>
      <div class="code-block">
        <div class="code-block-head"><span class="code-lang">python</span><button class="copy-btn" onclick="copyCode(this)">Copy</button></div>
        <pre><span class="hl-keyword">import</span> requests

API_KEY = <span class="hl-str">"sl_live_your_key"</span>
BASE = <span class="hl-str">"${escHtml(baseUrl)}/v1"</span>
HEADERS = {<span class="hl-str">"Authorization"</span>: <span class="hl-str">f"Bearer {API_KEY}"</span>}

<span class="hl-comment"># 1. List profiles</span>
profiles = requests.get(<span class="hl-str">f"{BASE}/profiles"</span>, headers=HEADERS).json()
profile_id = profiles[<span class="hl-str">"profiles"</span>][<span class="hl-num">0</span>][<span class="hl-str">"id"</span>]

<span class="hl-comment"># 2. Publish a video</span>
<span class="hl-keyword">with</span> open(<span class="hl-str">"video.mp4"</span>, <span class="hl-str">"rb"</span>) <span class="hl-keyword">as</span> f:
    result = requests.post(
        <span class="hl-str">f"{BASE}/profiles/{profile_id}/publish"</span>,
        headers=HEADERS,
        data={<span class="hl-str">"platform"</span>: <span class="hl-str">"tiktok"</span>, <span class="hl-str">"title"</span>: <span class="hl-str">"My video"</span>},
        files={<span class="hl-str">"video"</span>: f}
    ).json()

<span class="hl-keyword">print</span>(result)  <span class="hl-comment"># {'ok': True, 'publish_id': '...', 'platform': 'tiktok'}</span></pre>
      </div>
    </div>

  </main>
</div>

<script>
function copyCode(btn) {
  const pre = btn.closest('.code-block').querySelector('pre');
  navigator.clipboard.writeText(pre.innerText).then(() => {
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = 'Copy', 2000);
  });
}
// Highlight active nav link on scroll
const sections = document.querySelectorAll('.docs-section');
const links = document.querySelectorAll('.docs-nav-link');
const obs = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      links.forEach(l => l.classList.remove('active'));
      const l = document.querySelector('.docs-nav-link[href="#' + e.target.id + '"]');
      if (l) l.classList.add('active');
    }
  });
}, { rootMargin: '-20% 0px -60% 0px' });
sections.forEach(s => obs.observe(s));
</script>
</body></html>`);
});

app.get("/health", (req, res) => res.json({ ok: true }));

function escHtml(s) {
  return String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// Global error guard — prevent server crash on unhandled rejections
process.on("unhandledRejection", (reason) => {
  console.error("[unhandledRejection]", reason);
});
process.on("uncaughtException", (err) => {
  console.error("[uncaughtException]", err.message);
});

// Start
(async () => {
  await ensureTables();
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Storyload running on port ${PORT}`);
    console.log(`[config] DB: ${process.env.NEON_DATABASE_URL ? "Neon (external)" : "Replit (managed)"}`);
    console.log(`[config] TIKTOK_CLIENT_KEY prefix: "${TIKTOK_CLIENT_KEY.slice(0, 8)}" (len=${TIKTOK_CLIENT_KEY.length})`);
    console.log(`[config] APP_URL: ${APP_URL}`);
  });
})();
