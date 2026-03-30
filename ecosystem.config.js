module.exports = {
  apps: [
    {
      name: "storyload",
      script: "server.js",
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "512M",
      env: {
        NODE_ENV: "production",
        PORT: 3001,
        // Fill in your actual values:
        APP_URL: "https://storyload.ru",
        SESSION_SECRET: "change-this-to-a-long-random-string",
        // Google OAuth (from Google Cloud Console)
        GOOG_CLIENT_ID: "",
        GOOG_CLIENT_SECRET: "",
        // TikTok OAuth (from TikTok Developer Portal)
        TIKTOK_CLIENT_KEY: "",
        TIKTOK_CLIENT_SECRET: "",
        // Neon PostgreSQL connection string
        NEON_DATABASE_URL: "",
      },
    },
  ],
};
