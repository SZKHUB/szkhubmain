# SZKHUB server
1. Copy .env.example to .env and fill it (never commit it). Keep MASTER_KEY safe: scripts are encrypted with it.
2. Run: `set -a; . ./.env; set +a; node server.js` (Node 18+). On Railway/Render set the same variables and start command `node server.js`; behind a proxy keep TRUST_PROXY=1 and use HTTPS.
3. Log in: POST /api/admin/login {"user","password"} -> Bearer token.
4. Add a script: POST /api/scripts {"name","source"}, then PUT /api/scripts/ID {"status":"published"}.
5. Distribute: loadstring(game:HttpGet("https://your-domain.com/api/loader"))()
Discord .get: GET /api/discord/get with headers `Authorization: Bot <DISCORD_BOT_SECRET>` and `x-guild-id`.
Limits: a client that runs the script can always capture it; this raises the cost of casual scraping. Storage is a local encrypted JSON file; mount a persistent volume at DATA_DIR.
