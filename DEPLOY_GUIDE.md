# CYBERGUARD deployment (GitHub + Render + Netlify)

## 1. Push to GitHub
1. Extract this ZIP. Open the `CYBERGUARD_DEPLOY` folder in a terminal.
2. Create an empty GitHub repository named `CYBERGUARD` (do not add a README/license there).
3. Run:
   ```bash
   git init
   git add .
   git commit -m "Prepare CyberGuard for deployment"
   git branch -M main
   git remote add origin https://github.com/YOUR-USERNAME/CYBERGUARD.git
   git push -u origin main
   ```
4. Replace `YOUR-USERNAME` with your GitHub username. Do not upload `.env`, `.venv`, or secrets.

## 2. Deploy backend on Render
1. Sign in to Render and choose **New + → Blueprint** (or create a Web Service from the GitHub repo).
2. If using Blueprint, Render reads `render.yaml` at the repository root.
3. After deploy, open `https://YOUR-BACKEND.onrender.com/health`; expect JSON with `healthy`. `/docs` shows API docs.
4. In Render environment variables, set `CORS_ORIGINS` to your exact Netlify site URL. The included value is a placeholder. Keep `SECRET_KEY` generated/private.

## 3. Deploy frontend on Netlify
1. In Netlify choose **Add new site → Import an existing project** and connect the same GitHub repository.
2. Set **Base directory** to blank/root, **Build command** blank, and **Publish directory** to `.` (root). This is a plain HTML/CSS/JS site.
3. Deploy, then copy the Netlify site URL.
4. In `script.js`, replace `https://YOUR-BACKEND.onrender.com` with the real Render URL. Also set Render's `CORS_ORIGINS` to the real Netlify URL. Commit and push the edit; Netlify will redeploy.

## Important
- The browser frontend must never use `127.0.0.1`/`localhost` for the hosted API.
- SQLite on many free hosting instances may be temporary. Use managed PostgreSQL and set `DATABASE_URL` for persistent production data.
- Do not commit real API keys or `.env`. Add optional threat-intelligence keys in Render's environment settings only.
- Check the first Render deploy logs and test `/health` and `/docs`.
