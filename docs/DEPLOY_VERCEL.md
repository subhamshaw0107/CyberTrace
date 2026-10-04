# Deploying PS 26237 to Vercel

Vercel natively supports **Python Serverless Functions** and Flask WSGI applications. This guide explains how to deploy the **PS 26237 (PRAMAAN)** prototype to Vercel in just a few clicks.

---

## 1. Why Vercel?

- **Native Python Runtime:** Unlike Netlify (which only officially supports Node.js/Go functions in production), Vercel natively compiles and runs Python serverless functions via its official Python runtime.
- **Native Flask Integration:** Vercel automatically detects the Flask WSGI instance (`app` in `api/index.py`).
- **Higher Limits:** Vercel provides up to 500 MB uncompressed bundle size and fluid compute.
- **Automatic HTTPS & Edge CDN:** Global CDN with instant `.vercel.app` domain.

---

## 2. One-Click / Git Deployment

### Step 1: Push changes to GitHub
Ensure the changes are pushed to your GitHub repository:
```bash
git add .
git commit -m "feat: add Vercel deployment support"
git push origin main
```

### Step 2: Import into Vercel
1. Go to [Vercel Dashboard](https://vercel.com/dashboard).
2. Click **"Add New..."** > **"Project"**.
3. Select your **`bala9387/encryption`** repository.
4. In the Project Configuration:
   - **Framework Preset:** Other (or Flask)
   - **Root Directory:** `./`
   - **Build Command:** (leave default/empty — Vercel detects `requirements.txt`)
   - **Output Directory:** (leave default/empty)
5. Click **"Deploy"**.

Vercel will install dependencies from `requirements.txt`, bundle `api/index.py`, and provide a live URL such as `https://encryption-<username>.vercel.app`.

---

## 3. Command-Line Deployment (Vercel CLI)

If you prefer deploying from your terminal:

1. Install Vercel CLI:
   ```bash
   npm install -g vercel
   ```
2. Log in:
   ```bash
   vercel login
   ```
3. Deploy:
   ```bash
   vercel --prod
   ```

---

## 4. Architecture on Vercel

- **Entrypoint:** `api/index.py` exposes the Flask `app` instance.
- **Routing:** `vercel.json` rewrites all incoming traffic (`/(.*)`) to `/api/index`.
- **Ephemeral Storage:** The workspace runs in `/tmp/ps26237_workspace`. Demo identities (`alice`, `bob`, `carol` with passphrase `password123`) are automatically seeded on cold starts.
- **Cryptography:** Uses genuine `liboqs 0.16.0` on local machines, and automatically falls back to size-matched pure-Python FIPS 203/204 lattice emulation on Vercel serverless containers.
- **Static Assets:** Downloadable sample files (`sample_contract.png`, `sample_memo.pdf`) are served from `public/samples/`.
