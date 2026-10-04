# Deploying PS 26237 to Netlify

This guide explains how to deploy the **PS 26237 (PRAMAAN)** prototype to **Netlify** for live cloud demonstration, evaluation, or stakeholder reviews.

---

## 1. Architecture on Netlify

Netlify is an edge-and-serverless platform. While the production specification of PS 26237 is designed for an air-gapped host with hardware-token keys and a Dockerized Hyperledger Fabric network (see [DEPLOYMENT.md](DEPLOYMENT.md)), this Netlify deployment packages the system as a **zero-maintenance serverless application**:

```
                       User Browser
                            │
               ┌────────────┴────────────┐
               │  Netlify Global CDN Edge │
               └────────────┬────────────┘
                            │
         ┌──────────────────┴──────────────────┐
         │                                     │
   Static Assets                        API & Dynamic Routes
   (/samples/*, HTML, icons)           (/, /sender, /recipient, /trace)
         │                                     │
    Served instantly                    Netlify Function
      from Edge CDN                     (AWS Lambda Runtime)
                                               │
                                     netlify/functions/api.py
                                        (WSGI Flask Console)
                                               │
                         ┌─────────────────────┼─────────────────────┐
                         │                     │                     │
                  Crypto Layer          Watermark Engine       Quorum Ledger
               (ML-KEM-768/ML-DSA-65      (DCT Transform       (4 simulated nodes,
               size-matched emulator)     OpenCV Headless)       quorum=3, in /tmp)
```

### Key Differences: Netlify Serverless vs Air-Gapped Production

| Feature | Netlify Cloud Deployment | Production Air-Gapped Host |
|---|---|---|
| **Hosting Model** | Serverless (AWS Lambda, Python 3.11) | Dedicated bare-metal / VM |
| **PQC Backend** | Size-matched pure-Python FIPS 203/204 emulator | Genuine compiled `liboqs 0.16.0` C library |
| **Watermark Engine** | `opencv-python-headless` (DCT, rotation/scale) | Full `opencv-python` + `pymupdf` |
| **Ledger Engine** | 4-node simulated quorum ledger in `/tmp` | Real Hyperledger Fabric (Docker peers + Raft orderer) |
| **Private Keys** | Auto-seeded in ephemeral `/tmp` (`alice`, `bob`, `carol`) | Hardware tokens / HSMs / OS keystore |
| **Network** | Public HTTPS via Netlify | Physically air-gapped |

---

## 2. One-Click / Git Deployment

### Step 1: Push repository to GitHub
Ensure your repository is pushed to your GitHub, GitLab, or Bitbucket account:
```bash
git add .
git commit -m "Configure PS 26237 for Netlify serverless deployment"
git push origin main
```

### Step 2: Import into Netlify
1. Log in to [Netlify Dashboard](https://app.netlify.com/).
2. Click **"Add new site"** > **"Import an existing project"**.
3. Select your Git provider and choose the `PS26237_prototype` repository.
4. Netlify will automatically detect the settings from `netlify.toml`:
   - **Base directory:** (leave blank or `.`)
   - **Build command:** (leave blank or `pip install -r requirements.txt`)
   - **Publish directory:** `public`
   - **Functions directory:** `netlify/functions`
5. Click **"Deploy site"**.

Your live site will be provisioned at `https://<site-name>.netlify.app`.

---

## 3. Command-Line Deployment (Netlify CLI)

If you prefer to deploy directly from your terminal without connecting Git:

1. Install the Netlify CLI:
   ```bash
   npm install -g netlify-cli
   ```
2. Authenticate:
   ```bash
   netlify login
   ```
3. Initialize and deploy:
   ```bash
   netlify deploy --prod
   ```
   Follow the prompts to link or create a new site. The CLI will bundle the functions and static assets automatically.

---

## 4. Local Testing with Netlify CLI

To simulate the exact Netlify environment locally:
```bash
netlify dev
```
This starts a local edge server proxying to Python functions on `http://localhost:8888`.

Alternatively, test standard local development:
```bash
python app.py
```
This runs the local development server at `http://127.0.0.1:8237`.

---

## 5. Walkthrough of the Live Demo

Once deployed on Netlify:

1. **Dashboard (`/`)**:
   - Inspect the 4 ledger nodes (`sender-org-node`, `independent-auditor-node`, `security-dept-node`, `offsite-backup-node`).
   - Notice the status badge confirming node quorum agreement and pre-seeded demo identities (`alice`, `bob`, `carol`).
2. **Sender (`/sender`)**:
   - Click the built-in sample link to download `sample_contract.png` or `sample_memo.pdf`.
   - Drop the document, select `alice` and `bob`, and click **"Encrypt and download package"**.
   - Your browser downloads `<document_id>.ps26237`.
3. **Recipient (`/recipient`)**:
   - Drop the `.ps26237` package, select `alice`, enter passphrase `password123`, and click **"Decrypt, watermark and commit"**.
   - The system embeds Alice's unique invisible watermark, generates a non-repudiable signature over the session record, commits it to all 4 ledger nodes, and presents the signed provenance certificate.
   - Click **"Download watermarked file"**.
4. **Forensic Trace (`/trace`)**:
   - Drop Alice's watermarked file (or crop/rescale it).
   - Click **"Analyse"**.
   - The engine performs DCT extraction, queries the ledger nodes for quorum, verifies Alice's signature, and reports:
     `CONFIRMED -- Leaked document matches watermark ... belonging to alice`.

---

## 6. Alternative: Full Container Deployment (Fabric + C-liboqs)

If you require persistent ledger storage or the real Hyperledger Fabric network in the cloud (rather than serverless), deploy using Docker on a container platform such as **Render**, **Railway**, or **Fly.io**:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y gcc cmake ninja-build git libgl1 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8237
CMD ["python", "app.py"]
```
