# Deploying PS 26237 to Google Cloud Platform (GCP)

This repository supports two seamless deployment methods on Google Cloud:
1. **Google Cloud Run** (Recommended: fully managed container, fast autoscaling, zero idle cost)
2. **Google App Engine** (Standard Python 3.11 environment via `app.yaml`)

Both deployment targets have been verified end-to-end for:
- One-time encryption with per-recipient post-quantum ML-KEM-768 wraps
- Discrete Cosine Transform (DCT) invisible watermarking
- Post-quantum ML-DSA-65 digital signatures
- Multi-node PBFT ledger quorum commitment
- Forensic watermark recovery and mathematical attribution

---

## Method 1: Google Cloud Run (Recommended)

### Prerequisites
1. [Google Cloud SDK (`gcloud`)](https://cloud.google.com/sdk/docs/install) installed and configured:
   ```bash
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```
2. Enable required GCP services:
   ```bash
   gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com
   ```

### 1-Command Deployment (Zero Configuration)
Run this directly from the repository root:

```bash
gcloud run deploy ps26237 \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8080 \
  --memory 1Gi \
  --cpu 1 \
  --timeout 300
```

When prompted:
- **Service name**: `ps26237` (press Enter)
- **Region**: choose any region (e.g. `us-central1`)
- **Allow unauthenticated invocations**: `y`

### Optional: Password Protection (Basic Auth)
If you want to protect your public demo URL with a username and password, supply the environment variable:

```bash
gcloud run deploy ps26237 \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8080 \
  --memory 1Gi \
  --cpu 1 \
  --timeout 300 \
  --set-env-vars PS26237_AUTH_USER=admin,PS26237_AUTH_PASS=YourSecretPassword123!
```

---

## Method 2: Deploy from GCP Web Console (GitHub Direct)

1. Open [Google Cloud Run Console](https://console.cloud.google.com/run).
2. Click **Create Service**.
3. Choose **"Continuously deploy from a repository"** and connect `bala9387/encryption`.
4. Select **Branch**: `main`.
5. Under **Build configuration**:
   - Build Type: **Dockerfile** (path: `Dockerfile`)
6. Under **Authentication**:
   - Select **"Allow unauthenticated invocations"**.
7. Under **Container > Port**:
   - Set to `8080`.
8. Under **Container > Request timeout**:
   - Set to `300` seconds.
9. Click **Create**. Cloud Build will build the container and deploy the service automatically.

---

## Method 3: Google App Engine

Deploying via App Engine Standard:

```bash
gcloud app deploy app.yaml
```

View the live app:
```bash
gcloud app browse
```

---

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Port listened to by Gunicorn (Cloud Run sets this automatically). |
| `PS26237_AUTH_USER` | `ps26237` | Basic Auth username (if auth pass is set). |
| `PS26237_AUTH_PASS` | `""` (disabled) | Optional password for Basic Auth protection. |
| `PS26237_HOME` | `/tmp/ps26237_workspace` | Workspace path inside container instance. |

---

## Testing the Prototype on GCP

Once deployed, visit your Cloud Run URL:

1. **Check Status (`/`):**
   - Health check: `/healthz` returns `200 ok`.
   - The web console shows all 4 simulated ledger nodes (`sender-org-node`, `independent-auditor-node`, `security-dept-node`, `offsite-backup-node`) and pre-seeded demo identities (`alice`, `bob`, `carol`).
2. **Encrypt as Sender (`/sender`):**
   - Drop a test document (e.g. `sample_contract.png`).
   - Check **`alice`** (and optionally `bob`, `carol`).
   - Click **"Encrypt and download package"**.
   - Your browser downloads the `.ps26237` package, and the progress modal automatically dismisses.
3. **Decrypt as Recipient (`/recipient`):**
   - Drop the `.ps26237` package.
   - Select **`alice`**.
   - Enter passphrase:
     ```
     password123
     ```
   - Click **"Decrypt, watermark and commit"**.
   - Download the watermarked document.
4. **Forensic Trace (`/trace`):**
   - Drop the decrypted document into the Forensic Trace tab.
   - The system extracts the DCT watermark, verifies the ledger quorum, validates Alice's signature, and attributes the leak to `alice`!
