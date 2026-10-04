# PS 26237 — Cryptographic Attribution & Immutable Decryption Provenance
### Working Prototype | Ministry of Defence — Indian Navy (WESEE) | Blockchain & Cybersecurity

---

## 1. What this is

A complete, runnable, end-to-end prototype of the leak-attribution system described in PS 26237:
a sender encrypts a document once, distributes it to multiple recipients, and — if any recipient's
copy later leaks — the system can prove cryptographically **which specific recipient's decryption
session** produced the leaked copy, using an invisible per-session watermark, a signature made with
the recipient's own private key, and a tamper-evident multi-node ledger that no single administrator
can rewrite.

**Use it (CLI):**
```bash
python ps26237.py init                                             # create a workspace (ledger: sim | fabric)
python ps26237.py keygen --id alice                                # ML-KEM-768 + ML-DSA-65 identity
python ps26237.py encrypt --doc annex.pdf --recipients alice,bob,carol
python ps26237.py decrypt --as alice --package annex.ps26237       # watermark + sign + commit, then release
python ps26237.py trace --leaked leaked_photo.jpg                  # attribution report
python ps26237.py serve                                            # local web UI on 127.0.0.1:8237
```

**Live Cloud Demo (Vercel — Recommended):**
Deploy this prototype instantly to **Vercel** with native Python runtime support:
- Connect your GitHub repo to Vercel or run `vercel --prod` (configured in `vercel.json` & `api/index.py`).
- Pre-seeds demo identities (`alice`, `bob`, `carol` with passphrase `password123`) in `/tmp`.
- Includes downloadable sample files (`sample_contract.png`, `sample_memo.pdf`) on the Sender page for instant testing.
- Full instructions & architecture: [`docs/DEPLOY_VERCEL.md`](docs/DEPLOY_VERCEL.md).

**Netlify Deployment:**
- See [`docs/DEPLOY_NETLIFY.md`](docs/DEPLOY_NETLIFY.md). (Note: Netlify only natively supports Node.js/Go in production, whereas Vercel natively supports Python).

**Test suites** (on Windows prefix with `PYTHONIOENCODING=utf-8`):
```bash
python demo/test_requirements.py          # 17/17 requirement scorecard (no Docker needed)
python demo/test_app.py                   # 24/24 application layer: CLI/web service, PDF, tracing
python demo/test_watermark_robustness.py  # measured bit error rates under 23 leak transformations
python demo/run_full_pipeline.py          # narrated end-to-end demo
bash ledger/fabric/network.sh up && python demo/test_fabric_ledger.py   # 17/17 on real Fabric (needs Docker)
```

## 2. Cryptography: real NIST post-quantum algorithms (liboqs)

`crypto/pqc.py` calls the Open Quantum Safe **liboqs** C library through `liboqs-python`:
- `MLKEM` → `oqs.KeyEncapsulation("ML-KEM-768")` (FIPS 203): public key 1184 B, secret key 2400 B, ciphertext 1088 B
- `MLDSA` → `oqs.Signature("ML-DSA-65")` (FIPS 204): public key 1952 B, secret key 4032 B, signature 3309 B

These sizes are what liboqs actually outputs; nothing is padded. The module checks them against liboqs when
it loads. **There is no classical fallback:** if liboqs is missing, the import fails instead of quietly running
non-PQC crypto. (An earlier version of this prototype used X25519/Ed25519 as a stand-in with matching sizes.
That code has been removed.)

**Tested on:** Windows 11, Python 3.14.4, liboqs 0.16.0 built from source with MSVC 14.50
(VS 2026 Build Tools, Ninja, `-DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65"`), liboqs-python 0.16.0.
On Windows, `pip install liboqs-python` alone was **not enough**: its automatic build failed because `cmake` was not on PATH.
Building liboqs from inside a `vcvars64.bat` environment, in a short directory path (Windows path-length limit), worked.

**Measured on this machine** (average of 100 runs): ML-KEM-768 keygen ≈ 0.05 ms, ML-DSA-65 sign ≈ 0.32 ms,
verify ≈ 0.09 ms. Decrypting with another recipient's ML-KEM secret key is rejected (AES-GCM `InvalidTag`).

**What is still not claimed:** liboqs is a research/prototyping library. It is not a FIPS 140-3 validated
module, and no side-channel evaluation has been done here. For air-gapped hosts: `liboqs-python` tries to
`git clone` liboqs if it can't find the shared library, so ship a prebuilt `oqs.dll`/`liboqs.so` and set
`OQS_INSTALL_PATH`.

## 2b. Ledger: real Hyperledger Fabric network (`ledger/fabric/`)

Two ledger backends share one interface (`commit_record` / `lookup_by_watermark` / `verify_network_integrity`),
so `forensics/trace_leak.py` works with either:

| Backend | What it is | Test |
|---|---|---|
| `ledger/ledger_network.py` | Python simulation: 4 nodes as objects in one process (fast, no Docker) | `demo/test_requirements.py` |
| `ledger/fabric_ledger.py` + `ledger/fabric/` | **Hyperledger Fabric 2.5**: 1 Raft orderer + 4 organisation peers (SenderOrg, AuditorOrg, SecurityOrg, BackupOrg), each org in its own container with its own MSP identity, plus its own chaincode container | `demo/test_fabric_ledger.py` |

```bash
bash ledger/fabric/network.sh up          # ~24 s on this machine once images are pulled
PYTHONIOENCODING=utf-8 python demo/test_fabric_ledger.py
bash ledger/fabric/network.sh down        # removes containers, volumes, generated identities
```

**What Fabric enforces:**
- **Endorsement policy:** `OutOf(3, SenderOrg.peer, AuditorOrg.peer, SecurityOrg.peer, BackupOrg.peer)`. A write
  that fewer than 3 organisations endorsed is marked invalid by every peer.
- **Chaincode checks** (`ledger/fabric/chaincode/provenance/main.go`, Go). Every endorsing peer checks the
  record independently:
  - the recipient's **ML-DSA-65 signature** (Cloudflare CIRCL v1.6.5). We tested that CIRCL verifies
    signatures made by liboqs and rejects them when the message is tampered with.
  - that the signed bytes match the record's fields
  - that the signer key is the recipient's **write-once registered key**
  - that the watermark has **no existing record**. There are no update or delete functions.
- **Read side** (`fabric_ledger.py`): each organisation's peer is queried separately, and a record is trusted
  only if 3 of 4 return it identically and the ML-DSA signature verifies again in Python.

**Measured: `demo/test_fabric_ledger.py`, 17/17 passing** (twice, including after a full `down` then `up`):
- **Honest network:** 3 records committed, each valid at 4/4 peers. All four peers hold identical state, and a
  JPEG-q85 leak is traced to the right recipient.
- **Rejected by chaincode, with the specific error checked:**
  - committing the same watermark again ("records are immutable")
  - a record naming bob but signed with alice's key ("ML-DSA-65 signature verification failed")
  - an unregistered signer key
  - fields that don't match the signed bytes
  - re-registering a recipient with a different key
- **Compromised SecurityOrg** (its chaincode is swapped for a version that lies on reads and endorses forged
  overwrites, via `network.sh rogue <recipient>`):
  - Its false answers are detected (`tampered_nodes=['security-dept-node']`).
  - An overwrite endorsed only by that org is invalidated (`ENDORSEMENT_POLICY_FAILURE`).
  - An overwrite that needs honest orgs' endorsement is refused by them.
  - The honest peers show exactly 1 write ever for the record.
  - The trace still confirms the true recipient, 3 peers to 1.
- **Timings** (Docker Desktop on Windows, peer CLI via `docker exec`): about 1.4–2.0 s per commit, about
  1.3 s per forensic trace. Most of this is CLI and process overhead, not Fabric consensus.

**Limits of this deployment (not hidden):**
- **Single machine:** all containers run on one host. Separate processes, identities and state, but not
  separate machines or administrators.
- **One orderer:** it could censor or delay transactions, but it cannot forge endorsements. Production should
  run a Raft/BFT orderer cluster with nodes spread across the organisations.
- **Classical crypto inside Fabric:** peer, orderer and TLS identities use Fabric's standard ECDSA P-256,
  which is not post-quantum. The post-quantum guarantee covers the *decryption record* (recipient's
  ML-DSA-65 signature, checked on-chain and again at trace time), not Fabric's own transport and consensus.
- **Test identities:** they come from `cryptogen`, which is for testing only. Production needs a Fabric CA or
  offline-issued certificates.
- **Air-gap preparation:** Go dependencies are vendored (`chaincode/provenance/vendor`), so the chaincode image
  builds offline. The Docker images (`fabric-peer/orderer/tools:2.5`, `golang:alpine`, `alpine`) must be
  pre-loaded with `docker save`/`docker load`.

## 2c. Application: CLI and web UI (`ps26237.py`, `app/`)

Both interfaces share `app/service.py`, so they behave identically.

A **workspace** directory holds `config.json` (which ledger), `identities/<id>.json`
(public keys + secret keys encrypted with AES-256-GCM under a scrypt-derived passphrase key,
N=2^15) and, for the simulated ledger, `ledger_sim.pkl`.

**Web UI** (`python ps26237.py serve`): Status (nodes, record count, cross-node agreement),
Sender (upload, pick recipients, download package), Recipient (decrypt, see the record, download
the watermarked copy), Forensic trace (upload a leaked file, get the report). All CSS and markup
are inline — no CDN, no external fonts, nothing fetched at run time, because the system must run
air-gapped. It binds to `127.0.0.1` and has **no user authentication**: it is an operator tool to
run behind the host's own access control, not a public service.

**Rule enforced in the service layer:** the watermarked document is released only *after* its
signed record is committed to the ledger. If the commit fails, the recipient gets an error and no
file — so there is no such thing as a decryption with no ledger record.

**Document formats:** PNG, JPEG and PDF. PDF pages are rendered at 150 DPI, watermarked, and
written back as images (about 0.4 MB per A4 page, JPEG q92). This means **the text layer is gone**:
a watermarked PDF is not searchable or selectable. That is deliberate — an untouched text layer
could be copied out without the watermark. **Office documents (docx/pptx/xlsx) are rejected** with
a message telling the operator to convert to PDF first (`soffice --headless --convert-to pdf`):
an Office file has no single fixed rendering, so a pixel watermark in one rendering says nothing
about what another viewer displays.

## 3. Architecture

```
 SENDER                                   RECIPIENT (e.g. "Alice")
 ┌─────────────┐   1. encrypt ONCE        ┌──────────────────────────────┐
 │  Document   │ ───────────────────────► │ decrypt_for_recipient()      │
 └─────────────┘   (AES-256-GCM,          │   using Alice's OWN          │
        │           DEK wrapped per       │   ML-KEM secret key          │
        │           recipient via         └──────────────┬───────────────┘
        │           ML-KEM-768)                           │
        ▼                                                  ▼
 EncryptedPackage                          ┌──────────────────────────────┐
  - ciphertext (SHARED,                    │ embed_watermark()            │
    identical for all recipients)          │  unique 128-bit ID via       │
  - key_wraps{alice:.., bob:.., ..}        │  DCT mid-freq coefficients   │
                                            │  -> visually identical,     │
                                            │     forensically unique     │
                                            └──────────────┬───────────────┘
                                                            │
                                            ┌──────────────▼───────────────┐
                                            │ MLDSA.sign(record, Alice's   │
                                            │   OWN secret key)            │
                                            │  -> non-repudiable proof     │
                                            └──────────────┬───────────────┘
                                                            │
                          ┌─────────────────────────────────┘
                          ▼
        ┌───────────────────────────────────────────────────────┐
        │      LEDGER NETWORK (4 independent nodes, quorum=3)     │
        │  sender-org | auditor | security-dept | offsite-backup  │
        │  Each node independently hash-chains + signs its own    │
        │  copy. A record is only "committed/trusted" once a      │
        │  QUORUM of nodes agree. One compromised admin editing   │
        │  ONE node's file is detected & outvoted.                │
        └───────────────────────────────────────────────────────┘
                          │
                          ▼  (later: leak happens)
        ┌───────────────────────────────────────────────────────┐
        │  FORENSIC TRACE: extract_watermark(leaked_file)         │
        │   -> lookup_by_watermark() against ledger quorum        │
        │   -> MLDSA.verify(record, signature, recipient_pubkey)  │
        │   -> AttributionReport: "CONFIRMED: Alice, session X,   │
        │      timestamp Y -- non-repudiable"                     │
        └───────────────────────────────────────────────────────┘
```

## 4. Module map

| Module | Responsibility |
|---|---|
| `crypto/pqc.py` | ML-KEM-768 / ML-DSA-65 via liboqs (see section 2) |
| `crypto/document_crypto.py` | Broadcast-encrypt-once / decrypt-individually via AES-256-GCM + per-recipient KEM key-wrap |
| `crypto/decryption_session.py` | Ties decryption → watermark generation → signed record together per session |
| `watermark/dct_watermark.py` | DCT mid-frequency coefficient watermarking with redundant embedding + majority-vote extraction |
| `ledger/ledger_node.py` | Single hash-chained, self-signing ledger participant |
| `ledger/ledger_network.py` | Multi-node quorum commit, tamper detection, forensic lookup (in-process simulation) |
| `ledger/fabric_ledger.py` | Same interface backed by the real Fabric network (section 2b) |
| `ledger/fabric/` | Fabric network: compose file, channel config, `network.sh`, Go chaincode |
| `demo/test_fabric_ledger.py` | 17 checks against the live Fabric network incl. compromised-org attack |
| `forensics/trace_leak.py` | Leak → watermark → ledger (exact or nearest-ID match) → signature → verdict |
| `watermark/document_formats.py` | Per-format watermarking: PNG/JPEG direct, PDF page-by-page; Office rejected |
| `app/service.py` | Workspace, identities, encrypt/decrypt/trace used by both CLI and web UI |
| `app/web.py` | Local Flask UI (status / sender / recipient / trace), no external assets |
| `api/index.py` | Vercel Python serverless entrypoint for the Flask web application |
| `vercel.json` | Vercel routing configuration and URL rewrites |
| `netlify/functions/api.py` | Netlify Functions serverless WSGI bridge with auto demo seeding |
| `netlify.toml`, `runtime.txt` | Netlify build, routing, and Python 3.11 environment configuration |
| `ps26237.py` | CLI: init, keygen, encrypt, decrypt, trace, ledger-status, serve |
| `docs/DEPLOYMENT.md` | Air-gapped install bundle, HSM/token guidance, topology, scale numbers |
| `docs/DEPLOY_VERCEL.md` | Cloud deployment guide for Vercel Python serverless hosting |
| `docs/DEPLOY_NETLIFY.md` | Cloud deployment guide for Netlify serverless hosting |
| `demo/test_app.py` | 24 checks on the application layer (identities, PDF, tracing, persistence) |
| `demo/test_watermark_robustness.py` | Bit error rates across 23 leak transformations, 8 documents |
| `demo/run_full_pipeline.py` | Full narrated demo (3 recipients, 1 leak, 1 rogue-admin attack) |
| `demo/test_requirements.py` | Automated scorecard against all 17 checkable requirements |

## 5. Measured results (not claimed — actually run)

Every number below comes from a test run on this machine. Reproduce with the commands in
section 1. Raw data: `output/watermark_robustness_v2-resync.json`.

### 5.1 Invisibility

Watermarked copies of the same document differ from each other by a **mean of 0.65/255 per
pixel** (`demo/test_app.py`), i.e. visually identical. Against the *original* document:

| Document | PSNR | mean abs diff | max single-pixel diff |
|---|---|---|---|
| synthetic 512x512 | 43.5 dB | 0.83 | 37 |
| PDF page render, 150 dpi | 35.2 dB | 1.32 | 107 |
| 6 real scanned forms (FUNSD) | 35.7-38.3 dB | 1.09-1.32 | 88-118 |

The large maximum differences sit on high-contrast text edges, where they are least visible;
the mean is what the eye integrates. This is a deliberate trade: strength was tuned up until
geometric attacks survived (section 5.2).

### 5.2 Watermark robustness under 23 leak transformations

8 documents: 1 synthetic image, 1 rendered PDF page, 6 **real scanned business forms** from
the FUNSD dataset (`testdata/scans/`, research/non-commercial use only -- see
`testdata/README.md`). "Attributable" means the recovered ID is within 16 of 128 bits of the
ledger ID, which is what `forensics/trace_leak.py` accepts (false-match probability for a
random ID is 3.2e-19; with a million records, 3.2e-13).

| Transformation | exact | attributable | mean BER | worst BER |
|---|---|---|---|---|
| lossless copy | 8/8 | 8/8 | 0.000 | 0.000 |
| JPEG q90 / q75 | 8/8 | 8/8 | 0.000 | 0.000 |
| JPEG q60 | 5/8 | 7/8 | 0.062 | 0.484 |
| JPEG q50 | 4/8 | 7/8 | 0.068 | 0.477 |
| Gaussian noise sigma=5 | 8/8 | 8/8 | 0.000 | 0.000 |
| crop header 10% / footer 15% / centre 50% only | 8/8 | 8/8 | 0.000 | 0.000 |
| crop 3px off left+top (breaks the 8x8 grid) | 8/8 | 8/8 | 0.000 | 0.000 |
| rescale x0.5 / x0.75 / x0.9 / x1.25 / x2.0 | 8/8 | 8/8 | 0.000 | 0.000 |
| rotate 1 / 2 / 3 / 5 degrees | 8/8 | 8/8 | 0.000 | 0.000 |
| rotate 2 deg + JPEG q75 | 2/8 | 8/8 | 0.011 | 0.031 |
| crop header + rescale x0.8 + JPEG q75 | 0/8 | 7/8 | 0.098 | 0.500 |
| **print-and-scan simulation** | 1/8 | **3/8** | 0.317 | 0.547 |
| **photo-of-screen simulation** | 0/8 | **0/8** | 0.513 | 0.562 |

**Where the failures are, precisely:**
- Every "7/8" and "5/8" above fails on the **same document**: the 512x512 synthetic test image.
  It is small and almost blank, giving only ~16 votes per payload bit; the real scans and PDF
  pages (1000x754 and larger) carry 45+ votes per bit and survive. **Small or nearly blank
  documents are the weak case**, not compression as such.
- **Print-and-scan is unreliable** (3/8): geometry plus optical blur plus contrast loss
  together attenuate the mid-frequency band the watermark lives in. Some documents survive it
  exactly, others are destroyed. Do not rely on it.
- **Photo-of-a-screen does not survive at all** (0/8). Measured cause: downscaling to 0.8x
  followed by ~1.1 px blur removes the band entirely (BER 0.56 even without the perspective
  distortion). Fixing this needs a lower-frequency or multi-scale carrier, which costs
  visibility — measured on one scan, moving the carrier to coefficients (1,2)/(2,1) recovered
  print-and-scan exactly but dropped PSNR from 35.7 to 33.7 dB. Not adopted.

**Extraction time**: mean 4.0 s, max 16.7 s across all cases. Untransformed or merely
compressed/cropped copies decode in under 0.1 s; the geometric search is what costs seconds.

**For comparison, the original algorithm** (`output/watermark_robustness_v1-original.json`)
scored 8/8 only on lossless, JPEG >= 75, noise and footer-cropping, and **0/8 on every
rotation, rescale, header-crop and combined attack** — it had no resynchronisation at all.

### 5.3 Application layer (`demo/test_app.py`, 24/24)

- Encrypt-once/decrypt-individually, unique watermark per recipient **and** per session.
- Decrypt + watermark + sign + commit: **~250 ms** per recipient for a 1000x754 image
  (simulated ledger); the Fabric ledger adds 1.4-2.0 s for the commit.
- Cropped + rescaled + JPEG leak traced correctly: **4-6 bits differ** of 128 across runs.
- Screenshot of one PDF page (110 dpi, cropped, JPEG q80) traced correctly: **9-14 bits
  differ**. This is the closest case to the 16-bit limit — in one of four repeat runs it
  failed to match at all. Treat PDF-screenshot attribution as likely, not guaranteed.
- Refusals verified: unknown recipient, wrong passphrase, recipient not in the package,
  Office file, and an unwatermarked document (reported NO MATCH rather than misattributed).

### 5.4 Ledger

- **Fabric** (`demo/test_fabric_ledger.py`, 17/17): see section 2b, including the
  compromised-organisation attack, which is detected and outvoted 3-1.
- **Simulated ledger**: 4.5 ms per commit across 4 nodes.
- **Storage**: one decryption record is 10.9 kB (the ML-DSA-65 signature and public key in hex
  dominate); ~27 kB across all 4 node copies. 100,000 decryptions ~ 4.4 GB total. See
  `docs/DEPLOYMENT.md` section 4.

## 6. What a production build would still need

Direct about the gap between this prototype and a deployable system:

1. **Validated PQC module.** Real ML-KEM-768/ML-DSA-65 are integrated via liboqs (done), but liboqs is
   a research library: no FIPS 140-3 validation, no side-channel review on this platform.
2. **Multi-host Fabric.** The 4-organisation network runs and is tested (section 2b) but on one machine,
   with one orderer and `cryptogen` test identities. Production needs a host and administrator per
   organisation, an orderer cluster, and a real CA. Fabric's own identities stay classical (ECDSA P-256):
   the post-quantum guarantee covers the decryption records, not Fabric's transport and consensus.
3. **Watermark: two attacks still win.** Photo-of-a-screen never survives, and print-and-scan survives
   only sometimes (3/8) -- measured, section 5.2. A lower-frequency or multi-scale carrier would help at
   a cost in visibility. Small or nearly blank documents are the weak case and could be rejected at
   encrypt time with a "too few blocks to watermark reliably" warning (not implemented).
4. **Private keys in software.** Keys are encrypted at rest with scrypt + AES-256-GCM under a passphrase,
   which is software protection only. Hardware tokens are the right answer for the signing key; PKCS#11
   support for ML-DSA is new and must be confirmed with the vendor. See `docs/DEPLOYMENT.md` section 2.
5. **Formats.** PNG, JPEG and PDF are supported; Office files must be converted to PDF first (a
   documented scope decision, section 2c). Video is not supported at all.
6. **Web UI has no authentication.** It is a localhost operator tool, not a multi-user service.
7. **Forensic trace speed.** 4 s average, up to 17 s when the geometric search runs; single-threaded.
