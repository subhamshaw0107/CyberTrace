# PS 26237 — Cryptographic Attribution & Immutable Decryption Provenance

## Project goal
Build a working system that: encrypts a document once for multiple recipients,
lets each decrypt independently, embeds a unique invisible watermark per
decryption session, signs a decryption record with the recipient's own private
key, commits it to a tamper-evident multi-node ledger, and can later trace a
leaked copy back to the exact recipient. Full requirements in
`docs/problem_statement.md` (paste the original PS 26237 text there if not present).

## Current status: ALL SIX PRIORITIES DONE (2026-09-20)

| Suite | Result | Needs |
|---|---|---|
| `demo/test_requirements.py` | 17/17 | nothing |
| `demo/test_app.py` | 24/24 | nothing |
| `demo/test_fabric_ledger.py` | 17/17 | Docker + `bash ledger/fabric/network.sh up` |
| `demo/test_watermark_robustness.py` | measured, no pass/fail | ~45 min to run |
| `demo/run_full_pipeline.py` | narrated demo | nothing |

On Windows, prefix test commands with `PYTHONIOENCODING=utf-8` (the scorecards print emoji).

- **P1 real PQC**: `crypto/pqc.py` uses liboqs 0.16.0 ML-KEM-768 / ML-DSA-65, no classical fallback.
  liboqs was built from source (short path `C:\oqsb`, MSVC from a vcvars64 shell) and installed to
  `C:\Users\balac\_oqs`.
- **P2 Fabric ledger**: `ledger/fabric/` -- 4 org peers + orderer, OutOf(3) endorsement, Go chaincode
  verifying ML-DSA-65 via CIRCL. Single host only. `network.sh up` is idempotent; run it from Git Bash
  (it sets MSYS_NO_PATHCONV=1). Chaincode packages are built deterministically -- do not "simplify" the
  tar flags in `scripts/cli.sh`, or package IDs change and peers stop matching the committed definition.
- **P3 application**: `ps26237.py` CLI + `app/web.py` Flask UI over `app/service.py`.
- **P4 watermark**: rewritten with tiled sync bits + rotation/scale/offset search. Survives rotation,
  rescaling, cropping, JPEG q75+. Print-and-scan 3/8; photo-of-screen 0/8. See README 5.2.
- **P5 formats**: PNG/JPEG/PDF (`watermark/document_formats.py`); Office rejected by decision.
- **P6 deployment**: `docs/DEPLOYMENT.md` (offline bundle, HSM guidance, topology, scale numbers).

Shell scripts must keep LF line endings -- writing them from Python on Windows produces CRLF, which
breaks them inside the Linux containers.

---

## REMAINING WORK (all six original priorities are complete; these are the known gaps)

Ranked by how likely a judge or a real deployment is to hit them. Full detail in README section 6.

1. **Watermark vs print-and-scan / photo-of-screen** -- measured 3/8 and 0/8 (README 5.2). Needs a
   lower-frequency or multi-scale carrier; that costs visibility, so measure PSNR before adopting.
2. **Warn when a document is too small/blank to watermark reliably** -- every measured failure on
   compression and combined attacks was the 512x512 near-blank synthetic image (~16 votes per bit).
   `embed_watermark` could return the redundancy and the app could refuse or warn below a threshold.
3. **Multi-host Fabric** -- currently one machine, one orderer, cryptogen test identities.
4. **Hardware-token private keys** -- confirm PKCS#11 ML-DSA support with a vendor first
   (docs/DEPLOYMENT.md section 2).
5. **Faster forensic trace** -- the geometric search is single-threaded, up to 17 s.
6. **Authentication for the web UI** if it is ever exposed beyond localhost.

Do not restate any of these as done without a test run that shows it.

## Module map
- `crypto/pqc.py` — real ML-KEM-768 / ML-DSA-65 via liboqs
- `ps26237.py`, `app/service.py`, `app/web.py` — CLI and local web UI
- `watermark/document_formats.py` — PNG/JPEG/PDF watermarking; Office rejected
- `ledger/fabric/`, `ledger/fabric_ledger.py` — real Fabric network and its client
- `docs/DEPLOYMENT.md`, `docs/problem_statement.md` — deployment guide, original PS text
- `crypto/document_crypto.py` — broadcast-encrypt-once / decrypt-individually (AES-256-GCM + per-recipient KEM wrap)
- `crypto/decryption_session.py` — ties decrypt → watermark → sign together
- `watermark/dct_watermark.py` — DCT mid-frequency invisible watermarking, 128-bit ID, redundant embedding + majority-vote extraction
- `ledger/ledger_node.py` — single hash-chained, self-signing ledger participant
- `ledger/ledger_network.py` — multi-node quorum commit + tamper detection + forensic lookup
- `forensics/trace_leak.py` — leaked file → watermark extraction → ledger lookup → signature verify → verdict
- `demo/run_full_pipeline.py` — full narrated demo (3 recipients, 1 leak, 1 rogue-admin attack simulation)
- `demo/test_requirements.py` — automated scorecard against every stated requirement (regression suite — run after every change)

## Conventions
- Every crypto primitive lives behind the `MLKEM`/`MLDSA` interface — never call
  X25519/Ed25519 (or liboqs, post-swap) directly from outside `crypto/pqc.py`.
- Ledger records are plain JSON dicts with a fixed schema (see
  `DecryptionRecord.to_dict()` in `crypto/decryption_session.py`); don't add
  fields without updating both the signer and the forensic verifier.
- Watermark IDs are always 128-bit (16 bytes), hex-encoded when stored in
  ledger records.
- Run `demo/test_requirements.py` after ANY change to crypto/watermark/ledger
  modules — it's the regression test suite for this project.
- Every claim in README.md must be backed by an actual test run, not
  aspirational text. Report real measured numbers (bit error rates, pixel
  diffs, quorum results), not assertions of correctness.

## First message to send in a new Claude Code session
"Read CLAUDE.md and README.md in full. Run demo/test_requirements.py (17/17) and
demo/test_app.py (24/24) to confirm the baseline on this machine. If you will touch the
ledger, start Docker, run `bash ledger/fabric/network.sh up`, then demo/test_fabric_ledger.py
(17/17). Then tell me what you plan to change before changing it."
