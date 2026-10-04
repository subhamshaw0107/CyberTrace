# Air-gapped deployment guide — PS 26237

Everything below was run on the development machine (Windows 11, Python 3.14.4,
Docker Desktop 29.3.1). Numbers are measured, not estimated; anything untested is
marked **untested**.

The system needs no internet at run time. It needs no cloud KMS (keys are generated
and held locally) and no public blockchain (the ledger is a private, permissioned
Fabric network, or the in-process simulation).

---

## 1. Offline installation bundle

Build the bundle on a connected staging machine, copy it in on removable media,
install on the air-gapped host. Nothing below calls out to a network at install time.

### 1.1 What goes in the bundle

| Item | How to obtain on the staging machine | Size (measured) |
|---|---|---|
| Python 3.12+ installer | vendor's offline installer | ~30 MB |
| Python wheels | `pip download -d wheels liboqs-python opencv-python numpy cryptography pillow pymupdf flask` | ~120 MB |
| liboqs shared library | build once per target OS (section 1.2) | 1.1 MB (`oqs.dll`, ML-KEM+ML-DSA only) |
| This repository | copy the working tree | ~25 MB incl. vendored Go modules and test scans |
| Docker images (only if using the Fabric ledger) | `docker save hyperledger/fabric-peer:2.5 hyperledger/fabric-orderer:2.5 hyperledger/fabric-tools:2.5 ps26237/provenance-cc:latest -o fabric-images.tar` | ~1.6 GB |

Pinned versions this was tested with: `liboqs 0.16.0`, `liboqs-python 0.16.0`,
`cryptography 46.0.7`, `numpy 2.4.4`, `opencv-python 5.0.0.93`, `pillow 12.3.0`,
`pymupdf 1.28.2`, `Flask 3.1.3`, Fabric `2.5`.

### 1.2 Building liboqs for the bundle

`pip install liboqs-python` only installs the Python wrapper. If it cannot find the
compiled library at import time it tries to **git-clone and build liboqs**, which fails
(and must fail) on an air-gapped host. So ship the compiled library.

On the staging machine (this is exactly what was done here, on Windows with the
VS 2026 Build Tools — a Linux host uses the same commands with `gcc`/`make`):

```bash
git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
      -DCMAKE_INSTALL_PREFIX=/opt/oqs
cmake --build build && cmake --install build
```

Windows notes learned the hard way: run this from a `vcvars64.bat` shell (cmake and the
compiler are not on PATH otherwise), and build in a short path such as `C:\oqsb` —
a long path exceeds the Windows object-path limit and the build fails.

On the air-gapped host, set `OQS_INSTALL_PATH` to the directory holding `bin/oqs.dll`
(or `lib/liboqs.so`) before starting anything. **Verify the wrapper never reaches the
network** — if `crypto/pqc.py` imports successfully, liboqs was found locally; if it
tries to clone, the import fails loudly instead of silently falling back to classical
crypto (there is no classical fallback).

### 1.3 Install

```bash
pip install --no-index --find-links=wheels liboqs-python opencv-python numpy cryptography pillow pymupdf flask
export OQS_INSTALL_PATH=/opt/oqs
python demo/test_requirements.py      # expect 17/17
python demo/test_app.py               # expect 24/24
```

For the Fabric ledger: `docker load -i fabric-images.tar`, then
`bash ledger/fabric/network.sh up`. The chaincode's Go dependencies are vendored in
`ledger/fabric/chaincode/provenance/vendor`, so its image builds with no network;
the only other image needed for that build is `golang:alpine` (include it in the tar).

---

## 2. Recipient private keys: hardware tokens and HSMs

**Current state (prototype):** secret keys live in
`<workspace>/identities/<id>.json`, encrypted with AES-256-GCM under a scrypt-derived
key (N=2^15, r=8, p=1) from the recipient's passphrase. They are decrypted into process
memory for each decryption. This is software protection only: anyone with the file and
the passphrase has the key, and the key is briefly recoverable from a memory dump.

**What a real deployment needs**, in order of increasing assurance:

1. **OS-level key storage** — smallest change: keep the same file format but store the
   passphrase-derived key in the platform keystore (Windows DPAPI/CNG, Linux kernel keyring).
   Stops casual file copying; does not stop a compromised host.
2. **Smart card / hardware token per recipient** — the signing key never leaves the token;
   the user's PIN authorises each signature. This is the right fit for the *signing* key
   (ML-DSA-65), because non-repudiation is exactly the property a token protects: a
   signature then proves possession of the token, not just of a file.
3. **Network HSM** for organisational keys, with the same argument.

**The blocker, stated honestly:** ML-DSA (FIPS 204) and ML-KEM (FIPS 203) support in
PKCS#11 tokens and HSMs is new and thin. PKCS#11 3.2 (2025) defines the mechanisms, and
vendor/firmware support is arriving but is not something to assume. Before committing:
confirm with the vendor that the device does **ML-DSA-65 and ML-KEM-768 in hardware**,
not just RSA/ECC.

**Interim option if tokens are unavailable:** keep ML-DSA keys in a hardware token only
if it supports the algorithm; otherwise keep them in software (as now) and compensate with
full-disk encryption, a strong passphrase policy, and per-workstation access control.
Write the choice into the threat model rather than leaving it implied. The code isolates
this cleanly: only `app/service.py::_unlock` and `crypto/pqc.py` touch private keys, so a
PKCS#11 backend replaces one function plus the `MLDSA.sign` call path.

**Fabric identities are separate and also classical.** Peer, orderer and TLS certificates
use ECDSA P-256 (Fabric's own crypto), and this deployment generates them with
`cryptogen`, which is a **test tool**. Production: issue them from a Fabric CA or an
offline organisational CA, one administrator per organisation, and store those keys in
the same hardware-backed way.

---

## 3. Network topology for the air-gapped ledger

```
              ┌──────────────── air-gapped LAN (no route to any external network) ────────────────┐
              │                                                                                   │
  ┌───────────┴───────────┐   ┌───────────────────┐   ┌──────────────────┐   ┌───────────────────┐
  │ SenderOrg peer        │   │ AuditorOrg peer   │   │ SecurityOrg peer │   │ BackupOrg peer    │
  │ + orderer node        │   │ (separate admin)  │   │ (separate admin) │   │ (offsite / vault) │
  └───────────┬───────────┘   └─────────┬─────────┘   └────────┬─────────┘   └─────────┬─────────┘
              │      gRPC/TLS 7051 (peer), 7050 (orderer), 7053 (orderer admin)        │
              └───────────────────────────┬───────────────────────────────────────────┘
                                          │
                 ┌────────────────────────┴────────────────────────┐
                 │ Operator workstations (sender / recipients /     │
                 │ investigator) running ps26237 CLI or local web UI│
                 └─────────────────────────────────────────────────┘
```

Rules that make the "no single administrator" property real:

- **One organisation per administrative authority.** Four peers under one administrator
  is theatre: that person can change all four. The endorsement policy is `OutOf(3, ...)`,
  so an attacker must compromise **three separate organisations** to alter history.
- **Orderers:** this prototype runs a single Raft orderer. It cannot forge endorsements,
  but it can delay or censor. Production: at least 3 (ideally 5) orderer nodes run by
  different organisations.
- **Offsite/backup peer** on a separate power and physical security domain, ideally in a
  different building, so a physical incident cannot take out the quorum.
- **Ports:** only 7050/7051/7053 between ledger hosts, plus SSH/management from an admin
  segment. No outbound route. TLS is mutual between peers and orderer.
- **Operator workstations** never need to reach the internet; the CLI and web UI talk to
  the peers only. The web UI binds to `127.0.0.1` and has **no authentication** — treat it
  as a local operator tool behind the host's own login, or put it behind a reverse proxy
  with client certificates (**untested**).
- **Time:** ledger records carry timestamps used as evidence. Run a local NTP source on
  the air-gapped LAN; without it, host clocks drift and timestamps weaken as evidence.

---

## 4. Performance and scale (measured on the development machine)

Measured with the included test suites; hardware: Windows 11 laptop, Docker Desktop with
8 GB RAM and 16 CPUs.

**Cryptography** (`crypto/pqc.py`, liboqs 0.16.0, average of 100 runs):

| Operation | Time |
|---|---|
| ML-KEM-768 keygen | 0.05 ms |
| ML-DSA-65 sign | 0.32 ms |
| ML-DSA-65 verify | 0.09 ms |

**Encrypt once, distribute to many** (2 MB document):

| Recipients | Encrypt time | Package size |
|---|---|---|
| 10 | 20 ms | 2.68 MB |
| 100 | 34 ms | 2.82 MB |

The ciphertext is shared; each extra recipient adds only a ~1.5 kB key wrap. Recipient
count is not a practical limit — thousands are fine.

**Per-decryption cost** (1000x754 scan, `demo/test_app.py`): ~250 ms total for
decrypt + watermark + sign + commit to the simulated ledger. Against the Fabric ledger the
commit itself is 1.4-2.0 s (`demo/test_fabric_ledger.py`), dominated by driving the peer
CLI through `docker exec`; a native gateway client would cut this substantially
(**untested**).

**Watermarking**: embedding is ~50 ms for a 1 MP image. PDFs are rasterised at 150 DPI:
about 0.4 MB per A4 page in the output file, and roughly 0.4 s per page to embed.

**Forensic trace**: 0.02-0.5 s when the leaked copy is untransformed or only
compressed/cropped; **13-24 s** when a rotation/scale search is needed. The search is
single-threaded and parallelises trivially if needed (**untested**).

**Ledger growth** (measured): one decryption record is **10.9 kB** of JSON — dominated by
the ML-DSA-65 signature (3309 B) and public key (1952 B) in hex. Each of the 4 nodes keeps
a copy, so **~27 kB of total storage per decryption event** (before Fabric's own block
overhead).

| Decryption events | Per node | All 4 nodes |
|---|---|---|
| 10,000 | 109 MB | 436 MB |
| 100,000 | 1.1 GB | 4.4 GB |
| 1,000,000 | 10.9 GB | 43.6 GB |

Practical guidance: a 500 GB disk per peer covers about 10 million decryption events with
room to spare. Two cheap reductions if that ever matters: store the signature in binary
rather than hex (saves ~40%), and store the recipient's public key once in the key
registry instead of in every record (saves ~3.9 kB per record, ~36%). Neither is
implemented — the current schema favours records that are self-contained for forensics.

**Commit throughput**: the simulated ledger commits at 4.5 ms per record (4 nodes, one
process). Fabric here is ~1.4-2.0 s per record through the CLI; Fabric itself sustains
far more, so this ceiling is the client, not the ledger (**untested** at scale).

---

## 5. Operational checklist

- [ ] `OQS_INSTALL_PATH` set; `python -c "import oqs; print(oqs.oqs_version())"` prints 0.16.0 with no network access
- [ ] `python demo/test_requirements.py` → 17/17
- [ ] `python demo/test_app.py` → 24/24
- [ ] `bash ledger/fabric/network.sh up && python demo/test_fabric_ledger.py` → 17/17 (if using Fabric)
- [ ] Each organisation's peer administered by a different person; credentials not shared
- [ ] Recipient identity passphrases set per person; key files backed up (losing them means
      past records can still be verified, but that recipient can no longer decrypt)
- [ ] Local NTP running; host clocks agree
- [ ] Workspace directory (`identities/`, `ledger_sim.pkl`) included in the backup policy
- [ ] Recipients briefed: every decryption is recorded and attributable — this is the point
