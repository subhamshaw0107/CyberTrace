"""
watermark/dct_watermark.py
============================

Invisible forensic watermarking via DCT (Discrete Cosine Transform)
mid-frequency coefficient embedding, with geometric resynchronisation.

EMBEDDING
---------
- The luminance channel is split into 8x8 blocks (as in JPEG).
- One bit is carried per block by forcing the sign of the difference between
  two mid-frequency DCT coefficients (COEF_A - COEF_B) with margin
  EMBED_STRENGTH. Mid frequencies are the usual compromise: low frequencies
  are visible, high frequencies are destroyed by JPEG.
- Blocks are laid out as a repeating TILE x TILE-block tile (16x16 blocks =
  128x128 px). Each tile carries the 128 payload bits (the watermark ID) and
  128 fixed, publicly known SYNC bits. Every bit is repeated in every tile.
- Embedding is repeated EMBED_PASSES times so that nudges lost to clipping
  at 0/255 (very common on white paper) are pushed back in.

EXTRACTION
----------
The leaked image may be cropped, rescaled or rotated, so the block grid and
tile origin are unknown. The extractor:
  1. correlates the image with the (COEF_A - COEF_B) DCT basis at every pixel
     (one filter2D call), which gives the block statistic for all 64 possible
     8x8 grid offsets at once;
  2. folds block votes into tile positions and scores all 256 tile shifts at
     once by FFT cross-correlation with the known sync bits;
  3. if the untransformed image doesn't lock on, searches rotation and scale
     on image patches, refines the best candidate, then decodes by combining
     votes from several patches (each individually aligned), which also
     tolerates mild perspective distortion.
The payload is decoded only from the alignment whose sync bits match.

The payload is an opaque random session ID; the mapping to recipient lives
only in the ledger. Measured robustness (all attacks, real scans, PDF
renders): see demo/test_watermark_robustness.py and README section 5.
"""

from __future__ import annotations
import hashlib
import numpy as np
import cv2

BLOCK_SIZE = 8
COEF_A = (2, 3)          # (row, col) in the 8x8 DCT block
COEF_B = (3, 2)
EMBED_STRENGTH = 14.0    # minimum |A - B| margin forced per block
EMBED_PASSES = 3
WATERMARK_BITS = 128
TILE = 16                # tile = TILE x TILE blocks, holds payload + sync bits
N_POS = TILE * TILE      # 256 positions
SYNC_BITS = np.unpackbits(np.frombuffer(hashlib.sha3_256(b"PS26237-WATERMARK-SYNC-v2").digest()[:16], np.uint8))

# Extraction search parameters
LOCK_Z = 9.0             # sync z-score at which alignment is accepted without geometric search
PATCH = 384              # patch size (px, original scale) for the coarse geometric search
BIG_PATCH = 768          # patch size for re-scoring and refinement
COARSE_CANDIDATES = 12   # coarse hypotheses re-scored on the bigger patch
# Screenshots and re-renders usually land on a common resampling ratio. These are
# tried first at FULL-image sensitivity, which recovers weak signals (heavy
# downscale + recompression) that the patch search cannot see.
HINT_SCALES = sorted({1.0, 0.25, 1 / 3, 0.5, 0.6, 2 / 3, 0.72, 0.75, 0.8, 0.9, 1.1, 1.25, 4 / 3, 1.5, 2.0,
                      72 / 150, 96 / 150, 110 / 150, 120 / 150, 200 / 150, 300 / 150, 150 / 96, 150 / 72})
HINT_ANGLES = (0.0, -0.5, 0.5, -1.0, 1.0)
MAX_WARP_SIDE = 2600     # skip hypotheses that would warp the image larger than this
ANGLES = np.arange(-6.0, 6.01, 0.5)
SCALES = np.geomspace(0.45, 2.25, 136)   # ~1.2% steps


def _bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def _bits_to_bytes(bits: np.ndarray) -> bytes:
    nbytes = len(bits) // 8
    return np.packbits(bits[: nbytes * 8]).tobytes()


def generate_watermark_id(recipient_id: str, document_id: str, session_nonce: bytes) -> bytes:
    """Fresh, unique 16-byte (128-bit) watermark ID per decryption session."""
    h = hashlib.sha3_256()
    h.update(recipient_id.encode())
    h.update(b"|")
    h.update(document_id.encode())
    h.update(b"|")
    h.update(session_nonce)
    return h.digest()[:16]


def _dct_basis(u: int, v: int) -> np.ndarray:
    c = lambda k: np.sqrt(1 / 8) if k == 0 else np.sqrt(2 / 8)
    y = np.arange(8)[:, None]
    x = np.arange(8)[None, :]
    return (c(u) * c(v) * np.cos((2 * y + 1) * u * np.pi / 16) * np.cos((2 * x + 1) * v * np.pi / 16)).astype(np.float32)


KERNEL = _dct_basis(*COEF_A) - _dct_basis(*COEF_B)   # <block, KERNEL> = coefA - coefB (orthonormal DCT)


def _luma(image: np.ndarray):
    if image.ndim == 3:
        ycrcb = cv2.cvtColor(image, cv2.COLOR_BGR2YCrCb)
        return ycrcb, ycrcb[:, :, 0].astype(np.float32)
    return None, image.astype(np.float32)


def _tile_signs(watermark_id: bytes) -> np.ndarray:
    bits = np.concatenate([_bytes_to_bits(watermark_id), SYNC_BITS])
    return (bits.astype(np.float32) * 2 - 1).reshape(TILE, TILE)


def embed_watermark(image: np.ndarray, watermark_id: bytes):
    """image: grayscale or BGR uint8. watermark_id: 16 bytes.
    Returns (watermarked image, redundancy = full tiles' worth of repeats per bit)."""
    if len(watermark_id) * 8 != WATERMARK_BITS:
        raise ValueError("watermark_id must be 16 bytes")
    ycrcb, y = _luma(image)
    h, w = y.shape
    nby, nbx = h // BLOCK_SIZE, w // BLOCK_SIZE
    if nby * nbx < N_POS:
        raise ValueError(f"Image too small: {nby * nbx} blocks, need at least {N_POS}")

    signs = _tile_signs(watermark_id)
    t = signs[np.arange(nby)[:, None] % TILE, np.arange(nbx)[None, :] % TILE]   # (nby, nbx)
    hh, ww = nby * BLOCK_SIZE, nbx * BLOCK_SIZE
    work = y.copy()
    for _ in range(EMBED_PASSES):
        region = work[:hh, :ww]
        blocks = region.reshape(nby, 8, nbx, 8).transpose(0, 2, 1, 3)           # (nby, nbx, 8, 8)
        d = np.einsum("abij,ij->ab", blocks, KERNEL)
        need = np.maximum(0.0, EMBED_STRENGTH - t * d)                           # shortfall per block
        if not need.any():
            break
        # adding alpha*KERNEL changes d by alpha*|KERNEL|^2 = 2*alpha
        alpha = t * need / 2.0
        blocks = blocks + alpha[:, :, None, None] * KERNEL[None, None]
        work[:hh, :ww] = np.clip(blocks.transpose(0, 2, 1, 3).reshape(hh, ww), 0, 255)

    out = np.clip(np.round(work), 0, 255).astype(np.uint8)
    if ycrcb is not None:
        ycrcb = ycrcb.copy()
        ycrcb[:, :, 0] = out
        result = cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2BGR)
    else:
        result = out
    return result, (nby * nbx) // N_POS


# ---------------------------------------------------------------- extraction

_SYNC_TEMPLATE = np.zeros((TILE, TILE), np.float32)
_SYNC_TEMPLATE.flat[WATERMARK_BITS:] = SYNC_BITS.astype(np.float32) * 2 - 1
_SYNC_MASK = (_SYNC_TEMPLATE != 0).astype(np.float32)


def _fold_fast(y: np.ndarray):
    """Same as _fold for a square patch whose side is a multiple of TILE*BLOCK_SIZE (128 px):
    a pure reshape/sum, ~20x faster. Used inside the geometric search."""
    d = cv2.filter2D(y, cv2.CV_32F, KERNEL, anchor=(0, 0), borderType=cv2.BORDER_REPLICATE)
    n = y.shape[0] // (TILE * BLOCK_SIZE)
    v = np.tanh(d / EMBED_STRENGTH).reshape(n, TILE, BLOCK_SIZE, n, TILE, BLOCK_SIZE)
    F = v.sum(axis=(0, 3)).transpose(1, 3, 0, 2).reshape(64, TILE, TILE)
    N = np.full_like(F, n * n)
    return F, N


def _fold(y: np.ndarray):
    """Returns per-offset tile vote sums F (64, TILE, TILE) and counts N (64, TILE, TILE)."""
    d = cv2.filter2D(y, cv2.CV_32F, KERNEL, anchor=(0, 0), borderType=cv2.BORDER_REPLICATE)
    h, w = y.shape
    v = np.tanh(d / EMBED_STRENGTH)
    F = np.zeros((64, N_POS), np.float32)
    N = np.zeros((64, N_POS), np.float32)
    for oy in range(8):
        for ox in range(8):
            g = v[oy:h - 7:8, ox:w - 7:8]
            if g.size == 0:
                continue
            p = ((np.arange(g.shape[0]) % TILE)[:, None] * TILE + (np.arange(g.shape[1]) % TILE)[None, :]).ravel()
            F[oy * 8 + ox] = np.bincount(p, weights=g.ravel(), minlength=N_POS)
            N[oy * 8 + ox] = np.bincount(p, minlength=N_POS)
    return F.reshape(64, TILE, TILE), N.reshape(64, TILE, TILE)


def _best_alignment(F: np.ndarray, N: np.ndarray):
    """Scores every (grid offset, tile shift) by sync correlation.
    Returns (z, offset_index, ty, tx). z is a z-score: sum of sync-agreeing votes
    divided by the noise std expected if votes were random +-1."""
    # corr[k, ty, tx] = sum_ij F[k, i, j] * T[(i+ty)%TILE, (j+tx)%TILE]
    Ff = np.fft.fft2(F)
    corr = np.real(np.fft.ifft2(np.conj(np.fft.fft2(_SYNC_TEMPLATE))[None] * Ff))
    cnt = np.real(np.fft.ifft2(np.conj(np.fft.fft2(_SYNC_MASK))[None] * np.fft.fft2(N)))
    z = corr / np.sqrt(np.maximum(cnt, 1.0))
    # z indices are the (negative) shift such that tile position i in the image = template position i + shift
    k, ty, tx = np.unravel_index(np.argmax(z), z.shape)
    return float(z[k, ty, tx]), int(k), int(ty), int(tx)


def _reindex(tile: np.ndarray, ty: int, tx: int) -> np.ndarray:
    out = np.empty_like(tile)
    idx_i = (np.arange(TILE) - ty) % TILE   # template position = image position - shift
    idx_j = (np.arange(TILE) - tx) % TILE
    out[np.ix_(idx_i, idx_j)] = tile
    return out


def _warp(y: np.ndarray, cx: float, cy: float, angle: float, s: float, size_w: int, size_h: int) -> np.ndarray:
    """Samples a size_w x size_h window (in ORIGINAL-scale pixels) centred on (cx, cy) of the
    leaked image, undoing a rotation by `angle` degrees and a scale by `s`."""
    m = cv2.getRotationMatrix2D((cx, cy), angle, 1.0 / s)
    m[0, 2] += size_w / 2 - cx
    m[1, 2] += size_h / 2 - cy
    return cv2.warpAffine(y, m, (size_w, size_h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)


def _score(y, cx, cy, a, sc, patch) -> float:
    return _best_alignment(*_fold_fast(_warp(y, cx, cy, a, sc, patch, patch)))[0]


def _search(y: np.ndarray, cx: float, cy: float, angles, scales, patch: int,
            stop_z: float = float("inf"), topk: int = 1):
    """Grid search over rotation x scale, most likely values (angle 0, scale 1) first.
    Returns the best (z, angle, scale), or the topk best when topk > 1."""
    angles = sorted(angles, key=abs)
    scales = sorted(scales, key=lambda v: abs(np.log(v)))
    out = []
    for sc in scales:
        for a in angles:
            z = _score(y, cx, cy, a, sc, patch)
            out.append((z, float(a), float(sc)))
            if z >= stop_z:
                return sorted(out, reverse=True)[:topk] if topk > 1 else max(out)
    out.sort(reverse=True)
    return out[:topk] if topk > 1 else out[0]


def extract_watermark_detailed(image: np.ndarray, n_bits: int = WATERMARK_BITS):
    """Returns (watermark_id bytes, info). info has 'confidence' in [0, 1]
    (fraction of the 128 sync bits recovered correctly, rescaled so random = 0),
    'sync_z', 'angle', 'scale', and 'method'."""
    if n_bits != WATERMARK_BITS:
        raise ValueError("only 128-bit watermarks are supported")
    _, y = _luma(image)
    h, w = y.shape

    # 1. no geometric change (lossless, JPEG, noise, crops)
    F, N = _fold(y)
    z, k, ty, tx = _best_alignment(F, N)
    if z >= LOCK_Z:
        return _decode(_reindex(F[k], ty, tx), {"sync_z": z, "angle": 0.0, "scale": 1.0, "method": "direct"})

    cx, cy = w / 2, h / 2
    patch = PATCH

    # 2. common resampling ratios, scored on the whole image (cheap: a few dozen folds)
    best_hint = (-1e9, 0.0, 1.0, None)
    for sc in HINT_SCALES:
        if max(w, h) / sc > MAX_WARP_SIDE:
            continue
        for a in HINT_ANGLES:
            Fh, Nh = _fold(_warp(y, cx, cy, a, sc, int(w / sc), int(h / sc)))
            zh, kh, tyh, txh = _best_alignment(Fh, Nh)
            if zh > best_hint[0]:
                best_hint = (zh, a, sc, _reindex(Fh[kh], tyh, txh))
    if best_hint[0] >= LOCK_Z:
        return _decode(best_hint[3], {"sync_z": best_hint[0], "angle": best_hint[1], "scale": best_hint[2],
                                      "method": "resample-ratio hypothesis"})

    # 3. coarse rotation/scale search on the central patch
    # A weak signal (heavy rescale + recompression) can be invisible at this patch size,
    # so keep several candidates and re-score them on a larger patch, where a true
    # alignment separates from noise much more clearly.
    cands = _search(y, cx, cy, ANGLES, SCALES, patch, stop_z=2 * LOCK_Z, topk=COARSE_CANDIDATES)
    big0 = int(np.clip((0.9 * min(h, w) / cands[0][2]) // 128 * 128, patch, BIG_PATCH))
    coarse_z, a0, s0 = max((_score(y, cx, cy, a, sc, big0), a, sc) for _, a, sc in cands)

    # 4. refine on a bigger patch (side a multiple of 128 px)
    big = int(np.clip((0.9 * min(h, w) / s0) // 128 * 128, patch, BIG_PATCH))
    _, a1, s1 = _search(y, cx, cy, a0 + np.arange(-0.3, 0.31, 0.1), s0 * np.geomspace(0.985, 1.015, 13), big)

    # 5. decode. Two candidate decodes, best sync agreement wins:
    #    (a) the WHOLE image under one global alignment -- most votes when the leak is
    #        a uniform rotate/scale/crop;
    #    (b) several patches aligned independently -- survives mild perspective, where
    #        no single global alignment fits the whole page.
    cands = []
    side = int(max(TILE * BLOCK_SIZE, (min(h, w) / s1) // (TILE * BLOCK_SIZE) * (TILE * BLOCK_SIZE)))
    Ff, Nf = _fold(_warp(y, cx, cy, a1, s1, int(w / s1), int(h / s1)))
    zf, kf, tyf, txf = _best_alignment(Ff, Nf)
    cands.append((zf, _reindex(Ff[kf], tyf, txf), "search (full image)", a1, s1))
    if best_hint[3] is not None:
        cands.append((best_hint[0], best_hint[3], "resample-ratio hypothesis", best_hint[1], best_hint[2]))

    total = np.zeros((TILE, TILE), np.float32)
    zs = []
    for fx, fy in [(0.5, 0.5), (0.3, 0.3), (0.7, 0.3), (0.3, 0.7), (0.7, 0.7)]:
        px, py = w * fx, h * fy
        pz, pa, ps = _search(y, px, py, a1 + np.arange(-0.2, 0.21, 0.1), s1 * np.geomspace(0.99, 1.01, 5), patch)
        Fp, Np = _fold_fast(_warp(y, px, py, pa, ps, patch, patch))
        zp, kp, typ, txp = _best_alignment(Fp, Np)
        if zp >= 4.0:
            total += _reindex(Fp[kp], typ, txp)
            zs.append(zp)
    if zs:
        cands.append((float(np.sqrt(np.sum(np.square(zs)))), total, f"search ({len(zs)} patches)", a1, s1))

    # Independent decodes of the same watermark: pooling their votes (each normalised by
    # its own vote count) recovers more bits than trusting any single one.
    usable = [c for c in cands if _sync_agreement(c[1]) > 0.6]
    if len(usable) > 1:
        pooled = sum(c[1] / max(np.abs(c[1]).max(), 1e-6) for c in usable)
        cands = cands + [(max(c[0] for c in usable), pooled, "pooled " + "+".join(
            c[2].split(" (")[0] for c in usable), usable[0][3], usable[0][4])]
    best_z, best_tile, method, ba, bs = max(cands, key=lambda c: _sync_agreement(c[1]))
    return _decode(best_tile, {"sync_z": best_z, "angle": ba, "scale": bs, "method": method})


def _sync_agreement(tile: np.ndarray) -> float:
    flat = tile.ravel()
    return float(np.mean((flat[WATERMARK_BITS:] > 0).astype(np.uint8) == SYNC_BITS))


def _decode(tile: np.ndarray, info: dict):
    flat = tile.ravel()
    payload = (flat[:WATERMARK_BITS] > 0).astype(np.uint8)
    sync_ok = np.mean((flat[WATERMARK_BITS:] > 0).astype(np.uint8) == SYNC_BITS)
    info["sync_bit_agreement"] = float(sync_ok)
    info["confidence"] = float(max(0.0, 2 * sync_ok - 1))
    return _bits_to_bytes(payload), info


def extract_watermark(image: np.ndarray, n_bits: int = WATERMARK_BITS) -> bytes:
    """Recovers the 16-byte watermark ID from a (possibly degraded) image."""
    return extract_watermark_detailed(image, n_bits)[0]


def bit_error_rate(original_id: bytes, recovered_id: bytes) -> float:
    """Hamming distance / total bits -- used for robustness testing."""
    orig_bits = _bytes_to_bits(original_id)
    rec_bits = _bytes_to_bits(recovered_id)
    n = min(len(orig_bits), len(rec_bits))
    return float(np.sum(orig_bits[:n] != rec_bits[:n]) / n)
