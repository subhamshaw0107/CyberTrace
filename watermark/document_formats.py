"""
watermark/document_formats.py
===============================

Applies the per-session watermark to whole documents, not just pixel arrays.

Supported:
  - PNG / JPEG  : watermark embedded directly, re-encoded in the same format
                  (JPEG at quality 95).
  - PDF         : each page rendered to an image at PDF_DPI, watermarked, and
                  written into a new PDF with the original page sizes.

SCOPE DECISION -- Office documents (docx/pptx/xlsx) are NOT supported directly.
They must be converted to PDF before encryption (e.g. LibreOffice headless,
which runs offline). Reasons: Office files have no single rendering (layout
depends on fonts and the application), so a pixel-domain watermark embedded
in one rendering says nothing about what another viewer shows; and embedding
inside the XML/zip structure would be stripped by a simple copy-paste of the
text. Converting to PDF fixes the rendering the watermark is bound to.

TRADE-OFF FOR PDFs (stated plainly): the watermarked PDF's pages are images.
Text is no longer selectable or searchable, and files get larger. A vector
text layer is deliberately NOT kept: an untouched text layer could be copied
out without the watermark, which defeats the purpose.
"""

from __future__ import annotations
from dataclasses import dataclass, field

import cv2
import numpy as np

from watermark.dct_watermark import embed_watermark, extract_watermark_detailed

PDF_DPI = 150
PDF_PAGE_JPEG_QUALITY = 92

OFFICE_MAGIC = b"PK\x03\x04"


class UnsupportedFormat(ValueError):
    pass


def detect_format(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.lstrip()[:5] == b"%PDF-":
        return "pdf"
    if data.startswith(OFFICE_MAGIC):
        raise UnsupportedFormat("Office/zip documents are not supported directly: convert to PDF first "
                                "(e.g. `soffice --headless --convert-to pdf file.docx`).")
    raise UnsupportedFormat("Unsupported document format (supported: PNG, JPEG, PDF).")


EXTENSIONS = {"png": ".png", "jpeg": ".jpg", "pdf": ".pdf"}


def embed_document(data: bytes, watermark_id: bytes) -> tuple[bytes, str]:
    """Returns (watermarked document bytes, format)."""
    fmt = detect_format(data)
    if fmt in ("png", "jpeg"):
        img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            raise UnsupportedFormat("Could not decode image")
        wm, _ = embed_watermark(img, watermark_id)
        if fmt == "png":
            ok, enc = cv2.imencode(".png", wm)
        else:
            ok, enc = cv2.imencode(".jpg", wm, [cv2.IMWRITE_JPEG_QUALITY, 95])
        return enc.tobytes(), fmt
    return _embed_pdf(data, watermark_id), fmt


def _render_pages(doc) -> list[np.ndarray]:
    import pymupdf
    pages = []
    for page in doc:
        pix = page.get_pixmap(dpi=PDF_DPI, colorspace=pymupdf.csRGB, alpha=False)
        arr = np.frombuffer(pix.samples, np.uint8).reshape(pix.height, pix.width, 3)
        pages.append(cv2.cvtColor(arr, cv2.COLOR_RGB2BGR))
    return pages


def _embed_pdf(data: bytes, watermark_id: bytes) -> bytes:
    import pymupdf
    src = pymupdf.open(stream=data, filetype="pdf")
    out = pymupdf.open()
    for page, img in zip(src, _render_pages(src)):
        wm, _ = embed_watermark(img, watermark_id)
        # JPEG q92 keeps watermarked PDFs ~10x smaller than PNG; measured to survive
        # re-compression well below this quality (see demo/test_watermark_robustness.py).
        ok, enc = cv2.imencode(".jpg", wm, [cv2.IMWRITE_JPEG_QUALITY, PDF_PAGE_JPEG_QUALITY])
        new = out.new_page(width=page.rect.width, height=page.rect.height)
        new.insert_image(new.rect, stream=enc.tobytes())
    return out.tobytes(deflate=True, garbage=3)


@dataclass
class Candidate:
    source: str            # "image" or "page N"
    watermark_id: bytes
    confidence: float      # 0..1, see extract_watermark_detailed
    info: dict = field(default_factory=dict)


def extract_candidates(data: bytes) -> list[Candidate]:
    """Extracts a watermark candidate from an image, or one per PDF page.
    Callers look each candidate up in the ledger."""
    fmt = detect_format(data)
    if fmt in ("png", "jpeg"):
        img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            raise UnsupportedFormat("Could not decode image")
        wm, info = extract_watermark_detailed(img)
        return [Candidate("image", wm, info["confidence"], info)]
    import pymupdf
    doc = pymupdf.open(stream=data, filetype="pdf")
    cands = []
    for i, img in enumerate(_render_pages(doc), 1):
        wm, info = extract_watermark_detailed(img)
        cands.append(Candidate(f"page {i}", wm, info["confidence"], info))
    return sorted(cands, key=lambda c: -c.confidence)
