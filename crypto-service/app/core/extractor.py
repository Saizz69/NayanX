"""
Forensic Extraction Engine for Leaked Documents.

Extracts real bits from uploaded PDF bytes:
1. Wording Channel:
   - Matches each slot's alternate wording pair (alt_a, alt_b) against extracted text.
   - alt_a matched -> 0, alt_b matched -> 1, collision/missing -> None (erasure).
2. Layout Channel:
   - Parses word bounding boxes and horizontal inter-word gaps using pypdf visitor.
   - Compares gaps against reference layout re-rendered with all-zero variants.
   - Delta within tolerance -> 0 or 1; mismatch/shift/re-typeset -> None (erasure).
3. Output observed vector with erasures explicitly marked; never invents bits.
"""

from __future__ import annotations
import io
from typing import List, Optional, Dict, Any, Tuple
from pypdf import PdfReader
from reportlab.pdfgen import canvas

from app.core.document_variants import (
    StructuredDocument,
    FONT_FAMILY,
    DEFAULT_DELTA_PT,
)


GAP_TOLERANCE_PT = 0.15


def extract_wording_channel(
    pdf_bytes: bytes, wording_slots: List[Tuple[int, str, str]]
) -> Tuple[List[Optional[int]], int, int]:
    """
    Extracts wording bits from leaked PDF.
    Returns (bits_list, valid_count, erasure_count).
    """
    reader = PdfReader(io.BytesIO(pdf_bytes))
    full_text = "\n".join(page.extract_text() or "" for page in reader.pages)

    extracted_bits: List[Optional[int]] = []
    valid_count = 0
    erasure_count = 0

    for slot_idx, alt_a, alt_b in wording_slots:
        has_a = alt_a in full_text
        has_b = alt_b in full_text

        if has_a and not has_b:
            extracted_bits.append(0)
            valid_count += 1
        elif has_b and not has_a:
            extracted_bits.append(1)
            valid_count += 1
        else:
            # Missing or conflicting (both altered/merged)
            extracted_bits.append(None)
            erasure_count += 1

    return extracted_bits, valid_count, erasure_count


def _extract_body_word_gaps(pdf_bytes: bytes) -> List[Tuple[str, str, float]]:
    """
    Extracts (word1, word2, gap_pt) between adjacent words on the same line in body text.
    Filters out header banner and footer.
    """
    reader = PdfReader(io.BytesIO(pdf_bytes))
    words: List[Tuple[str, float, float, float]] = []

    def visitor(text: str, cm: Any, tm: Any, font_dict: Any, font_size: float):
        t_clean = text.strip()
        # Filter for body text: y between 80.0 (above footer) and 700.0 (below header)
        if t_clean and float(tm[5]) <= 700.0 and float(tm[5]) >= 80.0:
            words.append((t_clean, float(tm[4]), float(tm[5]), float(font_size)))

    for page in reader.pages:
        page.extract_text(visitor_text=visitor)

    c_dummy = canvas.Canvas(io.BytesIO())
    gaps: List[Tuple[str, str, float]] = []

    for i in range(len(words) - 1):
        w1, x1, y1, s1 = words[i]
        w2, x2, y2, s2 = words[i + 1]

        # Adjacent words on the same line
        if abs(y1 - y2) < 2.0 and x2 > x1:
            w_len = c_dummy.stringWidth(w1, FONT_FAMILY, s1)
            gap = x2 - (x1 + w_len)
            gaps.append((w1, w2, gap))

    return gaps


def extract_layout_channel(
    leaked_pdf_bytes: bytes,
    ref_pdf_bytes: bytes,
    expected_layout_slots: int,
    delta_pt: float = DEFAULT_DELTA_PT,
    tolerance_pt: float = GAP_TOLERANCE_PT,
) -> Tuple[List[Optional[int]], int, int]:
    """
    Extracts layout bits by comparing observed gaps against reference all-zero layout gaps.
    Returns (bits_list, valid_count, erasure_count).
    """
    obs_gaps = _extract_body_word_gaps(leaked_pdf_bytes)
    ref_gaps = _extract_body_word_gaps(ref_pdf_bytes)

    extracted_bits: List[Optional[int]] = []
    valid_count = 0
    erasure_count = 0

    num_slots = expected_layout_slots

    for i in range(num_slots):
        if i >= len(obs_gaps) or i >= len(ref_gaps):
            extracted_bits.append(None)
            erasure_count += 1
            continue

        w1_obs, w2_obs, g_obs = obs_gaps[i]
        w1_ref, w2_ref, g_ref = ref_gaps[i]

        # Words should correspond
        delta_diff = g_obs - g_ref

        if abs(delta_diff) <= tolerance_pt:
            # 0 bit: standard nominal gap
            extracted_bits.append(0)
            valid_count += 1
        elif abs(delta_diff - delta_pt) <= tolerance_pt:
            # 1 bit: dilated gap (+delta_pt)
            extracted_bits.append(1)
            valid_count += 1
        else:
            # Layout corrupted, re-typeset, or shifted
            extracted_bits.append(None)
            erasure_count += 1

    return extracted_bits, valid_count, erasure_count


def extract_document_slots(
    leaked_pdf_bytes: bytes,
    structured_doc: StructuredDocument,
    ref_pdf_bytes: bytes,
) -> Dict[str, Any]:
    """
    Extracts all slots (wording + layout) from a leaked PDF.
    Outputs observed vector with erasures explicitly marked.
    """
    wording_bits, w_valid, w_erased = extract_wording_channel(
        leaked_pdf_bytes, structured_doc.wording_slots
    )

    layout_bits, l_valid, l_erased = extract_layout_channel(
        leaked_pdf_bytes,
        ref_pdf_bytes,
        expected_layout_slots=structured_doc.layout_slots_count,
        delta_pt=structured_doc.delta_pt,
    )

    observed_vector: List[Optional[int]] = wording_bits + layout_bits
    total_slots = len(observed_vector)
    total_erased = w_erased + l_erased
    total_valid = w_valid + l_valid
    erasure_rate = (total_erased / total_slots) if total_slots > 0 else 1.0

    return {
        "observed_vector": observed_vector,
        "total_slots": total_slots,
        "wording_slots_count": len(wording_bits),
        "wording_valid": w_valid,
        "wording_erased": w_erased,
        "layout_slots_count": len(layout_bits),
        "layout_valid": l_valid,
        "layout_erased": l_erased,
        "total_valid": total_valid,
        "total_erased": total_erased,
        "erasure_rate": round(erasure_rate, 4),
    }
