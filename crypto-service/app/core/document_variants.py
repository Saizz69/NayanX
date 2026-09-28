"""
Structured Document & Content-Level Variant Engine.

Handles:
- Parsing structured text / markdown blocks containing {{a|b}} wording alternates.
- Wording slots: {{a|b}} (bit 0 = alternate a, bit 1 = alternate b).
- Layout slots: Inter-word horizontal gaps (bit 0 = standard gap, bit 1 = standard + delta pt).
- High-fidelity PDF rendering via ReportLab Canvas.
- Reference all-zero PDF layout generation for baseline gap extraction.
- Labelled metadata watermark injection as a secondary convenience tag.
"""

from __future__ import annotations
import io
import re
import json
from typing import List, Dict, Any, Tuple, Optional
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter

from app.core.tardos import estimate_collusion_capacity


DEFAULT_DELTA_PT = 0.35
NOMINAL_GAP_PT = 4.0
FONT_FAMILY = "Helvetica"
FONT_SIZE = 10.0
FONT_HEADING_SIZE = 14.0
LEFT_MARGIN = 54.0
TOP_MARGIN = 720.0
LINE_HEIGHT = 16.0
MAX_LINE_WIDTH = 500.0


WORDING_REGEX = re.compile(r"\{\{([^|{}]+)\|([^|{}]+)\}\}")


class StructuredDocument:
    """
    Parsed representation of a document containing wording and layout slots.
    """

    def __init__(self, raw_source: str | Dict[str, Any], delta_pt: float = DEFAULT_DELTA_PT):
        self.delta_pt = delta_pt
        self.title = "CLASSIFIED BRIEFING"
        self.classification = "TOP SECRET // AIR-GAPPED DISTRIBUTION"
        self.paragraphs: List[str] = []

        self._parse_source(raw_source)
        self._analyze_slots()

    def _parse_source(self, raw_source: str | Dict[str, Any]):
        if isinstance(raw_source, dict):
            self.title = raw_source.get("title", self.title)
            self.classification = raw_source.get("classification", self.classification)
            content = raw_source.get("content") or raw_source.get("paragraphs") or []
            if isinstance(content, str):
                self.paragraphs = [p.strip() for p in content.split("\n\n") if p.strip()]
            elif isinstance(content, list):
                self.paragraphs = [str(p).strip() for p in content if str(p).strip()]
        elif isinstance(raw_source, str):
            lines = raw_source.strip().split("\n")
            current_p: List[str] = []
            for line in lines:
                line_str = line.strip()
                if line_str.startswith("# "):
                    self.title = line_str[2:].strip()
                elif line_str.startswith("CLASSIFICATION:"):
                    self.classification = line_str.split(":", 1)[1].strip()
                elif not line_str:
                    if current_p:
                        self.paragraphs.append(" ".join(current_p))
                        current_p = []
                else:
                    current_p.append(line_str)
            if current_p:
                self.paragraphs.append(" ".join(current_p))

        if not self.paragraphs:
            self.paragraphs = [
                "This {{preliminary|initial}} forensic report provides {{crucial|vital}} telemetry.",
                "Authorized personnel must {{observe|maintain}} strict protocol during {{operation|execution}}.",
            ]

    def _analyze_slots(self):
        """
        Tokenizes paragraphs to count:
        1. Wording slots: {{a|b}}
        2. Layout slots: inter-word gaps in rendered lines
        """
        self.wording_slots: List[Tuple[int, str, str]] = []  # (slot_idx, alt_a, alt_b)
        self.tokenized_paragraphs: List[List[Dict[str, Any]]] = []

        slot_counter = 0
        for p in self.paragraphs:
            p_tokens: List[Dict[str, Any]] = []
            # Split paragraph into tokens while preserving {{a|b}}
            parts = re.split(r"(\{\{[^|{}]+\|[^|{}]+\}\}|\s+)", p)
            for part in parts:
                if not part or part.isspace():
                    continue
                m = WORDING_REGEX.match(part)
                if m:
                    alt_a, alt_b = m.group(1).strip(), m.group(2).strip()
                    p_tokens.append({
                        "type": "wording_slot",
                        "slot_idx": slot_counter,
                        "alt_a": alt_a,
                        "alt_b": alt_b,
                    })
                    self.wording_slots.append((slot_counter, alt_a, alt_b))
                    slot_counter += 1
                else:
                    p_tokens.append({
                        "type": "literal",
                        "text": part.strip(),
                    })
            self.tokenized_paragraphs.append(p_tokens)

        # Pre-wrap lines with nominal text (alt_a) to count layout gaps
        c_dummy = canvas.Canvas(io.BytesIO())
        c_dummy.setFont(FONT_FAMILY, FONT_SIZE)

        self.layout_slots_count = 0
        for p_tokens in self.tokenized_paragraphs:
            lines = self._wrap_tokens_into_lines(p_tokens, [0] * len(self.wording_slots), c_dummy)
            for line in lines:
                if len(line) > 1:
                    # Gaps between adjacent words
                    self.layout_slots_count += (len(line) - 1)

        self.total_slots = len(self.wording_slots) + self.layout_slots_count

    def _wrap_tokens_into_lines(
        self, tokens: List[Dict[str, Any]], wording_bits: List[int], c: canvas.Canvas
    ) -> List[List[Dict[str, Any]]]:
        """
        Greedy line breaking using token text.
        """
        lines: List[List[Dict[str, Any]]] = []
        current_line: List[Dict[str, Any]] = []
        current_width = 0.0

        for tok in tokens:
            if tok["type"] == "wording_slot":
                bit = wording_bits[tok["slot_idx"]] if tok["slot_idx"] < len(wording_bits) else 0
                word_str = tok["alt_b"] if bit == 1 else tok["alt_a"]
            else:
                word_str = tok["text"]

            w_len = c.stringWidth(word_str, FONT_FAMILY, FONT_SIZE)
            extra_gap = NOMINAL_GAP_PT if current_line else 0.0

            if current_width + extra_gap + w_len > MAX_LINE_WIDTH and current_line:
                lines.append(current_line)
                current_line = [{**tok, "rendered_text": word_str, "width": w_len}]
                current_width = w_len
            else:
                current_line.append({**tok, "rendered_text": word_str, "width": w_len})
                current_width += extra_gap + w_len

        if current_line:
            lines.append(current_line)

        return lines

    def get_capacity(self, target_fpr: float = 1e-3) -> Dict[str, Any]:
        """
        Returns slot counts per channel and max collusion size c supported at target_fpr.
        """
        return {
            "wording_slots": len(self.wording_slots),
            "layout_slots": self.layout_slots_count,
            "total_slots": self.total_slots,
            "delta_pt": self.delta_pt,
            "target_fpr": target_fpr,
            "largest_collusion_c": estimate_collusion_capacity(self.total_slots, target_fpr=target_fpr),
        }

    def render_pdf(
        self,
        codeword_bits: List[int],
        secondary_watermark_payload: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """
        Renders a PDF for given codeword bits:
        - codeword_bits[:len(wording_slots)] controls wording alternates.
        - codeword_bits[len(wording_slots):] controls layout inter-word gap deltas.
        - Injects secondary convenience metadata watermark if provided.
        """
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=letter)

        wording_count = len(self.wording_slots)
        wording_bits = codeword_bits[:wording_count] if len(codeword_bits) >= wording_count else [0] * wording_count
        layout_bits = codeword_bits[wording_count:]

        # Header banner
        c.setFillColor(colors.HexColor("#0f172a"))
        c.rect(0, 730, 612, 62, fill=True, stroke=False)
        c.setFillColor(colors.HexColor("#f8fafc"))
        c.setFont("Helvetica-Bold", 14)
        c.drawString(LEFT_MARGIN, 762, self.title)
        c.setFont("Helvetica", 9)
        c.drawString(LEFT_MARGIN, 744, f"CLASSIFICATION: {self.classification}")

        c.setFillColor(colors.HexColor("#0f172a"))
        c.setFont(FONT_FAMILY, FONT_SIZE)

        y = TOP_MARGIN - 20.0
        layout_slot_idx = 0

        for p_tokens in self.tokenized_paragraphs:
            lines = self._wrap_tokens_into_lines(p_tokens, wording_bits, c)
            for line in lines:
                x = LEFT_MARGIN
                for i, tok in enumerate(line):
                    word_str = tok["rendered_text"]
                    c.drawString(x, y, word_str)
                    x += tok["width"]

                    # If not the last word in line, advance by nominal gap + delta bit
                    if i < len(line) - 1:
                        has_delta = (
                            layout_slot_idx < len(layout_bits)
                            and layout_bits[layout_slot_idx] == 1
                        )
                        gap = NOMINAL_GAP_PT + (self.delta_pt if has_delta else 0.0)
                        x += gap
                        layout_slot_idx += 1

                y -= LINE_HEIGHT
            y -= (LINE_HEIGHT * 0.5)

        # Footer
        c.setStrokeColor(colors.HexColor("#94a3b8"))
        c.setLineWidth(0.5)
        c.line(LEFT_MARGIN, 70, 612 - LEFT_MARGIN, 70)
        c.setFillColor(colors.HexColor("#64748b"))
        c.setFont("Helvetica", 8)
        c.drawString(LEFT_MARGIN, 55, "NAYANX SECURE PQC DOCUMENT — CONTENT-LEVEL FINGERPRINT EMBEDDED")
        c.drawString(400, 55, f"CHANNELS: WORDING ({wording_count}) | LAYOUT ({self.layout_slots_count})")

        # Labelled secondary convenience tag (NEVER sole basis of attribution)
        if secondary_watermark_payload:
            tag_json = json.dumps({
                **secondary_watermark_payload,
                "note": "Convenience tag only. Attribution is computed from Tardos content/layout slots.",
            })
            c.setAuthor(f"NayanX Convenience Tag: {secondary_watermark_payload.get('recipient_id', 'unknown')}")
            c.setSubject(f"Forensic Hash: {secondary_watermark_payload.get('watermark_hash', '')}")
            c.setCreator("NayanX Tardos Document Engine")

        c.save()
        pdf_bytes = buf.getvalue()

        # If secondary watermark is present, also attach metadata via pypdf safely
        if secondary_watermark_payload:
            from pypdf import PdfReader, PdfWriter
            reader = PdfReader(io.BytesIO(pdf_bytes))
            writer = PdfWriter()
            writer.append(reader)
            tag_json = json.dumps({
                **secondary_watermark_payload,
                "role": "secondary_convenience_tag",
            })
            writer.add_metadata({
                "/ForensicWatermarkConvenienceTag": tag_json,
                "/WatermarkHash": secondary_watermark_payload.get("watermark_hash", ""),
            })
            out_stream = io.BytesIO()
            writer.write(out_stream)
            pdf_bytes = out_stream.getvalue()

        return pdf_bytes

    def render_reference_layout(self) -> bytes:
        """
        Renders the reference all-zero layout (codeword = [0] * total_slots).
        This serves as the exact geometric baseline for gap and position comparison.
        """
        all_zeros = [0] * self.total_slots
        return self.render_pdf(all_zeros, secondary_watermark_payload=None)

    render_reference_pdf = render_reference_layout
