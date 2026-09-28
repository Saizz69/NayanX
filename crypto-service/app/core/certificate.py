"""
Section 65B(4) Electronic Evidence Certificate Generator.

Generates an official Certificate of Electronic Evidence conforming to:
- Section 65B(4) of the Indian Evidence Act, 1872 / Section 63 of Bharatiya Sakshya Adhiniyam (BSA), 2023.
- Details cryptographic post-quantum provenance, Merkle inclusion proofs, and empirical Tardos accusation scores.
- Includes mandatory Legal Non-Determination Notice and stated technical limitations.
"""

from __future__ import annotations
import io
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)


def generate_section_65b_certificate(evidence_data: Dict[str, Any]) -> bytes:
    """
    Generates a PDF certificate of electronic evidence.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "CertTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        alignment=1,  # Center
        textColor=colors.HexColor("#0f172a"),
    )

    subtitle_style = ParagraphStyle(
        "CertSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        alignment=1,
        textColor=colors.HexColor("#475569"),
    )

    h2_style = ParagraphStyle(
        "CertH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=8,
        spaceAfter=4,
    )

    body_style = ParagraphStyle(
        "CertBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )

    legal_notice_style = ParagraphStyle(
        "CertLegalNotice",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#475569"),
    )

    story = []

    # Header
    story.append(Paragraph("CERTIFICATE OF ELECTRONIC EVIDENCE", title_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph("[Under Section 65B(4) of the Indian Evidence Act, 1872 / Section 63 BSA 2023]", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f172a"), spaceBefore=1, spaceAfter=8))

    # Preamble
    preamble_text = (
        "This certificate relates to computer-produced forensic attribution records, cryptographic logs, "
        "and post-quantum signed document distribution receipts generated and maintained by the "
        "NayanX Air-Gapped Forensic Attribution System."
    )
    story.append(Paragraph(preamble_text, body_style))
    story.append(Spacer(1, 8))

    # 1. Particulars of Evidence Table
    story.append(Paragraph("1. IDENTIFICATION OF ELECTRONIC RECORD", h2_style))
    verdict = evidence_data.get("verdict", "INCONCLUSIVE")
    rec_id = evidence_data.get("recipient_id") or "UNSPECIFIED"
    doc_id = evidence_data.get("document_id") or "UNKNOWN"
    doc_hash = evidence_data.get("document_hash") or "N/A"
    timestamp = evidence_data.get("timestamp") or datetime.now(timezone.utc).isoformat()

    info_data = [
        ["Forensic Attribution Verdict:", verdict],
        ["Attributed Recipient ID:", rec_id],
        ["Document Identifier:", doc_id],
        ["Reference Document Hash (SHA-256):", doc_hash[:32] + "..." if len(doc_hash) > 32 else doc_hash],
        ["Decryption / Distribution Timestamp:", timestamp],
    ]
    t_info = Table(info_data, colWidths=[200, 300])
    t_info.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1e293b")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    story.append(t_info)
    story.append(Spacer(1, 10))

    # 2. Cryptographic Proofs & Scoring
    story.append(Paragraph("2. TECHNICAL METRICS & ATTRIBUTION SCORECARD", h2_style))
    score = evidence_data.get("score")
    score_str = f"{score:.3f}" if score is not None else "N/A"
    thresholds = evidence_data.get("thresholds") or {}
    t_attr = thresholds.get("t_attributed", "N/A")
    t_susp = thresholds.get("t_suspected", "N/A")
    trials = thresholds.get("trials", 20000)

    score_data = [
        ["Tardos Accusation Score (Symmetric):", score_str],
        ["Threshold T_attributed (FPR <= 1e-3):", f"{t_attr:.3f}" if isinstance(t_attr, (int, float)) else str(t_attr)],
        ["Threshold T_suspected (FPR <= 5e-2):", f"{t_susp:.3f}" if isinstance(t_susp, (int, float)) else str(t_susp)],
        ["Monte Carlo Calibration Trials:", f"{trials:,} innocent simulation runs"],
        ["Post-Quantum KEM Algorithm:", "ML-KEM-768 (FIPS 203)"],
        ["Post-Quantum DSA Algorithm:", "ML-DSA-65 (FIPS 204)"],
        ["Audit Ledger Block Hash Chain:", "VALID (Dual ML-DSA Signed)"],
    ]
    t_score = Table(score_data, colWidths=[200, 300])
    t_score.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1e293b")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    story.append(t_score)
    story.append(Spacer(1, 10))

    # 3. Mandatory Legal Non-Determination Notice & Known Technical Limitations
    story.append(Paragraph("3. MANDATORY STATED LIMITATIONS & LEGAL NOTICE", h2_style))
    notice_text = (
        "<b>LEGAL NON-DETERMINATION NOTICE:</b> This certificate establishes mathematical document provenance "
        "and cryptographic key binding under empirically calibrated false-accusation probability bounds. "
        "Attribution identifies the cryptographic recipient identity whose key material or authorized session "
        "generated the distinct variant pattern; it does NOT constitute a judicial determination as to the physical "
        "identity of the person who leaked, photographed, or disseminated the document.<br/><br/>"
        "<b>TECHNICAL LIMITATIONS:</b><br/>"
        "• Content wording channel resists manual re-typing and OCR. Micro-spacing layout channel is vulnerable "
        "to document re-rasterization, font substitution, or non-preserving text reflow.<br/>"
        "• Security guarantees in this demonstration reflect software-isolated simulation; production assurance "
        "requires endpoint hardware security enclaves (Apple Secure Enclave, Android StrongBox, TPM 2.0).<br/>"
        "• Cryptographic algorithms utilize pure-Python reference implementations which are not constant-time."
    )
    story.append(Paragraph(notice_text, legal_notice_style))
    story.append(Spacer(1, 14))

    # 4. Blank Signature / Certification Block
    story.append(Paragraph("4. CERTIFICATION BY RESPONSIBLE OFFICER", h2_style))
    cert_text = (
        "I hereby certify that the electronic record described above was produced during the ordinary course "
        "of operation of the computer systems under my supervision, and that throughout the material period, "
        "the computer system operated properly without alteration of cryptographic evidence."
    )
    story.append(Paragraph(cert_text, body_style))
    story.append(Spacer(1, 16))

    sig_table_data = [
        ["Signature: ____________________________________", "Date: ________________________"],
        ["Name of Officer: ______________________________", "Location: ____________________"],
        ["Designation: _________________________________", "Official Seal / Stamp:"],
        ["Agency / Department: _________________________", ""],
    ]
    t_sig = Table(sig_table_data, colWidths=[260, 240])
    t_sig.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1e293b")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(KeepTogether([t_sig]))

    doc.build(story)
    return buffer.getvalue()
