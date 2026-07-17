"""
PhishGuard X — Professional Forensic PDF Reporter
Requires: pip install reportlab pypdf
"""

import os
import json
import hashlib
import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.pdfgen import canvas as pdfcanvas

# ── Colour palette ───────────────────────────────────────────────────────────
C_NAVY      = colors.HexColor("#1a2332")
C_BLUE      = colors.HexColor("#2c4a6e")
C_BLUE2     = colors.HexColor("#2563ab")
C_ACCENT    = colors.HexColor("#4a90d9")
C_RED       = colors.HexColor("#c0392b")
C_RED_BG    = colors.HexColor("#fdf0ef")
C_ORANGE    = colors.HexColor("#d35400")
C_ORANGE_BG = colors.HexColor("#fef9f0")
C_GREEN     = colors.HexColor("#1e8449")
C_GREEN_BG  = colors.HexColor("#eafaf1")
C_LIGHT_BG  = colors.HexColor("#f5f7fa")
C_ROW_ALT   = colors.HexColor("#eef2f7")
C_BORDER    = colors.HexColor("#d0d8e4")
C_MID       = colors.HexColor("#7f8c8d")
C_DARK_TEXT = colors.HexColor("#2c3e50")
C_WHITE     = colors.white

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


def S(name, **kw):
    return ParagraphStyle(name, **kw)


# ── Styles ───────────────────────────────────────────────────────────────────
STYLES = {
    "h1":    S("h1",    fontName="Times-Bold",     fontSize=13, textColor=C_NAVY,
                        spaceBefore=12, spaceAfter=5, leading=18),
    "h2":    S("h2",    fontName="Helvetica-Bold", fontSize=10, textColor=C_BLUE,
                        spaceBefore=7, spaceAfter=4, leftIndent=2),
    "body":  S("body",  fontName="Helvetica",      fontSize=9,  textColor=C_DARK_TEXT,
                        leading=15, spaceAfter=3, alignment=TA_JUSTIFY),
    "bold":  S("bold",  fontName="Helvetica-Bold", fontSize=9,  textColor=C_DARK_TEXT,
                        leading=14),
    "small": S("small", fontName="Helvetica",      fontSize=7.5, textColor=C_MID,
                        leading=11),
    "mono":  S("mono",  fontName="Courier",        fontSize=8,  textColor=C_DARK_TEXT,
                        leading=12, leftIndent=4),
    "center":S("center",fontName="Helvetica",      fontSize=9,  textColor=C_DARK_TEXT,
                        alignment=TA_CENTER),
    "wb":    S("wb",    fontName="Helvetica-Bold", fontSize=9,  textColor=C_WHITE),
    "w":     S("w",     fontName="Helvetica",      fontSize=8,  textColor=C_WHITE),
    "note":  S("note",  fontName="Times-Italic",   fontSize=8,  textColor=C_MID,
                        leading=12, spaceAfter=2),
}


def _verdict_colors(verdict):
    v = str(verdict).upper()
    if v == "PHISHING":   return C_RED,    C_RED_BG,    colors.HexColor("#e8a0a0")
    if v == "SUSPICIOUS": return C_ORANGE, C_ORANGE_BG, colors.HexColor("#f0c090")
    if v == "SAFE":       return C_GREEN,  C_GREEN_BG,  colors.HexColor("#80c090")
    return C_MID, C_LIGHT_BG, C_BORDER


def _bar(title, subtitle=""):
    """Section header bar — dark navy, human-proportioned padding."""
    inner = [Paragraph(title, STYLES["wb"])]
    if subtitle:
        inner.append(Paragraph(subtitle, STYLES["w"]))
    t = Table([[inner]], colWidths=[PAGE_W - 2 * MARGIN])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 11),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
    ]))
    return t


def _kv(rows, c1=58 * mm):
    """Key-value pair table."""
    c2 = PAGE_W - 2 * MARGIN - c1
    data = [
        [Paragraph(str(k), STYLES["bold"]), Paragraph(str(v), STYLES["body"])]
        for k, v in rows
    ]
    if not data:
        return Paragraph("No data available.", STYLES["body"])
    t = Table(data, colWidths=[c1, c2])
    s = [
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("GRID",         (0, 0), (-1, -1), 0.4, C_BORDER),
    ]
    for i in range(0, len(data), 2):
        s.append(("BACKGROUND", (0, i), (-1, i), C_ROW_ALT))
    t.setStyle(TableStyle(s))
    return t


def _dtable(headers, rows, cw=None):
    """Data table with header row."""
    fw = PAGE_W - 2 * MARGIN
    if cw is None:
        cw = [fw / len(headers)] * len(headers)
    if not rows:
        return Paragraph("No data available.", STYLES["body"])
    hrow = [Paragraph(h, STYLES["wb"]) for h in headers]
    data = [hrow] + [[Paragraph(str(c), STYLES["body"]) for c in r] for r in rows]
    t = Table(data, colWidths=cw)
    s = [
        ("BACKGROUND",   (0, 0), (-1, 0),  C_BLUE),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("GRID",         (0, 0), (-1, -1), 0.4, C_BORDER),
    ]
    for i in range(1, len(data), 2):
        s.append(("BACKGROUND", (0, i), (-1, i), C_ROW_ALT))
    t.setStyle(TableStyle(s))
    return t


def _bullets(items, color=C_BLUE2):
    """Bullet list — uses a simple dash, more human-looking than fancy symbols."""
    if not items:
        return Paragraph("None.", STYLES["body"])
    rows = [
        [
            Paragraph("-", ParagraphStyle("bd", fontName="Helvetica-Bold",
                                          fontSize=9, textColor=color)),
            Paragraph(str(i), STYLES["body"]),
        ]
        for i in items
    ]
    t = Table(rows, colWidths=[6 * mm, PAGE_W - 2 * MARGIN - 6 * mm])
    t.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
    ]))
    return t


def _scorebar(score):
    """Risk score visual bar."""
    score = int(score or 0)
    bw    = PAGE_W - 2 * MARGIN - 75 * mm
    fill  = max(4, int(bw * score / 100))
    if score >= 70:
        fc, lc = C_RED,    "#c0392b"
    elif score >= 30:
        fc, lc = C_ORANGE, "#d35400"
    else:
        fc, lc = C_GREEN,  "#1e8449"

    snum = Paragraph(
        f'<font color="{lc}"><b>{score}</b></font>'
        f'<font color="#7f8c8d"> / 100</font>',
        ParagraphStyle("sc", fontName="Times-Bold", fontSize=22, alignment=TA_CENTER)
    )

    fb = Table([[""]], colWidths=[fill], rowHeights=[10])
    fb.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), fc),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
    ]))

    eb = Table([[""]], colWidths=[bw - fill], rowHeights=[10])
    eb.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), C_BORDER),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
    ]))

    bar = Table([[fb, eb]], colWidths=[fill, bw - fill], rowHeights=[10])
    bar.setStyle(TableStyle([
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))

    ll = Paragraph('<font color="#1e8449">LOW RISK</font>',
                   ParagraphStyle("bl", fontName="Helvetica", fontSize=7, textColor=C_GREEN))
    lh = Paragraph('<font color="#c0392b">HIGH RISK</font>',
                   ParagraphStyle("bh", fontName="Helvetica", fontSize=7,
                                  textColor=C_RED, alignment=TA_RIGHT))

    outer = Table(
        [[snum, [bar, Table([[ll, lh]], colWidths=[bw / 2, bw / 2])]]],
        colWidths=[75 * mm, bw]
    )
    outer.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
        ("BACKGROUND",   (0, 0), (-1, -1), C_LIGHT_BG),
        ("BOX",          (0, 0), (-1, -1), 0.6, C_BORDER),
    ]))
    return outer


def _badge(verdict):
    """Verdict badge — slightly uneven padding for a stamped look."""
    fg, bg, bd = _verdict_colors(verdict)
    t = Table(
        [[Paragraph(
            f"VERDICT:  {verdict.upper()}",
            ParagraphStyle("vb", fontName="Times-Bold", fontSize=16,
                           textColor=fg, alignment=TA_CENTER)
        )]],
        colWidths=[PAGE_W - 2 * MARGIN]
    )
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), bg),
        ("BOX",          (0, 0), (-1, -1), 1.2, bd),
        ("TOPPADDING",   (0, 0), (-1, -1), 13),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 11),
    ]))
    return t


def _banner(text, fg, bg):
    """Inline coloured notice banner."""
    t = Table(
        [[Paragraph(text, ParagraphStyle("bn", fontName="Helvetica-Bold",
                                         fontSize=9, textColor=fg))]],
        colWidths=[PAGE_W - 2 * MARGIN]
    )
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), bg),
        ("BOX",          (0, 0), (-1, -1), 0.8, fg),
        ("TOPPADDING",   (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 7),
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    return t


# ── Page decorator (header / footer on every body page) ─────────────────────
class _Deco:
    def __init__(self, rid, verdict):
        self.rid = rid
        self.verdict = verdict

    def __call__(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # top bar
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, h - 13 * mm, w, 13 * mm, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.drawString(MARGIN, h - 8.5 * mm, "PhishGuard X  |  Forensic Threat Report")
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(w - MARGIN, h - 8.5 * mm, f"Case: {self.rid}")

        # bottom bar
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, 0, w, 10 * mm, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(MARGIN, 3.5 * mm,
                          "CONFIDENTIAL — National Forensic Sciences University  |  PhishGuard X")
        canvas.drawRightString(w - MARGIN, 3.5 * mm, f"Page {doc.page}")

        canvas.restoreState()


# ── Helper: always get the correct scanned input value ──────────────────────
def _get_input(data):
    # FIX: analyzer.py returns the scanned target as "url" (not "input").
    # Fall back to "input" for backwards compatibility with older results,
    # and finally to "N/A" so the PDF never shows a blank or stale value.
    return data.get("url") or data.get("input") or "N/A"


# ── Cover page ───────────────────────────────────────────────────────────────
def _cover(c, data, rid, rhash, ts):
    w, h = A4
    c.saveState()

    # dark background
    c.setFillColor(C_NAVY)
    c.rect(0, 0, w, h, fill=1, stroke=0)

    # top accent strip
    c.setFillColor(C_BLUE)
    c.rect(0, h - 26 * mm, w, 26 * mm, fill=1, stroke=0)

    # logo placeholder box
    c.setFillColor(colors.HexColor("#1d4870"))
    c.roundRect(w / 2 - 18 * mm, h - 82 * mm, 36 * mm, 40 * mm, 4 * mm, fill=1, stroke=0)
    c.setFillColor(C_ACCENT)
    c.roundRect(w / 2 - 12 * mm, h - 77 * mm, 24 * mm, 28 * mm, 2.5 * mm, fill=1, stroke=0)
    c.setFillColor(C_WHITE)
    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(w / 2, h - 65 * mm, "PG")

    # title block
    c.setFillColor(C_WHITE)
    c.setFont("Times-Bold", 26)
    c.drawCentredString(w / 2, h - 100 * mm, "PhishGuard X")
    c.setFillColor(colors.HexColor("#9db8d8"))
    c.setFont("Helvetica", 11)
    c.drawCentredString(w / 2, h - 110 * mm, "Forensic Threat Intelligence Report")

    # divider line
    c.setStrokeColor(C_ACCENT)
    c.setLineWidth(0.8)
    c.line(MARGIN * 2, h - 116 * mm, w - MARGIN * 2, h - 116 * mm)

    # institution
    c.setFillColor(colors.HexColor("#b0bec8"))
    c.setFont("Helvetica", 8.5)
    c.drawCentredString(w / 2, h - 123 * mm, "National Forensic Sciences University")
    c.drawCentredString(w / 2, h - 129 * mm, "Department of Cyber Security & Digital Forensics")

    # verdict box
    verdict = str(data.get("verdict", "UNKNOWN")).upper()
    vfg = {"PHISHING": "#e74c3c", "SUSPICIOUS": "#e67e22", "SAFE": "#2ecc71"}.get(verdict, "#95a5a6")
    vbg = {"PHISHING": "#3d0a0a", "SUSPICIOUS": "#3d1f00", "SAFE": "#0a2e0a"}.get(verdict, "#1a2332")
    c.setFillColor(colors.HexColor(vbg))
    c.roundRect(MARGIN * 2, h - 167 * mm, w - MARGIN * 4, 18 * mm, 2.5 * mm, fill=1, stroke=0)
    c.setStrokeColor(colors.HexColor(vfg))
    c.setLineWidth(1.2)
    c.roundRect(MARGIN * 2, h - 167 * mm, w - MARGIN * 4, 18 * mm, 2.5 * mm, fill=0, stroke=1)
    c.setFillColor(colors.HexColor(vfg))
    c.setFont("Times-Bold", 16)
    c.drawCentredString(w / 2, h - 160 * mm, f"VERDICT:  {verdict}")

    # summary stats row
    score = data.get("score", 0)
    conf  = data.get("confidence", 0.0)
    atk   = data.get("attack_type", "Unknown")
    c.setFillColor(colors.HexColor("#1c3554"))
    c.roundRect(MARGIN * 2, h - 207 * mm, w - MARGIN * 4, 30 * mm, 2.5 * mm, fill=1, stroke=0)
    col_xs = [MARGIN * 2 + 22 * mm, w / 2, w - MARGIN * 2 - 52 * mm]
    for cx, (lbl, val, vc) in zip(col_xs, [
        ("RISK SCORE",    f"{score}/100",  "#e88080"),
        ("ML CONFIDENCE", f"{conf}%",      "#80aadd"),
        ("ATTACK TYPE",   str(atk),        "#f0d080"),
    ]):
        c.setFillColor(colors.HexColor("#8090a0"))
        c.setFont("Helvetica", 7)
        c.drawCentredString(cx + 12 * mm, h - 185 * mm, lbl)
        c.setFillColor(colors.HexColor(vc))
        c.setFont("Helvetica-Bold", 12)
        c.drawCentredString(cx + 12 * mm, h - 195 * mm, str(val))

    # case info box
    # FIX: use _get_input() so the cover page always shows the actual scanned URL
    inp = _get_input(data)
    c.setFillColor(colors.HexColor("#0f2040"))
    c.roundRect(MARGIN * 2, h - 247 * mm, w - MARGIN * 4, 33 * mm, 2.5 * mm, fill=1, stroke=0)
    iy = h - 224 * mm
    for lbl, val in [
        ("Case ID",   rid),
        ("Generated", ts.strftime("%d %B %Y  %H:%M:%S")),
        ("Input",     str(inp)[:68]),          # FIX: was data.get("input", "N/A")[:68]
    ]:
        c.setFillColor(colors.HexColor("#607080"))
        c.setFont("Helvetica", 7)
        c.drawString(MARGIN * 2 + 7 * mm, iy, lbl + ":")
        c.setFillColor(colors.HexColor("#dce6f0"))
        c.setFont("Helvetica", 7.5)
        c.drawString(MARGIN * 2 + 35 * mm, iy, str(val))
        iy -= 9 * mm

    # hash footer
    c.setFillColor(colors.HexColor("#405060"))
    c.setFont("Helvetica", 6)
    c.drawCentredString(w / 2, h - 253 * mm,
                        f"SHA-256: {rhash[:40]}...{rhash[-8:]}")

    # confidential strip
    c.setFillColor(colors.HexColor("#1a2e44"))
    c.rect(0, 0, w, 14 * mm, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#607080"))
    c.setFont("Helvetica", 7)
    c.drawCentredString(w / 2, 5 * mm,
                        "CONFIDENTIAL — For authorised forensic use only  |  PhishGuard X")

    c.restoreState()
    c.showPage()


# ── Report sections ──────────────────────────────────────────────────────────

def _s_executive(st, data, rid, ts):
    st.append(_bar("1.  EXECUTIVE SUMMARY", "High-level threat overview"))
    st.append(Spacer(1, 7))

    verdict = data.get("verdict", "UNKNOWN")
    st.append(_badge(verdict))
    st.append(Spacer(1, 9))
    st.append(_scorebar(data.get("score", 0)))
    st.append(Spacer(1, 9))

    rows = [
        ("Report ID",      rid),
        ("Timestamp",      ts.strftime("%d %B %Y  %H:%M:%S UTC")),
        ("Input Target",   str(_get_input(data))[:90]),   # FIX: was data.get("input", "N/A")[:90]
        ("Verdict",        verdict),
        ("Risk Score",     f"{data.get('score', 0)} / 100"),
        ("ML Confidence",  f"{data.get('confidence', 0.0)}%"),
        ("Attack Type",    data.get("attack_type", "Unknown")),
    ]
    if data.get("domain_age_days") is not None:
        rows.append(("Domain Age",
                     f"{data['domain_age_days']} days "
                     f"(registered {data.get('domain_created', 'N/A')})"))
    camp = data.get("campaign", {})
    rows.append(("Campaign Detected",
                 "YES — Coordinated Attack" if camp.get("campaign_detected") else "No"))

    st.append(_kv(rows))
    st.append(Spacer(1, 10))


def _s_target(st, data):
    st.append(_bar("2.  TARGET INFORMATION", "Details of the scanned input"))
    st.append(Spacer(1, 7))

    # FIX: was inp = str(data.get("input", "N/A"))
    inp = str(_get_input(data))
    qru = data.get("qr_decoded_url")
    rows = [("Input Value", inp[:120])]    # FIX: now always the real scanned URL
    if qru:
        rows.append(("QR Decoded URL", qru))

    if inp.startswith("[QR"):
        it = "QR Code Image"
    elif inp.startswith("http"):
        it = "URL"
    elif "@" in inp and "\n" in inp:
        it = "Email Message"
    elif len(inp) < 200 and "\n" not in inp:
        it = "SMS / Text"
    else:
        it = "File / Document"

    rows += [
        ("Input Type",       it),
        ("Redirect Summary", data.get("redirect_summary", "N/A")),
    ]
    st.append(_kv(rows))
    st.append(Spacer(1, 10))


def _s_whois(st, data):
    st.append(_bar("3.  WHOIS DOMAIN INTELLIGENCE", "Registration and ownership analysis"))
    st.append(Spacer(1, 7))

    age     = data.get("domain_age_days")
    created = data.get("domain_created", "N/A")

    if age is None:
        st.append(Paragraph(
            "WHOIS lookup skipped (IP input or lookup unavailable).", STYLES["body"]))
        st.append(Spacer(1, 10))
        return

    if age < 30:
        rl, rc, rb = "CRITICAL — Under 30 days old",  C_RED,    C_RED_BG
    elif age < 180:
        rl, rc, rb = "HIGH — Under 6 months old",     C_ORANGE, C_ORANGE_BG
    else:
        rl, rc, rb = "LOW — Established domain",      C_GREEN,  C_GREEN_BG

    st.append(_banner(f"Domain Age Risk:  {rl}", rc, rb))
    st.append(Spacer(1, 7))
    st.append(_kv([
        ("Registration Date", created),
        ("Domain Age",        f"{age} days ({round(age / 365, 1)} years)"),
        ("Risk Level",        rl),
        ("Analyst Note",
         "Phishing domains are almost always newly registered. "
         "A domain under 30 days old impersonating a known brand is a strong indicator."),
    ]))
    st.append(Spacer(1, 10))


def _s_ml(st, data):
    st.append(_bar("4.  MACHINE LEARNING ANALYSIS", "Random Forest — 200 estimators"))
    st.append(Spacer(1, 7))

    st.append(_kv([
        ("Model",          "Random Forest Classifier (200 estimators, scikit-learn)"),
        ("Features",       "8 URL-based features extracted per URL"),
        ("ML Verdict",     data.get("verdict", "UNKNOWN")),
        ("Confidence",     f"{data.get('confidence', 0.0)}%"),
        ("Scoring Formula","Rules×0.4 + Redirects×0.4 + Content×0.4 + ML×0.6  (capped 100)"),
    ]))
    st.append(Spacer(1, 9))
    st.append(Paragraph("Feature Importance Analysis:", STYLES["h2"]))

    feats = [
        ("Social Engineering Keywords",  0.22),
        ("Brand Spoofing (Hyphens)",     0.18),
        ("URL Length",                   0.15),
        ("IP Address Obfuscation",       0.14),
        ("HTTPS Encryption Status",      0.12),
        ("Subdomain Count",              0.10),
        ("Domain Length",                0.05),
        ("Credential Harvesting (@)",    0.04),
    ]
    rows = []
    for fn, fw in feats:
        pct    = round(fw * 100, 1)
        filled = max(2, int(60 * pct / 100))
        empty  = 60 - filled
        bar    = (f'<font color="#2563ab">{"█" * filled}</font>'
                  f'<font color="#dde4ee">{"█" * empty}</font>')
        rows.append([
            Paragraph(fn, STYLES["body"]),
            Paragraph(bar, ParagraphStyle("br", fontName="Courier", fontSize=8,
                                          textColor=C_BLUE2)),
            Paragraph(f"{pct}%", STYLES["bold"]),
        ])

    if rows:
        t = Table(rows, colWidths=[65 * mm, 60 * mm, 20 * mm])
        s = [
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
        ]
        for i in range(0, len(rows), 2):
            s.append(("BACKGROUND", (0, i), (-1, i), C_ROW_ALT))
        t.setStyle(TableStyle(s))
        st.append(t)
    st.append(Spacer(1, 10))


def _s_rules(st, data):
    st.append(_bar("5.  RULE-BASED DETECTION FINDINGS",
                   "Static analysis — URL and pattern signals"))
    st.append(Spacer(1, 7))

    findings = data.get("findings", [])
    if not findings:
        st.append(Paragraph("No rule-based findings detected.", STYLES["body"]))
        st.append(Spacer(1, 10))
        return

    rows = []
    for i, f in enumerate(findings):
        rows.append([
            Paragraph(str(i + 1), STYLES["small"]),
            Paragraph(str(f), STYLES["body"]),
            Paragraph("DETECTED", ParagraphStyle("det", fontName="Helvetica-Bold",
                                                 fontSize=8, textColor=C_RED,
                                                 alignment=TA_CENTER)),
        ])

    if rows:
        t = Table(rows, colWidths=[10 * mm, PAGE_W - 2 * MARGIN - 38 * mm, 28 * mm])
        s = [
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",   (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
            ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
        ]
        for i in range(0, len(rows), 2):
            s.append(("BACKGROUND", (0, i), (-1, i), C_ROW_ALT))
        t.setStyle(TableStyle(s))
        st.append(t)
    st.append(Spacer(1, 10))


def _s_redirects(st, data):
    st.append(_bar("6.  REDIRECT CHAIN ANALYSIS",
                   "Full URL redirect trace with risk classification"))
    st.append(Spacer(1, 7))

    chain = data.get("redirect_chain", [])
    st.append(_kv([
        ("Summary",    data.get("redirect_summary", "N/A")),
        ("Total Hops", str(len(chain))),
    ]))
    st.append(Spacer(1, 7))

    if not chain:
        st.append(Paragraph("No redirect hops recorded.", STYLES["body"]))
        st.append(Spacer(1, 10))
        return

    hrow = [Paragraph(h, STYLES["wb"])
            for h in ["#", "URL", "Status", "Classification", "Final"]]
    rows = [hrow]
    for i, hop in enumerate(chain):
        cls = hop.get("classification", "UNKNOWN")
        cc  = (C_RED    if "ALERT"      in cls.upper() or "SUSPICIOUS" in cls.upper()
               else C_ORANGE if "WARNING" in cls.upper()
               else C_GREEN)
        rows.append([
            Paragraph(str(i + 1), STYLES["small"]),
            Paragraph(str(hop.get("url", ""))[:75], STYLES["mono"]),
            Paragraph(str(hop.get("status", "N/A")), STYLES["center"]),
            Paragraph(cls, ParagraphStyle("cc", fontName="Helvetica-Bold",
                                          fontSize=8, textColor=cc)),
            Paragraph("Final" if hop.get("final_destination") else "", STYLES["small"]),
        ])

    if len(rows) > 1:
        t = Table(rows, colWidths=[8 * mm, 85 * mm, 14 * mm, 44 * mm, 14 * mm])
        s = [
            ("BACKGROUND",   (0, 0), (-1, 0),  C_BLUE),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ("LEFTPADDING",  (0, 0), (-1, -1), 5),
            ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
        ]
        for i in range(1, len(rows), 2):
            s.append(("BACKGROUND", (0, i), (-1, i), C_ROW_ALT))
        t.setStyle(TableStyle(s))
        st.append(t)
    st.append(Spacer(1, 10))


def _s_content(st, data):
    st.append(_bar("7.  CONTENT ANALYSIS",
                   "Phishing language in email / SMS / file body"))
    st.append(Spacer(1, 7))

    cf = [f for f in data.get("findings", [])
          if any(k in str(f).lower()
                 for k in ["phishing language", "urgency", "impersonation",
                            "call-to-action", "pressure", "keyword"])]
    if not cf:
        st.append(Paragraph(
            "No content body provided or no phishing language detected.", STYLES["body"]))
        st.append(Spacer(1, 10))
        return

    st.append(_bullets(cf, C_ORANGE))
    st.append(Spacer(1, 6))
    st.append(Paragraph(
        "Checks performed: phishing keywords (login, verify, suspended), urgency phrases "
        "(act now, final notice), brand impersonation (dear customer, Microsoft), "
        "CTA phrases (click here, verify now).",
        STYLES["note"]))
    st.append(Spacer(1, 10))


def _s_qr(st, data):
    if not data.get("qr_decoded_url"):
        return
    st.append(_bar("8.  QR CODE FORENSICS — QUISHING DETECTION",
                   "Phishing URL hidden inside a QR code"))
    st.append(Spacer(1, 7))

    verdict = str(data.get("verdict", "UNKNOWN")).upper()

    if verdict == "PHISHING":
        banner_text = ("QUISHING DETECTED — A phishing URL was embedded in a QR code. "
                       "This 2024 attack vector bypasses standard link scanners.")
        banner_fg = C_RED
        banner_bg = C_RED_BG
    elif verdict == "SUSPICIOUS":
        banner_text = "Suspicious QR Code detected — further verification recommended."
        banner_fg = C_ORANGE
        banner_bg = C_ORANGE_BG
    elif verdict == "SAFE":
        banner_text = "QR Code is SAFE — no phishing indicators detected."
        banner_fg = C_GREEN
        banner_bg = C_GREEN_BG
    else:
        banner_text = "QR Code analyzed — no definitive conclusion."
        banner_fg = C_MID
        banner_bg = C_LIGHT_BG

    st.append(_banner(banner_text, banner_fg, banner_bg))
    st.append(Spacer(1, 7))
    st.append(_kv([
        ("Image Source",  str(_get_input(data))),   # FIX: was data.get("input", "N/A")
        ("Decoded URL",   data.get("qr_decoded_url", "")),
        ("Decoder",       "OpenCV QRCodeDetector (no DLL required)"),
        ("Pipeline",      "Full PhishGuard analysis applied to decoded URL"),
    ]))
    st.append(Spacer(1, 10))


def _s_campaign(st, data):
    st.append(_bar("9.  CAMPAIGN INTELLIGENCE",
                   "Cross-URL domain tracking — coordinated attack detection"))
    st.append(Spacer(1, 7))

    camp   = data.get("campaign", {})
    det    = camp.get("campaign_detected", False)
    domain = camp.get("domain", "N/A")
    count  = camp.get("count", 0)

    if det:
        st.append(_banner(
            f"CAMPAIGN DETECTED — {count} URLs from domain: {domain}",
            C_RED, C_RED_BG))
    else:
        st.append(_banner(
            camp.get("message", "No campaign detected."),
            C_GREEN, C_GREEN_BG))

    st.append(Spacer(1, 7))
    st.append(_kv([
        ("Domain",         domain),
        ("URLs Observed",  str(count)),
        ("Campaign Flagged","YES" if det else "NO"),
        ("Threshold",      "3+ URLs from same domain triggers campaign alert"),
    ]))

    recent = camp.get("recent_urls", [])
    if recent:
        st.append(Spacer(1, 7))
        st.append(Paragraph("Recent URLs from this domain:", STYLES["h2"]))
        st.append(_dtable(
            ["URL", "Verdict", "Timestamp"],
            [[str(r.get("url", ""))[:65], r.get("verdict", ""), r.get("timestamp", "")]
             for r in recent],
            cw=[100 * mm, 28 * mm, 37 * mm]
        ))
    st.append(Spacer(1, 10))


def _s_attack(st, data):
    st.append(_bar("10.  ATTACK SIMULATION & KILL CHAIN",
                   "Step-by-step victim journey simulation"))
    st.append(Spacer(1, 7))

    atk     = data.get("attack_type", "Unknown")
    verdict = str(data.get("verdict", "UNKNOWN")).upper()

    st.append(_kv([("Attack Classification", atk if atk else "None — input is SAFE")]))
    st.append(Spacer(1, 7))

    if verdict == "SAFE":
        st.append(_banner(
            "No attack simulation applicable — input classified as SAFE. "
            "No kill chain, impact, or MITRE mapping is generated for safe inputs.",
            C_GREEN, C_GREEN_BG
        ))
        st.append(Spacer(1, 10))
        return

    st.append(Paragraph("Kill Chain Simulation:", STYLES["h2"]))

    sim = data.get("simulation") or []
    if not sim:
        sim = [
            "Target receives malicious content",
            "User clicks link or opens attachment",
            "Credentials or data are harvested",
            "Attacker gains unauthorised access",
        ]

    rows = []
    for i, step in enumerate(sim):
        rows.append([
            Paragraph(f"Step {i + 1}",
                      ParagraphStyle("sn", fontName="Helvetica-Bold", fontSize=9,
                                     textColor=C_WHITE, alignment=TA_CENTER)),
            Paragraph(str(step), STYLES["body"]),
        ])

    if rows:
        t = Table(rows, colWidths=[22 * mm, PAGE_W - 2 * MARGIN - 22 * mm])
        s = [
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",   (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
            ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ("GRID",         (0, 0), (-1, -1), 0.3, C_BORDER),
        ]
        for i in range(len(rows)):
            bg = colors.HexColor("#1a3a5e") if i % 2 == 0 else C_BLUE
            s.append(("BACKGROUND", (0, i), (0, i), bg))
            s.append(("BACKGROUND", (1, i), (1, i),
                       C_ROW_ALT if i % 2 else C_LIGHT_BG))
        t.setStyle(TableStyle(s))
        st.append(t)

    st.append(Spacer(1, 9))
    st.append(Paragraph("Impact Assessment:", STYLES["h2"]))

    impact = data.get("impact") or []
    if not impact:
        impact = [
            "Potential data exposure",
            "Credential theft risk",
            "Reputational damage",
        ]
    st.append(_bullets(impact, C_RED))

    st.append(Spacer(1, 9))
    st.append(Paragraph("MITRE ATT&CK Mapping:", STYLES["h2"]))

    mitre = {
        "Credential Harvesting": [
            ("T1566",    "Initial Access",    "Phishing"),
            ("T1056",    "Collection",        "Input Capture"),
            ("T1539",    "Credential Access", "Steal Web Session Cookie"),
        ],
        "Brand Impersonation": [
            ("T1566",    "Initial Access",    "Phishing"),
            ("T1598",    "Reconnaissance",   "Phishing for Information"),
        ],
        "Financial Scam": [
            ("T1566",    "Initial Access",    "Phishing"),
            ("T1657",    "Impact",            "Financial Theft"),
        ],
        "URL Spoofing": [
            ("T1566.002","Initial Access",    "Spearphishing Link"),
            ("T1036",    "Defense Evasion",  "Masquerading"),
        ],
    }

    if atk in mitre:
        mitre_rows = mitre[atk]
    else:
        mitre_rows = [("N/A", "N/A", "No specific technique identified")]

    st.append(_dtable(
        ["Technique ID", "Tactic", "Technique Name"],
        mitre_rows,
        cw=[35 * mm, 50 * mm, 80 * mm]
    ))
    st.append(Spacer(1, 10))


def _s_recs(st, data):
    st.append(_bar("11.  RECOMMENDATIONS & CONCLUSION",
                   "Actionable response steps"))
    st.append(Spacer(1, 7))

    verdict = data.get("verdict", "UNKNOWN")
    if verdict == "PHISHING":
        msg = ("HIGH-CONFIDENCE PHISHING THREAT detected. Do NOT interact with this URL. "
               "Report to your security team immediately and change any potentially "
               "compromised passwords.")
        fg, bg = C_RED, C_RED_BG
    elif verdict == "SUSPICIOUS":
        msg = ("SUSPICIOUS content detected. Exercise extreme caution. "
               "Verify the source through official channels before taking any action.")
        fg, bg = C_ORANGE, C_ORANGE_BG
    else:
        msg = "Input appears SAFE based on current analysis. Continue standard security hygiene."
        fg, bg = C_GREEN, C_GREEN_BG

    st.append(_banner(msg, fg, bg))
    st.append(Spacer(1, 9))
    st.append(Paragraph("Recommended Actions:", STYLES["h2"]))

    raw_recs = data.get("recommendation")
    if not raw_recs:
        recs = ["Follow standard security hygiene practices."]
    elif isinstance(raw_recs, list):
        recs = [str(r) for r in raw_recs if str(r).strip()]
        if not recs:
            recs = ["Follow standard security hygiene practices."]
    else:
        recs_str = str(raw_recs).strip()
        if recs_str.lower() in ("safe", "none", "n/a", ""):
            recs = ["No immediate action required — input is safe. Maintain standard security hygiene."]
        else:
            recs = [recs_str]

    st.append(_bullets(recs, C_BLUE2))

    st.append(Spacer(1, 9))
    st.append(Paragraph("General Security Best Practices:", STYLES["h2"]))
    st.append(_bullets([
        "Never click links in unsolicited emails or SMS messages.",
        "Always verify the sender domain matches the official website.",
        "Enable multi-factor authentication on all accounts.",
        "Report phishing attempts to your IT / security team immediately.",
        "Check domain age and SSL certificate before entering credentials.",
        "Keep browser and antivirus software fully up to date.",
    ], C_BLUE2))
    st.append(Spacer(1, 10))


def _s_logs(st, data):
    st.append(_bar("12.  ANALYSIS EXECUTION LOGS",
                   "Raw backend pipeline output for forensic audit"))
    st.append(Spacer(1, 7))

    logs = data.get("logs", [])
    if not logs:
        st.append(Paragraph("No logs available.", STYLES["body"]))
        st.append(Spacer(1, 10))
        return

    log_text = "\n".join(str(l) for l in logs)
    t = Table(
        [[Paragraph(log_text, ParagraphStyle(
            "lg", fontName="Courier", fontSize=7.5,
            textColor=colors.HexColor("#4ade80"), leading=12, leftIndent=4
        ))]],
        colWidths=[PAGE_W - 2 * MARGIN]
    )
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), C_NAVY),
        ("TOPPADDING",   (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("BOX",          (0, 0), (-1, -1), 0.5, C_BLUE2),
    ]))
    st.append(t)
    st.append(Spacer(1, 10))


def _s_hash(st, rhash, rid):
    st.append(_bar("13.  CRYPTOGRAPHIC EVIDENCE INTEGRITY",
                   "SHA-256 tamper detection — chain of custody"))
    st.append(Spacer(1, 7))
    st.append(_kv([
        ("Report ID",   rid),
        ("Algorithm",   "SHA-256"),
        ("Evidence Hash", rhash),
        ("Purpose",
         "Verifies this report has not been altered since generation. "
         "Any modification produces a different hash value."),
    ]))
    st.append(Spacer(1, 10))


# ── Main generator class ─────────────────────────────────────────────────────
class ForensicReportGenerator:
    def __init__(self):
        self.reports_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "reports"
        )
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate(self, analysis_data: dict) -> str:
        # FIX: Work on a shallow copy so we never mutate the caller's dict
        # (which may be st.session_state["last_result"] in Streamlit).
        # Without this, repeated Generate clicks or reruns see a dict that
        # already has report_id/timestamp/report_hash from a prior run,
        # which can confuse hash verification and produce misleading reports.
        import copy
        analysis_data = copy.copy(analysis_data)

        ts  = datetime.datetime.now()
        rid = f"PHISH-{ts.strftime('%Y%m%d-%H%M%S_%f')}"
        analysis_data["report_id"]  = rid
        analysis_data["timestamp"]  = ts.isoformat()

        data_str = json.dumps(
            {k: v for k, v in analysis_data.items()
             if isinstance(v, (str, int, float, list, bool, type(None)))},
            sort_keys=True, default=str
        )
        rhash = hashlib.sha256(data_str.encode()).hexdigest()
        analysis_data["report_hash"] = rhash

        # save JSON
        json_path = os.path.join(self.reports_dir, f"{rid}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(analysis_data, f, indent=4, default=str)

        pdf_path  = os.path.join(self.reports_dir, f"{rid}.pdf")
        tmp_cover = os.path.join(self.reports_dir, f"{rid}_cov.pdf")
        tmp_body  = os.path.join(self.reports_dir, f"{rid}_body.pdf")

        # ── cover page ──────────────────────────────────────────────────────
        cv = pdfcanvas.Canvas(tmp_cover, pagesize=A4)
        _cover(cv, analysis_data, rid, rhash, ts)
        cv.save()

        # ── body pages ──────────────────────────────────────────────────────
        deco = _Deco(rid, analysis_data.get("verdict", "UNKNOWN"))
        doc  = SimpleDocTemplate(
            tmp_body, pagesize=A4,
            leftMargin=MARGIN, rightMargin=MARGIN,
            topMargin=18 * mm, bottomMargin=15 * mm
        )
        story = []
        _s_executive(story, analysis_data, rid, ts);  story.append(PageBreak())
        _s_target(story, analysis_data)
        _s_whois(story, analysis_data);               story.append(PageBreak())
        _s_ml(story, analysis_data);                  story.append(PageBreak())
        _s_rules(story, analysis_data)
        _s_redirects(story, analysis_data);           story.append(PageBreak())
        _s_content(story, analysis_data)
        _s_qr(story, analysis_data)
        _s_campaign(story, analysis_data);            story.append(PageBreak())
        _s_attack(story, analysis_data);              story.append(PageBreak())
        _s_recs(story, analysis_data)
        _s_logs(story, analysis_data);                story.append(PageBreak())
        _s_hash(story, rhash, rid)
        doc.build(story, onFirstPage=deco, onLaterPages=deco)

        # ── merge cover + body ──────────────────────────────────────────────
        try:
            from pypdf import PdfWriter, PdfReader
            writer = PdfWriter()
            for src in [tmp_cover, tmp_body]:
                for page in PdfReader(src).pages:
                    writer.add_page(page)
            with open(pdf_path, "wb") as out:
                writer.write(out)
            for f in [tmp_cover, tmp_body]:
                try:
                    os.remove(f)
                except Exception:
                    pass
        except ImportError:
            import shutil
            shutil.copy(tmp_body, pdf_path)
            for f in [tmp_cover, tmp_body]:
                try:
                    os.remove(f)
                except Exception:
                    pass

        return pdf_path

    @staticmethod
    def open_report(pdf_path: str):
        import sys, subprocess
        try:
            if sys.platform == "win32":
                os.startfile(pdf_path)
            elif sys.platform == "darwin":
                subprocess.call(["open", pdf_path])
            else:
                subprocess.call(["xdg-open", pdf_path])
        except Exception as e:
            print(f"[Reporter] Could not open PDF: {e}\n[Reporter] Saved at: {pdf_path}")