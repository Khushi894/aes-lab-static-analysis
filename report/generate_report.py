#!/usr/bin/env python3
"""Builds report/AES_ECB_vs_GCM_Lab_Report.pdf from the real program output in evidence/.
Usage: python report/generate_report.py [--name "Your Name"] [--roll "ID"] [--course "..."]"""
import argparse
import re
from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (Image, KeepTogether, PageBreak, Paragraph, Preformatted,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

ROOT = Path(__file__).resolve().parent.parent
EV = ROOT / "evidence"
OUT = ROOT / "report" / "AES_ECB_vs_GCM_Lab_Report.pdf"

ap = argparse.ArgumentParser()
ap.add_argument("--name", default="")
ap.add_argument("--roll", default="")
ap.add_argument("--course", default="Secure Coding and Vulnerabilities Lab")
ap.add_argument("--repo", default="<your GitHub repository URL>")
args = ap.parse_args()

ss = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontSize=15, spaceBefore=14, spaceAfter=6,
                    textColor=colors.HexColor("#14388c"))
H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=11.5, spaceBefore=10, spaceAfter=4)
B = ParagraphStyle("B", parent=ss["BodyText"], fontSize=10, leading=14)
CAP = ParagraphStyle("CAP", parent=B, fontSize=8.5, leading=11, textColor=colors.HexColor("#444444"),
                     alignment=TA_CENTER)
CODE = ParagraphStyle("CODE", fontName="Courier", fontSize=6.6, leading=8.1)
TERM = ParagraphStyle("TERM", fontName="Courier", fontSize=7.4, leading=9.2,
                      backColor=colors.HexColor("#f3f4f6"), borderPadding=5)
TITLE = ParagraphStyle("TITLE", parent=ss["Title"], fontSize=22, leading=27)


def term(text, width=118):
    import textwrap
    lines = []
    for l in text.rstrip("\n").splitlines():
        lines += textwrap.wrap(l, width, subsequent_indent="    ", drop_whitespace=False) or [""]
    return Preformatted("\n".join(lines), TERM)


def code_listing(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    return [Preformatted("\n".join(f"{n:>3}  {l}" for n, l in enumerate(lines, start=1)), CODE)]


def img(path, width_cm):
    from PIL import Image as PI
    w, h = PI.open(path).size
    return Image(str(path), width=width_cm * cm, height=width_cm * cm * h / w)


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(2 * cm, 1.1 * cm, "AES-ECB vs AES-GCM Lab Report")
    canvas.drawRightString(A4[0] - 2 * cm, 1.1 * cm, f"Page {doc.page}")
    canvas.restoreState()


S = []

# ---------------- Title ----------------
S += [Spacer(1, 3 * cm), Paragraph("AES Encryption and Decryption", TITLE),
      Paragraph("ECB vs GCM: Why Mode of Operation Matters", ParagraphStyle("sub", parent=TITLE, fontSize=14, leading=18)),
      Spacer(1, 0.8 * cm), Paragraph(args.course, ParagraphStyle("c", parent=B, alignment=TA_CENTER, fontSize=12)),
      Spacer(1, 1.2 * cm)]
details = [["Name", args.name or "______________________________"],
           ["Roll / ID", args.roll or "______________________________"],
           ["Date", date.today().strftime("%d %B %Y")],
           ["Language / Library", "Python 3 / pyca cryptography (OpenSSL backend)"],
           ["Source code", args.repo]]
t = Table(details, colWidths=[4 * cm, 11 * cm])
t.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 10), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                       ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey), ("TOPPADDING", (0, 0), (-1, -1), 6),
                       ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
S += [t, PageBreak()]

# ---------------- Aim ----------------
S += [Paragraph("1. Aim", H1),
      Paragraph("To implement AES encryption and decryption of a data file with a vetted cryptographic library, "
                "generating the key from a cryptographically secure random source and keeping it out of the source "
                "code and repository; to demonstrate visually that AES-ECB is unacceptable because identical plaintext "
                "blocks produce identical ciphertext blocks; and to verify that AES-GCM provides authenticated "
                "encryption by tampering with the ciphertext and confirming that the authentication tag check fails.", B),
      Paragraph("2. Requirements and how each is met", H1)]
req = [["#", "Requirement", "Implementation"],
       ["1", "Key from a CSPRNG, never hard-coded",
        "generate_key() returns secrets.token_bytes(32) (OS CSPRNG). Key is passed only via the AES_KEY environment variable; a unit test asserts it is not in the source."],
       ["2", "Random IV per encryption",
        "gcm_encrypt() draws a fresh 96-bit nonce with secrets.token_bytes(12) on every call (Section 6.1). ECB has no IV, which is itself a weakness."],
       ["3", "ECB vs GCM on structured input",
        "A 256x256 24-bit bitmap and a repeating text are encrypted under both modes; the ciphertexts are shown side by side (Sections 6.2, 6.3)."],
       ["4", "Prove GCM authenticity",
        "Bit flips in ciphertext, tag, nonce and header, plus truncation/extension, all raise InvalidTag and release no plaintext (Section 7)."],
       ["5", "Key not committed",
        ".gitignore excludes .env, *.key, *.pem; only .env.example (placeholder) is tracked."]]
rows = [[Paragraph(f"<b>{c}</b>" if r == 0 else c, ParagraphStyle("t", parent=B, fontSize=8.8, leading=11))
         for c in row] for r, row in enumerate(req)]
t = Table(rows, colWidths=[0.8 * cm, 4.6 * cm, 11.6 * cm], repeatRows=1)
t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                       ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbe4f5")),
                       ("VALIGN", (0, 0), (-1, -1), "TOP")]))
S += [t]

# ---------------- Theory ----------------
S += [Paragraph("3. Theory", H1),
      Paragraph("<b>AES-ECB.</b> Every 16-byte block is encrypted independently with the same key, so "
                "<i>equal plaintext blocks always give equal ciphertext blocks</i>. The ciphertext leaks the pattern of the "
                "plaintext (the classic \"ECB penguin\"), is deterministic, uses no IV, and offers no integrity: blocks can be "
                "removed, duplicated, reordered or altered without detection.", B),
      Paragraph("<b>AES-GCM.</b> Counter-mode encryption combined with GHASH authentication (AEAD). Each message needs a "
                "unique nonce; the counter stream makes every ciphertext block look random even when plaintext blocks repeat. "
                "A 128-bit authentication tag covers the ciphertext, the nonce and any Associated Data (AAD); decryption "
                "verifies the tag first and refuses to return plaintext if it does not match. Reusing a (key, nonce) pair "
                "breaks GCM, hence a fresh random nonce per encryption.", B),
      Paragraph("4. Design", H1),
      Paragraph("<b>Key handling.</b> 256-bit key, URL-safe base64, read from AES_KEY at run time and validated for length. "
                "The key is never written to a file by the program and is never printed by the demo commands.", B),
      Paragraph("<b>GCM file format.</b> <font name='Courier'>MAGIC(4) | NONCE(12) | CIPHERTEXT(n) | TAG(16)</font>. "
                "The 4-byte magic header is supplied as AAD, so editing the header is detected too.", B),
      Paragraph("<b>Bitmap experiment.</b> A BMP header is public structure and not secret. Only the pixel array is encrypted; the "
                "original header is re-attached to the ciphertext bytes so that the ciphertext can be viewed as an image.", B),
      Paragraph("5. Procedure", H1),
      Paragraph("Windows PowerShell:", B),
      term("pip install -r requirements.txt\n$env:AES_KEY = (python aes_lab.py genkey)\n"
           "python aes_lab.py demo\npython aes_lab.py tamper\npython -m unittest -v"),
      Spacer(1, 4), Paragraph("Linux / macOS:", B),
      term("pip install -r requirements.txt\nexport AES_KEY=$(python3 aes_lab.py genkey)\n"
           "python3 aes_lab.py demo\npython3 aes_lab.py tamper\npython3 -m unittest -v")]

# ---------------- Code listing ----------------
S += [Paragraph("Code listing A: aes_lab.py", H1)] + code_listing(ROOT / "aes_lab.py")
S += [Paragraph("Code listing B: test_aes_lab.py", H1)] + code_listing(ROOT / "test_aes_lab.py")
S += [PageBreak()]

# ---------------- Evidence ----------------
demo = (EV / "demo_output.txt").read_text()
S += [Paragraph("6. Results: encryption evidence", H1), Paragraph("6.1 Random nonce per encryption", H2),
      Paragraph("The same plaintext was encrypted twice under GCM. Nonces and ciphertexts differ every time, whereas "
                "ECB returns an identical ciphertext for identical input.", B)]
m = re.search(r"== Random nonce per encryption ==\n(.*?)\n\n", demo, re.S)
S += [term(m.group(1))]

S += [Paragraph("6.2 Bitmap: ECB vs GCM visual comparison", H2),
      img(EV / "comparison.png", 17),
      Paragraph("Figure 1. Left: plaintext bitmap. Centre: pixel data encrypted with AES-256-ECB; the banner text, circle "
                "and polygon outlines are still clearly visible. Right: the same data under AES-256-GCM; indistinguishable "
                "from random noise.", CAP), Spacer(1, 6)]
stats = re.findall(r"^(plaintext pixels|AES-ECB ciphertext|AES-GCM ciphertext)\s*:\s*(\d+) blocks, (\d+) unique, most-repeated block x(\d+)",
                   demo, re.M)
rows = [["Data (16-byte blocks)", "Total", "Unique", "Most repeated block"]] + [[a, b, c, f"x{d}"] for a, b, c, d in stats]
t = Table(rows, colWidths=[6 * cm, 3 * cm, 3 * cm, 4.5 * cm])
t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 9),
                       ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbe4f5")),
                       ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#fde2e2")),
                       ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#dff5e1"))]))
S += [t, Spacer(1, 4),
      Paragraph("Table 1. Block-level statistics. ECB keeps the same low number of distinct blocks as the plaintext "
                "(one ciphertext block for each distinct plaintext block); GCM yields all-distinct blocks. "
                "(ECB has one extra block because of PKCS#7 padding.)", CAP)]

S += [Paragraph("6.3 Text with repeating content", H2),
      Paragraph("Plaintext: <font name='Courier'>ATTACK AT DAWN!!</font> repeated, with one different block. "
                "Rows highlighted in red show identical ECB ciphertext blocks, which reveal which plaintext blocks are equal.", B)]
rows = [["Blk", "Plaintext", "AES-ECB block", "AES-GCM block"]]
colors_map = {}
for line in (EV / "text_blocks.txt").read_text().splitlines()[1:]:
    blk, pt, ecb, gcm = line[0:3].strip(), line[5:21], line[23:55], line[57:89]
    rows.append([blk, pt, ecb, gcm])
t = Table(rows, colWidths=[1 * cm, 3.2 * cm, 6.4 * cm, 6.4 * cm], repeatRows=1)
st = [("FONTNAME", (1, 1), (-1, -1), "Courier"), ("FONTSIZE", (0, 0), (-1, -1), 7), ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
      ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbe4f5"))]
seen = {}
for i, r in enumerate(rows[1:], start=1):
    seen.setdefault(r[2], []).append(i)
for blks in seen.values():
    if len(blks) > 1:
        for i in blks:
            st.append(("BACKGROUND", (2, i), (2, i), colors.HexColor("#fde2e2")))
t.setStyle(TableStyle(st))
S += [t, Spacer(1, 4), Paragraph("Table 2. ECB repeats ciphertext for repeated plaintext; GCM does not.", CAP), PageBreak()]

# ---------------- Tamper ----------------
tamper = (EV / "tamper_output.txt").read_text()
S += [Paragraph("7. Results: tampered-ciphertext failure proof", H1),
      Paragraph("A message was encrypted with AES-256-GCM. Individual bits of the stored container were then flipped, and "
                "the data truncated or extended, before attempting decryption with the correct key. Every modification caused "
                "<font name='Courier'>cryptography.exceptions.InvalidTag</font> and no plaintext was released. For contrast, "
                "the same single-bit change in an ECB ciphertext decrypted with no error and silently corrupted a block.", B),
      term(tamper), Spacer(1, 8),
      Paragraph("7.1 Command-line proof (file level)", H2),
      Paragraph("Encrypt a file, decrypt it, then flip one bit in the encrypted file and try again. The program exits with "
                "status 2 and does not create an output file.", B),
      term((EV / "cli_transcript.txt").read_text()), Spacer(1, 8),
      Paragraph("7.2 Automated tests", H2), term((EV / "unittest_output.txt").read_text()), PageBreak()]

# ---------------- Result ----------------
S += [Paragraph("8. Result", H1),
      Paragraph("AES-256 encryption and decryption of files was implemented with the pyca/cryptography library. The key is "
                "generated from the operating-system CSPRNG, supplied through the AES_KEY environment variable and never "
                "stored in source control; a fresh random 96-bit nonce is used for every GCM encryption.", B),
      Paragraph("The visual experiment showed that AES-ECB preserved the full structure of the bitmap (banner text, circle "
                "and polygon edges) and produced identical ciphertext blocks for identical plaintext blocks (4,332 repeats of "
                "one block), while AES-GCM output was indistinguishable from random noise with every block unique.", B),
      Paragraph("In the tamper tests, all modifications of the GCM ciphertext, tag, nonce, header or length were rejected by tag "
                "verification, and a wrong key was rejected too. This confirms AES-GCM provides confidentiality "
                "<i>and</i> integrity/authenticity, while ECB provides neither adequate confidentiality nor integrity.", B),
      Paragraph("9. Conclusion and security notes", H1),
      Paragraph("ECB must not be used for real data. Use an AEAD mode such as AES-GCM (or ChaCha20-Poly1305) with a unique "
                "nonce per key, a random 256-bit key held in a secrets manager or environment (never in code or Git), and treat "
                "an authentication failure as a hard error: discard the data and release nothing. Limits of this lab: a key in an "
                "environment variable is visible to the process owner and child processes; production systems should use a KMS/HSM; "
                "random 96-bit nonces are safe for up to about 2<super>32</super> messages per key, after which the key should be rotated.", B)]

SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm,
                  bottomMargin=1.8 * cm, title="AES ECB vs GCM Lab Report").build(S, onFirstPage=footer, onLaterPages=footer)
print("wrote", OUT)
