#!/usr/bin/env python3
"""Builds report/Static_Analysis_Lab_Report.pdf from the real tool output in evidence/static/.
Semgrep rows are read from semgrep-results.json. If evidence/static/sonar-issues.json exists
(created by scripts/export_sonar.py) the SonarQube section is rendered from it; otherwise the
section states plainly that the scan has not been run.
Usage: python report/generate_static_report.py --name "Your Name" --roll "ID" --repo "<url>" """
import argparse
import json
import sys
from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, Preformatted, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

ROOT = Path(__file__).resolve().parent.parent
EV = ROOT / "evidence"
ST = EV / "static"
OUT = ROOT / "report" / "Static_Analysis_Lab_Report.pdf"

ap = argparse.ArgumentParser()
ap.add_argument("--name", default="")
ap.add_argument("--roll", default="")
ap.add_argument("--course", default="Secure Coding and Vulnerabilities Lab")
ap.add_argument("--repo", default="<your GitHub repository URL>")
ap.add_argument("--rules-commit", default="a5ad1714f00c (semgrep/semgrep-rules, 10 Nov 2026)")
args = ap.parse_args()

ss = getSampleStyleSheet()
NAVY = colors.HexColor("#14388c")
H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontSize=14.5, spaceBefore=12, spaceAfter=5, textColor=NAVY)
H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=11, spaceBefore=8, spaceAfter=3)
B = ParagraphStyle("B", parent=ss["BodyText"], fontSize=9.6, leading=13.4)
SM = ParagraphStyle("SM", parent=B, fontSize=7.4, leading=9.4)
SMB = ParagraphStyle("SMB", parent=SM, fontName="Helvetica-Bold", textColor=colors.white)
NOTE = ParagraphStyle("NOTE", parent=B, fontSize=9, leading=12.4, backColor=colors.HexColor("#fff4e0"),
                      borderColor=colors.HexColor("#e0a030"), borderWidth=0.6, borderPadding=6)
TERM = ParagraphStyle("TERM", fontName="Courier", fontSize=7.2, leading=9, backColor=colors.HexColor("#f3f4f6"),
                      borderPadding=5)
TITLE = ParagraphStyle("TITLE", parent=ss["Title"], fontSize=21, leading=26)

P = lambda t, s=B: Paragraph(t, s)
CLS_COL = {"a": "#d6efd6", "b": "#e6e6e6", "c": "#fde9c4"}


def term(text):
    return Preformatted(text.rstrip("\n"), TERM)


def table(rows, widths, header=True, cls_col=None):
    data = [[P(str(c), SMB if (header and i == 0) else SM) for c in r] for i, r in enumerate(rows)]
    t = Table(data, colWidths=[w * cm for w in widths], repeatRows=1 if header else 0)
    st = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b8bec9")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
          ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
          ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]
    if header:
        st.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    if cls_col is not None:
        for i, r in enumerate(rows[1:], start=1):
            k = str(r[cls_col])[:1].lower()
            if k in CLS_COL:
                st.append(("BACKGROUND", (cls_col, i), (cls_col, i), colors.HexColor(CLS_COL[k])))
    t.setStyle(TableStyle(st))
    return t


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawString(1.6 * cm, 1.0 * cm, "Static Analysis Lab: SonarQube + Semgrep on aes_lab.py")
    canvas.drawRightString(A4[0] - 1.6 * cm, 1.0 * cm, f"Page {doc.page}")
    canvas.restoreState()


# ------------------------------------------------------------------ load real Semgrep output
sem = json.loads((ST / "semgrep-results.json").read_text())
by = {}
for r in sem["results"]:
    by[(r["check_id"].split(".")[-1], r["start"]["line"])] = r
sem_version = sem.get("version", "?")
n_rules_line = [l for l in (ST / "semgrep-run-log.txt").read_text().splitlines() if "Rules run" in l]
n_rules = n_rules_line[0].split(":")[1].strip() if n_rules_line else "?"


def meta(rule, line):
    r = by.get((rule, line))
    if r is None:
        sys.exit(f"expected Semgrep finding {rule}:{line} not in semgrep-results.json - re-check triage table")
    m = r["extra"]["metadata"]
    return r["extra"]["severity"], (m.get("confidence") or "n/a"), (m.get("cwe") or ["-"])[0].split(":")[0]


# ------------------------------------------------------------------ triage data (hand-triaged against real findings)
# id, rule, line, triaged severity, class, dynamic evidence, justification / next step
F = [
    ("SG-01", "aes-lab-ecb-mode-any-args", 80, "Medium", "a",
     "D-01 (bitmap 369 unique blocks, top block x4332; identical ECB ciphertext for identical plaintext)",
     "ECB structure leakage reproduced. Triaged Medium, not High: ecb_encrypt is reachable only from the demo and "
     "tamper commands, never from encrypt/decrypt (those call gcm_*)."),
    ("SG-02", "aes-lab-ecb-mode-any-args", 85, "Medium", "a",
     "D-01 (round trip in demo verified, assert at L253 passed)",
     "Same insecure mode on the decrypt side; same reachability limit as SG-01."),
    ("SG-03", "aes-lab-ecb-mode-any-args", 93, "Medium", "a",
     "D-02 (1-bit flip decrypts with no error; one block becomes garbage)",
     "No integrity protection reproduced. Trace 1."),
    ("SG-04", "aes-lab-cli-path-taint", 196, "Info", "b", "D-04 transcript shows normal use only",
     "FALSE POSITIVE for path traversal: args.input is chosen by the operator running the CLI and read with the "
     "operator's own privileges. No trust boundary is crossed (T3 confirms ../ is accepted, by design)."),
    ("SG-05", "aes-lab-cli-path-taint", 197, "Low", "a",
     "T2b+ (symlink at output path overwritten by ciphertext)",
     "Confirmed CWE-59 behaviour: writer follows a pre-planted symlink. Low because only ciphertext is written."),
    ("SG-06", "aes-lab-cli-path-taint", 203, "Info", "b", "D-04 transcript shows normal use only",
     "FALSE POSITIVE for traversal, same reasoning as SG-04. Whole-file read is tracked separately as M-01."),
    ("SG-07", "aes-lab-cli-path-taint", 210, "Medium", "a",
     "T2+ (symlink at output path: victim file overwritten with plaintext)",
     "Confirmed CWE-59 on the plaintext write path. Trace 2."),
    ("SG-08", "aes-lab-decrypted-output-default-perms", 210, "Medium", "a",
     "T1+ (decrypted file created mode 644 under umask 022)",
     "Confirmed CWE-732: plaintext readable by other local users. Same sink as SG-07."),
    ("SG-09", "useless-eqeq", 231, "Info", "b", "D-01 (line prints 'identical? True' by design)",
     "FALSE POSITIVE: the two identical calls are the experiment, demonstrating ECB determinism. Not a typo."),
    ("SG-10", "aes-lab-assert-used-for-check", 253, "Info", "b", "T4+ (python -O demo still runs)",
     "FALSE POSITIVE as a security finding: the assert only double-checks a demo round trip. The real integrity "
     "check is gcm_decrypt raising InvalidTag, which is not an assert."),
    ("SG-11", "aes-lab-assert-used-for-check", 254, "Info", "b", "T4+", "Same as SG-10."),
]
M = [("M-01", "manual review (not a tool finding)", "196, 203", "Low", "c", "Not exercised in Q1",
      "cmd_encrypt/cmd_decrypt read the whole file into memory (CWE-400). Next step: run encrypt on a file "
      "larger than free RAM and larger than 2 GiB to record the failure mode.")]

# ------------------------------------------------------------------ story
st = []
st += [P("Static Analysis Lab Report", TITLE),
       P("SonarQube and Semgrep review of the AES file-encryption application (aes_lab.py)", B),
       Spacer(1, 6),
       table([["Name", args.name or "____________________", "Roll / ID", args.roll or "____________"],
              ["Course", args.course, "Date", date.today().strftime("%d %B %Y")],
              ["Repository", args.repo, "Target", "aes_lab.py (356 lines), test_aes_lab.py"]],
             [2.2, 7.0, 2.4, 5.8], header=False), Spacer(1, 6)]

st += [P("1. Aim", H1),
       P("To run static analysis on the source of the file-based AES-256 application using two complementary tools "
         "(SonarQube and Semgrep), triage each finding by severity and confidence, cross-reference the findings with "
         "the dynamic-testing results from Question 1, and trace untrusted data from source to sink for at least two "
         "confirmed findings.")]

sonar_path = ST / "sonar-issues.json"
sonar = json.loads(sonar_path.read_text()) if sonar_path.exists() else None

st += [P("2. Scope, environment and honest limits", H1),
       table([["Item", "Detail"],
              ["Application", "aes_lab.py: CLI with genkey, encrypt, decrypt (AES-256-GCM) and demo, tamper (ECB vs GCM)"],
              ["Semgrep", f"OSS {sem_version}, {n_rules} rules: semgrep-rules python/, generic/secrets, "
                          f"problem-based-packs/ (commit {args.rules_commit}) plus 4 custom rules in rules/aes-lab.yml"],
              ["Why a local rules clone", "The analysis sandbox could not reach semgrep.dev. The same open-source rules were "
                                         "cloned from GitHub. scripts/run_semgrep.sh runs the registry packs when online."],
              ["SonarQube", "Scanned and exported: yes" if sonar else
               "NOT RUN in this report. No SonarQube server or scanner download was reachable from the sandbox. "
               "Configuration, runner and exporter are in the repository (section 5)."],
              ["Q1 dynamic baseline", "Taken from evidence/ (demo_output, tamper_output, cli_transcript, unittest_output). "
                                      "Replace with your own Q1 IDs if they differ."]],
             [3.6, 14.0])]

st += [P("3. Dynamic baseline (Question 1)", H1),
       table([["ID", "Dynamic test", "Observed result", "Source"],
              ["D-01", "ECB vs GCM on 256x256 bitmap and repeating text",
               "ECB: 369 unique of 12,289 blocks, one block repeated x4332; text 2 unique of 6. GCM: all blocks unique. "
               "Same plaintext twice gives identical ECB ciphertext.", "demo_output.txt"],
              ["D-02", "Flip 1 bit in ECB ciphertext", "Decrypts without error; one 16-byte block silently becomes garbage.", "tamper_output.txt"],
              ["D-03", "6 GCM tamper cases + wrong key", "All rejected with InvalidTag, no plaintext released.", "tamper_output.txt"],
              ["D-04", "CLI decrypt of a 1-bit-flipped file", "Exit code 2; no output file created.", "cli_transcript.txt"],
              ["D-05", "Nonce uniqueness", "Different nonce and ciphertext on every call.", "demo_output.txt, unit tests"],
              ["D-06", "Key handling", "Key only from AES_KEY; missing key exits; no hard-coded key in source.", "unit tests"]],
             [1.2, 4.4, 9.0, 3.0]),
       Spacer(1, 4),
       P("<b>Supplementary dynamic checks (marked + below).</b> Q1 never exercised file-path or permission handling, so "
         "evidence/static/supplementary_dynamic.sh was run to test the findings that needed it. Output in "
         "supplementary_dynamic_output.txt:", B),
       table([["ID", "Test", "Observed result"],
              ["T1+", "decrypt, then stat the output (umask 022)", "Mode 644: plaintext readable by other local users."],
              ["T2+", "-o is a symlink to an existing victim file; run decrypt",
               "Victim file overwritten with the decrypted plaintext. Symlink followed."],
              ["T2b+", "same symlink trick on the encrypt output path", "Victim file overwritten with ciphertext (starts with AGC1)."],
              ["T3+", "-o contains ../ components", "Accepted. Expected for a CLI run by the owner."],
              ["T4+", "python -O aes_lab.py demo", "Runs normally with asserts stripped."]],
             [1.4, 6.4, 9.8])]

st += [PageBreak(), P("4. Semgrep findings and severity triage", H1),
       P(f"Semgrep reported <b>{len(sem['results'])} findings</b> with 0 scan errors. Severity and confidence columns come "
         "from the rule metadata in semgrep-results.json. <i>Triaged severity</i> is my judgement after checking "
         "reachability and impact in this application.", B), Spacer(1, 4)]
rows = [["ID", "Rule", "Line", "CWE", "Semgrep sev.", "Confidence", "Triaged sev."]]
for fid, rule, line, tri, cl, dyn, just in F:
    sv, cf, cwe = meta(rule, line)
    rows.append([fid, rule, line, cwe, sv, cf, tri])
st += [table(rows, [1.3, 6.1, 1.1, 2.0, 2.4, 2.4, 2.3]), Spacer(1, 6)]

st += [P("Tool gap found while triaging", H2),
       P("The stock rule <font face='Courier'>insecure-cipher-mode-ecb</font> did not flag the real code. Its pattern is "
         "<font face='Courier'>modes.ECB($IV)</font> with one argument, but <font face='Courier'>modes.ECB()</font> takes none. "
         "A two-line test file confirmed it: the stock rule flagged <font face='Courier'>ECB(b'x')</font> and missed "
         "<font face='Courier'>ECB()</font>. The custom rule <font face='Courier'>aes-lab-ecb-mode-any-args</font> "
         "(pattern <font face='Courier'>modes.ECB(...)</font>) fixes this and produced SG-01 to SG-03. "
         "Without it, Semgrep reported no cryptographic finding at all.", B)]

st += [P("5. SonarQube findings and severity triage", H1)]
if sonar is None:
    st += [P("<b>Status: not executed for this PDF.</b> The sandbox that produced this report could not reach a SonarQube "
             "server or the scanner download, so no SonarQube result is shown here and none has been estimated. "
             "To complete this section run the following, then regenerate this PDF:", NOTE), Spacer(1, 4),
           term("docker compose -f docker-compose.sonar.yml up -d     # http://localhost:9000, admin/admin\n"
                "# create project 'aes-lab', generate a token\n"
                "export SONAR_TOKEN=<token>\n"
                "bash scripts/run_sonar.sh        # scans, then writes evidence/static/sonar-issues.json\n"
                "python report/generate_static_report.py --name ... --roll ... --repo ..."),
           Spacer(1, 4),
           P("Configuration used (sonar-project.properties): projectKey aes-lab, sources aes_lab.py, tests test_aes_lab.py, "
             "Python 3.12, evidence/ and report/ excluded. SonarQube issues carry a severity but no confidence field; "
             "the confidence equivalent is the Security Hotspot review priority (vulnerabilityProbability), which the "
             "exporter captures.", B),
           P("Every SonarQube finding added later enters the cross-reference table below as class (c) until it is "
             "compared with the dynamic evidence.", B)]
else:
    rows = [["Key", "Type", "Rule", "File:line", "Severity / priority", "Message"]]
    for i in sonar["issues"]:
        rows.append([i["key"][-6:], "Issue", i["rule"], f"{i['component'].split(':')[-1]}:{i.get('line', '-')}",
                     i.get("severity", "-"), i["message"]])
    for h in sonar["hotspots"]:
        rows.append([h["key"][-6:], "Hotspot", h["ruleKey"], f"{h['component'].split(':')[-1]}:{h.get('line', '-')}",
                     h.get("vulnerabilityProbability", "-"), h["message"]])
    st += [table(rows, [1.4, 1.6, 2.6, 2.6, 2.6, 6.8])]

st += [PageBreak(), P("6. Cross-reference with dynamic testing", H1),
       P("Classes: <b>(a)</b> confirmed by dynamic testing; <b>(b)</b> false positive, justified; <b>(c)</b> needs further "
         "investigation. A + mark means the evidence comes from the supplementary tests, not Q1 itself.", B), Spacer(1, 4)]
rows = [["ID", "Tool / rule", "Line", "Class", "Dynamic evidence", "Justification or next step"]]
for fid, rule, line, tri, cl, dyn, just in F + M:
    rows.append([fid, rule, line, cl, dyn, just])
st += [table(rows, [1.2, 3.4, 1.0, 1.2, 4.3, 6.5], cls_col=3), Spacer(1, 4)]
cnt = {k: sum(1 for r in F + M if r[4] == k) for k in "abc"}
st += [P(f"Totals: (a) confirmed = {cnt['a']}, (b) false positive = {cnt['b']}, (c) investigate = {cnt['c']}. "
         "No Q1 test contradicts any Semgrep finding. The GCM path (D-03 to D-06) produced no Semgrep finding, "
         "which agrees with the dynamic result.", B)]

st += [P("7. Source-to-sink traces", H1),
       KeepTogether([P("Trace 1: unauthenticated ECB decryption of attacker-modified ciphertext (SG-03, D-02)", H2),
       term("SOURCE  aes_lab.py:326   ecb_ct = ecb_encrypt(key, plaintext)       ciphertext stored on disk\n"
            "        aes_lab.py:327   bad = flip_bit(ecb_ct, 10)                 attacker edits the file (untrusted)\n"
            "          |  flip_bit (L135-138) XORs one bit; no MAC, tag or length check anywhere\n"
            "        aes_lab.py:328   recovered = ecb_decrypt_nopad(key, bad)    untrusted bytes passed as 'ciphertext'\n"
            "          |  L93  dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()\n"
            "SINK    aes_lab.py:94    return dec.update(ciphertext) + dec.finalize()   plaintext released unverified\n"
            "\n"
            "Dynamic proof (tamper_output.txt): after the flip, bytes 0-15 are garbage, the rest is intact, and no\n"
            "exception is raised. The same weakness exists in ecb_decrypt (L84-88).\n"
            "Contrast: cmd_decrypt -> gcm_decrypt (L108-114) -> AESGCM.decrypt raises InvalidTag, so nothing is released.\n"
            "Fix: remove ECB from any real path; use AESGCM for all file encryption (already true for encrypt/decrypt).")]),
       Spacer(1, 6),
       KeepTogether([P("Trace 2: output path reaches a symlink-following, default-permission write (SG-07, SG-08, T1+, T2+)", H2),
       term("SOURCE  aes_lab.py:341   sp.add_argument('-o', '--output')          path supplied by the caller\n"
            "          |  an attacker with write access to the output directory can pre-plant a symlink there\n"
            "        aes_lab.py:201   def cmd_decrypt(args)\n"
            "        aes_lab.py:203   blob = Path(args.input).read_bytes()\n"
            "        aes_lab.py:205   plaintext = gcm_decrypt(key, blob)           authentic data, correctly decrypted\n"
            "          |  no os.path.realpath / islink check, no O_NOFOLLOW, no O_EXCL, no explicit mode\n"
            "SINK    aes_lab.py:210   Path(args.output).write_bytes(plaintext)     open(path, 'wb'): follows symlink,\n"
            "                                                                    mode 0666 & ~umask\n"
            "\n"
            "Dynamic proof (supplementary_dynamic_output.txt):\n"
            "  T1+  decrypted file created with mode 644\n"
            "  T2+  victim.txt (target of the pre-planted symlink) now contains the decrypted plaintext\n"
            "Fix: os.open(tmp, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0o600) in the destination directory, write, fsync,\n"
            "     then os.replace(tmp, args.output); refuse if the destination is a symlink.")]),
       P("Threat model note: both traces need an attacker who can reach the file system the tool runs on. Trace 1 needs "
         "write access to a stored ciphertext; Trace 2 needs write access to the output directory. Neither is remote.", B)]

st += [P("8. Remediation summary", H1),
       table([["Finding", "Recommended fix", "Priority"],
              ["SG-01 to SG-03", "Move ECB helpers into a clearly labelled demo module or delete them; keep AESGCM-only code on the real path.", "Medium"],
              ["SG-07, SG-08, SG-05", "Atomic write with O_EXCL | O_NOFOLLOW and mode 0600; refuse symlink destinations.", "Medium"],
              ["M-01", "Stream large files in chunks with a chunked-AEAD format, or reject files above a size limit.", "Low"],
              ["Semgrep rule gap", "Keep the custom ECB(...) rule in CI; report the zero-argument miss upstream.", "Low"]],
             [3.4, 12.0, 2.2]),
       P("Not changed: aes_lab.py was left untouched so that the code scanned matches the evidence in this report.", B)]

st += [P("9. Result", H1),
       P(f"Semgrep analysed aes_lab.py and test_aes_lab.py and produced {len(sem['results'])} findings. After triage, "
         f"{cnt['a']} are confirmed by dynamic testing (three ECB weaknesses proven by Q1 and three file-write weaknesses "
         "proven by the supplementary tests), "
         f"{cnt['b']} are justified false positives, and {cnt['c']} item remains open (M-01). "
         "The production encrypt and decrypt path (AES-256-GCM, random nonce, env-supplied key) produced no cryptographic "
         "finding and held up under every Q1 tamper test. The real weaknesses are the ECB helpers (reachable only from "
         "demo code) and unsafe output-file handling. "
         + ("SonarQube results are included above." if sonar else
            "The SonarQube section is pending its scan, as stated in section 5; this report makes no claim about what "
            "SonarQube will report."), B),
       P("10. Evidence and repository", H1),
       P(f"Repository: {args.repo}", B),
       term("evidence/static/semgrep-results.json | .sarif | .txt | semgrep-run-log.txt\n"
            "evidence/static/supplementary_dynamic.sh | supplementary_dynamic_output.txt\n"
            "rules/aes-lab.yml            custom Semgrep rules\n"
            "sonar-project.properties, docker-compose.sonar.yml, scripts/run_sonar.sh, scripts/export_sonar.py\n"
            "scripts/run_semgrep.sh       registry-based Semgrep run (online)\n"
            "report/generate_static_report.py")]

doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=1.6 * cm, rightMargin=1.6 * cm, topMargin=1.5 * cm,
                        bottomMargin=1.7 * cm, title="Static Analysis Lab Report", author=args.name or "")
doc.build(st, onFirstPage=footer, onLaterPages=footer)
print("wrote", OUT)
