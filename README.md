# AES-ECB vs AES-GCM Lab

Implements AES-256 file encryption/decryption with the Python `cryptography` library (OpenSSL backend) and
demonstrates (1) why ECB is unacceptable and (2) that GCM detects tampering.

* Key: 256-bit, from the OS CSPRNG (`secrets.token_bytes`), supplied **only** via the `AES_KEY` environment variable.
* GCM: fresh random 96-bit nonce for every encryption; header authenticated as AAD.
* ECB: used only to demonstrate leakage of structure (bitmap + repeating text).

## Setup
```bash
pip install -r requirements.txt
```

### Generate the key and store it in an environment variable (never in a file in this repo)
Linux / macOS:
```bash
export AES_KEY=$(python3 aes_lab.py genkey)
```
Windows PowerShell:
```powershell
$env:AES_KEY = (python aes_lab.py genkey)
```
(The variable lasts for the current terminal session. Use a secrets manager for anything real.)

## Usage
```bash
python aes_lab.py encrypt -i secret.txt -o secret.enc     # AES-256-GCM
python aes_lab.py decrypt -i secret.enc -o secret.dec.txt # verifies tag first
python aes_lab.py demo    -d evidence                     # ECB vs GCM bitmap + text
python aes_lab.py tamper  -d evidence                     # bit-flip / truncation tests
python -m unittest -v                                     # unit tests

```

## Layout
| Path | Purpose |
|---|---|
| `aes_lab.py` | implementation + CLI |
| `test_aes_lab.py` | unit tests |
| `evidence/` | generated images and program output used in the report |
| `report/` | PDF lab report and its generator |
| `.gitignore` | excludes `.env`, `*.key`, `*.pem` |

## Security notes
* Never commit the key. `.env.example` contains only a placeholder.
* If a key is ever committed, treat it as compromised and rotate it; deleting the commit is not enough.
* Do not use ECB for real data.

## Static analysis (SonarQube + Semgrep)
| Path | Purpose |
|---|---|
| `rules/aes-lab.yml` | custom Semgrep rules (ECB `modes.ECB()` gap in the stock rule, CLI path taint, output permissions) |
| `scripts/run_semgrep.sh` | Semgrep run against the registry packs; writes `evidence/static/` |
| `sonar-project.properties`, `docker-compose.sonar.yml`, `scripts/run_sonar.sh`, `scripts/export_sonar.py` | SonarQube scan and issue export |
| `evidence/static/` | Semgrep JSON/SARIF/text, supplementary dynamic test and its output |
| `report/generate_static_report.py` | builds `report/Static_Analysis_Lab_Report.pdf` from the evidence |
