# JordanSec

JordanSec is a lightweight **defensive** web security auditing tool designed to help website owners and developers identify common security misconfigurations—especially missing HTTP security headers—and improve their security posture through clear, ethical, and actionable reports.

✅ Defensive checks only (no exploitation)  
✅ Fast & lightweight (Termux-friendly)  
✅ Clear output (Score/Grade + Findings)  
✅ JSON report export for documentation and tracking

---

## Features

- Detects missing common HTTP security headers:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Detects basic server disclosure (when available)
- Generates a simple **Score / Grade**
- Exports results to a **JSON report**

---

## Installation

### Clone the repository
```bash
git clone https://github.com/DefendIQOps/JordanSec.git
cd JordanSec

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python cli.py scan example.com
python cli.py scan https://example.com
##

Example Output

Running headers audit on example.com...

✓ HTTPS enabled
Score: 28/100   Grade: F

Missing security headers:
 - Content-Security-Policy
 - Strict-Transport-Security
 - X-Frame-Options
 - X-Content-Type-Options
 - Referrer-Policy
 - Permissions-Policy

Warnings:
 - Server disclosure: Apache/2.4.58 (Ubuntu)
 - Missing CSP can allow XSS attacks
 - HSTS not enabled
