# 🔐 TLS/SSL Cipher Scanner – 100% Automated Security Monitoring

A fully automated TLS/SSL security scanning tool that performs **hourly scans** on all your production domains and APIs, detects weak protocols and ciphers, and generates **visual PDF reports** — without any manual effort.

---

## 🚀 Key Features

✅ **Fully Automated Scanning**  
- Scans run **every hour** automatically via GitHub Actions  
- Also triggers immediately on **any update to `targets.txt`**  
- Requires **zero manual execution**

✅ **Comprehensive TLS/SSL Cipher Check**  
- Uses `nmap` with `ssl-enum-ciphers` to scan for outdated/weak protocols and ciphers  
- Flags:
  - Insecure Protocols: `SSLv2`, `SSLv3`, `TLSv1.0`, `TLSv1.1`
  - Weak Ciphers: `RC4`, `3DES`, `CBC`, etc.

✅ **Detailed PDF Reports**  
- Includes a summary cover page with timestamp, target count, status breakdown  
- Each target has a dedicated page with:
  - Scan output
  - Highlighted vulnerabilities in **red**
- Auto-saves reports to appropriate folders:
  - `output/daily_scans/` → for scheduled scans
  - `output/new_target_scans/` → for new target pushes

---

## 🧠 How It Works

1. **Update `targets.txt`**  
   Add or update the list of domains/APIs to be scanned (one per line).

2. **GitHub Actions Trigger**  
   - On every **push to `targets.txt`**, a scan is triggered
   - Additionally, a scan runs **every 1 hour** using scheduled GitHub Actions

3. **PDF Report Generation**  
   - Output file is auto-named as:
     - `HH-MM-AM/PM_YYYY-MM-DD_targets.pdf` for daily scans
     - `HH-MM-AM/PM_YYYY-MM-DD_new_targets.pdf` for push-triggered scans

---

## 📁 Project Structure

├── targets.txt # List of domains to scan
├── tls_cipher_scanner.py # Main scanner script
├── output/
│ ├── daily_scans/ # PDF reports from scheduled runs
│ └── new_target_scans/ # PDF reports from new targets pushed
└── .github/
└── workflows/
└── tls-scan.yml # GitHub Actions automation workflow


---

## 🛠️ Requirements

- GitHub Actions (CI/CD)
- Python 3.x
- `nmap` installed on the GitHub runner
- Python libraries: `fpdf`

---

## 🧪 Sample Targets Format (targets.txt)

santhoshagain.github.io
example.com

---

## 📦 How to Use

1. Clone the repo  
2. Add your target domains to `targets.txt`  
3. Push your changes  
4. Sit back — reports will auto-generate in `output/`

---

## 🧭 Why This Project?

Security should be **continuous, automated, and easy to consume**.  
This tool empowers teams to:
- Proactively monitor TLS/SSL posture
- Detect regressions early
- Share audit-ready reports instantly

---

## 🙌 Contributions Welcome

Have ideas? Want to extend this to scan security headers or HTTP issues next?  
Feel free to fork and contribute!

---

## ⚡ Built With

- [Nmap](https://nmap.org/)
- [GitHub Actions](https://github.com/features/actions)
- [FPDF](https://pyfpdf.github.io/)

---

## 🔒 Maintained with ❤️ by Santhosh Kumar Chintada
