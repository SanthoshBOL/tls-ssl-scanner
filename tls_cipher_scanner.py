import subprocess
import os
import sys
import shutil
from datetime import datetime
from fpdf import FPDF

# === Global Configuration === #
WEAK_TLS_INDICATORS = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'RC4', '3DES', 'CBC']
PORT = "443"

# === Utilities === #
def get_output_path(mode):
    now = datetime.now()
    time_str = now.strftime('%I-%M-%p')  # 12-hour format + AM/PM
    date_str = now.strftime('%Y-%m-%d')

    if mode == "daily":
        folder = "output/daily_scans"
        filename = f"{time_str}_{date_str}_targets.pdf"
    elif mode == "push":
        folder = "output/new_target_scans"
        filename = f"{time_str}_{date_str}_new_targets.pdf"
    else:
        raise ValueError("❌ Unknown mode. Use 'daily' or 'push'.")

    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, filename)


# === TLS/SSL Scanner === #
def run_ssl_scan(targets_file, output_pdf):
    if not shutil.which("nmap"):
        print("[!] Nmap is not installed or not in PATH. Please install Nmap.")
        return

    with open(targets_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    results = {}

    for target in targets:
        print(f"[+] Scanning {target} ...")
        try:
            output = subprocess.check_output(
                [
                    'nmap',
                    '-sV',
                    '--script', 'ssl-enum-ciphers',
                    '--host-timeout', '60s',
                    '--script-timeout', '45s',
                    '-p', PORT,
                    target
                ],
                stderr=subprocess.STDOUT,
                timeout=90  # Python-level timeout
            ).decode()

            is_weak = any(indicator in output for indicator in WEAK_TLS_INDICATORS)
            results[target] = {
                'output': output,
                'status': 'WEAK' if is_weak else 'STRONG'
            }

        except subprocess.TimeoutExpired:
            results[target] = {
                'output': f"[TIMEOUT] Scan for {target} took too long and was skipped.",
                'status': 'ERROR'
            }
        except subprocess.CalledProcessError as e:
            results[target] = {
                'output': f"[ERROR] Could not scan {target}:\n{e.output.decode()}",
                'status': 'ERROR'
            }

    generate_pdf_report(results, output_pdf)

# === PDF Generator === #
def generate_pdf_report(results, output_pdf):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=10)

    # Cover Page
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "TLS/SSL Cipher Scan Report", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("Arial", '', 12)
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(0, 10, f"Total Targets Scanned: {len(results)}", ln=True)

    weak = sum(1 for t in results.values() if t['status'] == 'WEAK')
    strong = sum(1 for t in results.values() if t['status'] == 'STRONG')
    errors = sum(1 for t in results.values() if t['status'] == 'ERROR')

    pdf.cell(0, 10, f"Weak Targets: {weak}", ln=True)
    pdf.cell(0, 10, f"Strong Targets: {strong}", ln=True)
    pdf.cell(0, 10, f"Errors: {errors}", ln=True)

    # Results
    for target, data in results.items():
        pdf.add_page()
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, f"Target: {target}", ln=True)

        # Color-coded status
        pdf.set_font("Arial", 'B', 12)
        if data['status'] == "WEAK":
            pdf.set_text_color(255, 0, 0)
        elif data['status'] == "STRONG":
            pdf.set_text_color(0, 128, 0)
        else:
            pdf.set_text_color(128, 0, 128)
        pdf.cell(0, 10, f"Status: {data['status']}", ln=True)
        pdf.set_text_color(0, 0, 0)

        # Output content
        pdf.set_font("Courier", '', 9)
        for line in data['output'].splitlines():
            if any(w in line for w in WEAK_TLS_INDICATORS):
                pdf.set_text_color(255, 0, 0)
                pdf.multi_cell(0, 4, line)
                pdf.set_text_color(0, 0, 0)
            else:
                pdf.multi_cell(0, 4, line)

    pdf.output(output_pdf)
    print(f"\n✅ PDF report generated at: {output_pdf}\n")

# === Main Entry === #
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tls_cipher_scanner.py [daily|push]")
        sys.exit(1)

    mode = sys.argv[1].strip().lower()
    targets_file = "targets.txt"
    output_pdf = get_output_path(mode)
    run_ssl_scan(targets_file, output_pdf)
