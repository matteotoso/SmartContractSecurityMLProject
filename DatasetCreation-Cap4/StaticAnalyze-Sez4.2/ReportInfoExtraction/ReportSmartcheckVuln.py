#!/usr/bin/env python3
import os
import re
import json

# =========================
# CONFIGURAZIONE
# =========================
input_folder = "sc_reports"        # Cartella con i report SmartCheck (.txt)
solidity_folder = "contracts"      # Cartella con i file .sol originali
output_file = "reportSmartcheckVuln.jsonl"  # File di output JSONL


# =========================
# FUNZIONI
# =========================
def extract_vulnerabilities(text):
    """
    Estrae da un report SmartCheck:
      - title
      - severity
      - line_start
      - content (una sola riga)
    """
    vulnerabilities = []
    vuln = None
    sev_map = {"1": "Low", "2": "Medium", "3": "High"}

    for raw in text.splitlines():
        line = raw.strip()

        # Inizio nuova vulnerabilità
        if "ruleid:" in line.lower():
            if vuln:
                vulnerabilities.append(vuln)
            m = re.search(r"ruleid:\s*([A-Z0-9_]+)", line, re.IGNORECASE)
            vuln = {"title": m.group(1) if m else "UNKNOWN"}

        elif vuln and "severity:" in line.lower():
            m = re.search(r"severity:\s*(\d+)", line, re.IGNORECASE)
            if m:
                vuln["severity"] = sev_map.get(m.group(1), "Info")

        elif vuln and "line:" in line.lower():
            m = re.search(r"\bline\b\s*[:=]\s*(\d+)", line, re.IGNORECASE)
            if m:
                vuln["line_start"] = int(m.group(1))

        elif vuln and "content:" in line.lower():
            m = re.search(r"content:\s*(.+)", line, re.IGNORECASE)
            if m:
                vuln["content"] = m.group(1).strip()

    if vuln:
        vulnerabilities.append(vuln)

    return vulnerabilities


def count_non_space_chars(s: str) -> int:
    """Conta solo i caratteri effettivi, escludendo spazi, tab e newline."""
    return len(re.sub(r"[ \t\r\n]", "", s))


def find_line_end_by_charcount(sol_file_path, line_start, content):
    """
    Parte dalla linea indicata, scorre le righe del file .sol
    contando solo i caratteri effettivi (senza spazi o newline)
    fino a raggiungere il numero di caratteri del content.
    Restituisce la riga finale corrispondente.
    """
    if not os.path.exists(sol_file_path) or not content.strip():
        return line_start

    with open(sol_file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    total_needed = len(content)
    total_found = 0
    start_idx = max(line_start - 1, 0)

    for i in range(start_idx, len(lines)):
        line_clean = re.sub(r"[ \t\r\n]", "", lines[i])
        total_found += len(line_clean)
        if total_found >= total_needed:
            return i + 1  # 1-based line number

    return len(lines)


# =========================
# SCRIPT PRINCIPALE
# =========================
report_files = [f for f in os.listdir(input_folder) if f.endswith(".txt")]

if not report_files:
    print(f"Nessun file .txt trovato nella cartella '{input_folder}'.")
    exit(1)

results = []

for report_file in report_files:
    name = os.path.splitext(report_file)[0]
    report_path = os.path.join(input_folder, report_file)
    sol_path = os.path.join(solidity_folder, name + ".sol")

    with open(report_path, "r", encoding="utf-8") as f:
        text = f.read()

    vulns = extract_vulnerabilities(text)

    for v in vulns:
        start = v.get("line_start", 0)
        content = v.get("content", "")
        end = find_line_end_by_charcount(sol_path, start, content)

        # Campo finale: singola linea o range
        v["lines"] = start if start == end else f"{start}-{end}"

        # Rimuove campi intermedi
        v.pop("line_start", None)
        v.pop("content", None)

    results.append({"file": name, "vulnerabilities": vulns})

# Scrittura JSONL finale
with open(output_file, "w", encoding="utf-8") as f:
    for obj in results:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")
