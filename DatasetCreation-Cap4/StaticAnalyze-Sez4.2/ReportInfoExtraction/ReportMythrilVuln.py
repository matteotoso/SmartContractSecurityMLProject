#!/usr/bin/env python3
import re
import json
import os
import glob

# === CONFIGURAZIONE ===
input_folder = "my_reports"        # Cartella con i report Mythril (.txt)
output_file = "reportMythrilVuln.jsonl"  # File JSONL di output

# === FUNZIONI ===
def parse_report(text):
    """
    Estrae le vulnerabilità da un report Mythril.
    Restituisce lista di dizionari con:
      - title
      - swc_id
      - severity
      - lines
    """
    pattern = re.compile(r"====\s*(.+?)\s*====", re.DOTALL)
    matches = list(pattern.finditer(text))
    sections = []

    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i+1].start() if i+1 < len(matches) else len(text)
        title = m.group(1).strip()
        body = text[start:end].strip()
        sections.append((title, body))

    vulnerabilities = []
    for title, body in sections:
        swc = re.search(r"SWC ID:\s*(\d+)", body)
        sev = re.search(r"Severity:\s*([A-Za-z0-9_ +-]+)", body)
        line_match = re.search(r"In file:.*?:(\d+)", body)
        line_range = line_match.group(1) if line_match else None

        vulnerabilities.append({
            "title": title,
            "swc_id": swc.group(1) if swc else None,
            "severity": sev.group(1) if sev else None,
            "lines": line_range
        })

    return vulnerabilities

def process_folder(folder):
    """
    Processa tutti i report .txt nella cartella e restituisce lista di oggetti JSON.
    Esclude i report senza vulnerabilità.
    """
    out_lines = []
    for path in sorted(glob.glob(os.path.join(folder, "*.txt"))):
        filename = os.path.splitext(os.path.basename(path))[0]
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        vulns = parse_report(text)
        # Mantieni solo i file con almeno una vulnerabilità
        if vulns:
            obj = {"file": filename, "vulnerabilities": vulns}
            out_lines.append(obj)
    return out_lines

# === SCRIPT PRINCIPALE ===
lines = process_folder(input_folder)

with open(output_file, "w", encoding="utf-8") as f:
    for obj in lines:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

