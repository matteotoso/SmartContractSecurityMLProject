#!/usr/bin/env python3
import os
import json

# =========================
# CONFIGURAZIONE
# =========================
reports_dir = "sl_report_selected"       # Cartella con i report Slither (.json)
output_file = "reportSlitherVuln.jsonl"  # File di output JSONL

# =========================
# SCRIPT
# =========================
with open(output_file, "w", encoding="utf-8") as out:
    for root, _, files in os.walk(reports_dir):
        for file_name in files:
            if not file_name.endswith(".json") or not file_name.startswith("slither_"):
                continue

            file_path = os.path.join(root, file_name)
            try:
                with open(file_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except json.JSONDecodeError:
                continue

            detectors = data.get("results", {}).get("detectors", [])
            if not detectors:
                continue

            # Rimuove "slither_" e ".json" dal nome del file
            file_rel = os.path.relpath(file_path, reports_dir).removeprefix("slither_").removesuffix(".json")

            vulnerabilities = set()  # useremo un set per evitare duplicati

            for issue in detectors:
                impact = issue.get("impact", "N/A")
                if impact not in ["High", "Medium", "Low"]:
                    continue

                title = issue.get("check", "Unknown")

                for element in issue.get("elements", []):
                    lines = element.get("source_mapping", {}).get("lines", [])
                    if not lines:
                        continue

                    # Calcola il range di linee
                    start_line = min(lines)
                    end_line = max(lines)
                    if start_line == end_line:
                        line_range = str(start_line)
                    else:
                        line_range = f"{start_line}-{end_line}"

                    # Aggiunge una tupla unica
                    vulnerabilities.add((title, impact, line_range))

            # Converte i valori unici in dizionari
            vuln_list = [
                {"title": t, "severity": s, "lines": l}
                for (t, s, l) in sorted(vulnerabilities)
            ]

            if vuln_list:
                out_line = {
                    "file": file_rel,
                    "vulnerabilities": vuln_list
                }
                out.write(json.dumps(out_line, ensure_ascii=False) + "\n")

