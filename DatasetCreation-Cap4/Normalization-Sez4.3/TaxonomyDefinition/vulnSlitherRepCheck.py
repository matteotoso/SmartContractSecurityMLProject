import os
import json

# Percorso della cartella contenente i report Slither
reports_dir = "slither_reports"

# File di testo contenente i prefissi dei nomi dei file da leggere
file_prefixes_txt = "fileVulnTrain.txt"

# Legge i prefissi dal file txt in un insieme per ricerca veloce
with open(file_prefixes_txt, "r", encoding="utf-8") as f:
    prefixes = {line.strip() for line in f if line.strip()}

vulnerabilities = set()  # uso un set per evitare duplicati

# Cammina nella directory dei report
for root, _, files in os.walk(reports_dir):
    for file_name in files:
        # Salta file non JSON e file che non iniziano con uno dei prefissi
        if not file_name.endswith(".json") or not any(file_name.startswith("slither_" + p) for p in prefixes):
            continue

        file_path = os.path.join(root, file_name)
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError:
            print(f"[!] Errore nel file {file_path}")
            continue

        # Cerca vulnerabilità nel campo classico di Slither
        detectors = data.get("results", {}).get("detectors", [])
        for issue in detectors:
            name = issue.get("check", "Unknown")
            impact = issue.get("impact", "N/A")
            if impact in ["High", "Medium", "Low"]:
                vulnerabilities.add(name)  # aggiunge solo se non già presente

# Stampa risultati
if vulnerabilities:
    print(f"\n✅ Trovate {len(vulnerabilities)} vulnerabilità uniche:")
    for v in sorted(vulnerabilities):
        print("-", v)
else:
    print("✅ Nessuna vulnerabilità rilevata nei report.")

