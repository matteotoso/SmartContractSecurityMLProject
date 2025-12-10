#!/usr/bin/env python3
import re
from pathlib import Path

# Cartella dove sono salvati i report
REPORT_DIR = "./sc_reports"  # modifica con il percorso della tua cartella

# File di testo contenente i nomi dei file da leggere (senza estensione)
FILE_NAMES_TXT = "fileVulnTrain.txt"  # modifica con il nome del file txt corretto

# Regex per catturare ruleId
RE_RULEID = re.compile(r'ruleId:\s*(\S+)')

def extract_rule_ids(file_path):
    text = file_path.read_text(encoding='utf-8', errors='ignore')
    return set(match.group(1) for match in RE_RULEID.finditer(text))

def main():
    report_path = Path(REPORT_DIR)
    if not report_path.is_dir():
        print(f"Errore: {REPORT_DIR} non è una cartella valida.")
        return

    # Legge i nomi dei file dal file txt in un set, senza estensione e spazi
    with open(FILE_NAMES_TXT, "r", encoding='utf-8') as f:
        valid_names = {line.strip() for line in f if line.strip()}

    all_rules = set()
    for file in report_path.glob('*'):
        if file.is_file():
            # Controlla se il nome del file (senza estensione) è tra i nomi validi
            if file.stem in valid_names:
                all_rules.update(extract_rule_ids(file))

    if all_rules:
        print("Vulnerabilità uniche rilevate in tutti i report:")
        for r in sorted(all_rules):
            print(f" - {r}")
        print(f"\nTotale vulnerabilità uniche: {len(all_rules)}")
    else:
        print("Nessuna vulnerabilità trovata nei report.")

if __name__ == "__main__":
    main()
