import json

# Configurazioni
INPUT_FILE = "reportSlither.jsonl"  # il file .jsonl
OUTPUT_FILE = "reportSlitherSelected.jsonl"  # file di output
TARGET_COUNT = 10000  # numero di contratti da selezionare

def compute_severity(findings):
    """Assegna un punteggio numerico agli impatti per priorizzare i contratti"""
    score = 0
    for finding in findings:
        impact = finding.get("impact", "").lower()
        if impact == "high":
            score += 3
        elif impact == "medium":
            score += 2
        elif impact == "low":
            score += 1
    return score

def main():
    contracts = []
    
    # Leggi il file .jsonl
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                data = json.loads(line)
                file = data.get("file")
                findings = data.get("findings", [])
                severity_score = compute_severity(findings)
                
                contracts.append({
                    "file": file,
                    "findings": findings,
                    "severity_score": severity_score
                })
            except json.JSONDecodeError:
                continue  # ignora righe malformate

    # Ordina per gravità decrescente
    contracts.sort(key=lambda x: x["severity_score"], reverse=True)

    # Prendi i primi TARGET_COUNT contratti
    selected_contracts = contracts[:TARGET_COUNT]

    # Salva in formato .jsonl (una riga = un contratto)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for contract in selected_contracts:
            # Rimuovi il campo 'severity_score' dall'output se vuoi solo file e findings
            output = {
                "file": contract["file"],
                "findings": contract["findings"]
            }
            f.write(json.dumps(output) + "\n")

    print(f"Selezionati {len(selected_contracts)} contratti. Salvati in {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
