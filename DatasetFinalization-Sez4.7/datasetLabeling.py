#!/usr/bin/env python3
"""
Script di generazione delle etichette del dataset
-------------------------------------------------

Questo script converte il dataset finale `datasetRaw.jsonl` nel formato
`datasetRawLabel.jsonl`, aggiungendo a ciascun chunk una o più etichette
numeriche rappresentanti le categorie di vulnerabilità presenti.

Poiché i chunk del dataset possono contenere vulnerabilità sia nel corpo
principale sia all’interno dei sub-chunk, la procedura raccoglie tutte le
vulnerabilità presenti all’interno della struttura gerarchica del chunk.
Se un chunk non contiene alcuna vulnerabilità (né nel padre né nei
sub-chunk), esso viene automaticamente etichettato come SAFE (0).

L’output così generato è strutturato per essere utilizzato in un modello di
classificazione multilabel basato su CodeBERT.

Autore: Matteo Toso (2025)
"""
#!/usr/bin/env python3
import json
from pathlib import Path

# === CONFIG ===
input_file = Path("Data/chunkDivision/datasetRaw.jsonl")
output_file = Path("Data/chunkDivision/datasetRawLabel.jsonl")

# Mappa categoria → label ID
combo_map = {
    0: "SAFE",
    1: "ACCESS CONTROL",
    2: "REENTRANCY",
    3: "ARITHMETIC",
    4: "ENVIRONMENTAL / TIME DEPENDENCE",
    5: "INSECURE RANDOMNESS",
    6: "DENIAL OF SERVICE (DOS)",
    7: "UNSAFE EXTERNAL CALLS",
    8: "TRANSACTION ORDER DEPENDENCE (TOD)",
    9: "LOGIC / IMPLEMENTATION BUGS"
}

def map_vulns(vulns, combo_map):
    """Converte le vulnerabilità in lista di label numerici."""
    if not vulns:
        return [0]  # SAFE
    labels = []
    for v in vulns:
        cat = v.get("categoria", "").strip()
        found = None
        for num, name in combo_map.items():
            if cat == name:
                found = num
                break
        labels.append(found if found is not None else 0)
    return labels

with open(input_file, "r", encoding="utf-8") as f_in, \
     open(output_file, "w", encoding="utf-8") as f_out:

    for line in f_in:
        if not line.strip():
            continue

        contract = json.loads(line)
        new_contract = {"contract": contract["contract"], "chunks": []}

        for chunk in contract.get("chunks", []):
            
            # Caso A: chunk SENZA subchunk → aggiungiamo label al padre
            if "sub_chunks" not in chunk or not chunk["sub_chunks"]:
                new_chunk = {
                    "id": chunk["id"],
                    "lines_range": chunk.get("lines_range", []),
                    "token_count": chunk.get("token_count", 0),
                    "label": map_vulns(chunk.get("vulns", []), combo_map)
                }
                new_contract["chunks"].append(new_chunk)
                continue
            
            # Caso B: chunk CON subchunk → il padre NON deve avere label
            new_chunk = {
                "id": chunk["id"],
                "sub_chunks": []
            }

            for sub in chunk["sub_chunks"]:
                new_chunk["sub_chunks"].append({
                    "lines_range": sub.get("lines_range", []),
                    "token_count": sub.get("token_count", 0),
                    "label": map_vulns(sub.get("vulns", []), combo_map)
                })

            new_contract["chunks"].append(new_chunk)

        f_out.write(json.dumps(new_contract, ensure_ascii=False) + "\n")

print(f"[✓] Conversione completata. Output salvato in: {output_file}")
