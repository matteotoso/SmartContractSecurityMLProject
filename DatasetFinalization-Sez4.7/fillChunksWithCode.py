import json

"""
Script di generazione del dataset per CodeBERT
----------------------------------------------

Questo script integra le informazioni del dataset etichettato
(`datasetRawLabel.jsonl`) con il codice sorgente suddiviso in chunk
(`contractChunk.jsonl`) per produrre il dataset finale
`CodeBertDataset.jsonl`.

Per ogni chunk (o sub-chunk) etichettato, lo script:
- identifica il corrispondente chunk nel file del codice,
  tramite l'indice `id`;
- in caso di sub-chunk, effettua il matching confrontando gli intervalli
  di linee tramite conversione in range consecutivi;
- genera un record completo contenente:
      • codice sorgente,
      • intervallo di linee,
      • label numerica (anche multilabel),
      • numero di token,
      • identificativo del contratto e del chunk.

Il risultato è un dataset coerente e direttamente utilizzabile per
l’addestramento del modello CodeBERT nella classificazione delle
vulnerabilità.

Autore: Matteo Toso (2025)
"""


labels_file = "Data/chunkDivision/datasetRawLabel.jsonl"
code_file = "Data/chunkDivision/contractChunksWithReport.jsonl"
output_file = "Data/chunkDivision/CodeBertDataset.jsonl"

def to_consecutive_ranges(lines):
    """Trasforma una lista di linee in range consecutivi ordinati, es. [3,1,2,5,6] -> ['1-3','5-6']"""
    if not lines:
        return []

    sorted_lines = sorted(set(lines))
    ranges = []
    start = prev = sorted_lines[0]

    for line in sorted_lines[1:]:
        if line == prev + 1:
            prev = line
        else:
            ranges.append(f"{start}-{prev}")
            start = prev = line

    ranges.append(f"{start}-{prev}")
    return ranges

# Carica tutto il file code in memoria per contratto
code_data = {}
with open(code_file, "r") as f:
    for line in f:
        item = json.loads(line)
        code_data[item["contract"]] = item

with open(output_file, "w") as out_f, open(labels_file, "r") as f:
    for label_line in f:
        label_item = json.loads(label_line)
        contract = label_item["contract"]
        if contract not in code_data:
            continue

        code_item = code_data[contract]
        code_chunks = code_item["chunks"]

        for chunk in label_item.get("chunks", []):
            chunk_id = chunk.get("id")
            # trova chunk corrispondente in code file (id implicito: primo = 1)
            if chunk_id - 1 < len(code_chunks):
                code_chunk = code_chunks[chunk_id - 1]
            else:
                continue

            # Se ci sono sub-chunk in label
            sub_chunks_label = chunk.get("sub_chunks", [])
            if sub_chunks_label and "sub_chunks" in code_chunk:
                used_idx = set()
                for sub_label in sub_chunks_label:
                    label_ranges = sub_label["lines_range"]
                    matched = None
                    for idx, code_sub in enumerate(code_chunk["sub_chunks"]):
                        if idx in used_idx:
                            continue
                        code_ranges = to_consecutive_ranges(code_sub["lines_idx"])
                        if code_ranges == label_ranges:
                            matched = code_sub
                            used_idx.add(idx)
                            break
                    if matched:
                        out_item = {
                            "contract": contract,
                            "chunk_id": chunk_id,
                            "lines_range": sub_label["lines_range"],
                            "code": matched["lines"],  # prendiamo lines così com’è
                            "label": sub_label["label"],
                            "token_count": matched.get("token_count")
                        }
                        out_f.write(json.dumps(out_item) + "\n")
                    else:
                        print(f"Attenzione: nessun sub-chunk code trovato per contract={contract}, chunk_id={chunk_id}, label_ranges={label_ranges}")
            else:
                # chunk normale senza sub-chunk
                out_item = {
                    "contract": contract,
                    "chunk_id": chunk_id,
                    "lines_range": chunk.get("lines_range"),
                    "code": code_chunk["lines"],
                    "label": chunk["label"],
                    "token_count": code_chunk.get("token_count")
                }
                out_f.write(json.dumps(out_item) + "\n")

print(f"Output generato in {output_file}")
