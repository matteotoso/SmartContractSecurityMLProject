#!/usr/bin/env python3
"""
Aggiunta di chunk SAFE nel dataset bilanciato
----------------------------------------------

Questo script integra un certo numero di chunk privi di vulnerabilità
(SAFE) all’interno del dataset bilanciato già esistente.

Operazioni effettuate:

1. Caricamento del dataset bilanciato (`balancedDataset.jsonl`)
2. Caricamento dei chunk considerati SAFE (`chunkSafe.jsonl`)
3. Inserimento dei primi N chunk SAFE nel dataset finale
      - mantenendo separazione per contratto
      - evitando duplicati
4. Ordinamento dei chunk per ID
5. Produzione del dataset finale (`datasetRaw.jsonl`)
6. Log dei chunk SAFE effettivamente aggiunti

Autore: Matteo Toso (2025)
"""

import json
from pathlib import Path

# ============================================================
# CONFIG
# ============================================================

NUM_SAFE_TO_ADD = 1200
balanced_file = Path("Data/chunkDivision/balancedDataset.jsonl")
safe_file = Path("Data/chunkDivision/chunkSafe.jsonl")
output_file = Path("Data/chunkDivision/datasetRaw.jsonl")
added_safe_file = Path("added_safe_chunks.jsonl")


# ============================================================
# CARICAMENTO DATASET BILANCIATO
# ============================================================

contracts_data = []
contracts_index = {}

if balanced_file.exists():
    with open(balanced_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rec = json.loads(line)
                contracts_data.append(rec)
                contracts_index[rec["contract"]] = rec
else:
    raise FileNotFoundError(f"File non trovato: {balanced_file}")


# ============================================================
# CARICAMENTO CHUNK SAFE
# ============================================================

safe_chunks = []
if safe_file.exists():
    with open(safe_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                safe_chunks.append(json.loads(line))
else:
    raise FileNotFoundError(f"File non trovato: {safe_file}")

safe_chunks_to_add = safe_chunks[:NUM_SAFE_TO_ADD]


# ============================================================
# INSERIMENTO CHUNK SAFE
# ============================================================

used_safe_keys = set()      # (contract, id)
added_safe_chunks = []

for ch in safe_chunks_to_add:

    contract_addr = ch["contract"]
    chunk_id = ch["id"]
    key = (contract_addr, chunk_id)

    # evita duplicati
    if key in used_safe_keys:
        continue

    # prepara il chunk ripulito
    new_chunk = {
        "id": ch["id"],
        "lines_range": ch["lines_range"],
        "token_count": ch["token_count"],
        "vulns": []   # SAFE → nessuna vulnerabilità
    }

    # --- inserimento ---
    if contract_addr in contracts_index:
        contracts_index[contract_addr]["chunks"].append(new_chunk)
    else:
        new_contract = {
            "contract": contract_addr,
            "chunks": [new_chunk]
        }
        contracts_data.append(new_contract)
        contracts_index[contract_addr] = new_contract

    used_safe_keys.add(key)
    added_safe_chunks.append(new_chunk)


# ============================================================
# ORDINAMENTO CHUNK PER ID
# ============================================================

for entry in contracts_data:
    entry["chunks"].sort(key=lambda x: x.get("id", 0))


# ============================================================
# SCRITTURA OUTPUT
# ============================================================

with open(output_file, "w", encoding="utf-8") as f:
    for rec in contracts_data:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

with open(added_safe_file, "w", encoding="utf-8") as f:
    for ch in added_safe_chunks:
        f.write(json.dumps(ch, ensure_ascii=False) + "\n")


# ============================================================
# REPORT
# ============================================================

print(f"[✓] File finale generato: {output_file}")
print(f"[✓] Log SAFE generato: {added_safe_file}")
print(f"[i] Totale chunk SAFE aggiunti: {len(added_safe_chunks)}")
