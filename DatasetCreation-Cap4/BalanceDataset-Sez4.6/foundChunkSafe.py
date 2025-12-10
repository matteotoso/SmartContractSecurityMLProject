#!/usr/bin/env python3
import json
from pathlib import Path
"""
Estrazione dei chunk sicuri (senza vulnerabilità)
-------------------------------------------------

Questo script individua i chunk “safe”, selezionando esclusivamente i 
chunk padre privi di vulnerabilità e privi di sotto–chunk. Vengono 
quindi esclusi tutti i chunk che possiedono sub-chunk, indipendentemente 
dal contenuto di questi ultimi.

Criteri di selezione:
  • nessuna vulnerabilità nel chunk padre;
  • assenza completa di sub-chunk;
  • token_count compreso tra 50 e 512;
  • rimozione dei duplicati basata su (lines_range, token_count);
  • ordinamento decrescente rispetto al token_count.

Il risultato finale viene scritto nel file `chunkSafe.jsonl` e costituisce
la base “safe” da utilizzare come classe negativa nel dataset bilanciato.

Autore: Matteo Toso (2025)
"""



# --- Config ---
vuln_file = Path("Data/chunkDivision/contractsChunkSummary.jsonl")
output_file = Path("Data/chunkDivision/chunkSafe.jsonl")

min_tokens = 50
max_tokens = 512

def load_safe_parent_chunks(path):
    safe = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            data = json.loads(line)
            contract = data["contract"]

            for idx, chunk in enumerate(data.get("chunks", []), start=1):

                # token count
                tc = chunk.get("token_count", 0)
                if not (min_tokens <= tc <= max_tokens):
                    continue

                # sub chunks (nel tuo dataset non esistono, ma per sicurezza)
                if "sub_chunks" in chunk and chunk["sub_chunks"]:
                    continue

                # vulnerabilità: safe se "vulns" NON esiste oppure è una lista vuota
                vulns = chunk.get("vulns")
                if isinstance(vulns, list) and len(vulns) > 0:
                    continue
                # se è None → safe
                # se è lista vuota → safe

                safe.append({
                    "contract": contract,
                    "id": idx,
                    "lines_range": chunk.get("lines_range", []),
                    "token_count": tc,
                    "vulns": []
                })

    return safe


safe_chunks = load_safe_parent_chunks(vuln_file)

# --- Elimina duplicati basati su (lines_range, token_count)
seen = set()
unique_safe = []
for ch in safe_chunks:
    key = (tuple(ch["lines_range"]), ch["token_count"])
    if key not in seen:
        seen.add(key)
        unique_safe.append(ch)

# --- Ordina
unique_safe.sort(key=lambda x: x["token_count"], reverse=True)

# --- Output
with open(output_file, "w", encoding="utf-8") as f:
    for ch in unique_safe:
        f.write(json.dumps(ch, ensure_ascii=False) + "\n")

print(f"[✓] Chunk safe estratti: {len(unique_safe)}")
print(f"Output: {output_file}")
