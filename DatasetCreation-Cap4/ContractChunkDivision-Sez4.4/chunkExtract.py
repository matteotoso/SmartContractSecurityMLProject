"""
Script di Generazione del Chunk Summary per Smart Contract
----------------------------------------------------------

Questo script elabora un file JSONL contenente la suddivisione
in chunk dei contratti Solidity (derivante da una precedente 
fase di analisi strutturale). Per ogni contratto viene generata 
una rappresentazione compatta che riporta:

  - gli intervalli di righe relativi ad ogni chunk;
  - il numero di token del chunk;
  - gli eventuali sotto-chunk generati tramite mini-splitting.

L'obiettivo è ridurre la complessità del file di input mantenendo 
invariata la struttura logica utile per successive analisi o 
per la fase di inference del modello di classificazione.
"""

import json

# ==============================================================
# === Configurazione dei percorsi
# ==============================================================

input_jsonl  = "Data/chunkDivision/contractChunksWithReport.jsonl"   # File JSONL di input
output_jsonl = "Data/chunkDivision/contractsChunkSummary.jsonl"    # File JSONL di output


# ==============================================================
# === Funzione di supporto
# ==============================================================

def to_consecutive_ranges(lines):
    """
    Trasforma una lista di numeri di riga in un insieme di intervalli consecutivi.
    
    Esempio:
        Input  -> [3, 1, 2, 5, 6]
        Output -> ['1-3', '5-6']
    """
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


# ==============================================================
# === Elaborazione del file JSONL e generazione summary
# ==============================================================

with open(input_jsonl, "r", encoding="utf-8") as f_in, \
     open(output_jsonl, "w", encoding="utf-8") as f_out:

    for line in f_in:

        if not line.strip():
            continue

        data = json.loads(line)
        contract_name = data["contract"]
        chunks = data.get("chunks", [])

        summarized_chunks = []

        for idx, chunk in enumerate(chunks, start=1):

            # Intervalli di righe del chunk principale
            lines_range = to_consecutive_ranges(chunk["lines_idx"])

            chunk_record = {
                "id": idx,
                "lines_range": lines_range,
                "token_count": chunk["token_count"]
            }

            # Elaborazione degli eventuali sotto-chunk
            sub_chunks = chunk.get("sub_chunks", [])
            if sub_chunks:
                summarized_subchunks = []
                for sub in sub_chunks:
                    sub_range = to_consecutive_ranges(sub["lines_idx"])
                    summarized_subchunks.append({
                        "lines_range": sub_range,
                        "token_count": sub["token_count"]
                    })
                chunk_record["sub_chunks"] = summarized_subchunks

            summarized_chunks.append(chunk_record)

        # Record finale per il contratto
        output_record = {
            "contract": contract_name,
            "chunks": summarized_chunks
        }

        f_out.write(json.dumps(output_record, ensure_ascii=False) + "\n")

print(f"[✓] Elaborazione completata. Risultato salvato in '{output_jsonl}'")
