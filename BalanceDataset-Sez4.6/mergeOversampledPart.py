#!/usr/bin/env python3
"""
Script di integrazione dei dataset delle vulnerabilità
------------------------------------------------------

Questo script unisce due dataset con l’obiettivo di integrare nel dataset
principale i chunk aggiuntivi selezionati per il bilanciamento delle
categorie rare.

La procedura implementa:

- normalizzazione del formato delle vulnerabilità;
- inserimento dei contratti mancanti;
- fusione dei chunk quando già esistenti (basata sull'identificativo `id`);
- estensione delle liste di vulnerabilità senza deduplicazione,
  coerentemente con il formato scelto per il dataset finale;
- generazione di un file di log che documenta tutte le operazioni svolte.

Autore: Matteo Toso (2025)
"""

import json
from pathlib import Path

# ============================================================
# 1. CONFIGURAZIONE DEI PERCORSI
# ============================================================

main_file = Path("Data/chunkDivision/contractsChunksUndersampled.jsonl")
add_file = Path("Data/chunkDivision/rareVulnBalanceDataset.jsonl")
output_file = Path("Data/chunkDivision/balancedDataset.jsonl")
log_file = Path("merge_log.jsonl")


# ============================================================
# 2. FUNZIONI DI SUPPORTO
# ============================================================

def normalize_vuln(v):
    """
    Normalizza la struttura delle vulnerabilità secondo il formato unificato
    adottato nel dataset principale, privo di sottocategoria.

    Formato finale:
        {
            "categoria": "...",
            "tools": ["ToolName"],
            "severity": "..."
        }
    """
    tool = v.get("tool")
    return {
        "categoria": v.get("categoria"),
        "tools": [tool] if tool else [],
        "severity": v.get("severity", "Low")
    }


# ============================================================
# 3. CARICAMENTO DEL DATASET PRINCIPALE
# ============================================================

main_data = {}

if main_file.exists():
    with open(main_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                entry = json.loads(line)
                main_data[entry["contract"]] = entry
else:
    print(f"[Errore] File principale non trovato: {main_file}")
    exit(1)


# ============================================================
# 4. PROCEDURA DI MERGE DEL DATASET AGGIUNTIVO
# ============================================================

merge_log = []
contracts_added = 0
chunks_added = 0
vulns_added = 0

if not add_file.exists():
    print(f"[Errore] File secondario non trovato: {add_file}")
    exit(1)

with open(add_file, "r", encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue

        new_entry = json.loads(line)
        contract = new_entry.get("contract")

        # Conversione della struttura in lista di chunk
        if "chunks" in new_entry:
            new_chunks = new_entry["chunks"]
        elif "chunk" in new_entry:
            new_chunks = [new_entry["chunk"]]
        else:
            continue

        # Normalizzazione delle vulnerabilità
        for ch in new_chunks:
            ch["vulns"] = [normalize_vuln(v) for v in ch.get("vulns", [])]

        # ------------------------------------------------------------
        # Caso 1 — Il contratto non esiste nel dataset principale
        # ------------------------------------------------------------
        if contract not in main_data:
            main_data[contract] = {"contract": contract, "chunks": new_chunks}

            contracts_added += 1
            chunks_added += len(new_chunks)
            vulns_added += sum(len(c["vulns"]) for c in new_chunks)

            merge_log.append({
                "contract": contract,
                "action": "added_new_contract",
                "chunks_added": [c.get("id") for c in new_chunks]
            })
            continue

        # ------------------------------------------------------------
        # Caso 2 — Il contratto esiste: fusione dei chunk
        # ------------------------------------------------------------
        main_chunks = main_data[contract].setdefault("chunks", [])
        existing_by_id = {c.get("id"): c for c in main_chunks if "id" in c}

        for ch in new_chunks:
            cid = ch.get("id")

            # Chunk non presente → aggiunta diretta
            if cid not in existing_by_id:
                main_chunks.append(ch)
                chunks_added += 1
                vulns_added += len(ch["vulns"])

                merge_log.append({
                    "contract": contract,
                    "chunk_id": cid,
                    "action": "added_new_chunk"
                })
                continue

            # Chunk presente → unione delle vulnerabilità
            existing_chunk = existing_by_id[cid]
            existing_vulns = existing_chunk.setdefault("vulns", [])

            existing_vulns.extend(ch["vulns"])
            vulns_added += len(ch["vulns"])

            merge_log.append({
                "contract": contract,
                "chunk_id": cid,
                "action": "added_vulns_to_existing_chunk",
                "vulns_added": [v["categoria"] for v in ch["vulns"]]
            })


# ============================================================
# 5. SCRITTURA DEL DATASET UNIFICATO
# ============================================================

with open(output_file, "w", encoding="utf-8") as f_out:
    for entry in main_data.values():
        f_out.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ============================================================
# 6. SCRITTURA DEL LOG
# ============================================================

with open(log_file, "w", encoding="utf-8") as f_log:
    for rec in merge_log:
        f_log.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ============================================================
# 7. REPORT FINALE
# ============================================================

print("\n[✓] Merge completato con successo")
print("File risultante:", output_file)
print("Log delle operazioni:", log_file)
print("\nStatistiche:")
print("  • Contratti aggiunti:", contracts_added)
print("  • Chunk aggiunti:", chunks_added)
print("  • Vulnerabilità integrate:", vulns_added)
