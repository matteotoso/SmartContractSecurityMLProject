
#!/usr/bin/env python3

import json
from pathlib import Path
from collections import Counter, defaultdict
"""
Costruzione di un dataset bilanciato per le categorie rare
----------------------------------------------------------

Questo script seleziona, a partire da un file JSONL contenente i chunk di
codice e le vulnerabilità associate, un sottoinsieme controllato di esempi
con l'obiettivo di bilanciare alcune categorie di vulnerabilità rare fino
a circa 600 occorrenze ciascuna.

Categorie target da incrementare:
    - ARITHMETIC
    - UNSAFE EXTERNAL CALLS
    - ACCESS CONTROL
    - INSECURE RANDOMNESS
    - TRANSACTION ORDER DEPENDENCE (TOD)

Si parte dai conteggi già presenti nel dataset principale (current_counts)
e si aggiungono nuovi esempi seguendo una pipeline di filtraggio e
prioritizzazione.

LOGICA DELLA SELEZIONE
----------------------

1. Filtri di esclusione (HARD FILTERS)
   - Scartati tutti i chunk con token_count < 50 o > 512.
   - Scartati i chunk in cui una categoria è segnalata da più tool diversi.
   - Eliminazione dei duplicati tramite “chunk signature” (anti-clone).

2. Per ogni categoria target si cercano esempi secondo la seguente priorità:

   a) Chunk "puri target":
      - contengono SOLO categorie target;
      - preferenza a:
          • chunk con UNA sola categoria target;
          • vulnerabilità rilevate da un solo tool;
          • severity più alta;
          • token_count maggiore (entro range ammesso).

   b) Chunk "puri multi-target":
      - contengono più categorie, ma tutte target;
      - sempre senza conflitti di tool.

   c) Chunk "mixed ripuliti":
      - contengono sia categorie target sia non-target;
      - le vulnerabilità non-target vengono eliminate nel chunk di output.

3. Vincoli aggiuntivi
   - Nessuna categoria target deve superare MAX_PER_CAT (di default 600).
   - Per evitare sbilanciamenti, massimo MAX_PER_CONTRACT chunk selezionati
     per (contratto, categoria).
   - Si seleziona un chunk solo se almeno una categoria target beneficia
     dell’incremento.

OUTPUT
------

L’output è un file JSONL in cui ogni riga contiene:

    {
        "contract": "<address>",
        "chunk": {
            "id": ...,
            "lines_range": [...],
            "token_count": ...,
            "vulns": [
                {"tool": "...", "categoria": "...", "severity": "..."},
                ...
            ]
        }
    }

Autore: Matteo Toso
Anno accademico: 2025
"""

# ============================================================
# 1. CONFIG
# ============================================================

input_file = Path("Data/chunkDivision/contractsChunkSummary.jsonl")
output_file = Path("Data/chunkDivision/rareVulnBalanceDataset.jsonl")

MAX_PER_CAT = 600
MAX_PER_CONTRACT = 3

TARGET_CATEGORIES = {
    "ARITHMETIC",
    "UNSAFE EXTERNAL CALLS",
    "ACCESS CONTROL",
    "INSECURE RANDOMNESS",
    "TRANSACTION ORDER DEPENDENCE (TOD)",
}

current_counts = {
    "ARITHMETIC": 515,
    "UNSAFE EXTERNAL CALLS": 403,
    "ACCESS CONTROL": 227,
    "INSECURE RANDOMNESS": 34,
    "TRANSACTION ORDER DEPENDENCE (TOD)": 27,
}

TOOL_RANK = {"Mythril": 0, "Slither": 1, "SmartCheck": 2}
SEVERITY_ORDER = {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3}

MIN_TOKENS = 50
MAX_TOKENS = 512


# ============================================================
# 2. SUPPORT FUNCTIONS
# ============================================================

def base_filters(chunk):
    """Filtri hard: range token + nessuna categoria con segnalazioni di tool diversi."""
    token_count = chunk.get("token_count", 0)
    if token_count < MIN_TOKENS or token_count > MAX_TOKENS:
        return False

    vulns = chunk.get("vulns", [])
    if not vulns:
        return False

    cat_tools = defaultdict(set)
    for v in vulns:
        cat, tool = v.get("categoria"), v.get("tool")
        if cat and tool:
            cat_tools[cat].add(tool)

    # Escludi categorie rilevate da ≥2 tool
    for tools in cat_tools.values():
        if len(tools) >= 2:
            return False

    return True


def chunk_category_sets(chunk):
    vulns = chunk.get("vulns", [])
    categories = {v.get("categoria") for v in vulns if v.get("categoria")}
    target = {c for c in categories if c in TARGET_CATEGORIES}
    non_target = categories - target
    return categories, target, non_target


def chunk_type(chunk):
    cats, tc, nt = chunk_category_sets(chunk)
    if not tc:
        return "no_target"
    if nt:
        return "mixed"
    return "pure_single_target" if len(tc) == 1 else "pure_multi_target"


def chunk_priority(chunk):
    """Ordina: pure_single > pure_multi > mixed, tool migliore, severity, token."""
    ctype = chunk_type(chunk)
    _, tc, _ = chunk_category_sets(chunk)
    vulns = chunk.get("vulns", [])

    if ctype == "pure_single_target": t = 0
    elif ctype == "pure_multi_target": t = 1
    else: t = 2

    best_tool = 999
    max_sev = 0
    for v in vulns:
        if v["categoria"] in tc:
            best_tool = min(best_tool, TOOL_RANK.get(v["tool"], 999))
            max_sev = max(max_sev, SEVERITY_ORDER.get(v.get("severity", "Unknown"), 0))

    return (t, best_tool, -max_sev, -chunk.get("token_count", 0))


def chunk_signature(chunk):
    """Identifica duplicati: token_count + lines_range + vulnerabilità ordinarie."""
    vulns = chunk.get("vulns", [])
    sig_v = tuple(sorted((v["categoria"], v["tool"], v["severity"]) for v in vulns))
    lr = tuple(chunk.get("lines_range", []))
    return (chunk.get("token_count", 0), lr, sig_v)


def make_output_chunk(chunk, allow_cats):
    """Crea versione pulita del chunk mantenendo SOLO le categorie in allow_cats."""
    newc = {k: v for k, v in chunk.items() if k not in ("vulns", "sub_chunks")}
    new_v = [v for v in chunk.get("vulns", []) if v["categoria"] in allow_cats]
    newc["vulns"] = new_v
    return newc


# ============================================================
# 3. LOAD DATA
# ============================================================

contracts = []
with input_file.open("r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            contracts.append(json.loads(line))

print("[INFO] Contratti letti:", len(contracts))


# ============================================================
# 4. BUILD CANDIDATES (with anti-clone)
# ============================================================

candidates_pure = []
candidates_mixed = []
seen_signatures = set()
clone_count = 0

for contract in contracts:
    cid = contract["contract"]
    for chunk in contract.get("chunks", []):

        if not base_filters(chunk):
            continue

        sig = chunk_signature(chunk)
        if sig in seen_signatures:
            clone_count += 1
            continue
        seen_signatures.add(sig)

        ctype = chunk_type(chunk)
        if ctype == "no_target":
            continue

        _, tc, nt = chunk_category_sets(chunk)
        record = {"contract_id": cid, "chunk": chunk}

        if nt:
            candidates_mixed.append(record)
        else:
            candidates_pure.append(record)

print(f"[INFO] Candidati puri: {len(candidates_pure)}")
print(f"[INFO] Candidati mixed: {len(candidates_mixed)}")
print(f"[INFO] Anti-clone: {clone_count} duplicati rimossi")

candidates_pure.sort(key=lambda r: chunk_priority(r["chunk"]))
candidates_mixed.sort(key=lambda r: chunk_priority(r["chunk"]))


# ============================================================
# 5. SELECTION (con patch: rimozione categorie piene)
# ============================================================

added_counts = Counter()
contract_cat_counts = defaultdict(Counter)
selected = []


# === FASE 1: pure ===
for rec in candidates_pure:
    cid = rec["contract_id"]
    chunk = rec["chunk"]

    _, tc, _ = chunk_category_sets(chunk)

    # tieni solo categorie target non piene
    valid_cats = [c for c in tc if current_counts[c] + added_counts[c] < MAX_PER_CAT]
    if not valid_cats:
        continue

    # limiti per contratto
    if all(contract_cat_counts[cid][c] >= MAX_PER_CONTRACT for c in valid_cats):
        continue

    outc = make_output_chunk(chunk, allow_cats=set(valid_cats))
    selected.append({"contract": cid, "chunk": outc})

    for c in valid_cats:
        added_counts[c] += 1
        contract_cat_counts[cid][c] += 1


# === FASE 2: mixed ===
for rec in candidates_mixed:
    cid = rec["contract_id"]
    chunk = rec["chunk"]

    if all(current_counts[c] + added_counts[c] >= MAX_PER_CAT for c in TARGET_CATEGORIES):
        break

    _, tc, _ = chunk_category_sets(chunk)

    # only categories still not full
    valid_cats = [c for c in tc if current_counts[c] + added_counts[c] < MAX_PER_CAT]
    if not valid_cats:
        continue

    if all(contract_cat_counts[cid][c] >= MAX_PER_CONTRACT for c in valid_cats):
        continue

    outc = make_output_chunk(chunk, allow_cats=set(valid_cats))
    selected.append({"contract": cid, "chunk": outc})

    for c in valid_cats:
        added_counts[c] += 1
        contract_cat_counts[cid][c] += 1


# ============================================================
# 6. WRITE OUTPUT
# ============================================================

with output_file.open("w", encoding="utf-8") as f:
    for item in selected:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")

print("\n[✓] Dataset generato:", output_file)
print("\n[INFO] Conteggi finali per categoria:")

for c in TARGET_CATEGORIES:
    print(f"  {c}: {current_counts[c] + added_counts[c]}   (+{added_counts[c]})")