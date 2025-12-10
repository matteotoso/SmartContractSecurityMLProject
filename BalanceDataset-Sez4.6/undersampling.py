#!/usr/bin/env python3
"""
Undersampling controllato dei chunk di codice vulnerabili
---------------------------------------------------------

Questo script esegue una fase di UNDER–SAMPLING guidata sul dataset
di chunk di codice Solidity arricchiti con informazioni sulle
vulnerabilità (categorie e severità), con l’obiettivo di ridurre
alcune classi molto frequenti mantenendo al contempo esempi
informativi e bilanciati.

In particolare, si considerano come *categorie da ridurre* le seguenti:

    - REENTRANCY
    - ENVIRONMENTAL / TIME DEPENDENCE
    - DENIAL OF SERVICE (DOS)
    - LOGIC / IMPLEMENTATION BUGS

Le regole fondamentali rispettate dallo script sono:

1. Mai rimuovere chunk che contengono anche categorie NON target:
   se un chunk (o i suoi sub–chunk) includono almeno una vulnerabilità
   con categoria al di fuori del set da ridurre, quel chunk è “protetto”
   e non viene mai eliminato.

2. Mantenere almeno MIN_PURE_PER_CAT (es. 200) chunk “puri” per ciascuna
   categoria target, dove “puro” significa che tutte le vulnerabilità
   del chunk appartengono alla stessa categoria target.

3. Rimuovere per primi i chunk duplicati:
   se due chunk hanno stessa combinazione di (range di linee, numero di
   token e insieme di categorie), se ne conserva uno solo (tipicamente
   quello con severità complessiva più alta) e si eliminano gli altri.

4. Riduzione per categoria:
   per ogni categoria target si cerca di portare il numero di chunk
   che la contengono verso un massimo MAX_PER_CAT (es. 800).
   Tra i chunk “puri” di una categoria si conservano per primi quelli
   con severità più alta, e gli eventuali chunk eccedenti vengono
   rimossi iniziando da quelli con severità più bassa.

L’output è un nuovo file JSONL contenente una versione ridotta e
più bilanciata del dataset, adatta alla costruzione del dataset
di training per CodeBERT–base.

Autore: Matteo Toso
Anno accademico: 2025
"""

import json
from pathlib import Path
from collections import defaultdict

# ============================================================
# 1. Configurazione di base
# ============================================================

# File di input: dataset già filtrato e consolidato
INPUT_FILE = Path("Data/chunkDivision/contractsChunkVulMergedReduced.jsonl")

# File di output: dataset dopo undersampling
OUTPUT_FILE = Path("Data/chunkDivision/contractsChunksUndersampled.jsonl")

# (Opzionale) file in cui salvare i chunk rimossi
REMOVED_FILE = Path("Data/chunkDivision/contractsChunksRemoved.jsonl")

# Categorie da ridurre
TARGET_CATEGORIES = {
    "REENTRANCY",
    "ENVIRONMENTAL / TIME DEPENDENCE",
    "DENIAL OF SERVICE (DOS)",
    "LOGIC / IMPLEMENTATION BUGS",
}

# Numero minimo di chunk “puri” da mantenere per ogni categoria
MIN_PURE_PER_CAT = 200

# Numero massimo di chunk complessivi per categoria (obiettivo di riduzione)
MAX_PER_CAT = 800

# Ordine di importanza della severità (per scelta dei chunk da mantenere o rimuovere)
SEVERITY_ORDER = {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3}


# ============================================================
# 2. Funzioni di supporto
# ============================================================

def collect_group_vulns(chunk):
    """
    Restituisce la lista di tutte le vulnerabilità associate a un chunk,
    considerando sia il livello padre (chunk["vulns"]) sia gli eventuali
    sub–chunk (chunk["sub_chunks"][...]["vulns"]).
    """
    all_v = []
    all_v.extend(chunk.get("vulns", []))
    for sub in chunk.get("sub_chunks", []):
        all_v.extend(sub.get("vulns", []))
    return all_v


def extract_categories_and_severity(vulns):
    """
    Dato un elenco di vulnerabilità, calcola:

      - l'insieme delle categorie presenti
      - la severità massima per ciascuna categoria target (se presente)

    Restituisce:
      (set_categorie, dict_categoria -> max_severity)
    """
    cats = set()
    per_cat_max_sev = {}

    for v in vulns:
        cat = v.get("categoria")
        if not cat:
            continue
        cats.add(cat)

        if cat in TARGET_CATEGORIES:
            sev = v.get("severity", "Unknown")
            old = per_cat_max_sev.get(cat)
            if old is None or SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(old, 0):
                per_cat_max_sev[cat] = sev

    return cats, per_cat_max_sev


def is_protected_group(categories):
    """
    Un chunk è “protetto” se contiene almeno una categoria NON target.
    In tal caso non deve mai essere rimosso dallo script.
    """
    if not categories:
        return False
    # Se esiste almeno una categoria NON target, il gruppo è protetto
    return any(cat not in TARGET_CATEGORIES for cat in categories)


def group_signature(chunk, categories):
    """
    Costruisce una firma (signature) che cerca di identificare chunk duplicati.
    Usa:
      - lines_range e token_count del chunk padre, se presenti
      - altrimenti fallback a soli ranges e token dei sub–chunk
      - insieme (ordinato) delle categorie nel gruppo

    Due chunk con la stessa signature sono considerati candidati duplicati.
    Se mancano completamente metadati di range/token, si restituisce None.
    """
    lines_range = chunk.get("lines_range")
    token_count = chunk.get("token_count")

    if lines_range is None or token_count is None:
        # fallback: prova a basarti sui sub–chunk
        sub = chunk.get("sub_chunks", [])
        if not sub:
            return None
        # Aggrega tutti i ranges e somma i token
        all_ranges = []
        total_tokens = 0
        for s in sub:
            r = s.get("lines_range")
            if r is None:
                continue
            all_ranges.extend(r)
            total_tokens += s.get("token_count", 0)
        if not all_ranges:
            return None
        lines_range = sorted(all_ranges)
        token_count = total_tokens

    cats_sorted = tuple(sorted(categories))
    return (tuple(lines_range), int(token_count), cats_sorted)


def severity_for_group_cat(per_cat_max_sev, cat):
    """
    Restituisce la severità per una data categoria in un chunk, usando
    la mappa categoria -> max severity (per quel chunk). Se assente,
    restituisce "Unknown".
    """
    return per_cat_max_sev.get(cat, "Unknown")


# ============================================================
# 3. Caricamento dell’intero dataset
# ============================================================

if not INPUT_FILE.exists():
    raise FileNotFoundError(f"File di input non trovato: {INPUT_FILE}")

contracts = []
with INPUT_FILE.open("r", encoding="utf-8") as f_in:
    for line in f_in:
        if line.strip():
            contracts.append(json.loads(line))

print(f"[INFO] Contratti caricati: {len(contracts)}")


# ============================================================
# 4. Costruzione metadati per chunk (gruppi)
# ============================================================

# Ogni elemento di groups conterrà:
# {
#   "contract_idx": int,
#   "chunk_idx": int,
#   "categories": set(...),
#   "target_cats": set(...),
#   "non_target_cats": set(...),
#   "per_cat_max_sev": {cat: sev},
#   "protected": bool,
#   "type": "pure_single" | "pure_multi" | "mixed" | "non_target",
#   "signature": tuple(...) o None
# }

groups = []

for ci, contract in enumerate(contracts):
    for ji, chunk in enumerate(contract.get("chunks", [])):
        vulns = collect_group_vulns(chunk)
        cats, per_cat_max_sev = extract_categories_and_severity(vulns)

        target_cats = {c for c in cats if c in TARGET_CATEGORIES}
        non_target_cats = {c for c in cats if c not in TARGET_CATEGORIES}

        if not cats:
            group_type = "empty"
        elif not target_cats:
            group_type = "non_target"
        elif non_target_cats:
            group_type = "mixed"
        elif len(target_cats) == 1:
            group_type = "pure_single"
        else:
            group_type = "pure_multi"

        prot = is_protected_group(cats)

        sig = group_signature(chunk, cats) if (group_type != "non_target" and not prot) else None

        groups.append({
            "contract_idx": ci,
            "chunk_idx": ji,
            "categories": cats,
            "target_cats": target_cats,
            "non_target_cats": non_target_cats,
            "per_cat_max_sev": per_cat_max_sev,
            "protected": prot or (group_type == "non_target"),
            "type": group_type,
            "signature": sig,
        })

print(f"[INFO] Gruppi (chunk) totali: {len(groups)}")


# ============================================================
# 5. Conteggi iniziali per categoria target
# ============================================================

cat_total_counts = {cat: 0 for cat in TARGET_CATEGORIES}
cat_pure_single_counts = {cat: 0 for cat in TARGET_CATEGORIES}

for g in groups:
    for cat in g["target_cats"]:
        cat_total_counts[cat] += 1
        if g["type"] == "pure_single":
            cat_pure_single_counts[cat] += 1

print("\n[INFO] Conteggi iniziali per categoria (tutti i gruppi):")
for cat in TARGET_CATEGORIES:
    print(f"  {cat}: tot={cat_total_counts[cat]}, pure_single={cat_pure_single_counts[cat]}")


# ============================================================
# 6. Rimozione duplicati tra chunk target-only
# ============================================================

# Mappatura: signature -> lista di indici di gruppo
sig_to_indices = defaultdict(list)
for idx, g in enumerate(groups):
    if g["protected"]:
        continue
    if not g["target_cats"]:
        continue
    sig = g.get("signature")
    if sig is not None:
        sig_to_indices[sig].append(idx)

to_remove = set()

for sig, idx_list in sig_to_indices.items():
    if len(idx_list) <= 1:
        continue

    # Se più gruppi condividono stessa signature, se ne conserva uno solo
    # Si sceglie quello con “qualità” globale migliore (somma severità target)
    def group_quality(g):
        q = 0
        for cat, sev in g["per_cat_max_sev"].items():
            q += SEVERITY_ORDER.get(sev, 0)
        return q

    # ordina indici per qualità decrescente
    sorted_idx = sorted(idx_list, key=lambda i: group_quality(groups[i]), reverse=True)

    # conserva il migliore, marca per rimozione gli altri
    for to_drop in sorted_idx[1:]:
        g = groups[to_drop]
        # aggiorna conteggi solo se gruppo non protetto
        for cat in g["target_cats"]:
            cat_total_counts[cat] -= 1
            if g["type"] == "pure_single":
                cat_pure_single_counts[cat] -= 1
        to_remove.add(to_drop)

print(f"\n[INFO] Duplicati rimossi: {len(to_remove)}")


# ============================================================
# 7. Selezione dei 200 chunk “puri” migliori per categoria
# ============================================================

# Per ogni categoria target individuiamo i chunk "pure_single" candidati
# e selezioniamo i migliori MIN_PURE_PER_CAT in base alla severità.

protected_pure_single = {cat: set() for cat in TARGET_CATEGORIES}

for cat in TARGET_CATEGORIES:
    # ottieni tutti gli indici di gruppi pure_single con solo questa categoria
    candidates = []
    for idx, g in enumerate(groups):
        if idx in to_remove:
            continue
        if g["type"] != "pure_single":
            continue
        if g["protected"]:
            continue
        if g["target_cats"] == {cat}:
            sev = severity_for_group_cat(g["per_cat_max_sev"], cat)
            candidates.append((idx, sev))

    if not candidates:
        continue

    # ordina per severity discendente (High > Medium > Low > Unknown)
    candidates.sort(key=lambda t: SEVERITY_ORDER.get(t[1], 0), reverse=True)

    # seleziona i migliori MIN_PURE_PER_CAT (se disponibili)
    keep_n = min(MIN_PURE_PER_CAT, len(candidates))
    chosen = {idx for idx, _ in candidates[:keep_n]}
    protected_pure_single[cat] = chosen

    print(f"[INFO] Categoria {cat}: protetti {len(chosen)} chunk pure_single (target={MIN_PURE_PER_CAT})")


# ============================================================
# 8. Riduzione per categoria verso MAX_PER_CAT
# ============================================================

# In questa fase si rimuovono chunk in eccesso per ogni categoria target,
# rispettando:
#   - i chunk protetti (misti o non-target)
#   - i 200 pure_single selezionati per categoria
#   - i gruppi già marcati per rimozione (duplicati)

for cat in TARGET_CATEGORIES:
    current_total = cat_total_counts[cat]
    print(f"\n[RIDUZIONE] Categoria {cat} - conteggio attuale: {current_total}")

    if current_total <= MAX_PER_CAT:
        print(f"  Nessuna riduzione necessaria (<= {MAX_PER_CAT}).")
        continue

    # Costruiamo lista di candidati alla rimozione per questa categoria.
    # 1) pure_single non protetti
    # 2) pure_multi (solo target) che includono questa categoria

    candidates = []

    for idx, g in enumerate(groups):
        if idx in to_remove:
            continue
        if g["protected"]:
            continue
        if cat not in g["target_cats"]:
            continue

        # se pure_single e tra i protetti di questa categoria → non rimuovere
        if g["type"] == "pure_single" and idx in protected_pure_single[cat]:
            continue

        # consideriamo solo gruppi che contengono SOLO categorie target
        if g["non_target_cats"]:
            continue

        sev = severity_for_group_cat(g["per_cat_max_sev"], cat)
        candidates.append((idx, sev, g["type"]))

    if not candidates:
        print("  Nessun candidato alla rimozione trovato senza violare vincoli.")
        continue

    # Ordine di rimozione: severity crescente (Unknown, Low, Medium, High),
    # e come secondario: pure_single prima, poi pure_multi
    def removal_priority(item):
        idx, sev, gtype = item
        sev_score = SEVERITY_ORDER.get(sev, 0)
        # pure_single (0) ha priorità prima di pure_multi (1) nell'ordinamento
        type_score = 0 if gtype == "pure_single" else 1
        return (sev_score, type_score)

    candidates.sort(key=removal_priority)

    # Rimozione effettiva fino a portare la categoria vicino a MAX_PER_CAT
    for idx, sev, gtype in candidates:
        if cat_total_counts[cat] <= MAX_PER_CAT:
            break
        if idx in to_remove:
            continue

        g = groups[idx]

        # Non violare il vincolo sui 200 pure_single rimanenti:
        if g["type"] == "pure_single" and g["target_cats"] == {cat}:
            # quante pure_single rimarrebbero se lo rimuovo?
            remaining_pure = cat_pure_single_counts[cat] - 1
            if remaining_pure < MIN_PURE_PER_CAT:
                continue  # non posso scendere sotto il minimo

        # Posso rimuovere questo gruppo
        to_remove.add(idx)

        # Aggiorno conteggi per tutte le categorie target presenti nel gruppo
        for c2 in g["target_cats"]:
            cat_total_counts[c2] -= 1
            if g["type"] == "pure_single" and g["target_cats"] == {c2}:
                cat_pure_single_counts[c2] -= 1

    print(f"  Conteggio finale stimato per {cat}: {cat_total_counts[cat]}")


# ============================================================
# 9. Applicazione delle rimozioni e salvataggio output
# ============================================================

removed_records = []

# Costruiamo una struttura per segnalare, per ogni contratto, quali chunk
# sono stati rimossi.
removed_by_contract = defaultdict(list)

for idx, g in enumerate(groups):
    if idx not in to_remove:
        continue
    ci = g["contract_idx"]
    ji = g["chunk_idx"]
    removed_by_contract[ci].append(ji)

# Applichiamo la cancellazione chunk–per–chunk
final_contracts = []

for ci, contract in enumerate(contracts):
    chunks = contract.get("chunks", [])
    if not chunks:
        continue

    removed_indices = set(removed_by_contract.get(ci, []))
    if not removed_indices:
        # contratto intatto
        final_contracts.append(contract)
        continue

    new_chunks = []
    removed_chunks_here = []
    for ji, ch in enumerate(chunks):
        if ji in removed_indices:
            removed_chunks_here.append(ch)
        else:
            new_chunks.append(ch)

    if new_chunks:
        new_contract = {
            "contract": contract["contract"],
            "chunks": new_chunks,
        }
        final_contracts.append(new_contract)

    if removed_chunks_here:
        removed_records.append({
            "contract": contract["contract"],
            "chunks": removed_chunks_here,
        })

# Scrittura del dataset sottocampionato
with OUTPUT_FILE.open("w", encoding="utf-8") as f_out:
    for rec in final_contracts:
        f_out.write(json.dumps(rec, ensure_ascii=False) + "\n")

# Scrittura opzionale dei chunk rimossi
with REMOVED_FILE.open("w", encoding="utf-8") as f_rm:
    for rec in removed_records:
        f_rm.write(json.dumps(rec, ensure_ascii=False) + "\n")

print("\n[✓] Undersampling completato.")
print(f"[INFO] Contratti rimanenti: {len(final_contracts)}")
print(f"[INFO] File output:   {OUTPUT_FILE}")
print(f"[INFO] Chunk rimossi: {len(removed_records)} contratti interessati, dettagli in {REMOVED_FILE}")

print("\n[INFO] Conteggi FINALi per categoria:")
for cat in TARGET_CATEGORIES:
    print(f"  {cat}: tot={cat_total_counts[cat]}, pure_single={cat_pure_single_counts[cat]}")
