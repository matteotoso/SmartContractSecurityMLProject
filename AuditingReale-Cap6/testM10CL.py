#!/usr/bin/env python3
import os
import re
import torch
from slither.slither import Slither
from transformers import AutoModelForSequenceClassification
from transformers import AutoTokenizer



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

NUM_LABELS = len(combo_map)   #
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

MODEL_DIR = "CodeBERT_multilabel_model"

tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR).to(DEVICE)
model.eval()

# ============================================================
# 1️⃣ CLEAN CODE — rimuove commenti mantenendo le linee
# ============================================================
def clean_code_file(input_path: str, output_path: str):
    """Legge un file .sol, rimuove i commenti mantenendo le linee e salva il file pulito."""
    with open(input_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    def remove_block_comments(match):
        text = match.group(0)
        return "\n" * text.count("\n")

    # Rimuovi commenti multi-linea /* ... */
    no_block = re.sub(r"/\*.*?\*/", remove_block_comments, source_code, flags=re.DOTALL)

    cleaned_lines = []
    for line in no_block.splitlines():
        if "//" in line:
            idx = line.find("//")
            cleaned_lines.append(line[:idx].rstrip())
        else:
            cleaned_lines.append(line.rstrip())

    cleaned_code = "\n".join(cleaned_lines)

    # Salva il file pulito
    with open(output_path, "w", encoding="utf-8") as f_out:
        f_out.write(cleaned_code)


# ============================================================
# 2️⃣ EXTRACT VERSION — estrae pragma solidity
# ============================================================
pragma_regex = re.compile(r"pragma solidity\s+([^;]+);")

def extract_version(source_code: str) -> str | None:
    """Estrae la versione solc dal pragma solidity."""
    for line in source_code.splitlines():
        match = pragma_regex.search(line)
        if match:
            raw = match.group(1)
            version = re.search(r"\d+\.\d+\.\d+", raw)
            return version.group(0) if version else None
    return None


# ============================================================
# 3️⃣ EXTRACT ELEMENTS — Slither sul file .sol
# ============================================================
def extract_elements(sol_file_path: str):
    """Estrae funzioni, linee e modifier tramite Slither dal file .sol originale."""
    
    sl = Slither(sol_file_path)
    elements_list = []
    seen_ranges = set()

    for contract in sl.contracts:

        # Mappa modifier del contratto
        modifier_map = {}
        for mod in contract.modifiers:
            lines = mod.source_mapping.lines
            if lines:
                modifier_map[mod.name] = {
                    "name": mod.name,
                    "lines": f"{min(lines)}-{max(lines)}"
                }

        # Funzioni del contratto
        for func in contract.functions_declared:

            # 🚫 IGNORA LA FUNZIONE FANTASMA DI SLITHER
            if func.full_name == "slitherConstructorVariables()":
                continue

            lines = func.source_mapping.lines
            if not lines:
                continue

            start = min(lines)
            end = max(lines)
            line_range = f"{start}-{end}"

            if line_range in seen_ranges:
                continue
            seen_ranges.add(line_range)

            applied_modifiers = [
                modifier_map[m.name]
                for m in func.modifiers
                if m.name in modifier_map
            ]

            elements_list.append({
                "full_name": func.full_name,
                "lines": line_range,
                "type": "function",
                "modifiers": applied_modifiers
            })

    return elements_list



def mini_split(func_lines, max_tokens, tokenizer, chunk_id=None, base_start_line=1):
    """
    Mini-split di una funzione lunga basato su blocchi logici e max token.
    Gestisce i modifier iniziali come blocchi separati.
    La parentesi di apertura della funzione non viene conteggiata nel balance.
    """
    sub_chunks = []
    current_chunk = []
    current_chunk_lines_idx = []
    current_tokens = 0

    block = []
    block_lines_idx = []
    block_tokens = 0
    balance = 0
    inside_control_block = False
    modifier_mode = False
    function_started = False  # True quando inizia il corpo della funzione

    for i, line in enumerate(func_lines):
        stripped_line = line.strip()
        line_tokens = len(tokenizer.tokenize(line))

        # 🔹 Controllo se è un modifier all'inizio
        if stripped_line.startswith("modifier"):
            modifier_mode = True
            balance = 0  # resetta il bilancio parentesi

        if modifier_mode:
            block.append(line)
            block_lines_idx.append(base_start_line + i)
            block_tokens += line_tokens

            # Aggiorna il bilancio parentesi
            # (anche se { è su una riga successiva, il balance lo terrà in sospeso)
            balance += line.count("{") - line.count("}")

            # Se abbiamo trovato almeno una parentesi aperta,
            # restiamo in modalità modifier finché non torna a 0
            if balance > 0:
                # siamo dentro il corpo del modifier
                continue

            # Se balance torna a 0 *dopo* aver aperto un blocco, chiudi il modifier
            if balance == 0 and "modifier" not in stripped_line:
                sub_chunks.append({
                    "lines": block.copy(),
                    "lines_idx": block_lines_idx.copy(),
                    "token_count": block_tokens,
                    "parent_chunk_id": chunk_id
                })
                block = []
                block_lines_idx = []
                block_tokens = 0
                modifier_mode = False
                continue

        # --- Logica funzione ---
        # Se non abbiamo ancora iniziato il corpo, non contare la prima `{`
        if not function_started:
            # Verifica se la riga contiene solo la parentesi di apertura
            if "{" in line:
                function_started = True
                # Non aggiungere `{` al balance
                block.append(line)
                block_lines_idx.append(base_start_line + i)
                block_tokens += line_tokens
                continue
            else:
                block.append(line)
                block_lines_idx.append(base_start_line + i)
                block_tokens += line_tokens
                continue

        # Corpo della funzione già iniziato → conteggio normale del balance
        block.append(line)
        block_lines_idx.append(base_start_line + i)
        block_tokens += line_tokens
        balance += line.count("{") - line.count("}")

        line_check = stripped_line.lstrip("}").strip()
        if any(line_check.startswith(k) for k in ("if", "try")):
            inside_control_block = True
        elif inside_control_block and any(line_check.startswith(k) for k in ("else if", "else", "catch")):
            inside_control_block = True
        elif inside_control_block and balance == 0:
            inside_control_block = False

        if balance == 0 and not inside_control_block:
            # Blocchi troppo grandi → salva chunk separato
            if block_tokens > max_tokens:
                if current_chunk:
                    sub_chunks.append({
                        "lines": current_chunk.copy(),
                        "lines_idx": current_chunk_lines_idx.copy(),
                        "token_count": current_tokens,
                        "parent_chunk_id": chunk_id
                    })
                    current_chunk = []
                    current_chunk_lines_idx = []
                    current_tokens = 0

                sub_chunks.append({
                    "lines": block.copy(),
                    "lines_idx": block_lines_idx.copy(),
                    "token_count": block_tokens,
                    "parent_chunk_id": chunk_id
                })
            else:
                if current_tokens + block_tokens <= max_tokens:
                    current_chunk.extend(block)
                    current_chunk_lines_idx.extend(block_lines_idx)
                    current_tokens += block_tokens
                else:
                    if current_chunk:
                        sub_chunks.append({
                            "lines": current_chunk.copy(),
                            "lines_idx": current_chunk_lines_idx.copy(),
                            "token_count": current_tokens,
                            "parent_chunk_id": chunk_id
                        })
                    current_chunk = block.copy()
                    current_chunk_lines_idx = block_lines_idx.copy()
                    current_tokens = block_tokens

            block = []
            block_lines_idx = []
            block_tokens = 0

    if block:
        if current_chunk and current_tokens + block_tokens <= max_tokens:
            current_chunk.extend(block)
            current_chunk_lines_idx.extend(block_lines_idx)
            current_tokens += block_tokens
        else:
            if current_chunk:
                sub_chunks.append({
                    "lines": current_chunk.copy(),
                    "lines_idx": current_chunk_lines_idx.copy(),
                    "token_count": current_tokens,
                    "parent_chunk_id": chunk_id
                })
            sub_chunks.append({
                "lines": block.copy(),
                "lines_idx": block_lines_idx.copy(),
                "token_count": block_tokens,
                "parent_chunk_id": chunk_id
            })

    if current_chunk:
        sub_chunks.append({
            "lines": current_chunk.copy(),
            "lines_idx": current_chunk_lines_idx.copy(),
            "token_count": current_tokens,
            "parent_chunk_id": chunk_id
        })

    return sub_chunks


# ===========================================================================================
# FUNZIONE PRINCIPALE: chunk_contract()
# ===========================================================================================
def chunk_contract(sol_path: str, elements: list, tokenizer, max_tokens=512):

    with open(sol_path, "r", encoding="utf-8") as fsol:
        sol_lines = fsol.readlines()

    # === Mappa delle funzioni/modifier (per non spezzarle) ===
    element_ranges = []
    for el in elements:
        start, end = map(int, el["lines"].split("-"))
        element_ranges.append({
            "start": start,
            "end": end,
            "name": el.get("full_name", "unknown"),
            "modifiers": el.get("modifiers", [])
        })

    element_ranges.sort(key=lambda x: x["start"])

    # === Regex per riconoscere nuovi contratti ===
    contract_pattern = re.compile(r"^\s*(contract|library|interface)\s+\w+")

    # === Creazione chunk ===
    chunks = []
    current_chunk = []
    current_chunk_lines_idx = []
    current_tokens = 0
    chunk_id = 0
    line_idx = 1
    element_idx = 0
    total_lines = len(sol_lines)
    sub_chunks = []
    sub_chunks_final = []
    used_modifiers = [
        mod
        for el in elements
        for mod in el.get("modifiers", [])
    ]

    # =====================================================
    #                    LOOP PRINCIPALE
    # =====================================================
   
    while line_idx <= total_lines:
        line = sol_lines[line_idx - 1]

        # Se inizia un nuovo contract e il chunk corrente contiene già codice → nuovo chunk
        if contract_pattern.match(line) and current_chunk:
            if any("}" in l for l in current_chunk):
                chunk_id += 1
                chunks.append({
                    "lines": current_chunk,
                    "lines_idx": current_chunk_lines_idx,
                    "token_count": current_tokens,
                    "chunk_id": chunk_id
                })
                current_chunk = []
                current_chunk_lines_idx = []
                current_tokens = 0

        # Salta righe dei modifier già usati
        found_modifier = next(
            (mod for mod in used_modifiers
            if int(mod["lines"].split("-")[0]) <= line_idx <= int(mod["lines"].split("-")[1])),
            None
        )
        if found_modifier:
            line_idx = int(found_modifier["lines"].split("-")[1]) + 1
            continue

        # Controlla se siamo all’inizio di una funzione o costruttore
        if element_idx < len(element_ranges) and line_idx == element_ranges[element_idx]["start"]:
            el = element_ranges[element_idx]
            start, end = el["start"], el["end"]

            func_tokens = len(tokenizer.tokenize("".join(sol_lines[start-1:end])))
            # === Includi prima i modifier ===
            func_lines = []
            func_lines_idx = []
            ignore_modifier_check = current_tokens + func_tokens > max_tokens
            for mod in el["modifiers"]:
                mod_start, mod_end = map(int, mod["lines"].split("-"))
                mod_lines = sol_lines[mod_start-1:mod_end]
                mod_range = list(range(mod_start, mod_end+1))
                if ignore_modifier_check or not any(idx in current_chunk_lines_idx for idx in mod_range):
                    func_lines.extend(mod_lines)
                    func_lines_idx.extend(mod_range)

            # Poi aggiungi le linee della funzione
            func_lines.extend(sol_lines[start-1:end])
            func_lines_idx.extend(range(start, end+1))

            func_tokens = len(tokenizer.tokenize("".join(func_lines)))

            # === 🔹 Caso 1: funzione singolarmente troppo lunga ===
            if func_tokens > max_tokens:
                if current_chunk:
                    chunk_id += 1
                    chunks.append({
                        "lines": current_chunk,
                        "lines_idx": current_chunk_lines_idx,
                        "token_count": current_tokens,
                        "chunk_id": chunk_id
                    })
                chunk_id += 1
                chunks.append({
                    "lines": "",
                    "lines_idx": func_lines_idx,
                    "token_count": func_tokens,
                    "chunk_id": chunk_id
                })
                sub_chunks = mini_split(func_lines, max_tokens, tokenizer, chunk_id=chunk_id, base_start_line=func_lines_idx[0] )
                sub_chunks_final.extend(sub_chunks)
                # Non aggiungere a current_chunk, la gestisci a parte
                current_chunk = []
                current_chunk_lines_idx = []
                current_tokens = 0

            # === 🔹 Caso 2: funzione + chunk corrente superano max_tokens ===
            elif current_tokens + func_tokens > max_tokens and current_chunk:
                chunk_id += 1
                chunks.append({
                    "lines": current_chunk,
                    "lines_idx": current_chunk_lines_idx,
                    "token_count": current_tokens,
                    "chunk_id": chunk_id
                })
                current_chunk = func_lines
                current_chunk_lines_idx = func_lines_idx
                current_tokens = func_tokens

            # === 🔹 Caso 3: funzione normale, dentro al chunk corrente ===
            else:
                current_chunk.extend(func_lines)
                current_chunk_lines_idx.extend(func_lines_idx)
                current_tokens += func_tokens

            line_idx = end + 1
            element_idx += 1
        else:
            # Linea normale
            line_tokens = len(tokenizer.tokenize(line))
            if current_tokens + line_tokens > max_tokens and current_chunk:
                chunk_id += 1
                chunks.append({
                    "lines": current_chunk,
                    "lines_idx": current_chunk_lines_idx,
                    "token_count": current_tokens,
                    "chunk_id": chunk_id
                })
                current_chunk = [line]
                current_chunk_lines_idx = [line_idx]
                current_tokens = line_tokens
            else:
                current_chunk.append(line)
                current_chunk_lines_idx.append(line_idx)
                current_tokens += line_tokens

            line_idx += 1

    # Aggiungi ultimo chunk
    if current_chunk:
        chunk_id += 1
        chunks.append({
            "lines": current_chunk,
            "lines_idx": current_chunk_lines_idx,
            "token_count": current_tokens,
            "chunk_id": chunk_id 
        })

    return {
        "chunks": chunks,
        "subchunks": sub_chunks_final
    }




def predict_vulnerabilities(text, tokenizer, model):
    """Ritorna lista vulnerabilità rilevate nel testo."""
    
    enc = tokenizer(
        text,
        truncation=True,
        padding="max_length",
        max_length=512,
        return_tensors="pt"
    ).to(DEVICE)

    with torch.no_grad():
        logits = model(**enc).logits
        probs = logits.sigmoid().cpu().numpy()[0]
    preds = (probs >= 0.5).astype(int)

    detected = []

    # label 0 = SAFE → la consideriamo solo se è l’unica attiva
    for i in range(1, NUM_LABELS):
        if preds[i] == 1:
            detected.append(combo_map[i])

    if len(detected) == 0:
        return ["SAFE"]

    return detected


def analyze_chunks(chunks, subchunks, tokenizer, model):
    """Analizza tutti i chunk e subchunk >512 token."""
    results = []

    # mappa subchunks per chunk_id
    sub_map = {}
    for sc in subchunks:
        pid = sc.get("parent_chunk_id")
        if pid not in sub_map:
            sub_map[pid] = []
        sub_map[pid].append(sc)

    for ch in chunks:
        cid = ch["chunk_id"]
        token_count = ch["token_count"]

        if token_count <= 512:
            # usare chunk normale
            text = "".join(ch["lines"])
            vulns = predict_vulnerabilities(text, tokenizer, model)

            results.append({
                "chunk_id": cid,
                "lines": ch["lines_idx"],
                "vulnerabilities": vulns
            })
        else:
            # usare subchunks
            sub_vulns = set()

            if cid not in sub_map:
                results.append({
                    "chunk_id": cid,
                    "lines": ch["lines_idx"],
                    "vulnerabilities": ["ERROR: chunk too large and no subchunks"]
                })
                continue

            for sc in sub_map[cid]:
                text = "".join(sc["lines"])
                vulns = predict_vulnerabilities(text, tokenizer, model)
                for v in vulns:
                    sub_vulns.add(v)

            if not sub_vulns:
                sub_vulns = {"SAFE"}

            results.append({
                "chunk_id": cid,
                "lines": ch["lines_idx"],
                "vulnerabilities": list(sub_vulns)
            })

    return results


def print_analysis(analysis):
    print("\n==================== RISULTATI MODELLO ====================")

    for item in analysis:
        print(f"\n--- CHUNK {item['chunk_id']} ---")
        print(f"Linee: {item['lines']}")
        print("Vulnerabilità:")
        for v in item["vulnerabilities"]:
            print(f"  - {v}")

    # Valutazione file
    all_vulns = set()
    for item in analysis:
        for v in item["vulnerabilities"]:
            if v != "SAFE":
                all_vulns.add(v)

    print("\n==================== REPORT FINALE ====================")

    if len(all_vulns) == 0:
        print("🟩 CONTRATTO CLASSIFICATO COME SAFE")
    else:
        print("🟥 CONTRATTO VULNERABLE — Vulnerabilità trovate:")
        for v in all_vulns:
            print(f" - {v}")



# ============================================================
# 4️⃣ MAIN AUTOMATICO (NESSUN INPUT / NESSUN ARGOMENTO)
# ============================================================

if __name__ == "__main__":

    CONTRACT_FOLDER = "contracts"
    
    sol_files = [
        f for f in os.listdir(CONTRACT_FOLDER)
        if f.endswith(".sol")
    ]

    if not sol_files:
        raise FileNotFoundError("❌ Nessun file .sol trovato nella cartella.")

    sol_path = os.path.join(CONTRACT_FOLDER, sol_files[0])
    clean_path = os.path.join("contractsCleanTest", sol_files[0])
    print(f"📄 File selezionato automaticamente: {sol_path}")

    clean_code_file(sol_path, clean_path)
    elements = extract_elements(sol_path)
    result = chunk_contract(clean_path, elements, tokenizer)
    
    chunks = result["chunks"]
    subchunks = result["subchunks"]

    print("🔍 Analisi delle vulnerabilità in corso...")

    analysis = analyze_chunks(chunks, subchunks, tokenizer, model)

    print_analysis(analysis)

   