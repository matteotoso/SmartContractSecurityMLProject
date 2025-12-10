"""
Script per la suddivisione in chunk dei contratti Solidity  
-----------------------------------------------------------

Questo script ha lo scopo di suddividere automaticamente gli smart contract
in blocchi (chunk) compatibili con il limite massimo di token previsto dai
modelli CodeBERT/CodeBERTa. Ogni chunk rappresenta una porzione logica del 
contratto: funzioni, costruttori, modifier e blocchi di controllo.

Il processo garantisce che:

- Nessun chunk superi `max_tokens`.
- I blocchi logici non vengano spezzati in punti incoerenti.
- Le funzioni troppo lunghe vengano suddivise tramite una logica dedicata
  (mini-split), mantenendo il più possibile la relazione strutturale interna.
- I modifier vengono aggregati alla funzione che li utilizza.
- Viene prodotta una struttura JSONL facilmente utilizzabile per il training.

Autore: Matteo Toso  
Anno: 2025  
"""

import json
import os
import re
from transformers import AutoTokenizer


# ============================================================
# === Configurazione
# ============================================================

jsonl_file  = "Data/chunkDivision/splitContracts.jsonl"       # File JSONL con metadati funzioni/modifier
sol_folder  = "contractsSelectedClean"                        # Cartella contenente i .sol completi
output_file = "Data/chunkDivision/contractsChunks.jsonl"      # File di output
max_tokens  = 512                                             # Token massimi per chunk


# ============================================================
# === Tokenizer di CodeBERT
# ============================================================

tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")


# ============================================================
# === Regex per intercettare definizioni di contract / library / interface
# ============================================================

contract_pattern = re.compile(r"^\s*(contract|library|interface)\s+\w+")


# ============================================================
# === Funzione mini-split per funzioni molto lunghe
# ============================================================

def mini_split(func_lines, max_tokens, tokenizer, chunk_id=None, base_start_line=1):
    """
    Suddivide funzioni estremamente lunghe in sotto-chunk coerenti.
    Mantiene blocchi logici, gestisce i modifier e rispetta max_tokens.
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
    function_started = False

    for i, line in enumerate(func_lines):
        stripped_line = line.strip()
        line_tokens = len(tokenizer.tokenize(line))

        # Blocchi modifier
        if stripped_line.startswith("modifier"):
            modifier_mode = True
            balance = 0

        if modifier_mode:
            block.append(line)
            block_lines_idx.append(base_start_line + i)
            block_tokens += line_tokens
            balance += line.count("{") - line.count("}")

            if balance > 0:
                continue

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

        # Identificazione inizio funzione
        if not function_started:
            if "{" in line:
                function_started = True
            block.append(line)
            block_lines_idx.append(base_start_line + i)
            block_tokens += line_tokens
            continue

        # Accumulo righe funzione
        block.append(line)
        block_lines_idx.append(base_start_line + i)
        block_tokens += line_tokens
        balance += line.count("{") - line.count("}")

        # Gestione blocchi di controllo (if/else/catch)
        line_check = stripped_line.lstrip("}").strip()
        if any(line_check.startswith(k) for k in ("if", "try")):
            inside_control_block = True
        elif inside_control_block and any(line_check.startswith(k) for k in ("else if", "else", "catch")):
            inside_control_block = True
        elif inside_control_block and balance == 0:
            inside_control_block = False

        # Chiusura blocco logico
        if balance == 0 and not inside_control_block:

            # Caso blocco troppo grande
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

            # Blocco rientra nel chunk corrente
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

    # Righe rimanenti
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


# ============================================================
# === Elaborazione di tutti i contratti
# ============================================================

# Creazione directory output (se non esiste)
os.makedirs(os.path.dirname(output_file), exist_ok=True)

with open(output_file, "w", encoding="utf-8") as f_out:
    with open(jsonl_file, "r", encoding="utf-8") as f_jsonl:

        for line in f_jsonl:
            if not line.strip():
                continue

            contract_data = json.loads(line)
            contract_name = contract_data["file"]
            elements = contract_data.get("elements", [])

            # Percorso del sorgente Solidity
            sol_path = os.path.join(sol_folder, f"{contract_name}.sol")

            if not os.path.exists(sol_path):
                print(f"[ATTENZIONE] File .sol non trovato: {sol_path}, salto contratto")
                continue

            with open(sol_path, "r", encoding="utf-8") as fsol:
                sol_lines = fsol.readlines()

            # Estrarre range di funzioni/modifier
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

            # Variabili di accumulo chunk
            chunks = []
            current_chunk = []
            current_chunk_lines_idx = []
            current_tokens = 0
            line_idx = 1
            element_idx = 0
            total_lines = len(sol_lines)
            used_modifiers = [m for el in elements for m in el.get("modifiers", [])]
            chunk_id = 0

            # ============================================================
            # === Ciclo principale di costruzione chunk
            # ============================================================
            while line_idx <= total_lines:

                line = sol_lines[line_idx - 1]

                # Nuovo contratto: salva chunk corrente
                if contract_pattern.match(line) and current_chunk:
                    if any("}" in l for l in current_chunk):
                        chunk_id += 1
                        chunks.append({
                            "lines": current_chunk,
                            "lines_idx": current_chunk_lines_idx,
                            "token_count": current_tokens,
                            "sub_chunks": []
                        })
                        current_chunk = []
                        current_chunk_lines_idx = []
                        current_tokens = 0

                # Evita di duplicare i modifier
                found_modifier = next(
                    (mod for mod in used_modifiers
                     if int(mod["lines"].split("-")[0]) <= line_idx <= int(mod["lines"].split("-")[1])),
                    None
                )
                if found_modifier:
                    line_idx = int(found_modifier["lines"].split("-")[1]) + 1
                    continue

                # Funzione o costruttore
                if element_idx < len(element_ranges) and line_idx == element_ranges[element_idx]["start"]:

                    el = element_ranges[element_idx]
                    start, end = el["start"], el["end"]

                    func_tokens = len(tokenizer.tokenize("".join(sol_lines[start - 1:end])))

                    # Inserimento eventuali modifier
                    func_lines = []
                    func_lines_idx = []
                    ignore_mod_check = current_tokens + func_tokens > max_tokens

                    for mod in el["modifiers"]:
                        mod_start, mod_end = map(int, mod["lines"].split("-"))
                        mod_lines = sol_lines[mod_start - 1:mod_end]
                        mod_range = list(range(mod_start, mod_end + 1))

                        if ignore_mod_check or not any(idx in current_chunk_lines_idx for idx in mod_range):
                            func_lines.extend(mod_lines)
                            func_lines_idx.extend(mod_range)

                    func_lines.extend(sol_lines[start - 1:end])
                    func_lines_idx.extend(range(start, end + 1))

                    func_tokens = len(tokenizer.tokenize("".join(func_lines)))

                    # Funzione troppo grande → mini-split
                    if func_tokens > max_tokens:
                        if current_chunk:
                            chunk_id += 1
                            chunks.append({
                                "lines": current_chunk,
                                "lines_idx": current_chunk_lines_idx,
                                "token_count": current_tokens,
                                "sub_chunks": []
                            })

                        chunk_id += 1
                        sub_chunks = mini_split(
                            func_lines, max_tokens, tokenizer,
                            chunk_id=chunk_id, base_start_line=func_lines_idx[0]
                        )

                        chunks.append({
                            "lines": func_lines,
                            "lines_idx": func_lines_idx,
                            "token_count": func_tokens,
                            "sub_chunks": sub_chunks
                        })

                        current_chunk = []
                        current_chunk_lines_idx = []
                        current_tokens = 0

                    else:
                        if current_tokens + func_tokens > max_tokens and current_chunk:
                            chunk_id += 1
                            chunks.append({
                                "lines": current_chunk,
                                "lines_idx": current_chunk_lines_idx,
                                "token_count": current_tokens,
                                "sub_chunks": []
                            })
                            current_chunk = func_lines
                            current_chunk_lines_idx = func_lines_idx
                            current_tokens = func_tokens

                        else:
                            current_chunk.extend(func_lines)
                            current_chunk_lines_idx.extend(func_lines_idx)
                            current_tokens += func_tokens

                    line_idx = end + 1
                    element_idx += 1
                    continue

                # Righe standard
                line_tokens = len(tokenizer.tokenize(line))

                if current_tokens + line_tokens > max_tokens and current_chunk:
                    chunk_id += 1
                    chunks.append({
                        "lines": current_chunk,
                        "lines_idx": current_chunk_lines_idx,
                        "token_count": current_tokens,
                        "sub_chunks": []
                    })
                    current_chunk = [line]
                    current_chunk_lines_idx = [line_idx]
                    current_tokens = line_tokens

                else:
                    current_chunk.append(line)
                    current_chunk_lines_idx.append(line_idx)
                    current_tokens += line_tokens

                line_idx += 1

            # Ultimo chunk
            if current_chunk:
                chunk_id += 1
                chunks.append({
                    "lines": current_chunk,
                    "lines_idx": current_chunk_lines_idx,
                    "token_count": current_tokens,
                    "sub_chunks": []
                })

            # Scrittura su JSONL
            f_out.write(json.dumps({
                "contract": contract_name,
                "chunks": chunks
            }, ensure_ascii=False) + "\n")
