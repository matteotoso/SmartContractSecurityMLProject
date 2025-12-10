#!/usr/bin/env python3
import os
import re
import subprocess
import json
from slither.slither import Slither

# =========================
# CONFIGURAZIONE
# =========================
contracts_dir = "contractsSelected"  # cartella dei contratti .sol
output_file = "splitContracts.jsonl"

# Regex per catturare pragma solidity
pragma_regex = re.compile(r"pragma solidity\s+([^;]+);")

def extract_version(raw_version):
    """Estrae la prima versione numerica da pragma (es. >=0.7.0 <0.9.0 -> 0.7.0)"""
    match = re.search(r"\d+\.\d+\.\d+", raw_version)
    return match.group(0) if match else None

# =========================
# SCRIPT PRINCIPALE
# =========================
with open(output_file, "w", encoding="utf-8") as out:
    for root, _, files in os.walk(contracts_dir):
        for file in files:
            if not file.endswith(".sol"):
                continue

            path = os.path.join(root, file)

            # ----------------------
            # Leggi pragma per la versione di solc
            # ----------------------
            versione = None
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    match = pragma_regex.search(line)
                    if match:
                        versione = extract_version(match.group(1))
                        break

            if not versione:
                print(f"[ATTENZIONE] {file} → pragma non trovato, salto file")
                continue

            # ----------------------
            # Imposta versione corretta di solc
            # ----------------------
            res = subprocess.run(["solc-select", "use", versione], capture_output=True, text=True)
            if res.returncode != 0:
                print(f"[ERRORE] {file} → impossibile usare solc {versione}")
                continue

            # ----------------------
            # Analisi con Slither
            # ----------------------
            try:
                sl = Slither(path)
            except Exception as e:
                print(f"[!] Skipping {file}: {e}")
                continue

            elements_list = []
            seen_ranges = set()  # per evitare duplicati basati sul line_range

            # Mappa dei modifier del contratto
            modifier_map = {}
            for contract in sl.contracts:
                for mod in contract.modifiers:
                    lines = getattr(mod.source_mapping, "lines", None)
                    if not lines:
                        continue
                    line_range = f"{min(lines)}-{max(lines)}"
                    modifier_map[mod.name] = {
                        "name": mod.name,
                        "lines": line_range
                    }

            # Funzioni con modifier
            for contract in sl.contracts:
                for func in contract.functions:
                    if func.name.startswith("slither"):
                        continue

                    lines = getattr(func.source_mapping, "lines", None)
                    if not lines:
                        continue

                    start_line = min(lines)
                    end_line = max(lines)
                    line_range = f"{start_line}-{end_line}"

                    if line_range in seen_ranges:
                        continue
                    seen_ranges.add(line_range)

                    # recupera modifier applicati
                    func_modifiers = []
                    if hasattr(func, "modifiers"):
                        for m in func.modifiers:
                            if m.name in modifier_map:
                                func_modifiers.append(modifier_map[m.name])

                    elements_list.append({
                        "full_name": func.full_name,
                        "lines": line_range,
                        "type": "function",
                        "modifiers": func_modifiers
                    })

            if elements_list:
                out.write(json.dumps({
                    "file": os.path.splitext(file)[0],
                    "elements": elements_list
                }, ensure_ascii=False) + "\n")

print(f"\n[✓] Estrazione completata! Risultati in → {output_file}")
