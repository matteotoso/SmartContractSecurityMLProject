"""
Modulo di normalizzazione dei report di vulnerabilità
------------------------------------------------------

Questo script realizza un processo di armonizzazione dei risultati
provenienti da tre strumenti di analisi statica per smart contract 
Solidity: Mythril, Slither e SmartCheck.

Poiché ciascun tool adotta criteri differenti per la classificazione 
delle vulnerabilità (SWC-ID, codici interni o etichette proprietarie), 
lo script effettua una mappatura unificata verso un insieme comune 
di categorie macro. Il risultato finale consiste in un file JSONL 
normalizzato, adatto a successive analisi quantitative oppure alla 
creazione di dataset per modelli di apprendimento automatico.

Autore: Matteo Toso
Anno accademico: 2025
"""

import json
from pathlib import Path
import argparse


# ==============================================================
# 1. Mappatura unificata delle categorie di vulnerabilità
# --------------------------------------------------------------
# Ogni strumento utilizza una tassonomia diversa. Le voci vengono
# convertite in sette categorie macro condivise.
# ==============================================================

MYTHRIL_MAPPING = {
    "SWC-115": "ACCESS CONTROL",
    "SWC-105": "ACCESS CONTROL",
    "SWC-106": "ACCESS CONTROL",
    "SWC-124": "ACCESS CONTROL",
    "SWC-107": "REENTRANCY",
    "SWC-101": "ARITHMETIC",
    "SWC-116": "ENVIRONMENTAL / TIME DEPENDENCE",
    "SWC-120": "INSECURE RANDOMNESS",
    "SWC-110": "DENIAL OF SERVICE (DOS)",
    "SWC-132": "DENIAL OF SERVICE (DOS)",
    "SWC-104": "UNSAFE EXTERNAL CALLS",
    "SWC-112": "UNSAFE EXTERNAL CALLS",
    "SWC-113": "TRANSACTION ORDER DEPENDENCE (TOD)",
    "SWC-114": "TRANSACTION ORDER DEPENDENCE (TOD)",
    "SWC-123": "LOGIC / IMPLEMENTATION BUGS",
}

SLITHER_MAPPING = {
    "tx-origin": "ACCESS CONTROL",
    "arbitrary-send-eth": "ACCESS CONTROL",
    "suicidal": "ACCESS CONTROL",
    "write-after-write": "ACCESS CONTROL",

    "reentrancy-eth": "REENTRANCY",
    "reentrancy-no-eth": "REENTRANCY",
    "reentrancy-benign": "REENTRANCY",
    "reentrancy-events": "REENTRANCY",

    "incorrect-exp": "ARITHMETIC",
    "tautological-compare": "ARITHMETIC",
    "incorrect-equality": "ARITHMETIC",

    "timestamp": "ENVIRONMENTAL / TIME DEPENDENCE",
    "weak-prng": "INSECURE RANDOMNESS",

    "calls-loop": "DENIAL OF SERVICE (DOS)",
    "msg-value-loop": "DENIAL OF SERVICE (DOS)",
    "locked-ether": "DENIAL OF SERVICE (DOS)",

    "unchecked-lowlevel": "UNSAFE EXTERNAL CALLS",
    "unchecked-send": "UNSAFE EXTERNAL CALLS",
    "unchecked-transfer": "UNSAFE EXTERNAL CALLS",
    "unused-return": "UNSAFE EXTERNAL CALLS",
    "controlled-delegatecall": "UNSAFE EXTERNAL CALLS",

    "boolean-cst": "LOGIC / IMPLEMENTATION BUGS",
    "void-cst": "LOGIC / IMPLEMENTATION BUGS",
    "incorrect-modifier": "LOGIC / IMPLEMENTATION BUGS",
    "erc20-interface": "LOGIC / IMPLEMENTATION BUGS",
    "arbitrary-send-erc20": "LOGIC / IMPLEMENTATION BUGS",
}

SMARTCHECK_MAPPING = {
    "SOLIDITY_TX_ORIGIN": "ACCESS CONTROL",
    "SOLIDITY_LOCKED_MONEY": "DENIAL OF SERVICE (DOS)",

    "SOLIDITY_UINT_CANT_BE_NEGATIVE": "ARITHMETIC",
    "SOLIDITY_SAFEMATH": "ARITHMETIC",

    "SOLIDITY_EXACT_TIME": "ENVIRONMENTAL / TIME DEPENDENCE",
    "SOLIDITY_INCORRECT_BLOCKHASH": "INSECURE RANDOMNESS",

    "SOLIDITY_EXTRA_GAS_IN_LOOPS": "DENIAL OF SERVICE (DOS)",
    "SOLIDITY_GAS_LIMIT_IN_LOOPS": "DENIAL OF SERVICE (DOS)",

    "SOLIDITY_UNCHECKED_CALL": "UNSAFE EXTERNAL CALLS",
    "SOLIDITY_SEND": "UNSAFE EXTERNAL CALLS",

    "SOLIDITY_TRANSFER_IN_LOOP": "TRANSACTION ORDER DEPENDENCE (TOD)",
    "SOLIDITY_REVERT_REQUIRE": "LOGIC / IMPLEMENTATION BUGS",
    "SOLIDITY_PRIVATE_MODIFIER_DONT_HIDE_DATA": "LOGIC / IMPLEMENTATION BUGS",

    "SOLIDITY_ERC20_APPROVE": "LOGIC / IMPLEMENTATION BUGS",
    "SOLIDITY_ERC20_TRANSFER_SHOULD_THROW": "LOGIC / IMPLEMENTATION BUGS",
    "SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE": "LOGIC / IMPLEMENTATION BUGS",
}


# ==============================================================
# 2. Funzioni di supporto
# ==============================================================

def detect_tool(line_obj):
    """
    Identifica quale strumento ha generato la vulnerabilità,
    analizzando i campi caratteristici del record.
    """
    vulns = line_obj.get("vulnerabilities", [])
    if not vulns:
        return "unknown"

    first = vulns[0]

    if "swc_id" in first:
        return "Mythril"
    if any("SOLIDITY_" in (v.get("title", "") or "") for v in vulns):
        return "SmartCheck"
    return "Slither"


def normalize_vuln(vuln, tool, contract):
    """
    Converte una vulnerabilità nel formato unificato:
    - categoria macro
    - severità
    - posizione nel file
    - tool sorgente
    """
    if not vuln:
        return None

    severity = str(vuln.get("severity", "Unknown")).capitalize()
    lines = str(vuln.get("lines", "")).strip()

    if tool == "Mythril":
        categoria = MYTHRIL_MAPPING.get(f"SWC-{vuln.get('swc_id')}")
    elif tool == "Slither":
        categoria = SLITHER_MAPPING.get(vuln.get("title", ""))
    elif tool == "SmartCheck":
        categoria = SMARTCHECK_MAPPING.get(vuln.get("title", ""))
    else:
        return None

    if not categoria:
        return None

    return {
        "contract": contract,
        "tool": tool,
        "categoria": categoria,
        "severity": severity,
        "lines": lines,
    }


SEVERITY_PRIORITY = {"High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


# ==============================================================
# 3. Normalizzazione e deduplicazione dei report
# ==============================================================

def normalize_reports(input_path: str, output_path: str):
    """
    Normalizza un file JSONL contenente vulnerabilità provenienti 
    da diversi strumenti di analisi statica.
    Le vulnerabilità vengono raggruppate, deduplicate e convertite 
    nel formato unificato.
    """

    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(f"File non trovato: {input_path}")

    records_dict = {}

    with input_path.open("r", encoding="utf-8") as infile:
        for line_num, raw_line in enumerate(infile, 1):
            if not raw_line.strip():
                continue

            try:
                data = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            contract = data.get("file", f"unknown_contract_{line_num}")
            tool = detect_tool(data)
            grouped = {}

            # Normalizzazione singole vulnerabilità
            for vuln in data.get("vulnerabilities", []):
                record = normalize_vuln(vuln, tool, contract)
                if not record:
                    continue

                key = (record["contract"], record["tool"], record["categoria"])
                grouped.setdefault(key, []).append(record)

            # Deduplicazione interna
            for base_key, rec_list in grouped.items():
                observed_lines = set()
                filtered = []

                for rec in rec_list:
                    lk = rec["lines"]
                    if lk not in observed_lines:
                        observed_lines.add(lk)
                        filtered.append(rec)

                # Aggiornamento globale con priorità sulla severità
                for rec in filtered:
                    line_key = rec["lines"]
                    dict_key = base_key + (line_key,)

                    new_sev = SEVERITY_PRIORITY.get(rec["severity"], 0)
                    existing = records_dict.get(dict_key)

                    if existing:
                        old_sev = SEVERITY_PRIORITY.get(existing["severity"], 0)
                        if new_sev > old_sev:
                            records_dict[dict_key] = rec
                    else:
                        records_dict[dict_key] = rec

    # Scrittura file normalizzato
    output_path = Path(output_path)
    with output_path.open("w", encoding="utf-8") as outfile:
        for record in records_dict.values():
            outfile.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"Report normalizzato salvato in: {output_path}")


# ==============================================================
# 4. Interfaccia CLI
# ==============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normalizza report JSONL generati da Mythril, Slither e SmartCheck.")
    parser.add_argument("input_jsonl", help="Percorso del file JSONL di input.")
    parser.add_argument("-o", "--output", default="normalized_report.jsonl", help="Percorso del file JSONL di output.")

    args = parser.parse_args()
    normalize_reports(args.input_jsonl, args.output)
