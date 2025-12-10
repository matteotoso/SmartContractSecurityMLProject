import os
import subprocess
import re

# Cartella con i contratti
sol_folder = "contracts"

# Regex per catturare pragma solidity
pragma_regex = re.compile(r"pragma solidity\s+([^;]+);")

# Lista contratti che non compilano
failed_contracts = []

def extract_version(raw_version):
    """Estrae la prima versione numerica da pragma (es. >=0.7.0 <0.9.0 -> 0.7.0)"""
    match = re.search(r"\d+\.\d+\.\d+", raw_version)
    return match.group(0) if match else None

# Scansiona i file .sol
for idx, file_name in enumerate(os.listdir(sol_folder), 1):
    if not file_name.endswith(".sol"):
        continue

    file_path = os.path.join(sol_folder, file_name)

    # Mostra a quale contratto siamo arrivati
    print(f"[INFO] ({idx}) Processando: {file_name}")

    # Leggi pragma
    versione = None
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            match = pragma_regex.search(line)
            if match:
                versione = extract_version(match.group(1))
                break

    if not versione:
        print(f"[ATTENZIONE] {file_name} → pragma non trovato, contratto eliminato")
        failed_contracts.append(file_name)
        os.remove(file_path)
        continue

    print(f"[INFO] {file_name} → uso Solidity {versione}")

    # Imposta la versione di solc
    res = subprocess.run(["solc-select", "use", versione], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[ERRORE] {file_name} → impossibile usare solc {versione}, contratto eliminato")
        failed_contracts.append(file_name)
        os.remove(file_path)
        continue

    # Prova a compilare
    res = subprocess.run(["solc", "--bin", file_path], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[ERRORE] {file_name} → compilazione fallita, contratto eliminato")
        failed_contracts.append(file_name)
        os.remove(file_path)

print("\n=== RISULTATI ===")
if failed_contracts:
    print("Contratti eliminati perché non compilavano:")
    for fc in failed_contracts:
        print(f" - {fc}")
else:
    print("Tutti i contratti compilano correttamente!")
