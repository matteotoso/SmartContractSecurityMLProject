import os
import hashlib

def get_code_hash(code: str) -> str:
    # Normalizza rimuovendo commenti e righe vuote
    lines = []
    for line in code.splitlines():
        line = line.strip()
        if line.startswith("//") or line.startswith("/*") or line == "":
            continue
        lines.append(line)
    normalized = "\n".join(lines)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

unique_contracts = {}
base_path = "contracts"
duplicates_removed = 0

for root, _, files in os.walk(base_path):
    for f in files:
        if f.endswith(".sol"):
            path = os.path.join(root, f)
            with open(path, "r", errors="ignore") as file:
                code = file.read()

            # Calcolo hash DOPO aver chiuso il file
            h = get_code_hash(code)

            if h not in unique_contracts:
                # Primo file con questo hash → lo teniamo
                unique_contracts[h] = path
            else:
                # Duplicato → rimuoviamo
                print(f"Rimuovo duplicato: {path}")
                try:
                    os.remove(path)
                    duplicates_removed += 1
                except PermissionError as e:
                    print(f"Non riesco a rimuovere {path}: {e}")

print(f"Contratti unici rimasti: {len(unique_contracts)}")
print(f"Duplicati rimossi: {duplicates_removed}")
