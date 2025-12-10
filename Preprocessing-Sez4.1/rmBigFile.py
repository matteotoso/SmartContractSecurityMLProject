import os

cartella_contracts = os.path.join(os.getcwd(), "contracts")

for root, _, files in os.walk(cartella_contracts):
    for f in files:
        if f.endswith(".sol"):
            percorso = os.path.join(root, f)
            with open(percorso, "r", encoding="utf-8", errors="ignore") as file:
                righe = sum(1 for _ in file)
            if righe > 500:
                os.remove(percorso)
                print(f"Rimosso: {percorso} ({righe} righe)")
