import os
import re

# 🔧 Inserisci solo il nome della cartella (non tutto il percorso)
nome_cartella = "my_report_vuln"   # ← cambia solo questo

# trova il percorso completo relativo alla cartella corrente
cartella = os.path.join(os.getcwd(), nome_cartella)

pattern = re.compile(r"^=+\s*(.*?)\s*=+\s*[\r\n]+SWC\s*ID\s*:\s*(\d+)", re.MULTILINE | re.IGNORECASE)

# insieme per evitare duplicati
trovati = set()

if not os.path.isdir(cartella):
    print(f"❌ La cartella '{cartella}' non esiste. Controlla il nome.")
else:
    for root, _, files in os.walk(cartella):
        for nomefile in files:
            if nomefile.lower().endswith(".txt"):
                percorso = os.path.join(root, nomefile)
                try:
                    with open(percorso, "r", encoding="utf-8", errors="ignore") as f:
                        testo = f.read()
                    matches = pattern.findall(testo)
                    for descrizione, swc in matches:
                        trovati.add((descrizione.strip(), swc.strip()))
                except Exception as e:
                    print(f"Errore leggendo {percorso}: {e}")

    if trovati:
        print("\n=== Tipi di vulnerabilità trovati ===\n")
        for descrizione, swc in sorted(trovati, key=lambda x: int(x[1])):
            print(f"SWC-{swc}: {descrizione}")
        print(f"\nTotale tipi distinti: {len(trovati)}")
    else:
        print("⚠️  Nessuna vulnerabilità trovata nei file .txt.")
