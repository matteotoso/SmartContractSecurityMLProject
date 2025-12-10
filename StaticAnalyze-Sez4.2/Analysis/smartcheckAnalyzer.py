import subprocess
from pathlib import Path
import shutil
import os

# ---------------------------------------
# CONFIGURAZIONE
# ---------------------------------------
contracts_dir = Path("../safeContracts")   # cartella con i .sol
results_dir = Path("../results_smartcheck")   # cartella dei risultati SmartBugs
logs_dir = Path("../logs_extracted_safe")          # cartella dove salvare i log come .txt

# Assicurati che le cartelle esistano
results_dir.mkdir(parents=True, exist_ok=True)
logs_dir.mkdir(parents=True, exist_ok=True)

# ---------------------------------------
# 1. Trova tutti i file .sol
# ---------------------------------------
sol_files = sorted(contracts_dir.glob("*.sol"))
if not sol_files:
    print("❌ Nessun file .sol trovato in", contracts_dir)
    exit(1)

# ---------------------------------------
# 2. Filtra i contratti senza report (senza usare .stem)
# ---------------------------------------
pending_files = []
for f in sol_files:
    # Prendi il nome del file senza estensione usando os.path.splitext
    file_name = os.path.splitext(f.name)[0]
    report_file = logs_dir / (file_name + ".txt")
    if not report_file.exists():
        pending_files.append(f)

if not pending_files:
    print("✅ Tutti i contratti hanno già un report. Nessuna analisi necessaria.")
    exit()

total_files = len(pending_files)
print(f"📊 Trovati {total_files} contratti da analizzare (su {len(sol_files)} totali).\n")

# ---------------------------------------
# 3. Analizza i contratti pendenti
# ---------------------------------------
for i, contract in enumerate(pending_files, start=1):
    file_name = os.path.splitext(contract.name)[0]
    output_txt = logs_dir / (file_name + ".txt")
    print(f"🔍 [{i}/{total_files}] Analisi di: {contract.name}")

    try:
        subprocess.run([
            "python", "-m", "sb",
            "-t", "smartcheck",
            "-f", str(contract),
            "--results", str(results_dir)
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Errore durante l'analisi di {contract.name}: {e}")
        continue

    # ---------------------------------------
    # 4. Prendi il file .log e salva come .txt
    # ---------------------------------------
    log_files = list(results_dir.glob("*.log"))
    if not log_files:
        print(f"⚠️ Nessun file .log trovato per {contract.name}")
        continue

    log_file = log_files[0]
    with open(log_file, "r", encoding="utf-8") as f:
        log_content = f.read()

    with open(output_txt, "w", encoding="utf-8") as f:
        f.write(log_content)

    print(f"✅ Log salvato come {output_txt.name}")

    # ---------------------------------------
    # 5. Pulisci la cartella results_smartcheck
    # ---------------------------------------
    for item in results_dir.iterdir():
        if item.is_file():
            item.unlink()
        elif item.is_dir():
            shutil.rmtree(item)

print(f"\n🎯 Tutti i log salvati correttamente in: {logs_dir}")
print(f"🧹 Cartella {results_dir} pulita dopo ogni contratto.")
