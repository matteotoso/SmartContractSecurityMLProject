import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# === CONFIGURAZIONE ===
INPUT_DIR = "./safeContracts"
OUTPUT_DIR = "./my_reports"

MYTHRIL_IMAGE = "mythril/myth"
EXECUTION_TIMEOUT = 60
MAX_DEPTH = 22
SOLVER_TIMEOUT = 15000
MAX_PARALLEL = 4  # numero massimo di container in parallelo

# === SETUP ===
os.makedirs(OUTPUT_DIR, exist_ok=True)
abs_input_dir = os.path.abspath(INPUT_DIR)

# === TROVA FILE DA ANALIZZARE ===
sol_files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".sol")]

# Filtra solo quelli **senza report già presente**
pending_files = []
for f in sol_files:
    report_path = os.path.join(OUTPUT_DIR, os.path.splitext(f)[0] + ".txt")
    if not os.path.exists(report_path):
        pending_files.append(f)

if not pending_files:
    print("✅ Tutti i contratti hanno già un report. Nessuna analisi necessaria.")
    exit()

total_files = len(pending_files)
print(f"📊 Trovati {total_files} contratti da analizzare (su {len(sol_files)} totali).\n")

# === FUNZIONE DI ANALISI ===
def analyze_contract(filename, index):
    input_path = os.path.join(INPUT_DIR, filename)
    output_filename = os.path.splitext(filename)[0] + ".txt"
    output_path = os.path.join(OUTPUT_DIR, output_filename)

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{abs_input_dir}:/tmp",
        MYTHRIL_IMAGE,
        "analyze", f"/tmp/{filename}",
        "--execution-timeout", str(EXECUTION_TIMEOUT),
        "--max-depth", str(MAX_DEPTH),
        "--solver-timeout", str(SOLVER_TIMEOUT),
        "--parallel-solving",
        "--disable-iprof"
    ]

    print(f"[{index}/{total_files}] 🚀 Avvio analisi: {filename}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)
        print(f"[{index}/{total_files}] ✅ Completato: {filename}")
    except Exception as e:
        print(f"[{index}/{total_files}] ❌ Errore in {filename}: {e}")

# === ESECUZIONE PARALLELA ===
with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as executor:
    futures = {
        executor.submit(analyze_contract, f, i + 1): f
        for i, f in enumerate(pending_files)
    }
    for future in as_completed(futures):
        future.result()

print("\n🏁 Analisi completata per tutti i contratti rimanenti!")
