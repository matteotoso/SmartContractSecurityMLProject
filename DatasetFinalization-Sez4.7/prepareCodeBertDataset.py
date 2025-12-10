import pandas as pd
import json
from sklearn.preprocessing import MultiLabelBinarizer
import argparse

# === 1️⃣ Setup argomenti da linea di comando ===
parser = argparse.ArgumentParser(description="Converti dataset multilabel per CodeBERT small v1")
parser.add_argument("--input", "-i", required=True, help="File JSONL di input")
parser.add_argument("--output", "-o", required=True, help="File JSONL di output")
parser.add_argument("--num_labels", "-n", type=int, default=10, help="Numero totale di categorie")
args = parser.parse_args()

INPUT_FILE = args.input
OUTPUT_FILE = args.output
NUM_LABELS = args.num_labels

# === 2️⃣ Carica dataset ===
df = pd.read_json(INPUT_FILE, lines=True)
print(f"📂 Caricate {len(df)} righe dal dataset {INPUT_FILE}")

# === 3️⃣ MultiLabelBinarizer ===
mlb = MultiLabelBinarizer(classes=list(range(NUM_LABELS)))
labels_bin = mlb.fit_transform(df["label"])

# === 4️⃣ Crea nuovo dataset con codice concatenato ===
new_rows = []
for i, row in df.iterrows():
    code_text = "".join(row["code"])  # concatena tutte le righe
    new_rows.append({
        "code": code_text,
        "labels": labels_bin[i].tolist()
    })

# === 5️⃣ Salva come JSONL ===
with open(OUTPUT_FILE, "w") as f:
    for row in new_rows:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")

print(f"✅ Salvato {len(new_rows)} esempi in {OUTPUT_FILE}")
