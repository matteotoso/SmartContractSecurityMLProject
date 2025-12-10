import pandas as pd
import numpy as np
from skmultilearn.model_selection import iterative_train_test_split
from sklearn.preprocessing import MultiLabelBinarizer

# =========================
#   CONFIG
# =========================
INPUT_FILE = "Data/chunkDivision/CodeBertDataset.jsonl"

TRAIN_FILE = "Data/datasetFinal/train.jsonl"
VAL_FILE   = "Data/datasetFinal/validation.jsonl"
TEST_FILE  = "Data/datasetFinal/test.jsonl"

TEST_SIZE = 0.2   # 20% → (val + test)
VAL_SIZE  = 0.5   # del temp → metà val, metà test

NUM_LABELS = 10   # label da 0 a 9

# =========================
#   1️⃣ CARICA DATASET
# =========================
df = pd.read_json(INPUT_FILE, lines=True)
assert "label" in df.columns, "❌ Il file deve contenere 'label'"

print(f"📂 Caricate {len(df)} righe dal dataset originale")

# =========================
#   2️⃣ MULTILABEL BINARIZATION
# =========================
mlb = MultiLabelBinarizer(classes=list(range(NUM_LABELS)))
Y = mlb.fit_transform(df["label"])
X = np.arange(len(df)).reshape(-1, 1)

# =========================
#   3️⃣ SPLIT MULTILABEL STRATIFICATO
# =========================

# Primo split: train (80%) + temp (20%)
X_train, y_train, X_temp, y_temp = iterative_train_test_split(
    X, Y, test_size=TEST_SIZE
)

# Secondo split: val (10%) + test (10%)
X_val, y_val, X_test, y_test = iterative_train_test_split(
    X_temp, y_temp, test_size=VAL_SIZE
)

train_df = df.iloc[X_train.ravel()].reset_index(drop=True)
val_df   = df.iloc[X_val.ravel()].reset_index(drop=True)
test_df  = df.iloc[X_test.ravel()].reset_index(drop=True)

# =========================
#   4️⃣ SALVA FILE
# =========================
for name, split_df, file in [
    ("TRAIN", train_df, TRAIN_FILE),
    ("VAL",   val_df,   VAL_FILE),
    ("TEST",  test_df,  TEST_FILE),
]:
    split_df.to_json(file, orient="records", lines=True, force_ascii=False)
    print(f"✅ {name}: {len(split_df)} esempi salvati in {file}")

# =========================
#   5️⃣ DISTRIBUZIONE LABEL
# =========================
def label_counts(df):
    counts = {i: 0 for i in range(NUM_LABELS)}
    for labels in df["label"]:
        for l in labels:
            counts[l] += 1
    return counts

print("\n📊 Distribuzione finale dopo split:")
for name, split_df in [("TRAIN", train_df), ("VAL", val_df), ("TEST", test_df)]:
    print(f"\n{name}:")
    counts = label_counts(split_df)
    for lbl, cnt in sorted(counts.items()):
        print(f"  Label {lbl}: {cnt}")
