import json
import torch
import numpy as np
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from transformers import get_linear_schedule_with_warmup
from torch.optim import AdamW
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score
from tqdm import tqdm

# ============================================
# SEED PER RIPRODUCIBILITÀ
# ============================================

torch.manual_seed(42)
np.random.seed(42)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(42)

# ============================================
# CONFIGURAZIONE
# ============================================

TRAIN_FILE = "Data/datasetFinal/trainDataset.jsonl"
VAL_FILE   = "Data/datasetFinal/validationDataset.jsonl"
TEST_FILE  = "Data/datasetFinal/testDataset.jsonl"

MODEL_NAME = "microsoft/codebert-base"
MAX_LENGTH = 512
BATCH_SIZE = 16
EPOCHS     = 10
LR         = 2e-5

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
NUM_LABELS = 10
OUTPUT_METRICS_FILE = "Data/Result/training_metrics.json"

# ============================================
# DATASET CLASS
# ============================================

class CodeDataset(Dataset):
    def __init__(self, file_path, tokenizer, max_length):
        self.samples = []
        with open(file_path, "r") as f:
            for line in f:
                item = json.loads(line)
                self.samples.append({
                    "code": item["code"],
                    "labels": torch.tensor(item["labels"], dtype=torch.float)
                })
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        item = self.samples[idx]
        enc = self.tokenizer(
            item["code"],
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt"
        )
        return {
            "input_ids": enc["input_ids"].squeeze(0),
            "attention_mask": enc["attention_mask"].squeeze(0),
            "labels": item["labels"]
        }

# ============================================
# LOAD TOKENIZER & DATASETS
# ============================================

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

train_dataset = CodeDataset(TRAIN_FILE, tokenizer, MAX_LENGTH)
val_dataset   = CodeDataset(VAL_FILE, tokenizer, MAX_LENGTH)
test_dataset  = CodeDataset(TEST_FILE, tokenizer, MAX_LENGTH)

train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True, drop_last=True)
val_loader   = DataLoader(val_dataset, batch_size=BATCH_SIZE, drop_last=False)
test_loader  = DataLoader(test_dataset, batch_size=BATCH_SIZE, drop_last=False)

# ============================================
# MODELLO
# ============================================

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=NUM_LABELS,
    problem_type="multi_label_classification"
).to(DEVICE)

# ============================================
# LOSS (senza pos_weight)
# ============================================

criterion = torch.nn.BCEWithLogitsLoss()

# ============================================
# OPTIMIZER & SCHEDULER
# ============================================

optimizer = AdamW(model.parameters(), lr=LR)
total_steps = len(train_loader) * EPOCHS

scheduler = get_linear_schedule_with_warmup(
    optimizer,
    num_warmup_steps=int(0.1 * total_steps),
    num_training_steps=total_steps
)

# ============================================
# EVALUATION FUNCTION
# ============================================

def evaluate(model, dataloader):
    model.eval()
    preds, labels_all = [], []

    with torch.no_grad():
        for batch in dataloader:
            ids = batch["input_ids"].to(DEVICE)
            mask = batch["attention_mask"].to(DEVICE)
            labs = batch["labels"].cpu().numpy()

            out = model(input_ids=ids, attention_mask=mask)
            logits = out.logits.sigmoid().cpu().numpy()

            preds.append(logits)
            labels_all.append(labs)

    preds = np.vstack(preds)
    labels_all = np.vstack(labels_all)
    preds_bin = (preds >= 0.5).astype(int)

    metrics = {
        "macro_f1":  float(f1_score(labels_all, preds_bin, average="macro")),
        "micro_f1":  float(f1_score(labels_all, preds_bin, average="micro")),
        "precision": float(precision_score(labels_all, preds_bin, average="macro")),
        "recall":    float(recall_score(labels_all, preds_bin, average="macro")),
        "accuracy":  float(accuracy_score(labels_all, preds_bin)),
        "per_class": {}
    }

    for i in range(NUM_LABELS):
        metrics["per_class"][i] = {
            "precision": float(precision_score(labels_all[:, i], preds_bin[:, i], zero_division=0)),
            "recall":    float(recall_score(labels_all[:, i], preds_bin[:, i], zero_division=0)),
            "f1":        float(f1_score(labels_all[:, i], preds_bin[:, i], zero_division=0)),
            "accuracy":  float(accuracy_score(labels_all[:, i], preds_bin[:, i])),
        }

    return metrics

# ============================================
# LOG SETUP
# ============================================

log = {
    "config": {
        "model": MODEL_NAME,
        "epochs": EPOCHS,
        "batch_size": BATCH_SIZE,
        "learning_rate": LR,
        "num_labels": NUM_LABELS,
        "device": DEVICE,
        "loss_function": "BCEWithLogitsLoss (no pos_weight)"
    },
    "train_loss": [],
    "val_metrics": [],
    "test_metrics": None
}

# ============================================
# TRAINING LOOP
# ============================================

for epoch in range(EPOCHS):
    model.train()
    model.zero_grad()
    running_loss = 0

    loop = tqdm(train_loader, desc=f"Epoch {epoch+1}/{EPOCHS}")

    for batch in loop:
        optimizer.zero_grad()

        ids = batch["input_ids"].to(DEVICE)
        mask = batch["attention_mask"].to(DEVICE)
        labs = batch["labels"].to(DEVICE)

        out = model(input_ids=ids, attention_mask=mask)
        loss = criterion(out.logits, labs)

        loss.backward()
        optimizer.step()
        scheduler.step()

        running_loss += loss.item()
        loop.set_postfix(loss=loss.item())

    avg_loss = running_loss / len(train_loader)
    log["train_loss"].append(avg_loss)

    val_metrics = evaluate(model, val_loader)
    log["val_metrics"].append(val_metrics)

    print(f"\n📘 Epoch {epoch+1}")
    print(f"Loss: {avg_loss:.4f}")
    print(f"Val Macro F1: {val_metrics['macro_f1']:.4f}")
    print(f"Val Micro F1: {val_metrics['micro_f1']:.4f}")

# ============================================
# TEST FINALE
# ============================================

test_metrics = evaluate(model, test_loader)
log["test_metrics"] = test_metrics

print("\n🎯 TEST RESULTS")
print(json.dumps(test_metrics, indent=4))

# ============================================
# SALVATAGGIO MODELLO & METRICHE
# ============================================

model.save_pretrained("CodeBERT_multilabel_model")
tokenizer.save_pretrained("CodeBERT_multilabel_model")

with open(OUTPUT_METRICS_FILE, "w") as f:
    json.dump(log, f, indent=4)

print("\n💾 Modello salvato in CodeBERT_multilabel_model")
print(f"💾 Metriche salvate in {OUTPUT_METRICS_FILE}")
