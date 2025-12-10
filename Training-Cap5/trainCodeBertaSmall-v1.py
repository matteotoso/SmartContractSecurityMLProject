import json
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification, get_linear_schedule_with_warmup
from torch.optim import AdamW
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
import numpy as np
from tqdm import tqdm

# === CONFIG ===
TRAIN_FILE = "trainDataset.jsonl"
VAL_FILE   = "valDataset.jsonl"
TEST_FILE  = "testDataset.jsonl"
MODEL_NAME = "huggingface/CodeBERTa-small-v1"
BATCH_SIZE = 32
EPOCHS     = 15
LR         = 2e-5
MAX_LENGTH = 512
DEVICE     = "cuda" if torch.cuda.is_available() else "cpu"
NUM_LABELS = 16

# === Dataset class ===
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
        encoding = self.tokenizer(
            item["code"],
            padding="max_length",
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt"
        )
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": item["labels"]
        }

# === Tokenizer e DataLoader ===
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
train_dataset = CodeDataset(TRAIN_FILE, tokenizer, MAX_LENGTH)
val_dataset   = CodeDataset(VAL_FILE, tokenizer, MAX_LENGTH)
test_dataset  = CodeDataset(TEST_FILE, tokenizer, MAX_LENGTH)

train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
val_loader   = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)
test_loader  = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

# === Modello ===
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=NUM_LABELS,
    problem_type="multi_label_classification"
).to(DEVICE)

# === Calcolo pesi classi rare ===
label_counts = np.zeros(NUM_LABELS)
for s in train_dataset.samples:
    label_counts += s["labels"].numpy()
num_samples = len(train_dataset)
pos_weight = torch.tensor((num_samples - label_counts) / (label_counts + 1e-6), dtype=torch.float).to(DEVICE)
criterion = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight)

# === Ottimizzatore e scheduler ===
optimizer = AdamW(model.parameters(), lr=LR)
total_steps = len(train_loader) * EPOCHS
scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=0, num_training_steps=total_steps)

# === Metriche da salvare ===
all_train_loss = []
all_macro_f1 = []
all_micro_f1 = []
all_metrics_per_class = []  # precision/recall/f1/accuracy per epoca

# === Funzione di valutazione multilabel ===
def evaluate_metrics(model, dataloader):
    model.eval()
    preds, labels_all = [], []

    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(DEVICE)
            attention_mask = batch["attention_mask"].to(DEVICE)
            labels_batch = batch["labels"].cpu().numpy()

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits.sigmoid().cpu().numpy()

            preds.append(logits)
            labels_all.append(labels_batch)

    preds = np.vstack(preds)
    labels_all = np.vstack(labels_all)
    preds_bin = (preds >= 0.5).astype(int)

    metrics_per_class = {}
    for i in range(NUM_LABELS):
        metrics_per_class[i] = {
            "precision": precision_score(labels_all[:, i], preds_bin[:, i], zero_division=0),
            "recall": recall_score(labels_all[:, i], preds_bin[:, i], zero_division=0),
            "f1": f1_score(labels_all[:, i], preds_bin[:, i], zero_division=0),
            "accuracy": accuracy_score(labels_all[:, i], preds_bin[:, i])
        }

    macro_f1 = f1_score(labels_all, preds_bin, average="macro")
    micro_f1 = f1_score(labels_all, preds_bin, average="micro")

    return metrics_per_class, macro_f1, micro_f1


# === Training loop ===
for epoch in range(EPOCHS):
    model.train()
    running_loss = 0
    loop = tqdm(train_loader, desc=f"Epoch {epoch+1}/{EPOCHS}")

    for batch in loop:
        optimizer.zero_grad()
        input_ids = batch["input_ids"].to(DEVICE)
        attention_mask = batch["attention_mask"].to(DEVICE)
        labels_batch = batch["labels"].to(DEVICE)

        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
        loss = criterion(outputs.logits, labels_batch)

        loss.backward()
        optimizer.step()
        scheduler.step()

        running_loss += loss.item()
        loop.set_postfix(loss=loss.item())

    epoch_loss = running_loss / len(train_loader)
    all_train_loss.append(epoch_loss)

    # Valutazione
    metrics_per_class, macro_f1, micro_f1 = evaluate_metrics(model, val_loader)
    all_macro_f1.append(macro_f1)
    all_micro_f1.append(micro_f1)
    all_metrics_per_class.append(metrics_per_class)

    print(f"\n📊 Epoch {epoch+1} Metrics")
    print(f"Macro F1: {macro_f1:.4f}, Micro F1: {micro_f1:.4f}")
    for lbl, m in metrics_per_class.items():
        print(f"Label {lbl}: P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} Acc={m['accuracy']:.3f}")

# === Salvataggio modello ===
model.save_pretrained("codeberta_multilabel_model")
tokenizer.save_pretrained("codeberta_multilabel_model")
print("✅ Modello salvato")

# === Test finale ===
metrics_test, macro_f1_test, micro_f1_test = evaluate_metrics(model, test_loader)

# === Salva metriche ===
results = {
    "train_loss": all_train_loss,
    "macro_f1": all_macro_f1,
    "micro_f1": all_micro_f1,
    "metrics_per_class": all_metrics_per_class,
    "test": {
        "macro_f1": macro_f1_test,
        "micro_f1": micro_f1_test,
        "metrics_per_class": metrics_test
    }
}

with open("metrics_training_full.json", "w") as f:
    json.dump(results, f, indent=4)

print("📁 Metriche salvate in metrics_training_full.json")
