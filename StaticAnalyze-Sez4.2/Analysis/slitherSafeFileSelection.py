import os
import json

reports_dir = "slither_reports"
output_file = "safe_reports.txt"

def is_safe(file_path: str) -> bool:
    """
    Ritorna True se il report NON contiene vulnerabilità (High/Medium/Low).
    """
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        for issue in data.get("results", {}).get("detectors", []):
            impact = issue.get("impact", "N/A")
            if impact in ["High", "Medium", "Low"]:
                return False  # trovato un problema
        return True  # nessun problema rilevato

    except Exception:
        return False


def main():
    safe_files = []

    for root, _, files in os.walk(reports_dir):
        for file_name in files:
            if not file_name.endswith(".json"):
                continue

            file_path = os.path.join(root, file_name)
            if is_safe(file_path):
                # rimuovi prefisso "slither_" se esiste
                clean_name = file_name.replace("slither_", "", 1)
                safe_files.append(clean_name)

    # stampa solo il numero
    print(len(safe_files))

    # salva i nomi "puliti" in un file
    with open(output_file, "w", encoding="utf-8") as out:
        for name in safe_files:
            out.write(name + "\n")


if __name__ == "__main__":
    main()
