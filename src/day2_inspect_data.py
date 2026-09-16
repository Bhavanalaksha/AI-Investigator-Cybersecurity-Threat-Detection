import gzip
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"

files = [
    "dns.txt.gz",
    "proc.txt.gz",
    "flows.txt.gz"
]

for filename in files:
    filepath = RAW_DIR / filename

    print("\n" + "=" * 60)
    print(f"FILE: {filename}")
    print("=" * 60)

    try:
        with gzip.open(filepath, "rt", encoding="utf-8", errors="ignore") as f:
            print("\nFirst 5 lines:\n")

            for i in range(5):
                line = f.readline().strip()
                print(line)

    except FileNotFoundError:
        print(f"ERROR: Could not find {filepath}")