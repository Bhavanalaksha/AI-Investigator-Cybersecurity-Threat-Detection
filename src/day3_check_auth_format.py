import gzip

AUTH_FILE = "data/raw/auth.txt.gz"

print("=" * 70)
print("AUTH DATA FORMAT CHECK")
print("=" * 70)

with gzip.open(AUTH_FILE, "rt", encoding="utf-8") as file:

    for i, line in enumerate(file):

        print(f"\nLINE {i + 1}:")
        print(line.strip())

        columns = line.strip().split(",")

        print("\nCOLUMNS:")

        for index, value in enumerate(columns):
            print(f"Column {index}: {value}")

        if i == 4:
            break

print("\n" + "=" * 70)
print("FORMAT CHECK COMPLETE")
print("=" * 70)