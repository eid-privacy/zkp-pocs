import json
import sys
import tomllib

def convert(toml_path, json_path):
    with open(toml_path, "rb") as f:
        data = tomllib.load(f)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <input.toml> <output.json>")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
