import json
from pathlib import Path


def load_json_file(file_path):
    """
    Load a JSON file and return its content as a Python dictionary.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"JSON file not found: {file_path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_json_file(file_path, data):
    """
    Save a Python dictionary as a formatted JSON file.
    """

    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)