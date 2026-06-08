from pathlib import Path


def write_markdown_file(file_path, content):
    """
    Write Markdown content into a .md file.
    """

    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        file.write(content)