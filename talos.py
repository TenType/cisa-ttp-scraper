from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator
from rich.console import Console

BASE_URL = "https://raw.githubusercontent.com/Cisco-Talos/IOCs/refs/heads/main"

console = Console()
print = console.print

def yield_talos_ioc_jsons(talos_root: Path) -> Iterator[tuple[str, Any]]:
    root = Path(talos_root).resolve()
    if not root.exists() or not root.is_dir():
        return

    # Deterministic ordering makes results predictable in tests and CLIs
    for path in sorted(root.rglob("*.json")):
        if not path.is_file():  # defensive, though rglob("*.json") should already be files
            continue

        rel = path.relative_to(root).as_posix()
        url = f"{BASE_URL}/{rel}"
        text = path.read_text(encoding="utf-8")
        obj = json.loads(text)

        yield url, obj

def get_nested(dictn, keys: list[str], default=None):
    d = dictn
    for key in keys:
        if key == "[0]" and len(d) > 0:
            d = d[0]
        elif isinstance(d, dict) and key in d:
            d = d[key]
        else:
            return default
    return d

def find_title(contents: Any) -> str:
    objects = contents.get("objects")
    if objects is not None:
        for obj in objects:
            if obj.get("type") == "report":
                return obj.get("name")

    title = get_nested(contents, [
        "related_packages",
        "related_packages",
        "[0]",
        "package",
        "incidents",
        "[0]",
        "title",
    ])

    if title is not None:
        return title
    
    title = get_nested(contents, [
        "response",
        "[0]",
        "Event",
        "info",
    ])

    if title is not None:
        return title
    
    return ""


def main():
    root = Path(__file__).parent / "talos-iocs"
    count = 0
    # reports: list[dict] = []

    for url, contents in yield_talos_ioc_jsons(root):
        title = find_title(contents)
        if title == "":
            print(f"{url}", style="red")
        else:
            print(title)
        count += 1


    # for url, contents in yield_talos_ioc_jsons(root):
    #     count += 1

    # output_file = "out.json"
    # with open(output_file, "w", encoding="utf-8") as f:
    #     json.dump(reports, f, indent=2)

    print(f"Total JSON files discovered: {count}")


if __name__ == "__main__":
    main()

