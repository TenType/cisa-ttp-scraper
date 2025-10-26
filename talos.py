from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator, Tuple

# Base URL for raw files in the Cisco Talos IOCs repository
BASE_URL = "https://raw.githubusercontent.com/Cisco-Talos/IOCs/refs/heads/main"


def iter_talos_ioc_jsons(talos_root: Path) -> Iterator[Tuple[str, Any]]:
    """Yield (raw_github_url, json_text) for each JSON file under talos-iocs.

    - Traverses the provided talos_root directory recursively
    - Only processes files with a .json extension
    - Constructs the raw GitHub URL using the path relative to talos_root

    Args:
        talos_root: Path to the local 'talos-iocs' directory. Defaults to a
            sibling folder next to this script named 'talos-iocs'.

    Yields:
        Tuples of (url: str, json_obj: Any)
    """
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


def main():
    """Tiny CLI to validate generator behavior locally.

    Prints the first few URLs discovered and a total JSON file count.
    """
    root = Path(__file__).parent / "talos-iocs"
    count = 0
    for url, contents in iter_talos_ioc_jsons(root):
        count += 1

    print(f"Total JSON files discovered: {count}")


if __name__ == "__main__":
    main()

