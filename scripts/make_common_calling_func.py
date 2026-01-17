import os
from collections import defaultdict
from typing import Dict, Iterable, List


DATA_DIR = "dump/calling_func_name"
OUTPUT_FILENAME = "common_calling_func.txt"
AMD64_MARKER = "windows_amd64_"


def parse_calling_func_name_file(path: str) -> List[Dict[str, object]]:
    """Parse a calling_func_name file into structured records."""
    parsed: List[Dict[str, object]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f.read().splitlines():
            parts = line.split("|")
            if len(parts) < 3:
                continue
            parsed.append(
                {
                    "base": os.path.basename(path),
                    "version": os.path.basename(path).split("_")[2][:-4],
                    "address": parts[0],
                    "name": parts[1],
                    "file": parts[2],
                    "calling": parts[3:] if len(parts) > 3 and parts[3] != "" else [],
                }
            )
    return parsed


def iter_go_files(directory: str) -> Iterable[str]:
    """Yield absolute paths of files containing '_go'."""
    for filename in os.listdir(directory):
        if "_go" not in filename:
            continue
        yield os.path.join(directory, filename)


def longest_common_prefix(a: List[str], b: List[str]) -> List[str]:
    common: List[str] = []
    for left, right in zip(a, b):
        if left != right:
            break
        common.append(left)
    return common


def longest_common_suffix(a: List[str], b: List[str]) -> List[str]:
    reversed_suffix = []
    for left, right in zip(reversed(a), reversed(b)):
        if left != right:
            break
        reversed_suffix.append(left)
    return list(reversed(reversed_suffix))


def collect_all_data(directory: str) -> Dict[str, List[Dict[str, object]]]:
    """Group parsed records by function name."""
    grouped: Dict[str, List[Dict[str, object]]] = {}
    for path in iter_go_files(directory):
        print(os.path.basename(path))
        for record in parse_calling_func_name_file(path):
            grouped.setdefault(record["name"], []).append(record)
    return grouped


def build_common_calling_map(all_data: Dict[str, List[Dict[str, object]]]) -> Dict[str, Dict[str, Dict[str, object]]]:
    """Build common prefix/suffix calling info per function name per version."""
    result: Dict[str, Dict[str, Dict[str, object]]] = {}

    for func_name, entries in all_data.items():
        version_map: Dict[str, Dict[str, object]] = {}

        for entry in entries:
            version = entry["version"]
            calling = entry["calling"]
            base = entry["base"]

            if version not in version_map:
                version_map[version] = {
                    "pre_calling": calling,
                    "post_calling": calling,
                    "base_list": [base],
                }
                continue

            version_entry = version_map[version]
            version_entry["pre_calling"] = longest_common_prefix(
                version_entry["pre_calling"], calling
            )
            version_entry["post_calling"] = longest_common_suffix(
                version_entry["post_calling"], calling
            )
            version_entry["base_list"].append(base)

        result[func_name] = version_map

    return result


def write_common_calling_file(common_data: Dict[str, Dict[str, Dict[str, object]]], output_path: str) -> None:
    """Persist common calling info for amd64 binaries."""
    with open(output_path, "w", encoding="utf-8") as f:
        for func_name, versions in common_data.items():
            for version, meta in versions.items():
                base_list = meta["base_list"]
                if not any(AMD64_MARKER in base for base in base_list):
                    continue

                pre_calling = meta["pre_calling"]
                post_calling = meta["post_calling"]
                line_parts = [version, func_name, "pre", *pre_calling, "post", *post_calling]
                f.write("|".join(line_parts) + "\n")


def consolidate_versions(output_path: str) -> None:
    """Combine lines with identical calling chains by aggregating versions."""
    with open(output_path, "r", encoding="utf-8") as f:
        data = f.read()

    groups: Dict[str, List[str]] = defaultdict(list)
    for line in data.splitlines():
        parts = line.split("|")
        if not parts:
            continue
        key = "|".join(parts[1:])
        groups[key].append(parts[0])

    with open(output_path, "w", encoding="utf-8") as f:
        for key, versions in groups.items():
            combined_line = ",".join(versions) + "|" + key
            f.write(combined_line + "\n")


def main() -> None:
    all_data = collect_all_data(DATA_DIR)
    common_data = build_common_calling_map(all_data)
    output_path = os.path.join(DATA_DIR, OUTPUT_FILENAME)
    write_common_calling_file(common_data, output_path)
    consolidate_versions(output_path)


if __name__ == "__main__":
    main()
