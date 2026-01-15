# Initialize FILE_NAME_LIST in FileLine.java

import argparse
import subprocess
from pathlib import Path
from typing import List


root: Path = None


def go_checkout(version_tag: str, repo_dir: Path) -> None:
    global root

    if not (repo_dir / ".git").exists():
        raise Exception(f"Not a git repo: {repo_dir}")

    subprocess.run(["git", "-C", str(repo_dir), "checkout", "--quiet", version_tag], check=True)

    candidate = (repo_dir / "src").resolve()
    if not candidate.is_dir():
        raise Exception(f"src directory not found after checkout: {candidate}")

    root = candidate


def files_list() -> List[str]:
    files_new = [
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p.suffix in (".go", ".s", ".S")
    ]
    files_new.sort()
    return files_new


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo_dir")
    args = parser.parse_args()

    repo_dir = Path(args.repo_dir).expanduser().resolve()

    versions = [
        "go1.25.0",
        "go1.24.0",
        "go1.23.0",
        "go1.22.0",
        "go1.21.0",
        "go1.20",
        "go1.19",
        "go1.18",
        "go1.17",
        "go1.16",
        "go1.15",
    ]

    lists: List[List[str]] = []
    for v in versions:
        go_checkout(v, repo_dir)
        lists.append(files_list())

    common = list(set(lists[0]).intersection(*map(set, lists[1:])))
    common.sort()

    data = ""
    for i in common:
        data += "\"%s\", " % i

    print(data)


if __name__ == "__main__":
    main()
