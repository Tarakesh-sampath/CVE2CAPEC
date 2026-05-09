import os
from typing import Set

# ---------------- CONFIG ---------------- #

INCLUDE_DIRS: Set[str] = {
    "docs",
}

INCLUDE_EXTS: Set[str] = {
    ".py",
}

INCLUDE_FILES: Set[str] = {
    "README.md",
}

EXCLUDE_EXTS: Set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".pyc",
    ".so",
    ".exe",
}

# ---------------- HELPERS ---------------- #

def is_allowed_file(filename: str) -> bool:
    if filename.startswith("."):
        return False

    ext = os.path.splitext(filename)[1].lower()

    if filename in INCLUDE_FILES:
        return True

    if ext in EXCLUDE_EXTS:
        return False

    return ext in INCLUDE_EXTS


# ---------------- DIRECTORY STRUCTURE ---------------- #

def get_directory_structure(root_dir: str) -> str:
    lines = []

    for root, dirs, files in os.walk(root_dir):
        rel_root = os.path.relpath(root, root_dir)

        if root != root_dir:
            path_parts = rel_root.split(os.sep)
            if path_parts[0] not in INCLUDE_DIRS:
                dirs[:] = []
                continue

        if root == root_dir:
            dirs[:] = [d for d in dirs if d in INCLUDE_DIRS]

        level = root.replace(root_dir, "").count(os.sep)
        indent = " " * 4 * level
        lines.append(f"{os.path.basename(root) if root == root_dir else indent + os.path.basename(root)}/")

        sub_indent = " " * 4 * (level + 1)

        for f in files:
            if is_allowed_file(f):
                lines.append(f"{sub_indent}{f}")

    return "\n".join(lines)


# ---------------- FILE CONTENTS ---------------- #

def get_file_contents(root_dir: str) -> str:
    content_blocks = []

    for root, dirs, files in os.walk(root_dir):
        rel_root = os.path.relpath(root, root_dir)

        if root != root_dir:
            path_parts = rel_root.split(os.sep)
            if path_parts[0] not in INCLUDE_DIRS:
                dirs[:] = []
                continue

        if root == root_dir:
            dirs[:] = [d for d in dirs if d in INCLUDE_DIRS]

        for f in files:
            if not is_allowed_file(f):
                continue

            file_path = os.path.join(root, f)
            rel_path = os.path.relpath(file_path, root_dir)

            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    content = file.read()

                ext = os.path.splitext(f)[1].lstrip(".") or "text"

                content_blocks.append(
                    f"## File: {rel_path}\n\n```{ext}\n{content}\n```\n"
                )

            except (UnicodeDecodeError, PermissionError):
                continue

    return "\n".join(content_blocks)


# ---------------- MAIN ---------------- #

if __name__ == "__main__":
    root = "./"
    output_file = "./project_summary.md"

    structure = get_directory_structure(root)
    contents = get_file_contents(root)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# Project Summary\n\n")
        f.write("## Directory Structure\n\n```\n")
        f.write(structure)
        f.write("\n```\n\n")
        f.write(contents)

    print(f"Generated {output_file}")