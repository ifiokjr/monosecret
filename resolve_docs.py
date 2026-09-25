#!/usr/bin/env python3
"""Docs conflict resolver for the monosecret sync.

Rules:
  - Fork docs use :::note[Version compatibility] (no @cachix/site-kit).
  - Upstream hunks that are only imports/components/anchors -> keep fork side.
  - Everything else -> leave markers for manual pass.
"""
import os
import re

COMPONENT_RE = re.compile(r"<VersionCompatibility[^>]*/>")


def strip_noise(text: str) -> str:
    out = []

    for line in text.splitlines():
        s = line.strip()

        if not s:
            continue

        if s.startswith("import VersionCompatibility"):
            continue

        if s.startswith("<VersionCompatibility"):
            continue
        out.append(s)

    return "\n".join(out)


def is_version_note(text: str) -> bool:
    t = text.strip()

    return t.startswith(":::note") or t.startswith(":::caution")


def main():
    resolved = manual = 0

    for root, dirs, files in os.walk("docs"):
        if "node_modules" in root:
            continue

        for name in files:
            path = os.path.join(root, name)

            if name.endswith((".lock", )):
                continue
            try:
                text = open(path, encoding="utf-8", errors="surrogateescape").read()

            except Exception:
                continue

            if "<<<<<<<" not in text:
                continue
            parts = re.split(r"(<<<<<<< fork\n.*?>>>>>>> upstream\n)", text, flags=re.S)
            changed = False

            for i, part in enumerate(parts):
                m = re.fullmatch(r"<<<<<<< fork\n(.*?)=======\n(.*?)>>>>>>> upstream\n", part, flags=re.S)

                if not m:
                    continue
                fork, up = m.group(1), m.group(2)
                up_reduced = strip_noise(up)
                fork_reduced = strip_noise(fork)
                decision = None

                if not up_reduced.strip():
                    # upstream adds nothing beyond version machinery
                    decision = fork
                elif is_version_note(fork_reduced) and not up_reduced.strip():
                    decision = fork
                elif (
                    fork_reduced.strip()
                    and up_reduced.strip()
                    and re.sub(r"\(0\.2\+\)|\(0\.2\)", "", fork_reduced).strip()
                    == re.sub(r"\{/\* #[^*]*\*/\}", "", up_reduced).strip()
                ):
                    # same heading/prose modulo fork version label vs upstream anchor
                    decision = fork

                if decision is not None:
                    parts[i] = decision
                    changed = True
                    resolved += 1
                else:
                    manual += 1

            if changed:
                open(path, "w", encoding="utf-8", errors="surrogateescape").write("".join(parts))
    print(f"auto-resolved hunks: {resolved}, left for manual: {manual}")


if __name__ == "__main__":
    main()