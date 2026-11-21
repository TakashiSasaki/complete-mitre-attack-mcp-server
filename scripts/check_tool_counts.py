"""Verify every tool count the README advertises matches the code.

The tool count now appears in the tagline, a badge, a section heading and a
per-area table. Any of those can drift from reality. This asserts all of them
against the registered tools, and that the per-area counts sum correctly.
"""

import asyncio
import pathlib
import re
import sys

from mitre_mcp_server.server import mcp

rd = pathlib.Path("README.md").read_text()
tools = asyncio.run(mcp.list_tools())
names = {t.name for t in tools}
n = len(names)
problems = []

# Tool tables: rows like "| `get_technique_by_id` | ... |". Environment-variable
# rows use the same shape but uppercase names, so filter those out.
documented_list = [m for m in re.findall(r"^\| `(\w+)`", rd, re.M) if not m.isupper()]
documented = set(documented_list)
if len(documented_list) != len(documented):
    seen = set()
    dups = sorted({m for m in documented_list if m in seen or seen.add(m)})
    problems.append(f"duplicate tools in README tables: {dups}")
if missing := sorted(names - documented):
    problems.append(f"tools missing from the README tables: {missing}")
if ghost := sorted(documented - names):
    problems.append(f"README documents tools that do not exist: {ghost}")

# Every advertised figure must equal the real count.
advertised = {
    "tagline": r"\*\*(\d+) MCP tools",
    "badge": r"MCP%20tools-(\d+)-",
    "heading": r"^### (\d+) tools across",
    "security_readonly": r"All (\d+) tools are queries over",
    "available_tools_intro": r"^(\d+) tools covering the major ATT&CK entities",
}
for label, pattern in advertised.items():
    found = re.search(pattern, rd, re.M)
    if not found:
        problems.append(f"could not find the tool count in the {label}")
    elif int(found.group(1)) != n:
        problems.append(f"{label} advertises {found.group(1)} tools, code has {n}")

# The per-area table in the overview must sum to the real count and match
# the number of tool rows in each corresponding "### <Area>" section.
area_rows = re.findall(r"^\| \[([^\]]+)\]\(#[^)]+\) \| +(\d+) \|", rd, re.M)
if not area_rows:
    problems.append("could not find the per-area tool table")
else:
    total = sum(int(c) for _, c in area_rows)
    if total != n:
        problems.append(
            f"per-area table sums to {total} across {len(area_rows)} areas, code has {n}"
        )
    sections = re.split(r"^### ", rd, flags=re.M)
    section_map = {}
    for sec in sections[1:]:
        title, _, body = sec.partition("\n")
        sec_tools = [m for m in re.findall(r"^\| `(\w+)`", body, re.M) if not m.isupper()]
        section_map[title.strip()] = len(sec_tools)
    for area_name, expected_str in area_rows:
        actual = section_map.get(area_name)
        if actual is None:
            problems.append(f"missing '### {area_name}' section in README")
        elif actual != int(expected_str):
            problems.append(
                f"area '{area_name}' advertises {expected_str} tools, section table has {actual}"
            )

if problems:
    for p in problems:
        print(f"::error::{p}")
    sys.exit(1)

print(f"{n} tools; README tagline, badge, heading and per-area table all agree.")
