"""Regression guard: pytest JUnit evidence must be independently verifiable.

``unittest.TestCase.subTest`` executions are counted in the JUnit ``tests=``
attribute by pytest-subtests but are not emitted as ``<testcase>`` elements, so
declared > observed.  These tests (1) statically forbid ``subTest`` in the suite
and (2) prove with a real, isolated pytest run that parametrized cases produce
one ``<testcase>`` each and that counters agree with the elements.
"""

import ast
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent


def test_no_subtest_usage_in_test_suite() -> None:
    offenders = []
    for path in sorted(TESTS_DIR.glob("*.py")):
        if path.name == Path(__file__).name:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr == "subTest":
                offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, f"subTest hides cases from JUnit <testcase> output; use pytest.mark.parametrize: {offenders}"


def test_junit_counters_match_testcase_elements(tmp_path: Path) -> None:
    sample = tmp_path / "test_sample_param.py"
    sample.write_text(
        "import pytest\n\n"
        "@pytest.mark.parametrize('n', [1, 2, 3], ids=['a', 'b', 'c'])\n"
        "def test_param(n):\n"
        "    assert n > 0\n",
        encoding="utf-8",
    )
    xml_path = tmp_path / "out.xml"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(sample),
         f"--junitxml={xml_path}", "--rootdir", str(tmp_path), "-c", "/dev/null"],
        capture_output=True, text=True, cwd=tmp_path,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    suite = ET.parse(xml_path).getroot().find("testsuite")
    cases = suite.findall("testcase")
    ids = [f"{c.get('classname')}::{c.get('name')}" for c in cases]
    assert len(cases) == 3 == int(suite.get("tests"))
    assert len(set(ids)) == len(ids)
    failing = sum(len(c.findall("failure")) + len(c.findall("error")) for c in cases)
    assert failing == int(suite.get("failures")) + int(suite.get("errors")) == 0
