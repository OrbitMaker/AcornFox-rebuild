#!/usr/bin/env python3
"""Merge JUnit test suites without treating duplicate milestone IDs as one test."""

from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path
import xml.etree.ElementTree as ET


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("inputs", nargs="+", type=Path)
    args = parser.parse_args()

    merged = ET.Element("testsuite", {"name": "open-card-mvp-evidence", "tests": "0", "failures": "0"})
    tests = failures = 0
    for path in args.inputs:
        suite = ET.parse(path).getroot()
        if suite.tag != "testsuite":
            raise SystemExit(f"expected testsuite root: {path}")
        tests += int(suite.attrib.get("tests", len(suite.findall("testcase"))))
        failures += int(suite.attrib.get("failures", len(suite.findall(".//failure"))))
        for testcase in suite.findall("testcase"):
            merged.append(deepcopy(testcase))
    merged.set("tests", str(tests))
    merged.set("failures", str(failures))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(merged).write(args.output, encoding="utf-8", xml_declaration=True)
    print(f"tests={tests} failures={failures} output={args.output}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
