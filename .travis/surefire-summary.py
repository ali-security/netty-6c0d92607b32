"""Print per-test skip reasons and the overall totals from target/surefire-reports.

Skips without a message (bare @Ignore, JUnit 4 assumptions) get the matching
@Ignore/Assume line from the test source. Surefire 2.10 reports a class-level
@Ignore as one testcase whose name equals the class name; for those the class
declaration's @Ignore is located and reported with file:line.
"""
import glob
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET


def read_source(classname):
    path = os.path.join("src/test/java", classname.split("$")[0].replace(".", "/") + ".java")
    try:
        with open(path, encoding="utf-8") as f:
            return path, f.readlines()
    except OSError:
        return path, None


def class_reason(classname):
    path, lines = read_source(classname)
    if lines is None:
        return None
    simple = classname.split(".")[-1].split("$")[-1]
    for i, line in enumerate(lines):
        if re.search(r"\bclass\s+%s\b" % re.escape(simple), line):
            for j in range(max(0, i - 6), i):
                if "@Ignore" in lines[j]:
                    return "whole class disabled upstream by %s at %s:%d" % (lines[j].strip(), path, j + 1)
    return None


def method_reason(classname, method):
    path, lines = read_source(classname)
    if lines is None:
        return None
    name = re.sub(r"\[.*$", "", method)
    for i, line in enumerate(lines):
        if re.search(r"\bvoid\s+%s\s*\(" % re.escape(name), line):
            for j in range(max(0, i - 4), i):
                if "@Ignore" in lines[j]:
                    return "disabled upstream by %s at %s:%d" % (lines[j].strip(), path, j + 1)
            for j in range(i + 1, min(len(lines), i + 40)):
                if re.search(r"assume", lines[j], re.IGNORECASE):
                    return "assumption not met: %s at %s:%d" % (lines[j].strip(), path, j + 1)
    return None


tests = failures = errors = skipped = 0
skips = []
for path in sorted(glob.glob("target/surefire-reports/TEST-*.xml")):
    root = ET.parse(path).getroot()
    tests += int(root.get("tests", 0))
    failures += int(root.get("failures", 0))
    errors += int(root.get("errors", 0))
    skipped += int(root.get("skipped", 0))
    for case in root.iter("testcase"):
        sk = case.find("skipped")
        if sk is None:
            continue
        classname = case.get("classname", "") or ""
        name = case.get("name", "") or ""
        message = (sk.get("message") or "").strip()
        if not message:
            src = None
            if name == classname or name == classname.split(".")[-1]:
                src = class_reason(classname)
            if src is None:
                src = method_reason(classname, name)
            if src is None:
                src = class_reason(classname)
            message = src if src else "(no message)"
        skips.append("%s.%s: %s" % (classname, name, message))

print("Skipped tests (%d):" % len(skips))
for line in skips:
    print("  SKIPPED " + line)
# A per-run nonce lets .travis/wait-for-log.sh tell this run's archived summary
# apart from an earlier run of the same (restarted) Travis job.
nonce = uuid.uuid4().hex[:12]
with open("/tmp/seal-log-nonce", "w") as f:
    f.write(nonce)
print("Surefire totals: tests=%d passed=%d failures=%d errors=%d skipped=%d (run %s)"
      % (tests, tests - failures - errors - skipped, failures, errors, skipped, nonce))
sys.exit(0 if tests > 0 and failures == 0 and errors == 0 else 1)
