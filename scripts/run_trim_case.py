#!/usr/bin/env python3
"""Run the trim report flow end to end and check the used-set it reports.

Usage: run_trim_case.py <bomwerk-binary> <fixture-dir>

The acceptance check: the used-set is correct on a fixture. The unit tests
cover the two halves separately -- test_compile_map for the argv rules and the
path arithmetic, test_trace_read for the parser, test_sbom_read/test_cyclonedx
for the component location surviving a round trip through an SBOM -- and none
of them drives the real binary, so none of them can catch a wiring mistake
between those pieces. This does: real CLI parsing, the real SBOM reader
restoring each component's root from evidence.occurrences, the real trace
reader, the real mapping, the real exit-code contract, once, end to end. Same
role the golden harness plays for `scan` and a private daemon integration harness
plays for the trace reader.

The same composition check runs across both report entry points:
`trim --html` over the checked-in SBOM, and `scan --trace --html` over the
fixture tree. It also checks scan's root-local auto-discovery and its explicit
BOMWERK_TRACE failure posture, because a false zero on either path would be a
more dangerous regression than no report.

Why the trace carries "@FIXTURE_ROOT@" placeholders: a real trace records the
ABSOLUTE paths the build system used, which cannot be committed to a
repository that gets checked out somewhere different every time. This script
substitutes the temp copy's own absolute path using the same local-fixture
approach as other integration tests.

Why the assertions are structured rather than a byte-diff snapshot of stdout:
what this fixture exists to pin is the ANSWER -- which component was used, on
what evidence, and which one got dropped -- not the column widths a summary
line happens to print at. The golden harness byte-diffs because SBOM bytes ARE
the product artifact (hard rule 3); a console summary is not, and pinning its
spacing would turn every cosmetic wording change into a failing test with
nothing to say. The determinism that DOES matter is checked directly below: the
trimmed SBOM is written twice and the two must be byte-identical.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# `  - <purl padded> <verdict padded> <root>[ (qualifier)]`, the shape
# cli/trim_command.cpp's per-component listing prints.
VERDICT_LINE = re.compile(r"^  - (\S+)\s+(used|UNUSED)\s+(\S+)(.*)$")

FIXTURE_ROOT_TOKEN = "@FIXTURE_ROOT@"

# `metadata.timestamp` honors SOURCE_DATE_EPOCH and otherwise reads the wall
# clock at one-second resolution, so two back-to-back runs that straddle a
# second boundary differ in that one field. Pinning it is what makes the
# byte-equality check below test the ORDERING guarantees that can actually
# regress -- component order, the serialNumber derived from the component set
# -- instead of testing whether the two subprocesses happened to land in the
# same second. Same value and same reason as run_golden_case.py's
# GOLDEN_SOURCE_DATE_EPOCH (2025-01-01T00:00:00Z).
TRIM_SOURCE_DATE_EPOCH = "1735689600"


def fail(message):
    print(f"trim case FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def check(condition, message):
    if not condition:
        fail(message)


def run(command, cwd, phase, environment_overrides=None):
    """Run one phase, echoing its output so a CI failure is readable."""
    # The environment is inherited rather than scrubbed (the loader vars a
    # sanitizer build needs must survive); SOURCE_DATE_EPOCH is pinned and
    # BOMWERK_TRACE is cleared so a developer's shell cannot redirect a test.
    run_environment = dict(
        os.environ,
        SOURCE_DATE_EPOCH=TRIM_SOURCE_DATE_EPOCH,
        BOMWERK_TRACE="",
    )
    if environment_overrides:
        run_environment.update(environment_overrides)
    completed = subprocess.run(
        command, cwd=str(cwd), capture_output=True, text=True,
        env=run_environment,
    )
    print(f"=== {phase}: {' '.join(str(part) for part in command)} ===")
    print(f"--- exit {completed.returncode} ---")
    if completed.stdout:
        print(completed.stdout)
    if completed.stderr:
        print(completed.stderr, file=sys.stderr)
    return completed


def check_unused_report(report_path, unused_report, identity_key):
    """Assert the cover, card, and main-row badge name the same components.

    Every fact asserted here comes from the fixture's own `unused_report` block
    in expected.used-set.json, never from this script: a harness that hard-codes
    one fixture's component names cannot run a second fixture.
    `identity_key` picks which purls the report is expected to show - the ones
    in the hand-written sbom.cdx.json (`trim_identities`) or the ones a fresh
    `scan` of the tree derives (`scan_identities`).
    """
    document = report_path.read_text()
    unused_count = unused_report["count"]
    check(
        re.search(
            rf'metric-value">{unused_count}</span><span class="metric-label">unused of \d+ located',
            document,
        ),
        f"{report_path.name} does not show {unused_count} unused component(s) on the cover",
    )
    unused_card_start = document.find("<h2>Unused components</h2>")
    components_card_start = document.find("<h2>Components</h2>", unused_card_start)
    check(unused_card_start >= 0, f"{report_path.name} has no Unused components card")
    check(
        components_card_start > unused_card_start,
        f"{report_path.name} has no component table after the unused card",
    )
    unused_card = document[unused_card_start:components_card_start]
    for unused_identity in unused_report[identity_key]:
        check(
            unused_identity in unused_card,
            f"{report_path.name} does not list {unused_identity} in its unused card",
        )
    for unused_root in unused_report["roots"]:
        check(
            unused_root in unused_card,
            f"{report_path.name} does not show the unused root {unused_root}",
        )
    check(
        ">UNUSED</span>" in document,
        f"{report_path.name} does not badge the unused component in the main table",
    )


def check_trace_discovery(bomwerk_binary, workspace, trace_path, unused_report):
    """Trace discovery: root-local, current-directory, unreadable env."""
    # Discovery order: root-local trace when --trace/BOMWERK_TRACE are
    # absent. The trace itself adds one file under the scanned root, so the
    # report's file-count tile legitimately differs from the explicit run;
    # the unused verdict must still be identical.
    auto_trace = workspace / "tree" / ".bomwerk" / "trace.jsonl"
    auto_trace.parent.mkdir(parents=True, exist_ok=True)
    auto_trace.write_bytes(trace_path.read_bytes())
    auto_scan = run(
        [bomwerk_binary, "scan", "tree", "--html", "scan-report-auto.html",
         "--no-vuln", "-q", "-o", "scan-auto.cdx.json"],
        cwd=workspace, phase="scan auto-detected trace",
    )
    check(auto_scan.returncode == 0, f"auto-detected scan exited {auto_scan.returncode}")
    check_unused_report(workspace / "scan-report-auto.html", unused_report,
                    "scan_identities")

    # The final discovery fallback is the current directory. Move the
    # trace out of the scanned root so this run can only find that path.
    current_directory_trace = workspace / ".bomwerk" / "trace.jsonl"
    current_directory_trace.parent.mkdir(parents=True, exist_ok=True)
    current_directory_trace.write_bytes(auto_trace.read_bytes())
    auto_trace.unlink()
    current_directory_scan = run(
        [bomwerk_binary, "scan", "tree", "--html", "scan-report-cwd.html",
         "--no-vuln", "-q", "-o", "scan-cwd.cdx.json"],
        cwd=workspace, phase="scan current-directory trace",
    )
    check(
        current_directory_scan.returncode == 0,
        f"current-directory trace scan exited {current_directory_scan.returncode}",
    )
    check_unused_report(workspace / "scan-report-cwd.html", unused_report,
                    "scan_identities")

    # A set-but-unreadable environment path wins over defaults, warns, and
    # produces no unused claim. This is degraded (1), never incomplete (2).
    invalid_environment_scan = run(
        [bomwerk_binary, "scan", "tree", "--html", "scan-report-no-trace.html",
         "--no-vuln", "-q", "-o", "scan-no-trace.cdx.json"],
        cwd=workspace, phase="scan with unreadable BOMWERK_TRACE",
        environment_overrides={"BOMWERK_TRACE": "missing-trace.jsonl"},
    )
    check(
        invalid_environment_scan.returncode == 1,
        "an unreadable BOMWERK_TRACE did not produce exit 1",
    )
    no_trace_report = (workspace / "scan-report-no-trace.html").read_text()
    check(
        "unused (no build trace)" in no_trace_report,
        "an unreadable BOMWERK_TRACE produced an unused count instead of unknown",
    )
    check(
        "<h2>Unused components</h2>" not in no_trace_report,
        "an unreadable BOMWERK_TRACE still produced an unused-components card",
    )


def parse_report(stdout):
    """Turn the command's stdout into the facts this test asserts on."""
    # The `not judged:` and `out of tree:` lines print only when their count is
    # non-zero, so "absent" means zero -- defaulted here rather than left unset,
    # or a fixture legitimately expecting 0 would compare against None and fail
    # with a message pointing at the wrong thing.
    report = {"verdicts": {}, "qualifiers": {}, "not_judged": 0, "out_of_tree_sources": 0}
    for line in stdout.splitlines():
        verdict_match = VERDICT_LINE.match(line)
        if verdict_match:
            identity, verdict, _root, qualifier = verdict_match.groups()
            report["verdicts"][identity] = verdict
            if qualifier.strip():
                report["qualifiers"][identity] = qualifier.strip()
            continue

        numbers = re.findall(r"\d+", line)
        if line.startswith("trace:") and len(numbers) >= 2:
            report["compile_invocations"] = int(numbers[0])
            report["in_tree_sources"] = int(numbers[1])
        elif line.startswith("links:") and len(numbers) >= 2:
            report["link_invocations"] = int(numbers[0])
            report["unresolved_library_names"] = int(numbers[1])
        elif line.startswith("used:") and len(numbers) >= 2:
            report["used"] = int(numbers[0])
            report["judged"] = int(numbers[1])
        elif line.startswith("not judged:") and numbers:
            report["not_judged"] = int(numbers[0])
        elif line.startswith("out of tree:") and numbers:
            report["out_of_tree_sources"] = int(numbers[0])
    return report


def main():
    if len(sys.argv) != 3:
        fail(f"usage: {Path(sys.argv[0]).name} <bomwerk> <fixture-dir>")
    bomwerk_binary = Path(sys.argv[1]).resolve()
    fixture_directory = Path(sys.argv[2]).resolve()
    expected = json.loads((fixture_directory / "expected.used-set.json").read_text())

    with tempfile.TemporaryDirectory(prefix="bomwerk_trim_") as temporary_root:
        workspace = Path(temporary_root) / "case"
        shutil.copytree(fixture_directory, workspace)
        # resolve() because macOS puts the system temp dir behind a symlink
        # (/var -> /private/var); baking the unresolved spelling into the trace
        # would make this test assert the symlink handling by accident instead
        # of the mapping it is actually about.
        workspace = workspace.resolve()

        trace_path = workspace / "trace.jsonl"
        trace_path.write_text(
            trace_path.read_text().replace(FIXTURE_ROOT_TOKEN, str(workspace))
        )

        # Paths are RELATIVE and the command runs inside the workspace, so
        # nothing temp-dir-specific can leak into the output being asserted on.
        trim = run(
            [bomwerk_binary, "trim", "sbom.cdx.json", "--trace", "trace.jsonl",
             "--root", "tree", "-o", "trimmed.cdx.json",
             "--html", "trim-report.html"],
            cwd=workspace, phase="trim",
        )
        check(
            trim.returncode == expected["exit_code"],
            f"exit {trim.returncode}, expected {expected['exit_code']} "
            "(0 clean / 1 warnings / 2 incomplete -- hard rule 2)",
        )

        report = parse_report(trim.stdout)
        for key in ("compile_invocations", "in_tree_sources", "out_of_tree_sources",
                    "link_invocations", "unresolved_library_names",
                    "judged", "used", "not_judged"):
            check(
                report.get(key) == expected[key],
                f"{key}: reported {report.get(key)}, expected {expected[key]}",
            )
        check(
            report["verdicts"] == expected["verdicts"],
            f"used-set is wrong.\n  reported: {report['verdicts']}\n"
            f"  expected: {expected['verdicts']}",
        )
        check(
            report["qualifiers"] == expected["qualifiers"],
            "a component was judged used on the WRONG evidence -- a compiled source "
            "and an include path are different claims.\n"
            f"  reported: {report['qualifiers']}\n  expected: {expected['qualifiers']}",
        )

        # The listing and the trimmed document must agree: a component printed
        # "used" that the SBOM then dropped would be worse than either error
        # alone, because each surface would look right on its own.
        trimmed = json.loads((workspace / "trimmed.cdx.json").read_text())
        trimmed_purls = sorted(
            component.get("purl", "") for component in trimmed.get("components", [])
        )
        check(
            trimmed_purls == expected["trimmed_purls"],
            f"trimmed SBOM holds {trimmed_purls}, expected {expected['trimmed_purls']}",
        )
        # The product it describes must survive the trim: a BOM that renamed
        # its own subject would be worse than no trimmed BOM at all.
        check(
            trimmed["metadata"]["component"]["name"] == expected["product_name"],
            "the trimmed SBOM lost the product identity from the SBOM it trimmed",
        )
        unused_report = expected["unused_report"]
        check_unused_report(workspace / "trim-report.html", unused_report, "trim_identities")
        trim_report = (workspace / "trim-report.html").read_text()
        check(
            "files scanned (not recorded)" in trim_report,
            "trim --html presented an invented scan file count",
        )
        check(
            "<code>bomwerk trim</code>" in trim_report,
            "trim --html did not explain why vulnerabilities were not checked",
        )

        # The acceptance path: the same tree is scanned, the existing trace is
        # applied before output, and the fixture's unused components are visible on the
        # HTML cover/card.
        scan = run(
            [bomwerk_binary, "scan", "tree", "--trace", "trace.jsonl",
             "--html", "scan-report.html", "--no-vuln", "-q",
             "-o", "scan.cdx.json"],
            cwd=workspace, phase="scan --trace --html",
        )
        check(scan.returncode == 0, f"scan --trace --html exited {scan.returncode}")
        check_unused_report(workspace / "scan-report.html", unused_report, "scan_identities")
        scanned = json.loads((workspace / "scan.cdx.json").read_text())
        scanned_purls = sorted(
            component.get("purl", "") for component in scanned.get("components", [])
        )
        for unused_identity in unused_report["scan_identities"]:
            check(
                unused_identity in scanned_purls,
                f"scan --trace dropped {unused_identity} from the declared SBOM",
            )

        # Trace DISCOVERY (root-local, current-directory, unreadable env var) is a
        # property of bomwerk, not of a fixture: it is exercised once, by the
        # fixture that opts in, rather than repeated by every trim case.
        if expected["discovery_checks"]:
            check_trace_discovery(bomwerk_binary, workspace, trace_path, unused_report)

        # Hard rule 3: two runs, byte-identical.
        first_bytes = (workspace / "trimmed.cdx.json").read_bytes()
        rerun = run(
            [bomwerk_binary, "trim", "sbom.cdx.json", "--trace", "trace.jsonl",
             "--root", "tree", "-o", "trimmed-again.cdx.json"],
            cwd=workspace, phase="trim again (determinism)",
        )
        check(rerun.returncode == expected["exit_code"], "the second run exited differently")
        check(
            (workspace / "trimmed-again.cdx.json").read_bytes() == first_bytes,
            "two runs of the same trim produced different bytes (hard rule 3)",
        )

        # the logging rule in docs/CONTRIBUTING.md: scan RESULTS are product output on stdout,
        # diagnostics are logs on stderr. A clean run has nothing to say on
        # stderr at all.
        check(
            not rerun.stderr.strip(),
            f"a clean run wrote to stderr: {rerun.stderr!r}",
        )

        # --quiet drops the itemized listing and keeps every summary line, the
        # same contract `scan -q` has.
        quiet = run(
            [bomwerk_binary, "trim", "sbom.cdx.json", "--trace", "trace.jsonl",
             "--root", "tree", "-q"],
            cwd=workspace, phase="trim --quiet",
        )
        check(quiet.returncode == expected["exit_code"], "--quiet changed the exit code")
        quiet_report = parse_report(quiet.stdout)
        check(not quiet_report["verdicts"], "--quiet still printed the per-component listing")
        check(
            quiet_report.get("used") == expected["used"],
            "--quiet dropped the summary lines too; it must only skip the listing",
        )

    print("trim case passed")


if __name__ == "__main__":
    main()
