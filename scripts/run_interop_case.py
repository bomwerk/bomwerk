#!/usr/bin/env python3
"""Scan fixtures/interop/crane-pipeline/tree/, then validate the
resulting CycloneDX SBOM against the real upstream `sbom-tools` validator
(sbom-tool/sbom-tools) that CRANE itself shells out to for `--standard
ntia`/`cra` scoring -- the concrete end-to-end proof behind bomwerk's
"accurate front-end to any CRA platform" pipeline: `bomwerk scan` output
should pass NTIA/CRA validation with no manual fixup.

Usage: run_interop_case.py <bomwerk-binary> <case-dir> [sbom-tools-binary]

sbom-tools-binary defaults to <repo-root>/.cache/sbom-tools/sbom-tools, where
scripts/fetch-sbom-tools.sh installs it. Absent (a bare dev machine that
never ran that script), this exits 77 -- SKIP, not fail -- the same
convention scripts/validate_purls.py uses for a missing packageurl-python;
CI always runs fetch-sbom-tools.sh first, so it can never skip there.

The exact claim this asserts, verified by hand against the real sbom-tools
0.2.0 binary before this fixture existed (the pull request that added it records the
full before/after transcript):

  BEFORE this change, an unmodified `bomwerk scan --product <x>
  --product-version <y>` fails both standards on the SAME real binary:
    ntia: SBOM-NTIA-IDENTIFIER, SBOM-NTIA-SUPPLIER (x2), SBOM-NTIA-DEPENDENCY
    cra:  SBOM-CRA-ANNEX-I-IDENTIFIER, SBOM-CRA-ANNEX-I-DEPENDENCY

  AFTER: `--standard ntia` exits 0 (COMPLIANT, zero violations of any
  severity) -- the concrete bar this test gates on. `--standard cra` still
  exits 1: attributing a real supplier to more components (this PR's own
  fix) makes ONE new CRA Phase 2 rule visible, SBOM-CRA-PRE-7-RQ-07-RE
  (vendor-supplied components must carry a cryptographic hash) -- a
  component with a supplier from a git remote owner has no cryptographic
  hash of its content (a commit id is not that hash), and bomwerk's one
  producer that DOES carry a hash (cmake_deps' URL_HASH archives)
  deliberately attributes no supplier (see cmake_deps.cpp: parsing an
  arbitrary download URL's path as host/owner/repo is unreliable). Closing
  that gap is a real, separate vendor-hash-provenance project, out of this test's
  scope. This test asserts it is the ONLY remaining error rather than that it
  is gone, so a genuine regression on anything else is still caught.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Same value and same reason as run_golden_case.py's GOLDEN_SOURCE_DATE_EPOCH
# and run_trim_case.py's TRIM_SOURCE_DATE_EPOCH: metadata.timestamp honors
# SOURCE_DATE_EPOCH, so pinning it keeps a scan's bytes reproducible.
CASE_SOURCE_DATE_EPOCH = "1735689600"

# Checked-in name for this fixture's git plumbing, renamed to ".git" in the
# copy -- see run_golden_case.py's module docstring for why (git refuses to
# track a path containing a ".git" component).
GIT_DIR_STAND_IN = "_git"

# Return code that tells ctest's SKIP_RETURN_CODE property this is a skip,
# not a failure -- same convention scripts/validate_purls.py uses.
SKIP_RETURN_CODE = 77

# The one CRA Phase 2 error this fixture is expected to still report -- see
# the module docstring. Any OTHER error is a genuine regression.
KNOWN_RESIDUAL_CRA_ERROR_RULE_IDS = frozenset({"SBOM-CRA-PRE-7-RQ-07-RE"})


def fail(message):
    print(f"interop case FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def check(condition, message):
    if not condition:
        fail(message)


def run(command, cwd, phase):
    completed = subprocess.run(
        command, cwd=str(cwd), capture_output=True, text=True,
        env=dict(os.environ, SOURCE_DATE_EPOCH=CASE_SOURCE_DATE_EPOCH),
    )
    print(f"=== {phase}: {' '.join(str(part) for part in command)} ===")
    print(f"--- exit {completed.returncode} ---")
    if completed.stdout:
        print(completed.stdout)
    if completed.stderr:
        print(completed.stderr, file=sys.stderr)
    return completed


def materialize_tree(case_tree, destination):
    """Copy `case_tree` to `destination`, renaming every `_git` to `.git`
    (deepest first, so renaming a parent never invalidates a path still
    queued for a nested submodule's plumbing) -- same logic as
    run_golden_case.py's materialize_tree.
    """
    shutil.copytree(case_tree, destination)
    stand_ins = sorted(
        destination.rglob(GIT_DIR_STAND_IN), key=lambda path: len(path.parts), reverse=True
    )
    for stand_in in stand_ins:
        stand_in.rename(stand_in.with_name(".git"))


def default_sbom_tools_binary():
    repo_root = Path(__file__).resolve().parent.parent
    return repo_root / ".cache" / "sbom-tools" / "sbom-tools"


def main():
    if len(sys.argv) not in (3, 4):
        print(f"usage: {sys.argv[0]} <bomwerk-binary> <case-dir> [sbom-tools-binary]",
              file=sys.stderr)
        return 2
    bomwerk_binary = Path(sys.argv[1]).resolve()
    case_dir = Path(sys.argv[2]).resolve()
    sbom_tools_binary = (
        Path(sys.argv[3]).resolve() if len(sys.argv) == 4 else default_sbom_tools_binary()
    )

    if not sbom_tools_binary.is_file():
        print(
            f"interop case SKIPPED: sbom-tools not found at {sbom_tools_binary} -- run "
            f"scripts/fetch-sbom-tools.sh first",
            file=sys.stderr,
        )
        return SKIP_RETURN_CODE

    with tempfile.TemporaryDirectory(prefix="bomwerk-interop-") as workspace_name:
        workspace = Path(workspace_name)
        materialize_tree(case_dir / "tree", workspace / "tree")

        scan = run(
            [str(bomwerk_binary), "scan", "tree", "--product", "gateway-fw",
             "--product-version", "2.3.0", "--no-vuln", "-o", "sbom.cdx.json"],
            cwd=workspace, phase="bomwerk scan",
        )
        check(scan.returncode <= 1, f"scan exited {scan.returncode} (expected 0 or 1)")
        check((workspace / "sbom.cdx.json").is_file(), "scan produced no sbom.cdx.json")
        check(
            (workspace / "sbom.cra.json").is_file(),
            "scan produced no sbom.cra.json -- bomwerk.toml's [cra] table did not take effect",
        )

        ntia = run(
            [str(sbom_tools_binary), "validate", "sbom.cdx.json", "--standard", "ntia",
             "--offline"],
            cwd=workspace, phase="sbom-tools validate --standard ntia",
        )
        check(
            ntia.returncode == 0,
            "sbom-tools --standard ntia did not exit 0 (COMPLIANT) -- this is the concrete "
            "bar: 'bomwerk scan' output must pass NTIA validation with no manual fixup",
        )

        cra = run(
            [str(sbom_tools_binary), "validate", "sbom.cdx.json", "--standard", "cra",
             "--offline", "-o", "json"],
            cwd=workspace, phase="sbom-tools validate --standard cra",
        )
        # cra's own exit code is not asserted to be 0 -- see the module
        # docstring: one known, structural error (vendor-hash coverage) is
        # expected to remain, outside this test's scope. 3 would mean the
        # validator itself failed to run (unsupported output, broken
        # config, I/O) -- that is always a hard failure, never expected.
        check(
            cra.returncode in (0, 1),
            f"sbom-tools --standard cra exited {cra.returncode} (expected 0 or 1; 3 means "
            f"the validator itself failed to run)",
        )
        cra_report = json.loads(cra.stdout)
        for violation in cra_report["violations"]:
            if violation["severity"] != "Error":
                continue
            rule_id = violation["rule_id"]
            check(
                rule_id in KNOWN_RESIDUAL_CRA_ERROR_RULE_IDS,
                f"unexpected CRA error {rule_id}: {violation['message']} -- either this is a "
                f"regression in a rule this test locks in, or a new gap that needs a decision: fix it, "
                f"or add it to KNOWN_RESIDUAL_CRA_ERROR_RULE_IDS with a reason",
            )

        print("interop case passed")
        return 0


if __name__ == "__main__":
    sys.exit(main())
