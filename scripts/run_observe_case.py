#!/usr/bin/env python3
"""Run a real cmake build under `bomwerk observe` and check the JSONL trace.

Usage: run_observe_case.py <bomwerk-binary> <shim-binary> <fixture-dir> <cmake-binary>

The observer acceptance check: a full cmake build traced to JSONL. Unit tests cover
the pieces -- the line format, the locked append, the validation pass -- but
only this harness exercises the mechanism that actually has to work: PATH
interception, a genuine compiler running behind a shim, and the trace that
falls out the other end. It drives the real binaries for the same reason the
golden harness does.

Why BOTH cmake phases run under observe: cmake records the compiler's ABSOLUTE
path in CMakeCache.txt at configure time, so building an already-configured
tree never consults PATH and the shims are never reached. Configuring under
observe is what puts the shim path into the cache. A test that observed only
the build phase would pass on an empty trace and prove nothing.

The last phase is the one that protects the developer: it rebuilds with the
bomwerk variables gone, the way a plain `cmake --build` runs the morning after.
The cached compiler path still points at a shim, so that build only works
because each shim has a `<tool>.real` sidecar telling it what to exec. Losing
that would leave every observed build tree broken until reconfigured, which is
a far worse bug than a missing trace.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(message):
    print(f"observe case FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def run(command, cwd, env, phase):
    """Run one phase, echoing its output so a CI failure is readable."""
    completed = subprocess.run(
        command, cwd=str(cwd), env=env, capture_output=True, text=True
    )
    print(f"=== {phase}: {' '.join(str(part) for part in command)} ===")
    print(f"--- exit {completed.returncode} ---")
    if completed.stdout:
        print(completed.stdout)
    if completed.stderr:
        print(completed.stderr, file=sys.stderr)
    return completed


def read_trace(trace_path):
    """Every line must be a well-formed record; that is the trace's whole job."""
    if not trace_path.is_file():
        fail(f"no trace written at {trace_path}")
    records = []
    for line_number, line in enumerate(
        trace_path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            fail(f"{trace_path}:{line_number} is not valid JSON ({error})")
        for key in ("argv", "cwd", "pid", "tool"):
            if key not in record:
                fail(f"{trace_path}:{line_number} has no '{key}' key: {line[:200]}")
        if not isinstance(record["argv"], list):
            fail(f"{trace_path}:{line_number} has a non-list argv")
        records.append(record)
    return records


def main():
    if len(sys.argv) != 5:
        fail(f"usage: {Path(sys.argv[0]).name} <bomwerk> <shim> <fixture-dir> <cmake>")
    bomwerk_binary = Path(sys.argv[1]).resolve()
    shim_binary = Path(sys.argv[2]).resolve()
    fixture_directory = Path(sys.argv[3]).resolve()
    cmake_binary = Path(sys.argv[4]).resolve()

    with tempfile.TemporaryDirectory(prefix="bomwerk_observe_") as temporary_root:
        workspace = Path(temporary_root)
        # The fixture is copied so the build tree, the shim directory and the
        # touched source all stay out of the repo.
        source_directory = workspace / "src"
        shutil.copytree(fixture_directory, source_directory)
        build_directory = workspace / "build"
        trace_path = workspace / "trace.jsonl"

        observe_environment = dict(os.environ)
        # Pin the shim explicitly: ctest may run the binary from anywhere, and a
        # wrong shim here would make every later assertion meaningless.
        observe_environment["BOMWERK_SHIM_BINARY"] = str(shim_binary)

        configure = run(
            [bomwerk_binary, "observe", "--trace", str(trace_path), "--",
             cmake_binary, "-S", str(source_directory), "-B", str(build_directory)],
            cwd=workspace, env=observe_environment, phase="configure under observe",
        )
        if configure.returncode > 1:
            fail(f"configure under observe exited {configure.returncode}")

        build = run(
            [bomwerk_binary, "observe", "--trace", str(trace_path), "--",
             cmake_binary, "--build", str(build_directory)],
            cwd=workspace, env=observe_environment, phase="build under observe",
        )
        if build.returncode != 0:
            fail(f"build under observe exited {build.returncode}, expected 0 (clean)")

        # Each run starts a fresh trace, so this is the build phase alone.
        records = read_trace(trace_path)
        if not records:
            fail("the trace is empty -- the shims were never reached")

        tools_seen = sorted({record["tool"] for record in records})
        print(f"=== recorded {len(records)} invocations across tools: {tools_seen} ===")

        compiled_sources = [
            record for record in records
            if any(str(argument).endswith("hello.c") for argument in record["argv"])
        ]
        if not compiled_sources:
            fail(f"no invocation mentions hello.c; tools seen: {tools_seen}")

        # Canonical order (hard rule 3): the validation pass sorts the file, so
        # two runs of the same build produce byte-identical traces.
        trace_lines = [
            line for line in trace_path.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        if trace_lines != sorted(trace_lines):
            fail("the trace is not in canonical (sorted) order")

        shim_directory = workspace / ".bomwerk" / "shims"
        if not (shim_directory / "cc").exists():
            fail(f"no cc shim was created in {shim_directory}")
        if not (shim_directory / "cc.real").is_file():
            fail(f"no cc.real sidecar beside the shim in {shim_directory}")

        # The developer's tree must keep working without bomwerk. The cached
        # compiler path still points at a shim, so this passes only because of
        # the sidecar.
        plain_environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("BOMWERK_")
        }
        (source_directory / "hello.c").touch()
        plain_rebuild = run(
            [cmake_binary, "--build", str(build_directory)],
            cwd=workspace, env=plain_environment, phase="plain rebuild, no observe",
        )
        if plain_rebuild.returncode != 0:
            fail(
                "a plain `cmake --build` failed after the tree was configured under "
                f"observe (exit {plain_rebuild.returncode}) -- the shim sidecar fallback "
                "is broken, and every observed build tree would be left unbuildable"
            )

    print("observe case passed")


if __name__ == "__main__":
    main()
