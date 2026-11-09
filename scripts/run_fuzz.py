#!/usr/bin/env python3
"""Run the libFuzzer harnesses listed in scripts/fuzz_targets.json (T40, docs/fuzzing.md).

Usage:
  run_fuzz.py --build-dir build-fuzz [--budget-seconds 600] [--jobs 4]
              [--shard I/N] [--targets GLOB] [--corpus-root DIR] [--artifacts-dir DIR]
  run_fuzz.py --build-dir build-fuzz --replay   # run every corpus input once
  run_fuzz.py --build-dir build-fuzz --merge    # minimize each corpus in place

A campaign seeds each selected target's corpus (from the manifest's seed paths, and
the generated ELF and `ar` seeds), then runs up to --jobs fuzzers at a time, splitting
--budget-seconds of wall clock between the targets. Corpora live under the build
directory, never in fixtures/: libFuzzer writes every new input into its first
corpus directory. The exit status is 1 when any target produced a crash-, leak-,
timeout- or oom- file or ended badly, so CI fails on findings; each finding's input
is under --artifacts-dir/<target>/.

Standard library only: CI runs it before any pip install.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPOSITORY / "scripts" / "fuzz_targets.json"
FINDING_PREFIXES = ("crash-", "leak-", "timeout-", "oom-")
SKIPPED_SEED_NAMES = {"README.md", "SOURCES.md"}
MINIMUM_SECONDS_PER_TARGET = 30
BUDGET_RESERVE = 0.05  # kept back for start-up, seeding and the summary
SUBPROCESS_GRACE_SECONDS = 120  # beyond -max_total_time before a fuzzer counts as hung
SEED_WRITER = "fuzz_binary_seed_writer"
# A finding file written during a run is stamped after the run started; the
# slack absorbs coarse filesystem timestamps, nothing more.
FINDING_CLOCK_SLACK_SECONDS = 1.0


@dataclass
class TargetOutcome:
    name: str
    seconds: int
    exit_code: int | None
    findings: list[str] = field(default_factory=list)
    note: str = ""
    earlier: list[str] = field(default_factory=list)  # finding files left by earlier runs

    @property
    def failed(self) -> bool:
        return bool(self.findings) or self.exit_code not in (0, None) or bool(self.note)


def load_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != 1:
        raise SystemExit(f"run_fuzz: {path}: unsupported schema {manifest.get('schema')!r}")
    return manifest


def parse_shard(text: str | None) -> tuple[int, int]:
    """`I/N` as (I, N); None means the whole manifest, (0, 1)."""
    if text is None:
        return 0, 1
    index_text, _, count_text = text.partition("/")
    index, count = int(index_text), int(count_text)
    if count < 1 or not 0 <= index < count:
        raise SystemExit(f"run_fuzz: --shard {text}: expected I/N with 0 <= I < N")
    return index, count


def shard_of(name: str, shard_count: int) -> int:
    """A stable shard for a target name: adding a target never moves the others,
    so each shard's cached corpus keeps belonging to the same targets."""
    return zlib.crc32(name.encode()) % shard_count


def select_targets(targets: list[dict], shard: tuple[int, int], pattern: str | None) -> list[dict]:
    index, count = shard
    return [
        target for target in targets
        if shard_of(target["name"], count) == index
        and (pattern is None or fnmatch.fnmatch(target["name"], pattern))
    ]


def seconds_per_target(budget_seconds: int, jobs: int, target_count: int) -> int:
    """Wall-clock seconds each target fuzzes so that `target_count` targets, `jobs` at
    a time, fit in `budget_seconds` (less a small reserve). Never below the minimum
    a useful run needs, so a tight budget overruns rather than fuzzing nothing."""
    if target_count == 0:
        return 0
    usable = budget_seconds * (1.0 - BUDGET_RESERVE)
    rounds = -(-target_count // max(jobs, 1))  # ceil
    return max(MINIMUM_SECONDS_PER_TARGET, int(usable // rounds))


def seed_files(target: dict, repository: Path, generated_root: Path) -> list[Path]:
    """Every file the target is seeded from, in path order."""
    suffixes = target["seed_suffixes"]
    roots = [repository / seed_path for seed_path in target["seed_paths"]]
    if target.get("generated_seeds"):
        roots.append(generated_root / target["generated_seeds"])
    files = []
    for root in roots:
        candidates = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
        for candidate in candidates:
            if candidate.name in SKIPPED_SEED_NAMES:
                continue
            if not suffixes or any(candidate.name.endswith(suffix) for suffix in suffixes):
                files.append(candidate)
    return files


def seed_corpus(files: list[Path], corpus_directory: Path) -> int:
    """Copy seeds into the corpus under content-hash names; idempotent."""
    corpus_directory.mkdir(parents=True, exist_ok=True)
    added = 0
    for path in files:
        data = path.read_bytes()
        destination = corpus_directory / hashlib.sha1(data).hexdigest()
        if not destination.exists():
            destination.write_bytes(data)
            added += 1
    return added


def libfuzzer_flags(target: dict, defaults: dict, repository: Path, artifact_directory: Path) -> list[str]:
    return [
        f"-max_len={defaults['max_len']}",
        f"-timeout={defaults['timeout_seconds']}",
        f"-rss_limit_mb={defaults['rss_limit_mb']}",
        f"-dict={repository / target['dictionary']}",
        f"-artifact_prefix={artifact_directory}/",
        "-print_final_stats=1",
    ]


def findings_in(artifact_directory: Path, since: float = 0.0) -> list[str]:
    """Finding files written at or after `since` (epoch seconds): what this run found."""
    if not artifact_directory.is_dir():
        return []
    return sorted(p.name for p in artifact_directory.iterdir()
                  if p.name.startswith(FINDING_PREFIXES) and p.stat().st_mtime >= since)


def earlier_findings(artifact_directory: Path, since: float) -> list[str]:
    """Finding files left by earlier runs: reported, but they do not fail this one. A
    crash that is still unfixed is found again, so nothing real is hidden."""
    if not artifact_directory.is_dir():
        return []
    return sorted(p.name for p in artifact_directory.iterdir()
                  if p.name.startswith(FINDING_PREFIXES) and p.stat().st_mtime < since)


def run_logged(command: list[str], log_path: Path, timeout: int | None) -> tuple[int | None, str]:
    """Run `command` with stdout and stderr into `log_path`; (exit code, note)."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("wb") as log:
        try:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                       timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return None, "did not stop after its time budget (hung)"
        except OSError as error:
            return None, f"could not start: {error}"
    return completed.returncode, ""


def fuzz_one(target: dict, binary: Path, defaults: dict, repository: Path, corpus_directory: Path,
             artifact_directory: Path, seconds: int) -> TargetOutcome:
    command = [str(binary), f"-max_total_time={seconds}",
               *libfuzzer_flags(target, defaults, repository, artifact_directory),
               str(corpus_directory)]
    started = time.time() - FINDING_CLOCK_SLACK_SECONDS
    exit_code, note = run_logged(command, artifact_directory / "fuzz.log",
                                 seconds + SUBPROCESS_GRACE_SECONDS)
    return TargetOutcome(target["name"], seconds, exit_code, findings_in(artifact_directory, started), note,
                         earlier_findings(artifact_directory, started))


def replay_one(target: dict, binary: Path, defaults: dict, repository: Path, corpus_directory: Path,
               artifact_directory: Path) -> TargetOutcome:
    # -runs=0 executes every corpus input once and stops: a regression check.
    command = [str(binary), "-runs=0",
               *libfuzzer_flags(target, defaults, repository, artifact_directory),
               str(corpus_directory)]
    started = time.time() - FINDING_CLOCK_SLACK_SECONDS
    exit_code, note = run_logged(command, artifact_directory / "replay.log", None)
    return TargetOutcome(target["name"], 0, exit_code, findings_in(artifact_directory, started), note,
                         earlier_findings(artifact_directory, started))


def merge_one(target: dict, binary: Path, defaults: dict, repository: Path, corpus_directory: Path,
              artifact_directory: Path) -> TargetOutcome:
    """Minimize the corpus: keep the smallest set of inputs with the same coverage."""
    merged = corpus_directory.with_name(corpus_directory.name + ".merged")
    shutil.rmtree(merged, ignore_errors=True)
    merged.mkdir(parents=True)
    command = [str(binary), "-merge=1",
               f"-merge_control_file={corpus_directory.with_name(corpus_directory.name + '.merge-control')}",
               *libfuzzer_flags(target, defaults, repository, artifact_directory),
               str(merged), str(corpus_directory)]
    started = time.time() - FINDING_CLOCK_SLACK_SECONDS
    exit_code, note = run_logged(command, artifact_directory / "merge.log", None)
    if exit_code == 0 and not note and any(merged.iterdir()):
        # Swap through a sibling so the corpus is never absent: an interrupted
        # run leaves either the old corpus or the merged one in place.
        previous = corpus_directory.with_name(corpus_directory.name + ".previous")
        shutil.rmtree(previous, ignore_errors=True)
        corpus_directory.rename(previous)
        merged.rename(corpus_directory)
        shutil.rmtree(previous, ignore_errors=True)
    else:
        shutil.rmtree(merged, ignore_errors=True)
    return TargetOutcome(target["name"], 0, exit_code, findings_in(artifact_directory, started), note,
                         earlier_findings(artifact_directory, started))


def write_summary(outcomes: list[TargetOutcome], mode: str) -> str:
    lines = [f"### Fuzzing ({mode})", "", "| target | seconds | result |", "|---|---|---|"]
    for outcome in sorted(outcomes, key=lambda item: item.name):
        if outcome.findings:
            result = "**findings:** " + ", ".join(outcome.findings)
        elif outcome.note:
            result = "**" + outcome.note + "**"
        elif outcome.exit_code not in (0, None):
            result = f"**exit {outcome.exit_code}**"
        elif outcome.earlier:
            result = "clean (earlier finding files ignored: " + ", ".join(outcome.earlier) + ")"
        else:
            result = "clean"
        lines.append(f"| `{outcome.name}` | {outcome.seconds} | {result} |")
    failed = sum(1 for outcome in outcomes if outcome.failed)
    lines += ["", f"{len(outcomes)} target(s), {failed} with findings or errors."]
    summary = "\n".join(lines) + "\n"
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as stream:
            stream.write(summary)
    return summary


def generate_binary_seeds(build_directory: Path, generated_root: Path, targets: list[dict]) -> None:
    if not any(target.get("generated_seeds") for target in targets):
        return
    writer = build_directory / SEED_WRITER
    completed = subprocess.run([str(writer), str(generated_root)], check=False)
    if completed.returncode != 0:
        raise SystemExit(f"run_fuzz: {writer} failed with exit {completed.returncode}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--build-dir", type=Path, required=True,
                        help="a build configured with -DBOMWERK_FUZZ=ON and built with --target fuzzers")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--corpus-root", type=Path, help="default: <build-dir>/fuzz-corpus")
    parser.add_argument("--artifacts-dir", type=Path, help="default: <build-dir>/fuzz-artifacts")
    parser.add_argument("--budget-seconds", type=int, default=600,
                        help="wall clock for the whole campaign (default 600)")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1,
                        help="fuzzers run at the same time (default: CPU count)")
    parser.add_argument("--shard", help="I/N: run only the targets of shard I of N")
    parser.add_argument("--targets", help="only targets whose name matches this glob")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--replay", action="store_true", help="run every corpus input once")
    mode.add_argument("--merge", action="store_true", help="minimize every corpus in place")
    arguments = parser.parse_args(argv)

    manifest = load_manifest(arguments.manifest)
    build_directory = arguments.build_dir.resolve()
    corpus_root = (arguments.corpus_root or build_directory / "fuzz-corpus").resolve()
    artifacts_root = (arguments.artifacts_dir or build_directory / "fuzz-artifacts").resolve()
    generated_root = build_directory / "fuzz-seeds"
    targets = select_targets(manifest["targets"], parse_shard(arguments.shard), arguments.targets)
    if not targets:
        print("run_fuzz: no target selected", file=sys.stderr)
        return 1

    generate_binary_seeds(build_directory, generated_root, targets)
    for target in targets:
        seed_corpus(seed_files(target, REPOSITORY, generated_root), corpus_root / target["name"])

    seconds = seconds_per_target(arguments.budget_seconds, arguments.jobs, len(targets))
    mode_name = "replay" if arguments.replay else "merge" if arguments.merge else "campaign"
    print(f"run_fuzz: {mode_name}, {len(targets)} target(s)"
          + ("" if arguments.replay or arguments.merge else f", {seconds}s each, {arguments.jobs} at a time"))

    def run(target: dict) -> TargetOutcome:
        binary = build_directory / target["name"]
        corpus_directory = corpus_root / target["name"]
        artifact_directory = artifacts_root / target["name"]
        artifact_directory.mkdir(parents=True, exist_ok=True)
        if not binary.is_file():
            return TargetOutcome(target["name"], 0, None, [], f"missing binary {binary}")
        if arguments.replay:
            return replay_one(target, binary, manifest["defaults"], REPOSITORY, corpus_directory,
                              artifact_directory)
        if arguments.merge:
            return merge_one(target, binary, manifest["defaults"], REPOSITORY, corpus_directory,
                             artifact_directory)
        return fuzz_one(target, binary, manifest["defaults"], REPOSITORY, corpus_directory,
                        artifact_directory, seconds)

    outcomes: list[TargetOutcome] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(arguments.jobs, 1)) as pool:
        futures = [pool.submit(run, target) for target in targets]
        # A line per target as it finishes: the fuzzers write to log files, so
        # without this a two-hour CI step prints nothing until the very end.
        for future in concurrent.futures.as_completed(futures):
            outcome = future.result()
            outcomes.append(outcome)
            state = "FAILED" if outcome.failed else "ok"
            print(f"run_fuzz: [{len(outcomes)}/{len(targets)}] {outcome.name} {state}", flush=True)

    print(write_summary(outcomes, mode_name))
    return 1 if any(outcome.failed for outcome in outcomes) else 0


if __name__ == "__main__":
    sys.exit(main())
