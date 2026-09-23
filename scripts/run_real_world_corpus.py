#!/usr/bin/env python3
"""Download pinned public repositories and scan them with bomwerk.

The corpus is deliberately outside this checkout by default. Each repository is
checked out at an immutable commit, and repository code is never executed.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Sequence


K_EXIT_CLEAN = 0
K_EXIT_WARNINGS = 1
K_EXIT_INCOMPLETE = 2
K_SOURCE_DATE_EPOCH = "1788998400"  # 2026-09-10 00:00:00 UTC
K_PROFILE_MAX_TIER = {"smoke": 0, "demo": 1, "all": 2}


@dataclass(frozen=True)
class CorpusRepository:
    full_name: str
    commit: str
    ecosystem: str
    tier: int
    reason: str

    @property
    def slug(self) -> str:
        return self.full_name.replace("/", "--")

    @property
    def url(self) -> str:
        return f"https://github.com/{self.full_name}.git"


@dataclass
class CorpusOutcome:
    repository: str
    ecosystem: str
    commit: str
    download: str = "not-requested"
    scan_exit_code: int | None = None
    scan_status: str = "not-requested"
    components: int | None = None
    elapsed_seconds: float | None = None
    detail: str = ""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_corpus_directory() -> Path:
    return repository_root().parent / "bomwerk-real-world-corpus"


def load_repositories() -> tuple[CorpusRepository, ...]:
    manifest_path = Path(__file__).with_name("real_world_corpus.json")
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    return tuple(CorpusRepository(**entry) for entry in document["repositories"])


REPOSITORIES = load_repositories()


def select_repositories(profile: str, requested: Sequence[str]) -> list[CorpusRepository]:
    if requested:
        requested_names = set(requested)
        selected = [
            repository
            for repository in REPOSITORIES
            if repository.full_name in requested_names or repository.slug in requested_names
        ]
        matched_names = {repository.full_name for repository in selected}
        matched_names.update(repository.slug for repository in selected)
        unknown_names = sorted(requested_names - matched_names)
        if unknown_names:
            raise ValueError("unknown corpus repository: " + ", ".join(unknown_names))
        return selected

    maximum_tier = K_PROFILE_MAX_TIER[profile]
    return [repository for repository in REPOSITORIES if repository.tier <= maximum_tier]


def sanitized_git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_LFS_SKIP_SMUDGE"] = "1"
    environment.pop("GIT_DIR", None)
    environment.pop("GIT_WORK_TREE", None)
    return environment


def run_process(
    arguments: Sequence[str],
    *,
    working_directory: Path | None = None,
    environment: dict[str, str] | None = None,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(arguments),
        cwd=working_directory,
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=timeout_seconds,
    )


def checked_git_command(
    arguments: Sequence[str], *, environment: dict[str, str], timeout_seconds: int
) -> subprocess.CompletedProcess[str]:
    completed = run_process(
        ["git", *arguments], environment=environment, timeout_seconds=timeout_seconds
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip() or completed.stdout.strip() or "git failed"
        raise RuntimeError(diagnostic)
    return completed


def existing_checkout_matches(
    repository: CorpusRepository, destination: Path, *, timeout_seconds: int
) -> tuple[bool, str]:
    if not (destination / ".git").is_dir():
        return False, f"{destination} exists but is not a Git checkout"

    environment = sanitized_git_environment()
    try:
        head = checked_git_command(
            ["-C", str(destination), "rev-parse", "HEAD"],
            environment=environment,
            timeout_seconds=timeout_seconds,
        ).stdout.strip()
        origin = checked_git_command(
            ["-C", str(destination), "remote", "get-url", "origin"],
            environment=environment,
            timeout_seconds=timeout_seconds,
        ).stdout.strip()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        return False, str(error)

    if head != repository.commit:
        return False, f"existing checkout is {head}; expected {repository.commit}"
    accepted_origins = {repository.url, repository.url.removesuffix(".git")}
    if origin not in accepted_origins:
        return False, f"existing checkout origin is {origin}; expected {repository.url}"
    return True, "already at pinned commit"


def download_repository(
    repository: CorpusRepository, repositories_directory: Path, *, timeout_seconds: int
) -> tuple[str, str]:
    destination = repositories_directory / repository.slug
    if destination.exists():
        matches, detail = existing_checkout_matches(
            repository, destination, timeout_seconds=timeout_seconds
        )
        return ("ready" if matches else "failed"), detail

    repositories_directory.mkdir(parents=True, exist_ok=True)
    temporary_path = Path(
        tempfile.mkdtemp(prefix=f".{repository.slug}-", dir=repositories_directory)
    )
    environment = sanitized_git_environment()
    try:
        checked_git_command(
            ["-c", "init.templateDir=", "init", "--quiet", str(temporary_path)],
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        disabled_hooks = temporary_path / ".git" / "disabled-hooks"
        disabled_hooks.mkdir()
        checked_git_command(
            ["-C", str(temporary_path), "config", "core.hooksPath", str(disabled_hooks)],
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        checked_git_command(
            ["-C", str(temporary_path), "remote", "add", "origin", repository.url],
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        checked_git_command(
            [
                "-C",
                str(temporary_path),
                "-c",
                "protocol.file.allow=never",
                "fetch",
                "--depth=1",
                "--filter=blob:none",
                "origin",
                repository.commit,
            ],
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        checked_git_command(
            [
                "-C",
                str(temporary_path),
                "-c",
                "advice.detachedHead=false",
                "checkout",
                "--quiet",
                "--detach",
                "FETCH_HEAD",
            ],
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        temporary_path.replace(destination)
        return "ready", "downloaded pinned commit"
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
        return "failed", str(error)
    finally:
        if temporary_path.exists():
            shutil.rmtree(temporary_path)


def vulnerability_arguments(mode: str) -> list[str]:
    if mode == "off":
        return ["--no-vuln"]
    if mode == "offline":
        return ["--offline"]
    return []


def component_count(sbom_path: Path) -> int | None:
    try:
        document = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    components = document.get("components")
    return len(components) if isinstance(components, list) else None


def scan_repository(
    repository: CorpusRepository,
    repository_directory: Path,
    results_directory: Path,
    bomwerk_binary: Path,
    vulnerability_mode: str,
    *,
    timeout_seconds: int,
) -> CorpusOutcome:
    outcome = CorpusOutcome(repository.full_name, repository.ecosystem, repository.commit)
    matches, detail = existing_checkout_matches(
        repository, repository_directory, timeout_seconds=timeout_seconds
    )
    if not matches:
        outcome.scan_exit_code = K_EXIT_INCOMPLETE
        outcome.scan_status = "incomplete"
        outcome.detail = detail
        return outcome

    artifact_directory = results_directory / repository.slug
    artifact_directory.mkdir(parents=True, exist_ok=True)
    sbom_path = artifact_directory / "sbom.cdx.json"
    arguments = [
        str(bomwerk_binary),
        "scan",
        str(repository_directory),
        "--quiet",
        "--output",
        str(sbom_path),
        "--html",
        str(artifact_directory / "report.html"),
        "--coverage",
        str(artifact_directory / "coverage.json"),
        "--product",
        repository.slug,
        "--product-version",
        repository.commit[:12],
        *vulnerability_arguments(vulnerability_mode),
    ]
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = K_SOURCE_DATE_EPOCH
    started_at = time.monotonic()
    try:
        completed = run_process(
            arguments,
            working_directory=repository_root(),
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        outcome.elapsed_seconds = round(time.monotonic() - started_at, 3)
        (artifact_directory / "scan.stdout").write_text(completed.stdout, encoding="utf-8")
        (artifact_directory / "scan.stderr").write_text(completed.stderr, encoding="utf-8")
        (artifact_directory / "command.txt").write_text(
            shlex.join(arguments) + "\n", encoding="utf-8"
        )
        outcome.scan_exit_code = completed.returncode
        outcome.components = component_count(sbom_path)
        if completed.returncode == K_EXIT_CLEAN:
            outcome.scan_status = "clean"
        elif completed.returncode == K_EXIT_WARNINGS:
            outcome.scan_status = "warnings"
        else:
            outcome.scan_status = "incomplete"
        outcome.detail = "artifacts: " + str(artifact_directory)
    except subprocess.TimeoutExpired as error:
        outcome.elapsed_seconds = round(time.monotonic() - started_at, 3)
        outcome.scan_exit_code = K_EXIT_INCOMPLETE
        outcome.scan_status = "incomplete"
        outcome.detail = f"scan exceeded {error.timeout} seconds"
    except OSError as error:
        outcome.elapsed_seconds = round(time.monotonic() - started_at, 3)
        outcome.scan_exit_code = K_EXIT_INCOMPLETE
        outcome.scan_status = "incomplete"
        outcome.detail = str(error)
    return outcome


def aggregate_exit_code(outcomes: Sequence[CorpusOutcome]) -> int:
    if any(
        outcome.download == "failed"
        or outcome.scan_exit_code not in (None, K_EXIT_CLEAN, K_EXIT_WARNINGS)
        for outcome in outcomes
    ):
        return K_EXIT_INCOMPLETE
    if any(outcome.scan_exit_code == K_EXIT_WARNINGS for outcome in outcomes):
        return K_EXIT_WARNINGS
    return K_EXIT_CLEAN


def write_summary(results_directory: Path, outcomes: Sequence[CorpusOutcome]) -> None:
    results_directory.mkdir(parents=True, exist_ok=True)
    ordered_outcomes = sorted(outcomes, key=lambda outcome: outcome.repository)
    (results_directory / "summary.json").write_text(
        json.dumps([asdict(outcome) for outcome in ordered_outcomes], indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    field_names = list(asdict(ordered_outcomes[0]).keys())
    with (results_directory / "summary.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=field_names)
        writer.writeheader()
        for outcome in ordered_outcomes:
            writer.writerow(asdict(outcome))


def print_repository_list(repositories: Sequence[CorpusRepository]) -> None:
    print(f"selected repositories: {len(repositories)}")
    for repository in repositories:
        print(
            f"{repository.full_name:34} {repository.ecosystem:14} "
            f"{repository.commit[:12]}  {repository.reason}"
        )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("list", "download", "scan", "all"))
    parser.add_argument("--profile", choices=tuple(K_PROFILE_MAX_TIER), default="demo")
    parser.add_argument(
        "--repository",
        action="append",
        default=[],
        help="run only owner/name or owner--name; repeat for several repositories",
    )
    parser.add_argument("--corpus-dir", type=Path, default=default_corpus_directory())
    parser.add_argument("--bomwerk", type=Path, default=repository_root() / "build" / "bomwerk")
    parser.add_argument(
        "--vulnerability-mode", choices=("off", "offline", "online"), default="off"
    )
    parser.add_argument("--download-timeout", type=int, default=1800)
    parser.add_argument("--scan-timeout", type=int, default=900)
    return parser


def main(command_line_arguments: Sequence[str] | None = None) -> int:
    arguments = build_argument_parser().parse_args(command_line_arguments)
    try:
        repositories = select_repositories(arguments.profile, arguments.repository)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return K_EXIT_INCOMPLETE

    if arguments.action == "list":
        print_repository_list(repositories)
        return K_EXIT_CLEAN

    corpus_directory = arguments.corpus_dir.resolve()
    repositories_directory = corpus_directory / "repositories"
    results_directory = corpus_directory / "results"
    outcomes = {
        repository.full_name: CorpusOutcome(
            repository.full_name, repository.ecosystem, repository.commit
        )
        for repository in repositories
    }

    if arguments.action in ("download", "all"):
        for position, repository in enumerate(repositories, start=1):
            print(f"[{position}/{len(repositories)}] download {repository.full_name}", flush=True)
            status, detail = download_repository(
                repository,
                repositories_directory,
                timeout_seconds=arguments.download_timeout,
            )
            outcomes[repository.full_name].download = status
            outcomes[repository.full_name].detail = detail
            print(f"  {status}: {detail}", flush=True)

    if arguments.action in ("scan", "all"):
        bomwerk_binary = arguments.bomwerk.resolve()
        if not bomwerk_binary.is_file():
            print(f"error: bomwerk binary not found: {bomwerk_binary}", file=sys.stderr)
            for outcome in outcomes.values():
                outcome.scan_exit_code = K_EXIT_INCOMPLETE
                outcome.scan_status = "incomplete"
                outcome.detail = f"bomwerk binary not found: {bomwerk_binary}"
            write_summary(results_directory, list(outcomes.values()))
            return K_EXIT_INCOMPLETE
        for position, repository in enumerate(repositories, start=1):
            print(f"[{position}/{len(repositories)}] scan {repository.full_name}", flush=True)
            scanned = scan_repository(
                repository,
                repositories_directory / repository.slug,
                results_directory,
                bomwerk_binary,
                arguments.vulnerability_mode,
                timeout_seconds=arguments.scan_timeout,
            )
            scanned.download = outcomes[repository.full_name].download
            outcomes[repository.full_name] = scanned
            component_text = "?" if scanned.components is None else str(scanned.components)
            print(
                f"  {scanned.scan_status}: exit={scanned.scan_exit_code}, "
                f"components={component_text}, {scanned.detail}",
                flush=True,
            )

    ordered_outcomes = [outcomes[repository.full_name] for repository in repositories]
    write_summary(results_directory, ordered_outcomes)
    exit_code = aggregate_exit_code(ordered_outcomes)
    print(f"summary: {results_directory / 'summary.csv'}")
    print(f"corpus exit: {exit_code} (0 clean, 1 warnings, 2 incomplete)")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
