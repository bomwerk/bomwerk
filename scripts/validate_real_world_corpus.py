#!/usr/bin/env python3
"""Hermetic contract checks for run_real_world_corpus.py."""

from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def load_corpus_module():
    script_path = Path(__file__).with_name("run_real_world_corpus.py")
    specification = importlib.util.spec_from_file_location("run_real_world_corpus", script_path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot import {script_path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def check_checkout_contract(corpus) -> None:
    repository = corpus.REPOSITORIES[0]
    with tempfile.TemporaryDirectory(prefix="bomwerk_corpus_checkout_") as temporary_directory:
        checkout = Path(temporary_directory) / repository.slug
        (checkout / ".git").mkdir(parents=True)
        original_checked_git_command = corpus.checked_git_command

        def fake_checked_git_command(arguments, *, environment, timeout_seconds):
            del environment, timeout_seconds
            if "rev-parse" in arguments:
                output = repository.commit + "\n"
            else:
                output = repository.url + "\n"
            return subprocess.CompletedProcess(arguments, 0, output, "")

        corpus.checked_git_command = fake_checked_git_command
        try:
            matches, detail = corpus.existing_checkout_matches(
                repository, checkout, timeout_seconds=1
            )
        finally:
            corpus.checked_git_command = original_checked_git_command
        require(matches, f"matching checkout was refused: {detail}")


def check_download_contract(corpus) -> None:
    repository = corpus.REPOSITORIES[0]
    with tempfile.TemporaryDirectory(prefix="bomwerk_corpus_download_") as temporary_directory:
        repositories_directory = Path(temporary_directory) / "repositories"
        original_checked_git_command = corpus.checked_git_command

        def fake_checked_git_command(arguments, *, environment, timeout_seconds):
            del environment, timeout_seconds
            if "init" in arguments:
                (Path(arguments[-1]) / ".git").mkdir()
            return subprocess.CompletedProcess(arguments, 0, "", "")

        corpus.checked_git_command = fake_checked_git_command
        try:
            status, detail = corpus.download_repository(
                repository, repositories_directory, timeout_seconds=1
            )
        finally:
            corpus.checked_git_command = original_checked_git_command
        require(status == "ready", f"hermetic download failed: {detail}")
        require(
            (repositories_directory / repository.slug / ".git").is_dir(),
            "download did not atomically move the prepared checkout",
        )
        require(
            not list(repositories_directory.glob(f".{repository.slug}-*")),
            "download left a temporary checkout behind",
        )


def check_scan_contract(corpus) -> None:
    repository = corpus.REPOSITORIES[0]
    with tempfile.TemporaryDirectory(prefix="bomwerk_corpus_scan_") as temporary_directory:
        temporary_root = Path(temporary_directory)
        checkout = temporary_root / "checkout"
        checkout.mkdir()
        results = temporary_root / "results"
        fake_bomwerk = temporary_root / "fake-bomwerk"
        fake_bomwerk.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "from pathlib import Path\n"
            "import sys\n"
            "def value(option):\n"
            "    return sys.argv[sys.argv.index(option) + 1]\n"
            "Path(value('--output')).write_text(json.dumps({'components': [{}, {}]}))\n"
            "Path(value('--html')).write_text('<html></html>')\n"
            "Path(value('--coverage')).write_text('{}')\n"
            "print('scan summary')\n"
            "print('expected warning', file=sys.stderr)\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        fake_bomwerk.chmod(0o700)
        original_checkout_check = corpus.existing_checkout_matches
        corpus.existing_checkout_matches = lambda *args, **kwargs: (True, "ready")
        try:
            outcome = corpus.scan_repository(
                repository,
                checkout,
                results,
                fake_bomwerk,
                "off",
                timeout_seconds=10,
            )
        finally:
            corpus.existing_checkout_matches = original_checkout_check
        artifact_directory = results / repository.slug
        require(outcome.scan_exit_code == 1, "scan did not preserve warning exit")
        require(outcome.scan_status == "warnings", "scan did not classify warning exit")
        require(outcome.components == 2, "scan did not count SBOM components")
        require(
            (artifact_directory / "scan.stdout").read_text(encoding="utf-8")
            == "scan summary\n",
            "scan stdout was not preserved",
        )
        require(
            (artifact_directory / "scan.stderr").read_text(encoding="utf-8")
            == "expected warning\n",
            "scan stderr was not preserved",
        )
        require(
            "--no-vuln" in (artifact_directory / "command.txt").read_text(encoding="utf-8"),
            "scan's safe default was not recorded",
        )


def check_missing_binary_summary(corpus) -> None:
    repository = corpus.REPOSITORIES[0]
    with tempfile.TemporaryDirectory(prefix="bomwerk_corpus_summary_") as temporary_directory:
        temporary_root = Path(temporary_directory)
        return_code = corpus.main(
            [
                "scan",
                "--repository",
                repository.full_name,
                "--corpus-dir",
                str(temporary_root),
                "--bomwerk",
                str(temporary_root / "missing-bomwerk"),
            ]
        )
        summary_path = temporary_root / "results" / "summary.json"
        require(return_code == 2, "missing binary must return incomplete")
        require(summary_path.is_file(), "missing binary did not preserve a summary")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        require(summary[0]["scan_exit_code"] == 2, "missing binary summary lost exit 2")


def main() -> int:
    corpus = load_corpus_module()
    repositories = corpus.REPOSITORIES

    # Given the checked-in corpus, when its immutable identities are inspected,
    # then every checkout target is unique, HTTPS-only, and fully pinned.
    require(len(repositories) == 36, "the all profile must contain 36 repositories")
    require(
        len({repository.full_name for repository in repositories}) == len(repositories),
        "repository names must be unique",
    )
    require(
        len({repository.slug for repository in repositories}) == len(repositories),
        "repository directory slugs must be unique",
    )
    for repository in repositories:
        require(
            re.fullmatch(r"[0-9a-f]{40}", repository.commit) is not None,
            f"{repository.full_name} is not pinned to a full commit SHA",
        )
        require(
            repository.url.startswith("https://github.com/"),
            f"{repository.full_name} must use an HTTPS GitHub URL",
        )
        require(repository.tier in (0, 1, 2), f"{repository.full_name} has an invalid tier")

    # Given cumulative profiles, when selected, then demo and all stay within
    # the requested 20-40 repositories while smoke remains quick.
    require(
        len(corpus.select_repositories("smoke", [])) == 12,
        "the smoke profile must contain 12 repositories",
    )
    require(
        len(corpus.select_repositories("demo", [])) == 24,
        "the demo profile must contain 24 repositories",
    )
    require(
        len(corpus.select_repositories("all", [])) == 36,
        "the all profile must contain 36 repositories",
    )

    # Given bomwerk's exit-code contract, when corpus outcomes are aggregated,
    # then incomplete wins over warnings and warnings win over clean.
    clean = corpus.CorpusOutcome("a/a", "test", "0" * 40, scan_exit_code=0)
    warned = corpus.CorpusOutcome("b/b", "test", "1" * 40, scan_exit_code=1)
    incomplete = corpus.CorpusOutcome("c/c", "test", "2" * 40, scan_exit_code=2)
    clone_failed = corpus.CorpusOutcome("d/d", "test", "3" * 40, download="failed")
    require(corpus.aggregate_exit_code([clean]) == 0, "clean aggregation changed")
    require(corpus.aggregate_exit_code([clean, warned]) == 1, "warning aggregation changed")
    require(
        corpus.aggregate_exit_code([warned, incomplete]) == 2,
        "incomplete aggregation changed",
    )
    require(
        corpus.aggregate_exit_code([clean, clone_failed]) == 2,
        "download failure must be incomplete",
    )

    # Given each vulnerability mode, when translated to scan arguments, then
    # network access is explicit and the default disables vulnerability calls.
    require(
        corpus.vulnerability_arguments("off") == ["--no-vuln"],
        "off mode must disable vulnerability matching",
    )
    require(
        corpus.vulnerability_arguments("offline") == ["--offline"],
        "offline mode must use the cache-only flag",
    )
    require(
        corpus.vulnerability_arguments("online") == [],
        "online mode must use scan's default vulnerability behavior",
    )

    # Given the CLI list action, when smoke is requested, then it performs no
    # network work and prints exactly the selected repository count.
    output = io.StringIO()
    with redirect_stdout(output):
        return_code = corpus.main(["list", "--profile", "smoke"])
    require(return_code == 0, "list action must exit cleanly")
    require(
        output.getvalue().splitlines()[0] == "selected repositories: 12",
        "list action reported the wrong profile size",
    )
    check_checkout_contract(corpus)
    check_download_contract(corpus)
    check_scan_contract(corpus)
    check_missing_binary_summary(corpus)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
