#!/usr/bin/env python3
"""scripts/fuzz_targets.json agrees with tests/fuzz/ and with the fixtures it names (T40).

CMake builds the harnesses from the manifest and scripts/run_fuzz.py runs them from it,
so a target that names a missing source, seed path or dictionary, or a harness that no
target builds, would only surface as a broken CI job. This catches it in ctest.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
MANIFEST = REPOSITORY / "scripts" / "fuzz_targets.json"
FUZZ_DIRECTORY = REPOSITORY / "tests" / "fuzz"

# Library targets a harness may link (CMakeLists.txt); empty means bomwerk_core alone.
KNOWN_LIBRARIES = {
    "bomwerk_parsers",
    "bomwerk_heuristics",
    "bomwerk_binscan",
    "bomwerk_sbom",
    "bomwerk_observe",
    "bomwerk_vuln",
}
GENERATED_SEED_KINDS = {"elf", "archive"}
NOT_HARNESSES = {"fuzz_support.cpp"}
SKIPPED_SEED_NAMES = {"README.md", "SOURCES.md"}


def load_run_fuzz():
    """scripts/run_fuzz.py as a module, without putting scripts/ on sys.path."""
    specification = importlib.util.spec_from_file_location(
        "run_fuzz", REPOSITORY / "scripts" / "run_fuzz.py")
    module = importlib.util.module_from_spec(specification)
    # `@dataclass` looks its own module up in sys.modules while the class body
    # is being processed, so the module must be registered before it runs.
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def write_stub_fuzzer(path: Path, crash: bool) -> None:
    """An executable that behaves like a libFuzzer binary for run_fuzz.py: it
    reads -artifact_prefix and either exits cleanly or leaves a crash file
    there and exits 77, as libFuzzer does on a finding."""
    lines = [
        "#!" + sys.executable,
        "import sys",
        "prefix = next(a.split('=', 1)[1] for a in sys.argv if a.startswith('-artifact_prefix='))",
    ]
    if crash:
        lines += ["open(prefix + 'crash-0123', 'w').write('boom')", "sys.exit(77)"]
    else:
        lines += ["sys.exit(0)"]
    path.write_text("\n".join(lines) + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def seed_files(target: dict) -> list[Path]:
    """The files the `<target>_seeds` replay would feed, as replay_main.cpp selects them."""
    suffixes = target["seed_suffixes"]
    files = []
    for seed_path in target["seed_paths"]:
        base = REPOSITORY / seed_path
        candidates = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file()]
        for candidate in candidates:
            if candidate.name in SKIPPED_SEED_NAMES:
                continue
            if not suffixes or any(candidate.name.endswith(suffix) for suffix in suffixes):
                files.append(candidate)
    return files


class FuzzTargetsManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = load_manifest()
        self.targets = self.manifest["targets"]

    def test_schema_and_defaults(self) -> None:
        # Given the manifest, then it is the schema run_fuzz.py reads, with
        # libFuzzer defaults present and positive.
        self.assertEqual(self.manifest["schema"], 1)
        for key in ("max_len", "timeout_seconds", "rss_limit_mb"):
            self.assertGreater(self.manifest["defaults"][key], 0, key)

    def test_names_are_unique_and_well_formed(self) -> None:
        # Given every target, then its name is a unique fuzz_<snake_case> name:
        # it becomes an executable, a ctest and a corpus directory.
        names = [target["name"] for target in self.targets]
        self.assertEqual(len(names), len(set(names)), "duplicate target names")
        for name in names:
            self.assertRegex(name, r"^fuzz_[a-z0-9_]+$")

    def test_every_source_exists_and_every_harness_is_built(self) -> None:
        # Given the harness sources, then each target's source exists and each
        # fuzz_*.cpp is built by at least one target.
        sources = {target["source"] for target in self.targets}
        for source in sources:
            self.assertTrue((FUZZ_DIRECTORY / source).is_file(), source)
        harnesses = {path.name for path in FUZZ_DIRECTORY.glob("fuzz_*.cpp")} - NOT_HARNESSES
        self.assertEqual(harnesses - sources, set(), "harnesses no target builds")

    def test_variants_are_given_where_a_harness_requires_one(self) -> None:
        # Given a harness that stops compiling without BOMWERK_FUZZ_VARIANT,
        # then every target built from it sets one.
        for target in self.targets:
            text = (FUZZ_DIRECTORY / target["source"]).read_text()
            if re.search(r"#error .*BOMWERK_FUZZ_VARIANT", text):
                self.assertTrue(target.get("variant"), target["name"])

    def test_libraries_are_known(self) -> None:
        # Given every target, then it links only library targets CMake defines.
        for target in self.targets:
            self.assertLessEqual(set(target["libraries"]), KNOWN_LIBRARIES, target["name"])

    def test_seed_paths_dictionaries_and_generators_exist(self) -> None:
        # Given every target, then its seed paths and dictionary exist and any
        # generated seeds are a kind the seed writer produces.
        for target in self.targets:
            for seed_path in target["seed_paths"]:
                self.assertTrue((REPOSITORY / seed_path).exists(), f"{target['name']}: {seed_path}")
            self.assertTrue((REPOSITORY / target["dictionary"]).is_file(), target["name"])
            generated = target.get("generated_seeds")
            if generated is not None:
                self.assertIn(generated, GENERATED_SEED_KINDS, target["name"])

    def test_every_target_has_a_seed(self) -> None:
        # Given every target, then it starts from at least one seed: a fuzzer
        # with an empty corpus wastes its first hour rediscovering the format,
        # and a replay ctest with nothing to replay fails.
        for target in self.targets:
            if target.get("generated_seeds"):
                continue
            self.assertTrue(seed_files(target), f"{target['name']} has no seed")

    def test_dictionaries_are_libfuzzer_syntax(self) -> None:
        # Given every dictionary, then each non-comment line is a quoted token
        # using only the escapes libFuzzer parses: \\, \" and \xAB. Anything else
        # (\n, \r, \t) makes the fuzzer exit 1 before it runs a single input.
        token = re.compile(r'^"(?:[^"\\\x00-\x1f]|\\\\|\\"|\\x[0-9a-fA-F]{2})*"$')
        for dictionary in sorted({target["dictionary"] for target in self.targets}):
            for line in (REPOSITORY / dictionary).read_text().splitlines():
                if line and not line.startswith("#"):
                    self.assertRegex(line, token, f"{dictionary}: {line}")


class RunFuzzTest(unittest.TestCase):
    def setUp(self) -> None:
        self.run_fuzz = load_run_fuzz()

    def test_shards_partition_the_targets_stably(self) -> None:
        # Given the real target list and four shards, when selected, then every
        # target lands in exactly one shard, and adding a target moves no other.
        targets = load_manifest()["targets"]
        shards = [self.run_fuzz.select_targets(targets, (index, 4), None) for index in range(4)]
        names = sorted(t["name"] for shard in shards for t in shard)
        self.assertEqual(names, sorted(t["name"] for t in targets))
        grown = targets + [{"name": "fuzz_new_parser"}]
        for index in range(4):
            before = {t["name"] for t in shards[index]}
            after = {t["name"] for t in self.run_fuzz.select_targets(grown, (index, 4), None)}
            self.assertEqual(after - {"fuzz_new_parser"}, before)

    def test_budget_fits_the_wall_clock(self) -> None:
        # Given 52 targets, 4 jobs and 600 seconds, then the rounds fit in the
        # budget; and a budget too small for everyone still gives each target
        # the minimum rather than nothing.
        seconds = self.run_fuzz.seconds_per_target(600, 4, 52)
        self.assertLessEqual(seconds * -(-52 // 4), 600)
        self.assertGreaterEqual(seconds, self.run_fuzz.MINIMUM_SECONDS_PER_TARGET)
        self.assertEqual(self.run_fuzz.seconds_per_target(10, 1, 50),
                         self.run_fuzz.MINIMUM_SECONDS_PER_TARGET)
        self.assertEqual(self.run_fuzz.seconds_per_target(7200, 4, 13), 7200 * 0.95 // 4)

    def test_seeding_is_idempotent_and_content_named(self) -> None:
        # Given two seed files with equal content and one different, when seeded
        # twice, then the corpus holds two files named by content hash.
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "seeds").mkdir()
            (root / "seeds" / "a.lock").write_text("same")
            (root / "seeds" / "b.lock").write_text("same")
            (root / "seeds" / "c.lock").write_text("other")
            (root / "seeds" / "README.md").write_text("not a seed")
            target = {"seed_paths": ["seeds"], "seed_suffixes": [".lock"]}
            files = self.run_fuzz.seed_files(target, root, root / "generated")
            self.assertEqual(len(files), 3)
            self.assertEqual(self.run_fuzz.seed_corpus(files, root / "corpus"), 2)
            self.assertEqual(self.run_fuzz.seed_corpus(files, root / "corpus"), 0)

    def test_a_finding_fails_the_campaign_and_is_reported(self) -> None:
        # Given one clean and one crashing stub fuzzer, when a short campaign
        # runs, then it exits 1, the crash file is in the crashing target's
        # artifacts and the summary names it.
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            build = root / "build"
            build.mkdir()
            write_stub_fuzzer(build / "fuzz_clean", crash=False)
            write_stub_fuzzer(build / "fuzz_crashing", crash=True)
            (root / "seed.txt").write_text("x")
            (root / "tokens.dict").write_text('"x"\n')
            manifest = {
                "schema": 1,
                "defaults": {"max_len": 64, "timeout_seconds": 5, "rss_limit_mb": 512},
                "targets": [
                    {"name": name, "source": "unused.cpp", "libraries": [],
                     "seed_paths": [str(root / "seed.txt")], "seed_suffixes": [],
                     "dictionary": str(root / "tokens.dict")}
                    for name in ("fuzz_clean", "fuzz_crashing")],
            }
            manifest_path = root / "targets.json"
            manifest_path.write_text(json.dumps(manifest))
            summary_path = root / "summary.md"
            previous = os.environ.get("GITHUB_STEP_SUMMARY")
            os.environ["GITHUB_STEP_SUMMARY"] = str(summary_path)
            try:
                status = self.run_fuzz.main(["--build-dir", str(build), "--manifest",
                                             str(manifest_path), "--budget-seconds", "1",
                                             "--jobs", "2"])
            finally:
                if previous is None:
                    os.environ.pop("GITHUB_STEP_SUMMARY")
                else:
                    os.environ["GITHUB_STEP_SUMMARY"] = previous
            self.assertEqual(status, 1)
            self.assertTrue((build / "fuzz-artifacts" / "fuzz_crashing" / "crash-0123").is_file())
            self.assertEqual(self.run_fuzz.findings_in(build / "fuzz-artifacts" / "fuzz_clean"), [])
            summary = summary_path.read_text()
            self.assertIn("crash-0123", summary)
            self.assertIn("| `fuzz_clean` |", summary)

    def test_findings_from_earlier_runs_do_not_fail_a_new_run(self) -> None:
        # Given a crash file left by an earlier run in a target's artifacts
        # directory, when a clean campaign runs, then it exits 0 and says it
        # ignored the file: a fixed bug must not keep failing the campaign.
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            build = root / "build"
            build.mkdir()
            write_stub_fuzzer(build / "fuzz_clean", crash=False)
            stale = build / "fuzz-artifacts" / "fuzz_clean" / "crash-old"
            stale.parent.mkdir(parents=True)
            stale.write_text("old")
            os.utime(stale, (1, 1))
            (root / "seed.txt").write_text("x")
            (root / "tokens.dict").write_text('"x"\n')
            manifest_path = root / "targets.json"
            manifest_path.write_text(json.dumps({
                "schema": 1,
                "defaults": {"max_len": 64, "timeout_seconds": 5, "rss_limit_mb": 512},
                "targets": [{"name": "fuzz_clean", "source": "unused.cpp", "libraries": [],
                             "seed_paths": [str(root / "seed.txt")], "seed_suffixes": [],
                             "dictionary": str(root / "tokens.dict")}]}))
            self.assertEqual(
                self.run_fuzz.main(["--build-dir", str(build), "--manifest", str(manifest_path),
                                    "--budget-seconds", "1", "--jobs", "1"]), 0)
            self.assertEqual(self.run_fuzz.findings_in(stale.parent, 2.0), [])
            self.assertEqual(self.run_fuzz.earlier_findings(stale.parent, 2.0), ["crash-old"])

    def test_corpora_never_land_in_the_repository(self) -> None:
        # Given the default paths, then corpora and artifacts are under the
        # build directory: libFuzzer writes new inputs into its first corpus
        # directory, and a fixtures/ directory there would fill with them.
        with tempfile.TemporaryDirectory() as scratch:
            build = Path(scratch)
            status = self.run_fuzz.main(["--build-dir", str(build), "--targets", "no_such_target"])
            self.assertEqual(status, 1)
            self.assertFalse((REPOSITORY / "fuzz-corpus").exists())


if __name__ == "__main__":
    unittest.main()
