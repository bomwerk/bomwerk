// ctest unit test for the Python lockfile producer (framework-free).
#include <cstdio>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "parsers/lockfiles/python.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::Result;
using bomwerk::core::Scope;
using bomwerk::test::TempTree;

namespace python_parser = bomwerk::parsers::lockfiles::python;

int main()
{
  // Given a uv.lock with a virtual root entry and two registry packages, when
  // parsed, then the root project is skipped and each dependency is a High
  // confidence pkg:pypi component with the resolver's exact version.
  {
    TempTree tree;
    tree.write("uv.lock",
               "version = 1\n"
               "\n"
               "[[package]]\n"
               "name = \"demo-app\"\n"
               "version = \"0.1.0\"\n"
               "source = { virtual = \".\" }\n"
               "\n"
               "[[package]]\n"
               "name = \"flask\"\n"
               "version = \"3.0.3\"\n"
               "source = { registry = \"https://pypi.org/simple\" }\n"
               "\n"
               "[[package]]\n"
               "name = \"requests\"\n"
               "version = \"2.32.3\"\n"
               "source = { registry = \"https://pypi.org/simple\" }\n");

    const Result<std::vector<Component>> result = python_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pypi/flask@3.0.3");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:pypi/requests@2.32.3");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
    // uv.lock carries no dev marking, so scope is never guessed.
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Required);
  }

  // Given a poetry.lock with a main-group and a dev-group package, when
  // parsed, then only the dev-group package carries Scope::Excluded: the
  // lockfile said so, nothing was guessed.
  {
    TempTree tree;
    tree.write("poetry.lock",
               "[[package]]\n"
               "name = \"flask\"\n"
               "version = \"3.0.3\"\n"
               "groups = [\"main\"]\n"
               "\n"
               "[[package]]\n"
               "name = \"pytest\"\n"
               "version = \"8.2.0\"\n"
               "groups = [\"dev\"]\n");

    const Result<std::vector<Component>> result = python_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pypi/flask@3.0.3");
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Required);
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:pypi/pytest@8.2.0");
    BOMWERK_TEST_CHECK(result.value[1].scope == Scope::Excluded);
  }

  // Given a poetry.lock in the legacy pre-1.5 shape (`category`, no groups),
  // when parsed, then a non-main category still marks the package Excluded.
  {
    TempTree tree;
    tree.write("poetry.lock",
               "[[package]]\n"
               "name = \"black\"\n"
               "version = \"24.4.0\"\n"
               "category = \"dev\"\n");

    const Result<std::vector<Component>> result = python_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Excluded);
  }

  // Given a requirements.txt mixing an exact pin, a range, a bare name and
  // unsupported lines, when parsed, then the pin is High with the version in
  // its purl, the rest are Low with version-less purls and the constraint kept
  // as evidence, and the unsupported lines produce ONE counted warning.
  {
    TempTree tree;
    tree.write("requirements.txt",
               "# comment line\n"
               "Flask==3.0.3\n"
               "requests>=2.31,<3  # inline comment\n"
               "click\n"
               "-r other-requirements.txt\n"
               "-e ./local-package\n"
               "https://example.com/wheel.whl\n");

    const Result<std::vector<Component>> result = python_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pypi/click");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:pypi/flask@3.0.3");
    BOMWERK_TEST_CHECK(result.value[2].purl == "pkg:pypi/requests");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[1]) == Confidence::High);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[2]) == Confidence::Low);
    BOMWERK_TEST_CHECK(result.value[2].evidence[0].detail.find("constraint=>=2.31,<3") !=
                       std::string::npos);
    // PEP 503: "Flask" declares under its normalized name, original recorded.
    BOMWERK_TEST_CHECK(result.value[1].name == "flask");
    BOMWERK_TEST_CHECK(result.value[1].evidence[0].detail.find("declared=Flask") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("3 unsupported requirement line(s)") !=
                       std::string::npos);
  }

  // Given a requirements.txt produced by `pip-compile --generate-hashes` /
  // `uv pip compile --generate-hashes`, where every pinned line ends with a
  // '\' line-continuation marker followed by indented --hash=... lines, when
  // parsed, then the trailing backslash is stripped from the version instead
  // of leaking into the purl, and the --hash lines are counted as unsupported.
  {
    TempTree tree;
    tree.write(
        "requirements.txt",
        "alabaster==1.0.0 \\\n"
        "    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
        "\\\n"
        "    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n");

    const Result<std::vector<Component>> result = python_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pypi/alabaster@1.0.0");
    BOMWERK_TEST_CHECK(result.value[0].version == "1.0.0");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("2 unsupported requirement line(s)") !=
                       std::string::npos);
  }

  // Given both supported requirements naming variants, when parsed, then
  // packages from each file are emitted in deterministic purl order and the
  // same normalized package found in both files merges with both evidence
  // paths retained.
  {
    TempTree tree;
    tree.write("requirements-docs.txt",
               "Sphinx==7.3.7\n"
               "Typing_Extensions==4.12.0\n");
    tree.write("requirements_proselint.txt",
               "proselint==0.16.0\n"
               "typing-extensions==4.12.0\n");

    const Result<std::vector<Component>> result = python_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pypi/proselint@0.16.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:pypi/sphinx@7.3.7");
    BOMWERK_TEST_CHECK(result.value[2].purl == "pkg:pypi/typing-extensions@4.12.0");
    BOMWERK_TEST_CHECK(result.value[2].evidence.size() == 2);
    BOMWERK_TEST_CHECK(result.value[2].evidence[0].detail.find("requirements-docs.txt") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(result.value[2].evidence[1].detail.find("requirements_proselint.txt") !=
                       std::string::npos);
  }

  // Given extras and an environment marker, when parsed, then both are
  // stripped from the identity and preserved in the evidence detail.
  {
    TempTree tree;
    tree.write("requirements.txt", "uvicorn[standard]==0.29.0 ; python_version >= \"3.9\"\n");

    const Result<std::vector<Component>> result = python_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pypi/uvicorn@0.29.0");
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("extras=standard") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("marker=python_version") !=
                       std::string::npos);
  }

  // Given a wildcard pin (==3.*) and a multi-clause pin (==3.0.3,>=3), when
  // parsed, then neither counts as exact: both stay Low and version-less
  // (a wildcard is a constraint, not a resolved version).
  {
    TempTree tree;
    tree.write("requirements.txt",
               "flask==3.*\n"
               "requests==2.32.3,>=2\n");

    const Result<std::vector<Component>> result = python_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pypi/flask");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:pypi/requests");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[1]) == Confidence::Low);
  }

  // Given the SAME package pinned in requirements.txt and resolved in uv.lock
  // under a different spelling (PEP 503), when parsed together, then both
  // findings merge into ONE component with layered evidence: the cross-file
  // seam the design promises.
  {
    TempTree tree;
    tree.write("requirements.txt", "Typing_Extensions==4.12.0\n");
    tree.write("uv.lock",
               "[[package]]\n"
               "name = \"typing-extensions\"\n"
               "version = \"4.12.0\"\n"
               "source = { registry = \"https://pypi.org/simple\" }\n");

    const Result<std::vector<Component>> result = python_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pypi/typing-extensions@4.12.0");
    BOMWERK_TEST_CHECK(result.value[0].evidence.size() == 2);
  }

  // Given hostile input (invalid TOML, oversized TOML, oversized
  // requirements), when parsed, then each degrades to warnings and partial
  // output without a crash or a throw (rule 1).
  {
    TempTree bad_toml_tree;
    bad_toml_tree.write("uv.lock", "this = is [ not ]] toml\n===\n");
    const Result<std::vector<Component>> bad_toml_result =
        python_parser::parse(bad_toml_tree.root());
    BOMWERK_TEST_CHECK(bad_toml_result.complete);
    BOMWERK_TEST_CHECK(bad_toml_result.value.empty());
    BOMWERK_TEST_CHECK(bad_toml_result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(bad_toml_result.warnings[0].message.find("not valid TOML") !=
                       std::string::npos);

    TempTree oversized_toml_tree;
    oversized_toml_tree.write("poetry.lock",
                              "[[package]]\nname = \"flask\"\nversion = \"3.0.3\"\n");
    python_parser::ParseOptions tiny_options;
    tiny_options.max_file_bytes = 10;
    const Result<std::vector<Component>> oversized_toml_result =
        python_parser::parse(oversized_toml_tree.root(), tiny_options);
    BOMWERK_TEST_CHECK(oversized_toml_result.value.empty());
    BOMWERK_TEST_CHECK(oversized_toml_result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(oversized_toml_result.warnings[0].message.find(
                           "exceeds size limit, skipped") != std::string::npos);

    TempTree oversized_requirements_tree;
    const std::string first_line = "flask==3.0.3\n";
    oversized_requirements_tree.write("requirements.txt", first_line + "requests==2.32.3\n");
    python_parser::ParseOptions prefix_options;
    prefix_options.max_file_bytes = first_line.size() + 3;  // cuts the second line mid-way
    const Result<std::vector<Component>> prefix_result =
        python_parser::parse(oversized_requirements_tree.root(), prefix_options);
    BOMWERK_TEST_CHECK(prefix_result.value.size() == 1);
    BOMWERK_TEST_CHECK(prefix_result.value[0].purl == "pkg:pypi/flask@3.0.3");
    BOMWERK_TEST_CHECK(prefix_result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(prefix_result.warnings[0].message.find("parsing first part only") !=
                       std::string::npos);
  }

  // Given more packages than max_total_packages across files, when parsed,
  // then the shared budget stops the parse early with a warning.
  {
    TempTree tree;
    tree.write("requirements.txt",
               "one==1.0.0\n"
               "two==1.0.0\n"
               "three==1.0.0\n");
    python_parser::ParseOptions options;
    options.max_total_packages = 2;
    const Result<std::vector<Component>> result = python_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pypi/one@1.0.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:pypi/two@1.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("python: package limit 2 reached") !=
                       std::string::npos);

    options.max_total_packages = 3;
    const Result<std::vector<Component>> exact_limit_result =
        python_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(exact_limit_result.complete);
    BOMWERK_TEST_CHECK(exact_limit_result.value.size() == 3);
    BOMWERK_TEST_CHECK(exact_limit_result.warnings.empty());
  }

  // Given requirements.txt exactly filling the budget plus a poetry.lock with
  // another valid entry, when parsed, then that later entry proves exhaustion:
  // the deterministic prefix survives, the result is incomplete, exactly one
  // warning is emitted, and the over-budget package does not leak into the
  // result.
  {
    TempTree tree;
    tree.write("requirements.txt",
               "one==1.0.0\n"
               "two==1.0.0\n");
    tree.write("vendor/other/poetry.lock", "[[package]]\nname = \"four\"\nversion = \"1.0.0\"\n");

    python_parser::ParseOptions options;
    options.max_total_packages = 2;
    const Result<std::vector<Component>> result = python_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    for (const Component& component : result.value)
    {
      BOMWERK_TEST_CHECK(component.name != "four");
    }
  }

  // Given more requirements.txt files than a caller-tightened
  // max_scanned_files allows, when parsed, then a warning reports the cap,
  // the run stays complete, and the scanned subset is the path-sorted
  // (deterministic) one.
  {
    TempTree tree;
    tree.write("a/requirements.txt", "aaa==1.0.0\n");
    tree.write("z/requirements.txt", "zzz==1.0.0\n");
    python_parser::ParseOptions options;
    options.max_scanned_files = 1;
    const auto result = python_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pypi/aaa@1.0.0");
  }

  std::puts("test_python: OK");
  return 0;
}
