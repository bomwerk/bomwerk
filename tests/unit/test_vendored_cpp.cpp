// ctest unit test for the vendored C/C++ code heuristic
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "heuristics/vendored_cpp.hpp"
#include "output/spdx_license_ids.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::Scope;
using bomwerk::test::TempTree;
namespace vendored_cpp = bomwerk::heuristics::vendored_cpp;

namespace
{

// A valid 40-hex (SHA-1) object id for a synthesized HEAD.
const std::string kSha = "0123456789abcdef0123456789abcdef01234567";

std::string read_file(const fs::path& path)
{
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream contents;
  contents << stream.rdbuf();
  return contents.str();
}

/// Build the shared FileIndex the same way `run_scan` does (no directory
/// exclusions: a synthetic test tree has nothing worth skipping) and hand it
/// to the producer under test. Mirrors the shared-walk call shape
/// `scan_command.cpp` actually uses, not a test-only convenience path.
bomwerk::core::Result<std::vector<Component>> parse_tree(const TempTree& tree,
                                                         vendored_cpp::ParseLimits limits = {})
{
  const bomwerk::core::Result<bomwerk::core::FileIndex> file_index =
      bomwerk::core::build_file_index(tree.root(), {}, {});
  BOMWERK_TEST_CHECK(file_index.complete);
  return vendored_cpp::parse(file_index.value, tree.root(), limits);
}

}  // namespace

int main()
{
  // Given a vendored zlib copy whose header declares ZLIB_VERSION, when
  // parsed, then one Medium-confidence component is reported with the
  // extracted version and a generic purl: the literal "vendored zlib
  // detected" acceptance criterion.
  {
    TempTree tree;
    tree.write("third_party/zlib/zlib.h",
               "/* zlib.h -- interface of the 'zlib' compression library */\n"
               "#ifndef ZLIB_H\n"
               "#define ZLIB_H\n"
               "#define ZLIB_VERSION \"1.2.11\"\n"
               "#define ZLIB_VERNUM 0x12b0\n"
               "#endif\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].name == "zlib");
    BOMWERK_TEST_CHECK(result.value[0].version == "1.2.11");
    BOMWERK_TEST_CHECK(result.value[0].root == fs::path("third_party/zlib"));
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/zlib@1.2.11");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
  }

  // Given a vendored FreeRTOS kernel whose nested include/task.h declares
  // tskKERNEL_VERSION_NUMBER (upstream's own shape: a doc comment naming the
  // macro first, then the #define padded with spaces), when parsed, then one
  // Medium-confidence component carries the declared version verbatim.
  {
    TempTree tree;
    tree.write("third_party/freertos/include/task.h",
               "#ifndef INC_TASK_H\n"
               "#define INC_TASK_H\n"
               " * If tskKERNEL_VERSION_NUMBER ends with + it represents the version\n"
               "#define tskKERNEL_VERSION_NUMBER       \"V11.1.0\"\n"
               "#define tskKERNEL_VERSION_MAJOR        11\n"
               "#endif\n");
    tree.write("third_party/freertos/list.c", "/* FreeRTOS Kernel V11.1.0 */\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].name == "freertos");
    BOMWERK_TEST_CHECK(result.value[0].version == "V11.1.0");
    BOMWERK_TEST_CHECK(result.value[0].root == fs::path("third_party/freertos"));
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/freertos@V11.1.0");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
  }

  // Given an unrelated library that also ships a task.h but no
  // tskKERNEL_VERSION_NUMBER macro, when parsed, then the common basename
  // alone does not claim FreeRTOS: identity falls back to the folder name at
  // Low confidence with no version.
  {
    TempTree tree;
    tree.write("third_party/jobqueue/task.h",
               "#ifndef JOBQUEUE_TASK_H\n"
               "#define JOBQUEUE_TASK_H\n"
               "#define JOBQUEUE_TASK_VERSION \"2.0.0\"\n"
               "#endif\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].name == "jobqueue");
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/jobqueue");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
  }

  // Given a vendored folder with only an unrecognized LICENSE (no version
  // header, no .git), when parsed, then a Low-confidence component named
  // after the folder is reported: versionless, license left unset rather
  // than guessed.
  {
    TempTree tree;
    tree.write("third_party/some-obscure-lib/LICENSE",
               "Some Obscure License\n\nCopyright (c) 2024 Someone.\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].name == "some-obscure-lib");
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(result.value[0].license.empty());
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/some-obscure-lib");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
  }

  // Given a LICENSE whose first line unambiguously names a known license,
  // when parsed, then Component::license carries the recognized SPDX id.
  {
    TempTree tree;
    tree.write("vendor/tinylib/LICENSE", "MIT License\n\nCopyright (c) 2024 Someone.\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].license == "MIT");
  }

  // Given a nested trigger name inside an already-claimed vendor root
  // (third_party/boost/libs/... : "libs" is itself a trigger word), when
  // parsed, then exactly one component is reported, rooted at the OUTER
  // trigger's subfolder rather than exploding into one per nested trigger.
  {
    TempTree tree;
    tree.write("third_party/boost/libs/algorithm/include/boost/algorithm/string.hpp", "// stub\n");
    tree.write("third_party/boost/LICENSE", "Boost Software License\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].root == fs::path("third_party/boost"));
    BOMWERK_TEST_CHECK(result.value[0].name == "boost");
  }

  // Given two distinct libraries vendored under a trigger dir whose immediate
  // subfolder is ITSELF a trigger word (third_party/libs/zlib,
  // third_party/libs/openssl: "libs" is generic, not a library name), when
  // parsed, then each gets its own component rather than collapsing into one
  // "third_party/libs" component that silently drops one library's identity.
  {
    TempTree tree;
    tree.write("third_party/libs/zlib/zlib.h", "#define ZLIB_VERSION \"1.2.11\"\n");
    tree.write("third_party/libs/openssl/opensslv.h",
               "#define OPENSSL_VERSION_TEXT \"OpenSSL 3.2.0\"\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].root == fs::path("third_party/libs/openssl"));
    BOMWERK_TEST_CHECK(result.value[0].name == "openssl");
    BOMWERK_TEST_CHECK(result.value[1].root == fs::path("third_party/libs/zlib"));
    BOMWERK_TEST_CHECK(result.value[1].name == "zlib");
  }

  // Given ecosystem-native Go vendor and license trees whose first child is
  // a DNS namespace, when parsed, then the namespace containers produce no
  // generic host placeholders; go.sum is the authoritative producer for
  // those dependencies.
  {
    TempTree tree;
    tree.write("vendor/github.com/acme/widget/widget.go", "package widget\n");
    tree.write("LICENSES/vendor/k8s.io/apimachinery/LICENSE", "Apache License\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given a non-`vendor` trigger word (`thirdparty`) whose immediate
  // subfolder is a DNS namespace container, when parsed, then no generic
  // host placeholder is fabricated either: the skip is not tied to the
  // `vendor` spelling.
  {
    TempTree tree;
    tree.write("thirdparty/github.com/acme/widget/widget.go", "package widget\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given the `libs` trigger word paired with a DNS namespace container,
  // when parsed, then the same skip applies.
  {
    TempTree tree;
    tree.write("libs/k8s.io/apimachinery/foo.go", "package apimachinery\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given the Kubernetes false-positive shape with a trigger below a test
  // directory, when parsed, then the testdata folder is not reported as a
  // production dependency.
  {
    TempTree tree;
    tree.write("test/e2e/storage/external/testdata/fixture.go", "package testdata\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given the React false-positive shape with a trigger below __tests__, when
  // parsed, then compiled Jest fixture directories produce no components.
  {
    TempTree tree;
    tree.write(
        "packages/react-devtools-shared/src/hooks/__tests__/__source__/__compiled__/external/"
        "fb-sources-extended/index.js",
        "export default {};\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given a legitimate external tree outside test/fixture ancestry, when
  // parsed, then the existing folder-name fallback still reports it.
  {
    TempTree tree;
    tree.write("components/external/libfoo/src/libfoo.cpp", "int libfoo() { return 0; }\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].root == fs::path("components/external/libfoo"));
    BOMWERK_TEST_CHECK(result.value[0].name == "libfoo");
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Required);
  }

  // Given a versioned library folder containing dots below vendor, when
  // parsed, then a numeric final segment prevents it from being mistaken for
  // a DNS namespace container.
  {
    TempTree tree;
    tree.write("vendor/zlib-1.2.13/zlib.h", "#define ZLIB_VERSION \"1.2.13\"\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].root == fs::path("vendor/zlib-1.2.13"));
    BOMWERK_TEST_CHECK(result.value[0].name == "zlib");
  }

  // Given a header whose first `#define <macro>...` occurrence is only a
  // prefix of the searched-for macro name (e.g. "ZLIB_VERSION_H" before the
  // real "ZLIB_VERSION"), when parsed, then the real, later occurrence is
  // still found rather than the search giving up at the first clash.
  {
    TempTree tree;
    tree.write("third_party/zlib/zlib.h",
               "#define ZLIB_VERSION_H\n"
               "#define ZLIB_VERSION \"1.2.13\"\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version == "1.2.13");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
  }

  // Given a file sitting directly in a trigger directory with no subfolder,
  // when parsed, then no component is reported for it: there is no
  // "library" to name.
  {
    TempTree tree;
    tree.write("third_party/README.md", "notes about vendoring in this repo\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given a vendored folder with an intact ".git" whose HEAD and origin both
  // resolve, when parsed, then the component's purl and version reflect the
  // resolved commit: the strongest signal this heuristic can produce, via
  // the shared core::git_dir/git_config/git_url primitives.
  {
    TempTree tree;
    tree.write("third_party/mbedtls/.git/HEAD", kSha + "\n");
    tree.write("third_party/mbedtls/.git/config",
               "[remote \"origin\"]\n\turl = https://github.com/Mbed-TLS/mbedtls.git\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version == kSha);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/mbed-tls/mbedtls@" + kSha);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
    // The leftover .git's remote owner doubles as NTIA/CRA supplier
    // evidence, case-preserved exactly as the manifest wrote it.
    BOMWERK_TEST_CHECK(result.value[0].supplier == "Mbed-TLS");
  }

  // Given a vendored folder whose ".git" HEAD resolves but whose config names
  // no origin remote, when parsed, then the purl falls back to a generic one
  // pinned at the commit rather than being left empty: a fork we cannot
  // attribute to a forge is still a precisely identified artifact.
  {
    TempTree tree;
    tree.write("third_party/mystery/.git/HEAD", kSha + "\n");
    tree.write("third_party/mystery/.git/config", "[core]\n\tbare = false\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version == kSha);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/mystery@" + kSha);
    // No origin remote at all: no supplier to attribute.
    BOMWERK_TEST_CHECK(result.value[0].supplier.empty());
  }

  // Given a vendored folder whose ".git" config names an origin on a host we
  // map to no purl type, when parsed, then the generic fallback pins the exact
  // remote in a vcs_url qualifier: two different forks of the same-named
  // library must never collide on one identity.
  {
    TempTree tree;
    tree.write("third_party/mbedtls/.git/HEAD", kSha + "\n");
    tree.write("third_party/mbedtls/.git/config",
               "[remote \"origin\"]\n\turl = https://git.internal.example/vendor/mbedtls.git\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl ==
                       "pkg:generic/mbedtls@" + kSha +
                           "?vcs_url=git%2Bhttps%3A%2F%2Fgit.internal.example%2Fvendor%2Fmbedtls."
                           "git");
    // An unmapped host still has a real owner path segment worth
    // recording as supplier evidence, even without a first-class purl type.
    BOMWERK_TEST_CHECK(result.value[0].supplier == "vendor");
  }

  // Given a tree with no third_party/thirdparty/vendor/external/deps/libs
  // folder anywhere, when parsed, then the result is simply empty: not a
  // warning, not an error.
  {
    TempTree tree;
    tree.write("src/main.cpp", "int main() { return 0; }\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given a version macro that sits past a caller-supplied byte bound, when
  // parsed, then the bounded read simply misses it: Low confidence, empty
  // version: never a warning: a bounded miss is not a degraded run, it is
  // this heuristic's normal "nothing recognized" outcome.
  {
    TempTree tree;
    const std::string padding(2000, '\n');
    tree.write("third_party/zlib/zlib.h", padding + "#define ZLIB_VERSION \"1.2.11\"\n");
    vendored_cpp::ParseLimits tiny_limits;
    tiny_limits.max_header_bytes = 100;
    const auto result = parse_tree(tree, tiny_limits);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given every hostile fixture, when parsed, then the heuristic never
  // crashes and never returns the exit-2 (incomplete) state for merely
  // adversarial content: malformed input degrades to "no match," never a
  // crash (rule 1). Each fixture keeps its own name (zlib.h, LICENSE, …) so
  // it lands under whichever sniffer it targets.
  {
    const fs::path hostile_dir = fs::path(BOMWERK_FIXTURES_DIR) / "vendored_cpp" / "hostile";
    for (const auto& entry : fs::directory_iterator(hostile_dir))
    {
      if (!entry.is_regular_file() || entry.path().extension() == ".md")
      {
        continue;
      }
      TempTree tree;
      tree.write(fs::path("third_party/hostile-case") / entry.path().filename(),
                 read_file(entry.path()));
      const auto result = parse_tree(tree);
      BOMWERK_TEST_CHECK(result.complete);
    }
  }

  // Given every SPDX id the LICENSE recognizer can produce, when checked
  // against the canonical SPDX table, then each one round-trips unchanged :
  // the two tables are deliberately separate (module dependency law), so
  // nothing else catches a future spelling drift between them.
  {
    for (std::string_view spdx_id : vendored_cpp::recognized_license_spdx_ids())
    {
      const auto canonical = bomwerk::output::canonical_spdx_license_id(spdx_id);
      BOMWERK_TEST_CHECK(canonical.has_value());
      BOMWERK_TEST_CHECK(*canonical == spdx_id);
    }
  }

  std::puts("test_vendored_cpp: OK");
  return 0;
}
