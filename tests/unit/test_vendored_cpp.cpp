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

  // Given uthash's own header shape, a BARE dotted macro
  // (`#define UTHASH_VERSION 2.4.0`, no quotes, so the quoted-string rows can
  // never read it), when parsed, then the version is read at Medium and the
  // purl carries it. This is nightmare's uthash, whose answer key says
  // `pkg:generic/uthash@2.4.0`. Read at upstream's own path (`src/uthash.h`)
  // too, since a header is matched by basename.
  {
    for (const char* header_path :
         {"third_party/uthash/uthash.h", "third_party/uthash/src/uthash.h"})
    {
      TempTree tree;
      tree.write(header_path,
                 "#ifndef UTHASH_H\n"
                 "#define UTHASH_H\n"
                 "\n"
                 "#define UTHASH_VERSION 2.4.0\n"
                 "\n"
                 "#include <string.h>\n"
                 "#endif\n");
      const auto result = parse_tree(tree);
      BOMWERK_TEST_CHECK(result.complete);
      BOMWERK_TEST_CHECK(result.value.size() == 1);
      BOMWERK_TEST_CHECK(result.value[0].name == "uthash");
      BOMWERK_TEST_CHECK(result.value[0].version == "2.4.0");
      BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/uthash@2.4.0");
      BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
      // The evidence quotes the header as written: no quotes appear around a
      // value the file did not quote.
      bool saw_unquoted_evidence = false;
      for (const auto& evidence : result.value[0].evidence)
      {
        if (evidence.detail.find("#define UTHASH_VERSION 2.4.0") != std::string::npos)
        {
          saw_unquoted_evidence = true;
        }
        BOMWERK_TEST_CHECK(evidence.detail.find("\"2.4.0\"") == std::string::npos);
      }
      BOMWERK_TEST_CHECK(saw_unquoted_evidence);
    }
  }

  // Given a bare macro value that is not a clean dotted version, when parsed,
  // then no version is asserted and identity falls back to the folder name at
  // Low. Each shape is a way a wrong or invented version could reach a purl:
  // a bare integer (an API revision, which is why stb's `STBI_VERSION 1` stays
  // unversioned), a suffix glued to the number, a trailing dot, a doubled dot,
  // a line continuation, and a value too long to be a version.
  {
    const std::string too_long = std::string(40, '1') + "." + std::string(40, '2');
    const std::vector<std::string> rejected_values = {
        "2", "2.", ".2.4", "2..4", "2.4.0abc", "2.4.0-dev", "2.4.0\\", "v2.4.0", "2.x.0", too_long};
    for (const std::string& value : rejected_values)
    {
      TempTree tree;
      tree.write("third_party/uthash/uthash.h", "#define UTHASH_VERSION " + value + "\n");
      const auto result = parse_tree(tree);
      BOMWERK_TEST_CHECK(result.complete);
      BOMWERK_TEST_CHECK(result.value.size() == 1);
      BOMWERK_TEST_CHECK(result.value[0].version.empty());
      BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/uthash");
      BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
    }
  }

  // Given a bare dotted value followed by a comment or CRLF, when parsed, then
  // the version is still read: both are how real headers end the line.
  {
    for (const char* line :
         {"#define UTHASH_VERSION 2.4.0 /* the release */\n", "#define UTHASH_VERSION 2.4.0\r\n",
          "#define UTHASH_VERSION\t2.4.0\t// release\n"})
    {
      TempTree tree;
      tree.write("third_party/uthash/uthash.h", line);
      const auto result = parse_tree(tree);
      BOMWERK_TEST_CHECK(result.value.size() == 1);
      BOMWERK_TEST_CHECK(result.value[0].version == "2.4.0");
    }
  }

  // Given `UTHASH_VERSION` mentioned earlier in the file (a comment, a longer
  // macro name) before the real `#define`, when parsed, then the real one is
  // still found: an unrelated earlier occurrence must never hide it, the same
  // rule the quoted form already follows.
  {
    TempTree tree;
    tree.write("third_party/uthash/uthash.h",
               "/* UTHASH_VERSION is defined below */\n"
               "#define UTHASH_VERSION_STRING \"not this one\"\n"
               "#define UTHASH_VERSION 2.4.0\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version == "2.4.0");
  }

  // Given a QUOTED value for a bare-form library, when parsed, then it is not
  // read: each table reads its macro in one form only, so a quoted `"2.4.0"`
  // cannot slip through the dotted-number rule and vice versa.
  {
    TempTree tree;
    tree.write("third_party/uthash/uthash.h", "#define UTHASH_VERSION \"2.4.0\"\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
  }

  // Given stb's header, `#define STBI_VERSION 1`, when parsed, then it stays
  // unversioned. stb is not in either table, and this pins that it must not
  // become one: `1` is an API revision, not a release, and upstream publishes
  // no tags, so there is no version to find. The answer key says the same.
  {
    TempTree tree;
    tree.write("third_party/stb/stb_image.h", "#define STBI_VERSION 1\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/stb");
  }

  // Given cJSON's header, which splits its release across three integer macros,
  // when parsed, then the version is assembled as MAJOR.MINOR.PATCH, the name is
  // the canonical `cjson` rather than the folder's `cjson-prebuilt`, and the
  // evidence quotes all three lines as written. This is nightmare's
  // `third_party/cjson-prebuilt`, whose answer key says `pkg:generic/cjson@1.7.15`.
  // Line order is irrelevant: each macro is found over the whole read.
  {
    const std::vector<std::string> headers = {
        "#ifndef cJSON__h\n"
        "#define cJSON__h\n"
        "/* project version */\n"
        "#define CJSON_VERSION_MAJOR 1\n"
        "#define CJSON_VERSION_MINOR 7\n"
        "#define CJSON_VERSION_PATCH 15\n"
        "#endif\n",
        "#define CJSON_VERSION_PATCH 15\r\n"
        "#define CJSON_VERSION_MAJOR\t1 /* major */\r\n"
        "#define CJSON_VERSION_MINOR 7 // minor\r\n"};
    for (const std::string& header : headers)
    {
      TempTree tree;
      tree.write("third_party/cjson-prebuilt/include/cJSON.h", header);
      const auto result = parse_tree(tree);
      BOMWERK_TEST_CHECK(result.complete);
      BOMWERK_TEST_CHECK(result.value.size() == 1);
      BOMWERK_TEST_CHECK(result.value[0].name == "cjson");
      BOMWERK_TEST_CHECK(result.value[0].version == "1.7.15");
      BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/cjson@1.7.15");
      BOMWERK_TEST_CHECK(result.value[0].root == fs::path("third_party/cjson-prebuilt"));
      BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
      bool saw_all_three_lines = false;
      for (const auto& evidence : result.value[0].evidence)
      {
        if (evidence.detail.find("#define CJSON_VERSION_MAJOR 1; #define CJSON_VERSION_MINOR 7; "
                                 "#define CJSON_VERSION_PATCH 15") != std::string::npos)
        {
          saw_all_three_lines = true;
        }
      }
      BOMWERK_TEST_CHECK(saw_all_three_lines);
    }
  }

  // Given a cJSON header whose split version is malformed in any one part, when
  // parsed, then NO version is asserted (never a partial `1.7`) and identity
  // falls back to the folder name at Low. Each shape is a way a wrong version
  // could reach a purl: a missing part, a quoted part, a non-integer part, a
  // negative or suffixed or octal-looking part, a part only mentioned in a
  // comment, a longer macro whose name merely starts with the part's name, a
  // duplicated part (two definitions, so either would be a guess), a value
  // ending in a line continuation, and a part too long to be a release number.
  {
    const std::string major = "#define CJSON_VERSION_MAJOR 1\n";
    const std::string minor = "#define CJSON_VERSION_MINOR 7\n";
    const std::string patch = "#define CJSON_VERSION_PATCH 15\n";
    const std::vector<std::string> rejected_headers = {
        major + minor, major + minor + "#define CJSON_VERSION_PATCH \"15\"\n",
        major + "#define CJSON_VERSION_MINOR 7a\n" + patch,
        major + "#define CJSON_VERSION_MINOR 7.0\n" + patch,
        major + minor + "#define CJSON_VERSION_PATCH -1\n",
        major + minor + "#define CJSON_VERSION_PATCH 15u\n",
        major + minor + "#define CJSON_VERSION_PATCH 015\n",
        major + minor + "#define CJSON_VERSION_PATCH\n",
        major + minor + "/* CJSON_VERSION_PATCH 15 */\n",
        major + minor + "#define CJSON_VERSION_PATCHLEVEL 15\n",
        major + minor + patch + "#define CJSON_VERSION_PATCH 16\n", major + minor + patch + patch,
        major + minor + "#define CJSON_VERSION_PATCH 15\\\n",
        major + minor + "#define CJSON_VERSION_PATCH 1234567890\n",
        // A commented-out definition is not a definition: alone it supplies
        // nothing, and beside a real one it does not make the part ambiguous.
        major + minor + "// #define CJSON_VERSION_PATCH 15\n",
        major + minor + "/* #define CJSON_VERSION_PATCH 15 */\n",
        // Two definitions in an #if/#else pair: either would be a guess.
        major + minor +
            "#if defined(OLD)\n#define CJSON_VERSION_PATCH 15\n"
            "#else\n#define CJSON_VERSION_PATCH 16\n#endif\n"};
    for (const std::string& header : rejected_headers)
    {
      TempTree tree;
      tree.write("third_party/cjson-prebuilt/include/cJSON.h", header);
      const auto result = parse_tree(tree);
      BOMWERK_TEST_CHECK(result.complete);
      BOMWERK_TEST_CHECK(result.value.size() == 1);
      BOMWERK_TEST_CHECK(result.value[0].version.empty());
      BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/cjson-prebuilt");
      BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
    }
  }

  // Given the header-size cap cuts cJSON.h in the middle of its PATCH line, when
  // parsed, then no version is asserted: the cut line's `1` must not be read as
  // the whole `15`. The bounded read drops a truncated file's last line.
  {
    const std::string header =
        "#define CJSON_VERSION_MAJOR 1\n"
        "#define CJSON_VERSION_MINOR 7\n"
        "#define CJSON_VERSION_PATCH 15\n";
    vendored_cpp::ParseLimits limits;
    limits.max_header_bytes = header.size() - 2;  // ends right after "PATCH 1"
    TempTree tree;
    tree.write("third_party/cjson-prebuilt/include/cJSON.h", header);
    const auto result = parse_tree(tree, limits);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
  }

  // Given a commented-out duplicate beside the real PATCH definition, when
  // parsed, then the real one is still read: only a `#define` that starts its
  // line counts, so a stale commented copy cannot hide the version.
  {
    TempTree tree;
    tree.write("third_party/cjson-prebuilt/include/cJSON.h",
               "#define CJSON_VERSION_MAJOR 1\n"
               "#define CJSON_VERSION_MINOR 7\n"
               "/* #define CJSON_VERSION_PATCH 14 */\n"
               "  #define CJSON_VERSION_PATCH 15\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version == "1.7.15");
  }

  // Given the folder-name guard, when the header sits in differently spelled
  // folders, then folders that carry the library name once case and punctuation
  // are ignored keep the version, and a folder named for something else does
  // not. The header filename match is exact, so a lowercase `cjson.h` is not
  // read: pinned so a loosening is a decision, not an accident.
  {
    for (const char* folder : {"third_party/cJSON", "third_party/cjson-1.7.15", "vendor/c_json"})
    {
      TempTree tree;
      tree.write(std::string(folder) + "/cJSON.h",
                 "#define CJSON_VERSION_MAJOR 1\n#define CJSON_VERSION_MINOR 7\n"
                 "#define CJSON_VERSION_PATCH 15\n");
      const auto result = parse_tree(tree);
      BOMWERK_TEST_CHECK(result.value.size() == 1);
      BOMWERK_TEST_CHECK(result.value[0].version == "1.7.15");
    }
    TempTree lowercase;
    lowercase.write("third_party/cjson/cjson.h",
                    "#define CJSON_VERSION_MAJOR 1\n#define CJSON_VERSION_MINOR 7\n"
                    "#define CJSON_VERSION_PATCH 15\n");
    const auto lowercase_result = parse_tree(lowercase);
    BOMWERK_TEST_CHECK(lowercase_result.value.size() == 1);
    BOMWERK_TEST_CHECK(lowercase_result.value[0].version.empty());
  }

  // Given the read cap cutting a zlib.h and a uthash.h mid-version, when parsed,
  // then no half-read version is asserted for either: the truncation rule covers
  // every row, not just the split one.
  {
    const std::string zlib_header = "/* pad */\n#define ZLIB_VERSION \"1.2.11\"\n";
    const std::string uthash_header = "/* pad */\n#define UTHASH_VERSION 2.4.0\n";
    vendored_cpp::ParseLimits zlib_limits;
    zlib_limits.max_header_bytes = zlib_header.size() - 4;  // inside the quoted value
    vendored_cpp::ParseLimits uthash_limits;
    uthash_limits.max_header_bytes = uthash_header.size() - 2;  // after "2.4." and one digit short
    TempTree zlib_tree;
    zlib_tree.write("third_party/zlib/zlib.h", zlib_header);
    const auto zlib_result = parse_tree(zlib_tree, zlib_limits);
    BOMWERK_TEST_CHECK(zlib_result.value.size() == 1);
    BOMWERK_TEST_CHECK(zlib_result.value[0].version.empty());
    TempTree uthash_tree;
    uthash_tree.write("third_party/uthash/uthash.h", uthash_header);
    const auto uthash_result = parse_tree(uthash_tree, uthash_limits);
    BOMWERK_TEST_CHECK(uthash_result.value.size() == 1);
    BOMWERK_TEST_CHECK(uthash_result.value[0].version.empty());
  }

  // Given libsodium's header, `SODIUM_LIBRARY_VERSION_MAJOR 10` and `_MINOR 3`,
  // when parsed, then it stays unversioned. Those macros are the ABI version,
  // not the release (1.0.18 ships ABI 10.3), so libsodium must never become a
  // split-version row. Pinned so a "generic MAJOR/MINOR reader" cannot creep in.
  {
    TempTree tree;
    tree.write("third_party/libsodium/src/libsodium/include/sodium/version.h",
               "#define SODIUM_LIBRARY_VERSION_MAJOR 10\n"
               "#define SODIUM_LIBRARY_VERSION_MINOR 3\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/libsodium");
  }

  // Given another library that bundles a uthash.h or a cJSON.h of its own (godot's
  // `thirdparty/libktx/lib/uthash.h` is the real case), when parsed, then the
  // directory keeps its own name: a bare or split version macro identifies the
  // header, and only names the whole directory when the folder is that library.
  // Before this check libktx was reported as `uthash@1.9.1` and disappeared.
  {
    TempTree tree;
    tree.write("thirdparty/libktx/lib/uthash.h", "#define UTHASH_VERSION 1.9.1\n");
    tree.write("thirdparty/libktx/lib/texture.c", "int ktx;\n");
    tree.write("third_party/jsonkit/cJSON.h",
               "#define CJSON_VERSION_MAJOR 1\n"
               "#define CJSON_VERSION_MINOR 7\n"
               "#define CJSON_VERSION_PATCH 15\n");
    const auto result = parse_tree(tree);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    for (const Component& component : result.value)
    {
      BOMWERK_TEST_CHECK(component.version.empty());
      BOMWERK_TEST_CHECK(component.purl == "pkg:generic/jsonkit" ||
                         component.purl == "pkg:generic/libktx");
      BOMWERK_TEST_CHECK(highest_confidence(component) == Confidence::Low);
    }
  }

  // Given a version macro holding an empty string (found by fuzzing, T40),
  // when matched in memory, then it is no match, and a later real definition
  // of the same macro still wins.
  {
    namespace vendored = bomwerk::heuristics::vendored_cpp;
    BOMWERK_TEST_CHECK(
        !vendored::match_version_header("zlib", "zlib/zlib.h", "#define ZLIB_VERSION \"\"\n")
             .has_value());
    const auto later = vendored::match_version_header(
        "zlib", "zlib/zlib.h", "#define ZLIB_VERSION \"\"\n#define ZLIB_VERSION \"1.3.1\"\n");
    BOMWERK_TEST_CHECK(later.has_value());
    BOMWERK_TEST_CHECK(later->version == "1.3.1");
  }

  std::puts("test_vendored_cpp: OK");
  return 0;
}
