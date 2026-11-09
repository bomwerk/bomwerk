// ctest unit test for every producer's in-memory entry point (`parse_bytes`):
// for the same file, parsing it from memory must give exactly the result of
// parsing it from a scanned tree. This is what makes a fuzz harness, which only
// ever calls `parse_bytes`, a test of the code a real scan runs.
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "parsers/ci/github_actions.hpp"
#include "parsers/cpp/cmake_deps.hpp"
#include "parsers/cpp/conan.hpp"
#include "parsers/cpp/submodules.hpp"
#include "parsers/cpp/vcpkg.hpp"
#include "parsers/embedded/west.hpp"
#include "parsers/lockfiles/cargo.hpp"
#include "parsers/lockfiles/composer.hpp"
#include "parsers/lockfiles/go.hpp"
#include "parsers/lockfiles/maven.hpp"
#include "parsers/lockfiles/npm.hpp"
#include "parsers/lockfiles/nuget.hpp"
#include "parsers/lockfiles/pnpm.hpp"
#include "parsers/lockfiles/pub.hpp"
#include "parsers/lockfiles/python.hpp"
#include "parsers/lockfiles/rubygems.hpp"
#include "parsers/lockfiles/yarn.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Component;
using bomwerk::core::FileIndex;
using bomwerk::core::Result;
using bomwerk::test::TempTree;

namespace parsers = bomwerk::parsers;

namespace
{

using Components = Result<std::vector<Component>>;

std::string read_fixture(const fs::path& relative_path)
{
  std::ifstream stream(fs::path(BOMWERK_FIXTURES_DIR) / relative_path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

/// Field-by-field equality of two producer results: every component field a
/// producer sets, every evidence entry, every warning, and `complete`.
bool same_result(const Components& left, const Components& right)
{
  if (left.complete != right.complete || left.value.size() != right.value.size() ||
      left.warnings.size() != right.warnings.size())
  {
    return false;
  }
  for (std::size_t index = 0; index < left.value.size(); ++index)
  {
    const Component& left_component = left.value[index];
    const Component& right_component = right.value[index];
    if (left_component.name != right_component.name ||
        left_component.version != right_component.version ||
        left_component.supplier != right_component.supplier ||
        left_component.license != right_component.license ||
        left_component.purl != right_component.purl || left_component.cpe != right_component.cpe ||
        left_component.sha256 != right_component.sha256 ||
        left_component.root != right_component.root ||
        left_component.scope != right_component.scope ||
        left_component.evidence.size() != right_component.evidence.size())
    {
      return false;
    }
    for (std::size_t evidence_index = 0; evidence_index < left_component.evidence.size();
         ++evidence_index)
    {
      const bomwerk::core::Evidence& left_evidence = left_component.evidence[evidence_index];
      const bomwerk::core::Evidence& right_evidence = right_component.evidence[evidence_index];
      if (left_evidence.source != right_evidence.source ||
          left_evidence.detail != right_evidence.detail ||
          left_evidence.confidence != right_evidence.confidence)
      {
        return false;
      }
    }
  }
  for (std::size_t index = 0; index < left.warnings.size(); ++index)
  {
    if (left.warnings[index].code != right.warnings[index].code ||
        left.warnings[index].message != right.warnings[index].message ||
        left.warnings[index].ecosystem != right.warnings[index].ecosystem ||
        left.warnings[index].affected_path != right.warnings[index].affected_path)
    {
      return false;
    }
  }
  return true;
}

/// Writes `bytes` as `file_name` into a fresh tree, parses it through the
/// FileIndex overload (the one `run_scan` uses) and through `parse_bytes`, and
/// requires the two results to be identical.
template <typename Producer>
void require_equivalent(const std::string& case_name, std::string_view file_name,
                        std::string_view bytes, const typename Producer::Options& options)
{
  TempTree tree;
  tree.write(fs::path(file_name), bytes);
  const FileIndex file_index{{fs::path(file_name)}};
  const Components from_tree = Producer::parse(file_index, tree.root(), options);
  const Components from_memory = Producer::parse_bytes(file_name, bytes, options);
  if (!same_result(from_tree, from_memory))
  {
    std::fprintf(stderr, "parse_bytes differs from parse: %s\n", case_name.c_str());
  }
  BOMWERK_TEST_CHECK(same_result(from_tree, from_memory));
}

/// The inputs every producer is checked against beyond its real-world files:
/// empty, a lone UTF-8 BOM, binary garbage and an embedded NUL.
const std::vector<std::string>& degenerate_inputs()
{
  static const std::vector<std::string> inputs = {
      std::string(),
      std::string("\xEF\xBB\xBF"),
      std::string("\x00\x01\x02\xFF garbage {[ \"\n", 18),
      std::string("a\0b\nc\n", 6),
  };
  return inputs;
}

/// One real file a producer reads, and the name a scan would find it under.
struct Sample
{
  std::string file_name;
  std::string fixture;  ///< path under fixtures/
};

/// The checks every producer gets: each real sample parsed from memory and
/// from a tree (at the root and nested), the same sample oversized and under a
/// one-entry budget, the degenerate inputs, and a name it does not read.
template <typename Producer>
void check_producer(const char* producer_name, const std::vector<Sample>& samples,
                    std::string_view foreign_name)
{
  for (const Sample& sample : samples)
  {
    const std::string bytes = read_fixture(sample.fixture);
    BOMWERK_TEST_CHECK(!bytes.empty());
    const std::string case_prefix = std::string(producer_name) + " " + sample.fixture;

    // Given the real file, when parsed both ways, then both agree and the
    // file yields at least one component.
    require_equivalent<Producer>(case_prefix, sample.file_name, bytes, {});
    BOMWERK_TEST_CHECK(!Producer::parse_bytes(sample.file_name, bytes, {}).value.empty());

    // Given the same file one directory down, then the nested label reaches
    // warnings and evidence identically.
    require_equivalent<Producer>(case_prefix + " nested", "nested/dir/" + sample.file_name, bytes,
                                 {});

    // Given a cap that cuts the file in half, then the producer's oversize
    // policy (skip, or keep complete lines) behaves identically.
    typename Producer::Options oversized;
    oversized.max_file_bytes = bytes.size() / 2;
    require_equivalent<Producer>(case_prefix + " oversized", sample.file_name, bytes, oversized);

    // Given a budget of one entry, then exhaustion behaves identically.
    require_equivalent<Producer>(case_prefix + " budget", sample.file_name, bytes,
                                 Producer::one_entry_budget());

    // Given degenerate bytes under the same name, then both degrade the same.
    for (const std::string& degenerate : degenerate_inputs())
    {
      require_equivalent<Producer>(case_prefix + " degenerate", sample.file_name, degenerate, {});
    }
  }

  // Given a name the producer never reads, when parsed from memory, then the
  // result is empty, warning-free and complete.
  const Components foreign = Producer::parse_bytes(foreign_name, "anything\n", {});
  BOMWERK_TEST_CHECK(foreign.value.empty());
  BOMWERK_TEST_CHECK(foreign.warnings.empty());
  BOMWERK_TEST_CHECK(foreign.complete);
}

// One adapter per producer: its options type, its two entry points, and the
// options that leave room for exactly one entry.

#define BOMWERK_PRODUCER_ADAPTER(adapter_name, producer_namespace, options_type, budget_field) \
  struct adapter_name                                                                          \
  {                                                                                            \
    using Options = producer_namespace::options_type;                                          \
    static Components parse(const FileIndex& file_index, const fs::path& root,                 \
                            const Options& options)                                            \
    {                                                                                          \
      return producer_namespace::parse(file_index, root, options);                             \
    }                                                                                          \
    static Components parse_bytes(std::string_view file_name, std::string_view bytes,          \
                                  const Options& options)                                      \
    {                                                                                          \
      return producer_namespace::parse_bytes(file_name, bytes, options);                       \
    }                                                                                          \
    static Options one_entry_budget()                                                          \
    {                                                                                          \
      Options options;                                                                         \
      options.budget_field = 1;                                                                \
      return options;                                                                          \
    }                                                                                          \
  }

BOMWERK_PRODUCER_ADAPTER(Cargo, parsers::lockfiles::cargo, ParseOptions, max_total_packages);
BOMWERK_PRODUCER_ADAPTER(Composer, parsers::lockfiles::composer, ParseOptions, max_total_packages);
BOMWERK_PRODUCER_ADAPTER(Go, parsers::lockfiles::go, ParseOptions, max_total_packages);
BOMWERK_PRODUCER_ADAPTER(Maven, parsers::lockfiles::maven, ParseOptions, max_total_packages);
BOMWERK_PRODUCER_ADAPTER(Npm, parsers::lockfiles::npm, ParseOptions, max_total_packages);
BOMWERK_PRODUCER_ADAPTER(Nuget, parsers::lockfiles::nuget, ParseOptions, max_total_packages);
BOMWERK_PRODUCER_ADAPTER(Pnpm, parsers::lockfiles::pnpm, ParseOptions, max_total_packages);
BOMWERK_PRODUCER_ADAPTER(Pub, parsers::lockfiles::pub, ParseOptions, max_total_packages);
BOMWERK_PRODUCER_ADAPTER(Python, parsers::lockfiles::python, ParseOptions, max_total_packages);
BOMWERK_PRODUCER_ADAPTER(Rubygems, parsers::lockfiles::rubygems, ParseOptions, max_total_packages);
BOMWERK_PRODUCER_ADAPTER(Yarn, parsers::lockfiles::yarn, ParseOptions, max_total_packages);
BOMWERK_PRODUCER_ADAPTER(Vcpkg, parsers::cpp::vcpkg, ParseOptions, max_total_requirements);
BOMWERK_PRODUCER_ADAPTER(West, parsers::embedded::west, ParseOptions, max_total_projects);
BOMWERK_PRODUCER_ADAPTER(GithubActions, parsers::ci::github_actions, ParseOptions,
                         max_total_uses_references);
BOMWERK_PRODUCER_ADAPTER(Conan, parsers::cpp::conan, ParseOptions, max_total_requirements);
BOMWERK_PRODUCER_ADAPTER(CmakeDeps, parsers::cpp::cmake_deps, ParseLimits, max_total_declarations);

#undef BOMWERK_PRODUCER_ADAPTER

}  // namespace

int main()
{
  check_producer<Cargo>("cargo", {{"Cargo.lock", "golden/cargo-lock/tree/Cargo.lock"}},
                        "Cargo.toml");
  check_producer<Composer>("composer",
                           {{"composer.lock", "golden/composer-lock/tree/composer.lock"},
                            {"composer.json", "golden/composer-json-only/tree/composer.json"}},
                           "package.json");
  check_producer<Go>("go", {{"go.sum", "golden/go-sum/tree/go.sum"}}, "go.mod");
  check_producer<Maven>("maven",
                        {{"pom.xml", "golden/maven-pom/tree/pom.xml"},
                         {"gradle.lockfile", "golden/gradle-lockfile/tree/gradle.lockfile"}},
                        "build.gradle");
  check_producer<Npm>("npm", {{"package-lock.json", "golden/npm-lockfile/tree/package-lock.json"}},
                      "package.json");
  check_producer<Nuget>("nuget",
                        {{"packages.lock.json", "golden/nuget-lock/tree/packages.lock.json"},
                         {"MyApp.csproj", "golden/nuget-csproj/tree/MyApp.csproj"},
                         {"packages.config", "golden/nuget-packages-config/tree/packages.config"}},
                        "MyApp.sln");
  check_producer<Pnpm>("pnpm",
                       {{"pnpm-lock.yaml", "golden/pnpm-lock-v6/tree/pnpm-lock.yaml"},
                        {"pnpm-lock.yaml", "golden/pnpm-lock-v9/tree/pnpm-lock.yaml"}},
                       "pnpm-workspace.yaml");
  check_producer<Python>(
      "python",
      {{"poetry.lock", "golden/python-poetry/tree/poetry.lock"},
       {"uv.lock", "golden/python-uv/tree/uv.lock"},
       {"requirements-docs.txt", "golden/python-requirements/tree/requirements-docs.txt"}},
      "pyproject.toml");
  check_producer<Rubygems>("rubygems", {{"Gemfile.lock", "golden/gemfile-lock/tree/Gemfile.lock"}},
                           "Gemfile");
  check_producer<Yarn>("yarn",
                       {{"yarn.lock", "golden/yarn-berry-lock/tree/yarn.lock"},
                        {"yarn.lock", "golden/yarn-classic-lock/tree/yarn.lock"}},
                       ".yarnrc.yml");
  check_producer<Vcpkg>(
      "vcpkg",
      {{"vcpkg.json", "golden/vcpkg-manifest/tree/vcpkg.json"},
       {"ports/zlib/vcpkg.json", "golden/vcpkg-ports-registry/tree/ports/zlib/vcpkg.json"}},
      "vcpkg-configuration.json");
  check_producer<West>("west", {{"west.yml", "golden/west-manifest/tree/app/west.yml"}},
                       "west.toml");
  check_producer<GithubActions>(
      "github_actions",
      {{".github/workflows/ci.yml", "golden/github-actions-clean/tree/.github/workflows/ci.yml"}},
      ".github/dependabot.yml");
  check_producer<Conan>("conan",
                        {{"conanfile.txt", "golden/conan-lock/tree/conanfile.txt"},
                         {"conan.lock", "golden/conan-lock/tree/conan.lock"}},
                        "conandata.yml");
  check_producer<CmakeDeps>("cmake_deps",
                            {{"CMakeLists.txt", "golden/cmake-fetchcontent/tree/CMakeLists.txt"},
                             {"deps.cmake", "golden/cmake-fetchcontent/tree/cmake/deps.cmake"}},
                            "CMakeCache.txt");

  // pub has no golden case yet (see the T40 test pass), so its sample is
  // written here: hosted, git, path and an unknown source in one lockfile.
  {
    const std::string lockfile =
        "packages:\n"
        "  collection:\n"
        "    dependency: transitive\n"
        "    description:\n"
        "      name: collection\n"
        "      url: \"https://pub.dev\"\n"
        "    source: hosted\n"
        "    version: \"1.18.0\"\n"
        "  forked:\n"
        "    dependency: direct main\n"
        "    description:\n"
        "      path: \".\"\n"
        "      ref: main\n"
        "      resolved-ref: \"0123456789abcdef0123456789abcdef01234567\"\n"
        "      url: \"https://github.com/example/forked.git\"\n"
        "    source: git\n"
        "    version: \"2.0.0\"\n"
        "  local:\n"
        "    dependency: direct main\n"
        "    description:\n"
        "      path: \"../local\"\n"
        "      relative: true\n"
        "    source: path\n"
        "    version: \"0.1.0\"\n"
        "  mystery:\n"
        "    source: somewhere\n"
        "    version: \"9.9.9\"\n";
    // Given the lockfile, when parsed both ways at several caps and budgets,
    // then both agree; check_producer needs a fixture path, so the same
    // checks are spelled out here.
    require_equivalent<Pub>("pub", "pubspec.lock", lockfile, {});
    BOMWERK_TEST_CHECK(!Pub::parse_bytes("pubspec.lock", lockfile, {}).value.empty());
    require_equivalent<Pub>("pub nested", "app/pubspec.lock", lockfile, {});
    Pub::Options oversized;
    oversized.max_file_bytes = lockfile.size() / 2;
    require_equivalent<Pub>("pub oversized", "pubspec.lock", lockfile, oversized);
    require_equivalent<Pub>("pub budget", "pubspec.lock", lockfile, Pub::one_entry_budget());
    for (const std::string& degenerate : degenerate_inputs())
    {
      require_equivalent<Pub>("pub degenerate", "pubspec.lock", degenerate, {});
    }
    BOMWERK_TEST_CHECK(Pub::parse_bytes("pubspec.yaml", "name: app\n", {}).value.empty());
  }

  // Given a .gitmodules with no checkout and no superproject origin around
  // it, when parsed from a tree and from memory, then both agree: every
  // submodule is reported, uninitialized, with the same warnings.
  {
    const std::string gitmodules = read_fixture("golden/gitmodules-pinned/tree/.gitmodules");
    BOMWERK_TEST_CHECK(!gitmodules.empty());
    TempTree tree;
    tree.write(".gitmodules", gitmodules);
    const Components from_tree = parsers::cpp::submodules::parse(tree.root());
    const Components from_memory = parsers::cpp::submodules::parse_bytes(gitmodules);
    BOMWERK_TEST_CHECK(same_result(from_tree, from_memory));
    BOMWERK_TEST_CHECK(!from_memory.value.empty());
    for (const std::string& degenerate : degenerate_inputs())
    {
      TempTree degenerate_tree;
      degenerate_tree.write(".gitmodules", degenerate);
      BOMWERK_TEST_CHECK(same_result(parsers::cpp::submodules::parse(degenerate_tree.root()),
                                     parsers::cpp::submodules::parse_bytes(degenerate)));
    }
  }

  std::puts("test_parse_bytes: OK");
  return 0;
}
