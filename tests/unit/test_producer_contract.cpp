// ctest unit test for the contract every manifest producer keeps, applied to
// all of them the same way (docs/CONTRIBUTING.md hard rule 1: hostile input
// degrades to warnings, never a crash). One table-driven test, rather than
// the same blocks copied into seventeen files, so no producer can quietly
// fall behind: a producer added here gets every check below.
//
// For each producer:
//   - every file in its fixtures/<name>/hostile directory parses, keeps
//     `complete`, and emits only valid purls;
//   - an empty file yields nothing, completely;
//   - a UTF-8 BOM in front of a real file changes nothing;
//   - CRLF line endings change nothing;
//   - an embedded NUL degrades without an invalid purl or `complete = false`;
//   - an oversized file warns exactly once (kFileSizeLimitExceeded);
//   - an unreadable file warns (kUnreadableFile) and keeps `complete`;
//   - `max_scanned_files` reads the first file in path order and warns
//     (kFileLimitReached).
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/purl.hpp"
#include "core/result.hpp"
#include "core/warning_code.hpp"
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
using bomwerk::core::WarningCode;
using bomwerk::test::TempTree;

namespace parsers = bomwerk::parsers;

namespace
{

using Components = Result<std::vector<Component>>;

std::string read_file(const fs::path& path)
{
  std::ifstream stream(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

std::string read_fixture(const fs::path& relative_path)
{
  return read_file(fs::path(BOMWERK_FIXTURES_DIR) / relative_path);
}

/// Every regular file under `directory`, recursively and in path order,
/// except the documentation that sits beside hostile inputs.
std::vector<fs::path> hostile_files(const fs::path& directory)
{
  std::vector<fs::path> files;
  for (const fs::directory_entry& entry : fs::recursive_directory_iterator(directory))
  {
    const std::string name = entry.path().filename().string();
    if (entry.is_regular_file() && name != "README.md" && name != "SOURCES.md")
    {
      files.push_back(entry.path());
    }
  }
  std::sort(files.begin(), files.end());
  return files;
}

std::size_t count_code(const Components& result, WarningCode code)
{
  return static_cast<std::size_t>(std::count_if(result.warnings.begin(), result.warnings.end(),
                                                [code](const auto& warning)
                                                { return warning.code == code; }));
}

/// No purl a producer emits may fail to parse back, and no producer may have
/// reported that one did: that warning exists so tests and fuzzers catch it.
bool purls_valid(const Components& result)
{
  if (count_code(result, WarningCode::kPurlValidationFailed) != 0)
  {
    return false;
  }
  return std::all_of(
      result.value.begin(), result.value.end(), [](const Component& component)
      { return component.purl.empty() || bomwerk::core::Purl::parse(component.purl).complete; });
}

std::vector<std::string> purls_of(const Components& result)
{
  std::vector<std::string> purls;
  for (const Component& component : result.value)
  {
    purls.push_back(component.purl);
  }
  return purls;
}

std::string with_crlf(std::string_view text)
{
  std::string converted;
  converted.reserve(text.size() + text.size() / 16);
  for (std::size_t index = 0; index < text.size(); ++index)
  {
    if (text[index] == '\n' && (index == 0 || text[index - 1] != '\r'))
    {
      converted += '\r';
    }
    converted += text[index];
  }
  return converted;
}

void report(const std::string& producer, const std::string& check)
{
  std::fprintf(stderr, "contract broken: %s: %s\n", producer.c_str(), check.c_str());
}

/// The checks every producer with options and a FileIndex overload keeps.
template <typename Producer>
void check_contract()
{
  const std::string producer = Producer::kName;
  const std::string sample_name = Producer::kSampleName;
  const std::string sample = read_fixture(Producer::kSampleFixture);
  BOMWERK_TEST_CHECK(!sample.empty());

  // Hostile fixtures: warn and continue.
  for (const std::string& directory : Producer::hostile_directories())
  {
    for (const fs::path& path : hostile_files(fs::path(BOMWERK_FIXTURES_DIR) / directory))
    {
      const std::string name = Producer::canonical_name(path);
      if (name.empty())
      {
        continue;  // documentation or a file this producer does not read
      }
      const Components result = Producer::parse_bytes(name, read_file(path), {});
      if (!result.complete || !purls_valid(result))
      {
        report(producer, "hostile " + path.string());
      }
      BOMWERK_TEST_CHECK(result.complete);
      BOMWERK_TEST_CHECK(purls_valid(result));
    }
  }

  // Empty: nothing, completely.
  {
    const Components result = Producer::parse_bytes(sample_name, "", {});
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.complete);
  }

  const Components baseline = Producer::parse_bytes(sample_name, sample, {});
  BOMWERK_TEST_CHECK(!baseline.value.empty());
  BOMWERK_TEST_CHECK(purls_valid(baseline));

  // BOM and CRLF change nothing.
  {
    const Components with_bom = Producer::parse_bytes(sample_name, "\xEF\xBB\xBF" + sample, {});
    if (purls_of(with_bom) != purls_of(baseline))
    {
      report(producer, "UTF-8 BOM changes the components");
    }
    BOMWERK_TEST_CHECK(purls_of(with_bom) == purls_of(baseline));
    const Components crlf = Producer::parse_bytes(sample_name, with_crlf(sample), {});
    if (purls_of(crlf) != purls_of(baseline))
    {
      report(producer, "CRLF line endings change the components");
    }
    BOMWERK_TEST_CHECK(purls_of(crlf) == purls_of(baseline));
  }

  // NUL: degrades, never an invalid purl or an incomplete scan.
  {
    std::string with_nul = sample;
    with_nul.insert(with_nul.size() / 2, 1, '\0');
    const Components result = Producer::parse_bytes(sample_name, with_nul, {});
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(purls_valid(result));
  }

  // Oversized: exactly one size warning.
  {
    typename Producer::Options options;
    options.max_file_bytes = 1;
    const Components result = Producer::parse_bytes(sample_name, sample, options);
    BOMWERK_TEST_CHECK(count_code(result, WarningCode::kFileSizeLimitExceeded) == 1);
    BOMWERK_TEST_CHECK(result.complete);
  }

  // Unreadable: a FileIndex naming a file that is not there
  // (docs/CONTRIBUTING.md, Tests).
  {
    TempTree tree;
    const FileIndex file_index{{fs::path(sample_name)}};
    const Components result = Producer::parse(file_index, tree.root(), {});
    BOMWERK_TEST_CHECK(count_code(result, WarningCode::kUnreadableFile) == 1);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.complete);
  }

  // File cap: the first file in path order, and one warning.
  {
    TempTree tree;
    const auto [first, second] = Producer::two_paths();
    tree.write(first, sample);
    tree.write(second, sample);
    typename Producer::Options options;
    options.max_scanned_files = 1;
    const Components result =
        Producer::parse(FileIndex{{fs::path(first), fs::path(second)}}, tree.root(), options);
    BOMWERK_TEST_CHECK(count_code(result, WarningCode::kFileLimitReached) == 1);
    for (const Component& component : result.value)
    {
      for (const auto& evidence : component.evidence)
      {
        BOMWERK_TEST_CHECK(evidence.detail.find(second) == std::string::npos);
      }
    }
  }
}

/// The name a hostile fixture stands for: the longest of `names` its file name
/// ends with (`bom.conanfile.txt` -> `conanfile.txt`), or empty for none.
std::string longest_suffix(const fs::path& path, std::initializer_list<std::string_view> names)
{
  const std::string file_name = path.filename().string();
  std::string best;
  for (const std::string_view name : names)
  {
    if (file_name.ends_with(name) && name.size() > best.size())
    {
      best = std::string(name);
    }
  }
  return best;
}

std::vector<std::string> no_hostile_directory()
{
  return {};
}

// ---- One adapter per producer ---------------------------------------------

#define BOMWERK_CONTRACT_ENTRY_POINTS(producer_namespace, options_type)        \
  using Options = producer_namespace::options_type;                            \
  static Components parse(const FileIndex& file_index, const fs::path& root,   \
                          const Options& options)                              \
  {                                                                            \
    return producer_namespace::parse(file_index, root, options);               \
  }                                                                            \
  static Components parse_bytes(std::string_view name, std::string_view bytes, \
                                const Options& options)                        \
  {                                                                            \
    return producer_namespace::parse_bytes(name, bytes, options);              \
  }

// The two contract macros below carry lines near the column limit, where
// clang-format 18 (CI) and newer versions align the trailing backslashes
// differently, so no single layout satisfies both. Keep them unformatted.
// clang-format off

/// Most producers: one canonical file name, no hostile directory of their
/// own yet, and two copies one directory apart for the file-cap check.
#define BOMWERK_SIMPLE_CONTRACT(adapter, producer_namespace, name, fixture)                  \
  struct adapter                                                                             \
  {                                                                                          \
    BOMWERK_CONTRACT_ENTRY_POINTS(producer_namespace, ParseOptions)                          \
    static constexpr const char* kName = #adapter;                                           \
    static constexpr const char* kSampleName = name;                                         \
    static constexpr const char* kSampleFixture = fixture;                                   \
    static std::vector<std::string> hostile_directories() { return no_hostile_directory(); } \
    static std::string canonical_name(const fs::path&) { return {}; }                        \
    static std::pair<std::string, std::string> two_paths()                                   \
    {                                                                                        \
      return {std::string("a/") + name, std::string("b/") + name};                           \
    }                                                                                        \
  }

BOMWERK_SIMPLE_CONTRACT(Cargo, parsers::lockfiles::cargo, "Cargo.lock",
                        "golden/cargo-lock/tree/Cargo.lock");
BOMWERK_SIMPLE_CONTRACT(ComposerLock, parsers::lockfiles::composer, "composer.lock",
                        "golden/composer-lock/tree/composer.lock");
BOMWERK_SIMPLE_CONTRACT(Go, parsers::lockfiles::go, "go.sum", "golden/go-sum/tree/go.sum");
BOMWERK_SIMPLE_CONTRACT(MavenPom, parsers::lockfiles::maven, "pom.xml",
                        "golden/maven-pom/tree/pom.xml");
BOMWERK_SIMPLE_CONTRACT(Gradle, parsers::lockfiles::maven, "gradle.lockfile",
                        "golden/gradle-lockfile/tree/gradle.lockfile");
BOMWERK_SIMPLE_CONTRACT(Npm, parsers::lockfiles::npm, "package-lock.json",
                        "golden/npm-lockfile/tree/package-lock.json");
BOMWERK_SIMPLE_CONTRACT(NugetLock, parsers::lockfiles::nuget, "packages.lock.json",
                        "golden/nuget-lock/tree/packages.lock.json");
BOMWERK_SIMPLE_CONTRACT(NugetCsproj, parsers::lockfiles::nuget, "MyApp.csproj",
                        "golden/nuget-csproj/tree/MyApp.csproj");
BOMWERK_SIMPLE_CONTRACT(Pnpm, parsers::lockfiles::pnpm, "pnpm-lock.yaml",
                        "golden/pnpm-lock-v9/tree/pnpm-lock.yaml");
BOMWERK_SIMPLE_CONTRACT(Rubygems, parsers::lockfiles::rubygems, "Gemfile.lock",
                        "golden/gemfile-lock/tree/Gemfile.lock");
BOMWERK_SIMPLE_CONTRACT(YarnBerry, parsers::lockfiles::yarn, "yarn.lock",
                        "golden/yarn-berry-lock/tree/yarn.lock");
BOMWERK_SIMPLE_CONTRACT(YarnClassic, parsers::lockfiles::yarn, "yarn.lock",
                        "golden/yarn-classic-lock/tree/yarn.lock");
BOMWERK_SIMPLE_CONTRACT(Pub, parsers::lockfiles::pub, "pubspec.lock",
                        "golden/pub-lock/tree/pubspec.lock");

/// A producer whose fixtures/<directory>/hostile files are named
/// `<what>.<canonical file name>`: the suffix says which file name each one
/// stands for.
#define BOMWERK_HOSTILE_CONTRACT(adapter, producer_namespace, name, fixture, directory, suffix) \
  struct adapter                                                                                \
  {                                                                                             \
    BOMWERK_CONTRACT_ENTRY_POINTS(producer_namespace, ParseOptions)                             \
    static constexpr const char* kName = #adapter;                                              \
    static constexpr const char* kSampleName = name;                                            \
    static constexpr const char* kSampleFixture = fixture;                                      \
    static std::vector<std::string> hostile_directories() { return {directory}; }               \
    static std::string canonical_name(const fs::path& path)                                     \
    {                                                                                           \
      return longest_suffix(path, {suffix});                                                    \
    }                                                                                           \
    static std::pair<std::string, std::string> two_paths()                                      \
    {                                                                                           \
      return {std::string("a/") + name, std::string("b/") + name};                              \
    }                                                                                           \
  }

// clang-format on

BOMWERK_HOSTILE_CONTRACT(PythonUv, parsers::lockfiles::python, "uv.lock",
                         "golden/python-uv/tree/uv.lock", "python/hostile", "uv.lock");
BOMWERK_HOSTILE_CONTRACT(PythonPoetry, parsers::lockfiles::python, "poetry.lock",
                         "golden/python-poetry/tree/poetry.lock", "python/hostile", "poetry.lock");
BOMWERK_HOSTILE_CONTRACT(PythonRequirements, parsers::lockfiles::python, "requirements-docs.txt",
                         "golden/python-requirements/tree/requirements-docs.txt", "python/hostile",
                         "requirements.txt");

struct Conan
{
  BOMWERK_CONTRACT_ENTRY_POINTS(parsers::cpp::conan, ParseOptions)
  static constexpr const char* kName = "Conan";
  static constexpr const char* kSampleName = "conanfile.txt";
  static constexpr const char* kSampleFixture = "golden/conan-lock/tree/conanfile.txt";
  static std::vector<std::string> hostile_directories() { return {"conan/hostile"}; }
  static std::string canonical_name(const fs::path& path)
  {
    return longest_suffix(path, {"conanfile.txt", "conanfile.py", "conan.lock"});
  }
  static std::pair<std::string, std::string> two_paths()
  {
    return {"a/conanfile.txt", "b/conanfile.txt"};
  }
};

struct Vcpkg
{
  BOMWERK_CONTRACT_ENTRY_POINTS(parsers::cpp::vcpkg, ParseOptions)
  static constexpr const char* kName = "Vcpkg";
  static constexpr const char* kSampleName = "vcpkg.json";
  static constexpr const char* kSampleFixture = "golden/vcpkg-manifest/tree/vcpkg.json";
  static std::vector<std::string> hostile_directories() { return {"vcpkg/hostile"}; }
  static std::string canonical_name(const fs::path& path)
  {
    return longest_suffix(path, {"vcpkg.json"});
  }
  static std::pair<std::string, std::string> two_paths()
  {
    return {"a/vcpkg.json", "b/vcpkg.json"};
  }
};

struct CmakeDeps
{
  BOMWERK_CONTRACT_ENTRY_POINTS(parsers::cpp::cmake_deps, ParseLimits)
  static constexpr const char* kName = "CmakeDeps";
  static constexpr const char* kSampleName = "CMakeLists.txt";
  static constexpr const char* kSampleFixture = "golden/cmake-fetchcontent/tree/CMakeLists.txt";
  static std::vector<std::string> hostile_directories() { return {"cmake/hostile"}; }
  static std::string canonical_name(const fs::path& path)
  {
    return path.extension() == ".cmake" ? path.filename().string() : std::string();
  }
  static std::pair<std::string, std::string> two_paths()
  {
    return {"a/CMakeLists.txt", "b/CMakeLists.txt"};
  }
};

struct GithubActions
{
  BOMWERK_CONTRACT_ENTRY_POINTS(parsers::ci::github_actions, ParseOptions)
  static constexpr const char* kName = "GithubActions";
  static constexpr const char* kSampleName = ".github/workflows/ci.yml";
  static constexpr const char* kSampleFixture =
      "golden/github-actions-clean/tree/.github/workflows/ci.yml";
  static std::vector<std::string> hostile_directories() { return {"github-actions/hostile"}; }
  static std::string canonical_name(const fs::path& path)
  {
    return path.extension() == ".yml" ? ".github/workflows/" + path.filename().string()
                                      : std::string();
  }
  static std::pair<std::string, std::string> two_paths()
  {
    return {".github/workflows/a.yml", ".github/workflows/b.yml"};
  }
};

struct West
{
  BOMWERK_CONTRACT_ENTRY_POINTS(parsers::embedded::west, ParseOptions)
  static constexpr const char* kName = "West";
  static constexpr const char* kSampleName = "west.yml";
  static constexpr const char* kSampleFixture = "golden/west-manifest/tree/app/west.yml";
  static std::vector<std::string> hostile_directories() { return {"west/hostile"}; }
  static std::string canonical_name(const fs::path& path)
  {
    return longest_suffix(path, {"west.yml", "west.yaml"});
  }
  static std::pair<std::string, std::string> two_paths() { return {"a/west.yml", "b/west.yml"}; }
};

#undef BOMWERK_SIMPLE_CONTRACT
#undef BOMWERK_HOSTILE_CONTRACT
#undef BOMWERK_CONTRACT_ENTRY_POINTS

}  // namespace

int main()
{
  check_contract<Cargo>();
  check_contract<ComposerLock>();
  check_contract<Go>();
  check_contract<MavenPom>();
  check_contract<Gradle>();
  check_contract<Npm>();
  check_contract<NugetLock>();
  check_contract<NugetCsproj>();
  check_contract<Pnpm>();
  check_contract<PythonUv>();
  check_contract<PythonPoetry>();
  check_contract<PythonRequirements>();
  check_contract<Rubygems>();
  check_contract<YarnBerry>();
  check_contract<YarnClassic>();
  check_contract<Pub>();
  check_contract<Conan>();
  check_contract<Vcpkg>();
  check_contract<CmakeDeps>();
  check_contract<GithubActions>();
  check_contract<West>();

  // submodules has no options or FileIndex overload (it reads only the root
  // .gitmodules), so it keeps the in-memory half of the contract.
  {
    const std::string gitmodules = read_fixture("golden/gitmodules-pinned/tree/.gitmodules");
    for (const fs::path& path :
         hostile_files(fs::path(BOMWERK_FIXTURES_DIR) / "gitmodules/hostile"))
    {
      const Components result = parsers::cpp::submodules::parse_bytes(read_file(path));
      if (!result.complete || !purls_valid(result))
      {
        report("Submodules", "hostile " + path.string());
      }
      BOMWERK_TEST_CHECK(result.complete);
      BOMWERK_TEST_CHECK(purls_valid(result));
    }
    BOMWERK_TEST_CHECK(parsers::cpp::submodules::parse_bytes("").value.empty());
    const Components baseline = parsers::cpp::submodules::parse_bytes(gitmodules);
    BOMWERK_TEST_CHECK(!baseline.value.empty());
    BOMWERK_TEST_CHECK(purls_of(parsers::cpp::submodules::parse_bytes(
                           "\xEF\xBB\xBF" + gitmodules)) == purls_of(baseline));
    BOMWERK_TEST_CHECK(purls_of(parsers::cpp::submodules::parse_bytes(with_crlf(gitmodules))) ==
                       purls_of(baseline));
  }

  std::puts("test_producer_contract: OK");
  return 0;
}
