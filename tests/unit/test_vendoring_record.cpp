// ctest unit test for the vendoring-record reader (Godot-style index, README.chromium)
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "heuristics/vendoring_record.hpp"
#include "support/check.hpp"

namespace fs = std::filesystem;
namespace vendoring_record = bomwerk::heuristics::vendoring_record;
using vendoring_record::Record;

namespace
{

const std::string kShaA = "0123456789abcdef0123456789abcdef01234567";

std::string read_fixture(const fs::path& relative)
{
  std::ifstream stream(fs::path(BOMWERK_FIXTURES_DIR) / "vendoring_record" / relative,
                       std::ios::binary);
  BOMWERK_TEST_CHECK(stream.good());
  std::ostringstream contents;
  contents << stream.rdbuf();
  return contents.str();
}

const Record* find_folder(const std::vector<Record>& records, std::string_view folder)
{
  for (const Record& record : records)
  {
    if (record.folder == folder)
    {
      return &record;
    }
  }
  return nullptr;
}

/// The one record a one-section index yields, or nullopt.
std::optional<Record> single_section(const std::string& text)
{
  const std::vector<Record> records = vendoring_record::parse_index(text);
  if (records.size() != 1)
  {
    return std::nullopt;
  }
  return records.front();
}

}  // namespace

int main()
{
  // Given an index in Godot's layout covering every Version shape it uses,
  // when parsed, then each section that states a release or one commit yields
  // exactly that, sorted by folder, and the ones that state neither (two
  // libraries in one folder, per-file bullets only, `?`) yield nothing.
  {
    const std::vector<Record> records =
        vendoring_record::parse_index(read_fixture("godot.README.md"));
    std::vector<std::string> folders;
    for (const Record& record : records)
    {
      folders.push_back(record.folder);
    }
    BOMWERK_TEST_CHECK(
        (folders == std::vector<std::string>{"alpha", "beta", "delta", "epsilon", "eta", "gamma",
                                             "lambda", "mu", "theta", "zeta"}));

    const Record* alpha = find_folder(records, "alpha");
    BOMWERK_TEST_CHECK(alpha != nullptr);
    BOMWERK_TEST_CHECK(alpha->version == "0.22.3");
    BOMWERK_TEST_CHECK(alpha->commit == kShaA);
    BOMWERK_TEST_CHECK(alpha->states_release());
    BOMWERK_TEST_CHECK(alpha->upstream == "https://github.com/example-org/alpha-c");
    BOMWERK_TEST_CHECK(alpha->version_line ==
                       "- Version: 0.22.3 (0123456789abcdef0123456789abcdef01234567, 2026)");

    // `git (<sha>)`: no release, so the version is the commit.
    const Record* beta = find_folder(records, "beta");
    BOMWERK_TEST_CHECK(beta != nullptr);
    BOMWERK_TEST_CHECK(beta->version == "89abcdef0123456789abcdef0123456789abcdef");
    BOMWERK_TEST_CHECK(beta->commit == beta->version);
    BOMWERK_TEST_CHECK(!beta->states_release());

    // `git (<branch>, <sha>, <year>)`: the branch is not the commit.
    const Record* gamma = find_folder(records, "gamma");
    BOMWERK_TEST_CHECK(gamma != nullptr);
    BOMWERK_TEST_CHECK(gamma->version == "fedcba9876543210fedcba9876543210fedcba98");
    BOMWERK_TEST_CHECK(gamma->upstream == "https://chromium.googlesource.com/example/gamma/");

    // `main (<sha>)` and a bare `<sha>, <year>` both state only a commit.
    const Record* delta = find_folder(records, "delta");
    BOMWERK_TEST_CHECK(delta != nullptr && !delta->states_release());
    BOMWERK_TEST_CHECK(delta->version == std::string(40, '1'));
    const Record* epsilon = find_folder(records, "epsilon");
    BOMWERK_TEST_CHECK(epsilon != nullptr && !epsilon->states_release());
    BOMWERK_TEST_CHECK(epsilon->version == std::string(40, '2'));

    // A release with no commit; a `+git` release; a tag-like release.
    const Record* zeta = find_folder(records, "zeta");
    BOMWERK_TEST_CHECK(zeta != nullptr);
    BOMWERK_TEST_CHECK(zeta->version == "26.0");
    BOMWERK_TEST_CHECK(zeta->commit.empty());
    BOMWERK_TEST_CHECK(zeta->states_release());
    const Record* eta = find_folder(records, "eta");
    BOMWERK_TEST_CHECK(eta != nullptr);
    BOMWERK_TEST_CHECK(eta->version == "1.1.1+git");
    BOMWERK_TEST_CHECK(eta->commit == std::string(40, '3'));
    const Record* theta = find_folder(records, "theta");
    BOMWERK_TEST_CHECK(theta != nullptr);
    BOMWERK_TEST_CHECK(theta->version == "vulkan-sdk-1.4.335.0");
    // `Example Corp, via https://...` is not one URL.
    BOMWERK_TEST_CHECK(theta->upstream.empty());

    // A `#` heading opens a section too (Godot writes `# wayland-protocols`).
    const Record* lambda = find_folder(records, "lambda");
    BOMWERK_TEST_CHECK(lambda != nullptr);
    BOMWERK_TEST_CHECK(lambda->version == "1.47");
    BOMWERK_TEST_CHECK(lambda->upstream == "https://gitlab.com/example-org/lambda");

    // The reader keeps a URL that points inside a repository; deciding it is
    // not a repository URL is the caller's job.
    const Record* mu = find_folder(records, "mu");
    BOMWERK_TEST_CHECK(mu != nullptr);
    BOMWERK_TEST_CHECK(mu->upstream == "https://github.com/example-org/mu/blob/master/src/mu.cpp");

    BOMWERK_TEST_CHECK(find_folder(records, "iota") == nullptr);
    BOMWERK_TEST_CHECK(find_folder(records, "kappa") == nullptr);
    BOMWERK_TEST_CHECK(find_folder(records, "nu") == nullptr);
  }

  // Given CRLF line endings, when parsed, then the record reads the same.
  {
    const std::optional<Record> record =
        single_section("## crlf\r\n\r\n- Upstream: https://github.com/o/r\r\n- Version: 1.2.3\r\n");
    BOMWERK_TEST_CHECK(record.has_value());
    BOMWERK_TEST_CHECK(record->version == "1.2.3");
    BOMWERK_TEST_CHECK(record->upstream == "https://github.com/o/r");
  }

  // Given a commit written in capitals, when parsed, then it is lower-cased:
  // one commit is one identity.
  {
    const std::optional<Record> record =
        single_section("## caps\n- Version: git (ABCDEF0123456789ABCDEF0123456789ABCDEF01)\n");
    BOMWERK_TEST_CHECK(record.has_value());
    BOMWERK_TEST_CHECK(record->commit == "abcdef0123456789abcdef0123456789abcdef01");
    BOMWERK_TEST_CHECK(record->version == record->commit);
  }

  // Given a 64-hex (SHA-256) commit, when parsed, then it is the commit.
  {
    const std::string sha256(64, 'c');
    const std::optional<Record> record =
        single_section("## wide\n- Version: git (" + sha256 + ")\n");
    BOMWERK_TEST_CHECK(record.has_value());
    BOMWERK_TEST_CHECK(record->commit == sha256);
  }

  // Given heads that only look like releases (an abbreviated commit, a VCS
  // word in any case, a placeholder, prose), when parsed, then no release is
  // stated, and without a full commit there is no record.
  {
    constexpr std::string_view kNotReleases[] = {"826d672 (2024)",
                                                 "Unknown",
                                                 "MASTER (2020)",
                                                 "N/A",
                                                 "none",
                                                 "?",
                                                 "minimal C implementation, http://example.org/x",
                                                 "1.2 3",
                                                 ""};
    for (const std::string_view value : kNotReleases)
    {
      BOMWERK_TEST_CHECK(
          vendoring_record::parse_index("## lib\n- Version: " + std::string(value) + "\n").empty());
    }
  }

  // Given a plain number as the head, when parsed, then it is a release: a
  // date-like version is all digits, which is not an abbreviated commit.
  {
    const std::optional<Record> record = single_section("## dated\n- Version: 20240101\n");
    BOMWERK_TEST_CHECK(record.has_value());
    BOMWERK_TEST_CHECK(record->version == "20240101");
  }

  // Given a release longer than kMaxVersionChars, when parsed, then it is not
  // a version, and the commit beside it still is.
  {
    const std::string too_long(vendoring_record::kMaxVersionChars + 1, '7');
    const std::optional<Record> record =
        single_section("## long\n- Version: " + too_long + " (" + kShaA + ")\n");
    BOMWERK_TEST_CHECK(record.has_value());
    BOMWERK_TEST_CHECK(record->version == kShaA);
    BOMWERK_TEST_CHECK(!record->states_release());
  }

  // Given two Upstream lines in one section, when parsed, then the record
  // keeps its version but claims no upstream; a scheme with nothing after it
  // is no upstream either.
  {
    const std::optional<Record> two_upstreams = single_section(
        "## up\n- Upstream: https://github.com/o/a\n- Upstream: https://github.com/o/b\n"
        "- Version: 1.0\n");
    BOMWERK_TEST_CHECK(two_upstreams.has_value());
    BOMWERK_TEST_CHECK(two_upstreams->upstream.empty());
    const std::optional<Record> bare_scheme =
        single_section("## up\n- Upstream: https://\n- Version: 1.0\n");
    BOMWERK_TEST_CHECK(bare_scheme.has_value());
    BOMWERK_TEST_CHECK(bare_scheme->upstream.empty());
    const std::optional<Record> plain_http =
        single_section("## up\n- Upstream: http://example.org/up\n- Version: 1.0\n");
    BOMWERK_TEST_CHECK(plain_http.has_value());
    BOMWERK_TEST_CHECK(plain_http->upstream == "http://example.org/up");
  }

  // Given a Version bullet before any section, or after a heading that is
  // not a folder name, when parsed, then it belongs to no folder.
  {
    BOMWERK_TEST_CHECK(vendoring_record::parse_index("- Version: 1.0\n## \n- Version: 2.0\n"
                                                     "## two words\n- Version: 3.0\n")
                           .empty());
  }

  // Given a `###` heading inside a section, when parsed, then it is section
  // text and does not end the section.
  {
    const std::optional<Record> record = single_section("## deep\n### Patches\n- Version: 4.5.6\n");
    BOMWERK_TEST_CHECK(record.has_value());
    BOMWERK_TEST_CHECK(record->folder == "deep");
  }

  // Given every hostile index fixture, when parsed, then the reader pins what
  // each probe is for.
  {
    BOMWERK_TEST_CHECK(
        vendoring_record::parse_index(read_fixture("hostile/two-versions.README.md")).empty());
    const std::vector<Record> long_lines =
        vendoring_record::parse_index(read_fixture("hostile/long-lines.README.md"));
    BOMWERK_TEST_CHECK(long_lines.size() == 1);
    BOMWERK_TEST_CHECK(long_lines.front().folder == "before");
    BOMWERK_TEST_CHECK(long_lines.front().version == "1.0.0");
  }

  // Given a Chromium record whose Version names no release, when parsed, then
  // its Revision is the version and the commit, its URL the upstream, and a
  // `Version:` after `Description:` is never read.
  {
    const std::optional<Record> record =
        vendoring_record::parse_readme_chromium(read_fixture("chromium.README.chromium"));
    BOMWERK_TEST_CHECK(record.has_value());
    BOMWERK_TEST_CHECK(record->folder.empty());
    BOMWERK_TEST_CHECK(record->version == "abcdef0123456789abcdef0123456789abcdef01");
    BOMWERK_TEST_CHECK(record->commit == record->version);
    BOMWERK_TEST_CHECK(record->upstream == "https://github.com/example-org/example");
    BOMWERK_TEST_CHECK(record->version_line ==
                       "Version: git (see METADATA); Revision: "
                       "abcdef0123456789abcdef0123456789abcdef01");
  }

  // Given a Chromium record stating a release and a revision, when parsed,
  // then the release is the version and the revision the commit.
  {
    const std::optional<Record> record = vendoring_record::parse_readme_chromium(
        "\n\nName: lib\nURL: https://example.org/lib\nVersion: 1.2.3\nRevision: " + kShaA + "\n");
    BOMWERK_TEST_CHECK(record.has_value());
    BOMWERK_TEST_CHECK(record->version == "1.2.3");
    BOMWERK_TEST_CHECK(record->commit == kShaA);
    BOMWERK_TEST_CHECK(record->states_release());
  }

  // Given Chromium's "no version" spellings and no revision, when parsed,
  // then there is no record.
  {
    constexpr std::string_view kNoVersions[] = {"0", "N/A", "unknown", "git (see METADATA)"};
    for (const std::string_view value : kNoVersions)
    {
      BOMWERK_TEST_CHECK(!vendoring_record::parse_readme_chromium(
                              "Name: lib\nVersion: " + std::string(value) + "\n")
                              .has_value());
    }
  }

  // Given a Version whose own commit and the Revision disagree, when parsed,
  // then no commit is stated (and with no release, no record).
  {
    BOMWERK_TEST_CHECK(
        !vendoring_record::parse_readme_chromium("Name: lib\nVersion: git (" + kShaA +
                                                 ")\nRevision: " + std::string(40, 'f') + "\n")
             .has_value());
  }

  // Given every hostile README.chromium fixture, when parsed, then the reader
  // pins what each probe is for.
  {
    BOMWERK_TEST_CHECK(
        !vendoring_record::parse_readme_chromium(read_fixture("hostile/prose.README.chromium"))
             .has_value());
    BOMWERK_TEST_CHECK(
        !vendoring_record::parse_readme_chromium(read_fixture("hostile/long-line.README.chromium"))
             .has_value());
    const std::optional<Record> duplicated = vendoring_record::parse_readme_chromium(
        read_fixture("hostile/duplicate-fields.README.chromium"));
    BOMWERK_TEST_CHECK(duplicated.has_value());
    BOMWERK_TEST_CHECK(duplicated->version == std::string(40, 'a'));
    BOMWERK_TEST_CHECK(duplicated->upstream.empty());
  }

  // Given empty input, when parsed, then neither reader states anything.
  {
    BOMWERK_TEST_CHECK(vendoring_record::parse_index("").empty());
    BOMWERK_TEST_CHECK(!vendoring_record::parse_readme_chromium("").has_value());
  }

  std::puts("test_vendoring_record: OK");
  return 0;
}
