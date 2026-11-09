// ctest unit test for the in-memory entry points of the readers that are not
// manifest producers: ELF and `ar` images, the fingerprint corpus index,
// `bomwerk.toml`, vendored version headers, and the OSV, NVD and registry
// license payloads. Each in-memory answer must equal the path version's for
// the same bytes: that is what makes a fuzz harness, which only ever calls the
// in-memory entry point, a test of the code a real scan runs.
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include "binscan/archive_read.hpp"
#include "binscan/elf_read.hpp"
#include "core/result.hpp"
#include "core/scan_config.hpp"
#include "core/warning.hpp"
#include "heuristics/fingerprint.hpp"
#include "heuristics/vendored_cpp.hpp"
#include "support/archive_builder.hpp"
#include "support/check.hpp"
#include "support/elf_builder.hpp"
#include "support/temp_tree.hpp"
#include "vuln/license_enrichment.hpp"
#include "vuln/nvd.hpp"
#include "vuln/osv.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Result;
using bomwerk::core::Warning;
using bomwerk::test::TempTree;

namespace
{

std::string read_fixture(const fs::path& relative_path)
{
  std::ifstream stream(fs::path(BOMWERK_FIXTURES_DIR) / relative_path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

bool same_warnings(const std::vector<Warning>& left, const std::vector<Warning>& right)
{
  if (left.size() != right.size())
  {
    return false;
  }
  for (std::size_t index = 0; index < left.size(); ++index)
  {
    if (left[index].code != right[index].code || left[index].message != right[index].message)
    {
      return false;
    }
  }
  return true;
}

bool same_elf(const Result<bomwerk::binscan::ElfImage>& left,
              const Result<bomwerk::binscan::ElfImage>& right)
{
  return left.value.shape == right.value.shape && left.value.soname == right.value.soname &&
         left.value.needed == right.value.needed &&
         left.value.exported_symbols == right.value.exported_symbols &&
         left.value.needed_truncated == right.value.needed_truncated &&
         left.value.symbols_truncated == right.value.symbols_truncated &&
         left.value.symbols_unavailable == right.value.symbols_unavailable &&
         left.complete == right.complete && same_warnings(left.warnings, right.warnings);
}

bool same_archive(const Result<bomwerk::binscan::ArchiveContents>& left,
                  const Result<bomwerk::binscan::ArchiveContents>& right)
{
  return left.value.is_archive == right.value.is_archive &&
         left.value.member_names == right.value.member_names &&
         left.value.indexed_symbols == right.value.indexed_symbols &&
         left.value.members_truncated == right.value.members_truncated &&
         left.value.symbols_truncated == right.value.symbols_truncated &&
         left.value.symbols_unavailable == right.value.symbols_unavailable &&
         left.complete == right.complete && same_warnings(left.warnings, right.warnings);
}

}  // namespace

int main()
{
  // Given ELF images of several shapes, plus a truncated one and garbage, when
  // read from a file and from memory under the same label, then both agree.
  {
    std::vector<std::string> images;
    bomwerk::test::ElfBuildOptions shared_library;
    shared_library.needed = {"libc.so.6", "libz.so.1"};
    shared_library.soname = "libdemo.so.1";
    shared_library.exported_symbols = {"demo_init", "demo_run"};
    images.push_back(bomwerk::test::build_elf(shared_library));
    bomwerk::test::ElfBuildOptions big_endian_32 = shared_library;
    big_endian_32.is_64_bit = false;
    big_endian_32.big_endian = true;
    images.push_back(bomwerk::test::build_elf(big_endian_32));
    bomwerk::test::ElfBuildOptions stripped = shared_library;
    stripped.include_section_headers = false;
    stripped.include_program_headers = true;
    images.push_back(bomwerk::test::build_elf(stripped));
    images.push_back(images.front().substr(0, images.front().size() / 2));
    images.push_back(
        std::string("\x7f"
                    "ELF\x09garbage",
                    12));
    images.push_back(std::string());

    for (const std::string& image : images)
    {
      TempTree tree;
      tree.write("image.so", image);
      const fs::path path = tree.root() / "image.so";
      BOMWERK_TEST_CHECK(same_elf(bomwerk::binscan::read_elf(path),
                                  bomwerk::binscan::read_elf_bytes(path.string(), image)));
    }
    BOMWERK_TEST_CHECK(bomwerk::binscan::read_elf_bytes("mem", images.front()).value.needed ==
                       shared_library.needed);
  }

  // Given GNU and BSD archives, plus a truncated one, when read from a file
  // and from memory under the same label, then both agree.
  {
    std::vector<std::string> archives;
    bomwerk::test::ArchiveBuildOptions gnu;
    gnu.members = {{"short.o", "data"}, {"a_rather_long_member_name.o", "more"}};
    gnu.indexed_symbols = {"alpha", "beta"};
    archives.push_back(bomwerk::test::build_archive(gnu));
    bomwerk::test::ArchiveBuildOptions bsd = gnu;
    bsd.bsd_long_names = true;
    bsd.bsd_symbol_index = true;
    archives.push_back(bomwerk::test::build_archive(bsd));
    archives.push_back(archives.front().substr(0, archives.front().size() - 3));
    archives.push_back("!<arch>\n");
    archives.push_back("not an archive");

    for (const std::string& archive : archives)
    {
      TempTree tree;
      tree.write("libdemo.a", archive);
      const fs::path path = tree.root() / "libdemo.a";
      BOMWERK_TEST_CHECK(
          same_archive(bomwerk::binscan::read_archive(path),
                       bomwerk::binscan::read_archive_bytes(path.string(), archive)));
    }
    BOMWERK_TEST_CHECK(
        !bomwerk::binscan::read_archive_bytes("mem", archives.front()).value.member_names.empty());
  }

  // Given the real fingerprint index and broken copies of it, when loaded from
  // a file and from memory, then both agree, and a cap below its size refuses
  // both the same way.
  {
    const std::string index =
        read_fixture("golden/nightmare-corpus-fingerprint/fingerprint-index.json");
    BOMWERK_TEST_CHECK(!index.empty());
    for (const std::string& bytes : {index, index.substr(0, index.size() / 2), std::string("{}")})
    {
      TempTree tree;
      tree.write("index.json", bytes);
      const auto from_file =
          bomwerk::heuristics::fingerprint::load_index(tree.root() / "index.json");
      const auto from_memory = bomwerk::heuristics::fingerprint::load_index_bytes(bytes);
      BOMWERK_TEST_CHECK(from_file.value.libraries.size() == from_memory.value.libraries.size());
      BOMWERK_TEST_CHECK(from_file.value.files.size() == from_memory.value.files.size());
      BOMWERK_TEST_CHECK(from_file.value.release_refs == from_memory.value.release_refs);
      BOMWERK_TEST_CHECK(same_warnings(from_file.warnings, from_memory.warnings));
    }
    bomwerk::heuristics::fingerprint::LoadLimits tight;
    tight.max_index_bytes = index.size() - 1;
    TempTree tree;
    tree.write("index.json", index);
    BOMWERK_TEST_CHECK(same_warnings(
        bomwerk::heuristics::fingerprint::load_index(tree.root() / "index.json", tight).warnings,
        bomwerk::heuristics::fingerprint::load_index_bytes(index, tight).warnings));
    BOMWERK_TEST_CHECK(
        !bomwerk::heuristics::fingerprint::load_index_bytes(index).value.files.empty());
  }

  // Given a bomwerk.toml with known, unknown and wrong-typed keys, and one
  // that is not TOML, when loaded from a file and parsed from memory, then the
  // warnings agree.
  {
    for (const std::string& config :
         {std::string("[scan]\nexclude = [\"vendor\"]\n[mystery]\nkey = 1\n"),
          std::string("[scan]\nexclude = 7\n"), std::string("not = [toml\n"), std::string()})
    {
      TempTree tree;
      tree.write("bomwerk.toml", config);
      const fs::path path = tree.root() / "bomwerk.toml";
      const auto from_file = bomwerk::core::load_scan_config(path);
      const auto from_memory = bomwerk::core::parse_scan_config(config, path);
      BOMWERK_TEST_CHECK(same_warnings(from_file.warnings, from_memory.warnings));
      BOMWERK_TEST_CHECK(from_file.value.exclude_paths == from_memory.value.exclude_paths);
    }
    const std::string oversized(1024u * 1024u + 1u, '#');
    BOMWERK_TEST_CHECK(
        bomwerk::core::parse_scan_config(oversized, "bomwerk.toml").warnings.size() == 1);
  }

  // Given a real vendored zlib.h, when matched in memory inside a folder named
  // for zlib, then it is recognized; the hostile copy whose version string is
  // unterminated is not; and every table row can be tried without restating
  // the tables.
  {
    const std::string zlib_header =
        read_fixture("golden/cpp-vendored/tree/third_party/zlib/zlib.h");
    BOMWERK_TEST_CHECK(!zlib_header.empty());
    const std::optional<bomwerk::heuristics::vendored_cpp::VersionHeaderMatch> match =
        bomwerk::heuristics::vendored_cpp::match_version_header("zlib", "zlib/zlib.h", zlib_header);
    BOMWERK_TEST_CHECK(match.has_value());
    BOMWERK_TEST_CHECK(match->canonical_name == "zlib");
    BOMWERK_TEST_CHECK(!match->version.empty());
    BOMWERK_TEST_CHECK(!bomwerk::heuristics::vendored_cpp::version_header_signatures().empty());
    BOMWERK_TEST_CHECK(!bomwerk::heuristics::vendored_cpp::match_version_header(
                            "zlib", "zlib/zlib.h", read_fixture("vendored_cpp/hostile/zlib.h"))
                            .has_value());
    BOMWERK_TEST_CHECK(!bomwerk::heuristics::vendored_cpp::match_version_header(
                            "zlib", "zlib/unrelated.h", zlib_header)
                            .has_value());
  }

  // Given well-formed and hostile network payloads, when parsed from memory,
  // then well-formed ones yield their content and hostile ones degrade to
  // "malformed" or empty without throwing.
  {
    const auto detection = bomwerk::vuln::parse_osv_detection_payload(
        R"({"vulns":[{"id":"GHSA-xxxx-yyyy-zzzz","modified":"2024-01-01T00:00:00Z"}]})");
    BOMWERK_TEST_CHECK(!detection.malformed);
    BOMWERK_TEST_CHECK(detection.advisory_revisions.size() == 1);
    BOMWERK_TEST_CHECK(bomwerk::vuln::parse_osv_detection_payload("{\"vulns\":").malformed);
    BOMWERK_TEST_CHECK(bomwerk::vuln::parse_osv_full_payload("[[[[").empty());
    BOMWERK_TEST_CHECK(bomwerk::vuln::parse_nvd_cve_payload("not json").malformed);
    BOMWERK_TEST_CHECK(
        !bomwerk::vuln::parse_registry_license_payload(bomwerk::vuln::LicenseRegistry::PyPi, "{")
             .usable_shape);
    BOMWERK_TEST_CHECK(
        !bomwerk::vuln::parse_cached_license_payload(std::string(200, '[')).usable_shape);
  }

  std::puts("test_in_memory_readers: OK");
  return 0;
}
