// ctest unit test for the `ar` reader (binscan/archive_read.hpp):
// bytes -> member names + symbol-index sample, in both dialects.
//
// Both dialects matter and neither is hypothetical: a vendored `.a` checked
// into a repository may have been produced by either toolchain, and they spell
// long names and the symbol index completely differently. As in
// test_elf_read.cpp, every fixture is written out rather than produced by the
// host `ar`, so the same bytes are tested on the Linux and macOS runners.
#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

#include "binscan/archive_read.hpp"
#include "core/result.hpp"
#include "support/archive_builder.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::binscan::ArchiveContents;
using bomwerk::binscan::read_archive;
using bomwerk::core::Result;
using bomwerk::test::ArchiveBuildOptions;
using bomwerk::test::ArchiveMember;
using bomwerk::test::build_archive;
using bomwerk::test::TempTree;

namespace
{

Result<ArchiveContents> read_bytes(const TempTree& tree, const std::string& name,
                                   const std::string& bytes)
{
  tree.write(name, bytes);
  return read_archive(tree.root() / name);
}

bool contains(const std::vector<std::string>& values, const std::string& wanted)
{
  return std::find(values.begin(), values.end(), wanted) != values.end();
}

}  // namespace

int main()
{
  TempTree tree;

  // Given a plain GNU archive with short names, when read, then every member
  // and every indexed symbol comes back, and the archive's own bookkeeping
  // members do not -- an SBOM reader asking what is inside an archive means
  // the objects, not the index.
  {
    ArchiveBuildOptions options;
    options.members = {{"aes.o", "aes"}, {"sha256.o", "sha"}};
    options.indexed_symbols = {"AES_encrypt", "SHA256_Init"};
    const Result<ArchiveContents> archive =
        read_bytes(tree, "libvendcrypto.a", build_archive(options));

    BOMWERK_TEST_CHECK(archive.value.is_archive);
    BOMWERK_TEST_CHECK(archive.value.member_names.size() == 2);
    BOMWERK_TEST_CHECK(contains(archive.value.member_names, "aes.o"));
    BOMWERK_TEST_CHECK(contains(archive.value.member_names, "sha256.o"));
    BOMWERK_TEST_CHECK(!contains(archive.value.member_names, "/"));
    BOMWERK_TEST_CHECK(contains(archive.value.indexed_symbols, "AES_encrypt"));
    BOMWERK_TEST_CHECK(contains(archive.value.indexed_symbols, "SHA256_Init"));
    BOMWERK_TEST_CHECK(!archive.value.symbols_unavailable);
    BOMWERK_TEST_CHECK(archive.warnings.empty());
  }

  // Given a GNU archive whose names live in the `//` string table, when read,
  // then the `/<offset>` spellings resolve through it. A name too long for the
  // 16-byte field is the normal case for any real C++ build, so this path is
  // not an edge case at all.
  {
    ArchiveBuildOptions options;
    options.members = {{"a-very-long-object-name.cpp.o", "x"}, {"short.o", "y"}};
    options.indexed_symbols = {"_Z3foov"};
    const Result<ArchiveContents> archive = read_bytes(tree, "longnames.a", build_archive(options));

    BOMWERK_TEST_CHECK(contains(archive.value.member_names, "a-very-long-object-name.cpp.o"));
    BOMWERK_TEST_CHECK(contains(archive.value.member_names, "short.o"));
    BOMWERK_TEST_CHECK(!contains(archive.value.member_names, "//"));
  }

  // Given a GNU archive that puts EVERY name in the table, when read, then
  // short names resolve through it too -- the `//` indirection is not reserved
  // for long names, and a reader that only consulted it past 15 characters
  // would silently lose members.
  {
    ArchiveBuildOptions options;
    options.members = {{"a.o", "1"}, {"b.o", "2"}};
    options.force_long_name_table = true;
    options.include_symbol_index = false;
    const Result<ArchiveContents> archive = read_bytes(tree, "alltable.a", build_archive(options));

    BOMWERK_TEST_CHECK(archive.value.member_names.size() == 2);
    BOMWERK_TEST_CHECK(contains(archive.value.member_names, "a.o"));
    BOMWERK_TEST_CHECK(contains(archive.value.member_names, "b.o"));
  }

  // Given a BSD archive, when read, then `#1/<length>` names resolve out of
  // each member's own payload -- and the symbol sample is declared
  // UNAVAILABLE rather than guessed. `__.SYMDEF` stores its counts in the
  // producing host's native byte order, which the archive does not record, so
  // reading it would mean guessing an endianness; a wrong guess yields
  // plausible garbage rather than an error, which is the one outcome worth
  // refusing outright.
  {
    ArchiveBuildOptions options;
    options.members = {{"bsd-object-with-long-name.o", "data"}, {"tiny.o", "d"}};
    options.indexed_symbols = {"unused"};
    options.bsd_long_names = true;
    options.bsd_symbol_index = true;
    const Result<ArchiveContents> archive = read_bytes(tree, "bsd.a", build_archive(options));

    BOMWERK_TEST_CHECK(archive.value.is_archive);
    BOMWERK_TEST_CHECK(contains(archive.value.member_names, "bsd-object-with-long-name.o"));
    BOMWERK_TEST_CHECK(contains(archive.value.member_names, "tiny.o"));
    BOMWERK_TEST_CHECK(archive.value.indexed_symbols.empty());
    BOMWERK_TEST_CHECK(archive.value.symbols_unavailable);
  }

  // Given an archive holding nothing but its magic, when read, then it is
  // recognized as an archive with no members -- an empty `.a` is something a
  // real build produces (a library whose sources were all excluded), and
  // reporting it as unreadable would be wrong.
  {
    const Result<ArchiveContents> archive = read_bytes(tree, "empty.a", "!<arch>\n");
    BOMWERK_TEST_CHECK(archive.value.is_archive);
    BOMWERK_TEST_CHECK(archive.value.member_names.empty());
    BOMWERK_TEST_CHECK(archive.warnings.empty());
  }

  // Given a member header cut off by the end of the file, when read, then the
  // members already collected survive and the run warns. Partial output beats
  // none (rule 1): a partly readable archive still names what it got through.
  {
    ArchiveBuildOptions options;
    options.members = {{"first.o", "aaaa"}, {"second.o", "bbbb"}};
    options.include_symbol_index = false;
    const std::string full = build_archive(options);
    const Result<ArchiveContents> archive =
        read_bytes(tree, "cut-header.a", full.substr(0, full.size() - 30));

    BOMWERK_TEST_CHECK(archive.value.is_archive);
    BOMWERK_TEST_CHECK(contains(archive.value.member_names, "first.o"));
    BOMWERK_TEST_CHECK(archive.value.members_truncated);
    BOMWERK_TEST_CHECK(!archive.warnings.empty());
  }

  // Given a member declaring a size that runs past the end of the file, when
  // read, then the walk stops there rather than slicing memory it does not
  // own. This is the archive equivalent of a section header pointing outside
  // the file, and it must degrade, not fault.
  {
    ArchiveBuildOptions options;
    options.members = {{"first.o", "aaaa"}};
    options.include_symbol_index = false;
    std::string bytes = build_archive(options);
    // The size field is the last 10 bytes before the "`\n" trailer of the
    // first (and only) member header, which begins right after the 8-byte
    // magic.
    constexpr std::size_t kFirstSizeField = 8 + 48;
    bytes.replace(kFirstSizeField, 10, "9999999999");
    const Result<ArchiveContents> archive = read_bytes(tree, "oversized-member.a", bytes);

    BOMWERK_TEST_CHECK(archive.value.is_archive);
    BOMWERK_TEST_CHECK(archive.value.member_names.empty());
    BOMWERK_TEST_CHECK(archive.value.members_truncated);
    BOMWERK_TEST_CHECK(!archive.warnings.empty());
  }

  // Given a member header whose size field is not a number, when read, then
  // the walk stops rather than treating garbage as zero -- `std::stoull` would
  // have thrown here, which is why the field is parsed by hand (rule 1).
  {
    ArchiveBuildOptions options;
    options.members = {{"first.o", "aaaa"}};
    options.include_symbol_index = false;
    std::string bytes = build_archive(options);
    constexpr std::size_t kFirstSizeField = 8 + 48;
    bytes.replace(kFirstSizeField, 10, "not-a-num ");
    const Result<ArchiveContents> archive = read_bytes(tree, "bad-size.a", bytes);

    BOMWERK_TEST_CHECK(archive.value.members_truncated);
    BOMWERK_TEST_CHECK(!archive.warnings.empty());
  }

  // Given bytes that are not an archive at all, when read, then they are
  // reported as such without a warning -- the caller aggregates that, exactly
  // as it does for a non-ELF file.
  {
    const Result<ArchiveContents> text = read_bytes(tree, "notes.txt", "placeholder archive\n");
    BOMWERK_TEST_CHECK(!text.value.is_archive);
    BOMWERK_TEST_CHECK(text.warnings.empty());

    const Result<ArchiveContents> empty = read_bytes(tree, "nothing.a", "");
    BOMWERK_TEST_CHECK(!empty.value.is_archive);
  }

  // Given a path that does not exist, when read, then it warns and returns an
  // empty record rather than throwing.
  {
    const Result<ArchiveContents> archive = read_archive(tree.root() / "absent.a");
    BOMWERK_TEST_CHECK(!archive.value.is_archive);
    BOMWERK_TEST_CHECK(!archive.warnings.empty());
  }

  // Given one archive read twice, when the results are compared, then they are
  // identical, sorted and deduplicated (rule 3).
  {
    ArchiveBuildOptions options;
    options.members = {{"zeta.o", "z"}, {"alpha.o", "a"}, {"middle.o", "m"}};
    options.indexed_symbols = {"z_symbol", "a_symbol"};
    const std::string bytes = build_archive(options);
    const Result<ArchiveContents> first = read_bytes(tree, "order-a.a", bytes);
    const Result<ArchiveContents> second = read_bytes(tree, "order-b.a", bytes);

    BOMWERK_TEST_CHECK(first.value.member_names == second.value.member_names);
    BOMWERK_TEST_CHECK(first.value.indexed_symbols == second.value.indexed_symbols);
    BOMWERK_TEST_CHECK(
        std::is_sorted(first.value.member_names.begin(), first.value.member_names.end()));
    BOMWERK_TEST_CHECK(
        std::is_sorted(first.value.indexed_symbols.begin(), first.value.indexed_symbols.end()));
  }

  return 0;
}
