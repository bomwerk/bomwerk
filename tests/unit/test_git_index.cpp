// ctest unit test for the git index reader (core/git_index.hpp, T110).
//
// The well-formed inputs are real git output: fixtures/gitindex/*.index, built
// by scripts/make_gitindex_fixtures.py with `git update-index` (see
// fixtures/gitindex/SOURCES.md). The hostile inputs are those same bytes with
// one field broken at a time, so each case states exactly which check it
// probes, and a reader that agrees with real git is also shown to refuse
// everything else.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "core/git_config.hpp"
#include "core/git_index.hpp"
#include "core/warning_code.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Gitlink;
using bomwerk::core::GitObjectFormat;
using bomwerk::core::Result;
using bomwerk::core::WarningCode;
using bomwerk::test::TempTree;
namespace core = bomwerk::core;

namespace
{

// The synthetic pins scripts/make_gitindex_fixtures.py records.
const std::string kOpensslCommit = "fedcba9876543210fedcba9876543210fedcba98";
const std::string kZlibCommit = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c";
const std::string kMbedtlsCommit = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d";
const std::string kOpensslCommitSha256 =
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

constexpr std::size_t kSha1ChecksumBytes = 20;
constexpr std::size_t kVersionOffset = 4;
constexpr std::size_t kEntryCountOffset = 8;
constexpr std::size_t kFirstEntryOffset = 12;
/// In a SHA-1 index: 40 bytes of stat data, then the 20-byte object id.
constexpr std::size_t kFirstEntryFlagsOffset = kFirstEntryOffset + 40 + 20;
constexpr std::size_t kFirstEntryNameOffset = kFirstEntryFlagsOffset + 2;

std::string read_fixture(std::string_view name)
{
  const fs::path path = fs::path(BOMWERK_FIXTURES_DIR) / "gitindex" / name;
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  BOMWERK_TEST_CHECK(!buffer.str().empty());
  return buffer.str();
}

Result<std::vector<Gitlink>> parse_sha1(const std::string& bytes)
{
  return core::parse_git_index_gitlinks(bytes, GitObjectFormat::Sha1, "index");
}

/// The whole index was refused: nothing returned, one BW-GIT-007 explaining it.
bool is_refused(const Result<std::vector<Gitlink>>& result)
{
  return result.value.empty() && result.warnings.size() == 1 &&
         result.warnings.front().code == WarningCode::kGitIndexUnreadable;
}

bool refusal_mentions(const Result<std::vector<Gitlink>>& result, std::string_view phrase)
{
  return is_refused(result) && result.warnings.front().message.find(phrase) != std::string::npos;
}

/// The three gitlinks every "standard" fixture records, in path order.
bool has_standard_gitlinks(const Result<std::vector<Gitlink>>& result)
{
  return result.warnings.empty() && result.value.size() == 3 &&
         result.value[0].path == "libs/mbedtls" && result.value[0].commit == kMbedtlsCommit &&
         result.value[1].path == "libs/zlib" && result.value[1].commit == kZlibCommit &&
         result.value[2].path == "third_party/openssl" && result.value[2].commit == kOpensslCommit;
}

void put_u32(std::string& bytes, std::size_t offset, std::uint32_t value)
{
  constexpr unsigned kBitsPerByte = 8;
  constexpr std::uint32_t kByteMask = 0xFF;
  for (std::size_t byte_index = 0; byte_index < 4; ++byte_index)
  {
    const unsigned shift = kBitsPerByte * static_cast<unsigned>(3 - byte_index);
    bytes[offset + byte_index] = static_cast<char>((value >> shift) & kByteMask);
  }
}

std::size_t offset_of(const std::string& bytes, std::string_view needle)
{
  const std::size_t offset = bytes.find(needle);
  BOMWERK_TEST_CHECK(offset != std::string::npos);
  return offset;
}

/// `bytes` with `extra` inserted just before the trailing checksum, where
/// extensions live. The checksum is not verified, so it needs no update.
std::string with_bytes_before_checksum(const std::string& bytes, const std::string& extra)
{
  std::string result = bytes;
  result.insert(result.size() - kSha1ChecksumBytes, extra);
  return result;
}

std::string big_endian_u32(std::uint32_t value)
{
  std::string bytes(4, '\0');
  put_u32(bytes, 0, value);
  return bytes;
}

}  // namespace

int main()
{
  const std::string v2 = read_fixture("v2-sha1.index");

  // --- What real git writes ---------------------------------------------------

  // Given index v2, v3 (an extended skip-worktree flag) and v4 (prefix-
  // compressed paths) holding the same entries, when read, then each yields
  // exactly the three gitlinks with their pins, sorted by path, and never the
  // regular files beside them.
  {
    BOMWERK_TEST_CHECK(has_standard_gitlinks(parse_sha1(v2)));
    BOMWERK_TEST_CHECK(has_standard_gitlinks(parse_sha1(read_fixture("v3-skip-worktree.index"))));
    BOMWERK_TEST_CHECK(has_standard_gitlinks(parse_sha1(read_fixture("v4-sha1.index"))));
  }

  // Given a SHA-256 repository's index, when read as SHA-256, then the pins are
  // 64 hex characters; when read as SHA-1 (the config was missed), then the
  // shifted fields fail the structural checks and the index is refused rather
  // than yielding a 40-character fragment of the real id.
  {
    const std::string sha256 = read_fixture("v2-sha256.index");
    const auto as_sha256 = core::parse_git_index_gitlinks(sha256, GitObjectFormat::Sha256, "index");
    BOMWERK_TEST_CHECK(as_sha256.warnings.empty());
    BOMWERK_TEST_CHECK(as_sha256.value.size() == 3);
    BOMWERK_TEST_CHECK(as_sha256.value[2].path == "third_party/openssl");
    BOMWERK_TEST_CHECK(as_sha256.value[2].commit == kOpensslCommitSha256);
    BOMWERK_TEST_CHECK(is_refused(parse_sha1(sha256)));
  }

  // Given a split index, when read, then it is refused: its own entries are
  // only a delta against a shared index file, so an absent gitlink there would
  // not mean an absent submodule.
  {
    BOMWERK_TEST_CHECK(refusal_mentions(parse_sha1(read_fixture("split.index")), "split index"));
  }

  // Given a gitlink present only at merge-conflict stages 1 to 3 beside a
  // stage-0 one, when read, then only the stage-0 pin is reported, without a
  // warning: a conflicted submodule simply has no single pin.
  {
    const auto result = parse_sha1(read_fixture("conflict.index"));
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].path == "third_party/openssl");
  }

  // Given a path of exactly 0xFFF bytes, where the 12-bit length field
  // saturates, when read, then the NUL terminator decides the length and the
  // full path comes back. One past the reader's 4096-byte cap is refused.
  {
    const auto saturated = parse_sha1(read_fixture("long-path.index"));
    BOMWERK_TEST_CHECK(saturated.warnings.empty());
    BOMWERK_TEST_CHECK(saturated.value.size() == 1);
    BOMWERK_TEST_CHECK(saturated.value[0].path.size() == 0xFFF);
    BOMWERK_TEST_CHECK(saturated.value[0].commit == kZlibCommit);
    BOMWERK_TEST_CHECK(
        refusal_mentions(parse_sha1(read_fixture("path-over-limit.index")), "longer than"));
  }

  // Given an unknown extension between the entries and the checksum, when
  // read, then it is skipped by its declared size and the gitlinks still come
  // back: only a split index changes what the entries mean.
  {
    const std::string extension = "ABCD" + big_endian_u32(4) + "wxyz";
    BOMWERK_TEST_CHECK(
        has_standard_gitlinks(parse_sha1(with_bytes_before_checksum(v2, extension))));
  }

  // Given a sparse index (the `sdir` extension), when read, then it is refused: a gitlink
  // inside a collapsed directory would otherwise be missing without any explanation.
  {
    const std::string sparse_marker = "sdir" + big_endian_u32(0);
    BOMWERK_TEST_CHECK(refusal_mentions(parse_sha1(with_bytes_before_checksum(v2, sparse_marker)),
                                        "sparse index"));
  }

  // Given a gitlink whose object id is all zeros, when read, then it is not
  // reported (there is no pin to report) and the rest of the index still is.
  {
    std::string bytes = v2;
    const std::string openssl_id =
        "\xfe\xdc\xba\x98\x76\x54\x32\x10\xfe\xdc\xba\x98\x76\x54\x32\x10"
        "\xfe\xdc\xba\x98";
    bytes.replace(offset_of(bytes, openssl_id), openssl_id.size(), openssl_id.size(), '\0');
    const auto result = parse_sha1(bytes);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
  }

  // --- Hostile input: refused as a whole, never misread, never a crash ---------

  // Given a wrong signature, when read, then the index is refused.
  {
    std::string bytes = v2;
    bytes[0] = 'X';
    BOMWERK_TEST_CHECK(refusal_mentions(parse_sha1(bytes), "DIRC"));
  }

  // Given every strict prefix of a real index (a header cut short, an entry
  // cut short, the checksum cut off), when read, then each is refused: a
  // truncated index never yields a partial list.
  {
    for (std::size_t length = 0; length < v2.size(); ++length)
    {
      BOMWERK_TEST_CHECK(is_refused(parse_sha1(v2.substr(0, length))));
    }
  }

  // Given versions the reader does not know (1, 5) or an absurd entry count,
  // when read, then each is refused before any entry is walked.
  {
    std::string version_one = v2;
    put_u32(version_one, kVersionOffset, 1);
    BOMWERK_TEST_CHECK(refusal_mentions(parse_sha1(version_one), "unsupported index version 1"));
    std::string version_five = v2;
    put_u32(version_five, kVersionOffset, 5);
    BOMWERK_TEST_CHECK(refusal_mentions(parse_sha1(version_five), "unsupported index version 5"));
    std::string absurd_count = v2;
    put_u32(absurd_count, kEntryCountOffset, 0xFFFFFFFFu);
    BOMWERK_TEST_CHECK(refusal_mentions(parse_sha1(absurd_count), "cannot fit"));
  }

  // Given an entry whose name runs to the end of the file with no NUL, when
  // read, then the index is refused rather than taking the bytes as a path.
  {
    std::string bytes = v2;
    const std::size_t content_end = bytes.size() - kSha1ChecksumBytes;
    const std::size_t last_name = offset_of(bytes, "third_party/openssl");
    bytes.replace(last_name, content_end - last_name, content_end - last_name, 'a');
    BOMWERK_TEST_CHECK(refusal_mentions(parse_sha1(bytes), "unterminated"));
  }

  // Given a first entry (".gitmodules", 11 bytes) whose length field says 10,
  // or whose NUL padding carries a stray byte, or that sets the extended flag
  // in a version 2 index, when read, then each is refused.
  {
    std::string wrong_length = v2;
    wrong_length[kFirstEntryFlagsOffset + 1] = 10;
    BOMWERK_TEST_CHECK(refusal_mentions(parse_sha1(wrong_length), "disagrees"));

    std::string dirty_padding = v2;
    dirty_padding[kFirstEntryNameOffset + 11 + 1] = 'x';
    BOMWERK_TEST_CHECK(refusal_mentions(parse_sha1(dirty_padding), "padding"));

    std::string extended_in_v2 = v2;
    extended_in_v2[kFirstEntryFlagsOffset] =
        static_cast<char>(extended_in_v2[kFirstEntryFlagsOffset] | 0x40);
    BOMWERK_TEST_CHECK(refusal_mentions(parse_sha1(extended_in_v2), "extended flags"));
  }

  // Given a v4 index whose first entry claims to strip bytes from a previous
  // path that does not exist, when read, then it is refused.
  {
    std::string bytes = read_fixture("v4-sha1.index");
    bytes[kFirstEntryNameOffset] = 5;
    BOMWERK_TEST_CHECK(refusal_mentions(parse_sha1(bytes), "strips more"));
  }

  // Given a gitlink path that climbs out of the repository, when read, then
  // the index is refused: git never writes one, so it is not git's index.
  {
    std::string bytes = v2;
    bytes.replace(offset_of(bytes, "libs/zlib"), 9, "../b/zlib");
    BOMWERK_TEST_CHECK(refusal_mentions(parse_sha1(bytes), "escapes"));
  }

  // Given bytes after the last entry that are too few for an extension
  // header, or an extension whose declared size runs past the checksum, when
  // read, then the index is refused.
  {
    BOMWERK_TEST_CHECK(
        refusal_mentions(parse_sha1(with_bytes_before_checksum(v2, "abc")), "stray"));
    const std::string oversized_extension = "TREE" + big_endian_u32(0xFFFFFFFFu);
    BOMWERK_TEST_CHECK(refusal_mentions(
        parse_sha1(with_bytes_before_checksum(v2, oversized_extension)), "past the checksum"));
  }

  // --- Reading from a git dir --------------------------------------------------

  // Given a git dir holding a real index, when read, then it matches the
  // in-memory parse; given a git dir with no index at all, then the result is
  // empty and silent (an export without one is not an error).
  {
    TempTree tree;
    tree.write(".git/index", v2);
    BOMWERK_TEST_CHECK(has_standard_gitlinks(
        core::read_git_index_gitlinks(tree.root() / ".git", GitObjectFormat::Sha1)));

    TempTree empty_tree;
    empty_tree.write(".git/HEAD", "ref: refs/heads/main\n");
    const auto absent =
        core::read_git_index_gitlinks(empty_tree.root() / ".git", GitObjectFormat::Sha1);
    BOMWERK_TEST_CHECK(absent.value.empty());
    BOMWERK_TEST_CHECK(absent.warnings.empty());
  }

  // Given an index one byte over the cap (a sparse file, so the test stays
  // cheap), when read, then it is refused by size before a byte is loaded.
  {
    TempTree tree;
    tree.write(".git/index", "");
    std::error_code resize_error;
    fs::resize_file(tree.root() / ".git" / "index", core::kMaxGitIndexBytes + 1, resize_error);
    BOMWERK_TEST_CHECK(!resize_error);
    BOMWERK_TEST_CHECK(refusal_mentions(
        core::read_git_index_gitlinks(tree.root() / ".git", GitObjectFormat::Sha1), "cap"));
  }

  // Given an index that is a symlink (it could point anywhere on the scanning
  // machine), when read, then it is refused and never followed.
  {
    TempTree tree;
    tree.write("elsewhere/index", v2);
    fs::create_directories(tree.root() / ".git");
    std::error_code link_error;
    fs::create_symlink(tree.root() / "elsewhere" / "index", tree.root() / ".git" / "index",
                       link_error);
    if (!link_error)  // a filesystem without symlinks has nothing to probe here
    {
      BOMWERK_TEST_CHECK(refusal_mentions(
          core::read_git_index_gitlinks(tree.root() / ".git", GitObjectFormat::Sha1), "symlink"));
    }
  }

  // --- Object format from .git/config ------------------------------------------

  // Given `extensions.objectFormat` set to sha256 in any case, then the format
  // is SHA-256; given no such key, then git's default SHA-1.
  {
    const auto sha256_config =
        core::parse_git_config("[extensions]\n\tobjectFormat = SHA256\n", "config");
    BOMWERK_TEST_CHECK(core::object_format_of(sha256_config.value) == GitObjectFormat::Sha256);
    const auto plain_config = core::parse_git_config("[core]\n\tbare = false\n", "config");
    BOMWERK_TEST_CHECK(core::object_format_of(plain_config.value) == GitObjectFormat::Sha1);
  }

  std::puts("test_git_index: OK");
  return 0;
}
