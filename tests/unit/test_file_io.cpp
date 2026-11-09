// ctest unit test for the bounded file-read and file-digest helpers
// (core/file_io).
#include <cstddef>
#include <cstdio>
#include <string>

#include "core/file_io.hpp"
#include "core/sha256.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::bound_in_memory_bytes;
using bomwerk::core::BoundedFileDigest;
using bomwerk::core::BoundedFileFastHash;
using bomwerk::core::BoundedFileRead;
using bomwerk::core::read_file_bounded;
using bomwerk::core::read_first_line_bounded;
using bomwerk::core::sha256;
using bomwerk::core::sha256_file_bounded;
using bomwerk::core::Sha256Digest;
using bomwerk::core::to_hex;
using bomwerk::core::xxh3_file_bounded;
using bomwerk::test::TempTree;

namespace
{

/// Content long enough to cross the 64 KiB hashing chunk several times, so a
/// whole-file digest is exercised across chunk boundaries and not only inside
/// one buffer.
std::string multi_chunk_content()
{
  std::string content;
  content.reserve(200000);
  for (std::size_t index = 0; index < 200000; ++index)
  {
    content.push_back(static_cast<char>(index % 251));
  }
  return content;
}

/// A whole-file digest has to equal the digest of the same bytes in memory, or
/// an index built by one route can never match a scan taking the other.
void whole_file_digests_equal_the_in_memory_digest()
{
  TempTree tree;
  tree.write("empty.bin", "");
  tree.write("small.bin", "abc");
  const std::string long_content = multi_chunk_content();
  tree.write("long.bin", long_content);
  const std::string binary_content("a\0b\0\0c", 6);
  tree.write("binary.bin", binary_content);

  const BoundedFileDigest empty = sha256_file_bounded(tree.root() / "empty.bin", 1024);
  BOMWERK_TEST_CHECK(empty.readable);
  BOMWERK_TEST_CHECK(!empty.over_limit);
  BOMWERK_TEST_CHECK(empty.bytes_hashed == 0);
  BOMWERK_TEST_CHECK(to_hex(empty.digest) ==
                     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  const BoundedFileDigest small = sha256_file_bounded(tree.root() / "small.bin", 1024);
  BOMWERK_TEST_CHECK(small.bytes_hashed == 3);
  BOMWERK_TEST_CHECK(small.digest == sha256("abc"));

  const BoundedFileDigest long_file = sha256_file_bounded(tree.root() / "long.bin", 1024 * 1024);
  BOMWERK_TEST_CHECK(long_file.readable);
  BOMWERK_TEST_CHECK(!long_file.over_limit);
  BOMWERK_TEST_CHECK(long_file.bytes_hashed == long_content.size());
  BOMWERK_TEST_CHECK(long_file.digest == sha256(long_content));

  const BoundedFileDigest binary = sha256_file_bounded(tree.root() / "binary.bin", 1024);
  BOMWERK_TEST_CHECK(binary.bytes_hashed == 6);
  BOMWERK_TEST_CHECK(binary.digest == sha256(binary_content));
}

/// The deliberate asymmetry with `read_file_bounded`: a file over the cap is
/// refused outright, not hashed partially. A prefix digest is a DIFFERENT
/// value that would silently never match, so returning one would be worse than
/// admitting the file was skipped.
void an_oversized_file_is_refused_rather_than_hashed_partially()
{
  TempTree tree;
  tree.write("exact.bin", "abcd");
  tree.write("over.bin", "abcde");

  const BoundedFileDigest exact = sha256_file_bounded(tree.root() / "exact.bin", 4);
  BOMWERK_TEST_CHECK(exact.readable);
  BOMWERK_TEST_CHECK(!exact.over_limit);
  BOMWERK_TEST_CHECK(exact.bytes_hashed == 4);
  BOMWERK_TEST_CHECK(exact.digest == sha256("abcd"));

  const BoundedFileDigest over = sha256_file_bounded(tree.root() / "over.bin", 4);
  BOMWERK_TEST_CHECK(over.readable);
  BOMWERK_TEST_CHECK(over.over_limit);
  BOMWERK_TEST_CHECK(over.bytes_hashed == 0);
  BOMWERK_TEST_CHECK(over.digest == Sha256Digest{});
  BOMWERK_TEST_CHECK(over.digest != sha256("abcd"));

  const BoundedFileFastHash fast_over = xxh3_file_bounded(tree.root() / "over.bin", 4);
  BOMWERK_TEST_CHECK(fast_over.readable);
  BOMWERK_TEST_CHECK(fast_over.over_limit);
  BOMWERK_TEST_CHECK(fast_over.bytes_hashed == 0);
  BOMWERK_TEST_CHECK(fast_over.hash == 0);
}

/// A missing file degrades through the flag, the same way `read_file_bounded`
/// does: no throw and nothing for a caller to mistake for content (rule 1).
void a_missing_file_degrades_through_the_flag()
{
  TempTree tree;
  const BoundedFileDigest digest = sha256_file_bounded(tree.root() / "absent.bin", 1024);
  BOMWERK_TEST_CHECK(!digest.readable);
  BOMWERK_TEST_CHECK(!digest.over_limit);
  BOMWERK_TEST_CHECK(digest.bytes_hashed == 0);
  BOMWERK_TEST_CHECK(digest.digest == Sha256Digest{});

  const BoundedFileFastHash fast = xxh3_file_bounded(tree.root() / "absent.bin", 1024);
  BOMWERK_TEST_CHECK(!fast.readable);
  BOMWERK_TEST_CHECK(fast.hash == 0);
}

/// The cheap pass only has to be stable and content-dependent: equal bytes give
/// one value whatever the path, and different bytes separate. It is never an
/// identity, so nothing stronger is asserted here.
void the_fast_hash_is_content_addressed_and_stable()
{
  TempTree tree;
  const std::string content = multi_chunk_content();
  tree.write("one/same.bin", content);
  tree.write("two/same.bin", content);
  tree.write("other.bin", content + "x");

  const BoundedFileFastHash first = xxh3_file_bounded(tree.root() / "one/same.bin", 1024 * 1024);
  const BoundedFileFastHash second = xxh3_file_bounded(tree.root() / "two/same.bin", 1024 * 1024);
  const BoundedFileFastHash other = xxh3_file_bounded(tree.root() / "other.bin", 1024 * 1024);

  BOMWERK_TEST_CHECK(first.readable && second.readable && other.readable);
  BOMWERK_TEST_CHECK(first.bytes_hashed == content.size());
  BOMWERK_TEST_CHECK(first.hash == second.hash);
  BOMWERK_TEST_CHECK(first.hash != other.hash);
  BOMWERK_TEST_CHECK(xxh3_file_bounded(tree.root() / "one/same.bin", 1024 * 1024).hash ==
                     first.hash);
}

/// The cheap pass only works if the C++ scanner and the Python builder agree on
/// what a file's xxh3 value is. The empty-input value is the one published
/// XXH3_64bits answer both sides can be pinned to; validate_fingerprint_corpus.py
/// checks that the builder's hex form of it is the same digits.
void the_fast_hash_matches_the_published_empty_input_value()
{
  TempTree tree;
  tree.write("empty.bin", "");
  const BoundedFileFastHash empty = xxh3_file_bounded(tree.root() / "empty.bin", 1024);
  BOMWERK_TEST_CHECK(empty.readable);
  BOMWERK_TEST_CHECK(empty.hash == 0x2D06800538D394C2ull);
}

}  // namespace

int main()
{
  // Given bytes held in memory, when bounded at, above and below their size,
  // then each answer equals what read_file_bounded gives for the same file.
  {
    TempTree tree;
    tree.write("three.bin", "abc");
    for (const std::size_t max_bytes :
         {std::size_t{0}, std::size_t{2}, std::size_t{3}, std::size_t{4}})
    {
      const BoundedFileRead from_disk = read_file_bounded(tree.root() / "three.bin", max_bytes);
      const BoundedFileRead from_memory = bound_in_memory_bytes("abc", max_bytes);
      BOMWERK_TEST_CHECK(from_memory.readable);
      BOMWERK_TEST_CHECK(from_memory.bytes == from_disk.bytes);
      BOMWERK_TEST_CHECK(from_memory.truncated == from_disk.truncated);
    }
  }

  // Given an empty buffer, when bounded, then it is readable, empty and whole.
  {
    const BoundedFileRead empty = bound_in_memory_bytes("", 8);
    BOMWERK_TEST_CHECK(empty.readable);
    BOMWERK_TEST_CHECK(empty.bytes.empty());
    BOMWERK_TEST_CHECK(!empty.truncated);
  }

  // Given a file smaller than the cap, when read, then the whole content comes
  // back untruncated.
  {
    TempTree tree;
    tree.write("small.txt", "abc");
    const BoundedFileRead outcome = read_file_bounded(tree.root() / "small.txt", 100);
    BOMWERK_TEST_CHECK(outcome.readable);
    BOMWERK_TEST_CHECK(!outcome.truncated);
    BOMWERK_TEST_CHECK(outcome.bytes == "abc");
  }

  // Given a file larger than the cap, when read, then only the first max_bytes
  // come back and the truncation is reported: never an unbounded read.
  {
    TempTree tree;
    tree.write("big.txt", "abcdef");
    const BoundedFileRead outcome = read_file_bounded(tree.root() / "big.txt", 2);
    BOMWERK_TEST_CHECK(outcome.readable);
    BOMWERK_TEST_CHECK(outcome.truncated);
    BOMWERK_TEST_CHECK(outcome.bytes == "ab");
  }

  // Given a file of exactly the cap size, when read, then it is complete and
  // NOT reported truncated (the boundary case).
  {
    TempTree tree;
    tree.write("exact.txt", "abcd");
    const BoundedFileRead outcome = read_file_bounded(tree.root() / "exact.txt", 4);
    BOMWERK_TEST_CHECK(outcome.readable);
    BOMWERK_TEST_CHECK(!outcome.truncated);
    BOMWERK_TEST_CHECK(outcome.bytes == "abcd");
  }

  // Given a missing file, when read, then readable is false and bytes empty :
  // no throw, no error state beyond the flag.
  {
    TempTree tree;
    const BoundedFileRead outcome = read_file_bounded(tree.root() / "absent.txt", 100);
    BOMWERK_TEST_CHECK(!outcome.readable);
    BOMWERK_TEST_CHECK(outcome.bytes.empty());
  }

  // Given a multi-line file with surrounding whitespace, when the first line is
  // read, then it comes back alone and trimmed.
  {
    TempTree tree;
    tree.write("lines.txt", "  ref: refs/heads/main \r\nsecond line\n");
    BOMWERK_TEST_CHECK(read_first_line_bounded(tree.root() / "lines.txt", 4096) ==
                       "ref: refs/heads/main");
  }

  // Given a missing file, when the first line is read, then it is empty.
  {
    TempTree tree;
    BOMWERK_TEST_CHECK(read_first_line_bounded(tree.root() / "absent.txt", 4096).empty());
  }

  // Given content with an embedded NUL before the newline, when the first line
  // is read, then the NUL survives inside the line (binary-safe read).
  {
    TempTree tree;
    std::string content = "ab";
    content.push_back('\0');
    content += "cd\nrest\n";
    tree.write("nul.txt", content);
    std::string expected = "ab";
    expected.push_back('\0');
    expected += "cd";
    BOMWERK_TEST_CHECK(read_first_line_bounded(tree.root() / "nul.txt", 4096) == expected);
  }

  whole_file_digests_equal_the_in_memory_digest();
  an_oversized_file_is_refused_rather_than_hashed_partially();
  a_missing_file_degrades_through_the_flag();
  the_fast_hash_is_content_addressed_and_stable();
  the_fast_hash_matches_the_published_empty_input_value();

  std::puts("test_file_io: OK");
  return 0;
}
