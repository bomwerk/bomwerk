// ctest unit test for the bounded file-read helpers (core/file_io).
#include <cassert>
#include <cstdio>
#include <string>

#include "core/file_io.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::BoundedFileRead;
using bomwerk::core::read_file_bounded;
using bomwerk::core::read_first_line_bounded;
using bomwerk::test::TempTree;

int main()
{
  // Given a file smaller than the cap, when read, then the whole content comes
  // back untruncated.
  {
    TempTree tree;
    tree.write("small.txt", "abc");
    const BoundedFileRead outcome = read_file_bounded(tree.root() / "small.txt", 100);
    assert(outcome.readable);
    assert(!outcome.truncated);
    assert(outcome.bytes == "abc");
  }

  // Given a file larger than the cap, when read, then only the first max_bytes
  // come back and the truncation is reported: never an unbounded read.
  {
    TempTree tree;
    tree.write("big.txt", "abcdef");
    const BoundedFileRead outcome = read_file_bounded(tree.root() / "big.txt", 2);
    assert(outcome.readable);
    assert(outcome.truncated);
    assert(outcome.bytes == "ab");
  }

  // Given a file of exactly the cap size, when read, then it is complete and
  // NOT reported truncated (the boundary case).
  {
    TempTree tree;
    tree.write("exact.txt", "abcd");
    const BoundedFileRead outcome = read_file_bounded(tree.root() / "exact.txt", 4);
    assert(outcome.readable);
    assert(!outcome.truncated);
    assert(outcome.bytes == "abcd");
  }

  // Given a missing file, when read, then readable is false and bytes empty :
  // no throw, no error state beyond the flag.
  {
    TempTree tree;
    const BoundedFileRead outcome = read_file_bounded(tree.root() / "absent.txt", 100);
    assert(!outcome.readable);
    assert(outcome.bytes.empty());
  }

  // Given a multi-line file with surrounding whitespace, when the first line is
  // read, then it comes back alone and trimmed.
  {
    TempTree tree;
    tree.write("lines.txt", "  ref: refs/heads/main \r\nsecond line\n");
    assert(read_first_line_bounded(tree.root() / "lines.txt", 4096) == "ref: refs/heads/main");
  }

  // Given a missing file, when the first line is read, then it is empty.
  {
    TempTree tree;
    assert(read_first_line_bounded(tree.root() / "absent.txt", 4096).empty());
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
    assert(read_first_line_bounded(tree.root() / "nul.txt", 4096) == expected);
  }

  std::puts("test_file_io: OK");
  return 0;
}
