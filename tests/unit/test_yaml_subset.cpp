// ctest unit test for the YAML-subset reader (framework-free).
// The shapes below are taken from real Yarn Berry and pnpm lockfiles, so a
// regression here is a regression against a real repository.
#include <cstddef>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "core/yaml_subset.hpp"
#include "support/check.hpp"

using bomwerk::core::yaml_subset::Node;
using bomwerk::core::yaml_subset::Reader;

namespace
{

/// One node, copied out of the reader so assertions can outlive the buffer.
struct CapturedNode
{
  std::size_t indentation = 0;
  std::string key;
  std::string value;
  bool opens_block = false;
  bool is_flow_mapping = false;
};

struct Scan
{
  std::vector<CapturedNode> nodes;
  std::size_t unsupported_line_count = 0;
};

/// Drain a reader completely: what every consumer's loop does.
Scan scan_all(std::string_view bytes)
{
  Scan scan;
  Reader reader(bytes);
  Node node;
  while (reader.next(node))
  {
    scan.nodes.push_back({node.indentation, std::string(node.key), std::string(node.value),
                          node.opens_block, node.is_flow_mapping});
  }
  scan.unsupported_line_count = reader.stats().unsupported_line_count;
  return scan;
}

}  // namespace

int main()
{
  // Given a Yarn Berry entry, when scanned, then the quoted entry key becomes a
  // block-opening node at indentation 0, its fields sit at 2, and a dependency
  // edge sits at 4: the indentation IS the grammar.
  {
    const Scan scan = scan_all(R"(# a comment line
__metadata:
  version: 8
  cacheKey: 10c0

"@scope/name@npm:^1.0.0, @scope/name@npm:^1.2.0":
  resolution: "@scope/name@npm:1.2.3"
  dependencies:
    tslib: "npm:^2.0.0"
  linkType: hard
)");
    BOMWERK_TEST_CHECK(scan.unsupported_line_count == 0);
    BOMWERK_TEST_CHECK(scan.nodes.size() == 8);

    BOMWERK_TEST_CHECK(scan.nodes[0].indentation == 0);
    BOMWERK_TEST_CHECK(scan.nodes[0].key == "__metadata");
    BOMWERK_TEST_CHECK(scan.nodes[0].opens_block);
    BOMWERK_TEST_CHECK(scan.nodes[1].indentation == 2);
    BOMWERK_TEST_CHECK(scan.nodes[1].key == "version");
    BOMWERK_TEST_CHECK(scan.nodes[1].value == "8");
    BOMWERK_TEST_CHECK(!scan.nodes[1].opens_block);

    // The whole multi-descriptor key is one quoted scalar: the ':' inside it is
    // part of the key, not the separator.
    BOMWERK_TEST_CHECK(scan.nodes[3].indentation == 0);
    BOMWERK_TEST_CHECK(scan.nodes[3].key == "@scope/name@npm:^1.0.0, @scope/name@npm:^1.2.0");
    BOMWERK_TEST_CHECK(scan.nodes[3].opens_block);
    BOMWERK_TEST_CHECK(scan.nodes[4].key == "resolution");
    BOMWERK_TEST_CHECK(scan.nodes[4].value == "@scope/name@npm:1.2.3");
    BOMWERK_TEST_CHECK(scan.nodes[5].key == "dependencies");
    BOMWERK_TEST_CHECK(scan.nodes[5].opens_block);
    BOMWERK_TEST_CHECK(scan.nodes[6].indentation == 4);
    BOMWERK_TEST_CHECK(scan.nodes[6].key == "tslib");
    BOMWERK_TEST_CHECK(scan.nodes[6].value == "npm:^2.0.0");
    BOMWERK_TEST_CHECK(scan.nodes[7].key == "linkType");
  }

  // Given a value carrying a literal '#' inside quotes: a Yarn patch locator :
  // when scanned, then the '#' survives and only the real trailing comment is
  // cut. Cutting at the first '#' would truncate the resolution and silently
  // produce the wrong component.
  {
    const Scan scan = scan_all(
        "  resolution: \"pkg@patch:pkg@npm%3A1.0.0#./p.patch::version=1.0.0\"  # trailing\n");
    BOMWERK_TEST_CHECK(scan.nodes.size() == 1);
    BOMWERK_TEST_CHECK(scan.nodes[0].key == "resolution");
    BOMWERK_TEST_CHECK(scan.nodes[0].value == "pkg@patch:pkg@npm%3A1.0.0#./p.patch::version=1.0.0");
  }

  // Given a '#' that is not preceded by whitespace, when scanned, then it is
  // part of the value: a URL fragment is not a comment.
  {
    const Scan scan = scan_all("resolved: https://example.com/x.tgz#sha1\n");
    BOMWERK_TEST_CHECK(scan.nodes.size() == 1);
    BOMWERK_TEST_CHECK(scan.nodes[0].value == "https://example.com/x.tgz#sha1");
  }

  // Given pnpm's spelling: single-quoted keys and one-line flow mappings :
  // when scanned, then the quotes come off and the flow mapping is handed back
  // as its raw inner text rather than mistaken for a scalar or a block.
  {
    const Scan scan = scan_all(R"(  '@adobe/css-tools@4.4.4':
    resolution: {integrity: sha512-Elp+iwUx5rN5==}
)");
    BOMWERK_TEST_CHECK(scan.unsupported_line_count == 0);
    BOMWERK_TEST_CHECK(scan.nodes.size() == 2);
    BOMWERK_TEST_CHECK(scan.nodes[0].key == "@adobe/css-tools@4.4.4");
    BOMWERK_TEST_CHECK(scan.nodes[0].opens_block);
    BOMWERK_TEST_CHECK(scan.nodes[1].is_flow_mapping);
    BOMWERK_TEST_CHECK(scan.nodes[1].value == "integrity: sha512-Elp+iwUx5rN5==");
  }

  // Given constructs outside the subset, when scanned, then each is counted and
  // skipped and nothing is emitted for it: never an error (Hard Rule 1).
  {
    BOMWERK_TEST_CHECK(scan_all("- item\n").unsupported_line_count == 1);
    BOMWERK_TEST_CHECK(scan_all("&anchor\n").unsupported_line_count == 1);
    BOMWERK_TEST_CHECK(scan_all("*alias\n").unsupported_line_count == 1);
    BOMWERK_TEST_CHECK(scan_all("---\n").unsupported_line_count == 1);
    BOMWERK_TEST_CHECK(scan_all("key: [a, b]\n").unsupported_line_count == 1);
    BOMWERK_TEST_CHECK(scan_all("key: &anchored value\n").unsupported_line_count == 1);
    BOMWERK_TEST_CHECK(scan_all("key: !!str x\n").unsupported_line_count == 1);
    BOMWERK_TEST_CHECK(scan_all("no separator here\n").unsupported_line_count == 1);
    BOMWERK_TEST_CHECK(scan_all(": orphan value\n").unsupported_line_count == 1);
    BOMWERK_TEST_CHECK(scan_all("- item\n").nodes.empty());
    BOMWERK_TEST_CHECK(scan_all("key: [a, b]\n").nodes.empty());
  }

  // Given a block scalar, when scanned, then its whole indented body is skipped
  // as a unit: free text inside it must never masquerade as mappings: and the
  // first line back at the opening indentation resumes normal reading.
  {
    const Scan scan = scan_all(R"(before: ok
notes: |
  key: not really a mapping
  more free text
after: ok
)");
    BOMWERK_TEST_CHECK(scan.nodes.size() == 2);
    BOMWERK_TEST_CHECK(scan.nodes[0].key == "before");
    BOMWERK_TEST_CHECK(scan.nodes[1].key == "after");
    BOMWERK_TEST_CHECK(scan.unsupported_line_count == 3);  // the indicator plus two body lines
  }

  // Given tab indentation, when scanned, then the line is counted and skipped:
  // a tab is not a nesting level, and no lockfile generator emits one, so
  // degrading to "not recognized" beats silently mis-nesting.
  {
    const Scan scan = scan_all("root: ok\n\tnested: x\n");
    BOMWERK_TEST_CHECK(scan.nodes.size() == 1);
    BOMWERK_TEST_CHECK(scan.nodes[0].key == "root");
    BOMWERK_TEST_CHECK(scan.unsupported_line_count == 1);
  }

  // Given CRLF line endings, a missing trailing newline, blank lines and
  // comment-only lines, when scanned, then content reads identically and none
  // of them counts as a gap.
  {
    const Scan crlf = scan_all("a: 1\r\nb: 2\r\n");
    BOMWERK_TEST_CHECK(crlf.nodes.size() == 2);
    BOMWERK_TEST_CHECK(crlf.nodes[0].value == "1");
    BOMWERK_TEST_CHECK(crlf.nodes[1].value == "2");

    const Scan unterminated = scan_all("a: 1");
    BOMWERK_TEST_CHECK(unterminated.nodes.size() == 1);
    BOMWERK_TEST_CHECK(unterminated.nodes[0].value == "1");

    const Scan sparse = scan_all("\n\n# only a comment\n   \na: 1\n");
    BOMWERK_TEST_CHECK(sparse.nodes.size() == 1);
    BOMWERK_TEST_CHECK(sparse.unsupported_line_count == 0);
  }

  // Given empty input, when scanned, then there is nothing to read and nothing
  // to report (no crash, no phantom gap).
  {
    const Scan scan = scan_all("");
    BOMWERK_TEST_CHECK(scan.nodes.empty());
    BOMWERK_TEST_CHECK(scan.unsupported_line_count == 0);
  }

  // Given hostile input: NUL bytes, an unterminated quote, a very long line :
  // when scanned, then it degrades to counted skips and never crashes (rule 1).
  {
    // Explicit length: the embedded NUL must reach the buffer, not truncate the
    // C-string literal.
    const std::string binary_garbage("\x00\x01 junk \xff\xfe\nkey: \"unterminated\n", 30);
    const Scan garbage = scan_all(binary_garbage);
    BOMWERK_TEST_CHECK(garbage.unsupported_line_count > 0);

    const Scan long_line = scan_all("key: " + std::string(10000, 'x') + "\n");
    BOMWERK_TEST_CHECK(long_line.nodes.size() == 1);
    BOMWERK_TEST_CHECK(long_line.nodes[0].value.size() == 10000);
  }

  std::puts("test_yaml_subset: OK");
  return 0;
}
