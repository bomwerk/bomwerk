#pragma once
#include <cstddef>
#include <string_view>

namespace bomwerk::core::yaml_subset
{

/// One `key: value` mapping line, indentation measured and quotes stripped. The
/// views point into the buffer handed to `Reader` and must not outlive it.
struct Node
{
  std::size_t indentation = 0;   ///< leading spaces; 0 is document level
  std::string_view key;          ///< unquoted key text, the `:` removed
  std::string_view value;        ///< unquoted scalar, or a flow mapping's inner text
  bool opens_block = false;      ///< the line carried no inline value
  bool is_flow_mapping = false;  ///< the value was `{ … }`; `value` is its raw inner text
};

/// What a scan deliberately did not read. Everything outside the subset is
/// counted here and skipped: never an error, never a throw (Hard Rule 1), so a
/// caller can report "N lines I did not understand" and still emit the rest.
struct ScanStats
{
  std::size_t unsupported_line_count = 0;
};

/// Pull cursor over the slice of YAML that lockfile generators actually write:
/// Yarn Berry's `yarn.lock` and pnpm's `pnpm-lock.yaml`.
///
/// **In the subset**: space indentation, `key: value` mappings, optionally
/// `"`- or `'`-quoted keys and values, one-line flow mappings `{a: 1, b: 2}`,
/// and `#` comments.
///
/// **Outside it**, counted in `ScanStats::unsupported_line_count` and skipped:
/// sequences (`- item`), anchors (`&a`), aliases (`*a`), tags (`!!str`), block
/// scalars (`|`, `>`, whose indented body is skipped as a unit), document
/// markers (`---`, `...`), flow sequences (`[a, b]`) and tab indentation. A tab
/// reads as no indentation rather than as a nesting level, so a tab-indented
/// file degrades to "nothing recognized" instead of silently mis-nesting.
///
/// Two rules that a naive line splitter gets wrong, both of which corrupt real
/// lockfiles: a `#` is a comment only outside quotes (a Yarn `patch:` locator
/// carries a literal `#`), and the key/value separator is the first `:` outside
/// quotes that ends the line or is followed by a space (a Berry entry key is
/// `"name@npm:^1.2.3":`, whose inner `:` must not split it).
///
/// Quoted interiors are handed back verbatim: escapes are honored when finding
/// where a quoted region ends, but `\"` is not turned back into `"`, since
/// unescaping cannot be done without allocating and no real lockfile needs it.
///
/// Allocation-free: a 47k-line lockfile costs one pass and no heap: and pure,
/// so it can be unit-tested and fuzzed against in-memory buffers.
///
/// Example:
/// ```cpp
/// yaml_subset::Reader reader(bytes);
/// yaml_subset::Node node;
/// while (reader.next(node))
/// {
///   if (node.indentation == 2 && node.key == "resolution") { … }
/// }
/// ```
class Reader
{
 public:
  explicit Reader(std::string_view bytes) : bytes_(bytes) {}

  /// Advance to the next mapping entry, writing it into `node`. Returns false
  /// once the input is exhausted; `node` is then unchanged.
  [[nodiscard]] bool next(Node& node);

  /// Counters for everything skipped so far. Only final once `next` has
  /// returned false.
  [[nodiscard]] const ScanStats& stats() const { return stats_; }

 private:
  /// Sentinel for `block_scalar_indentation_`: no block scalar is open.
  static constexpr std::size_t kNoBlockScalar = static_cast<std::size_t>(-1);

  /// Interpret one raw line. Returns false when the line yields no node :
  /// blank, a comment, or outside the subset (which also bumps the counter).
  [[nodiscard]] bool read_line(std::string_view raw_line, Node& node);

  std::string_view bytes_;
  std::size_t position_ = 0;
  ScanStats stats_;

  /// Indentation of the key that opened the block scalar currently being
  /// skipped, so its more-indented body is skipped as a unit.
  std::size_t block_scalar_indentation_ = kNoBlockScalar;
};

}  // namespace bomwerk::core::yaml_subset
