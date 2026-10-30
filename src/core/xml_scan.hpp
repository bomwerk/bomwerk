#pragma once
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bomwerk::core::xml_scan
{

/// A deliberately minimal XML scanner shared by the pom.xml and MSBuild
/// readers: no XML dependency (every dependency must appear in bomwerk's own
/// SBOM), no entity decoding, no namespaces. Anything it cannot pair is
/// treated as absent, so hostile input degrades and never throws.

/// True for the ASCII whitespace XML allows inside tags.
[[nodiscard]] bool is_xml_whitespace(char character);

/// Removes XML comments and unwraps CDATA sections so the tag scanner never
/// trips over commented-out or escaped markup. An unterminated comment or
/// CDATA section swallows the rest of the file. Every newline inside removed
/// text is kept, so `line_number_at` on the result still names the line of the
/// original file.
[[nodiscard]] std::string strip_comments_and_unwrap_cdata(std::string_view xml);

/// One matched XML element: where its span starts, its inner text, and where
/// scanning may resume after the closing tag.
struct ElementMatch
{
  std::size_t span_start = 0;
  std::string_view inner_text;
  std::size_t resume_position = 0;
};

/// Finds the next `<tag ...>...</tag>` element at or after `search_start`. The
/// opening tag may carry attributes; a self-closing `<tag .../>` yields empty
/// inner text. The closing tag must be the literal `</tag>`.
/// Example: `find_element("<a><b>1</b></a>", "b", 0)` has inner text `"1"`.
[[nodiscard]] std::optional<ElementMatch> find_element(std::string_view xml,
                                                       std::string_view tag_name,
                                                       std::size_t search_start);

/// One direct child element of a block: its tag name and trimmed inner text.
struct ChildElement
{
  std::string name;
  std::string text;
};

/// The child elements of `body`, in document order, one flat level. This is
/// what reading a `<properties>` or `<PropertyGroup>` block needs and nothing
/// more.
/// Example: `child_elements("<a>1</a><b/>")` -> `{a: "1"}, {b: ""}`.
[[nodiscard]] std::vector<ChildElement> child_elements(std::string_view body);

/// One matched opening tag's raw attribute text (the span between the tag name
/// and the closing `>` or `/>`) and where scanning may resume after it.
/// Element bodies are not tracked: `.csproj` and `packages.config` entries
/// carry their identity entirely in attributes on the opening tag.
struct TagMatch
{
  std::string_view attribute_text;
  std::size_t resume_position = 0;
};

/// Finds the next `<tag ...>` or `<tag .../>` opening at or after
/// `search_start`. Anything the scanner cannot pair, such as an unterminated
/// tag, degrades to "not found".
[[nodiscard]] std::optional<TagMatch> find_next_tag(std::string_view xml, std::string_view tag_name,
                                                    std::size_t search_start);

/// First `name="value"` (or `name='value'`) attribute in `attribute_text`;
/// nullopt when absent or unterminated. `attribute_name` must sit on a word
/// boundary, so `Version` never matches inside a longer attribute name.
[[nodiscard]] std::optional<std::string> find_attribute_value(std::string_view attribute_text,
                                                              std::string_view attribute_name);

/// 1-based line of byte `position` in `text`: one plus the newlines before it.
[[nodiscard]] std::size_t line_number_at(std::string_view text, std::size_t position);

}  // namespace bomwerk::core::xml_scan
