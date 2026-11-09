// ctest unit test for the minimal XML scanner shared by the pom.xml and
// MSBuild readers (framework-free).
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/xml_scan.hpp"
#include "support/check.hpp"

namespace xml_scan = bomwerk::core::xml_scan;

namespace
{

/// The child_elements scan as it was before T40 made it linear, kept here as
/// the reference: the new one must return exactly what this one returns.
std::vector<xml_scan::ChildElement> reference_child_elements(std::string_view body)
{
  std::vector<xml_scan::ChildElement> children;
  std::size_t position = 0;
  while (position < body.size())
  {
    const std::size_t open = body.find('<', position);
    if (open == std::string_view::npos)
    {
      break;
    }
    if (open + 1 >= body.size() || body[open + 1] == '/')
    {
      position = open + 1;
      continue;
    }
    std::size_t name_end = open + 1;
    while (name_end < body.size() && body[name_end] != '>' && body[name_end] != '/' &&
           !xml_scan::is_xml_whitespace(body[name_end]))
    {
      ++name_end;
    }
    const std::string child_name(body.substr(open + 1, name_end - open - 1));
    if (child_name.empty())
    {
      position = open + 1;
      continue;
    }
    const std::optional<xml_scan::ElementMatch> child =
        xml_scan::find_element(body, child_name, open);
    if (!child.has_value())
    {
      position = open + 1;
      continue;
    }
    std::string_view text = child->inner_text;
    while (!text.empty() && xml_scan::is_xml_whitespace(text.front()))
    {
      text.remove_prefix(1);
    }
    while (!text.empty() && xml_scan::is_xml_whitespace(text.back()))
    {
      text.remove_suffix(1);
    }
    children.push_back({child_name, std::string(text)});
    position = child->resume_position;
  }
  return children;
}

bool same_children(const std::vector<xml_scan::ChildElement>& left,
                   const std::vector<xml_scan::ChildElement>& right)
{
  if (left.size() != right.size())
  {
    return false;
  }
  for (std::size_t index = 0; index < left.size(); ++index)
  {
    if (left[index].name != right[index].name || left[index].text != right[index].text)
    {
      return false;
    }
  }
  return true;
}

/// Deterministic pseudo-random XML-ish text over the characters the scanner
/// cares about, so the differential check covers shapes nobody wrote by hand.
std::string generated_body(std::uint32_t seed, std::size_t length)
{
  static constexpr std::string_view kAlphabet = "<<<>>//ab b \n";
  std::string body;
  body.reserve(length);
  std::uint32_t state = seed;
  for (std::size_t index = 0; index < length; ++index)
  {
    state = state * 1664525u + 1013904223u;  // Numerical Recipes LCG
    body.push_back(kAlphabet[(state >> 16) % kAlphabet.size()]);
  }
  return body;
}

}  // namespace

int main()
{
  // Given a comment spanning two lines and a CDATA section, when stripped,
  // then the comment disappears but its newlines stay, and the CDATA text is
  // unwrapped: a line counted in the result is the line of the original.
  {
    const std::string xml = "<a>\n<!-- one\ntwo -->\n<b><![CDATA[x]]></b>\n</a>";
    const std::string cleaned = xml_scan::strip_comments_and_unwrap_cdata(xml);
    BOMWERK_TEST_CHECK(cleaned.find("one") == std::string::npos);
    BOMWERK_TEST_CHECK(cleaned.find("CDATA") == std::string::npos);
    BOMWERK_TEST_CHECK(cleaned.find("<b>x</b>") != std::string::npos);
    const std::size_t b_position = cleaned.find("<b>");
    BOMWERK_TEST_CHECK(xml_scan::line_number_at(cleaned, b_position) ==
                       xml_scan::line_number_at(xml, xml.find("<b>")));
  }

  // Given an unterminated comment, when stripped, then the rest of the file is
  // swallowed and nothing throws.
  {
    const std::string cleaned =
        xml_scan::strip_comments_and_unwrap_cdata("<a/><!-- never closed <b/>");
    BOMWERK_TEST_CHECK(cleaned == "<a/>");
  }

  // Given nested and similarly named elements, when searched, then only the
  // exact tag matches, with its inner text and resume position.
  {
    const std::string xml = "<groupIdX>no</groupIdX><groupId>yes</groupId><groupId>later</groupId>";
    const auto match = xml_scan::find_element(xml, "groupId", 0);
    BOMWERK_TEST_CHECK(match.has_value());
    BOMWERK_TEST_CHECK(match->inner_text == "yes");
    const auto next = xml_scan::find_element(xml, "groupId", match->resume_position);
    BOMWERK_TEST_CHECK(next.has_value());
    BOMWERK_TEST_CHECK(next->inner_text == "later");
    BOMWERK_TEST_CHECK(!xml_scan::find_element(xml, "artifactId", 0).has_value());
  }

  // Given a self-closing element and an unterminated one, when searched, then
  // the first has empty text and the second degrades to "not found".
  {
    const auto self_closing = xml_scan::find_element("<a/>", "a", 0);
    BOMWERK_TEST_CHECK(self_closing.has_value());
    BOMWERK_TEST_CHECK(self_closing->inner_text.empty());
    BOMWERK_TEST_CHECK(!xml_scan::find_element("<a>never closed", "a", 0).has_value());
  }

  // Given a block of properties, when read as children, then they come back in
  // document order with trimmed text, including an empty and a self-closing one.
  {
    const auto children = xml_scan::child_elements(
        "\n  <one> 1 </one>\n  <two Condition=\"x\">2</two>\n  <three/>\n");
    BOMWERK_TEST_CHECK(children.size() == 3);
    BOMWERK_TEST_CHECK(children[0].name == "one" && children[0].text == "1");
    BOMWERK_TEST_CHECK(children[1].name == "two" && children[1].text == "2");
    BOMWERK_TEST_CHECK(children[2].name == "three" && children[2].text.empty());
  }

  // Given a tag with attributes in both quote styles, when read, then the
  // values come back, `Version` never matches inside `VersionOverride`, and an
  // absent or unterminated attribute is nullopt.
  {
    const std::string xml =
        "<PackageReference Include=\"Foo\" VersionOverride=\"9\" Version='1.0' />";
    const auto tag = xml_scan::find_next_tag(xml, "PackageReference", 0);
    BOMWERK_TEST_CHECK(tag.has_value());
    BOMWERK_TEST_CHECK(xml_scan::find_attribute_value(tag->attribute_text, "Include") == "Foo");
    BOMWERK_TEST_CHECK(xml_scan::find_attribute_value(tag->attribute_text, "Version") == "1.0");
    BOMWERK_TEST_CHECK(
        !xml_scan::find_attribute_value(tag->attribute_text, "Condition").has_value());
    BOMWERK_TEST_CHECK(!xml_scan::find_attribute_value("Version=\"1.0", "Version").has_value());
  }

  // Given text with newlines, when asked for a line, then the answer is
  // 1-based and a position past the end is clamped.
  {
    BOMWERK_TEST_CHECK(xml_scan::line_number_at("a\nb\nc", 0) == 1);
    BOMWERK_TEST_CHECK(xml_scan::line_number_at("a\nb\nc", 2) == 2);
    BOMWERK_TEST_CHECK(xml_scan::line_number_at("a\nb\nc", 4) == 3);
    BOMWERK_TEST_CHECK(xml_scan::line_number_at("a\nb\nc", 999) == 3);
  }

  // Given hand-written and generated bodies, when the children are read,
  // then the linear scan returns exactly what the earlier quadratic one did.
  {
    const std::vector<std::string> bodies = {
        "<a>1</a><b/>", "<a>1</a><a>2</a>", "<a><b>x</b></a>",     "<a>unclosed<b>2</b>",
        "<a<b>1</a<b>", "<a <a <a >x</a>",  "<a/><b / ><c>3</c >", "  <x>\n  spaced \n</x>",
        "<>empty</>",   "</a><a>1</a>",     "<a>1</b></a>",
    };
    for (const std::string& body : bodies)
    {
      BOMWERK_TEST_CHECK(
          same_children(xml_scan::child_elements(body), reference_child_elements(body)));
    }
    for (std::uint32_t seed = 1; seed <= 400; ++seed)
    {
      const std::string body = generated_body(seed, 16 + seed % 240);
      BOMWERK_TEST_CHECK(
          same_children(xml_scan::child_elements(body), reference_child_elements(body)));
    }
  }

  // Given the three shapes that made the earlier scan quadratic, 256 KiB each,
  // when the children are read, then the scan finishes promptly (a 10 s fuzz
  // timeout would otherwise report it) and finds nothing.
  {
    const std::size_t repeat = 64 * 1024;
    std::string no_delimiter;
    std::string no_close_bracket;
    std::string unclosed_children;
    for (std::size_t index = 0; index < repeat; ++index)
    {
      no_delimiter += "<a<a";
      no_close_bracket += "<a  ";
      unclosed_children += "<a" + std::to_string(index % 1000) + ">";
    }
    const auto started = std::chrono::steady_clock::now();
    BOMWERK_TEST_CHECK(xml_scan::child_elements(no_delimiter).empty());
    BOMWERK_TEST_CHECK(xml_scan::child_elements(no_close_bracket).empty());
    BOMWERK_TEST_CHECK(xml_scan::child_elements(unclosed_children).empty());
    const auto elapsed = std::chrono::steady_clock::now() - started;
    BOMWERK_TEST_CHECK(elapsed < std::chrono::seconds(5));
  }

  // Given offsets asked in ascending order, and then one going back, when the
  // line counter answers, then every answer equals line_number_at's.
  {
    const std::string text = "a\nbb\n\nccc\nd";
    xml_scan::LineCounter counter(text);
    for (const std::size_t position : {0u, 1u, 2u, 5u, 6u, 9u, 11u, 999u, 3u, 0u})
    {
      BOMWERK_TEST_CHECK(counter.line_number_at(position) ==
                         xml_scan::line_number_at(text, position));
    }
  }

  std::puts("test_xml_scan: OK");
  return 0;
}
