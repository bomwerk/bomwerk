// ctest unit test for the minimal XML scanner shared by the pom.xml and
// MSBuild readers (framework-free).
#include <cstdio>
#include <string>

#include "core/xml_scan.hpp"
#include "support/check.hpp"

namespace xml_scan = bomwerk::core::xml_scan;

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

  std::puts("test_xml_scan: OK");
  return 0;
}
