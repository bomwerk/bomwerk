// libFuzzer harness for the XML scanner behind pom.xml and MSBuild reading
// (T40). Oracles: the incremental line counter agrees with `line_number_at`,
// and element scanning always moves forward.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "core/xml_scan.hpp"
#include "fuzz/fuzz_support.hpp"

namespace xml_scan = bomwerk::core::xml_scan;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const std::string cleaned =
      xml_scan::strip_comments_and_unwrap_cdata(bomwerk::fuzz::as_text(data, size));
  static_cast<void>(xml_scan::child_elements(cleaned));

  xml_scan::LineCounter line_counter(cleaned);
  std::size_t position = 0;
  while (const std::optional<xml_scan::ElementMatch> element =
             xml_scan::find_element(cleaned, "dependency", position))
  {
    bomwerk::fuzz::require(element->resume_position > position, "find_element did not advance");
    bomwerk::fuzz::require(line_counter.line_number_at(element->span_start) ==
                               xml_scan::line_number_at(cleaned, element->span_start),
                           "LineCounter disagrees with line_number_at");
    static_cast<void>(xml_scan::child_elements(element->inner_text));
    position = element->resume_position;
  }

  position = 0;
  while (const std::optional<xml_scan::TagMatch> tag =
             xml_scan::find_next_tag(cleaned, "PackageReference", position))
  {
    bomwerk::fuzz::require(tag->resume_position > position, "find_next_tag did not advance");
    static_cast<void>(xml_scan::find_attribute_value(tag->attribute_text, "Include"));
    static_cast<void>(xml_scan::find_attribute_value(tag->attribute_text, "Version"));
    position = tag->resume_position;
  }
  return 0;
}
