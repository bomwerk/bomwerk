#pragma once
#include <string>

namespace bomwerk::output
{

/// Tool identity recorded in every output document (the CycloneDX BOM's
/// `metadata.tools`, the HTML report's header/footer): supplied by the
/// caller so this module never depends on cli/ (module dependency law:
/// output may only include core). Lived in cyclonedx.hpp until the HTML report gave it
/// a second consumer.
struct ToolInfo
{
  std::string name;
  std::string version;
};

}  // namespace bomwerk::output
