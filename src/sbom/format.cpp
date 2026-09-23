#include "sbom/format.hpp"

namespace bomwerk::sbom
{

SbomInputFormat detect_sbom_format(std::string_view bytes)
{
  // CycloneDX is checked first because it is the only format bomwerk itself
  // ever writes (output::write_cyclonedx): the shape a published folder is
  // actually expected to hold. Both substrings are required so a coincidental
  // mention of "CycloneDX" in, say, a license file embedded elsewhere in the
  // bytes cannot misclassify an otherwise-unrecognized document.
  if (bytes.find("\"bomFormat\"") != std::string_view::npos &&
      bytes.find("CycloneDX") != std::string_view::npos)
  {
    return SbomInputFormat::CycloneDx;
  }
  if (bytes.find("\"spdxVersion\"") != std::string_view::npos)
  {
    return SbomInputFormat::Spdx;
  }
  return SbomInputFormat::Unknown;
}

}  // namespace bomwerk::sbom
