// ctest unit test for the SBOM format enum
#include <cassert>
#include <cstdio>
#include <string>

#include "core/sbom_format.hpp"

using bomwerk::core::SbomFormat;
using bomwerk::core::SpdxVersion;
using bomwerk::core::to_string;

int main()
{
  assert(std::string(to_string(SbomFormat::CycloneDx)) == "cyclonedx");
  assert(std::string(to_string(SbomFormat::Spdx)) == "spdx");

  // The SPDX version is a separate axis (only meaningful with the Spdx
  // format), spelled as the dotted version on the CLI and in the document.
  assert(std::string(to_string(SpdxVersion::V2_3)) == "2.3");
  assert(std::string(to_string(SpdxVersion::V3_0)) == "3.0");

  std::puts("test_sbom_format: OK");
  return 0;
}
