// ctest unit test for the SBOM format enum
#include <cstdio>
#include <string>

#include "core/sbom_format.hpp"
#include "support/check.hpp"

using bomwerk::core::SbomFormat;
using bomwerk::core::SpdxVersion;
using bomwerk::core::to_string;

int main()
{
  BOMWERK_TEST_CHECK(std::string(to_string(SbomFormat::CycloneDx)) == "cyclonedx");
  BOMWERK_TEST_CHECK(std::string(to_string(SbomFormat::Spdx)) == "spdx");

  // The SPDX version is a separate axis (only meaningful with the Spdx
  // format), spelled as the dotted version on the CLI and in the document.
  BOMWERK_TEST_CHECK(std::string(to_string(SpdxVersion::V2_3)) == "2.3");
  BOMWERK_TEST_CHECK(std::string(to_string(SpdxVersion::V3_0)) == "3.0");

  std::puts("test_sbom_format: OK");
  return 0;
}
