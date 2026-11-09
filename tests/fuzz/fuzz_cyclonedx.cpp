// libFuzzer harness for CycloneDX input (T40): the SBOM `bomwerk trim` reads
// may come from any tool.
#include <cstddef>
#include <cstdint>

#include "fuzz/fuzz_support.hpp"
#include "sbom/format.hpp"
#include "sbom/read.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const auto bytes = bomwerk::fuzz::as_text(data, size);
  static_cast<void>(bomwerk::sbom::detect_sbom_format(bytes));
  static_cast<void>(bomwerk::sbom::read_cyclonedx(bytes));
  return 0;
}
