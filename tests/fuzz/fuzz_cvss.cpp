// libFuzzer harness for CVSS vector scoring (T40): vectors come from OSV and
// NVD responses, so they are network input.
#include <cstddef>
#include <cstdint>

#include "core/cvss.hpp"
#include "fuzz/fuzz_support.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  static_cast<void>(bomwerk::core::score_cvss_vector(bomwerk::fuzz::as_text(data, size)));
  return 0;
}
