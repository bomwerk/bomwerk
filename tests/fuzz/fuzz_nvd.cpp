// libFuzzer harness for NVD CVE API 2.0 responses (T40): network input.
#include <cstddef>
#include <cstdint>
#include <string>

#include "fuzz/fuzz_support.hpp"
#include "vuln/nvd.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  static_cast<void>(
      bomwerk::vuln::parse_nvd_cve_payload(std::string(bomwerk::fuzz::as_text(data, size))));
  return 0;
}
