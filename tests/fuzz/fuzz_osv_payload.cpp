// libFuzzer harness for OSV responses (T40): network input. BOMWERK_FUZZ_VARIANT
// is `detection` (a querybatch entry) or `full` (a /v1/query record).
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "fuzz/fuzz_support.hpp"
#include "vuln/osv.hpp"

#ifndef BOMWERK_FUZZ_VARIANT
#error "BOMWERK_FUZZ_VARIANT must be detection or full"
#endif

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  constexpr std::string_view kVariant = BOMWERK_FUZZ_VARIANT;
  const std::string payload(bomwerk::fuzz::as_text(data, size));
  if constexpr (kVariant == "detection")
  {
    static_cast<void>(bomwerk::vuln::parse_osv_detection_payload(payload));
  }
  else
  {
    static_cast<void>(bomwerk::vuln::parse_osv_full_payload(payload));
  }
  return 0;
}
