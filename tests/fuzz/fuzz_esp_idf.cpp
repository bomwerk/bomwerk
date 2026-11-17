// libFuzzer harness for the ESP-IDF component manager producer: the input is
// one `dependencies.lock` or `idf_component.yml` file, parsed through
// `parse_bytes` exactly as a scan parses it. BOMWERK_FUZZ_VARIANT names the
// file (see scripts/fuzz_targets.json), so a crash input is a plain file that
// can be committed as-is under fixtures/esp_idf/hostile/.
#include <cstddef>
#include <cstdint>

#include "fuzz/fuzz_support.hpp"
#include "parsers/embedded/esp_idf.hpp"

#ifndef BOMWERK_FUZZ_VARIANT
#error "BOMWERK_FUZZ_VARIANT must name the file this harness parses"
#endif

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const auto result = bomwerk::parsers::embedded::esp_idf::parse_bytes(
      BOMWERK_FUZZ_VARIANT, bomwerk::fuzz::as_text(data, size), {});
  bomwerk::fuzz::require_valid_purls(result);
  return 0;
}
