// libFuzzer harness for `bomwerk.toml` (T40): read from the repository under
// scan, so untrusted.
#include <cstddef>
#include <cstdint>

#include "core/scan_config.hpp"
#include "fuzz/fuzz_support.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  static_cast<void>(
      bomwerk::core::parse_scan_config(bomwerk::fuzz::as_text(data, size), "bomwerk.toml"));
  return 0;
}
