// libFuzzer harness for the git submodules producer (T40): the input is one
// `.gitmodules`, parsed through `parse_bytes` (no checkout, no superproject
// origin). A crash input can be committed as-is under
// fixtures/gitmodules/hostile/.
#include <cstddef>
#include <cstdint>

#include "fuzz/fuzz_support.hpp"
#include "parsers/cpp/submodules.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  bomwerk::fuzz::require_valid_purls(
      bomwerk::parsers::cpp::submodules::parse_bytes(bomwerk::fuzz::as_text(data, size)));
  return 0;
}
