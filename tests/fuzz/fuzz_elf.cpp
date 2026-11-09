// libFuzzer harness for the ELF reader (T40). Oracles: the lists `read_elf`
// documents as sorted and deduplicated are, and none exceeds its cap.
#include <cstddef>
#include <cstdint>

#include "binscan/bounds.hpp"
#include "binscan/elf_read.hpp"
#include "fuzz/fuzz_support.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const auto image =
      bomwerk::binscan::read_elf_bytes("fuzz.so", bomwerk::fuzz::as_text(data, size));
  bomwerk::fuzz::require(bomwerk::fuzz::sorted_and_unique(image.value.needed),
                         "DT_NEEDED list is not sorted and unique");
  bomwerk::fuzz::require(bomwerk::fuzz::sorted_and_unique(image.value.exported_symbols),
                         "exported symbols are not sorted and unique");
  bomwerk::fuzz::require(image.value.needed.size() <= bomwerk::binscan::kMaxNeededEntries,
                         "DT_NEEDED list exceeds its cap");
  bomwerk::fuzz::require(image.value.exported_symbols.size() <= bomwerk::binscan::kMaxSymbolSample,
                         "symbol sample exceeds its cap");
  return 0;
}
