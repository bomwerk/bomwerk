// libFuzzer harness for the YAML subset reader behind pnpm, pub, west and
// GitHub Actions (T40). BOMWERK_FUZZ_VARIANT selects the reader mode:
// `default`, or `sequence_items` (the mode west uses).
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "core/yaml_subset.hpp"
#include "fuzz/fuzz_support.hpp"

#ifndef BOMWERK_FUZZ_VARIANT
#error "BOMWERK_FUZZ_VARIANT must be default or sequence_items"
#endif

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  constexpr std::string_view kVariant = BOMWERK_FUZZ_VARIANT;
  bomwerk::core::yaml_subset::ReaderOptions options;
  options.sequence_items = kVariant == "sequence_items";
  bomwerk::core::yaml_subset::Reader reader(bomwerk::fuzz::as_text(data, size), options);
  bomwerk::core::yaml_subset::Node node;
  while (reader.next(node))
  {
    // Reading to the end is the test: a reader that never ends is a libFuzzer
    // timeout, a bad offset an ASan report.
  }
  static_cast<void>(reader.stats());
  return 0;
}
