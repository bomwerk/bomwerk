// libFuzzer harness for the conan producer (T40): the input is one
// conanfile.txt, conanfile.py or conan.lock, parsed through `parse_bytes`, or
// `conan graph info` JSON through `parse_graph_bytes` when
// BOMWERK_FUZZ_VARIANT is `graph.json`. A crash input can be committed as-is
// under fixtures/conan/hostile/.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "fuzz/fuzz_support.hpp"
#include "parsers/cpp/conan.hpp"

#ifndef BOMWERK_FUZZ_VARIANT
#error "BOMWERK_FUZZ_VARIANT must name the file this harness parses"
#endif

namespace conan = bomwerk::parsers::cpp::conan;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  constexpr std::string_view kVariant = BOMWERK_FUZZ_VARIANT;
  const std::string_view bytes = bomwerk::fuzz::as_text(data, size);
  if constexpr (kVariant == "graph.json")
  {
    bomwerk::fuzz::require_valid_purls(conan::parse_graph_bytes(kVariant, bytes, {}));
  }
  else
  {
    bomwerk::fuzz::require_valid_purls(conan::parse_bytes(kVariant, bytes, {}));
  }
  return 0;
}
