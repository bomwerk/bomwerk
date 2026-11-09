// libFuzzer harness for conan reference parsing (T40): `name/version@user/
// channel#rrev` strings from conanfiles, locks and graph output. Oracle: the
// purl built from any reference parses, with and without the recipe
// revision qualifier.
#include <cstddef>
#include <cstdint>

#include "core/purl.hpp"
#include "fuzz/fuzz_support.hpp"
#include "parsers/cpp/conan_ref.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const auto reference =
      bomwerk::parsers::cpp::parse_conan_reference(bomwerk::fuzz::as_text(data, size));
  static_cast<void>(bomwerk::parsers::cpp::is_conan_version_range(reference.version));
  for (const bool include_recipe_revision : {false, true})
  {
    const auto purl = bomwerk::parsers::cpp::build_conan_purl(reference, include_recipe_revision);
    bomwerk::fuzz::require(bomwerk::core::Purl::parse(purl).complete,
                           "build_conan_purl built a purl that does not parse");
  }
  return 0;
}
