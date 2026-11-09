// libFuzzer harness for the git config reader behind `.gitmodules` and
// `.git/config` (T40).
#include <cstddef>
#include <cstdint>

#include "core/git_config.hpp"
#include "fuzz/fuzz_support.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const auto config =
      bomwerk::core::parse_git_config(bomwerk::fuzz::as_text(data, size), ".gitmodules");
  static_cast<void>(config.value.find("remote", "origin", "url"));
  return 0;
}
