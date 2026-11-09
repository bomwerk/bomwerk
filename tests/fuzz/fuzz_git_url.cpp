// libFuzzer harness for git remote parsing and relative url resolution
// (T40). The input's first line is a base url, the rest a submodule url.
// Oracle: the purl built from any url parses.
#include <cstddef>
#include <cstdint>
#include <string>

#include "core/git_url.hpp"
#include "core/purl.hpp"
#include "fuzz/fuzz_support.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const auto [base_text, url_text] =
      bomwerk::fuzz::split_at_first_newline(bomwerk::fuzz::as_text(data, size));
  const std::string base(base_text);
  const std::string url(url_text);
  static_cast<void>(bomwerk::core::parse_git_remote(url));
  const std::string resolved = bomwerk::core::resolve_relative_url(base, url);
  const std::string purl = bomwerk::core::build_git_purl(resolved, base, "fallback");
  bomwerk::fuzz::require(bomwerk::core::Purl::parse(purl).complete,
                         "build_git_purl built a purl that does not parse");
  return 0;
}
