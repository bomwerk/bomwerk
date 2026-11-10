// libFuzzer harness for the git index reader (T110): the input is one
// `.git/index`, read as the object format BOMWERK_FUZZ_VARIANT names (`sha1`
// or `sha256`, which fixes the width of every object id). Oracles: the reader
// either refuses the whole index (nothing returned, one warning) or returns
// gitlinks with no warning; paths are sorted, unique and contained; every
// commit is an object id of exactly the format's length.
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string_view>

#include "core/git_dir.hpp"
#include "core/git_index.hpp"
#include "core/text.hpp"
#include "fuzz/fuzz_support.hpp"

#ifndef BOMWERK_FUZZ_VARIANT
#error "BOMWERK_FUZZ_VARIANT must name the object format this harness reads"
#endif

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  constexpr std::string_view kVariant = BOMWERK_FUZZ_VARIANT;
  constexpr bool kIsSha256 = kVariant == "sha256";
  constexpr std::size_t kCommitHexLength = kIsSha256 ? 64 : 40;
  const auto object_format =
      kIsSha256 ? bomwerk::core::GitObjectFormat::Sha256 : bomwerk::core::GitObjectFormat::Sha1;

  const auto result = bomwerk::core::parse_git_index_gitlinks(bomwerk::fuzz::as_text(data, size),
                                                              object_format, "fuzz.index");
  bomwerk::fuzz::require(result.value.empty() || result.warnings.empty(),
                         "gitlinks returned alongside a refusal");
  bomwerk::fuzz::require(result.warnings.size() <= 1, "more than one warning for one index");
  for (std::size_t index = 0; index < result.value.size(); ++index)
  {
    const bomwerk::core::Gitlink& gitlink = result.value[index];
    bomwerk::fuzz::require(index == 0 || result.value[index - 1].path < gitlink.path,
                           "gitlinks are not sorted and unique by path");
    bomwerk::fuzz::require(
        bomwerk::core::is_contained_relative_path(std::filesystem::path(gitlink.path)),
        "gitlink path is absolute or escapes the repository");
    bomwerk::fuzz::require(gitlink.path.size() <= bomwerk::core::kMaxGitIndexPathBytes,
                           "gitlink path exceeds the cap");
    bomwerk::fuzz::require(gitlink.commit.size() == kCommitHexLength &&
                               bomwerk::core::is_hex_object_id(gitlink.commit),
                           "gitlink commit is not an object id of the format's length");
  }
  return 0;
}
