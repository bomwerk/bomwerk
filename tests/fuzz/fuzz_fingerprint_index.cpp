// libFuzzer harness for the fingerprint corpus index loader (T40). Oracles:
// every offset and index the loaded structure holds is in bounds, so the
// matcher can walk it without checks, and digests are sorted for its search.
#include <cstddef>
#include <cstdint>

#include "fuzz/fuzz_support.hpp"
#include "heuristics/fingerprint.hpp"

namespace fingerprint = bomwerk::heuristics::fingerprint;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const auto loaded = fingerprint::load_index_bytes(bomwerk::fuzz::as_text(data, size));
  const fingerprint::Index& index = loaded.value;
  for (const fingerprint::IndexRelease& release : index.releases)
  {
    bomwerk::fuzz::require(release.library < index.libraries.size(),
                           "a release names a library out of range");
  }
  for (const std::uint32_t release_ref : index.release_refs)
  {
    bomwerk::fuzz::require(release_ref < index.releases.size(), "a release ref is out of range");
  }
  for (std::size_t position = 0; position < index.files.size(); ++position)
  {
    const fingerprint::IndexFileEntry& file = index.files[position];
    bomwerk::fuzz::require(
        static_cast<std::size_t>(file.first_release_ref) + file.release_ref_count <=
            index.release_refs.size(),
        "a file's release refs run past the pool");
    if (position > 0)
    {
      bomwerk::fuzz::require(index.files[position - 1].digest < file.digest,
                             "file digests are not sorted and unique");
    }
    static_cast<void>(fingerprint::releases_for_digest(index, file.digest));
  }
  return 0;
}
