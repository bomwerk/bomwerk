#pragma once
#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

namespace bomwerk::binscan
{

/// Cap on how many bytes of one artifact are read into memory.
///
/// The whole image is loaded (via `core::read_file_bounded`) rather than
/// seeked through, because every bound this module relies on is expressed
/// against one buffer length: a seeking reader would have to re-derive that
/// safety at each read. A file larger than this is REFUSED, not partially
/// parsed: a truncated binary carries valid-looking headers pointing past the
/// end, which is precisely the shape a parser must not guess at.
inline constexpr std::size_t kMaxBinaryBytes = 128u * 1024u * 1024u;

/// Caps on how much structure one artifact may declare before bomwerk stops
/// following it. Every one of these is a "this file describes more than any
/// real toolchain emits" line, not a correctness limit: hitting one degrades
/// that artifact's record and is reported (rule 1), never fatal.
inline constexpr std::size_t kMaxProgramHeaders = 1024;
inline constexpr std::size_t kMaxSectionHeaders = 4096;
inline constexpr std::size_t kMaxDynamicEntries = 4096;
inline constexpr std::size_t kMaxSymbolTableEntries = 200'000;
inline constexpr std::size_t kMaxStringLength = 4096;
inline constexpr std::size_t kMaxNeededEntries = 512;
inline constexpr std::size_t kMaxArchiveMembers = 4096;

/// How many exported symbols are kept per artifact. This is a SAMPLE for a
/// fingerprint matcher, not an export table: a full one would
/// dominate the sidecar and buy nothing a sorted prefix does not.
inline constexpr std::size_t kMaxSymbolSample = 256;

/// Sort, deduplicate and cap `values` in place; true when the cap was hit.
///
/// Every list this module produces goes through here, so ordering is decided
/// in exactly one place: a symbol sample or a NEEDED list that depended on the
/// order a section happened to be laid out in would make two runs over one
/// artifact differ (rule 3).
inline bool normalize_and_cap(std::vector<std::string>& values, std::size_t maximum)
{
  std::sort(values.begin(), values.end());
  values.erase(std::unique(values.begin(), values.end()), values.end());
  if (values.size() <= maximum)
  {
    return false;
  }
  values.resize(maximum);
  return true;
}

}  // namespace bomwerk::binscan
