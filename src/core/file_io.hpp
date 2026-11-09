#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "core/sha256.hpp"

namespace bomwerk::core
{

/// Outcome of a bounded binary file read. `readable` is false when the file
/// could not be opened (`bytes` is then empty); `truncated` is true when the
/// file held more than the requested maximum (`bytes` carries the first part).
struct BoundedFileRead
{
  std::string bytes;
  bool readable = false;
  bool truncated = false;
};

/// Read at most `max_bytes` of `path` in binary mode. Never throws; unreadable
/// or oversized files degrade via the flags (rule 1). This is the shared
/// primitive for every producer that parses an untrusted file under a size cap.
/// Example: a 3-byte file read with `max_bytes = 2` yields
/// `{bytes: "ab", readable: true, truncated: true}`.
[[nodiscard]] BoundedFileRead read_file_bounded(const std::filesystem::path& path,
                                                std::size_t max_bytes);

/// The in-memory counterpart of `read_file_bounded`: exactly what reading a
/// file that holds `bytes` would yield, so a parser fed from memory (a fuzz
/// harness, `parse_bytes`) takes the same size-cap path as one fed from disk.
/// Bytes already in memory are always readable.
/// Example: `bound_in_memory_bytes("abc", 2)` yields
/// `{bytes: "ab", readable: true, truncated: true}`.
[[nodiscard]] BoundedFileRead bound_in_memory_bytes(std::string_view bytes, std::size_t max_bytes);

/// First line of a small text file, bounded and trimmed. Empty when the file is
/// absent or unreadable: callers treat that as "no value", never an error.
/// Example: a file holding `"ref: refs/heads/main\n…"` yields
/// `"ref: refs/heads/main"`.
[[nodiscard]] std::string read_first_line_bounded(const std::filesystem::path& path,
                                                  std::size_t max_bytes);

/// Outcome of a bounded WHOLE-file content digest.
///
/// Note the deliberate asymmetry with `BoundedFileRead`, which truncates: a
/// file larger than the cap is refused here (`over_limit`, `digest` left
/// unset) instead of hashed partially. Truncation is useful for PARSING, where
/// the first N bytes still answer the question. It is actively harmful for
/// IDENTITY: the digest of a prefix is a different value that would silently
/// never match any corpus entry, which is worse than admitting the file was
/// skipped.
struct BoundedFileDigest
{
  Sha256Digest digest{};
  std::uintmax_t bytes_hashed = 0;
  bool readable = false;    ///< false when the file could not be opened
  bool over_limit = false;  ///< larger than `max_bytes`; `digest` is unset
};

/// Same shape for the cheap pass. `hash` is a non-cryptographic 64-bit value
/// used only to decide whether a file is worth digesting properly: it is never
/// an identity and never reaches an SBOM.
struct BoundedFileFastHash
{
  std::uint64_t hash = 0;
  std::uintmax_t bytes_hashed = 0;
  bool readable = false;
  bool over_limit = false;
};

/// Stream `path` through SHA-256 in fixed chunks and return its content
/// identity. Never throws (rule 1): an unopenable file degrades through
/// `readable`, an oversized one through `over_limit`.
/// Example: an empty file yields
/// `to_hex(digest) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`.
[[nodiscard]] BoundedFileDigest sha256_file_bounded(const std::filesystem::path& path,
                                                    std::uintmax_t max_bytes);

/// Stream `path` through xxh3-64, the first of the two passes ADR A8
/// specifies. Roughly an order of magnitude cheaper than SHA-256, so a scan
/// can ask "could this file be in the corpus at all" over a large vendored
/// tree and pay for the real digest only on a hit. A collision costs one
/// wasted read, never a wrong answer, because `sha256_file_bounded` decides.
[[nodiscard]] BoundedFileFastHash xxh3_file_bounded(const std::filesystem::path& path,
                                                    std::uintmax_t max_bytes);

}  // namespace bomwerk::core
