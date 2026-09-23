#pragma once
#include <cstddef>
#include <filesystem>
#include <string>

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

/// First line of a small text file, bounded and trimmed. Empty when the file is
/// absent or unreadable: callers treat that as "no value", never an error.
/// Example: a file holding `"ref: refs/heads/main\n…"` yields
/// `"ref: refs/heads/main"`.
[[nodiscard]] std::string read_first_line_bounded(const std::filesystem::path& path,
                                                  std::size_t max_bytes);

}  // namespace bomwerk::core
