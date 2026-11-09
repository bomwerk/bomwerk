#include "core/file_io.hpp"

#include <xxhash.h>

#include <fstream>
#include <ios>
#include <memory>
#include <string_view>
#include <system_error>

#include "core/text.hpp"

namespace bomwerk::core
{
namespace
{

/// Chunk size for the whole-file hashes below. Large enough that the syscall
/// cost disappears against the hashing, small enough that a scan's peak memory
/// does not depend on the largest vendored file.
constexpr std::size_t kHashChunkBytes = 64u * 1024u;

struct StreamOutcome
{
  std::uintmax_t bytes_streamed = 0;
  bool readable = false;
  bool over_limit = false;
};

/// Feed `path` to `consume` in `kHashChunkBytes` pieces, in order, refusing a
/// file larger than `max_bytes`. Shared by both hashes so the two can never
/// disagree about which files they are willing to look at. Never throws
/// (rule 1).
template <typename Consumer>
StreamOutcome stream_file_bounded(const std::filesystem::path& path, std::uintmax_t max_bytes,
                                  Consumer consume)
{
  StreamOutcome outcome;

  // Size first, so an oversized file is refused without being read at all.
  // `file_size` failing (a race, a special file, a FIFO) is not fatal: the cap
  // is enforced again below while streaming, so the refusal does not depend on
  // this fast path succeeding.
  std::error_code size_error;
  const std::uintmax_t declared_size = std::filesystem::file_size(path, size_error);
  if (!size_error && declared_size > max_bytes)
  {
    outcome.readable = true;
    outcome.over_limit = true;
    return outcome;
  }

  std::ifstream stream(path, std::ios::binary);
  if (!stream)
  {
    return outcome;
  }
  outcome.readable = true;

  std::string chunk(kHashChunkBytes, '\0');
  while (stream.read(chunk.data(), static_cast<std::streamsize>(chunk.size())) ||
         stream.gcount() > 0)
  {
    const std::size_t chunk_bytes = static_cast<std::size_t>(stream.gcount());
    outcome.bytes_streamed += chunk_bytes;
    if (outcome.bytes_streamed > max_bytes)
    {
      outcome.over_limit = true;
      outcome.bytes_streamed = 0;
      return outcome;
    }
    consume(std::string_view(chunk.data(), chunk_bytes));
  }
  // A read error part-way through ends the loop exactly as end-of-file does,
  // and the digest of whatever arrived before it is a different value that
  // would silently never match. Report the file as unreadable instead.
  if (stream.bad())
  {
    outcome.readable = false;
    outcome.bytes_streamed = 0;
  }
  return outcome;
}

}  // namespace

BoundedFileRead read_file_bounded(const std::filesystem::path& path, std::size_t max_bytes)
{
  BoundedFileRead outcome;
  std::ifstream stream(path, std::ios::binary);
  if (!stream)
  {
    return outcome;
  }
  outcome.readable = true;

  // Read only as many bytes as the file actually holds (capped at max_bytes),
  // rather than always sizing the buffer to the full cap: a 1 MiB cap applied
  // to a few-KiB CMakeLists.txt would otherwise zero-fill and immediately
  // discard almost all of that buffer, on every one of up to thousands of
  // files per scan. `file_size` failing (a race, a special file) falls back to
  // the cap, matching the prior always-cap-sized behavior exactly.
  std::error_code size_error;
  const std::uintmax_t file_size = std::filesystem::file_size(path, size_error);
  const std::size_t bytes_to_read =
      (!size_error && file_size < max_bytes) ? static_cast<std::size_t>(file_size) : max_bytes;

  outcome.bytes.resize(bytes_to_read);
  stream.read(outcome.bytes.data(), static_cast<std::streamsize>(bytes_to_read));
  outcome.bytes.resize(static_cast<std::size_t>(stream.gcount()));
  if (stream.peek() != std::char_traits<char>::eof())
  {
    outcome.truncated = true;
  }
  return outcome;
}

BoundedFileRead bound_in_memory_bytes(std::string_view bytes, std::size_t max_bytes)
{
  BoundedFileRead outcome;
  outcome.readable = true;
  // Same rule as `read_file_bounded`: truncated means bytes remain past the cap.
  outcome.truncated = bytes.size() > max_bytes;
  outcome.bytes.assign(bytes.substr(0, max_bytes));
  return outcome;
}

std::string read_first_line_bounded(const std::filesystem::path& path, std::size_t max_bytes)
{
  const BoundedFileRead file_read = read_file_bounded(path, max_bytes);
  if (!file_read.readable)
  {
    return {};
  }
  std::string_view first_line(file_read.bytes);
  const std::size_t newline = first_line.find('\n');
  if (newline != std::string_view::npos)
  {
    first_line = first_line.substr(0, newline);
  }
  return trimmed(first_line);
}

BoundedFileDigest sha256_file_bounded(const std::filesystem::path& path, std::uintmax_t max_bytes)
{
  Sha256 hash;
  const StreamOutcome outcome =
      stream_file_bounded(path, max_bytes, [&hash](std::string_view chunk) { hash.update(chunk); });

  BoundedFileDigest result;
  result.readable = outcome.readable;
  result.over_limit = outcome.over_limit;
  result.bytes_hashed = outcome.bytes_streamed;
  if (result.readable && !result.over_limit)
  {
    result.digest = hash.digest();
  }
  return result;
}

BoundedFileFastHash xxh3_file_bounded(const std::filesystem::path& path, std::uintmax_t max_bytes)
{
  BoundedFileFastHash result;

  // xxhash keeps its streaming state opaque, so it hands out an allocation
  // rather than a value type. unique_ptr owns it here; the deleter's return
  // code is unused, which is why it is wrapped rather than called by hand.
  const std::unique_ptr<XXH3_state_t, decltype(&XXH3_freeState)> state(XXH3_createState(),
                                                                       &XXH3_freeState);
  if (state == nullptr || XXH3_64bits_reset(state.get()) != XXH_OK)
  {
    // An allocation failure is reported as "could not read this file" rather
    // than as a zero hash: a zero would be probed against the corpus like any
    // other value (rule 1, no throwing, but also no silent wrong answer).
    return result;
  }

  const StreamOutcome outcome =
      stream_file_bounded(path, max_bytes, [&state](std::string_view chunk)
                          { XXH3_64bits_update(state.get(), chunk.data(), chunk.size()); });

  result.readable = outcome.readable;
  result.over_limit = outcome.over_limit;
  result.bytes_hashed = outcome.bytes_streamed;
  if (result.readable && !result.over_limit)
  {
    result.hash = XXH3_64bits_digest(state.get());
  }
  return result;
}

}  // namespace bomwerk::core
