#include "core/file_io.hpp"

#include <fstream>
#include <ios>
#include <system_error>

#include "core/text.hpp"

namespace bomwerk::core
{

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

}  // namespace bomwerk::core
