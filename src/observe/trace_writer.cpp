#include "observe/trace_writer.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>

namespace bomwerk::observe
{
namespace
{

/// Trace files are ordinary developer artifacts: owner-writable, world-readable.
constexpr int kTraceFileMode = 0644;

/// Write every byte, tolerating short writes and signal interruption. A partial
/// write inside the lock would leave a truncated line behind, which is exactly
/// the corruption the lock exists to prevent.
bool write_fully(int file_descriptor, std::string_view bytes)
{
  std::size_t written_bytes = 0;
  while (written_bytes < bytes.size())
  {
    const ssize_t result =
        ::write(file_descriptor, bytes.data() + written_bytes, bytes.size() - written_bytes);
    if (result < 0)
    {
      if (errno == EINTR)
      {
        continue;
      }
      return false;
    }
    written_bytes += static_cast<std::size_t>(result);
  }
  return true;
}

}  // namespace

bool append_trace_line(const char* trace_path, std::string_view line)
{
  if (trace_path == nullptr || *trace_path == '\0')
  {
    return false;
  }

  // O_CLOEXEC: the real tool is exec'd moments later and must not inherit this
  // descriptor. O_APPEND keeps every write positioned at end-of-file even
  // though the lock already serializes writers.
  const int file_descriptor =
      ::open(trace_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, kTraceFileMode);
  if (file_descriptor < 0)
  {
    return false;
  }

  bool written = false;
  int lock_result = 0;
  while ((lock_result = ::flock(file_descriptor, LOCK_EX)) < 0 && errno == EINTR)
  {
    // Retry: a signal arriving mid-wait must not silently drop the line.
  }
  if (lock_result == 0)
  {
    written = write_fully(file_descriptor, line);
    ::flock(file_descriptor, LOCK_UN);
  }
  ::close(file_descriptor);
  return written;
}

}  // namespace bomwerk::observe
