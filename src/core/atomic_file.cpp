#include "core/atomic_file.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <system_error>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <sys/stat.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace bomwerk::core
{
namespace
{

/// Temporary names tried before giving up. A name is only ever taken by a
/// stale file from a killed run whose process id has since been reused, so a
/// handful of attempts covers it.
constexpr unsigned kMaxTemporaryNameAttempts = 16;

/// Bound on symbolic-link hops when resolving the destination, the common
/// POSIX `SYMLOOP_MAX`. A longer chain is a loop; the link itself is then
/// replaced, as it would be by any rename.
constexpr unsigned kMaxSymbolicLinkHops = 40;

/// Largest single write request. Keeps the byte count inside every platform's
/// `write` argument type (`unsigned int` on Windows).
constexpr std::size_t kMaxWriteChunkBytes = std::size_t{1} << 30;

/// Process-wide, so two writes in one process never try the same name.
std::atomic<unsigned> temporary_name_counter{0};

std::string errno_reason(int error_number)
{
  return std::error_code(error_number, std::generic_category()).message();
}

unsigned long current_process_id()
{
#if defined(_WIN32)
  return static_cast<unsigned long>(_getpid());
#else
  return static_cast<unsigned long>(::getpid());
#endif
}

#if !defined(_WIN32)

/// Mode a new temporary file is created with, before the umask applies: the
/// same mode an ordinary `std::ofstream` write creates a file with.
constexpr mode_t kNewFileMode = 0666;

/// Flush a descriptor's data to the disk itself, not only to the kernel.
bool sync_descriptor(int descriptor, std::string& reason)
{
#if defined(__APPLE__)
  // On macOS fsync only reaches the drive's own cache; F_FULLFSYNC asks the
  // drive to flush that too. Some filesystems (network shares, FAT) refuse it,
  // and plain fsync is then the best available.
  if (::fcntl(descriptor, F_FULLFSYNC) == 0)
  {
    return true;
  }
#endif
  while (::fsync(descriptor) != 0)
  {
    if (errno == EINTR)
    {
      continue;
    }
    reason = errno_reason(errno);
    return false;
  }
  return true;
}

/// Make the rename itself durable. Best effort: by the time this runs the
/// destination is already whole, and some filesystems (network and virtual
/// ones) refuse to sync a directory, so a failure is only logged.
void sync_parent_directory(const fs::path& destination)
{
  const fs::path directory =
      destination.has_parent_path() ? destination.parent_path() : fs::path(".");
  const int directory_descriptor = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (directory_descriptor < 0)
  {
    spdlog::debug("could not open {} to flush the rename of {}: {}", directory.string(),
                  destination.string(), errno_reason(errno));
    return;
  }
  if (::fsync(directory_descriptor) != 0)
  {
    spdlog::debug("could not flush {} after replacing {}: {}", directory.string(),
                  destination.string(), errno_reason(errno));
  }
  ::close(directory_descriptor);
}

/// Linux and macOS: exclusive `open`, `fsync` (`F_FULLFSYNC` on macOS) and
/// `rename(2)`, which replaces the destination atomically. A reader that
/// already holds the previous file open keeps reading the previous bytes.
class PosixFileSystemOperations final : public FileSystemOperations
{
 public:
  bool create_temporary(const fs::path& destination, std::optional<fs::perms> permissions,
                        fs::path& temporary_path, int& descriptor, std::string& reason) override
  {
    descriptor = -1;
    int last_error = EEXIST;
    for (unsigned attempt_index = 0; attempt_index < kMaxTemporaryNameAttempts; ++attempt_index)
    {
      temporary_path = atomic_temporary_path_for(destination, current_process_id(),
                                                 temporary_name_counter.fetch_add(1));
      descriptor =
          ::open(temporary_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, kNewFileMode);
      if (descriptor >= 0)
      {
        break;
      }
      last_error = errno;
      if (last_error != EEXIST && last_error != EINTR)
      {
        break;
      }
    }
    if (descriptor < 0)
    {
      reason = errno_reason(last_error);
      return false;
    }
    if (permissions.has_value())
    {
      // `perms::all` drops setuid, setgid and sticky: a generated artifact
      // never needs them, even when the file it replaces had them.
      const mode_t mode = static_cast<mode_t>(*permissions & fs::perms::all);
      if (::fchmod(descriptor, mode) != 0)
      {
        reason = errno_reason(errno);
        ::close(descriptor);
        ::unlink(temporary_path.c_str());
        descriptor = -1;
        return false;
      }
    }
    return true;
  }

  bool write_all(int descriptor, std::string_view contents, std::string& reason) override
  {
    std::size_t written_bytes = 0;
    while (written_bytes < contents.size())
    {
      const std::size_t chunk_bytes =
          std::min(contents.size() - written_bytes, kMaxWriteChunkBytes);
      const ssize_t result = ::write(descriptor, contents.data() + written_bytes, chunk_bytes);
      if (result < 0)
      {
        if (errno == EINTR)
        {
          continue;
        }
        reason = errno_reason(errno);
        return false;
      }
      if (result == 0)
      {
        // No progress and no error: report it rather than spin.
        reason = errno_reason(EIO);
        return false;
      }
      written_bytes += static_cast<std::size_t>(result);
    }
    return true;
  }

  bool flush_and_close(int descriptor, std::string& reason) override
  {
    bool is_flushed = sync_descriptor(descriptor, reason);
    if (::close(descriptor) != 0 && is_flushed)
    {
      reason = errno_reason(errno);
      is_flushed = false;
    }
    return is_flushed;
  }

  void close_quietly(int descriptor) override { ::close(descriptor); }

  bool replace(const fs::path& temporary_path, const fs::path& destination,
               std::string& reason) override
  {
    // rename() would replace a destination the operator made read-only, which
    // a plain write never could. Keep that protection.
    if (::access(destination.c_str(), W_OK) != 0 && errno != ENOENT)
    {
      reason = errno_reason(errno);
      return false;
    }
    if (::rename(temporary_path.c_str(), destination.c_str()) != 0)
    {
      reason = errno_reason(errno);
      return false;
    }
    sync_parent_directory(destination);
    return true;
  }

  void remove_quietly(const fs::path& temporary_path) override
  {
    std::error_code ignored;
    fs::remove(temporary_path, ignored);
  }
};

#else  // _WIN32

// TODO: no Windows build or CI exists, so this implementation has never been
// compiled or run.

/// Attempts to replace a destination another process briefly holds open
/// (virus scanners and search indexers do this to new files).
constexpr unsigned kMaxReplaceAttempts = 5;

/// Wait between those attempts.
constexpr DWORD kReplaceRetryDelayMilliseconds = 50;

std::string last_error_reason(DWORD error_number)
{
  return std::error_code(static_cast<int>(error_number), std::system_category()).message();
}

/// Windows: exclusive `_wopen`, `_commit` and `MoveFileExW` with
/// `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`, which replaces the
/// destination in one step and returns only once the move is on disk.
class WindowsFileSystemOperations final : public FileSystemOperations
{
 public:
  bool create_temporary(const fs::path& destination, std::optional<fs::perms> /*permissions*/,
                        fs::path& temporary_path, int& descriptor, std::string& reason) override
  {
    // Windows has no mode bits to carry over; a read-only destination is
    // refused by MoveFileExW at the replace step instead.
    descriptor = -1;
    int last_error = EEXIST;
    for (unsigned attempt_index = 0; attempt_index < kMaxTemporaryNameAttempts; ++attempt_index)
    {
      temporary_path = atomic_temporary_path_for(destination, current_process_id(),
                                                 temporary_name_counter.fetch_add(1));
      descriptor =
          _wopen(temporary_path.c_str(), _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY | _O_NOINHERIT,
                 _S_IREAD | _S_IWRITE);
      if (descriptor >= 0)
      {
        return true;
      }
      last_error = errno;
      if (last_error != EEXIST)
      {
        break;
      }
    }
    reason = errno_reason(last_error);
    return false;
  }

  bool write_all(int descriptor, std::string_view contents, std::string& reason) override
  {
    std::size_t written_bytes = 0;
    while (written_bytes < contents.size())
    {
      const std::size_t chunk_bytes =
          std::min(contents.size() - written_bytes, kMaxWriteChunkBytes);
      const int result = _write(descriptor, contents.data() + written_bytes,
                                static_cast<unsigned int>(chunk_bytes));
      if (result <= 0)
      {
        reason = errno_reason(result < 0 ? errno : EIO);
        return false;
      }
      written_bytes += static_cast<std::size_t>(result);
    }
    return true;
  }

  bool flush_and_close(int descriptor, std::string& reason) override
  {
    bool is_flushed = true;
    if (_commit(descriptor) != 0)
    {
      reason = errno_reason(errno);
      is_flushed = false;
    }
    if (_close(descriptor) != 0 && is_flushed)
    {
      reason = errno_reason(errno);
      is_flushed = false;
    }
    return is_flushed;
  }

  void close_quietly(int descriptor) override { _close(descriptor); }

  bool replace(const fs::path& temporary_path, const fs::path& destination,
               std::string& reason) override
  {
    DWORD last_error = ERROR_SUCCESS;
    for (unsigned attempt_index = 0; attempt_index < kMaxReplaceAttempts; ++attempt_index)
    {
      if (MoveFileExW(temporary_path.c_str(), destination.c_str(),
                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0)
      {
        return true;
      }
      last_error = GetLastError();
      const bool is_transient = last_error == ERROR_SHARING_VIOLATION ||
                                last_error == ERROR_LOCK_VIOLATION ||
                                last_error == ERROR_ACCESS_DENIED;
      if (!is_transient)
      {
        break;
      }
      Sleep(kReplaceRetryDelayMilliseconds);
    }
    reason = last_error_reason(last_error);
    return false;
  }

  void remove_quietly(const fs::path& temporary_path) override
  {
    std::error_code ignored;
    fs::remove(temporary_path, ignored);
  }
};

#endif  // _WIN32

/// Follow `destination` through symbolic links to the file a plain write
/// would reach, so the link survives and its target is what gets replaced.
/// A dangling link resolves to the path it names, which is then created.
fs::path resolve_symbolic_links(const fs::path& destination)
{
  fs::path resolved = destination;
  for (unsigned hop_index = 0; hop_index < kMaxSymbolicLinkHops; ++hop_index)
  {
    std::error_code error;
    if (!fs::is_symlink(fs::symlink_status(resolved, error)))
    {
      return resolved;
    }
    const fs::path link_target = fs::read_symlink(resolved, error);
    if (error)
    {
      return resolved;
    }
    resolved = link_target.is_absolute() ? link_target : resolved.parent_path() / link_target;
  }
  return resolved;
}

AtomicWriteOutcome failed(AtomicWriteOutcome outcome, AtomicWriteStep step, fs::path failed_path,
                          std::string reason)
{
  outcome.written = false;
  outcome.failed_step = step;
  outcome.failed_path = std::move(failed_path);
  outcome.reason = reason.empty() ? std::string("unknown error") : std::move(reason);
  return outcome;
}

/// What the operator is told about each step: what was being attempted and
/// what to check. Kept in one table so the wording stays consistent.
struct AtomicWriteStepText
{
  const char* action;
  const char* advice;
};

AtomicWriteStepText step_text(AtomicWriteStep step)
{
  switch (step)
  {
    case AtomicWriteStep::kCreateTemporary:
      return {"creating the temporary file", "Check that the directory exists and is writable."};
    case AtomicWriteStep::kWrite:
      return {"writing the temporary file", "Check free disk space and quota."};
    case AtomicWriteStep::kFlush:
      return {"flushing the temporary file to disk",
              "Check free disk space, quota and the health of the disk."};
    case AtomicWriteStep::kReplace:
      return {"renaming the finished temporary file onto",
              "Check that the destination is a writable file, not a directory, and that no other "
              "program holds it open."};
  }
  return {"writing", ""};
}

}  // namespace

fs::path atomic_temporary_path_for(const fs::path& destination, unsigned long process_id,
                                   unsigned attempt)
{
  fs::path temporary_path = destination;
  temporary_path +=
      ".bomwerk-" + std::to_string(process_id) + "-" + std::to_string(attempt) + ".tmp";
  return temporary_path;
}

FileSystemOperations& native_file_system_operations()
{
#if defined(_WIN32)
  static WindowsFileSystemOperations operations;
#else
  static PosixFileSystemOperations operations;
#endif
  return operations;
}

AtomicWriteOutcome AtomicFileWriter::write(const fs::path& destination, std::string_view contents)
{
  AtomicWriteOutcome outcome;
  const fs::path target = resolve_symbolic_links(destination);

  std::error_code status_error;
  const fs::file_status target_status = fs::status(target, status_error);
  outcome.destination_existed = fs::exists(target_status);
  std::optional<fs::perms> permissions;
  if (fs::is_regular_file(target_status))
  {
    permissions = target_status.permissions();
  }

  fs::path temporary_path;
  int descriptor = -1;
  std::string reason;
  if (!operations_.create_temporary(target, permissions, temporary_path, descriptor, reason))
  {
    return failed(outcome, AtomicWriteStep::kCreateTemporary, temporary_path, reason);
  }
  if (!operations_.write_all(descriptor, contents, reason))
  {
    operations_.close_quietly(descriptor);
    operations_.remove_quietly(temporary_path);
    return failed(outcome, AtomicWriteStep::kWrite, temporary_path, reason);
  }
  if (!operations_.flush_and_close(descriptor, reason))
  {
    operations_.remove_quietly(temporary_path);
    return failed(outcome, AtomicWriteStep::kFlush, temporary_path, reason);
  }
  if (!operations_.replace(temporary_path, target, reason))
  {
    operations_.remove_quietly(temporary_path);
    return failed(outcome, AtomicWriteStep::kReplace, target, reason);
  }
  outcome.written = true;
  return outcome;
}

AtomicWriteOutcome write_file_atomically(const fs::path& destination, std::string_view contents)
{
  AtomicFileWriter writer(native_file_system_operations());
  return writer.write(destination, contents);
}

std::string describe_atomic_write_failure(std::string_view artifact_label,
                                          const fs::path& destination,
                                          const AtomicWriteOutcome& outcome)
{
  const AtomicWriteStepText text = step_text(outcome.failed_step);
  std::string description = "could not write the ";
  description += artifact_label;
  description += " to " + destination.string() + ": " + text.action + " " +
                 outcome.failed_path.string() + " failed (" + outcome.reason + "); ";
  description += outcome.destination_existed
                     ? "the previous " + destination.string() + " is unchanged."
                     : std::string("no file was written.");
  description += " ";
  description += text.advice;
  return description;
}

}  // namespace bomwerk::core
