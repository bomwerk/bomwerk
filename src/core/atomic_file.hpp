#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace bomwerk::core
{

/// The step of an atomic write that failed, in the order the writer runs them.
enum class AtomicWriteStep
{
  kCreateTemporary,  ///< the temporary sibling could not be created
  kWrite,            ///< the contents could not be written to the temporary file
  kFlush,            ///< the temporary file could not be flushed to disk and closed
  kReplace,          ///< the temporary file could not be renamed onto the destination
};

/// What one `write_file_atomically` call did. On failure the destination is
/// exactly what it was before the call (absent if it never existed) and the
/// temporary file has been removed.
struct AtomicWriteOutcome
{
  bool written = false;
  AtomicWriteStep failed_step = AtomicWriteStep::kCreateTemporary;
  std::filesystem::path failed_path;  ///< the temporary file, or the destination for kReplace
  std::string reason;                 ///< the operating system's description of the failure
  bool destination_existed = false;   ///< whether a previous destination was left in place
};

/// The temporary sibling a write to `destination` stages its bytes in:
/// `<filename>.bomwerk-<process id>-<attempt>.tmp`, in the destination's own
/// directory so the final rename never crosses a filesystem.
///
/// The shape is fixed and documented (`docs/capabilities.md`) so endpoint
/// protection can recognise it: a plain, visible `.tmp` extension, the same
/// write-then-rename pattern editors and office suites use, with no random or
/// high-entropy characters and no hidden dot prefix.
/// Example: `/out/sbom.cdx.json`, process 4182, attempt 0 yields
/// `/out/sbom.cdx.json.bomwerk-4182-0.tmp`.
[[nodiscard]] std::filesystem::path atomic_temporary_path_for(
    const std::filesystem::path& destination, unsigned long process_id, unsigned attempt);

/// The operating-system primitives `AtomicFileWriter` is built from. The native
/// implementation is the one every caller uses; tests substitute their own to
/// make a chosen step fail (same precedent as the vuln module's fake HTTP
/// transport). Descriptors are C runtime file descriptors on every platform.
/// No method throws (rule 1).
class FileSystemOperations
{
 public:
  virtual ~FileSystemOperations() = default;

  /// Create a new, empty temporary file beside `destination` that did not exist
  /// before (exclusive create), named by `atomic_temporary_path_for`.
  /// `permissions`, when set, is applied to it so a replaced destination keeps
  /// its mode. Sets `temporary_path` even on failure, to the last name tried.
  virtual bool create_temporary(const std::filesystem::path& destination,
                                std::optional<std::filesystem::perms> permissions,
                                std::filesystem::path& temporary_path, int& descriptor,
                                std::string& reason) = 0;

  /// Write every byte of `contents`, retrying short and interrupted writes.
  virtual bool write_all(int descriptor, std::string_view contents, std::string& reason) = 0;

  /// Flush the file's data to disk, then close it. The descriptor is closed
  /// whether or not the flush succeeded.
  virtual bool flush_and_close(int descriptor, std::string& reason) = 0;

  /// Close a descriptor on a path that has already failed; errors are ignored.
  virtual void close_quietly(int descriptor) = 0;

  /// Atomically replace `destination` with `temporary_path`.
  virtual bool replace(const std::filesystem::path& temporary_path,
                       const std::filesystem::path& destination, std::string& reason) = 0;

  /// Remove a temporary file that will not be used; errors are ignored.
  virtual void remove_quietly(const std::filesystem::path& temporary_path) = 0;
};

/// The real operating-system implementation: POSIX `open`/`fsync`/`rename` on
/// Linux and macOS (`F_FULLFSYNC` on macOS), `_wopen`/`_commit`/`MoveFileExW`
/// on Windows.
[[nodiscard]] FileSystemOperations& native_file_system_operations();

/// Writes a file so a reader only ever sees the previous whole file or the new
/// whole file, never a prefix: the bytes go to a temporary sibling, which is
/// flushed, closed and then renamed over the destination. Any failure removes
/// the temporary file and leaves the destination untouched.
///
/// A destination that is a symbolic link is resolved first, so the link's
/// target is replaced and the link itself survives, as an ordinary write
/// through the link would behave.
class AtomicFileWriter
{
 public:
  explicit AtomicFileWriter(FileSystemOperations& operations) : operations_(operations) {}

  /// Replace `destination` with exactly `contents`. Never throws (rule 1).
  [[nodiscard]] AtomicWriteOutcome write(const std::filesystem::path& destination,
                                         std::string_view contents);

 private:
  FileSystemOperations& operations_;
};

/// `AtomicFileWriter` over the native operations: the shared primitive for
/// every generated artifact (SBOMs, sidecars, reports, traces).
/// Example: `write_file_atomically("sbom.cdx.json", document).written` is true
/// and `sbom.cdx.json` holds `document`; on a full disk it is false and the
/// previous `sbom.cdx.json` is unchanged.
[[nodiscard]] AtomicWriteOutcome write_file_atomically(const std::filesystem::path& destination,
                                                       std::string_view contents);

/// The operator-facing explanation of a failed write: what failed, on which
/// path, why, what state the destination is in, and what to check.
/// Example: `could not write the SBOM to out/sbom.cdx.json: creating the
/// temporary file out/sbom.cdx.json.bomwerk-41-0.tmp failed (Permission
/// denied); the previous out/sbom.cdx.json is unchanged. Check that the
/// directory exists and is writable.`
[[nodiscard]] std::string describe_atomic_write_failure(std::string_view artifact_label,
                                                        const std::filesystem::path& destination,
                                                        const AtomicWriteOutcome& outcome);

}  // namespace bomwerk::core
