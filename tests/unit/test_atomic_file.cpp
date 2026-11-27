// ctest unit test for the shared atomic artifact write (core/atomic_file).
//
// Every generated artifact goes through `write_file_atomically`, so these
// cases pin its contract: a failure at any step (create, write, flush,
// replace) leaves the previous destination byte-identical, or absent when
// there was none, removes the temporary file, and names the failed step and
// path. Failures are injected through a `FileSystemOperations` double that
// delegates to the real operations, so the real files and the real cleanup
// path are exercised. The POSIX replace semantics are checked directly.
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "core/atomic_file.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace core = bomwerk::core;

using bomwerk::test::TempTree;
using core::AtomicFileWriter;
using core::AtomicWriteOutcome;
using core::AtomicWriteStep;

namespace
{

constexpr std::string_view kPreviousContents = "previous whole document\n";
constexpr std::string_view kNewContents = "{\"bomFormat\": \"CycloneDX\", \"components\": []}\n";

std::string read_file(const fs::path& path)
{
  std::ifstream stream(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

/// Every staged temporary file left in `directory`: anything named
/// `*.bomwerk-*.tmp`.
std::vector<fs::path> leftover_temporary_files(const fs::path& directory)
{
  std::vector<fs::path> leftovers;
  std::error_code error;
  for (const fs::directory_entry& entry : fs::directory_iterator(directory, error))
  {
    const std::string name = entry.path().filename().string();
    const bool has_marker = name.find(".bomwerk-") != std::string::npos;
    const bool has_suffix = name.size() >= 4 && name.compare(name.size() - 4, 4, ".tmp") == 0;
    if (has_marker && has_suffix)
    {
      leftovers.push_back(entry.path());
    }
  }
  return leftovers;
}

/// The real operations, except that one chosen step fails. A failing write
/// writes half the bytes first, the way a disk that fills up mid-write does.
class FailingOperations final : public core::FileSystemOperations
{
 public:
  explicit FailingOperations(AtomicWriteStep failing_step) : failing_step_(failing_step) {}

  bool create_temporary(const fs::path& destination, std::optional<fs::perms> permissions,
                        fs::path& temporary_path, int& descriptor, std::string& reason) override
  {
    if (failing_step_ == AtomicWriteStep::kCreateTemporary)
    {
      temporary_path = core::atomic_temporary_path_for(destination, 1, 0);
      reason = "injected create failure";
      return false;
    }
    return native_.create_temporary(destination, permissions, temporary_path, descriptor, reason);
  }

  bool write_all(int descriptor, std::string_view contents, std::string& reason) override
  {
    if (failing_step_ == AtomicWriteStep::kWrite)
    {
      std::string ignored_reason;
      static_cast<void>(
          native_.write_all(descriptor, contents.substr(0, contents.size() / 2), ignored_reason));
      reason = "injected write failure";
      return false;
    }
    return native_.write_all(descriptor, contents, reason);
  }

  bool flush_and_close(int descriptor, std::string& reason) override
  {
    if (failing_step_ == AtomicWriteStep::kFlush)
    {
      // The descriptor is closed whether or not the flush succeeds; honour
      // that so the test does not leak it.
      native_.close_quietly(descriptor);
      reason = "injected flush failure";
      return false;
    }
    return native_.flush_and_close(descriptor, reason);
  }

  void close_quietly(int descriptor) override { native_.close_quietly(descriptor); }

  bool replace(const fs::path& temporary_path, const fs::path& destination,
               std::string& reason) override
  {
    if (failing_step_ == AtomicWriteStep::kReplace)
    {
      reason = "injected replace failure";
      return false;
    }
    return native_.replace(temporary_path, destination, reason);
  }

  void remove_quietly(const fs::path& temporary_path) override
  {
    native_.remove_quietly(temporary_path);
  }

 private:
  AtomicWriteStep failing_step_;
  core::FileSystemOperations& native_ = core::native_file_system_operations();
};

constexpr AtomicWriteStep kEveryStep[] = {AtomicWriteStep::kCreateTemporary,
                                          AtomicWriteStep::kWrite, AtomicWriteStep::kFlush,
                                          AtomicWriteStep::kReplace};

#if !defined(_WIN32)
bool is_running_as_root()
{
  return ::geteuid() == 0;
}
#endif

}  // namespace

int main()
{
  // Given a destination, a process id and an attempt number, when the temporary
  // name is derived, then it is the documented, recognisable shape: the full
  // file name, ".bomwerk-<pid>-<attempt>", and a plain ".tmp" extension, in the
  // same directory and with no hidden dot prefix.
  {
    const fs::path staged = core::atomic_temporary_path_for("out/sbom.cdx.json", 4182, 0);
    BOMWERK_TEST_CHECK(staged == fs::path("out/sbom.cdx.json.bomwerk-4182-0.tmp"));
    BOMWERK_TEST_CHECK(staged.parent_path() == fs::path("out"));
    BOMWERK_TEST_CHECK(staged.extension() == fs::path(".tmp"));
    BOMWERK_TEST_CHECK(staged.filename().string().front() != '.');
    BOMWERK_TEST_CHECK(core::atomic_temporary_path_for("sbom.json", 7, 12) ==
                       fs::path("sbom.json.bomwerk-7-12.tmp"));
  }

  // Given no destination yet, when it is written atomically, then it holds the
  // exact bytes and no temporary file is left beside it.
  {
    TempTree tree;
    const fs::path destination = tree.root() / "sbom.cdx.json";
    const AtomicWriteOutcome outcome = core::write_file_atomically(destination, kNewContents);
    BOMWERK_TEST_CHECK(outcome.written);
    BOMWERK_TEST_CHECK(!outcome.destination_existed);
    BOMWERK_TEST_CHECK(read_file(destination) == kNewContents);
    BOMWERK_TEST_CHECK(leftover_temporary_files(tree.root()).empty());
  }

  // Given empty contents (observe's trace reset), when written atomically, then
  // the destination exists and is empty.
  {
    TempTree tree;
    tree.write("trace.jsonl", kPreviousContents);
    const fs::path destination = tree.root() / "trace.jsonl";
    BOMWERK_TEST_CHECK(core::write_file_atomically(destination, "").written);
    BOMWERK_TEST_CHECK(fs::exists(destination));
    BOMWERK_TEST_CHECK(fs::file_size(destination) == 0);
    BOMWERK_TEST_CHECK(leftover_temporary_files(tree.root()).empty());
  }

  // Given an existing destination, when it is replaced, then it holds the new
  // bytes and the outcome records that a previous file existed.
  {
    TempTree tree;
    tree.write("sbom.cdx.json", kPreviousContents);
    const fs::path destination = tree.root() / "sbom.cdx.json";
    const AtomicWriteOutcome outcome = core::write_file_atomically(destination, kNewContents);
    BOMWERK_TEST_CHECK(outcome.written);
    BOMWERK_TEST_CHECK(outcome.destination_existed);
    BOMWERK_TEST_CHECK(read_file(destination) == kNewContents);
    BOMWERK_TEST_CHECK(leftover_temporary_files(tree.root()).empty());
  }

  // Given an existing destination and each step made to fail in turn, when it
  // is written atomically, then the previous bytes are untouched, no temporary
  // file remains, and the outcome names that step, the right path and a reason.
  for (const AtomicWriteStep failing_step : kEveryStep)
  {
    TempTree tree;
    tree.write("sbom.cdx.json", kPreviousContents);
    const fs::path destination = tree.root() / "sbom.cdx.json";
    FailingOperations operations(failing_step);
    AtomicFileWriter writer(operations);
    const AtomicWriteOutcome outcome = writer.write(destination, kNewContents);
    BOMWERK_TEST_CHECK(!outcome.written);
    BOMWERK_TEST_CHECK(outcome.failed_step == failing_step);
    BOMWERK_TEST_CHECK(outcome.destination_existed);
    BOMWERK_TEST_CHECK(!outcome.reason.empty());
    BOMWERK_TEST_CHECK(read_file(destination) == kPreviousContents);
    BOMWERK_TEST_CHECK(leftover_temporary_files(tree.root()).empty());
    if (failing_step == AtomicWriteStep::kReplace)
    {
      BOMWERK_TEST_CHECK(outcome.failed_path == destination);
    }
    else
    {
      BOMWERK_TEST_CHECK(outcome.failed_path.parent_path() == destination.parent_path());
      BOMWERK_TEST_CHECK(outcome.failed_path.extension() == fs::path(".tmp"));
    }
  }

  // Given no destination and each step made to fail in turn, when it is written
  // atomically, then no destination appears (not even a partial one) and no
  // temporary file remains.
  for (const AtomicWriteStep failing_step : kEveryStep)
  {
    TempTree tree;
    const fs::path destination = tree.root() / "coverage.json";
    FailingOperations operations(failing_step);
    AtomicFileWriter writer(operations);
    const AtomicWriteOutcome outcome = writer.write(destination, kNewContents);
    BOMWERK_TEST_CHECK(!outcome.written);
    BOMWERK_TEST_CHECK(!outcome.destination_existed);
    BOMWERK_TEST_CHECK(!fs::exists(destination));
    BOMWERK_TEST_CHECK(leftover_temporary_files(tree.root()).empty());
  }

  // Given a destination that is a directory, when a file is written there, then
  // the replace step fails, the directory and its contents are intact, and no
  // temporary file remains.
  {
    TempTree tree;
    tree.write("report.html/keep.txt", kPreviousContents);
    const fs::path destination = tree.root() / "report.html";
    const AtomicWriteOutcome outcome = core::write_file_atomically(destination, kNewContents);
    BOMWERK_TEST_CHECK(!outcome.written);
    BOMWERK_TEST_CHECK(outcome.failed_step == AtomicWriteStep::kReplace);
    BOMWERK_TEST_CHECK(fs::is_directory(destination));
    BOMWERK_TEST_CHECK(read_file(destination / "keep.txt") == kPreviousContents);
    BOMWERK_TEST_CHECK(leftover_temporary_files(tree.root()).empty());
  }

  // Given a destination directory that does not exist, when a file is written
  // there, then creating the temporary file fails and names the missing place.
  {
    TempTree tree;
    const fs::path destination = tree.root() / "missing" / "sbom.cdx.json";
    const AtomicWriteOutcome outcome = core::write_file_atomically(destination, kNewContents);
    BOMWERK_TEST_CHECK(!outcome.written);
    BOMWERK_TEST_CHECK(outcome.failed_step == AtomicWriteStep::kCreateTemporary);
    BOMWERK_TEST_CHECK(outcome.failed_path.parent_path() == destination.parent_path());
    BOMWERK_TEST_CHECK(!fs::exists(destination));
  }

#if !defined(_WIN32)
  // Given a reader that opened the destination before it was replaced, when it
  // is replaced, then that reader still sees the previous whole file while a
  // new reader sees the new one: rename(2) semantics on Linux and macOS.
  {
    TempTree tree;
    tree.write("sbom.cdx.json", kPreviousContents);
    const fs::path destination = tree.root() / "sbom.cdx.json";
    std::ifstream earlier_reader(destination, std::ios::binary);
    BOMWERK_TEST_CHECK(earlier_reader.good());
    BOMWERK_TEST_CHECK(core::write_file_atomically(destination, kNewContents).written);
    const std::string seen_by_earlier_reader((std::istreambuf_iterator<char>(earlier_reader)),
                                             std::istreambuf_iterator<char>());
    BOMWERK_TEST_CHECK(seen_by_earlier_reader == kPreviousContents);
    BOMWERK_TEST_CHECK(read_file(destination) == kNewContents);
  }

  // Given an existing destination with a narrower mode, when it is replaced,
  // then the new file keeps that mode.
  {
    TempTree tree;
    tree.write("sidecar.json", kPreviousContents);
    const fs::path destination = tree.root() / "sidecar.json";
    const fs::perms narrow_mode =
        fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read;
    fs::permissions(destination, narrow_mode, fs::perm_options::replace);
    BOMWERK_TEST_CHECK(core::write_file_atomically(destination, kNewContents).written);
    BOMWERK_TEST_CHECK((fs::status(destination).permissions() & fs::perms::all) == narrow_mode);
  }

  // Given a new destination, when it is written, then it is never executable.
  {
    TempTree tree;
    const fs::path destination = tree.root() / "report.html";
    BOMWERK_TEST_CHECK(core::write_file_atomically(destination, kNewContents).written);
    const fs::perms execute_bits =
        fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec;
    BOMWERK_TEST_CHECK((fs::status(destination).permissions() & execute_bits) == fs::perms::none);
  }

  // Given a destination reached through a symbolic link, when it is written,
  // then the link's target holds the new bytes and the link is still a link.
  {
    TempTree tree;
    tree.write("real/sbom.cdx.json", kPreviousContents);
    const fs::path link = tree.root() / "sbom.cdx.json";
    fs::create_symlink(fs::path("real") / "sbom.cdx.json", link);
    BOMWERK_TEST_CHECK(core::write_file_atomically(link, kNewContents).written);
    BOMWERK_TEST_CHECK(fs::is_symlink(fs::symlink_status(link)));
    BOMWERK_TEST_CHECK(read_file(tree.root() / "real" / "sbom.cdx.json") == kNewContents);
    BOMWERK_TEST_CHECK(leftover_temporary_files(tree.root()).empty());
    BOMWERK_TEST_CHECK(leftover_temporary_files(tree.root() / "real").empty());
  }

  // Root ignores permission bits, so the two real permission failures below can
  // only be observed as an ordinary user.
  if (!is_running_as_root())
  {
    // Given an existing destination in a directory that is not writable, when
    // it is written, then creating the temporary file fails with the
    // operating system's reason and the previous bytes are untouched.
    {
      TempTree tree;
      tree.write("locked/sbom.cdx.json", kPreviousContents);
      const fs::path directory = tree.root() / "locked";
      const fs::path destination = directory / "sbom.cdx.json";
      fs::permissions(directory, fs::perms::owner_read | fs::perms::owner_exec,
                      fs::perm_options::replace);
      const AtomicWriteOutcome outcome = core::write_file_atomically(destination, kNewContents);
      fs::permissions(directory, fs::perms::owner_all, fs::perm_options::replace);
      BOMWERK_TEST_CHECK(!outcome.written);
      BOMWERK_TEST_CHECK(outcome.failed_step == AtomicWriteStep::kCreateTemporary);
      BOMWERK_TEST_CHECK(!outcome.reason.empty());
      BOMWERK_TEST_CHECK(read_file(destination) == kPreviousContents);
      BOMWERK_TEST_CHECK(leftover_temporary_files(directory).empty());
    }

    // Given a destination the operator made read-only, when it is written, then
    // it is refused at the replace step and kept, as a plain write would refuse
    // it, rather than silently swapped out by the rename.
    {
      TempTree tree;
      tree.write("sbom.cdx.json", kPreviousContents);
      const fs::path destination = tree.root() / "sbom.cdx.json";
      fs::permissions(destination, fs::perms::owner_read, fs::perm_options::replace);
      const AtomicWriteOutcome outcome = core::write_file_atomically(destination, kNewContents);
      BOMWERK_TEST_CHECK(!outcome.written);
      BOMWERK_TEST_CHECK(outcome.failed_step == AtomicWriteStep::kReplace);
      BOMWERK_TEST_CHECK(read_file(destination) == kPreviousContents);
      BOMWERK_TEST_CHECK(leftover_temporary_files(tree.root()).empty());
      fs::permissions(destination, fs::perms::owner_read | fs::perms::owner_write,
                      fs::perm_options::replace);
    }
  }
#endif

  // Given a failed write over an existing destination, when it is described,
  // then the message names the artifact, both paths, the reason, that the
  // previous file is unchanged, and what to check.
  {
    AtomicWriteOutcome outcome;
    outcome.failed_step = AtomicWriteStep::kCreateTemporary;
    outcome.failed_path = "out/sbom.cdx.json.bomwerk-41-0.tmp";
    outcome.reason = "Permission denied";
    outcome.destination_existed = true;
    const std::string description =
        core::describe_atomic_write_failure("SBOM", "out/sbom.cdx.json", outcome);
    BOMWERK_TEST_CHECK(description ==
                       "could not write the SBOM to out/sbom.cdx.json: creating the temporary "
                       "file out/sbom.cdx.json.bomwerk-41-0.tmp failed (Permission denied); the "
                       "previous out/sbom.cdx.json is unchanged. Check that the directory exists "
                       "and is writable.");
  }

  // Given a failed write with no previous destination, when it is described,
  // then the message says no file was written instead.
  {
    AtomicWriteOutcome outcome;
    outcome.failed_step = AtomicWriteStep::kWrite;
    outcome.failed_path = "coverage.json.bomwerk-41-3.tmp";
    outcome.reason = "No space left on device";
    const std::string description =
        core::describe_atomic_write_failure("coverage file", "coverage.json", outcome);
    BOMWERK_TEST_CHECK(description.find("could not write the coverage file to coverage.json") == 0);
    BOMWERK_TEST_CHECK(description.find("(No space left on device)") != std::string::npos);
    BOMWERK_TEST_CHECK(description.find("no file was written.") != std::string::npos);
    BOMWERK_TEST_CHECK(description.find("unchanged") == std::string::npos);
    BOMWERK_TEST_CHECK(description.find("Check free disk space") != std::string::npos);
  }

  std::puts("test_atomic_file: OK");
  return 0;
}
