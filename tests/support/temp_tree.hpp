#pragma once
#include <atomic>
#include <filesystem>
#include <fstream>
#include <ios>
#include <random>
#include <string>
#include <string_view>
#include <system_error>

namespace bomwerk::test
{

/// A throwaway directory tree under the system temp dir, removed on
/// destruction. Producer tests use it to synthesize a repo (`.gitmodules` plus
/// git plumbing) without committing a nested `.git` into the source tree: git
/// refuses to track paths containing a `.git` component.
class TempTree
{
 public:
  TempTree()
  {
    static std::atomic<unsigned> counter{0};
    std::random_device device;
    root_ = std::filesystem::temp_directory_path() / ("bomwerk_test_" + std::to_string(device()) +
                                                      "_" + std::to_string(counter.fetch_add(1)));
    std::filesystem::create_directories(root_);
  }

  ~TempTree()
  {
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
  }

  TempTree(const TempTree&) = delete;
  TempTree& operator=(const TempTree&) = delete;

  const std::filesystem::path& root() const { return root_; }

  /// Write `contents` to `relative_path`, creating parent directories. Binary
  /// mode so exact bytes (CRLF, NUL, a missing trailing newline) survive.
  void write(const std::filesystem::path& relative_path, std::string_view contents) const
  {
    const std::filesystem::path full = root_ / relative_path;
    std::filesystem::create_directories(full.parent_path());
    std::ofstream stream(full, std::ios::binary);
    stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  }

 private:
  std::filesystem::path root_;
};

}  // namespace bomwerk::test
