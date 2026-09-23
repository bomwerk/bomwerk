#include "core/manifest_walk.hpp"

#include <string>
#include <utility>

#include "core/file_io.hpp"
#include "core/warning_code.hpp"

namespace bomwerk::core
{

Result<std::vector<WalkedManifestFile>> walk_bounded_manifest_files(
    const FileIndex& file_index, const std::filesystem::path& root, std::string_view filename,
    const ManifestWalkOptions& options)
{
  Result<std::vector<WalkedManifestFile>> result;
  std::size_t scanned_file_count = 0;
  for (const std::filesystem::path& relative_path : file_index.files)
  {
    if (relative_path.filename().string() != filename)
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      result.warn(WarningCode::kFileLimitReached,
                  options.producer_name + ": file limit reached; remaining " + options.file_label +
                      " files skipped",
                  options.producer_name);
      break;
    }
    ++scanned_file_count;

    const std::string label = relative_path.generic_string();
    const BoundedFileRead file_read =
        read_file_bounded(root / relative_path, options.max_file_bytes);
    if (!file_read.readable)
    {
      result.warn(WarningCode::kUnreadableFile,
                  options.producer_name + ": unreadable file: " + label, options.producer_name);
      continue;
    }

    WalkedManifestFile walked_file;
    walked_file.label = label;
    walked_file.bytes = file_read.bytes;
    walked_file.truncated = file_read.truncated;
    if (file_read.truncated)
    {
      if (!options.truncate_at_last_newline)
      {
        result.warn(WarningCode::kFileSizeLimitExceeded,
                    options.producer_name + ": file exceeds size limit, skipped: " + label,
                    options.producer_name);
        continue;
      }
      result.warn(
          WarningCode::kFileSizeLimitExceeded,
          options.producer_name + ": file exceeds size limit, parsing first part only: " + label,
          options.producer_name);
      const std::size_t last_newline = walked_file.bytes.rfind('\n');
      if (last_newline == std::string::npos)
      {
        walked_file.bytes.clear();
      }
      else
      {
        walked_file.bytes.resize(last_newline + 1);
      }
    }
    result.value.push_back(std::move(walked_file));
  }
  return result;
}

}  // namespace bomwerk::core
