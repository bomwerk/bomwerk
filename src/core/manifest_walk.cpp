#include "core/manifest_walk.hpp"

#include <string>
#include <utility>

#include "core/warning_code.hpp"

namespace bomwerk::core
{
namespace
{

constexpr std::string_view kUtf8ByteOrderMark = "\xEF\xBB\xBF";

/// The `Warning` a producer would build with `result.warn(code, message,
/// producer_name)`: the producer name is both prefix and ecosystem.
Warning producer_warning(WarningCode code, std::string_view producer_name, std::string_view text)
{
  const std::string producer(producer_name);
  return Warning{code, producer + ": " + std::string(text), producer, {}};
}

}  // namespace

std::optional<WalkedManifestFile> prepare_manifest_file(std::string label,
                                                        BoundedFileRead file_read,
                                                        std::string_view producer_name,
                                                        OversizedFilePolicy oversized,
                                                        std::vector<Warning>& warnings)
{
  if (!file_read.readable)
  {
    warnings.push_back(
        producer_warning(WarningCode::kUnreadableFile, producer_name, "unreadable file: " + label));
    return std::nullopt;
  }

  WalkedManifestFile file;
  file.truncated = file_read.truncated;
  file.bytes = std::move(file_read.bytes);
  if (file.truncated)
  {
    if (oversized == OversizedFilePolicy::kSkip)
    {
      warnings.push_back(producer_warning(WarningCode::kFileSizeLimitExceeded, producer_name,
                                          "file exceeds size limit, skipped: " + label));
      return std::nullopt;
    }
    warnings.push_back(
        producer_warning(WarningCode::kFileSizeLimitExceeded, producer_name,
                         "file exceeds size limit, parsing first part only: " + label));
    const std::size_t last_newline = file.bytes.rfind('\n');
    if (last_newline == std::string::npos)
    {
      file.bytes.clear();
    }
    else
    {
      file.bytes.resize(last_newline + 1);
    }
  }
  // A UTF-8 byte-order mark is stripped once, here, for every format: some
  // Windows editors save one, and a line- or key-oriented reader would
  // otherwise see it glued to the first key and silently lose that line.
  if (std::string_view(file.bytes).starts_with(kUtf8ByteOrderMark))
  {
    file.bytes.erase(0, kUtf8ByteOrderMark.size());
  }
  file.label = std::move(label);
  return file;
}

std::optional<WalkedManifestFile> bound_manifest_bytes(
    std::string_view label, std::string_view bytes, std::size_t max_file_bytes,
    std::string_view producer_name, OversizedFilePolicy oversized, std::vector<Warning>& warnings)
{
  return prepare_manifest_file(std::string(label), bound_in_memory_bytes(bytes, max_file_bytes),
                               producer_name, oversized, warnings);
}

std::optional<WalkedManifestFile> read_manifest_file(const std::filesystem::path& root,
                                                     const std::filesystem::path& relative_path,
                                                     std::size_t max_file_bytes,
                                                     std::string_view producer_name,
                                                     OversizedFilePolicy oversized,
                                                     std::vector<Warning>& warnings)
{
  return prepare_manifest_file(relative_path.generic_string(),
                               read_file_bounded(root / relative_path, max_file_bytes),
                               producer_name, oversized, warnings);
}

Warning file_limit_warning(const ManifestWalkOptions& options)
{
  return producer_warning(WarningCode::kFileLimitReached, options.producer_name,
                          "file limit reached; remaining " + options.file_label + " files skipped");
}

Result<std::vector<WalkedManifestFile>> walk_bounded_manifest_files(
    const FileIndex& file_index, const std::filesystem::path& root, std::string_view filename,
    const ManifestWalkOptions& options)
{
  Result<std::vector<WalkedManifestFile>> result;
  const OversizedFilePolicy oversized = options.truncate_at_last_newline
                                            ? OversizedFilePolicy::kTrimToLastNewline
                                            : OversizedFilePolicy::kSkip;
  for_each_manifest_file(
      file_index, root, options, result.warnings,
      [&](const std::filesystem::path& relative_path) -> std::optional<ManifestMatch<int>>
      {
        if (file_name_of(relative_path) != filename)
        {
          return std::nullopt;
        }
        return ManifestMatch<int>{0, oversized};
      },
      [] { return false; },
      [&](int, WalkedManifestFile&& file) { result.value.push_back(std::move(file)); });
  return result;
}

}  // namespace bomwerk::core
