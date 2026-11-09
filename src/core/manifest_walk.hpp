#pragma once
#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/file_index.hpp"
#include "core/file_io.hpp"
#include "core/result.hpp"
#include "core/warning.hpp"

namespace bomwerk::core
{

/// One manifest file found and read within the configured safety budgets.
struct WalkedManifestFile
{
  std::string label;       ///< root-relative path in generic_string() form
  std::string bytes;       ///< readable contents, possibly truncated
  bool truncated = false;  ///< true when bytes is only a readable prefix
};

/// What happens to a manifest larger than its producer's `max_file_bytes`.
enum class OversizedFilePolicy
{
  /// Whole-document formats (JSON, TOML, XML, a YAML document whose later
  /// keys resolve earlier ones): a prefix cannot parse or would mislead, so
  /// the file is skipped with one warning.
  kSkip,
  /// Line-based formats: every complete line before the cap is still a true
  /// statement, so the prefix is kept up to its last newline.
  kTrimToLastNewline,
};

/// A producer's answer to "is this indexed path one of mine?": which of its
/// formats the file is, and how an oversized copy of it is bounded.
template <typename Kind>
struct ManifestMatch
{
  Kind kind{};
  OversizedFilePolicy oversized = OversizedFilePolicy::kSkip;
};

/// Limits and warning identity for one producer's manifest discovery.
struct ManifestWalkOptions
{
  std::size_t max_scanned_files = 0;
  std::size_t max_file_bytes = 0;
  std::string producer_name;  ///< warning prefix and ecosystem, e.g. "cargo"
  std::string file_label;     ///< names the files in the file-limit warning
  /// Used only by `walk_bounded_manifest_files`, which reads a single format;
  /// `for_each_manifest_file` takes the policy per match instead.
  bool truncate_at_last_newline = true;
};

/// The walk options every producer builds the same way: its own per-scan
/// caps (`limits` is the producer's `ParseOptions` or `ParseLimits`, which
/// both carry `max_scanned_files` and `max_file_bytes`), its name, and the
/// label that names its files in the file-limit warning.
template <typename Limits>
[[nodiscard]] ManifestWalkOptions make_walk_options(const Limits& limits,
                                                    std::string_view producer_name,
                                                    std::string_view file_label)
{
  ManifestWalkOptions walk_options;
  walk_options.max_scanned_files = limits.max_scanned_files;
  walk_options.max_file_bytes = limits.max_file_bytes;
  walk_options.producer_name = std::string(producer_name);
  walk_options.file_label = std::string(file_label);
  return walk_options;
}

/// The per-file half of every manifest read: apply `oversized` to a bounded
/// read of the file labelled `label`, then strip a leading UTF-8 byte-order
/// mark so no parser has to. Returns the file ready to parse, or
/// nothing when it was unreadable or skipped; either way the one warning that
/// explains it is appended to `warnings` (prefixed and tagged with
/// `producer_name`). Shared by the disk walk and by `bound_manifest_bytes`, so
/// a file parsed from memory meets exactly the rules a scanned file does.
/// Example: an oversized `"a\nb\npar"` under `kTrimToLastNewline` yields
/// bytes `"a\nb\n"`, `truncated == true` and one kFileSizeLimitExceeded
/// warning.
[[nodiscard]] std::optional<WalkedManifestFile> prepare_manifest_file(
    std::string label, BoundedFileRead file_read, std::string_view producer_name,
    OversizedFilePolicy oversized, std::vector<Warning>& warnings);

/// `prepare_manifest_file` for bytes already in memory, bounded by
/// `max_file_bytes` exactly as `read_file_bounded` bounds a file. Never
/// touches the filesystem: this is what every producer's `parse_bytes` (and so
/// every fuzz harness) reads through.
[[nodiscard]] std::optional<WalkedManifestFile> bound_manifest_bytes(
    std::string_view label, std::string_view bytes, std::size_t max_file_bytes,
    std::string_view producer_name, OversizedFilePolicy oversized, std::vector<Warning>& warnings);

/// Bounded read of `root / relative_path`, then `prepare_manifest_file`. An
/// unopenable file yields nothing and one kUnreadableFile warning.
[[nodiscard]] std::optional<WalkedManifestFile> read_manifest_file(
    const std::filesystem::path& root, const std::filesystem::path& relative_path,
    std::size_t max_file_bytes, std::string_view producer_name, OversizedFilePolicy oversized,
    std::vector<Warning>& warnings);

/// The single warning a producer emits when it reaches `max_scanned_files`.
[[nodiscard]] Warning file_limit_warning(const ManifestWalkOptions& options);

/// The one discovery loop every manifest producer runs over a shared
/// FileIndex, in index (sorted) order:
///
/// 1. `select(relative_path)` returns `std::optional<ManifestMatch<Kind>>`;
///    paths it declines cost nothing further and never count.
/// 2. All selected files share ONE `max_scanned_files` budget, whatever their
///    kind; the first file past it adds `file_limit_warning` and ends the walk.
/// 3. `stop_requested()` is asked before each read, so a producer whose
///    package budget is exhausted stops opening files (vcpkg, conan and
///    GitHub Actions deliberately never ask it to: their later files still
///    report identities and warnings).
/// 4. The file is read and prepared (`read_manifest_file`), then handed to
///    `visit(kind, WalkedManifestFile&&)` and released: files are streamed,
///    never all held at once.
///
/// Warnings go straight into `warnings` (normally the producer's own
/// `result.warnings`), so they interleave with the producer's parse warnings
/// file by file. Never throws; does not change any `complete` flag.
template <typename Select, typename StopRequested, typename Visit>
void for_each_manifest_file(const FileIndex& file_index, const std::filesystem::path& root,
                            const ManifestWalkOptions& options, std::vector<Warning>& warnings,
                            Select&& select, StopRequested&& stop_requested, Visit&& visit)
{
  std::size_t scanned_file_count = 0;
  for (const std::filesystem::path& relative_path : file_index.files)
  {
    const auto match = select(relative_path);
    if (!match.has_value())
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      warnings.push_back(file_limit_warning(options));
      break;
    }
    if (stop_requested())
    {
      break;
    }
    ++scanned_file_count;

    std::optional<WalkedManifestFile> file =
        read_manifest_file(root, relative_path, options.max_file_bytes, options.producer_name,
                           match->oversized, warnings);
    if (file.has_value())
    {
      visit(match->kind, std::move(*file));
    }
  }
}

/// The in-memory twin of `for_each_manifest_file`, for one buffer the caller
/// says is the file `file_name` (a root-relative path such as
/// `app/Cargo.lock`): `select` decides the kind exactly as it would for an
/// indexed path, the bytes are bounded by `max_file_bytes` and prepared under
/// that kind's policy, and `visit` runs once, or not at all when `select`
/// declines the name or the bytes are skipped. `file_name` is also the label
/// in warnings and evidence. This is the body of every producer's
/// `parse_bytes`, which is what the fuzz harnesses call.
template <typename Select, typename Visit>
void for_manifest_bytes(std::string_view file_name, std::string_view bytes,
                        std::size_t max_file_bytes, std::string_view producer_name,
                        std::vector<Warning>& warnings, Select&& select, Visit&& visit)
{
  // Indexed paths are lexically normal, so a name such as `./app/Cargo.lock`
  // must meet the same selection rules as `app/Cargo.lock`.
  const std::filesystem::path relative_path = std::filesystem::path(file_name).lexically_normal();
  const auto match = select(relative_path);
  if (!match.has_value())
  {
    return;
  }
  std::optional<WalkedManifestFile> file =
      bound_manifest_bytes(relative_path.generic_string(), bytes, max_file_bytes, producer_name,
                           match->oversized, warnings);
  if (file.has_value())
  {
    visit(match->kind, std::move(*file));
  }
}

/// Find and bounded-read every file named exactly `filename` in an existing
/// FileIndex, collected into one vector. Unreadable and oversized files
/// produce warnings and are skipped or truncated according to the options;
/// this helper does not change complete. Prefer `for_each_manifest_file`,
/// which streams and can stop early.
[[nodiscard]] Result<std::vector<WalkedManifestFile>> walk_bounded_manifest_files(
    const FileIndex& file_index, const std::filesystem::path& root, std::string_view filename,
    const ManifestWalkOptions& options);

}  // namespace bomwerk::core
