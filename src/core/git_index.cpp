#include "core/git_index.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>

#include "core/byte_cursor.hpp"
#include "core/file_io.hpp"
#include "core/git_dir.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::core
{
namespace
{

// --- Format constants (git's Documentation/gitformat-index.txt) -------------
//
// Every integer in the index is big-endian ("network byte order") whatever
// the host, so the cursor below is always `ByteOrder::Big`.

constexpr std::string_view kIndexSignature = "DIRC";
constexpr std::size_t kVersionOffset = 4;
constexpr std::size_t kEntryCountOffset = 8;
constexpr std::size_t kHeaderSize = 12;

constexpr std::uint64_t kOldestReadableVersion = 2;
constexpr std::uint64_t kExtendedFlagsVersion = 3;
constexpr std::uint64_t kPathCompressedVersion = 4;  ///< also the newest version git writes

/// ctime and mtime (8 bytes each), then dev, ino, mode, uid, gid and size (4
/// bytes each): the stat data that opens every entry.
constexpr std::size_t kStatDataSize = 40;
constexpr std::size_t kModeOffset = 24;
constexpr std::size_t kFlagsSize = 2;
constexpr std::size_t kExtendedFlagsSize = 2;

constexpr std::uint64_t kExtendedFlag = 0x4000;
constexpr std::uint64_t kStageMask = 0x3000;
constexpr unsigned kStageShift = 12;
constexpr std::uint64_t kNameLengthMask = 0x0FFF;
/// skip-worktree and intent-to-add; every other extended bit is reserved and
/// must be zero, which git itself enforces on read.
constexpr std::uint64_t kKnownExtendedFlags = 0x6000;

constexpr std::uint64_t kObjectTypeMask = 0170000;
constexpr std::uint64_t kGitlinkObjectType = 0160000;

constexpr std::size_t kSha1ObjectIdBytes = 20;
constexpr std::size_t kSha256ObjectIdBytes = 32;

/// v2 and v3 entries are NUL-padded to a multiple of this many bytes.
constexpr std::size_t kEntryAlignment = 8;

/// A 4-byte signature plus a 4-byte big-endian payload size.
constexpr std::size_t kExtensionHeaderSize = 8;
constexpr std::size_t kExtensionSignatureSize = 4;
/// The split-index extension: the entries this index holds are only the ones
/// that changed since a separate shared index, so its own list is incomplete.
constexpr std::string_view kSplitIndexSignature = "link";
/// The sparse-index extension: directories outside the sparse-checkout cone are collapsed
/// into one tree entry each, so a gitlink inside one is simply not listed.
constexpr std::string_view kSparseIndexSignature = "sdir";

/// A v4 strip length is a git varint (7 payload bits per byte); ten bytes
/// already carry more than 64 bits, so an eleventh is never legitimate.
constexpr std::size_t kMaxVarintBytes = 10;
constexpr std::uint64_t kVarintPayloadMask = 0x7F;
constexpr std::uint64_t kVarintContinuationBit = 0x80;
constexpr unsigned kVarintGroupBits = 7;
constexpr unsigned kUint64Bits = 64;

constexpr std::string_view kSha256FormatName = "sha256";

bool spells(std::span<const std::byte> bytes, std::string_view text)
{
  if (bytes.size() != text.size())
  {
    return false;
  }
  for (std::size_t byte_index = 0; byte_index < bytes.size(); ++byte_index)
  {
    if (std::to_integer<char>(bytes[byte_index]) != text[byte_index])
    {
      return false;
    }
  }
  return true;
}

bool is_all_zero(std::span<const std::byte> bytes)
{
  return std::all_of(bytes.begin(), bytes.end(),
                     [](std::byte value) { return value == std::byte{0}; });
}

std::string lower_hex(std::span<const std::byte> bytes)
{
  constexpr std::string_view kHexDigits = "0123456789abcdef";
  constexpr unsigned kNibbleBits = 4;
  constexpr std::uint8_t kLowNibbleMask = 0x0F;
  std::string hex;
  hex.reserve(bytes.size() * 2);
  for (const std::byte value : bytes)
  {
    const auto octet = std::to_integer<std::uint8_t>(value);
    hex.push_back(kHexDigits[octet >> kNibbleBits]);
    hex.push_back(kHexDigits[octet & kLowNibbleMask]);
  }
  return hex;
}

struct VarintRead
{
  std::uint64_t value = 0;
  std::size_t byte_count = 0;
};

/// git's offset varint (varint.c `decode_varint`): each continuation adds one
/// before shifting, so every value has exactly one spelling. Nothing when the
/// run is unterminated, too long, or would overflow 64 bits.
std::optional<VarintRead> varint_at(const ByteCursor& cursor, std::size_t offset)
{
  std::optional<std::uint64_t> current = cursor.uint_at(offset, IntegerWidth::OneByte);
  if (!current)
  {
    return std::nullopt;
  }
  VarintRead read;
  read.value = *current & kVarintPayloadMask;
  read.byte_count = 1;
  while ((*current & kVarintContinuationBit) != 0)
  {
    if (read.byte_count == kMaxVarintBytes)
    {
      return std::nullopt;
    }
    ++read.value;
    if (read.value == 0 || (read.value >> (kUint64Bits - kVarintGroupBits)) != 0)
    {
      return std::nullopt;
    }
    current = cursor.uint_at(offset + read.byte_count, IntegerWidth::OneByte);
    if (!current)
    {
      return std::nullopt;
    }
    read.value = (read.value << kVarintGroupBits) + (*current & kVarintPayloadMask);
    ++read.byte_count;
  }
  return read;
}

/// One pass over one index image. A class rather than a free function because
/// the walk carries state from entry to entry: the read offset, and in v4 the
/// previous path every name is compressed against.
class GitIndexReader
{
 public:
  GitIndexReader(std::string_view bytes, GitObjectFormat object_format)
      : object_id_size_(object_format == GitObjectFormat::Sha256 ? kSha256ObjectIdBytes
                                                                 : kSha1ObjectIdBytes),
        image_size_(bytes.size()),
        content_end_(bytes.size() >= object_id_size_ ? bytes.size() - object_id_size_ : 0),
        // Everything but the trailing checksum: an entry or extension that
        // reaches into the checksum is then simply "past the end".
        content_(as_image(bytes.substr(0, content_end_)), ByteOrder::Big)
  {
  }

  /// Appends every stage-0 gitlink to `gitlinks`, sorted by path. Empty on
  /// success; otherwise the reason the whole index is refused, in which case
  /// `gitlinks` must be discarded.
  [[nodiscard]] std::string read_into(std::vector<Gitlink>& gitlinks)
  {
    if (image_size_ < kHeaderSize + object_id_size_)
    {
      return "shorter than an index header and checksum";
    }
    std::string refusal = read_header();
    if (!refusal.empty())
    {
      return refusal;
    }
    for (std::uint64_t entry_number = 0; entry_number < entry_count_; ++entry_number)
    {
      refusal = read_entry(gitlinks);
      if (!refusal.empty())
      {
        return "entry " + std::to_string(entry_number) + ": " + refusal;
      }
    }
    refusal = read_extensions();
    if (!refusal.empty())
    {
      return refusal;
    }
    std::sort(gitlinks.begin(), gitlinks.end(),
              [](const Gitlink& left, const Gitlink& right) { return left.path < right.path; });
    const auto duplicate = std::adjacent_find(gitlinks.begin(), gitlinks.end(),
                                              [](const Gitlink& left, const Gitlink& right)
                                              { return left.path == right.path; });
    if (duplicate != gitlinks.end())
    {
      return "gitlink '" + duplicate->path + "' appears twice at stage 0";
    }
    return {};
  }

 private:
  std::string read_header()
  {
    const std::optional<std::span<const std::byte>> signature =
        content_.bytes_at(0, kIndexSignature.size());
    if (!signature || !spells(*signature, kIndexSignature))
    {
      return "no DIRC signature";
    }
    const std::optional<std::uint64_t> version =
        content_.uint_at(kVersionOffset, IntegerWidth::FourBytes);
    const std::optional<std::uint64_t> entry_count =
        content_.uint_at(kEntryCountOffset, IntegerWidth::FourBytes);
    if (!version || !entry_count)
    {
      return "truncated header";
    }
    if (*version < kOldestReadableVersion || *version > kPathCompressedVersion)
    {
      return "unsupported index version " + std::to_string(*version);
    }
    version_ = *version;
    // Every entry costs at least `minimum_entry_size()` bytes, so a count the
    // file cannot hold is refused before a single entry is walked.
    const std::size_t entry_area = content_end_ - kHeaderSize;
    if (*entry_count > entry_area / minimum_entry_size())
    {
      return "entry count " + std::to_string(*entry_count) + " cannot fit in " +
             std::to_string(image_size_) + " bytes";
    }
    entry_count_ = *entry_count;
    offset_ = kHeaderSize;
    return {};
  }

  [[nodiscard]] std::size_t minimum_entry_size() const
  {
    const std::size_t name_offset = kStatDataSize + object_id_size_ + kFlagsSize;
    constexpr std::size_t kShortestName = 1;
    constexpr std::size_t kNulTerminator = 1;
    constexpr std::size_t kShortestVarint = 1;
    if (version_ == kPathCompressedVersion)
    {
      return name_offset + kShortestVarint + kNulTerminator;
    }
    return padded_entry_size(name_offset, kShortestName);
  }

  /// git's `ondisk_ce_size` for v2/v3: the name plus at least one NUL, rounded
  /// up to the entry alignment.
  static std::size_t padded_entry_size(std::size_t name_offset, std::size_t name_length)
  {
    return (name_offset + name_length + kEntryAlignment) & ~(kEntryAlignment - 1);
  }

  std::string read_entry(std::vector<Gitlink>& gitlinks)
  {
    const std::size_t entry_start = offset_;
    const std::optional<std::uint64_t> mode =
        content_.uint_at(entry_start + kModeOffset, IntegerWidth::FourBytes);
    const std::optional<std::span<const std::byte>> object_id =
        content_.bytes_at(entry_start + kStatDataSize, object_id_size_);
    const std::size_t flags_offset = entry_start + kStatDataSize + object_id_size_;
    const std::optional<std::uint64_t> flags =
        content_.uint_at(flags_offset, IntegerWidth::TwoBytes);
    if (!mode || !object_id || !flags)
    {
      return "runs past the end of the index";
    }

    std::size_t name_offset = flags_offset + kFlagsSize;
    if ((*flags & kExtendedFlag) != 0)
    {
      if (version_ < kExtendedFlagsVersion)
      {
        return "extended flags in a version " + std::to_string(version_) + " index";
      }
      const std::optional<std::uint64_t> extended_flags =
          content_.uint_at(name_offset, IntegerWidth::TwoBytes);
      if (!extended_flags)
      {
        return "runs past the end of the index";
      }
      if ((*extended_flags & ~kKnownExtendedFlags) != 0)
      {
        return "unknown extended flags";
      }
      name_offset += kExtendedFlagsSize;
    }

    std::string path;
    const std::string refusal = version_ == kPathCompressedVersion
                                    ? read_compressed_name(name_offset, path)
                                    : read_padded_name(entry_start, name_offset, path);
    if (!refusal.empty())
    {
      return refusal;
    }

    const std::uint64_t length_field = *flags & kNameLengthMask;
    const bool length_agrees = length_field < kNameLengthMask ? path.size() == length_field
                                                              : path.size() >= kNameLengthMask;
    if (path.empty() || !length_agrees)
    {
      return "name length " + std::to_string(path.size()) + " disagrees with its flags";
    }

    const std::uint64_t stage = (*flags & kStageMask) >> kStageShift;
    const bool is_gitlink = (*mode & kObjectTypeMask) == kGitlinkObjectType;
    // A gitlink at a conflict stage (1 to 3) has no single pin; a null object
    // id is no pin at all. Both are simply not reported.
    if (is_gitlink && stage == 0 && !is_all_zero(*object_id))
    {
      // Checked only for gitlinks: they are the only paths that leave this
      // reader, and the check is not free on an index of a million files.
      if (!is_contained_relative_path(fs::path(path)))
      {
        return "gitlink path '" + path + "' is absolute or escapes the repository";
      }
      gitlinks.push_back({path, lower_hex(*object_id)});
    }
    if (version_ == kPathCompressedVersion)
    {
      previous_path_ = std::move(path);
    }
    return {};
  }

  /// v2/v3: a NUL-terminated name, then NUL padding to the entry alignment.
  std::string read_padded_name(std::size_t entry_start, std::size_t name_offset, std::string& path)
  {
    const std::optional<std::string_view> name =
        content_.c_string_at(name_offset, kMaxGitIndexPathBytes + 1);
    if (!name)
    {
      return "name is unterminated or longer than " + std::to_string(kMaxGitIndexPathBytes) +
             " bytes";
    }
    const std::size_t name_end = name_offset + name->size();
    const std::size_t entry_end =
        entry_start + padded_entry_size(name_offset - entry_start, name->size());
    const std::optional<std::span<const std::byte>> padding =
        content_.bytes_at(name_end, entry_end - name_end);
    if (!padding)
    {
      return "runs past the end of the index";
    }
    if (!is_all_zero(*padding))
    {
      return "padding after the name is not NUL";
    }
    path.assign(*name);
    offset_ = entry_end;
    return {};
  }

  /// v4: a varint naming how many trailing bytes of the previous entry's path
  /// to drop, then the NUL-terminated suffix to append. No padding.
  std::string read_compressed_name(std::size_t name_offset, std::string& path)
  {
    const std::optional<VarintRead> strip_length = varint_at(content_, name_offset);
    if (!strip_length)
    {
      return "malformed path prefix length";
    }
    if (strip_length->value > previous_path_.size())
    {
      return "path prefix strips more than the previous path holds";
    }
    const std::size_t suffix_offset = name_offset + strip_length->byte_count;
    const std::optional<std::string_view> suffix =
        content_.c_string_at(suffix_offset, kMaxGitIndexPathBytes + 1);
    if (!suffix)
    {
      return "name is unterminated or longer than " + std::to_string(kMaxGitIndexPathBytes) +
             " bytes";
    }
    const std::size_t kept_length =
        previous_path_.size() - static_cast<std::size_t>(strip_length->value);
    if (kept_length + suffix->size() > kMaxGitIndexPathBytes)
    {
      return "name is longer than " + std::to_string(kMaxGitIndexPathBytes) + " bytes";
    }
    path.assign(previous_path_, 0, kept_length);
    path.append(*suffix);
    offset_ = suffix_offset + suffix->size() + 1;
    return {};
  }

  /// Extensions sit between the last entry and the checksum. None is needed
  /// to find a gitlink, so each is skipped by its declared size, except a split
  /// index, whose entries are only a delta against another file.
  std::string read_extensions()
  {
    while (offset_ < content_end_)
    {
      if (content_end_ - offset_ < kExtensionHeaderSize)
      {
        return "stray bytes before the checksum";
      }
      const std::optional<std::span<const std::byte>> signature =
          content_.bytes_at(offset_, kExtensionSignatureSize);
      const std::optional<std::uint64_t> payload_size =
          content_.uint_at(offset_ + kExtensionSignatureSize, IntegerWidth::FourBytes);
      if (!signature || !payload_size)
      {
        return "truncated extension header";
      }
      if (spells(*signature, kSplitIndexSignature))
      {
        return "split index (core.splitIndex): its entries live in a shared index file";
      }
      if (spells(*signature, kSparseIndexSignature))
      {
        return "sparse index (index.sparse): collapsed directories hide their gitlinks";
      }
      const std::size_t payload_offset = offset_ + kExtensionHeaderSize;
      if (!content_.has_range(payload_offset, static_cast<std::size_t>(*payload_size)))
      {
        return "extension runs past the checksum";
      }
      offset_ = payload_offset + static_cast<std::size_t>(*payload_size);
    }
    return {};
  }

  std::size_t object_id_size_;
  std::size_t image_size_;
  std::size_t content_end_;
  ByteCursor content_;
  std::uint64_t version_ = 0;
  std::uint64_t entry_count_ = 0;
  std::size_t offset_ = 0;
  std::string previous_path_;
};

void refuse(Result<std::vector<Gitlink>>& result, const std::string& label,
            const std::string& reason)
{
  result.value.clear();
  result.warn(WarningCode::kGitIndexUnreadable,
              label + ": " + reason + "; submodule commits are not read from it");
}

}  // namespace

GitObjectFormat object_format_of(const GitConfig& config)
{
  const std::string* object_format = config.find("extensions", "", "objectformat");
  if (object_format != nullptr && to_lower_ascii(trimmed(*object_format)) == kSha256FormatName)
  {
    return GitObjectFormat::Sha256;
  }
  return GitObjectFormat::Sha1;
}

Result<std::vector<Gitlink>> parse_git_index_gitlinks(std::string_view bytes,
                                                      GitObjectFormat object_format,
                                                      const std::string& label)
{
  Result<std::vector<Gitlink>> result;
  GitIndexReader reader(bytes, object_format);
  const std::string refusal = reader.read_into(result.value);
  if (!refusal.empty())
  {
    refuse(result, label, refusal);
  }
  return result;
}

Result<std::vector<Gitlink>> read_git_index_gitlinks(const fs::path& git_dir,
                                                     GitObjectFormat object_format)
{
  Result<std::vector<Gitlink>> result;
  const fs::path index_path = git_dir / "index";
  const std::string label = index_path.generic_string();

  std::error_code status_error;
  const fs::file_status status = fs::symlink_status(index_path, status_error);
  if (status.type() == fs::file_type::not_found)
  {
    return result;  // no index (an export without one, a fresh init): nothing to read
  }
  if (status_error)
  {
    refuse(result, label, "cannot be examined (" + status_error.message() + ")");
    return result;
  }
  if (fs::is_symlink(status))
  {
    refuse(result, label, "is a symlink, which is never followed");
    return result;
  }
  if (!fs::is_regular_file(status))
  {
    refuse(result, label, "is not a regular file");
    return result;
  }

  std::error_code size_error;
  const std::uintmax_t size = fs::file_size(index_path, size_error);
  if (size_error)
  {
    refuse(result, label, "cannot be sized (" + size_error.message() + ")");
    return result;
  }
  if (size > kMaxGitIndexBytes)
  {
    refuse(result, label,
           "is " + std::to_string(size) + " bytes, over the " + std::to_string(kMaxGitIndexBytes) +
               "-byte cap");
    return result;
  }

  const BoundedFileRead file_read = read_file_bounded(index_path, kMaxGitIndexBytes);
  if (!file_read.readable)
  {
    refuse(result, label, "cannot be read");
    return result;
  }
  if (file_read.truncated)
  {
    refuse(result, label, "grew past the cap while it was read");
    return result;
  }
  return parse_git_index_gitlinks(file_read.bytes, object_format, label);
}

}  // namespace bomwerk::core
