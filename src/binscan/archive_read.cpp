#include "binscan/archive_read.hpp"

#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>

#include "binscan/byte_cursor.hpp"
#include "core/file_io.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::binscan
{
namespace
{

// --- Format constants (`ar`, both dialects) ---------------------------------

constexpr std::string_view kArchiveMagic = "!<arch>\n";

/// Every member is introduced by a fixed 60-byte ASCII header. Only the name
/// and the size are load-bearing here; mtime/uid/gid/mode are metadata this
/// pass has no use for, and reading them would only add fields to get wrong.
constexpr std::size_t kMemberHeaderSize = 60;
constexpr std::size_t kMemberNameOffset = 0;
constexpr std::size_t kMemberNameLength = 16;
constexpr std::size_t kMemberSizeOffset = 48;
constexpr std::size_t kMemberSizeLength = 10;
constexpr std::size_t kMemberTrailerOffset = 58;
constexpr std::string_view kMemberTrailer = "`\n";

/// Member data is padded to an even offset; the pad byte is not counted in the
/// declared size, so a walk that forgets it lands one byte into the next
/// header and reads the whole rest of the archive as garbage.
constexpr std::size_t kMemberAlignment = 2;

constexpr std::string_view kGnuSymbolIndexName = "/";
constexpr std::string_view kGnuSymbolIndex64Name = "/SYM64/";
constexpr std::string_view kGnuLongNameTableName = "//";
constexpr std::string_view kBsdSymbolIndexName = "__.SYMDEF";
constexpr std::string_view kBsdLongNamePrefix = "#1/";

/// The GNU index counts and offsets are big-endian by specification, whatever
/// the host that wrote them was.
constexpr IntegerWidth kGnuIndexCountWidth = IntegerWidth::FourBytes;
constexpr IntegerWidth kGnuIndexCountWidth64 = IntegerWidth::EightBytes;

/// Parse an unsigned decimal ASCII field, as `ar` spells its sizes.
///
/// Hand-written rather than `std::stoull`, which throws on garbage: and every
/// byte here came from an untrusted file (rule 1). Trailing spaces are the
/// format's own padding; anything else is a malformed field, and an empty
/// field is nothing rather than zero.
[[nodiscard]] std::optional<std::uint64_t> parse_decimal_field(std::string_view field)
{
  const std::string_view digits = core::trimmed_view(field);
  if (digits.empty())
  {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  for (const char character : digits)
  {
    if (character < '0' || character > '9')
    {
      return std::nullopt;
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    constexpr std::uint64_t kDecimalBase = 10;
    if (value > (UINT64_MAX - digit) / kDecimalBase)
    {
      return std::nullopt;  // a size field no archive could honestly carry
    }
    value = value * kDecimalBase + digit;
  }
  return value;
}

/// The raw 16-byte name field, with the format's space padding removed.
[[nodiscard]] std::string_view raw_member_name(std::string_view header)
{
  return core::trimmed_view(header.substr(kMemberNameOffset, kMemberNameLength));
}

/// Whether `name` is one of the archive's own bookkeeping members rather than
/// an object the linker consumed. These are excluded from `member_names`: an
/// SBOM reader asking "what is inside this archive" means the objects.
[[nodiscard]] bool is_bookkeeping_member(std::string_view name)
{
  return name == kGnuSymbolIndexName || name == kGnuSymbolIndex64Name ||
         name == kGnuLongNameTableName || name.starts_with(kBsdSymbolIndexName);
}

/// One member's name resolved against the long-name table, or nothing when the
/// member is bookkeeping rather than an object.
///
/// Four spellings, and getting any of them wrong silently renames a component's
/// contents rather than failing: GNU short (`name/`), GNU long (`/<offset>`
/// into the `//` table), BSD long (`#1/<length>`, the name occupying the first
/// `<length>` bytes of the member's own data), BSD short (bare, space-padded).
[[nodiscard]] std::optional<std::string> resolve_member_name(std::string_view raw_name,
                                                             std::string_view long_name_table,
                                                             std::string_view member_data)
{
  if (raw_name.empty() || is_bookkeeping_member(raw_name))
  {
    return std::nullopt;
  }

  if (raw_name.starts_with(kBsdLongNamePrefix))
  {
    const std::optional<std::uint64_t> length =
        parse_decimal_field(raw_name.substr(kBsdLongNamePrefix.size()));
    if (!length || *length > member_data.size() || *length > kMaxStringLength)
    {
      return std::nullopt;
    }
    std::string_view name = member_data.substr(0, static_cast<std::size_t>(*length));
    const std::size_t terminator = name.find('\0');
    if (terminator != std::string_view::npos)
    {
      name = name.substr(0, terminator);
    }
    return name.empty() ? std::nullopt : std::optional<std::string>(std::string(name));
  }

  if (raw_name.front() == '/')
  {
    const std::optional<std::uint64_t> offset = parse_decimal_field(raw_name.substr(1));
    if (!offset || *offset >= long_name_table.size())
    {
      return std::nullopt;
    }
    std::string_view name = long_name_table.substr(static_cast<std::size_t>(*offset));
    const std::size_t terminator = name.find_first_of("/\n");
    if (terminator != std::string_view::npos)
    {
      name = name.substr(0, terminator);
    }
    if (name.size() > kMaxStringLength)
    {
      name = name.substr(0, kMaxStringLength);
    }
    return name.empty() ? std::nullopt : std::optional<std::string>(std::string(name));
  }

  // GNU short names end in the separator that lets a trailing space be part of
  // a name; BSD short names simply do not have it.
  if (raw_name.back() == '/')
  {
    raw_name.remove_suffix(1);
  }
  return raw_name.empty() ? std::nullopt : std::optional<std::string>(std::string(raw_name));
}

/// One walk of an archive. A class for the same reason `ElfReader` is one: the
/// image, the long-name table discovered mid-walk and the warning sink are
/// carried across every step.
class ArchiveReader
{
 public:
  ArchiveReader(std::string_view bytes, std::string label, core::Result<ArchiveContents>& result)
      : bytes_(bytes), label_(std::move(label)), result_(result)
  {
  }

  void read(ArchiveContents& out);

 private:
  // TODO: every interior structural complaint below (a cut-off member header, a
  // bad trailer, an unreadable/overrunning size field, or too many members) is mapped to the
  // closest existing cause, kBinaryMalformedHeader ("a structure bomwerk could not read"), since
  // this mapping only names a code for the whole-file "cannot be read"/"too large" cases; none
  // of these per-member complaints has its own registered WarningCode.
  void warn(const std::string& message)
  {
    result_.warn(core::WarningCode::kBinaryMalformedHeader, label_ + ": " + message);
  }

  void read_gnu_symbol_index(std::string_view index_data, bool is_64_bit, ArchiveContents& out);

  std::string_view bytes_;
  std::string label_;
  core::Result<ArchiveContents>& result_;
  std::string_view long_name_table_;
  /// Whether a symbol index member was seen at all. An archive whose index
  /// parsed fine and simply held no symbols is NOT "unavailable" -- a reader
  /// must be able to tell that apart from a BSD `__.SYMDEF` bomwerk refused to
  /// guess the byte order of.
  bool saw_symbol_index_ = false;
};

void ArchiveReader::read_gnu_symbol_index(std::string_view index_data, bool is_64_bit,
                                          ArchiveContents& out)
{
  const ByteCursor index(as_image(index_data),
                         ByteOrder::Big);  // big-endian by specification, independent of the host
  const IntegerWidth width = is_64_bit ? kGnuIndexCountWidth64 : kGnuIndexCountWidth;
  const std::size_t width_bytes = static_cast<std::size_t>(width);

  const std::optional<std::uint64_t> declared_count = index.uint_at(0, width);
  if (!declared_count)
  {
    out.symbols_unavailable = true;
    return;
  }
  const std::uint64_t capped_count =
      *declared_count > kMaxSymbolTableEntries ? kMaxSymbolTableEntries : *declared_count;

  // Names begin after the count and its table of member offsets; each is
  // NUL-terminated and they run in index order.
  std::size_t name_offset = width_bytes + width_bytes * static_cast<std::size_t>(capped_count);
  if (*declared_count != capped_count)
  {
    out.symbols_truncated = true;
  }
  for (std::uint64_t symbol_index = 0; symbol_index < capped_count; ++symbol_index)
  {
    const std::optional<std::string_view> name = index.c_string_at(name_offset, kMaxStringLength);
    if (!name)
    {
      break;
    }
    if (!name->empty())
    {
      out.indexed_symbols.emplace_back(*name);
    }
    name_offset += name->size() + 1;
  }
  out.symbols_truncated =
      normalize_and_cap(out.indexed_symbols, kMaxSymbolSample) || out.symbols_truncated;
}

void ArchiveReader::read(ArchiveContents& out)
{
  std::size_t offset = kArchiveMagic.size();
  std::size_t member_count = 0;

  while (offset < bytes_.size())
  {
    if (bytes_.size() - offset < kMemberHeaderSize)
    {
      warn("member header at byte " + std::to_string(offset) +
           " is cut off by the end of the file; the rest was skipped");
      out.members_truncated = true;
      break;
    }
    const std::string_view header = bytes_.substr(offset, kMemberHeaderSize);
    if (header.substr(kMemberTrailerOffset, kMemberTrailer.size()) != kMemberTrailer)
    {
      warn("member header at byte " + std::to_string(offset) +
           " is malformed; the rest was skipped");
      out.members_truncated = true;
      break;
    }

    const std::optional<std::uint64_t> declared_size =
        parse_decimal_field(header.substr(kMemberSizeOffset, kMemberSizeLength));
    if (!declared_size)
    {
      warn("member at byte " + std::to_string(offset) +
           " declares an unreadable size; the rest was skipped");
      out.members_truncated = true;
      break;
    }

    const std::size_t data_offset = offset + kMemberHeaderSize;
    if (*declared_size > bytes_.size() - data_offset)
    {
      warn("member at byte " + std::to_string(offset) +
           " declares a size running past the end of the file; the rest was skipped");
      out.members_truncated = true;
      break;
    }
    const std::string_view data =
        bytes_.substr(data_offset, static_cast<std::size_t>(*declared_size));

    const std::string_view raw_name = raw_member_name(header);
    if (raw_name == kGnuLongNameTableName)
    {
      long_name_table_ = data;
    }
    else if (raw_name == kGnuSymbolIndexName || raw_name == kGnuSymbolIndex64Name)
    {
      saw_symbol_index_ = true;
      read_gnu_symbol_index(data, raw_name == kGnuSymbolIndex64Name, out);
    }
    else if (raw_name.starts_with(kBsdSymbolIndexName))
    {
      // See `read_archive`'s doc comment: `__.SYMDEF` is native-endian and the
      // archive does not record which host wrote it, so the names are kept and
      // the symbols are declared unavailable rather than guessed at.
      out.symbols_unavailable = true;
    }
    else
    {
      if (member_count >= kMaxArchiveMembers)
      {
        warn("holds more members than bomwerk lists (" + std::to_string(kMaxArchiveMembers) +
             "); the rest were skipped");
        out.members_truncated = true;
        break;
      }
      const std::optional<std::string> name = resolve_member_name(raw_name, long_name_table_, data);
      if (name)
      {
        out.member_names.push_back(*name);
        ++member_count;
      }
    }

    const std::size_t padded_size =
        static_cast<std::size_t>(*declared_size) + (*declared_size % kMemberAlignment);
    if (padded_size > bytes_.size() - data_offset)
    {
      break;  // the pad byte itself is off the end: nothing further to read
    }
    offset = data_offset + padded_size;
  }

  normalize_and_cap(out.member_names, kMaxArchiveMembers);
  if (!saw_symbol_index_)
  {
    out.symbols_unavailable = true;
  }
}

}  // namespace

core::Result<ArchiveContents> read_archive(const fs::path& path)
{
  core::Result<ArchiveContents> outcome;

  const core::BoundedFileRead file = core::read_file_bounded(path, kMaxBinaryBytes);
  if (!file.readable)
  {
    outcome.warn(core::WarningCode::kBinaryUnreadable, path.string() + ": cannot be read; skipped");
    return outcome;
  }
  if (file.truncated)
  {
    outcome.warn(core::WarningCode::kBinaryTooLarge,
                 path.string() + ": larger than " + std::to_string(kMaxBinaryBytes) +
                     " bytes; refused rather than parsed from a partial image");
    return outcome;
  }
  if (file.bytes.size() < kArchiveMagic.size() ||
      std::string_view(file.bytes).substr(0, kArchiveMagic.size()) != kArchiveMagic)
  {
    return outcome;  // not an archive; the caller decides what that means
  }

  outcome.value.is_archive = true;
  ArchiveReader reader(file.bytes, path.string(), outcome);
  reader.read(outcome.value);
  return outcome;
}

}  // namespace bomwerk::binscan
