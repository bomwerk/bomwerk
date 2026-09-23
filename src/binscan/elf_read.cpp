#include "binscan/elf_read.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "binscan/bounds.hpp"
#include "binscan/byte_cursor.hpp"
#include "core/file_io.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::binscan
{
namespace
{

// --- Format constants (ELF gABI) --------------------------------------------

/// `e_ident`, the class-independent prefix every ELF file opens with.
constexpr std::size_t kIdentSize = 16;
constexpr std::array<std::uint8_t, 4> kMagic{0x7F, 'E', 'L', 'F'};
constexpr std::size_t kIdentClassOffset = 4;
constexpr std::size_t kIdentDataOffset = 5;
constexpr std::uint64_t kClass32 = 1;
constexpr std::uint64_t kClass64 = 2;
constexpr std::uint64_t kDataLittleEndian = 1;
constexpr std::uint64_t kDataBigEndian = 2;

constexpr std::uint64_t kTypeRelocatable = 1;

constexpr std::uint64_t kSegmentTypeLoad = 1;
constexpr std::uint64_t kSegmentTypeDynamic = 2;

constexpr std::uint64_t kSectionTypeStringTable = 3;
constexpr std::uint64_t kSectionTypeDynamic = 6;
constexpr std::uint64_t kSectionTypeDynamicSymbols = 11;

constexpr std::uint64_t kDynamicTagNull = 0;
constexpr std::uint64_t kDynamicTagNeeded = 1;
constexpr std::uint64_t kDynamicTagStringTable = 5;
constexpr std::uint64_t kDynamicTagStringTableSize = 10;
constexpr std::uint64_t kDynamicTagSoname = 14;

constexpr std::uint64_t kSectionIndexUndefined = 0;
constexpr std::uint64_t kSymbolBindShift = 4;
constexpr std::uint64_t kSymbolBindGlobal = 1;
constexpr std::uint64_t kSymbolBindWeak = 2;

/// Size of the ELF header itself, per class. An image shorter than its own
/// header is malformed, not merely uninformative.
constexpr std::size_t kHeaderSize32 = 52;
constexpr std::size_t kHeaderSize64 = 64;

constexpr std::size_t kDynamicEntrySize32 = 8;
constexpr std::size_t kDynamicEntrySize64 = 16;
constexpr std::size_t kSymbolEntrySize32 = 16;
constexpr std::size_t kSymbolEntrySize64 = 24;

// --- Field locations --------------------------------------------------------

/// Where one field sits inside its record, and how wide it is.
struct FieldLocation
{
  std::size_t offset;
  IntegerWidth width;
};

/// One field's location under each ELF class. Gathering them into tables is
/// what keeps `if (is_64_bit_)` out of the walking code entirely: every read
/// below is `field_of(record, kSomeField)`, and the class difference is data.
struct ClassDependentField
{
  FieldLocation in_class_32;
  FieldLocation in_class_64;
};

// ELF header. `e_type` sits before the first class-dependent field, so it is
// at the same place in both.
constexpr ClassDependentField kHeaderType{{16, IntegerWidth::TwoBytes},
                                          {16, IntegerWidth::TwoBytes}};
constexpr ClassDependentField kHeaderSegmentTableOffset{{28, IntegerWidth::FourBytes},
                                                        {32, IntegerWidth::EightBytes}};
constexpr ClassDependentField kHeaderSectionTableOffset{{32, IntegerWidth::FourBytes},
                                                        {40, IntegerWidth::EightBytes}};
constexpr ClassDependentField kHeaderSegmentEntrySize{{42, IntegerWidth::TwoBytes},
                                                      {54, IntegerWidth::TwoBytes}};
constexpr ClassDependentField kHeaderSegmentCount{{44, IntegerWidth::TwoBytes},
                                                  {56, IntegerWidth::TwoBytes}};
constexpr ClassDependentField kHeaderSectionEntrySize{{46, IntegerWidth::TwoBytes},
                                                      {58, IntegerWidth::TwoBytes}};
constexpr ClassDependentField kHeaderSectionCount{{48, IntegerWidth::TwoBytes},
                                                  {60, IntegerWidth::TwoBytes}};

// Program (segment) header.
constexpr ClassDependentField kSegmentType{{0, IntegerWidth::FourBytes},
                                           {0, IntegerWidth::FourBytes}};
constexpr ClassDependentField kSegmentFileOffset{{4, IntegerWidth::FourBytes},
                                                 {8, IntegerWidth::EightBytes}};
constexpr ClassDependentField kSegmentVirtualAddress{{8, IntegerWidth::FourBytes},
                                                     {16, IntegerWidth::EightBytes}};
constexpr ClassDependentField kSegmentFileSize{{16, IntegerWidth::FourBytes},
                                               {32, IntegerWidth::EightBytes}};

// Section header.
constexpr ClassDependentField kSectionType{{4, IntegerWidth::FourBytes},
                                           {4, IntegerWidth::FourBytes}};
constexpr ClassDependentField kSectionFileOffset{{16, IntegerWidth::FourBytes},
                                                 {24, IntegerWidth::EightBytes}};
constexpr ClassDependentField kSectionSize{{20, IntegerWidth::FourBytes},
                                           {32, IntegerWidth::EightBytes}};
constexpr ClassDependentField kSectionLink{{24, IntegerWidth::FourBytes},
                                           {40, IntegerWidth::FourBytes}};

// Dynamic array entry.
constexpr ClassDependentField kDynamicTag{{0, IntegerWidth::FourBytes},
                                          {0, IntegerWidth::EightBytes}};
constexpr ClassDependentField kDynamicValue{{4, IntegerWidth::FourBytes},
                                            {8, IntegerWidth::EightBytes}};

// Symbol table entry. THIS is the table worth reading twice: `Elf32_Sym` and
// `Elf64_Sym` do not merely widen their fields, they REORDER them --
// 32-bit is (name, value, size, info, other, shndx) while 64-bit is
// (name, info, other, shndx, value, size). Decoding one as the other yields
// plausible-looking symbol names attached to the wrong bindings rather than
// an obvious failure, which is why both classes get their own test.
constexpr ClassDependentField kSymbolName{{0, IntegerWidth::FourBytes},
                                          {0, IntegerWidth::FourBytes}};
constexpr ClassDependentField kSymbolInfo{{12, IntegerWidth::OneByte}, {4, IntegerWidth::OneByte}};
constexpr ClassDependentField kSymbolSectionIndex{{14, IntegerWidth::TwoBytes},
                                                  {6, IntegerWidth::TwoBytes}};

/// What one walk of the dynamic array found, before any of it is resolved
/// against a string table. The offsets are into that table and mean nothing
/// on their own, which is exactly why they are kept raw until it is located.
struct DynamicArray
{
  std::vector<std::uint64_t> needed_offsets;
  std::optional<std::uint64_t> soname_offset;
  std::optional<std::uint64_t> string_table_address;
  std::optional<std::uint64_t> string_table_size;
  bool array_truncated = false;   ///< hit kMaxDynamicEntries walking the array
  bool needed_truncated = false;  ///< hit kMaxNeededEntries collecting DT_NEEDED
};

/// Where the dynamic array lives, and how it was found. `from_section_headers`
/// decides whether a symbol sample is reachable at all -- see `read_elf`'s
/// doc comment.
struct DynamicLocation
{
  ByteCursor region;
  bool from_section_headers = false;
  std::optional<std::uint64_t> string_table_section_index;
};

/// One ELF file's walk. A class rather than free functions because the walk is
/// exactly the stateful, multi-step shape docs/CONTRIBUTING.md reserves classes for: the
/// image, the class width, the located tables and the warning sink are
/// threaded through every step, and passing them as parameters would put the
/// same five arguments on a dozen signatures.
class ElfReader
{
 public:
  ElfReader(ByteCursor image, bool is_64_bit, std::string label, core::Result<ElfImage>& result)
      : image_(image), is_64_bit_(is_64_bit), label_(std::move(label)), result_(result)
  {
  }

  void read(ElfImage& out);

 private:
  [[nodiscard]] static const FieldLocation& location_for(const ClassDependentField& field,
                                                         bool is_64_bit)
  {
    return is_64_bit ? field.in_class_64 : field.in_class_32;
  }

  /// One field of a record, where `record` is a cursor over that record alone.
  [[nodiscard]] std::optional<std::uint64_t> field_of(const ByteCursor& record,
                                                      const ClassDependentField& field) const
  {
    const FieldLocation& where = location_for(field, is_64_bit_);
    return record.uint_at(where.offset, where.width);
  }

  [[nodiscard]] std::size_t dynamic_entry_size() const
  {
    return is_64_bit_ ? kDynamicEntrySize64 : kDynamicEntrySize32;
  }

  [[nodiscard]] std::size_t symbol_entry_size() const
  {
    return is_64_bit_ ? kSymbolEntrySize64 : kSymbolEntrySize32;
  }

  // TODO: every interior structural complaint below (a truncated header, a
  // table/segment/section declared outside the file, an unreadable string/symbol table, a
  // dynamic array exceeding its walk cap, ...) is mapped to the closest existing cause,
  // kBinaryMalformedHeader ("a structure bomwerk could not read"), since this mapping only
  // names a code for the class/data-encoding-byte case explicitly; none of these other
  // structural complaints has its own registered WarningCode.
  void warn(const std::string& message)
  {
    result_.warn(core::WarningCode::kBinaryMalformedHeader, label_ + ": " + message);
  }

  [[nodiscard]] std::optional<ByteCursor> table_entry(std::uint64_t table_offset,
                                                      std::uint64_t entry_size,
                                                      std::size_t index) const;
  [[nodiscard]] std::optional<ByteCursor> section_header(std::size_t index) const;
  [[nodiscard]] std::optional<ByteCursor> segment_header(std::size_t index) const;
  [[nodiscard]] std::optional<ByteCursor> section_contents(const ByteCursor& header) const;

  [[nodiscard]] std::optional<DynamicLocation> locate_dynamic_via_sections();
  [[nodiscard]] std::optional<DynamicLocation> locate_dynamic_via_segments();
  [[nodiscard]] std::optional<std::uint64_t> file_offset_of_address(std::uint64_t address) const;

  [[nodiscard]] DynamicArray walk_dynamic_array(const ByteCursor& region);
  [[nodiscard]] std::optional<ByteCursor> resolve_string_table(const DynamicLocation& location,
                                                               const DynamicArray& dynamic_array);
  [[nodiscard]] std::optional<std::string> string_at(const ByteCursor& string_table,
                                                     std::uint64_t offset) const;
  [[nodiscard]] bool collect_exported_symbols(ElfImage& out);

  void read_table_bounds();

  ByteCursor image_;
  bool is_64_bit_ = false;
  std::string label_;
  core::Result<ElfImage>& result_;

  std::uint64_t section_table_offset_ = 0;
  std::uint64_t section_entry_size_ = 0;
  std::size_t section_count_ = 0;
  std::uint64_t segment_table_offset_ = 0;
  std::uint64_t segment_entry_size_ = 0;
  std::size_t segment_count_ = 0;
  bool section_headers_capped_ = false;
  bool segment_headers_capped_ = false;
  /// The header declared a table (a non-zero offset and a non-zero count).
  /// Distinguishing this from "no table at all" is what lets a file whose
  /// section table lies outside itself be reported as malformed rather than
  /// as a statically linked product.
  bool section_table_declared_ = false;
  bool segment_table_declared_ = false;
};

void ElfReader::read_table_bounds()
{
  const std::optional<std::uint64_t> section_offset = field_of(image_, kHeaderSectionTableOffset);
  const std::optional<std::uint64_t> section_entry = field_of(image_, kHeaderSectionEntrySize);
  const std::optional<std::uint64_t> section_count = field_of(image_, kHeaderSectionCount);
  if (section_offset && section_entry && section_count)
  {
    section_table_offset_ = *section_offset;
    section_entry_size_ = *section_entry;
    section_count_ = static_cast<std::size_t>(
        *section_count > kMaxSectionHeaders ? kMaxSectionHeaders : *section_count);
    section_headers_capped_ = *section_count > kMaxSectionHeaders;
    section_table_declared_ = section_table_offset_ != 0 && section_count_ > 0;
  }

  const std::optional<std::uint64_t> segment_offset = field_of(image_, kHeaderSegmentTableOffset);
  const std::optional<std::uint64_t> segment_entry = field_of(image_, kHeaderSegmentEntrySize);
  const std::optional<std::uint64_t> segment_count = field_of(image_, kHeaderSegmentCount);
  if (segment_offset && segment_entry && segment_count)
  {
    segment_table_offset_ = *segment_offset;
    segment_entry_size_ = *segment_entry;
    segment_count_ = static_cast<std::size_t>(
        *segment_count > kMaxProgramHeaders ? kMaxProgramHeaders : *segment_count);
    segment_headers_capped_ = *segment_count > kMaxProgramHeaders;
    segment_table_declared_ = segment_table_offset_ != 0 && segment_count_ > 0;
  }
}

std::optional<ByteCursor> ElfReader::table_entry(std::uint64_t table_offset,
                                                 std::uint64_t entry_size, std::size_t index) const
{
  if (entry_size == 0 || table_offset == 0)
  {
    return std::nullopt;
  }
  // Computed in 64-bit and bounds-checked by `subrange`, so a header claiming
  // a table far past the end simply produces nothing.
  const std::uint64_t entry_offset = table_offset + entry_size * static_cast<std::uint64_t>(index);
  if (entry_offset < table_offset)
  {
    return std::nullopt;  // wrapped: hostile offset/entry-size pair
  }
  if (entry_offset > static_cast<std::uint64_t>(image_.size()))
  {
    return std::nullopt;
  }
  return image_.subrange(static_cast<std::size_t>(entry_offset),
                         static_cast<std::size_t>(entry_size));
}

std::optional<ByteCursor> ElfReader::section_header(std::size_t index) const
{
  return table_entry(section_table_offset_, section_entry_size_, index);
}

std::optional<ByteCursor> ElfReader::segment_header(std::size_t index) const
{
  return table_entry(segment_table_offset_, segment_entry_size_, index);
}

std::optional<ByteCursor> ElfReader::section_contents(const ByteCursor& header) const
{
  const std::optional<std::uint64_t> offset = field_of(header, kSectionFileOffset);
  const std::optional<std::uint64_t> size = field_of(header, kSectionSize);
  if (!offset || !size)
  {
    return std::nullopt;
  }
  if (*offset > static_cast<std::uint64_t>(image_.size()) ||
      *size > static_cast<std::uint64_t>(image_.size()))
  {
    return std::nullopt;
  }
  return image_.subrange(static_cast<std::size_t>(*offset), static_cast<std::size_t>(*size));
}

std::optional<DynamicLocation> ElfReader::locate_dynamic_via_sections()
{
  for (std::size_t index = 0; index < section_count_; ++index)
  {
    const std::optional<ByteCursor> header = section_header(index);
    if (!header)
    {
      continue;
    }
    const std::optional<std::uint64_t> type = field_of(*header, kSectionType);
    if (!type || *type != kSectionTypeDynamic)
    {
      continue;
    }
    const std::optional<ByteCursor> contents = section_contents(*header);
    if (!contents)
    {
      warn("dynamic section lies outside the file");
      return std::nullopt;
    }
    DynamicLocation location{*contents, true, std::nullopt};
    const std::optional<std::uint64_t> link = field_of(*header, kSectionLink);
    if (link && *link < static_cast<std::uint64_t>(section_count_))
    {
      location.string_table_section_index = *link;
    }
    return location;
  }
  return std::nullopt;
}

std::optional<DynamicLocation> ElfReader::locate_dynamic_via_segments()
{
  for (std::size_t index = 0; index < segment_count_; ++index)
  {
    const std::optional<ByteCursor> header = segment_header(index);
    if (!header)
    {
      continue;
    }
    const std::optional<std::uint64_t> type = field_of(*header, kSegmentType);
    if (!type || *type != kSegmentTypeDynamic)
    {
      continue;
    }
    const std::optional<std::uint64_t> offset = field_of(*header, kSegmentFileOffset);
    const std::optional<std::uint64_t> size = field_of(*header, kSegmentFileSize);
    if (!offset || !size || *offset > static_cast<std::uint64_t>(image_.size()) ||
        *size > static_cast<std::uint64_t>(image_.size()))
    {
      warn("PT_DYNAMIC segment lies outside the file");
      return std::nullopt;
    }
    const std::optional<ByteCursor> region =
        image_.subrange(static_cast<std::size_t>(*offset), static_cast<std::size_t>(*size));
    if (!region)
    {
      warn("PT_DYNAMIC segment lies outside the file");
      return std::nullopt;
    }
    return DynamicLocation{*region, false, std::nullopt};
  }
  return std::nullopt;
}

std::optional<std::uint64_t> ElfReader::file_offset_of_address(std::uint64_t address) const
{
  // A dynamic-array pointer such as DT_STRTAB is a VIRTUAL address, which only
  // means something once mapped: the PT_LOAD segment covering it says where
  // those bytes live in the file. An address covered by no PT_LOAD is not a
  // location bomwerk may guess at.
  for (std::size_t index = 0; index < segment_count_; ++index)
  {
    const std::optional<ByteCursor> header = segment_header(index);
    if (!header)
    {
      continue;
    }
    const std::optional<std::uint64_t> type = field_of(*header, kSegmentType);
    const std::optional<std::uint64_t> virtual_address = field_of(*header, kSegmentVirtualAddress);
    const std::optional<std::uint64_t> file_offset = field_of(*header, kSegmentFileOffset);
    const std::optional<std::uint64_t> file_size = field_of(*header, kSegmentFileSize);
    if (!type || *type != kSegmentTypeLoad || !virtual_address || !file_offset || !file_size)
    {
      continue;
    }
    if (address < *virtual_address)
    {
      continue;
    }
    const std::uint64_t distance = address - *virtual_address;
    if (distance >= *file_size)
    {
      continue;
    }
    const std::uint64_t resolved = *file_offset + distance;
    if (resolved < *file_offset || resolved >= static_cast<std::uint64_t>(image_.size()))
    {
      // Wrapped, or a p_offset that lies outside the file the segment claims
      // to be mapped from. Returning it would make the caller's
      // `image_.size() - offset` underflow, so this segment simply does not
      // answer for the address.
      continue;
    }
    return resolved;
  }
  return std::nullopt;
}

DynamicArray ElfReader::walk_dynamic_array(const ByteCursor& region)
{
  DynamicArray found;
  const std::size_t entry_size = dynamic_entry_size();
  for (std::size_t index = 0; index < kMaxDynamicEntries; ++index)
  {
    const std::optional<ByteCursor> entry = region.subrange(index * entry_size, entry_size);
    if (!entry)
    {
      return found;  // ran off the end without DT_NULL; what was read still counts
    }
    const std::optional<std::uint64_t> tag = field_of(*entry, kDynamicTag);
    const std::optional<std::uint64_t> value = field_of(*entry, kDynamicValue);
    if (!tag || !value)
    {
      return found;
    }
    if (*tag == kDynamicTagNull)
    {
      return found;
    }
    if (*tag == kDynamicTagNeeded)
    {
      if (found.needed_offsets.size() >= kMaxNeededEntries)
      {
        found.needed_truncated = true;
      }
      else
      {
        found.needed_offsets.push_back(*value);
      }
    }
    else if (*tag == kDynamicTagSoname)
    {
      found.soname_offset = *value;
    }
    else if (*tag == kDynamicTagStringTable)
    {
      found.string_table_address = *value;
    }
    else if (*tag == kDynamicTagStringTableSize)
    {
      found.string_table_size = *value;
    }
  }
  found.array_truncated = true;
  return found;
}

std::optional<ByteCursor> ElfReader::resolve_string_table(const DynamicLocation& location,
                                                          const DynamicArray& dynamic_array)
{
  // Preferred: the dynamic section's own `sh_link`, which names the string
  // table section directly and so needs no address arithmetic at all.
  if (location.string_table_section_index)
  {
    const std::optional<ByteCursor> header =
        section_header(static_cast<std::size_t>(*location.string_table_section_index));
    // The link must actually NAME a string table. Following it blindly is how
    // a hostile `sh_link` pointing at `.text` turns executable bytes into
    // library names: `c_string_at` guarantees termination, not that the bytes
    // were ever a string table, so the result would be plausible garbage in an
    // SBOM rather than the refusal rule 1 asks for.
    if (header)
    {
      const std::optional<std::uint64_t> type = field_of(*header, kSectionType);
      if (type && *type == kSectionTypeStringTable)
      {
        const std::optional<ByteCursor> contents = section_contents(*header);
        if (contents)
        {
          return contents;
        }
      }
    }
  }

  // Fallback: DT_STRTAB, mapped back to a file offset through PT_LOAD.
  if (!dynamic_array.string_table_address)
  {
    warn("dynamic section declares no string table (DT_STRTAB); no library names recoverable");
    return std::nullopt;
  }
  const std::optional<std::uint64_t> offset =
      file_offset_of_address(*dynamic_array.string_table_address);
  if (!offset)
  {
    warn("DT_STRTAB address lies in no PT_LOAD segment; no library names recoverable");
    return std::nullopt;
  }
  // DT_STRSZ is advisory here: when it is absent or overlong, the rest of the
  // file bounds the table instead, and `c_string_at` still refuses anything
  // unterminated.
  // `file_offset_of_address` guarantees an offset inside the image, so this
  // subtraction cannot underflow.
  const std::uint64_t available = static_cast<std::uint64_t>(image_.size()) - *offset;
  const std::uint64_t size =
      dynamic_array.string_table_size && *dynamic_array.string_table_size <= available
          ? *dynamic_array.string_table_size
          : available;
  const std::optional<ByteCursor> table =
      image_.subrange(static_cast<std::size_t>(*offset), static_cast<std::size_t>(size));
  if (!table)
  {
    warn("string table does not fit the file; no library names recoverable");
  }
  return table;
}

std::optional<std::string> ElfReader::string_at(const ByteCursor& string_table,
                                                std::uint64_t offset) const
{
  if (offset > static_cast<std::uint64_t>(string_table.size()))
  {
    return std::nullopt;
  }
  const std::optional<std::string_view> text =
      string_table.c_string_at(static_cast<std::size_t>(offset), kMaxStringLength);
  if (!text || text->empty())
  {
    return std::nullopt;
  }
  return std::string(*text);
}

bool ElfReader::collect_exported_symbols(ElfImage& out)
{
  for (std::size_t index = 0; index < section_count_; ++index)
  {
    const std::optional<ByteCursor> header = section_header(index);
    if (!header)
    {
      continue;
    }
    const std::optional<std::uint64_t> type = field_of(*header, kSectionType);
    if (!type || *type != kSectionTypeDynamicSymbols)
    {
      continue;
    }
    const std::optional<ByteCursor> table = section_contents(*header);
    const std::optional<std::uint64_t> link = field_of(*header, kSectionLink);
    if (!table || !link || *link >= static_cast<std::uint64_t>(section_count_))
    {
      warn("dynamic symbol table is unreadable; symbol sample skipped");
      return false;
    }
    const std::optional<ByteCursor> names_header = section_header(static_cast<std::size_t>(*link));
    if (!names_header)
    {
      warn("dynamic symbol table is unreadable; symbol sample skipped");
      return false;
    }
    const std::optional<ByteCursor> names = section_contents(*names_header);
    if (!names)
    {
      warn("dynamic symbol table is unreadable; symbol sample skipped");
      return false;
    }

    const std::size_t entry_size = symbol_entry_size();
    const std::size_t declared_entries = table->size() / entry_size;
    const std::size_t entries =
        declared_entries > kMaxSymbolTableEntries ? kMaxSymbolTableEntries : declared_entries;
    for (std::size_t symbol_index = 0; symbol_index < entries; ++symbol_index)
    {
      const std::optional<ByteCursor> entry =
          table->subrange(symbol_index * entry_size, entry_size);
      if (!entry)
      {
        break;
      }
      const std::optional<std::uint64_t> section_index = field_of(*entry, kSymbolSectionIndex);
      const std::optional<std::uint64_t> info = field_of(*entry, kSymbolInfo);
      const std::optional<std::uint64_t> name_offset = field_of(*entry, kSymbolName);
      if (!section_index || !info || !name_offset)
      {
        continue;
      }
      // What a fingerprint matcher keys on is what a library PROVIDES, so an
      // undefined symbol (an import) is deliberately not part of the sample.
      if (*section_index == kSectionIndexUndefined)
      {
        continue;
      }
      const std::uint64_t binding = *info >> kSymbolBindShift;
      if (binding != kSymbolBindGlobal && binding != kSymbolBindWeak)
      {
        continue;
      }
      const std::optional<std::string> name = string_at(*names, *name_offset);
      if (name)
      {
        out.exported_symbols.push_back(*name);
      }
    }
    out.symbols_truncated = normalize_and_cap(out.exported_symbols, kMaxSymbolSample) ||
                            declared_entries > kMaxSymbolTableEntries;
    return true;
  }
  return false;
}

void ElfReader::read(ElfImage& out)
{
  read_table_bounds();
  if (section_headers_capped_ || segment_headers_capped_)
  {
    warn("declares more headers than bomwerk follows; the rest were skipped");
  }

  if (image_.size() < (is_64_bit_ ? kHeaderSize64 : kHeaderSize32))
  {
    warn("ELF header is truncated; nothing about this image could be read");
    out.shape = ElfShape::Malformed;
    return;
  }
  const std::optional<std::uint64_t> type = field_of(image_, kHeaderType);
  if (!type)
  {
    warn("ELF header is truncated");
    out.shape = ElfShape::Malformed;
    return;
  }
  // A table the header DECLARES but that lies outside the file is a
  // contradiction, not an absence. Reporting the absence would let a corrupt
  // shared object come back as `StaticExecutable`, which asserts the product
  // has no dynamic dependencies -- a claim about the product, from a file
  // bomwerk never managed to read.
  const bool section_table_unreachable = section_table_declared_ && !section_header(0);
  const bool segment_table_unreachable = segment_table_declared_ && !segment_header(0);
  if (section_table_unreachable || segment_table_unreachable)
  {
    warn("declares a header table that lies outside the file; nothing could be read from it");
    out.shape = ElfShape::Malformed;
    return;
  }
  if (*type == kTypeRelocatable)
  {
    // A `.o` carries no dynamic section by construction, so this is not a
    // degraded read -- it is the wrong kind of file to ask. The caller counts
    // it and says so; there is nothing here to warn about per file.
    out.shape = ElfShape::Relocatable;
    return;
  }

  std::optional<DynamicLocation> location = locate_dynamic_via_sections();
  if (!location)
  {
    location = locate_dynamic_via_segments();
  }
  if (!location)
  {
    out.shape = ElfShape::StaticExecutable;
    return;
  }
  out.shape = ElfShape::Dynamic;

  const DynamicArray dynamic_array = walk_dynamic_array(location->region);
  // Two different caps, so two different sentences: pointing an investigation
  // at kMaxDynamicEntries when the limit actually reached was
  // kMaxNeededEntries sends the reader to the wrong constant.
  if (dynamic_array.array_truncated)
  {
    warn("dynamic section declares more entries than bomwerk walks (" +
         std::to_string(kMaxDynamicEntries) + "); the rest were skipped");
    out.needed_truncated = true;
  }
  if (dynamic_array.needed_truncated)
  {
    warn("declares more dynamic dependencies than bomwerk records (" +
         std::to_string(kMaxNeededEntries) + "); the rest were skipped");
    out.needed_truncated = true;
  }

  const std::optional<ByteCursor> string_table = resolve_string_table(*location, dynamic_array);
  // Without a string table every DT_NEEDED offset is unresolvable, so an empty
  // `needed` list means "unread", not "declares nothing". The caller has to be
  // able to tell those apart (binscan/binary_map.hpp's counters do).
  out.names_unavailable = !string_table.has_value();
  if (string_table)
  {
    for (const std::uint64_t offset : dynamic_array.needed_offsets)
    {
      const std::optional<std::string> name = string_at(*string_table, offset);
      if (name)
      {
        out.needed.push_back(*name);
      }
    }
    if (dynamic_array.soname_offset)
    {
      const std::optional<std::string> soname =
          string_at(*string_table, *dynamic_array.soname_offset);
      if (soname)
      {
        out.soname = *soname;
      }
    }
  }
  out.needed_truncated = normalize_and_cap(out.needed, kMaxNeededEntries) || out.needed_truncated;

  if (!location->from_section_headers)
  {
    out.symbols_unavailable = true;
    warn(
        "section headers are stripped; dynamic dependencies were recovered from PT_DYNAMIC but "
        "the exported-symbol sample was not");
    return;
  }
  // A dynamic image with no `.dynsym` at all is unusual but not actionable, so
  // it records "no sample taken" without a warning of its own -- the warning
  // channel is reserved for what an operator can act on.
  out.symbols_unavailable = !collect_exported_symbols(out);
}

}  // namespace

core::Result<ElfImage> read_elf(const fs::path& path)
{
  core::Result<ElfImage> outcome;

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

  const ByteCursor identification(as_image(file.bytes), ByteOrder::Little);
  if (identification.size() < kIdentSize)
  {
    return outcome;  // too small to be an ELF; not a warning, see read_elf's doc
  }
  for (std::size_t index = 0; index < kMagic.size(); ++index)
  {
    const std::optional<std::uint64_t> byte = identification.uint_at(index, IntegerWidth::OneByte);
    if (!byte || *byte != kMagic[index])
    {
      return outcome;  // not an ELF at all; the caller aggregates this
    }
  }

  const std::optional<std::uint64_t> file_class =
      identification.uint_at(kIdentClassOffset, IntegerWidth::OneByte);
  const std::optional<std::uint64_t> file_data =
      identification.uint_at(kIdentDataOffset, IntegerWidth::OneByte);
  if (!file_class || (*file_class != kClass32 && *file_class != kClass64))
  {
    outcome.warn(core::WarningCode::kBinaryMalformedHeader,
                 path.string() + ": ELF magic with an unknown class byte; skipped");
    outcome.value.shape = ElfShape::Malformed;
    return outcome;
  }
  if (!file_data || (*file_data != kDataLittleEndian && *file_data != kDataBigEndian))
  {
    outcome.warn(core::WarningCode::kBinaryMalformedHeader,
                 path.string() + ": ELF magic with an unknown data-encoding byte; skipped");
    outcome.value.shape = ElfShape::Malformed;
    return outcome;
  }

  const ByteOrder byte_order = *file_data == kDataBigEndian ? ByteOrder::Big : ByteOrder::Little;
  ElfReader reader(identification.with_byte_order(byte_order), *file_class == kClass64,
                   path.string(), outcome);
  reader.read(outcome.value);
  return outcome;
}

}  // namespace bomwerk::binscan
