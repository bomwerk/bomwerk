#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "support/binary_writer.hpp"

namespace bomwerk::test
{

/// What kind of ELF file `build_elf` should produce.
///
/// Every knob here exists because some case in test_elf_read needs exactly one
/// thing about a real binary to be different: the class, the byte order, the
/// absence of a dynamic section (a statically linked product), the absence of
/// section headers (a stripped `.so`, which forces the PT_DYNAMIC fallback).
struct ElfBuildOptions
{
  bool is_64_bit = true;
  bool big_endian = false;
  std::uint16_t file_type = 3;  ///< ET_DYN; 1 = ET_REL, 2 = ET_EXEC
  std::vector<std::string> needed;
  std::string soname;
  std::vector<std::string> exported_symbols;
  std::vector<std::string> undefined_symbols;  ///< imports; must never reach the sample
  bool include_section_headers = true;
  bool include_program_headers = false;
  bool include_dynamic = true;
};

/// Assemble a complete, self-consistent ELF image in memory.
///
/// Virtual addresses are laid out as an identity map (one PT_LOAD covering the
/// whole file at vaddr 0), so `DT_STRTAB`'s address equals its file offset.
/// That is not a shortcut around the reader's address translation: the
/// translation still runs, it is just given an easy answer, which keeps a
/// failing test pointing at the field it actually broke.
[[nodiscard]] inline std::string build_elf(const ElfBuildOptions& options)
{
  constexpr std::uint64_t kSectionTypeStringTable = 3;
  constexpr std::uint64_t kSectionTypeDynamic = 6;
  constexpr std::uint64_t kSectionTypeDynamicSymbols = 11;
  constexpr std::uint64_t kSegmentTypeLoad = 1;
  constexpr std::uint64_t kSegmentTypeDynamic = 2;
  constexpr std::uint64_t kDynamicTagNull = 0;
  constexpr std::uint64_t kDynamicTagNeeded = 1;
  constexpr std::uint64_t kDynamicTagStringTable = 5;
  constexpr std::uint64_t kDynamicTagStringTableSize = 10;
  constexpr std::uint64_t kDynamicTagSoname = 14;
  constexpr std::uint64_t kGlobalFunctionInfo = 0x12;  ///< STB_GLOBAL << 4 | STT_FUNC

  const std::size_t address_width = options.is_64_bit ? 8 : 4;
  const std::size_t header_size = options.is_64_bit ? 64 : 52;
  const std::size_t segment_entry_size = options.is_64_bit ? 56 : 32;
  const std::size_t section_entry_size = options.is_64_bit ? 64 : 40;
  const std::size_t dynamic_entry_size = options.is_64_bit ? 16 : 8;
  const std::size_t symbol_entry_size = options.is_64_bit ? 24 : 16;

  // --- string table -------------------------------------------------------
  std::string string_table(1, '\0');  // index 0 is the empty string, by convention
  std::map<std::string, std::uint64_t> string_offsets;
  const auto intern = [&](const std::string& text)
  {
    const auto existing = string_offsets.find(text);
    if (existing != string_offsets.end())
    {
      return existing->second;
    }
    const std::uint64_t offset = static_cast<std::uint64_t>(string_table.size());
    string_table.append(text);
    string_table.push_back('\0');
    string_offsets.emplace(text, offset);
    return offset;
  };
  for (const std::string& name : options.needed)
  {
    intern(name);
  }
  if (!options.soname.empty())
  {
    intern(options.soname);
  }
  for (const std::string& name : options.exported_symbols)
  {
    intern(name);
  }
  for (const std::string& name : options.undefined_symbols)
  {
    intern(name);
  }

  const bool has_symbols = !options.exported_symbols.empty() || !options.undefined_symbols.empty();
  const std::size_t symbol_count =
      has_symbols ? 1 + options.exported_symbols.size() + options.undefined_symbols.size() : 0;
  const std::size_t dynamic_count =
      options.include_dynamic
          ? options.needed.size() + (options.soname.empty() ? 0u : 1u) + 3u  // STRTAB, STRSZ, NULL
          : 0;

  std::vector<std::uint64_t> segment_types;
  if (options.include_program_headers)
  {
    segment_types.push_back(kSegmentTypeLoad);
    if (options.include_dynamic)
    {
      segment_types.push_back(kSegmentTypeDynamic);
    }
  }

  // --- layout -------------------------------------------------------------
  const auto aligned = [](std::size_t offset)
  { return (offset + 7u) & ~static_cast<std::size_t>(7u); };
  std::size_t cursor = header_size;
  const std::size_t segment_table_offset = cursor;
  cursor += segment_entry_size * segment_types.size();
  const std::size_t string_table_offset = cursor;
  cursor = aligned(cursor + string_table.size());
  const std::size_t dynamic_offset = cursor;
  cursor = aligned(cursor + dynamic_entry_size * dynamic_count);
  const std::size_t symbol_table_offset = cursor;
  cursor = aligned(cursor + symbol_entry_size * symbol_count);

  // Section 0 is the reserved null entry; the reader looks only at sh_type and
  // sh_link, never at names, so no .shstrtab is needed to make this valid for
  // the questions it asks.
  std::size_t section_count = 0;
  std::size_t string_table_section = 0;
  std::size_t dynamic_section = 0;
  std::size_t symbol_table_section = 0;
  if (options.include_section_headers)
  {
    section_count = 2;  // null + .dynstr
    string_table_section = 1;
    if (options.include_dynamic)
    {
      dynamic_section = section_count;
      ++section_count;
    }
    if (has_symbols)
    {
      symbol_table_section = section_count;
      ++section_count;
    }
  }
  const std::size_t section_table_offset = cursor;
  const std::size_t total_size = cursor + section_entry_size * section_count;

  // --- emit ---------------------------------------------------------------
  BinaryWriter writer(options.big_endian);
  writer.put_bytes(
      "\x7F"
      "ELF");
  writer.put_uint(options.is_64_bit ? 2u : 1u, 1);   // EI_CLASS
  writer.put_uint(options.big_endian ? 2u : 1u, 1);  // EI_DATA
  writer.put_uint(1, 1);                             // EI_VERSION
  writer.pad_to(16);
  writer.put_uint(options.file_type, 2);
  writer.put_uint(62, 2);             // e_machine: EM_X86_64, never read by bomwerk
  writer.put_uint(1, 4);              // e_version
  writer.put_uint(0, address_width);  // e_entry
  writer.put_uint(segment_types.empty() ? 0 : segment_table_offset, address_width);
  writer.put_uint(section_count == 0 ? 0 : section_table_offset, address_width);
  writer.put_uint(0, 4);  // e_flags
  writer.put_uint(header_size, 2);
  writer.put_uint(segment_entry_size, 2);
  writer.put_uint(segment_types.size(), 2);
  writer.put_uint(section_entry_size, 2);
  writer.put_uint(section_count, 2);
  writer.put_uint(0, 2);  // e_shstrndx

  for (const std::uint64_t segment_type : segment_types)
  {
    const bool is_load = segment_type == kSegmentTypeLoad;
    const std::uint64_t offset = is_load ? 0 : dynamic_offset;
    const std::uint64_t size = is_load ? total_size : dynamic_entry_size * dynamic_count;
    writer.put_uint(segment_type, 4);
    if (options.is_64_bit)
    {
      writer.put_uint(0, 4);  // p_flags precedes the offsets in ELF64 only
    }
    writer.put_uint(offset, address_width);  // p_offset
    writer.put_uint(offset, address_width);  // p_vaddr: identity map
    writer.put_uint(offset, address_width);  // p_paddr
    writer.put_uint(size, address_width);    // p_filesz
    writer.put_uint(size, address_width);    // p_memsz
    if (!options.is_64_bit)
    {
      writer.put_uint(0, 4);  // p_flags follows the sizes in ELF32
    }
    writer.put_uint(1, address_width);  // p_align
  }

  writer.pad_to(string_table_offset);
  writer.put_bytes(string_table);

  writer.pad_to(dynamic_offset);
  if (options.include_dynamic)
  {
    for (const std::string& name : options.needed)
    {
      writer.put_uint(kDynamicTagNeeded, address_width);
      writer.put_uint(string_offsets[name], address_width);
    }
    if (!options.soname.empty())
    {
      writer.put_uint(kDynamicTagSoname, address_width);
      writer.put_uint(string_offsets[options.soname], address_width);
    }
    writer.put_uint(kDynamicTagStringTable, address_width);
    writer.put_uint(string_table_offset, address_width);  // identity map: address == offset
    writer.put_uint(kDynamicTagStringTableSize, address_width);
    writer.put_uint(string_table.size(), address_width);
    writer.put_uint(kDynamicTagNull, address_width);
    writer.put_uint(0, address_width);
  }

  writer.pad_to(symbol_table_offset);
  if (has_symbols)
  {
    const auto put_symbol =
        [&](std::uint64_t name_offset, std::uint64_t info, std::uint64_t section_index)
    {
      // The one place ELF32 and ELF64 differ in field ORDER rather than width,
      // which is exactly what test_elf_read asserts against on both classes.
      writer.put_uint(name_offset, 4);
      if (options.is_64_bit)
      {
        writer.put_uint(info, 1);
        writer.put_uint(0, 1);  // st_other
        writer.put_uint(section_index, 2);
        writer.put_uint(0, 8);  // st_value
        writer.put_uint(0, 8);  // st_size
      }
      else
      {
        writer.put_uint(0, 4);  // st_value
        writer.put_uint(0, 4);  // st_size
        writer.put_uint(info, 1);
        writer.put_uint(0, 1);  // st_other
        writer.put_uint(section_index, 2);
      }
    };
    put_symbol(0, 0, 0);  // the reserved null symbol
    for (const std::string& name : options.exported_symbols)
    {
      put_symbol(string_offsets[name], kGlobalFunctionInfo, 1);
    }
    for (const std::string& name : options.undefined_symbols)
    {
      put_symbol(string_offsets[name], kGlobalFunctionInfo, 0);  // SHN_UNDEF
    }
  }

  if (section_count > 0)
  {
    writer.pad_to(section_table_offset);
    const auto put_section =
        [&](std::uint64_t type, std::uint64_t offset, std::uint64_t size, std::uint64_t link)
    {
      writer.put_uint(0, 4);  // sh_name: never read by bomwerk
      writer.put_uint(type, 4);
      writer.put_uint(0, address_width);       // sh_flags
      writer.put_uint(offset, address_width);  // sh_addr: identity map
      writer.put_uint(offset, address_width);  // sh_offset
      writer.put_uint(size, address_width);    // sh_size
      writer.put_uint(link, 4);
      writer.put_uint(0, 4);              // sh_info
      writer.put_uint(1, address_width);  // sh_addralign
      writer.put_uint(0, address_width);  // sh_entsize
    };
    put_section(0, 0, 0, 0);  // the reserved null section
    put_section(kSectionTypeStringTable, string_table_offset, string_table.size(), 0);
    if (dynamic_section != 0)
    {
      put_section(kSectionTypeDynamic, dynamic_offset, dynamic_entry_size * dynamic_count,
                  string_table_section);
    }
    if (symbol_table_section != 0)
    {
      put_section(kSectionTypeDynamicSymbols, symbol_table_offset, symbol_entry_size * symbol_count,
                  string_table_section);
    }
  }

  return writer.bytes();
}

}  // namespace bomwerk::test
