#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "support/binary_writer.hpp"

namespace bomwerk::test
{

/// One object inside a fixture archive.
struct ArchiveMember
{
  std::string name;
  std::string data;
};

/// Which `ar` dialect and which optional members `build_archive` emits.
///
/// The two dialects are not a nicety: a vendored `.a` checked into a repository
/// may have been produced by either toolchain, and they spell long names and
/// the symbol index completely differently.
struct ArchiveBuildOptions
{
  std::vector<ArchiveMember> members;
  std::vector<std::string> indexed_symbols;
  bool bsd_long_names = false;         ///< `#1/<len>` names instead of a `//` table
  bool bsd_symbol_index = false;       ///< `__.SYMDEF` instead of the GNU `/` member
  bool include_symbol_index = true;    ///< false leaves the archive with no index at all
  bool force_long_name_table = false;  ///< emit `//` even when every name is short
};

/// Assemble a complete `ar` archive in memory.
[[nodiscard]] inline std::string build_archive(const ArchiveBuildOptions& options)
{
  constexpr std::size_t kNameFieldWidth = 16;
  constexpr std::size_t kSizeFieldWidth = 10;
  /// The longest name that fits the fixed field once GNU's `/` terminator is
  /// accounted for; anything longer must go through the `//` table.
  constexpr std::size_t kMaxShortNameLength = 15;

  BinaryWriter writer(/*big_endian=*/true);  // the GNU index is big-endian by specification
  writer.put_bytes("!<arch>\n");

  const auto put_member = [&](const std::string& header_name, const std::string& data)
  {
    writer.put_padded(header_name, kNameFieldWidth);
    writer.put_padded("0", 12);   // mtime
    writer.put_padded("0", 6);    // uid
    writer.put_padded("0", 6);    // gid
    writer.put_padded("644", 8);  // mode
    writer.put_padded(std::to_string(data.size()), kSizeFieldWidth);
    writer.put_bytes("`\n");
    writer.put_bytes(data);
    if (data.size() % 2 != 0)
    {
      writer.put_bytes("\n");  // members are padded to an even offset
    }
  };

  if (options.include_symbol_index && !options.indexed_symbols.empty())
  {
    if (options.bsd_symbol_index)
    {
      // Content deliberately left empty: bomwerk reads member names from a BSD
      // archive but refuses to guess the native byte order `__.SYMDEF` stores
      // its counts in, so what this member CONTAINS is never parsed: only
      // that it is present and suppresses the symbol sample.
      put_member("__.SYMDEF", std::string(8, '\0'));
    }
    else
    {
      BinaryWriter index(/*big_endian=*/true);
      index.put_uint(options.indexed_symbols.size(), 4);
      for (std::size_t entry = 0; entry < options.indexed_symbols.size(); ++entry)
      {
        index.put_uint(0, 4);  // member offset: present in the format, unused by bomwerk
      }
      for (const std::string& symbol : options.indexed_symbols)
      {
        index.put_c_string(symbol);
      }
      put_member("/", index.bytes());
    }
  }

  // GNU spells a long name as an offset into a `//` member that must precede
  // the members referring to it.
  std::vector<std::string> header_names;
  std::string long_name_table;
  for (const ArchiveMember& member : options.members)
  {
    if (options.bsd_long_names)
    {
      header_names.push_back("#1/" + std::to_string(member.name.size()));
      continue;
    }
    if (member.name.size() > kMaxShortNameLength || options.force_long_name_table)
    {
      header_names.push_back("/" + std::to_string(long_name_table.size()));
      long_name_table.append(member.name);
      long_name_table.append("/\n");
      continue;
    }
    header_names.push_back(member.name + "/");
  }
  if (!long_name_table.empty())
  {
    put_member("//", long_name_table);
  }

  for (std::size_t index = 0; index < options.members.size(); ++index)
  {
    const ArchiveMember& member = options.members[index];
    // A BSD long name lives in the member's own payload, ahead of its content,
    // and the declared size covers both.
    const std::string data = options.bsd_long_names ? member.name + member.data : member.data;
    put_member(header_names[index], data);
  }

  return writer.bytes();
}

}  // namespace bomwerk::test
