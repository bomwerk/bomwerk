#pragma once
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "core/result.hpp"

namespace bomwerk::core
{

/// One `key = value` line inside a section. Keys are lower-cased (git config is
/// case-insensitive for names); values keep their original case, minus one pair
/// of surrounding double quotes.
struct GitConfigEntry
{
  std::string key;
  std::string value;
};

/// A `[name "subsection"]` block. For `.gitmodules` this is
/// `[submodule "<path-or-name>"]`; for `.git/config`, `[remote "origin"]` etc.
struct GitConfigSection
{
  std::string name;        ///< lower-cased section name, e.g. "submodule"
  std::string subsection;  ///< verbatim text between the quotes, e.g. "lib/mbedtls"
  std::vector<GitConfigEntry> entries;

  /// First value whose key matches `key` (case-insensitive), or nullptr.
  const std::string* find(std::string_view key) const;
};

/// A parsed git-config file: its sections in file order.
struct GitConfig
{
  std::vector<GitConfigSection> sections;

  /// First value of `key` in the section matching `name`+`subsection`
  /// (case-insensitive on names), or nullptr. Convenience for lookups like
  /// remote/origin/url.
  const std::string* find(std::string_view name, std::string_view subsection,
                          std::string_view key) const;
};

/// Parse git-config INI text (shared by `.gitmodules` and `.git/config`) from a
/// file. Never throws (rule 1): a missing file yields an empty config with no
/// warning (a repo may simply have none); a present-but-unreadable, oversized,
/// or malformed file yields warnings plus whatever parsed cleanly. Bounded
/// against hostile input: total size, per-line length and section count are
/// capped, so a crafted file cannot exhaust memory or time.
[[nodiscard]] Result<GitConfig> read_git_config(const std::filesystem::path& path);

/// Parse git-config INI from an in-memory buffer; `label` names the source in
/// warnings. Used by tests and fuzzers, and by read_git_config() after it loads
/// the bytes.
[[nodiscard]] Result<GitConfig> parse_git_config(std::string_view text, const std::string& label);

}  // namespace bomwerk::core
