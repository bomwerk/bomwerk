// libFuzzer harness for the vendoring-record reader (T123): the input is one
// record file. BOMWERK_FUZZ_VARIANT names which format (see
// scripts/fuzz_targets.json): "README.md" reads it as a directory's index of
// its vendored libraries (Godot's thirdparty/README.md), "README.chromium" as
// the record a Chromium-style vendored directory keeps inside itself. A crash
// input is a plain record file that can be committed as-is under
// fixtures/vendoring_record/hostile/.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/text.hpp"
#include "fuzz/fuzz_support.hpp"
#include "heuristics/vendoring_record.hpp"

#ifndef BOMWERK_FUZZ_VARIANT
#error "BOMWERK_FUZZ_VARIANT must name the file this harness parses"
#endif

namespace
{

namespace vendoring_record = bomwerk::heuristics::vendoring_record;

bool has_newline(std::string_view text)
{
  return text.find('\n') != std::string_view::npos;
}

/// What `Record` promises whichever format produced it.
void require_record_invariants(const vendoring_record::Record& record)
{
  using bomwerk::fuzz::require;
  require(!record.version.empty(), "a record always states a version");
  require(record.commit.empty() || bomwerk::core::is_hex_object_id(record.commit),
          "a record's commit is a 40- or 64-hex object id");
  require(record.commit == bomwerk::core::to_lower_ascii(record.commit),
          "a record's commit is lower-cased");
  if (record.states_release())
  {
    require(record.version.size() <= vendoring_record::kMaxVersionChars,
            "a stated release fits kMaxVersionChars");
    require(!bomwerk::core::is_hex_object_id(record.version), "a stated release is not a commit");
  }
  require(record.upstream.empty() || record.upstream.starts_with("http://") ||
              record.upstream.starts_with("https://"),
          "an upstream is an http(s) URL");
  require(record.upstream.find(' ') == std::string::npos, "an upstream holds no blank");
  require(!has_newline(record.folder) && !has_newline(record.version) &&
              !has_newline(record.commit) && !has_newline(record.upstream) &&
              !has_newline(record.version_line),
          "no record field spans lines");
  require(record.upstream.size() <= vendoring_record::kMaxLineChars,
          "an upstream comes from one bounded line");
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  using bomwerk::fuzz::require;
  const std::string_view text = bomwerk::fuzz::as_text(data, size);
  constexpr std::string_view kVariant = BOMWERK_FUZZ_VARIANT;

  if (kVariant == "README.chromium")
  {
    if (const std::optional<vendoring_record::Record> record =
            vendoring_record::parse_readme_chromium(text))
    {
      require(record->folder.empty(), "a README.chromium names no other folder");
      require_record_invariants(*record);
    }
    return 0;
  }

  const std::vector<vendoring_record::Record> records = vendoring_record::parse_index(text);
  std::vector<std::string> folders;
  folders.reserve(records.size());
  for (const vendoring_record::Record& record : records)
  {
    require(!record.folder.empty(), "an index record names its folder");
    require(record.folder.find('/') == std::string::npos &&
                record.folder.find('\\') == std::string::npos,
            "an index folder is one path segment");
    require_record_invariants(record);
    folders.push_back(record.folder);
  }
  require(bomwerk::fuzz::sorted_and_unique(folders),
          "index records are sorted by folder, each name once");
  return 0;
}
