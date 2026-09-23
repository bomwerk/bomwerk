#include "output/warnings_report.hpp"

#include <algorithm>
#include <cstddef>
#include <map>
#include <nlohmann/json.hpp>
#include <utility>

#include "core/timestamp.hpp"
#include "core/warning_code.hpp"

namespace bomwerk::output
{
namespace
{

struct WarningGroupKey
{
  core::WarningCode code;
  std::string code_id;
  std::string ecosystem;

  [[nodiscard]] bool operator<(const WarningGroupKey& other) const
  {
    if (code_id != other.code_id)
    {
      return code_id < other.code_id;
    }
    return ecosystem < other.ecosystem;
  }
};

struct WarningGroup
{
  std::vector<std::string> messages;     ///< every occurrence's text, sorted below
  std::set<std::string> affected_paths;  ///< deduped, sorted by std::set itself
  std::size_t occurrence_count = 0;
};

nlohmann::json group_to_json(const WarningGroupKey& key, const WarningGroup& group, bool suppressed)
{
  nlohmann::json entry;
  entry["code"] = key.code_id;
  if (!key.ecosystem.empty())
  {
    entry["ecosystem"] = key.ecosystem;
  }
  // The lexicographically smallest message stands for the group: deterministic regardless
  // of the order producers ran in or the order their warnings were recorded (rule 3).
  entry["message"] = *std::min_element(group.messages.begin(), group.messages.end());
  entry["count"] = group.occurrence_count;
  entry["suppressed"] = suppressed;
  if (!group.affected_paths.empty())
  {
    entry["affected_paths"] = group.affected_paths;
  }
  return entry;
}

}  // namespace

std::string write_warnings_report(const std::vector<core::Warning>& warnings,
                                  const std::set<std::string>& suppressed_codes,
                                  const ToolInfo& tool, const core::ReleaseMeta& release_meta)
{
  nlohmann::json document;
  document["tool"]["name"] = tool.name;
  document["tool"]["version"] = tool.version;
  document["generated_at"] = core::current_timestamp_iso8601();

  if (!release_meta.product_id.empty())
  {
    document["product"]["id"] = release_meta.product_id;
    if (!release_meta.version.empty())
    {
      document["product"]["version"] = release_meta.version;
    }
  }

  std::map<WarningGroupKey, WarningGroup> groups;
  for (const core::Warning& warning : warnings)
  {
    const WarningGroupKey key{warning.code, std::string(core::code_info_of(warning).id),
                              warning.ecosystem};
    WarningGroup& group = groups[key];
    group.messages.push_back(warning.message);
    ++group.occurrence_count;
    if (!warning.affected_path.empty())
    {
      group.affected_paths.insert(warning.affected_path.generic_string());
    }
  }

  nlohmann::json warnings_json = nlohmann::json::array();
  for (const auto& [key, group] : groups)
  {
    const bool suppressed =
        core::is_warning_suppressed(key.code_id, key.ecosystem, suppressed_codes);
    warnings_json.push_back(group_to_json(key, group, suppressed));
  }
  document["warnings"] = std::move(warnings_json);
  document["total_occurrences"] = warnings.size();

  return document.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
}

}  // namespace bomwerk::output
