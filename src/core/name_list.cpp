#include "core/name_list.hpp"

#include <fstream>
#include <string_view>

#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace bomwerk::core
{
namespace
{

void append_view(std::string& destination, std::string_view value)
{
  destination.append(value.data(), value.size());
}

std::string unreadable_list_warning(std::string_view subject,
                                    const std::filesystem::path& list_path)
{
  const std::string list_path_string = list_path.string();
  std::string message;
  message.reserve(subject.size() + list_path_string.size() + 43);
  message.append("cannot read ");
  append_view(message, subject);
  message.append(" '");
  message.append(list_path_string);
  message.append("'; using built-in list");
  return message;
}

std::string empty_list_warning(std::string_view subject, const std::filesystem::path& list_path)
{
  const std::string list_path_string = list_path.string();
  std::string message;
  message.reserve(subject.size() + list_path_string.size() + 44);
  append_view(message, subject);
  message.append(" '");
  message.append(list_path_string);
  message.append("' contains no entries; using built-in list");
  return message;
}

}  // namespace

Result<std::set<std::string>> load_name_list(const std::filesystem::path& list_path,
                                             std::string_view subject,
                                             const std::set<std::string>& fallback)
{
  Result<std::set<std::string>> result;

  std::ifstream list_stream(list_path);
  if (!list_stream)
  {
    result.warn(WarningCode::kNameListUnreadable, unreadable_list_warning(subject, list_path));
    result.value = fallback;
    return result;
  }

  std::string line;
  while (std::getline(list_stream, line))
  {
    std::string_view name = trimmed_view(line);
    if (name.empty() || name.front() == '#')
    {
      continue;
    }
    result.value.emplace(name.data(), name.size());
  }

  if (result.value.empty())
  {
    result.warn(WarningCode::kNameListEmpty, empty_list_warning(subject, list_path));
    result.value = fallback;
  }
  return result;
}

}  // namespace bomwerk::core
