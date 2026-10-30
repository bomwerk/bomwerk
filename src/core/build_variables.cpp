#include "core/build_variables.hpp"

#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "core/text.hpp"

namespace bomwerk::core
{
namespace
{

constexpr std::size_t kMaxExpansionDepth = 8;
constexpr std::size_t kMaxSubstitutions = 256;
constexpr std::size_t kMaxExpandedBytes = 8192;

constexpr std::string_view kUnexpandedMarkers[] = {"${", "$(", "$<", "%(", "$ENV{", "$CACHE{"};

std::string table_key(const VariableDialect& dialect, std::string_view name)
{
  if (dialect.case_insensitive_names)
  {
    return to_lower_ascii(name);
  }
  return std::string(name);
}

struct ExpansionBudget
{
  std::size_t substitutions_left = kMaxSubstitutions;
  bool exceeded = false;
};

/// Index of the bracket closing the reference whose opening bracket is at
/// `open_position`, counting nested brackets of the same kind; npos when the
/// reference is never closed.
std::size_t find_closing_bracket(std::string_view text, std::size_t open_position,
                                 const VariableDialect& dialect)
{
  std::size_t nesting = 0;
  for (std::size_t position = open_position; position < text.size(); ++position)
  {
    if (text[position] == dialect.open_bracket)
    {
      ++nesting;
    }
    else if (text[position] == dialect.close_bracket)
    {
      --nesting;
      if (nesting == 0)
      {
        return position;
      }
    }
  }
  return std::string_view::npos;
}

std::string expand_with_budget(std::string_view text, const VariableTable& table,
                               const VariableDialect& dialect, std::size_t depth,
                               ExpansionBudget& budget)
{
  if (depth > kMaxExpansionDepth)
  {
    budget.exceeded = true;
    return std::string(text);
  }

  std::string expanded;
  std::size_t position = 0;
  while (position < text.size() && !budget.exceeded)
  {
    const bool starts_reference = text[position] == '$' && position + 1 < text.size() &&
                                  text[position + 1] == dialect.open_bracket;
    if (!starts_reference)
    {
      expanded.push_back(text[position]);
      ++position;
      continue;
    }

    const std::size_t bracket_position = position + 1;
    const std::size_t closing_position = find_closing_bracket(text, bracket_position, dialect);
    if (closing_position == std::string_view::npos)
    {
      expanded.append(text.substr(position));
      break;
    }

    const std::string_view reference = text.substr(position, closing_position - position + 1);
    const std::string_view raw_name =
        text.substr(bracket_position + 1, closing_position - bracket_position - 1);
    const std::string name = expand_with_budget(raw_name, table, dialect, depth + 1, budget);
    const auto found = table.find(table_key(dialect, name));
    const bool is_defined = found != table.end() && found->second.has_value();
    if (!is_defined)
    {
      expanded.append(reference);
    }
    else if (budget.substitutions_left == 0)
    {
      budget.exceeded = true;
    }
    else
    {
      --budget.substitutions_left;
      expanded += expand_with_budget(*found->second, table, dialect, depth + 1, budget);
    }
    position = closing_position + 1;

    if (expanded.size() > kMaxExpandedBytes)
    {
      budget.exceeded = true;
    }
  }
  return expanded;
}

}  // namespace

void record_variable_definition(VariableTable& table, const VariableDialect& dialect,
                                std::string_view name, std::string value)
{
  const std::string key = table_key(dialect, name);
  const auto found = table.find(key);
  if (value.empty())
  {
    table[key] = std::nullopt;
    return;
  }
  if (found == table.end())
  {
    table.emplace(key, std::move(value));
    return;
  }
  if (found->second.has_value() && *found->second != value)
  {
    found->second = std::nullopt;
  }
}

void mark_variable_ambiguous(VariableTable& table, const VariableDialect& dialect,
                             std::string_view name)
{
  table[table_key(dialect, name)] = std::nullopt;
}

void merge_variable_tables(VariableTable& destination, const VariableDialect& dialect,
                           const VariableTable& source)
{
  for (const auto& [name, value] : source)
  {
    if (value.has_value())
    {
      record_variable_definition(destination, dialect, name, *value);
    }
    else
    {
      mark_variable_ambiguous(destination, dialect, name);
    }
  }
}

bool contains_unexpanded_variable(std::string_view text)
{
  for (const std::string_view marker : kUnexpandedMarkers)
  {
    if (text.find(marker) != std::string_view::npos)
    {
      return true;
    }
  }
  return false;
}

std::string expand_variables(std::string_view text, const VariableTable& table,
                             const VariableDialect& dialect)
{
  if (table.empty() || text.find('$') == std::string_view::npos)
  {
    return std::string(text);
  }
  ExpansionBudget budget;
  std::string expanded = expand_with_budget(text, table, dialect, 0, budget);
  if (budget.exceeded)
  {
    return std::string(text);
  }
  return expanded;
}

}  // namespace bomwerk::core
