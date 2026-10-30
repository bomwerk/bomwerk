#pragma once
#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace bomwerk::core
{

/// How a build system spells a variable reference and compares variable names.
/// CMake writes `${name}` and is case-sensitive; MSBuild writes `$(Name)` and
/// compares names case-insensitively.
struct VariableDialect
{
  char open_bracket;
  char close_bracket;
  bool case_insensitive_names;
};

inline constexpr VariableDialect kCmakeVariableDialect{'{', '}', false};
inline constexpr VariableDialect kMsbuildVariableDialect{'(', ')', true};

/// Variable name to value, as far as static reading can tell. An entry holding
/// `std::nullopt` is ambiguous: the name was defined more than once with
/// different values, or in a way bomwerk cannot evaluate (a CMake function
/// parameter, a list). An ambiguous variable never expands, because a wrong
/// value in a component identity is worse than no value.
using VariableTable = std::map<std::string, std::optional<std::string>>;

/// Records `name = value`. A second definition with a different value turns the
/// entry ambiguous; the same value twice changes nothing. An empty value is
/// ambiguous from the start: expanding it would silently glue a name together.
/// Example: defining `Version` as `1.0` then `2.0` leaves it ambiguous.
void record_variable_definition(VariableTable& table, const VariableDialect& dialect,
                                std::string_view name, std::string value);

/// Marks `name` ambiguous, whatever it held before.
void mark_variable_ambiguous(VariableTable& table, const VariableDialect& dialect,
                             std::string_view name);

/// Copies every entry of `source` into `destination` through
/// `record_variable_definition`, so conflicting values become ambiguous.
void merge_variable_tables(VariableTable& destination, const VariableDialect& dialect,
                           const VariableTable& source);

/// True when `text` still carries a variable reference that no static reading
/// resolved: `${x}`, `$(x)`, `$<x>`, `%(x)` (an MSBuild item metadata
/// reference), `$ENV{x}` or `$CACHE{x}`. This is the one test every parser
/// applies before a name, version or URL reaches a purl.
/// Example: `contains_unexpanded_variable("v$(Major).0")` -> `true`.
[[nodiscard]] bool contains_unexpanded_variable(std::string_view text);

/// Replaces every reference in `text` whose variable is defined and
/// unambiguous, recursively (a value may reference other variables). A
/// reference that cannot be resolved stays in the output verbatim, so the
/// caller finds it with `contains_unexpanded_variable`. When expansion exceeds
/// its depth, substitution or size limit (a cycle, or a value that doubles at
/// every step), the original `text` is returned unchanged.
/// Example: with `Version` = `1.2`, `"$(Version)-beta"` -> `"1.2-beta"`.
[[nodiscard]] std::string expand_variables(std::string_view text, const VariableTable& table,
                                           const VariableDialect& dialect);

}  // namespace bomwerk::core
