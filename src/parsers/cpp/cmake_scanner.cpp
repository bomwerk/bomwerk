#include "parsers/cpp/cmake_scanner.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/result.hpp"
#include "core/warning_code.hpp"

namespace bomwerk::parsers::cpp
{
namespace
{

// Bounds against hostile input (Hard Rule 1): a crafted file can never make the
// lexer allocate or spin without limit. Real CMake files sit far below these.
constexpr std::size_t kMaxCommandsPerFile = 20000;
constexpr std::size_t kMaxArgumentsPerCommand = 4000;
constexpr std::size_t kMaxParenDepth = 64;
constexpr std::size_t kMaxArgumentBytes = 64u * 1024u;

bool is_space(char character)
{
  return character == ' ' || character == '\t' || character == '\r' || character == '\n';
}

bool is_identifier_start(char character)
{
  return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
         character == '_';
}

bool is_identifier_char(char character)
{
  return is_identifier_start(character) || (character >= '0' && character <= '9');
}

/// Single-pass CMake lexer. Stateful and multi-step, so a class earns its keep
/// here (docs/CONTRIBUTING.md code-shape rule); the public surface stays the free
/// `scan_cmake_commands` below.
class CmakeLexer
{
 public:
  explicit CmakeLexer(std::string_view text) : text_(text) {}

  core::Result<std::vector<CmakeCommand>> scan()
  {
    while (has_input())
    {
      skip_ignorable();
      if (!has_input())
      {
        break;
      }
      if (commands_.size() >= kMaxCommandsPerFile)
      {
        result_.warn(core::WarningCode::kEntryLimitReached,
                     "cmake: more than " + std::to_string(kMaxCommandsPerFile) +
                         " commands in one file; remaining commands ignored",
                     "cmake");
        break;
      }
      if (is_identifier_start(current()))
      {
        read_command();
      }
      else
      {
        advance();  // a stray delimiter at top level; nothing to record
      }
    }
    result_.value = std::move(commands_);
    return std::move(result_);
  }

 private:
  bool has_input() const { return position_ < text_.size(); }
  char current() const { return text_[position_]; }

  void advance()
  {
    if (position_ < text_.size())
    {
      if (text_[position_] == '\n')
      {
        ++line_;
      }
      ++position_;
    }
  }

  /// Skip whitespace and comments (`#` line, `#[[ ]]` / `#[=[ ]=]` bracket).
  void skip_ignorable()
  {
    while (has_input())
    {
      if (is_space(current()))
      {
        advance();
        continue;
      }
      if (current() == '#')
      {
        skip_comment();
        continue;
      }
      break;
    }
  }

  void skip_comment()
  {
    advance();  // consume '#'
    std::size_t equals_count = 0;
    if (has_input() && current() == '[' && match_bracket_open(equals_count))
    {
      while (has_input())
      {
        if (current() == ']' && match_bracket_close(equals_count))
        {
          return;
        }
        advance();
      }
      result_.warn(core::WarningCode::kMalformedEntrySkipped, "cmake: unterminated bracket comment",
                   "cmake");
      return;
    }
    while (has_input() && current() != '\n')
    {
      advance();
    }
  }

  void read_command()
  {
    const std::size_t start_line = line_;
    std::string name;
    while (has_input() && is_identifier_char(current()))
    {
      name.push_back(current());
      advance();
    }
    skip_ignorable();
    if (!has_input() || current() != '(')
    {
      return;  // a bare identifier, not a command invocation
    }
    advance();  // consume '('
    read_arguments(std::move(name), start_line);
  }

  void read_arguments(std::string name, std::size_t start_line)
  {
    std::vector<std::string> arguments;
    std::size_t paren_depth = 1;
    bool stopped_early = false;
    while (has_input())
    {
      skip_ignorable();
      if (!has_input())
      {
        break;  // unterminated; reported after the loop
      }
      const char character = current();
      if (character == ')')
      {
        advance();
        --paren_depth;
        if (paren_depth == 0)
        {
          commands_.push_back({std::move(name), std::move(arguments), start_line});
          return;
        }
        continue;
      }
      if (character == '(')
      {
        advance();
        ++paren_depth;
        if (paren_depth > kMaxParenDepth)
        {
          result_.warn(core::WarningCode::kEntryLimitReached,
                       "cmake: parenthesis nesting too deep near line " + std::to_string(line_),
                       "cmake");
          stopped_early = true;
          break;
        }
        continue;
      }
      if (arguments.size() >= kMaxArgumentsPerCommand)
      {
        result_.warn(
            core::WarningCode::kEntryLimitReached,
            "cmake: too many arguments to " + name + " near line " + std::to_string(start_line),
            "cmake");
        stopped_early = true;
        break;
      }
      if (character == '"')
      {
        arguments.push_back(read_quoted_argument());
        continue;
      }
      std::size_t equals_count = 0;
      if (character == '[' && match_bracket_open(equals_count))
      {
        arguments.push_back(read_bracket_argument(equals_count));
        continue;
      }
      arguments.push_back(read_bare_argument());
    }
    if (!stopped_early)
    {
      result_.warn(
          core::WarningCode::kMalformedEntrySkipped,
          "cmake: unterminated command " + name + " starting at line " + std::to_string(start_line),
          "cmake");
    }
    // Reached only via an unterminated command (EOF) or a tripped cap: either
    // way the arguments are a partial, best-effort recovery, so flag it.
    commands_.push_back({std::move(name), std::move(arguments), start_line, /*well_formed=*/false});
  }

  std::string read_quoted_argument()
  {
    advance();  // consume opening quote
    std::string value;
    while (has_input())
    {
      const char character = current();
      if (character == '"')
      {
        advance();  // consume closing quote
        return value;
      }
      if (character == '\\')
      {
        advance();
        if (!has_input())
        {
          break;
        }
        append_bounded(value, current());  // \" -> ", \\ -> \, else keep the char
        advance();
        continue;
      }
      append_bounded(value, character);
      advance();
    }
    result_.warn(core::WarningCode::kMalformedEntrySkipped, "cmake: unterminated quoted argument",
                 "cmake");
    return value;
  }

  std::string read_bracket_argument(std::size_t equals_count)
  {
    std::string value;
    while (has_input())
    {
      if (current() == ']' && match_bracket_close(equals_count))
      {
        return value;
      }
      append_bounded(value, current());
      advance();
    }
    result_.warn(core::WarningCode::kMalformedEntrySkipped, "cmake: unterminated bracket argument",
                 "cmake");
    return value;
  }

  /// A bare (unquoted) argument runs to the next whitespace or `(` `)` `"`. A
  /// `#` mid-token is kept (so `gh:owner/repo#tag` survives): a `#` only starts
  /// a comment at a token boundary, which `skip_ignorable` handles first. A
  /// backslash escapes the next character literally: real CMake files embed a
  /// quote this way inside an unquoted argument (e.g.
  /// `-DVERSION=\"${GIT_VERSION}\"`); without this, the escaped `"` would be
  /// mistaken for the start of a new quoted argument and swallow the rest of
  /// the file.
  std::string read_bare_argument()
  {
    std::string value;
    while (has_input())
    {
      const char character = current();
      if (character == '\\')
      {
        advance();
        if (!has_input())
        {
          break;
        }
        append_bounded(value, current());
        advance();
        continue;
      }
      if (is_space(character) || character == '(' || character == ')' || character == '"')
      {
        break;
      }
      append_bounded(value, character);
      advance();
    }
    return value;
  }

  /// At a `[`: consume a bracket opener `[` `=`* `[`, reporting its `=` count.
  /// Leaves the position unchanged and returns false when it is not an opener.
  bool match_bracket_open(std::size_t& equals_count)
  {
    if (current() != '[')
    {
      return false;
    }
    std::size_t scan = position_ + 1;
    std::size_t equals = 0;
    while (scan < text_.size() && text_[scan] == '=')
    {
      ++equals;
      ++scan;
    }
    if (scan >= text_.size() || text_[scan] != '[')
    {
      return false;
    }
    equals_count = equals;
    for (std::size_t step = 0; step < equals + 2; ++step)
    {
      advance();
    }
    return true;
  }

  /// At a `]`: consume a matching close `]` `=`{equals_count} `]` and return
  /// true, else leave the position unchanged and return false.
  bool match_bracket_close(std::size_t equals_count)
  {
    if (current() != ']')
    {
      return false;
    }
    std::size_t scan = position_ + 1;
    std::size_t equals = 0;
    while (scan < text_.size() && equals < equals_count && text_[scan] == '=')
    {
      ++equals;
      ++scan;
    }
    if (equals != equals_count || scan >= text_.size() || text_[scan] != ']')
    {
      return false;
    }
    for (std::size_t step = 0; step < equals_count + 2; ++step)
    {
      advance();
    }
    return true;
  }

  void append_bounded(std::string& value, char character)
  {
    if (value.size() < kMaxArgumentBytes)
    {
      value.push_back(character);
    }
  }

  std::string_view text_;
  std::size_t position_ = 0;
  std::size_t line_ = 1;
  std::vector<CmakeCommand> commands_;
  core::Result<std::vector<CmakeCommand>> result_;
};

}  // namespace

core::Result<std::vector<CmakeCommand>> scan_cmake_commands(std::string_view text)
{
  CmakeLexer lexer(text);
  return lexer.scan();
}

}  // namespace bomwerk::parsers::cpp
