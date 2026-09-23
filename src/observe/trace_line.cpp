#include "observe/trace_line.hpp"

#include <cstddef>

namespace bomwerk::observe
{
namespace
{

/// Typical compile command: a few hundred bytes of flags and include paths.
/// Reserving up front keeps the hot path (one per compile) free of reallocs.
constexpr std::size_t kInitialLineCapacity = 512;

/// U+FFFD REPLACEMENT CHARACTER, the standard stand-in for a byte sequence
/// that is not valid UTF-8.
constexpr std::string_view kReplacementCharacter = "\xEF\xBF\xBD";

constexpr std::string_view kHexDigits = "0123456789abcdef";

/// Append `\u00XX` for a control character JSON gives no short escape.
void append_unicode_escape(std::string& output, unsigned char value)
{
  output += "\\u00";
  output.push_back(kHexDigits[(value >> 4U) & 0x0FU]);
  output.push_back(kHexDigits[value & 0x0FU]);
}

bool is_utf8_continuation(unsigned char byte)
{
  return (byte & 0xC0U) == 0x80U;
}

/// Length of the well-formed UTF-8 sequence starting at `position`, or 0 when
/// the bytes there are not valid UTF-8. Rejects over-long encodings and the
/// surrogate range (ED A0..BF), both of which are invalid in JSON strings.
std::size_t valid_utf8_sequence_length(std::string_view text, std::size_t position)
{
  const std::size_t available = text.size() - position;
  const auto byte_at = [&text, position](std::size_t offset)
  { return static_cast<unsigned char>(text[position + offset]); };

  // The boundaries below are written as plain int literals, not 0xC2U-style
  // unsigned ones: `lead` promotes to int, and mixing it with an unsigned
  // constant is a signed/unsigned comparison the -Werror build would reject.
  const int lead = byte_at(0);
  if (lead >= 0xC2 && lead <= 0xDF)
  {
    return (available >= 2 && is_utf8_continuation(byte_at(1))) ? 2 : 0;
  }
  if (lead >= 0xE0 && lead <= 0xEF)
  {
    if (available < 3 || !is_utf8_continuation(byte_at(1)) || !is_utf8_continuation(byte_at(2)))
    {
      return 0;
    }
    const int second = byte_at(1);
    if (lead == 0xE0 && second < 0xA0)
    {
      return 0;  // over-long encoding of a two-byte value
    }
    if (lead == 0xED && second >= 0xA0)
    {
      return 0;  // UTF-16 surrogate half, never valid in UTF-8
    }
    return 3;
  }
  if (lead >= 0xF0 && lead <= 0xF4)
  {
    if (available < 4 || !is_utf8_continuation(byte_at(1)) || !is_utf8_continuation(byte_at(2)) ||
        !is_utf8_continuation(byte_at(3)))
    {
      return 0;
    }
    const int second = byte_at(1);
    if (lead == 0xF0 && second < 0x90)
    {
      return 0;  // over-long
    }
    if (lead == 0xF4 && second >= 0x90)
    {
      return 0;  // beyond U+10FFFF
    }
    return 4;
  }
  return 0;  // 0x80..0xC1 and 0xF5..0xFF never start a sequence
}

/// Append `text` as a quoted, escaped JSON string.
void append_json_string(std::string& output, std::string_view text)
{
  output.push_back('"');
  std::size_t position = 0;
  while (position < text.size())
  {
    const unsigned char byte = static_cast<unsigned char>(text[position]);
    if (byte < 0x80)
    {
      switch (byte)
      {
        case '"':
          output += "\\\"";
          break;
        case '\\':
          output += "\\\\";
          break;
        case '\b':
          output += "\\b";
          break;
        case '\f':
          output += "\\f";
          break;
        case '\n':
          output += "\\n";
          break;
        case '\r':
          output += "\\r";
          break;
        case '\t':
          output += "\\t";
          break;
        default:
          if (byte < 0x20)
          {
            append_unicode_escape(output, byte);
          }
          else
          {
            output.push_back(static_cast<char>(byte));
          }
          break;
      }
      ++position;
      continue;
    }

    const std::size_t sequence_length = valid_utf8_sequence_length(text, position);
    if (sequence_length == 0)
    {
      // A POSIX filename is any byte string; JSON strings must be Unicode.
      // Substituting keeps the line parseable, so one odd filename costs that
      // argument's fidelity instead of the whole invocation.
      output += kReplacementCharacter;
      ++position;
      continue;
    }
    output.append(text, position, sequence_length);
    position += sequence_length;
  }
  output.push_back('"');
}

}  // namespace

std::string build_trace_line(std::string_view tool_name, const std::vector<std::string>& arguments,
                             std::string_view working_directory, long process_id)
{
  std::string line;
  line.reserve(kInitialLineCapacity);

  // Key order is sorted and hand-written rather than left to a JSON library:
  // the shim links no dependencies at all (it runs once per compile), and
  // sorted keys are the rule-3 contract.
  line += "{\"argv\":[";
  for (std::size_t argument_index = 0; argument_index < arguments.size(); ++argument_index)
  {
    if (argument_index > 0)
    {
      line.push_back(',');
    }
    append_json_string(line, arguments[argument_index]);
  }
  line += "],\"cwd\":";
  append_json_string(line, working_directory);
  line += ",\"pid\":";
  line += std::to_string(process_id);
  line += ",\"tool\":";
  append_json_string(line, tool_name);
  line += "}\n";
  return line;
}

}  // namespace bomwerk::observe
