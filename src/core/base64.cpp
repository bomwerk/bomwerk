#include "core/base64.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace bomwerk::core
{
namespace
{

constexpr std::string_view kAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr std::string_view kUrlAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// One base64 symbol carries 6 bits, so a 3-byte group becomes 4 symbols; the
/// `>> 18/12/6` shifts below slice that 24-bit group six bits at a time (the
/// canonical RFC 4648 packing).
constexpr std::size_t kInputBytesPerGroup = 3;
constexpr std::size_t kOutputSymbolsPerGroup = 4;

int base64url_symbol_value(char symbol)
{
  const std::size_t position = kUrlAlphabet.find(symbol);
  if (position == std::string_view::npos)
  {
    return -1;
  }
  return static_cast<int>(position);
}

}  // namespace

std::string base64_encode(std::string_view bytes)
{
  std::string encoded;
  encoded.reserve(((bytes.size() + kInputBytesPerGroup - 1) / kInputBytesPerGroup) *
                  kOutputSymbolsPerGroup);

  std::size_t position = 0;
  while (position + kInputBytesPerGroup <= bytes.size())
  {
    const std::uint32_t group = (static_cast<std::uint8_t>(bytes[position]) << 16) |
                                (static_cast<std::uint8_t>(bytes[position + 1]) << 8) |
                                static_cast<std::uint8_t>(bytes[position + 2]);
    encoded += kAlphabet[(group >> 18) & 0x3F];
    encoded += kAlphabet[(group >> 12) & 0x3F];
    encoded += kAlphabet[(group >> 6) & 0x3F];
    encoded += kAlphabet[group & 0x3F];
    position += kInputBytesPerGroup;
  }

  const std::size_t remaining = bytes.size() - position;
  if (remaining == 1)
  {
    const std::uint32_t group = static_cast<std::uint8_t>(bytes[position]) << 16;
    encoded += kAlphabet[(group >> 18) & 0x3F];
    encoded += kAlphabet[(group >> 12) & 0x3F];
    encoded += '=';
    encoded += '=';
  }
  else if (remaining == 2)
  {
    const std::uint32_t group = (static_cast<std::uint8_t>(bytes[position]) << 16) |
                                (static_cast<std::uint8_t>(bytes[position + 1]) << 8);
    encoded += kAlphabet[(group >> 18) & 0x3F];
    encoded += kAlphabet[(group >> 12) & 0x3F];
    encoded += kAlphabet[(group >> 6) & 0x3F];
    encoded += '=';
  }
  return encoded;
}

std::optional<std::string> base64url_decode(std::string_view text)
{
  constexpr std::size_t kInvalidRemainder = 1;
  constexpr int kSecondSymbolUnusedBitMask = 0x0F;
  constexpr int kThirdSymbolUnusedBitMask = 0x03;

  if (text.size() % kOutputSymbolsPerGroup == kInvalidRemainder)
  {
    return std::nullopt;
  }

  std::string decoded;
  decoded.reserve((text.size() / kOutputSymbolsPerGroup) * kInputBytesPerGroup +
                  (text.size() % kOutputSymbolsPerGroup));

  std::size_t position = 0;
  while (position + kOutputSymbolsPerGroup <= text.size())
  {
    const int first = base64url_symbol_value(text[position]);
    const int second = base64url_symbol_value(text[position + 1]);
    const int third = base64url_symbol_value(text[position + 2]);
    const int fourth = base64url_symbol_value(text[position + 3]);
    if (first < 0 || second < 0 || third < 0 || fourth < 0)
    {
      return std::nullopt;
    }

    decoded.push_back(static_cast<char>((first << 2) | (second >> 4)));
    decoded.push_back(static_cast<char>((second << 4) | (third >> 2)));
    decoded.push_back(static_cast<char>((third << 6) | fourth));
    position += kOutputSymbolsPerGroup;
  }

  const std::size_t remaining = text.size() - position;
  if (remaining == 2)
  {
    const int first = base64url_symbol_value(text[position]);
    const int second = base64url_symbol_value(text[position + 1]);
    if (first < 0 || second < 0 || (second & kSecondSymbolUnusedBitMask) != 0)
    {
      return std::nullopt;
    }
    decoded.push_back(static_cast<char>((first << 2) | (second >> 4)));
  }
  else if (remaining == 3)
  {
    const int first = base64url_symbol_value(text[position]);
    const int second = base64url_symbol_value(text[position + 1]);
    const int third = base64url_symbol_value(text[position + 2]);
    if (first < 0 || second < 0 || third < 0 || (third & kThirdSymbolUnusedBitMask) != 0)
    {
      return std::nullopt;
    }
    decoded.push_back(static_cast<char>((first << 2) | (second >> 4)));
    decoded.push_back(static_cast<char>((second << 4) | (third >> 2)));
  }

  return decoded;
}

}  // namespace bomwerk::core
