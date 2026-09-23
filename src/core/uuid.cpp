#include "core/uuid.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace bomwerk::core
{
namespace
{

struct Sha1Digest
{
  std::array<std::uint8_t, 20> bytes{};
};

std::uint32_t rotate_left(std::uint32_t value, int bits)
{
  return (value << bits) | (value >> (32 - bits));
}

/// Textbook SHA-1 (RFC 3174): used only as the hash RFC 9562 (formerly RFC
/// 4122) specifies for version-5 UUIDs, never for anything
/// security-sensitive.
Sha1Digest sha1(const std::vector<std::uint8_t>& message)
{
  constexpr std::size_t kBlockBytes = 64;
  constexpr std::size_t kLengthSuffixBytes = 8;
  constexpr std::uint8_t kPaddingStartByte = 0x80;

  std::uint32_t h0 = 0x67452301;
  std::uint32_t h1 = 0xEFCDAB89;
  std::uint32_t h2 = 0x98BADCFE;
  std::uint32_t h3 = 0x10325476;
  std::uint32_t h4 = 0xC3D2E1F0;

  std::vector<std::uint8_t> padded(message);
  const std::uint64_t original_bit_length = static_cast<std::uint64_t>(message.size()) * 8;
  padded.push_back(kPaddingStartByte);
  while (padded.size() % kBlockBytes != kBlockBytes - kLengthSuffixBytes)
  {
    padded.push_back(0x00);
  }
  for (int shift = 56; shift >= 0; shift -= 8)
  {
    padded.push_back(static_cast<std::uint8_t>(original_bit_length >> shift));
  }

  for (std::size_t block_start = 0; block_start < padded.size(); block_start += kBlockBytes)
  {
    std::array<std::uint32_t, 80> schedule{};
    for (int word_index = 0; word_index < 16; ++word_index)
    {
      const std::size_t byte_offset = block_start + static_cast<std::size_t>(word_index) * 4;
      schedule[word_index] = (static_cast<std::uint32_t>(padded[byte_offset]) << 24) |
                             (static_cast<std::uint32_t>(padded[byte_offset + 1]) << 16) |
                             (static_cast<std::uint32_t>(padded[byte_offset + 2]) << 8) |
                             static_cast<std::uint32_t>(padded[byte_offset + 3]);
    }
    for (int word_index = 16; word_index < 80; ++word_index)
    {
      schedule[word_index] = rotate_left(schedule[word_index - 3] ^ schedule[word_index - 8] ^
                                             schedule[word_index - 14] ^ schedule[word_index - 16],
                                         1);
    }

    std::uint32_t a = h0;
    std::uint32_t b = h1;
    std::uint32_t c = h2;
    std::uint32_t d = h3;
    std::uint32_t e = h4;
    for (int round = 0; round < 80; ++round)
    {
      std::uint32_t round_function = 0;
      std::uint32_t round_constant = 0;
      if (round < 20)
      {
        round_function = (b & c) | (~b & d);
        round_constant = 0x5A827999;
      }
      else if (round < 40)
      {
        round_function = b ^ c ^ d;
        round_constant = 0x6ED9EBA1;
      }
      else if (round < 60)
      {
        round_function = (b & c) | (b & d) | (c & d);
        round_constant = 0x8F1BBCDC;
      }
      else
      {
        round_function = b ^ c ^ d;
        round_constant = 0xCA62C1D6;
      }
      const std::uint32_t temp =
          rotate_left(a, 5) + round_function + e + round_constant + schedule[round];
      e = d;
      d = c;
      c = rotate_left(b, 30);
      b = a;
      a = temp;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  Sha1Digest digest;
  const std::array<std::uint32_t, 5> words{h0, h1, h2, h3, h4};
  for (std::size_t word_index = 0; word_index < words.size(); ++word_index)
  {
    digest.bytes[word_index * 4] = static_cast<std::uint8_t>(words[word_index] >> 24);
    digest.bytes[word_index * 4 + 1] = static_cast<std::uint8_t>(words[word_index] >> 16);
    digest.bytes[word_index * 4 + 2] = static_cast<std::uint8_t>(words[word_index] >> 8);
    digest.bytes[word_index * 4 + 3] = static_cast<std::uint8_t>(words[word_index]);
  }
  return digest;
}

}  // namespace

std::string Uuid::to_string() const
{
  static constexpr char kHexDigits[] = "0123456789abcdef";
  std::string formatted;
  formatted.reserve(36);
  for (std::size_t byte_index = 0; byte_index < bytes_.size(); ++byte_index)
  {
    if (byte_index == 4 || byte_index == 6 || byte_index == 8 || byte_index == 10)
    {
      formatted.push_back('-');
    }
    formatted.push_back(kHexDigits[bytes_[byte_index] >> 4]);
    formatted.push_back(kHexDigits[bytes_[byte_index] & 0x0Fu]);
  }
  return formatted;
}

Uuid uuidv5(const Uuid& namespace_id, std::string_view name)
{
  std::vector<std::uint8_t> message(namespace_id.bytes().begin(), namespace_id.bytes().end());
  message.insert(message.end(), name.begin(), name.end());

  const Sha1Digest digest = sha1(message);

  std::array<std::uint8_t, 16> uuid_bytes{};
  std::copy_n(digest.bytes.begin(), uuid_bytes.size(), uuid_bytes.begin());
  uuid_bytes[6] = static_cast<std::uint8_t>((uuid_bytes[6] & 0x0Fu) | 0x50u);  // version 5
  uuid_bytes[8] =
      static_cast<std::uint8_t>((uuid_bytes[8] & 0x3Fu) | 0x80u);  // variant, RFC 9562 §4.1
  return Uuid(uuid_bytes);
}

const Uuid& purl_namespace()
{
  // uuidv5(NAMESPACE_DNS, "bomwerk.dev"); see the header doc comment.
  static const Uuid kNamespace(std::array<std::uint8_t, 16>{0xa9, 0xed, 0x27, 0xb8, 0xae, 0xaa,
                                                            0x51, 0x58, 0x8f, 0x3a, 0x40, 0x09,
                                                            0x32, 0x50, 0x59, 0x98});
  return kNamespace;
}

}  // namespace bomwerk::core
