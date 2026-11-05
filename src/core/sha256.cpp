#include "core/sha256.hpp"

#include <algorithm>

namespace bomwerk::core
{
namespace
{

constexpr std::size_t kBlockBytes = 64;
constexpr std::size_t kLengthSuffixBytes = 8;
constexpr std::uint8_t kPaddingStartByte = 0x80;

/// K0..K63, FIPS 180-4 section 4.2.2: the first 32 bits of the fractional
/// parts of the cube roots of the first 64 primes.
constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

std::uint32_t rotate_right(std::uint32_t value, unsigned int bits)
{
  return (value >> bits) | (value << (32u - bits));
}

/// One 64-byte block, FIPS 180-4 section 6.2.2. `block` is read byte by byte
/// rather than cast to a wider type: it points into an arbitrary caller buffer,
/// so it carries no alignment guarantee.
void compress_block(std::array<std::uint32_t, 8>& state, const char* block)
{
  std::array<std::uint32_t, 64> schedule{};
  for (std::size_t word_index = 0; word_index < 16; ++word_index)
  {
    const std::size_t byte_offset = word_index * 4;
    schedule[word_index] =
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(block[byte_offset])) << 24) |
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(block[byte_offset + 1])) << 16) |
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(block[byte_offset + 2])) << 8) |
        static_cast<std::uint32_t>(static_cast<std::uint8_t>(block[byte_offset + 3]));
  }
  for (std::size_t word_index = 16; word_index < 64; ++word_index)
  {
    const std::uint32_t previous_15 = schedule[word_index - 15];
    const std::uint32_t previous_2 = schedule[word_index - 2];
    const std::uint32_t sigma0 =
        rotate_right(previous_15, 7) ^ rotate_right(previous_15, 18) ^ (previous_15 >> 3u);
    const std::uint32_t sigma1 =
        rotate_right(previous_2, 17) ^ rotate_right(previous_2, 19) ^ (previous_2 >> 10u);
    schedule[word_index] = schedule[word_index - 16] + sigma0 + schedule[word_index - 7] + sigma1;
  }

  std::uint32_t a = state[0];
  std::uint32_t b = state[1];
  std::uint32_t c = state[2];
  std::uint32_t d = state[3];
  std::uint32_t e = state[4];
  std::uint32_t f = state[5];
  std::uint32_t g = state[6];
  std::uint32_t h = state[7];

  for (std::size_t round = 0; round < 64; ++round)
  {
    const std::uint32_t big_sigma1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    const std::uint32_t choose = (e & f) ^ (~e & g);
    const std::uint32_t temporary1 =
        h + big_sigma1 + choose + kRoundConstants[round] + schedule[round];
    const std::uint32_t big_sigma0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temporary2 = big_sigma0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + temporary1;
    d = c;
    c = b;
    b = a;
    a = temporary1 + temporary2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

/// One lowercase hex digit's value, or 16 for anything else (including an
/// uppercase digit: see `sha256_from_hex`).
unsigned int lowercase_hex_value(char character)
{
  if (character >= '0' && character <= '9')
  {
    return static_cast<unsigned int>(character - '0');
  }
  if (character >= 'a' && character <= 'f')
  {
    return static_cast<unsigned int>(character - 'a') + 10u;
  }
  return 16u;
}

}  // namespace

void Sha256::update(std::string_view bytes)
{
  total_bytes_ += bytes.size();
  std::size_t offset = 0;

  // Top up a partially filled block first, so a caller feeding uneven slices
  // gets the same digest as one feeding the whole message in a single call.
  if (buffered_bytes_ > 0)
  {
    const std::size_t taken = std::min(kBlockBytes - buffered_bytes_, bytes.size());
    std::copy_n(bytes.begin(), taken,
                block_.begin() + static_cast<std::ptrdiff_t>(buffered_bytes_));
    buffered_bytes_ += taken;
    offset = taken;
    if (buffered_bytes_ == kBlockBytes)
    {
      compress_block(state_, reinterpret_cast<const char*>(block_.data()));
      buffered_bytes_ = 0;
    }
  }

  while (bytes.size() - offset >= kBlockBytes)
  {
    compress_block(state_, bytes.data() + offset);
    offset += kBlockBytes;
  }

  const std::size_t remaining = bytes.size() - offset;
  if (remaining > 0)
  {
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), remaining, block_.begin());
    buffered_bytes_ = remaining;
  }
}

Sha256Digest Sha256::digest() const
{
  // Padding plus the 8-byte length never spans more than two blocks. The state
  // finalized here is a copy, so a caller may keep feeding afterwards.
  std::array<std::uint32_t, 8> state = state_;
  std::array<char, kBlockBytes * 2> tail{};
  std::size_t tail_size = buffered_bytes_;
  std::copy_n(block_.begin(), buffered_bytes_, tail.begin());

  tail[tail_size] = static_cast<char>(kPaddingStartByte);
  ++tail_size;
  while (tail_size % kBlockBytes != kBlockBytes - kLengthSuffixBytes)
  {
    tail[tail_size] = '\0';
    ++tail_size;
  }
  const std::uint64_t message_bit_length = total_bytes_ * 8u;
  for (int shift = 56; shift >= 0; shift -= 8)
  {
    tail[tail_size] = static_cast<char>(message_bit_length >> static_cast<unsigned int>(shift));
    ++tail_size;
  }

  for (std::size_t block_start = 0; block_start < tail_size; block_start += kBlockBytes)
  {
    compress_block(state, tail.data() + block_start);
  }

  Sha256Digest digest_bytes{};
  for (std::size_t word_index = 0; word_index < state.size(); ++word_index)
  {
    const std::uint32_t word = state[word_index];
    digest_bytes[word_index * 4] = static_cast<std::uint8_t>(word >> 24);
    digest_bytes[word_index * 4 + 1] = static_cast<std::uint8_t>(word >> 16);
    digest_bytes[word_index * 4 + 2] = static_cast<std::uint8_t>(word >> 8);
    digest_bytes[word_index * 4 + 3] = static_cast<std::uint8_t>(word);
  }
  return digest_bytes;
}

Sha256Digest sha256(std::string_view bytes)
{
  Sha256 hash;
  hash.update(bytes);
  return hash.digest();
}

std::string to_hex(const Sha256Digest& digest)
{
  constexpr std::string_view kHexDigits = "0123456789abcdef";
  std::string hex;
  hex.reserve(kSha256HexLength);
  for (const std::uint8_t byte : digest)
  {
    hex.push_back(kHexDigits[byte >> 4u]);
    hex.push_back(kHexDigits[byte & 0x0fu]);
  }
  return hex;
}

std::optional<Sha256Digest> sha256_from_hex(std::string_view lowercase_hex)
{
  if (lowercase_hex.size() != kSha256HexLength)
  {
    return std::nullopt;
  }
  Sha256Digest digest_bytes{};
  for (std::size_t byte_index = 0; byte_index < kSha256DigestBytes; ++byte_index)
  {
    const unsigned int high = lowercase_hex_value(lowercase_hex[byte_index * 2]);
    const unsigned int low = lowercase_hex_value(lowercase_hex[byte_index * 2 + 1]);
    if (high > 15u || low > 15u)
    {
      return std::nullopt;
    }
    digest_bytes[byte_index] = static_cast<std::uint8_t>((high << 4u) | low);
  }
  return digest_bytes;
}

}  // namespace bomwerk::core
