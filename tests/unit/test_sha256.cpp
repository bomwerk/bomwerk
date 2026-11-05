// ctest unit test for the SHA-256 content-identity digest
#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

#include "core/sha256.hpp"
#include "support/check.hpp"

using bomwerk::core::kSha256HexLength;
using bomwerk::core::sha256;
using bomwerk::core::Sha256;
using bomwerk::core::sha256_from_hex;
using bomwerk::core::Sha256Digest;
using bomwerk::core::to_hex;

namespace
{

/// The published FIPS 180-4 / NIST CAVS answers. These are the whole reason a
/// hand-rolled digest is acceptable here: a subtly wrong implementation
/// produces no corpus matches rather than wrong ones, and these vectors are
/// what catch it before it ships.
constexpr std::string_view kEmptyDigest =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
constexpr std::string_view kAbcDigest =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
constexpr std::string_view kTwoBlockDigest =
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
constexpr std::string_view kMillionADigest =
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

std::string digest_hex(std::string_view message)
{
  return to_hex(sha256(message));
}

void empty_and_short_messages_match_the_published_vectors()
{
  BOMWERK_TEST_CHECK(digest_hex("") == kEmptyDigest);
  BOMWERK_TEST_CHECK(digest_hex("abc") == kAbcDigest);
  // FIPS 180-4 B.2: 56 bytes, so the padding plus the 8-byte length spills
  // into a second block. The one case a single-block implementation gets wrong.
  BOMWERK_TEST_CHECK(digest_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
                     kTwoBlockDigest);
}

void a_long_message_matches_its_vector()
{
  Sha256 hash;
  const std::string chunk(1000, 'a');
  for (int repetition = 0; repetition < 1000; ++repetition)
  {
    hash.update(chunk);
  }
  BOMWERK_TEST_CHECK(to_hex(hash.digest()) == kMillionADigest);
}

/// Every message length around the 64-byte block boundary, hashed in one call
/// and then fed byte by byte: the two must agree, which is what pins the
/// buffering in `update`.
void block_boundary_lengths_agree_however_they_are_fed()
{
  for (const std::size_t length :
       {std::size_t{0}, std::size_t{1}, std::size_t{55}, std::size_t{56}, std::size_t{63},
        std::size_t{64}, std::size_t{65}, std::size_t{119}, std::size_t{120}, std::size_t{128},
        std::size_t{129}})
  {
    std::string message;
    message.reserve(length);
    for (std::size_t index = 0; index < length; ++index)
    {
      message.push_back(static_cast<char>('a' + (index % 26)));
    }

    Sha256 byte_at_a_time;
    for (const char character : message)
    {
      byte_at_a_time.update(std::string_view(&character, 1));
    }
    BOMWERK_TEST_CHECK(to_hex(byte_at_a_time.digest()) == digest_hex(message));
  }
}

/// Uneven slices across chunk boundaries, including empty updates, must not
/// change the answer: the corpus builder and the scanner feed different sizes.
void uneven_and_empty_updates_do_not_change_the_digest()
{
  std::string message;
  message.reserve(200000);
  for (std::size_t index = 0; index < 200000; ++index)
  {
    message.push_back(static_cast<char>(index % 251));
  }

  Sha256 sliced;
  std::size_t offset = 0;
  std::size_t slice_length = 1;
  while (offset < message.size())
  {
    sliced.update(std::string_view());
    const std::size_t taken = std::min(slice_length, message.size() - offset);
    sliced.update(std::string_view(message.data() + offset, taken));
    offset += taken;
    slice_length = slice_length * 3 + 7;
  }
  BOMWERK_TEST_CHECK(to_hex(sliced.digest()) == digest_hex(message));
}

/// `digest()` finalizes a copy of the state, so asking twice is allowed and
/// feeding more afterwards keeps working. The fingerprint matcher relies on
/// neither, but a digest that destroys its own state is a trap for the next
/// caller.
void digest_is_repeatable_and_does_not_end_the_stream()
{
  Sha256 hash;
  hash.update("abc");
  const Sha256Digest first = hash.digest();
  const Sha256Digest second = hash.digest();
  BOMWERK_TEST_CHECK(first == second);
  BOMWERK_TEST_CHECK(to_hex(first) == kAbcDigest);

  hash.update("d");
  BOMWERK_TEST_CHECK(to_hex(hash.digest()) == digest_hex("abcd"));
}

void hex_round_trips_and_rejects_anything_else()
{
  const Sha256Digest digest = sha256("abc");
  const std::string hex = to_hex(digest);
  BOMWERK_TEST_CHECK(hex.size() == kSha256HexLength);
  BOMWERK_TEST_CHECK(hex == kAbcDigest);

  const auto parsed = sha256_from_hex(hex);
  BOMWERK_TEST_CHECK(parsed.has_value());
  BOMWERK_TEST_CHECK(*parsed == digest);

  // Uppercase is rejected on purpose: an index keyed on two spellings of one
  // digest would hold the same file content twice and score it twice.
  std::string uppercase = hex;
  uppercase[0] = 'B';
  BOMWERK_TEST_CHECK(!sha256_from_hex(uppercase).has_value());

  BOMWERK_TEST_CHECK(!sha256_from_hex("").has_value());
  BOMWERK_TEST_CHECK(!sha256_from_hex(hex.substr(0, kSha256HexLength - 1)).has_value());
  BOMWERK_TEST_CHECK(!sha256_from_hex(hex + "0").has_value());

  std::string non_hex = hex;
  non_hex[kSha256HexLength - 1] = 'g';
  BOMWERK_TEST_CHECK(!sha256_from_hex(non_hex).has_value());

  std::string with_space = hex;
  with_space[10] = ' ';
  BOMWERK_TEST_CHECK(!sha256_from_hex(with_space).has_value());
}

/// A NUL byte is content like any other. The matcher hashes raw bytes with no
/// normalization, so a digest must not stop at a NUL the way a C string would.
void embedded_nul_bytes_are_hashed()
{
  const std::string with_nul("a\0b", 3);
  BOMWERK_TEST_CHECK(with_nul.size() == 3);
  BOMWERK_TEST_CHECK(digest_hex(with_nul) != digest_hex("a"));
  BOMWERK_TEST_CHECK(digest_hex(with_nul) != digest_hex("ab"));
}

/// CRLF and LF content hash differently. That is the documented consequence of
/// hashing raw bytes, and the reason the builder, not the matcher, is where a
/// CRLF variant will one day be added. Asserted so the decision cannot be
/// reversed silently.
void line_endings_are_not_normalized()
{
  BOMWERK_TEST_CHECK(digest_hex("line\r\n") != digest_hex("line\n"));
}

}  // namespace

int main()
{
  empty_and_short_messages_match_the_published_vectors();
  a_long_message_matches_its_vector();
  block_boundary_lengths_agree_however_they_are_fed();
  uneven_and_empty_updates_do_not_change_the_digest();
  digest_is_repeatable_and_does_not_end_the_stream();
  hex_round_trips_and_rejects_anything_else();
  embedded_nul_bytes_are_hashed();
  line_endings_are_not_normalized();
  return 0;
}
