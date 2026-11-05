#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace bomwerk::core
{

inline constexpr std::size_t kSha256DigestBytes = 32;

/// Length of a SHA-256 digest written as lowercase hex, the form
/// `Component::sha256` carries and the form the fingerprint corpus index keys
/// on. Several writers still define their own local copy of this number; this
/// is the one new code should use.
inline constexpr std::size_t kSha256HexLength = kSha256DigestBytes * 2;

using Sha256Digest = std::array<std::uint8_t, kSha256DigestBytes>;

/// Streaming SHA-256 (FIPS 180-4). Used only as a CONTENT-IDENTITY digest: it
/// answers "are these the same bytes as that upstream release file", nothing
/// else. Never used for a security purpose here, the same framing core/uuid.cpp
/// gives its SHA-1 (which exists only because RFC 9562 specifies it for
/// version-5 UUIDs).
///
/// Streaming rather than whole-buffer because a corpus match needs the digest
/// of a WHOLE file, and `core::read_file_bounded` deliberately truncates: a
/// digest over a truncated prefix is a different value that would silently
/// never match. See `sha256_file_bounded` in core/file_io.hpp.
class Sha256
{
 public:
  /// Appends `bytes` to the message. Any number of calls, any sizes, including
  /// empty ones, produce the same digest as one call with the concatenation.
  void update(std::string_view bytes);

  /// The digest of everything fed so far. Finalizes a COPY of the state, so a
  /// caller may keep calling `update` afterwards and ask again.
  [[nodiscard]] Sha256Digest digest() const;

 private:
  /// H0..H7, FIPS 180-4 section 5.3.3.
  std::array<std::uint32_t, 8> state_{0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                      0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  std::array<std::uint8_t, 64> block_{};
  std::size_t buffered_bytes_ = 0;
  std::uint64_t total_bytes_ = 0;
};

/// One-shot convenience over `Sha256`, for a message already in memory.
/// Example: `to_hex(sha256(""))` ->
/// `"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`.
[[nodiscard]] Sha256Digest sha256(std::string_view bytes);

/// Lowercase hex, `kSha256HexLength` characters. Lowercase is the contract, not
/// a preference: it is what `Component::sha256` already carries, what a corpus
/// index is keyed on, and what `sha256sum` prints, so an operator can check a
/// claim by hand.
[[nodiscard]] std::string to_hex(const Sha256Digest& digest);

/// Parse a digest written as exactly `kSha256HexLength` LOWERCASE hex digits.
/// Returns nullopt for any other length, for uppercase, and for a non-hex
/// character: this reads untrusted index keys, and accepting two spellings of
/// one digest would let the same file content occupy two index entries.
[[nodiscard]] std::optional<Sha256Digest> sha256_from_hex(std::string_view lowercase_hex);

}  // namespace bomwerk::core
