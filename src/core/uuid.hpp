#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace bomwerk::core
{

/// A 128-bit UUID, printable in canonical `8-4-4-4-12` lowercase-hex form.
class Uuid
{
 public:
  Uuid() = default;
  explicit Uuid(std::array<std::uint8_t, 16> bytes) : bytes_(bytes) {}

  [[nodiscard]] const std::array<std::uint8_t, 16>& bytes() const { return bytes_; }

  /// Canonical lowercase form, e.g. "3e671687-395b-41f5-a30f-a58921a69b79".
  [[nodiscard]] std::string to_string() const;

 private:
  std::array<std::uint8_t, 16> bytes_{};
};

/// Deterministic name-based UUID: UUID version 5 per RFC 9562 §5.5 (May
/// 2024; obsoletes RFC 4122, but the version-5 algorithm itself: namespace
/// + name hashed with SHA-1: is unchanged between the two). The same
/// `namespace_id` and `name` always produce the same UUID: the mechanism
/// behind rule 3's "IDs = UUIDv5(purl)". SHA-1 is used only because the spec
/// requires it for version-5 UUIDs; never used for security purposes here.
/// NOTE for future maintainers: if a newer RFC ever supersedes 9562, check
/// whether it changes the v5 algorithm before assuming this citation (or the
/// implementation) still applies as-is.
[[nodiscard]] Uuid uuidv5(const Uuid& namespace_id, std::string_view name);

/// bomwerk's fixed namespace UUID for deriving component identifiers from
/// purls: `uuidv5(NAMESPACE_DNS, "bomwerk.dev")` (RFC 9562 §6.1's
/// recommended way to mint a private namespace: the same recommendation RFC
/// 4122 Appendix C made; NAMESPACE_DNS is the standard
/// `6ba7b810-9dad-11d1-80b4-00c04fd430c8`). Fixed forever: changing it
/// would change every bom-ref bomwerk has ever emitted.
[[nodiscard]] const Uuid& purl_namespace();

}  // namespace bomwerk::core
