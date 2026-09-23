#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace bomwerk::binscan
{

/// Bits in a byte, named so the shift assembling a multi-byte field below
/// reads as a unit conversion rather than as a bare literal.
inline constexpr std::size_t kBitsPerByte = 8;

/// Byte order of the file being read, taken from the format's own header
/// (`EI_DATA` for ELF) rather than assumed from the host. A cross-compiled
/// firmware image is routinely the opposite endianness of the machine
/// scanning it.
enum class ByteOrder
{
  Little,
  Big
};

/// How many bytes wide one integer field is. Named rather than passed as a
/// bare literal so an ELF32/ELF64 walk reads as one code path parameterized
/// by width, not as two copies of the same arithmetic.
enum class IntegerWidth : std::size_t
{
  OneByte = 1,
  TwoBytes = 2,
  FourBytes = 4,
  EightBytes = 8
};

/// A read-only cursor over an in-memory image of an untrusted file.
///
/// This is the whole memory-safety story of `binscan`, deliberately confined
/// to one small type so it can be reviewed once and relied on above. Every
/// accessor is bounds-checked and returns `std::nullopt` past the end, so the
/// ELF and `ar` walks built on it contain no bounds arithmetic of their own :
/// there is no operation here that can index out of range, and therefore no
/// path through the format readers that can (rule 1). Nothing throws, so the
/// module needs no `try`/`catch` anywhere.
///
/// Defined entirely in the header on purpose: one call happens per field, and
/// a large binary has millions of fields, so these must inline.
class ByteCursor
{
 public:
  ByteCursor(std::span<const std::byte> bytes, ByteOrder byte_order)
      : bytes_(bytes), byte_order_(byte_order)
  {
  }

  [[nodiscard]] std::size_t size() const { return bytes_.size(); }

  [[nodiscard]] ByteOrder byte_order() const { return byte_order_; }

  /// Whether `[offset, offset + length)` lies inside the image.
  ///
  /// Written as a subtraction rather than `offset + length <= size()` because
  /// the addition overflows on a hostile header claiming a length near
  /// `SIZE_MAX`, and an overflowed comparison answers "yes, that fits".
  [[nodiscard]] bool has_range(std::size_t offset, std::size_t length) const
  {
    if (length > bytes_.size())
    {
      return false;
    }
    return offset <= bytes_.size() - length;
  }

  /// The unsigned integer of `width` bytes at `offset`, in this cursor's byte
  /// order, or nothing when the field does not fit.
  [[nodiscard]] std::optional<std::uint64_t> uint_at(std::size_t offset, IntegerWidth width) const
  {
    const std::size_t byte_count = static_cast<std::size_t>(width);
    if (!has_range(offset, byte_count))
    {
      return std::nullopt;
    }
    std::uint64_t value = 0;
    for (std::size_t byte_index = 0; byte_index < byte_count; ++byte_index)
    {
      const std::size_t source_index = byte_order_ == ByteOrder::Little
                                           ? offset + byte_index
                                           : offset + byte_count - 1 - byte_index;
      value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes_[source_index]))
               << (kBitsPerByte * byte_index);
    }
    return value;
  }

  /// The NUL-terminated string starting at `offset`, capped at `max_length`
  /// bytes, or nothing.
  ///
  /// An UNTERMINATED run is nothing, not a truncated string: a string table
  /// whose last entry runs off the end is malformed, and returning the
  /// fragment would put attacker-chosen bytes into an SBOM as a library name.
  /// The returned view points into the image and is only valid while it is.
  [[nodiscard]] std::optional<std::string_view> c_string_at(std::size_t offset,
                                                            std::size_t max_length) const
  {
    if (offset > bytes_.size())
    {
      return std::nullopt;
    }
    const std::size_t available = bytes_.size() - offset;
    const std::size_t searchable = max_length < available ? max_length : available;
    for (std::size_t length = 0; length < searchable; ++length)
    {
      if (bytes_[offset + length] == std::byte{0})
      {
        return std::string_view(reinterpret_cast<const char*>(bytes_.data()) + offset, length);
      }
    }
    return std::nullopt;
  }

  /// A cursor over `[offset, offset + length)` of this image, same byte order,
  /// or nothing when that range does not fit. Offsets inside the result are
  /// relative to it, which is what keeps a section walk from carrying the
  /// enclosing file's base offset through every read.
  [[nodiscard]] std::optional<ByteCursor> subrange(std::size_t offset, std::size_t length) const
  {
    if (!has_range(offset, length))
    {
      return std::nullopt;
    }
    return ByteCursor(bytes_.subspan(offset, length), byte_order_);
  }

  /// This image re-read in `byte_order`. The ELF walk needs it: `e_ident` is
  /// byte-order-independent and must be read before the order it announces is
  /// known.
  [[nodiscard]] ByteCursor with_byte_order(ByteOrder byte_order) const
  {
    return ByteCursor(bytes_, byte_order);
  }

 private:
  std::span<const std::byte> bytes_;
  ByteOrder byte_order_ = ByteOrder::Little;
};

/// View `bytes` as an image. `std::string` is what `core::read_file_bounded`
/// returns, and this is the one place that reinterpretation happens: taking a
/// view so a sub-range of an already-read file (an archive member, say) needs
/// no copy to be parsed in turn.
[[nodiscard]] inline std::span<const std::byte> as_image(std::string_view bytes)
{
  return std::span<const std::byte>(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
}

}  // namespace bomwerk::binscan
