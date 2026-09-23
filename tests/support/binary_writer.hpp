#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bomwerk::test
{

/// Assembles a binary file byte by byte, in a chosen endianness.
///
/// Test support for the binary pass. The readers under test must never see
/// a file produced by the host toolchain: CI runs macOS as well as Linux, and a
/// build there emits Mach-O, so a test that compiled something would assert
/// different things on the two runners. Every fixture is therefore written
/// out explicitly here: which also means a hostile case (a size field pointing
/// past the end, a stripped section table) is expressed directly rather than
/// carved out of a real binary by hand.
class BinaryWriter
{
 public:
  static constexpr std::size_t kBitsPerByte = 8;

  explicit BinaryWriter(bool big_endian = false) : big_endian_(big_endian) {}

  /// Append `value` as a `width`-byte unsigned integer in this writer's byte
  /// order.
  void put_uint(std::uint64_t value, std::size_t width)
  {
    for (std::size_t byte_index = 0; byte_index < width; ++byte_index)
    {
      const std::size_t shift = big_endian_ ? (width - 1 - byte_index) : byte_index;
      bytes_.push_back(static_cast<char>((value >> (kBitsPerByte * shift)) & 0xFFu));
    }
  }

  void put_bytes(std::string_view raw) { bytes_.append(raw); }

  /// Append `raw` and then a NUL, the way every string table stores an entry.
  void put_c_string(std::string_view raw)
  {
    bytes_.append(raw);
    bytes_.push_back('\0');
  }

  /// Append `raw`, then spaces up to `width`: the padding `ar` header fields
  /// use.
  void put_padded(std::string_view raw, std::size_t width)
  {
    const std::string_view kept = raw.substr(0, width);
    bytes_.append(kept);
    for (std::size_t index = kept.size(); index < width; ++index)
    {
      bytes_.push_back(' ');
    }
  }

  /// Zero-fill up to `offset`, so the next write lands exactly there.
  void pad_to(std::size_t offset)
  {
    while (bytes_.size() < offset)
    {
      bytes_.push_back('\0');
    }
  }

  /// Overwrite a `width`-byte integer already written at `offset`. Lets a
  /// layout that must know its own total size (a PT_LOAD covering the whole
  /// file) be back-filled instead of computed twice.
  void patch_uint(std::size_t offset, std::uint64_t value, std::size_t width)
  {
    for (std::size_t byte_index = 0; byte_index < width; ++byte_index)
    {
      const std::size_t shift = big_endian_ ? (width - 1 - byte_index) : byte_index;
      bytes_[offset + byte_index] = static_cast<char>((value >> (kBitsPerByte * shift)) & 0xFFu);
    }
  }

  [[nodiscard]] std::size_t size() const { return bytes_.size(); }
  [[nodiscard]] const std::string& bytes() const { return bytes_; }

 private:
  std::string bytes_;
  bool big_endian_ = false;
};

}  // namespace bomwerk::test
