// ctest unit test for the bounds-checked cursor (binscan/byte_cursor.hpp).
//
// Tested on its own rather than only through the ELF and ar readers, because
// this is the one type those readers TRUST: they contain no bounds arithmetic
// of their own precisely because every access goes through here. Checking its
// edges only via a format walk would leave them covered by accident -- the
// walk might simply never ask for the byte one past the end -- when the whole
// safety argument for the module rests on that ask being answered correctly.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "binscan/byte_cursor.hpp"
#include "support/check.hpp"

using bomwerk::binscan::as_image;
using bomwerk::binscan::ByteCursor;
using bomwerk::binscan::ByteOrder;
using bomwerk::binscan::IntegerWidth;

namespace
{

ByteCursor cursor_over(const std::string& bytes, ByteOrder byte_order = ByteOrder::Little)
{
  return ByteCursor(as_image(bytes), byte_order);
}

}  // namespace

int main()
{
  // Given a four-byte image, when each width is read at offset 0, then the
  // value is assembled in the cursor's own byte order -- the ELF32/ELF64 walk
  // is one code path parameterized by width, so every width must work in both
  // orders or that parameterization is a lie.
  {
    const std::string bytes("\x01\x02\x03\x04", 4);
    const ByteCursor little = cursor_over(bytes, ByteOrder::Little);
    const ByteCursor big = cursor_over(bytes, ByteOrder::Big);

    BOMWERK_TEST_CHECK(little.uint_at(0, IntegerWidth::OneByte) == 0x01u);
    BOMWERK_TEST_CHECK(little.uint_at(0, IntegerWidth::TwoBytes) == 0x0201u);
    BOMWERK_TEST_CHECK(little.uint_at(0, IntegerWidth::FourBytes) == 0x04030201u);

    BOMWERK_TEST_CHECK(big.uint_at(0, IntegerWidth::OneByte) == 0x01u);
    BOMWERK_TEST_CHECK(big.uint_at(0, IntegerWidth::TwoBytes) == 0x0102u);
    BOMWERK_TEST_CHECK(big.uint_at(0, IntegerWidth::FourBytes) == 0x01020304u);
  }

  // Given an eight-byte image, when the widest field is read, then all eight
  // bytes participate -- a 64-bit ELF offset is exactly this read, and a shift
  // that silently dropped the high word would point a section walk at the
  // wrong place rather than fail.
  {
    const std::string bytes("\x01\x00\x00\x00\x00\x00\x00\x80", 8);
    BOMWERK_TEST_CHECK(cursor_over(bytes).uint_at(0, IntegerWidth::EightBytes) ==
                       0x8000000000000001ull);
  }

  // Given a four-byte image, when a read straddles or starts past the end,
  // then it is nothing -- never a partial value, never a read of adjacent
  // memory.
  {
    const std::string bytes("\x01\x02\x03\x04", 4);
    const ByteCursor cursor = cursor_over(bytes);
    BOMWERK_TEST_CHECK(cursor.uint_at(3, IntegerWidth::OneByte).has_value());   // last byte
    BOMWERK_TEST_CHECK(!cursor.uint_at(4, IntegerWidth::OneByte).has_value());  // one past
    BOMWERK_TEST_CHECK(cursor.uint_at(0, IntegerWidth::FourBytes).has_value());
    BOMWERK_TEST_CHECK(!cursor.uint_at(1, IntegerWidth::FourBytes).has_value());
    BOMWERK_TEST_CHECK(!cursor.uint_at(0, IntegerWidth::EightBytes).has_value());
  }

  // Given an empty image, when anything at all is read, then it is nothing --
  // an empty file reaches these readers (a zero-byte build output is a real
  // shape), and every accessor must survive it.
  {
    const std::string bytes;
    const ByteCursor cursor = cursor_over(bytes);
    BOMWERK_TEST_CHECK(cursor.size() == 0);
    BOMWERK_TEST_CHECK(!cursor.uint_at(0, IntegerWidth::OneByte).has_value());
    BOMWERK_TEST_CHECK(!cursor.c_string_at(0, 16).has_value());
    BOMWERK_TEST_CHECK(!cursor.subrange(0, 1).has_value());
    BOMWERK_TEST_CHECK(cursor.subrange(0, 0).has_value());  // the empty range still fits
  }

  // Given a hostile length near SIZE_MAX, when a range is checked, then the
  // offset+length addition must not wrap into a "yes, that fits" answer. This
  // is the single most important case in the file: it is the shape a malformed
  // section header takes, and an overflowed comparison here would hand the
  // format walk a span over memory it does not own.
  {
    const std::string bytes("\x01\x02\x03\x04", 4);
    const ByteCursor cursor = cursor_over(bytes);
    constexpr std::size_t kNearlyMax = static_cast<std::size_t>(-1);
    BOMWERK_TEST_CHECK(!cursor.has_range(1, kNearlyMax));
    BOMWERK_TEST_CHECK(!cursor.has_range(kNearlyMax, 1));
    BOMWERK_TEST_CHECK(!cursor.has_range(kNearlyMax, kNearlyMax));
    BOMWERK_TEST_CHECK(!cursor.subrange(2, kNearlyMax).has_value());
  }

  // Given a string table, when an entry is read, then it stops at the NUL and
  // an entry at a later offset is reachable the way a real string-table walk
  // reaches it.
  {
    const std::string bytes = std::string("\0libc.so.6\0libm.so.6\0", 21);
    const ByteCursor cursor = cursor_over(bytes);
    BOMWERK_TEST_CHECK(cursor.c_string_at(1, 4096) == std::string_view("libc.so.6"));
    BOMWERK_TEST_CHECK(cursor.c_string_at(11, 4096) == std::string_view("libm.so.6"));
    BOMWERK_TEST_CHECK(cursor.c_string_at(0, 4096) == std::string_view(""));
  }

  // Given an UNTERMINATED run of bytes, when it is read as a string, then it
  // is nothing rather than a truncated value. Returning the fragment would put
  // attacker-chosen bytes into an SBOM as a library name, which is the one
  // outcome this module must never produce.
  {
    const std::string bytes("libc.so.6");  // no trailing NUL
    BOMWERK_TEST_CHECK(!cursor_over(bytes).c_string_at(0, 4096).has_value());
  }

  // Given a string longer than the caller's cap, when it is read, then it is
  // nothing -- the cap is a refusal, not a silent truncation, for the same
  // reason.
  {
    const std::string bytes = std::string("averylongname\0", 14);
    const ByteCursor cursor = cursor_over(bytes);
    BOMWERK_TEST_CHECK(!cursor.c_string_at(0, 4).has_value());
    BOMWERK_TEST_CHECK(cursor.c_string_at(0, 64).has_value());
  }

  // Given a subrange, when it is read, then its offsets are relative to
  // itself -- this is what lets a section walk stop carrying the enclosing
  // file's base offset through every read.
  {
    const std::string bytes("\x00\x00\x0A\x0B", 4);
    const std::optional<ByteCursor> section = cursor_over(bytes).subrange(2, 2);
    BOMWERK_TEST_CHECK(section.has_value());
    BOMWERK_TEST_CHECK(section->size() == 2);
    BOMWERK_TEST_CHECK(section->uint_at(0, IntegerWidth::OneByte) == 0x0Au);
    BOMWERK_TEST_CHECK(!section->uint_at(2, IntegerWidth::OneByte).has_value());
  }

  // Given a cursor, when its byte order is changed, then the same bytes read
  // differently -- the ELF walk needs exactly this, since e_ident announces
  // the order only after it has itself been read.
  {
    const std::string bytes("\x01\x02", 2);
    const ByteCursor little = cursor_over(bytes, ByteOrder::Little);
    const ByteCursor big = little.with_byte_order(ByteOrder::Big);
    BOMWERK_TEST_CHECK(little.uint_at(0, IntegerWidth::TwoBytes) == 0x0201u);
    BOMWERK_TEST_CHECK(big.uint_at(0, IntegerWidth::TwoBytes) == 0x0102u);
  }

  return 0;
}
