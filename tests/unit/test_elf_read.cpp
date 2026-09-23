// ctest unit test for the ELF reader (binscan/elf_read.hpp):
// bytes -> shape, DT_NEEDED, DT_SONAME, exported-symbol sample.
//
// No case here parses a real build product, and that is deliberate rather
// than convenient: CI runs macOS as well as Linux, where a build emits Mach-O,
// so a test that compiled something would assert different things on the two
// runners. Every image is written out byte by byte by tests/support/
// elf_builder.hpp, which also lets the hostile cases -- a stripped section
// table, a size field past EOF, a DT_STRTAB pointing nowhere -- be expressed
// directly instead of carved out of a real binary by hand.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "binscan/elf_read.hpp"
#include "core/result.hpp"
#include "support/check.hpp"
#include "support/elf_builder.hpp"
#include "support/temp_tree.hpp"

using bomwerk::binscan::ElfImage;
using bomwerk::binscan::ElfShape;
using bomwerk::binscan::read_elf;
using bomwerk::core::Result;
using bomwerk::test::build_elf;
using bomwerk::test::ElfBuildOptions;
using bomwerk::test::TempTree;

namespace
{

constexpr std::uint16_t kTypeRelocatable = 1;
constexpr std::uint16_t kTypeExecutable = 2;

/// Write `bytes` into `tree` under `name` and read them back through the real
/// entry point, so every case also exercises the bounded file read.
Result<ElfImage> read_image(const TempTree& tree, const std::string& name, const std::string& bytes)
{
  tree.write(name, bytes);
  return read_elf(tree.root() / name);
}

bool contains(const std::vector<std::string>& values, const std::string& wanted)
{
  return std::find(values.begin(), values.end(), wanted) != values.end();
}

}  // namespace

int main()
{
  TempTree tree;

  // Given a normal 64-bit shared object, when read, then its dynamic
  // dependencies, soname and exported symbols all come back -- and its
  // IMPORTS do not. What a fingerprint matcher keys on is what a library
  // provides, so an undefined symbol in the sample would be noise at best and
  // a false match at worst.
  {
    ElfBuildOptions options;
    options.needed = {"libc.so.6", "libz.so.1"};
    options.soname = "libvendcrypto.so.1";
    options.exported_symbols = {"AES_encrypt", "SHA256_Init"};
    options.undefined_symbols = {"malloc"};
    const Result<ElfImage> image = read_image(tree, "libvendcrypto.so.1", build_elf(options));

    BOMWERK_TEST_CHECK(image.value.shape == ElfShape::Dynamic);
    BOMWERK_TEST_CHECK(image.value.soname == "libvendcrypto.so.1");
    BOMWERK_TEST_CHECK(image.value.needed.size() == 2);
    BOMWERK_TEST_CHECK(contains(image.value.needed, "libc.so.6"));
    BOMWERK_TEST_CHECK(contains(image.value.needed, "libz.so.1"));
    BOMWERK_TEST_CHECK(contains(image.value.exported_symbols, "AES_encrypt"));
    BOMWERK_TEST_CHECK(contains(image.value.exported_symbols, "SHA256_Init"));
    BOMWERK_TEST_CHECK(!contains(image.value.exported_symbols, "malloc"));
    BOMWERK_TEST_CHECK(image.warnings.empty());
  }

  // Given the SAME content as a 32-bit image, when read, then the answer is
  // identical. `Elf32_Sym` and `Elf64_Sym` do not merely widen their fields,
  // they reorder them -- (name, value, size, info, other, shndx) against
  // (name, info, other, shndx, value, size) -- and decoding one as the other
  // yields plausible-looking names attached to the wrong bindings rather than
  // an obvious failure. Asserting the same symbol set on both classes is what
  // catches that.
  {
    ElfBuildOptions options;
    options.is_64_bit = false;
    options.needed = {"libc.so.6"};
    options.exported_symbols = {"AES_encrypt", "SHA256_Init"};
    options.undefined_symbols = {"malloc"};
    const Result<ElfImage> image = read_image(tree, "elf32.so", build_elf(options));

    BOMWERK_TEST_CHECK(image.value.shape == ElfShape::Dynamic);
    BOMWERK_TEST_CHECK(contains(image.value.needed, "libc.so.6"));
    BOMWERK_TEST_CHECK(image.value.exported_symbols.size() == 2);
    BOMWERK_TEST_CHECK(contains(image.value.exported_symbols, "AES_encrypt"));
    BOMWERK_TEST_CHECK(contains(image.value.exported_symbols, "SHA256_Init"));
    BOMWERK_TEST_CHECK(!contains(image.value.exported_symbols, "malloc"));
  }

  // Given a big-endian image, when read, then it reads the same. A
  // cross-compiled firmware artifact is routinely the opposite endianness of
  // the machine scanning it, so the order is taken from EI_DATA and never
  // from the host.
  {
    ElfBuildOptions options;
    options.big_endian = true;
    options.needed = {"libc.so.6"};
    options.exported_symbols = {"firmware_entry"};
    const Result<ElfImage> image = read_image(tree, "bigendian.so", build_elf(options));

    BOMWERK_TEST_CHECK(image.value.shape == ElfShape::Dynamic);
    BOMWERK_TEST_CHECK(contains(image.value.needed, "libc.so.6"));
    BOMWERK_TEST_CHECK(contains(image.value.exported_symbols, "firmware_entry"));
  }

  // Given a 32-bit BIG-endian image, when read, then both class and order are
  // applied together. The two knobs are independent in the format and are
  // therefore crossed here rather than tested one at a time.
  {
    ElfBuildOptions options;
    options.is_64_bit = false;
    options.big_endian = true;
    options.needed = {"libm.so.6"};
    const Result<ElfImage> image = read_image(tree, "elf32be.so", build_elf(options));
    BOMWERK_TEST_CHECK(contains(image.value.needed, "libm.so.6"));
  }

  // Given a STATICALLY LINKED executable, when read, then the shape says so
  // and nothing is invented. This is the case the whole diagnostics design
  // turns on: such a product genuinely HAS no dynamic dependencies, which is
  // a different statement from bomwerk failing to find any, and only the
  // shape carries that difference. (The operator-facing warning is raised
  // once per run by binscan::map_binaries_to_roots, not once per file here --
  // see test_binary_map.)
  {
    ElfBuildOptions options;
    options.file_type = kTypeExecutable;
    options.include_dynamic = false;
    const Result<ElfImage> image = read_image(tree, "static-app", build_elf(options));

    BOMWERK_TEST_CHECK(image.value.shape == ElfShape::StaticExecutable);
    BOMWERK_TEST_CHECK(image.value.needed.empty());
    BOMWERK_TEST_CHECK(image.value.soname.empty());
  }

  // Given a relocatable object, when read, then it is reported as such and no
  // dynamic section is looked for -- a `.o` cannot declare dependencies by
  // construction, so this is the wrong question rather than a failed answer.
  {
    ElfBuildOptions options;
    options.file_type = kTypeRelocatable;
    options.include_dynamic = false;
    const Result<ElfImage> image = read_image(tree, "adler32.o", build_elf(options));

    BOMWERK_TEST_CHECK(image.value.shape == ElfShape::Relocatable);
    BOMWERK_TEST_CHECK(image.value.needed.empty());
  }

  // Given a dynamic image that names no library at all (a -nostdlib build),
  // when read, then the shape is Dynamic with an empty NEEDED list -- again a
  // real answer, distinguishable downstream from a static binary and from a
  // failed read.
  {
    ElfBuildOptions options;
    options.needed = {};
    options.soname = "libfreestanding.so.0";
    const Result<ElfImage> image = read_image(tree, "freestanding.so", build_elf(options));

    BOMWERK_TEST_CHECK(image.value.shape == ElfShape::Dynamic);
    BOMWERK_TEST_CHECK(image.value.needed.empty());
    BOMWERK_TEST_CHECK(image.value.soname == "libfreestanding.so.0");
  }

  // Given a shared object with its SECTION HEADERS STRIPPED, when read, then
  // the dependencies still come back through PT_DYNAMIC, the symbol sample
  // does not, and the run says so. This is exactly the prebuilt-vendored-.so
  // case the pass exists for, so the fallback is load-bearing, not a nicety.
  {
    ElfBuildOptions options;
    options.include_section_headers = false;
    options.include_program_headers = true;
    options.needed = {"libssl.so.3"};
    options.soname = "libvendored.so.2";
    options.exported_symbols = {"vendored_init"};
    const Result<ElfImage> image = read_image(tree, "stripped.so", build_elf(options));

    BOMWERK_TEST_CHECK(image.value.shape == ElfShape::Dynamic);
    BOMWERK_TEST_CHECK(contains(image.value.needed, "libssl.so.3"));
    BOMWERK_TEST_CHECK(image.value.soname == "libvendored.so.2");
    BOMWERK_TEST_CHECK(image.value.exported_symbols.empty());
    BOMWERK_TEST_CHECK(image.value.symbols_unavailable);
    BOMWERK_TEST_CHECK(!image.warnings.empty());
  }

  // Given a stripped image whose PT_LOAD does not cover DT_STRTAB, when read,
  // then no library names are recovered and the run warns -- the address
  // translation refuses rather than reading from wherever the number happened
  // to land.
  {
    ElfBuildOptions options;
    options.include_section_headers = false;
    options.include_program_headers = true;
    options.needed = {"libssl.so.3"};
    std::string bytes = build_elf(options);
    // Shrink the PT_LOAD segment to nothing. It is the first program header,
    // whose p_filesz sits at byte 32 of a 64-bit entry, and the entries begin
    // right after the 64-byte ELF header.
    constexpr std::size_t kFirstSegmentFileSizeOffset = 64 + 32;
    for (std::size_t index = 0; index < 8; ++index)
    {
      bytes[kFirstSegmentFileSizeOffset + index] = '\0';
    }
    const Result<ElfImage> image = read_image(tree, "unmapped-strtab.so", bytes);

    BOMWERK_TEST_CHECK(image.value.shape == ElfShape::Dynamic);
    BOMWERK_TEST_CHECK(image.value.needed.empty());
    // The empty list is an admission, not a claim: the caller must not fold it
    // into "this image declares no library".
    BOMWERK_TEST_CHECK(image.value.names_unavailable);
    BOMWERK_TEST_CHECK(!image.warnings.empty());
  }

  // Given an image whose section table claims to start past the end of the
  // file, when read, then it is MALFORMED and says so -- not
  // `StaticExecutable`. That distinction is the whole point: "statically
  // linked" is a positive claim about the product, and a file bomwerk never
  // managed to parse has not earned it. A header pointing outside the file is
  // the canonical hostile shape, and the answer must be a degraded record
  // (rule 1), never a fault.
  {
    ElfBuildOptions options;
    options.needed = {"libc.so.6"};
    std::string bytes = build_elf(options);
    constexpr std::size_t kSectionTableOffsetField = 40;  // e_shoff, 64-bit
    for (std::size_t index = 0; index < 8; ++index)
    {
      bytes[kSectionTableOffsetField + index] = index < 4 ? '\xFF' : '\x7F';
    }
    const Result<ElfImage> image = read_image(tree, "bogus-shoff.so", bytes);

    BOMWERK_TEST_CHECK(image.value.shape == ElfShape::Malformed);
    BOMWERK_TEST_CHECK(image.value.needed.empty());
    BOMWERK_TEST_CHECK(!image.warnings.empty());
  }

  // Given a TRUNCATED ELF, when read, then it is malformed and warns, rather
  // than being reported as a product that declares nothing.
  {
    ElfBuildOptions options;
    options.needed = {"libc.so.6"};
    const std::string full = build_elf(options);
    const Result<ElfImage> image = read_image(tree, "cut.so", full.substr(0, 40));

    BOMWERK_TEST_CHECK(image.value.shape == ElfShape::Malformed);
    BOMWERK_TEST_CHECK(image.value.needed.empty());
    BOMWERK_TEST_CHECK(!image.warnings.empty());
  }

  // Given files that are not ELF at all, when read, then they are reported as
  // such WITHOUT a warning: a Mach-O output on a macOS build is a fact about
  // the platform, aggregated by the caller into one line, not one warning per
  // artifact.
  {
    const Result<ElfImage> empty_file = read_image(tree, "empty.bin", "");
    BOMWERK_TEST_CHECK(empty_file.value.shape == ElfShape::NotElf);
    BOMWERK_TEST_CHECK(empty_file.warnings.empty());

    const Result<ElfImage> script = read_image(tree, "wrapper.sh", "#!/bin/sh\nexec cc \"$@\"\n");
    BOMWERK_TEST_CHECK(script.value.shape == ElfShape::NotElf);
    BOMWERK_TEST_CHECK(script.warnings.empty());

    const Result<ElfImage> mach_o =
        read_image(tree, "app.macho", std::string("\xCF\xFA\xED\xFE", 4));
    BOMWERK_TEST_CHECK(mach_o.value.shape == ElfShape::NotElf);
    BOMWERK_TEST_CHECK(mach_o.warnings.empty());
  }

  // Given ELF magic followed by a class byte no ELF defines, when read, then
  // it IS warned about -- unlike the cases above, this file claims to be an
  // ELF and then contradicts itself, which is worth an operator's attention.
  {
    ElfBuildOptions options;
    std::string bytes = build_elf(options);
    bytes[4] = '\x09';  // EI_CLASS
    const Result<ElfImage> image = read_image(tree, "bad-class.so", bytes);

    BOMWERK_TEST_CHECK(image.value.shape == ElfShape::Malformed);
    BOMWERK_TEST_CHECK(!image.warnings.empty());
  }

  // Given a path that does not exist, when read, then it is a warning and a
  // NotElf record, never a throw -- the build tree may have been cleaned
  // between the observe run and this one.
  {
    const Result<ElfImage> image = read_elf(tree.root() / "never-written.so");
    BOMWERK_TEST_CHECK(image.value.shape == ElfShape::NotElf);
    BOMWERK_TEST_CHECK(!image.warnings.empty());
  }

  // Given one image read twice, when the results are compared, then they are
  // identical -- sorted and deduplicated, so nothing about the order sections
  // happened to be laid out in can reach the output (rule 3).
  {
    ElfBuildOptions options;
    options.needed = {"libz.so.1", "libc.so.6", "libz.so.1"};
    options.exported_symbols = {"zeta", "alpha", "middle"};
    const std::string bytes = build_elf(options);
    const Result<ElfImage> first = read_image(tree, "deterministic-a.so", bytes);
    const Result<ElfImage> second = read_image(tree, "deterministic-b.so", bytes);

    BOMWERK_TEST_CHECK(first.value.needed == second.value.needed);
    BOMWERK_TEST_CHECK(first.value.exported_symbols == second.value.exported_symbols);
    BOMWERK_TEST_CHECK(first.value.needed.size() == 2);  // the duplicate collapsed
    BOMWERK_TEST_CHECK(std::is_sorted(first.value.needed.begin(), first.value.needed.end()));
    BOMWERK_TEST_CHECK(
        std::is_sorted(first.value.exported_symbols.begin(), first.value.exported_symbols.end()));
  }

  return 0;
}
