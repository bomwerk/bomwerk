#pragma once
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

#include "binscan/bounds.hpp"
#include "core/result.hpp"

namespace bomwerk::binscan
{

/// What kind of ELF an artifact turned out to be: or that it was not one.
///
/// The rungs are separated because they answer the operator's question
/// differently, and collapsing them would turn "this product has no dynamic
/// dependencies" into "bomwerk found no dynamic dependencies", which are not
/// the same claim. A `StaticExecutable` genuinely declares none; a
/// `Relocatable` cannot declare any; only a `Dynamic` image that lists none
/// is surprising.
///
/// `Malformed` exists so that distinction survives a file bomwerk could not
/// read: an image whose section table is declared but lies wholly outside the
/// file, or whose class/encoding byte is not one ELF defines, must NOT come
/// back as `StaticExecutable`: that is a positive claim about the product,
/// and bomwerk has not earned it. Every file carrying ELF magic lands in
/// exactly one of these, so a caller's per-shape counters always reconcile
/// with its total.
enum class ElfShape
{
  NotElf,            ///< Mach-O, PE, `ar`, a script, garbage, or too small
  Malformed,         ///< ELF magic, but the structure contradicts itself; see below
  Relocatable,       ///< ET_REL: a `.o`; carries no dynamic section by construction
  StaticExecutable,  ///< ET_EXEC/ET_DYN with no dynamic section at all
  Dynamic            ///< carries a dynamic section
};

/// Protocol token for a shape, as written to the sidecar. Same shape as
/// `core::to_string(Scope)`: these are wire strings, never user-facing text,
/// and are never localized.
constexpr const char* to_string(ElfShape shape)
{
  switch (shape)
  {
    case ElfShape::NotElf:
      return "not-elf";
    case ElfShape::Malformed:
      return "malformed";
    case ElfShape::Relocatable:
      return "relocatable";
    case ElfShape::StaticExecutable:
      return "static";
    case ElfShape::Dynamic:
      return "dynamic";
  }
  return "not-elf";  // unreachable: all enumerators handled above
}

/// Everything one ELF file tells bomwerk about its dependencies.
struct ElfImage
{
  ElfShape shape = ElfShape::NotElf;
  std::string soname;                         ///< DT_SONAME; empty when absent
  std::vector<std::string> needed;            ///< DT_NEEDED, sorted, deduplicated
  std::vector<std::string> exported_symbols;  ///< .dynsym defined+global, sorted, deduplicated
  bool needed_truncated = false;              ///< hit kMaxNeededEntries or kMaxDynamicEntries
  bool symbols_truncated = false;             ///< hit kMaxSymbolSample
  bool symbols_unavailable = false;           ///< section headers stripped; see `read_elf`
  /// A dynamic section was found but its string table could not be resolved,
  /// so `needed` and `soname` being empty is NOT a claim that the image
  /// declares nothing: it is an admission that bomwerk could not read what it
  /// declares. Callers must not fold this into "declares no library".
  bool names_unavailable = false;
};

/// Read one ELF file's dynamic dependencies, soname and exported-symbol
/// sample.
///
/// Never throws and never indexes unchecked: every field goes through
/// `ByteCursor`, so a hostile header can only cost this function a warning
/// (rule 1). A file that is simply not an ELF returns `NotElf` WITHOUT a
/// warning: a Mach-O output on a macOS build is a fact about the platform,
/// which the caller aggregates into one line rather than one per artifact.
/// A file that IS an ELF but contradicts itself does warn.
///
/// Two ways in, in this order:
///
///   1. SECTION HEADERS. `SHT_DYNAMIC` and `SHT_DYNSYM` carry file offsets
///      and sizes directly, and `sh_link` names their string tables, so no
///      address arithmetic is needed. This is the path essentially every
///      normally-linked artifact takes.
///   2. PROGRAM HEADERS. A shared object with its section headers stripped is
///      exactly the prebuilt-vendored-`.so` case this pass exists for, so the
///      fallback is not optional: `PT_DYNAMIC` locates the dynamic array, and
///      `DT_STRTAB`'s VIRTUAL ADDRESS is translated to a file offset through
///      the `PT_LOAD` segment containing it. This path recovers DT_NEEDED and
///      DT_SONAME but NOT the symbol sample: sizing `.dynsym` without a
///      section header means walking `DT_HASH`/`DT_GNU_HASH` bucket chains,
///      which is a large amount of hostile-input surface for a sample that is
///      an optimization for a later task. That case sets
///      `symbols_unavailable` and warns rather than silently reporting a
///      library with no exports.
[[nodiscard]] core::Result<ElfImage> read_elf(const std::filesystem::path& path);

}  // namespace bomwerk::binscan
