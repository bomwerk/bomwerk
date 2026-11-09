// Shared pieces of the libFuzzer harnesses in tests/fuzz/ (T40).
//
// Each fuzz_<parser>.cpp defines `LLVMFuzzerTestOneInput`, hands the input
// bytes to one parser's in-memory entry point, and checks the invariants that
// parser documents. A violated invariant calls `std::abort()`, which libFuzzer
// reports exactly like a crash, so "zero crashes" also means "zero broken
// promises". The same sources build two ways (see CMakeLists.txt):
//
//   - with -DBOMWERK_FUZZ=ON (LLVM Clang): a libFuzzer binary, for campaigns;
//   - otherwise: linked with replay_main.cpp, a ctest that feeds every seed
//     and hostile fixture through the harness once, so the harnesses compile
//     in every build and known-bad inputs stay fixed.
#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

#include "core/model.hpp"
#include "core/result.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);
extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv);

namespace bomwerk::fuzz
{

/// The input as text. Parsers take bytes as `std::string_view`; nothing is
/// copied.
[[nodiscard]] std::string_view as_text(const std::uint8_t* data, std::size_t size);

/// Abort with `invariant` on stderr when `condition` is false: the harness's
/// oracle. Never compiled out.
void require(bool condition, const char* invariant);

/// A producer's output keeps the purl promise: no `kPurlValidationFailed`
/// warning (it exists "so tests and fuzzers catch it") and every emitted purl
/// parses back.
void require_valid_purls(const core::Result<std::vector<core::Component>>& result);

/// `text` split at its first newline, without the newline: harnesses that
/// need two inputs (a base and a relative url, a table and a text) read them
/// from one buffer this way.
/// Example: `split_at_first_newline("a\nb\nc")` -> `{"a", "b\nc"}`.
[[nodiscard]] std::pair<std::string_view, std::string_view> split_at_first_newline(
    std::string_view text);

/// True when `values` is sorted ascending with no repeats: the order several
/// readers promise for their output lists.
template <typename Value>
[[nodiscard]] bool sorted_and_unique(const std::vector<Value>& values)
{
  for (std::size_t index = 1; index < values.size(); ++index)
  {
    if (!(values[index - 1] < values[index]))
    {
      return false;
    }
  }
  return true;
}

}  // namespace bomwerk::fuzz
