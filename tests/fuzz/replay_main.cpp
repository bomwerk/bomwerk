// Stand-in `main` for a fuzz harness built without libFuzzer: feeds every
// matching file once through `LLVMFuzzerTestOneInput`. Each harness is
// registered as the ctest `<target>_seeds` this way, so a normal GCC or
// AppleClang build compiles every harness and replays every seed, hostile
// fixture and recorded crash under ASan and UBSan.
//
// Usage: <harness> [--suffix S]... PATH...
//   PATH is a file or a directory (walked recursively, in sorted order).
//   With one or more --suffix, only files whose name ends in one of them are
//   replayed. README.md and SOURCES.md are always skipped.
// Exits 1 when a PATH does not exist or nothing matched: a seed list that
// replays nothing is a broken seed list, not a passing test.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#include "fuzz/fuzz_support.hpp"

namespace fs = std::filesystem;

namespace
{

bool wanted(const fs::path& path, const std::vector<std::string>& suffixes)
{
  const std::string name = path.filename().string();
  if (name == "README.md" || name == "SOURCES.md")
  {
    return false;
  }
  if (suffixes.empty())
  {
    return true;
  }
  return std::any_of(suffixes.begin(), suffixes.end(),
                     [&name](const std::string& suffix) { return name.ends_with(suffix); });
}

}  // namespace

int main(int argc, char** argv)
{
  std::vector<std::string> suffixes;
  std::vector<fs::path> roots;
  for (int index = 1; index < argc; ++index)
  {
    const std::string_view argument(argv[index]);
    if (argument == "--suffix" && index + 1 < argc)
    {
      suffixes.emplace_back(argv[++index]);
    }
    else
    {
      roots.emplace_back(argument);
    }
  }

  std::vector<fs::path> inputs;
  for (const fs::path& root : roots)
  {
    std::error_code error;
    if (fs::is_regular_file(root, error))
    {
      if (wanted(root, suffixes))
      {
        inputs.push_back(root);
      }
      continue;
    }
    if (!fs::is_directory(root, error))
    {
      std::fprintf(stderr, "replay: no such file or directory: %s\n", root.string().c_str());
      return 1;
    }
    for (const fs::directory_entry& entry : fs::recursive_directory_iterator(root))
    {
      if (entry.is_regular_file() && wanted(entry.path(), suffixes))
      {
        inputs.push_back(entry.path());
      }
    }
  }
  std::sort(inputs.begin(), inputs.end());

  LLVMFuzzerInitialize(&argc, &argv);
  for (const fs::path& input : inputs)
  {
    std::ifstream stream(input, std::ios::binary);
    const std::string bytes((std::istreambuf_iterator<char>(stream)),
                            std::istreambuf_iterator<char>());
    LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
  }
  std::printf("replayed %zu inputs\n", inputs.size());
  return inputs.empty() ? 1 : 0;
}
