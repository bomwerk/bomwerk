#include "heuristics/vendor_root.hpp"

#include <cstddef>
#include <iterator>
#include <string>
#include <string_view>

#include "core/text.hpp"

namespace fs = std::filesystem;

namespace bomwerk::heuristics
{
namespace
{

// Directory names that mark the start of vendored third-party code. A library
// is the immediate subfolder of one of these, which is what `vendor_root_for`
// returns. Lowercase here; a directory matches when its whole name equals one
// of these ignoring ASCII case (`ThirdParty`, `External`), never as a
// substring. `3rdparty` is OpenCV's and nextcloud's layout, `ThirdParty` is
// VTK's and ParaView's.
constexpr std::string_view kTriggerDirNames[] = {"third_party", "thirdparty", "third-party",
                                                 "3rdparty",    "vendor",     "external",
                                                 "extern",      "deps",       "libs"};

// Directory names that hold several libraries side by side rather than being
// one (`3rdparty/include/vulkan`, `3rdparty/include/opencl` in OpenCV). They
// never start a vendor root on their own, so a project's own `include/` is
// untouched; they are only looked through when they sit right after a trigger,
// the same way a trigger name in that position is.
constexpr std::string_view kChainContainerDirNames[] = {"include"};

bool is_one_of_ignoring_case(const std::string& name, const auto& lowercase_candidates)
{
  const std::string lowered = core::to_lower_ascii(name);
  for (std::string_view candidate : lowercase_candidates)
  {
    if (lowered == candidate)
    {
      return true;
    }
  }
  return false;
}

bool is_trigger_dir_name(const std::string& name)
{
  return is_one_of_ignoring_case(name, kTriggerDirNames);
}

/// True for a component that continues a trigger chain: another trigger name,
/// or a container such as `include` that groups libraries.
bool continues_trigger_chain(const std::string& name)
{
  return is_trigger_dir_name(name) || is_one_of_ignoring_case(name, kChainContainerDirNames);
}

// A trigger below one of these directories describes test data rather than a
// dependency shipped by the product. Keep this deliberately narrow and
// structural: broad substring matching ("test-*", for example) would turn
// ordinary project names into exclusions.
constexpr std::string_view kTestOrFixtureDirNames[] = {
    "test", "tests", "testdata", "fixture", "fixtures", "__tests__", "__fixtures__"};

bool is_test_or_fixture_dir_name(const std::string& name)
{
  const std::string_view name_view(name);
  for (std::string_view candidate : kTestOrFixtureDirNames)
  {
    if (name_view == candidate)
    {
      return true;
    }
  }
  return false;
}

bool is_ascii_alpha(char character)
{
  return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z');
}

bool is_ascii_alphanumeric(char character)
{
  return is_ascii_alpha(character) || (character >= '0' && character <= '9');
}

/// True for DNS-style namespace containers used by ecosystem-native vendor
/// layouts (`github.com`, `k8s.io`, `gopkg.in`, ...). Requiring an
/// alphabetic final label keeps versioned library folders such as
/// `zlib-1.2.13` out of this category even though they also contain dots.
bool is_dns_namespace_container_name(const std::string& name)
{
  if (name.find('.') == std::string::npos)
  {
    return false;
  }

  std::size_t label_start = 0;
  while (label_start < name.size())
  {
    const std::size_t dot = name.find('.', label_start);
    const std::size_t label_end = (dot == std::string::npos) ? name.size() : dot;
    if (label_end == label_start || !is_ascii_alphanumeric(name[label_start]) ||
        !is_ascii_alphanumeric(name[label_end - 1]))
    {
      return false;
    }
    for (std::size_t position = label_start; position < label_end; ++position)
    {
      const char character = name[position];
      if (!is_ascii_alphanumeric(character) && character != '-')
      {
        return false;
      }
    }
    if (dot == std::string::npos)
    {
      const std::size_t final_label_length = label_end - label_start;
      if (final_label_length < 2u)
      {
        return false;
      }
      for (std::size_t position = label_start; position < label_end; ++position)
      {
        if (!is_ascii_alpha(name[position]))
        {
          return false;
        }
      }
      return true;
    }
    label_start = dot + 1;
  }
  return false;
}

}  // namespace

std::optional<fs::path> vendor_root_for(const fs::path& relative_path)
{
  fs::path accumulated;
  bool below_test_or_fixture_directory = false;
  for (auto component = relative_path.begin(); component != relative_path.end(); ++component)
  {
    const auto next = std::next(component);
    if (next == relative_path.end())
    {
      break;  // `component` is the filename itself; nothing left to trigger on
    }
    if (is_trigger_dir_name(component->string()))
    {
      if (below_test_or_fixture_directory)
      {
        return std::nullopt;
      }
      fs::path trigger_chain = accumulated / *component;
      auto subfolder = next;
      while (continues_trigger_chain(subfolder->string()))
      {
        const auto after_subfolder = std::next(subfolder);
        if (after_subfolder == relative_path.end())
        {
          return std::nullopt;  // file sits directly in the trigger chain, no subfolder
        }
        trigger_chain /= *subfolder;
        subfolder = after_subfolder;
      }
      const auto after_subfolder = std::next(subfolder);
      if (after_subfolder == relative_path.end())
      {
        return std::nullopt;  // file sits directly in the trigger dir, no subfolder
      }
      if (is_dns_namespace_container_name(subfolder->string()))
      {
        return std::nullopt;  // a namespace container is never a library
      }
      return trigger_chain / *subfolder;
    }
    below_test_or_fixture_directory =
        below_test_or_fixture_directory || is_test_or_fixture_dir_name(component->string());
    accumulated /= *component;
  }
  return std::nullopt;
}

}  // namespace bomwerk::heuristics
