#include "observe/link_map.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::observe
{

using core::contains;

namespace
{

/// Suffixes recognized without a version walk. `.so` is handled separately
/// (see `has_versioned_shared_object_extension`) because a shared object
/// routinely carries a soname version after the extension (`libz.so.1.2.3`),
/// which `.o`/`.a` never do.
constexpr std::array<std::string_view, 2> kLinkInputExtensions{".o", ".a"};

/// How many trailing numeric segments (`libz.so.1.2.3` has three) a shared
/// object's soname version may carry before bomwerk gives up looking for the
/// `.so` underneath. Real sonames are at most major.minor.patch.
constexpr std::size_t kMaxSonameVersionSegments = 3;

constexpr std::string_view kWholeArchiveOption = "--whole-archive";
constexpr std::string_view kNoWholeArchiveOption = "--no-whole-archive";
constexpr std::string_view kSearchDirectoryOption = "-L";
constexpr std::string_view kLibraryNameOption = "-l";
constexpr std::string_view kOutputOption = "-o";
constexpr std::string_view kOutputLongOption = "--output";
constexpr std::string_view kOutputLongOptionJoinedPrefix = "--output=";
/// `-oformat=binary` is `ld`'s single-dash spelling of `--oformat`, not an
/// output name. It is the one real collision with the joined `-o<value>`
/// form, so it is named and excluded rather than left to chance.
constexpr std::string_view kOutputFormatOptionPrefix = "-oformat";
constexpr std::string_view kMapOption = "-Map";
constexpr std::string_view kMapOptionJoinedPrefix = "-Map=";
constexpr std::string_view kXLinkerOption = "-Xlinker";
constexpr std::string_view kWlPrefix = "-Wl,";
constexpr char kResponseFilePrefix = '@';

/// Options that swallow the FOLLOWING argument on a link line. Without this
/// table, `-o app`'s output name, `-soname libfoo.so.1`'s soname, or
/// `-dynamic-linker /lib64/ld-linux-x86-64.so.2`'s interpreter path could
/// each be misread as a link input: the collision that matters most, since
/// a soname or an interpreter path routinely LOOKS like a versioned `.so`.
/// `-l`/`-L`/`-Map`/`--whole-archive` are handled separately and must not
/// appear here too, or their values would be consumed twice.
constexpr std::array<std::string_view, 11> kLinkOptionsConsumingNextArgument{
    "-o",     "-T",      "--script", "-soname", "-h", "--soname", "-dynamic-linker",
    "-rpath", "--rpath", "-e",       "-u"};

/// Preferred suffix order when guessing a `-lNAME` filename: `.so` before
/// `.a`, matching how a real linker prefers a shared object over a static
/// archive of the same name when both are present.
constexpr std::array<std::string_view, 2> kLibraryNameSuffixes{".so", ".a"};

bool is_all_digits(std::string_view text)
{
  return !text.empty() && std::all_of(text.begin(), text.end(), [](unsigned char character)
                                      { return character >= '0' && character <= '9'; });
}

/// Whether `candidate` is `something.so`, possibly followed by up to
/// `kMaxSonameVersionSegments` all-numeric extensions (`.so.1`, `.so.1.2.3`).
bool has_versioned_shared_object_extension(fs::path candidate)
{
  for (std::size_t stripped_segments = 0; stripped_segments <= kMaxSonameVersionSegments;
       ++stripped_segments)
  {
    const std::string extension = core::to_lower_ascii(candidate.extension().string());
    if (extension == ".so")
    {
      return true;
    }
    if (extension.size() <= 1 || !is_all_digits(extension.substr(1)))
    {
      return false;
    }
    candidate = candidate.stem();
  }
  return false;
}

/// Whether `argument` names a link input by suffix: `.o`, `.a`, or a `.so`
/// (optionally versioned).
bool has_link_input_extension(std::string_view argument)
{
  const fs::path path(argument);
  const std::string extension = core::to_lower_ascii(path.extension().string());
  if (contains(kLinkInputExtensions, extension))
  {
    return true;
  }
  return has_versioned_shared_object_extension(path);
}

/// The `-Map` value `token` carries, or nothing. Recognizes both the joined
/// form (`-Map=out.map`) and the separated one (`-Map out.map`: including
/// the shape `-Wl,-Map,out.map` reduces to after flattening). `consumed_next`
/// is set only when the value came from `next_token`, and only when there
/// was one to consume: a trailing bare `-Map` with nothing after it is left
/// for the generic "unrecognized flag" path rather than treated as a match
/// with an empty value.
std::optional<std::string> map_file_value(std::string_view token, std::string_view next_token,
                                          bool& consumed_next)
{
  consumed_next = false;
  if (token.starts_with(kMapOptionJoinedPrefix))
  {
    return std::string(token.substr(kMapOptionJoinedPrefix.size()));
  }
  if (token == kMapOption && !next_token.empty())
  {
    consumed_next = true;
    return std::string(next_token);
  }
  return std::nullopt;
}

/// The output name `token` carries, or nothing. All four spellings a real
/// build system emits are understood: separated (`-o app`, `--output app`),
/// joined (`-oapp`, `--output=app`).
///
/// `consumed_next` follows `map_file_value`'s convention exactly: set only
/// when the value came from `next_token`, and only when there was one, so a
/// trailing bare `-o` falls through to the generic
/// `kLinkOptionsConsumingNextArgument` path instead of recording an empty
/// output.
std::optional<std::string> output_path_value(std::string_view token, std::string_view next_token,
                                             bool& consumed_next)
{
  consumed_next = false;
  if (token.starts_with(kOutputLongOptionJoinedPrefix))
  {
    return std::string(token.substr(kOutputLongOptionJoinedPrefix.size()));
  }
  if ((token == kOutputOption || token == kOutputLongOption) && !next_token.empty())
  {
    consumed_next = true;
    return std::string(next_token);
  }
  if (token.size() > kOutputOption.size() && token.starts_with(kOutputOption) &&
      !token.starts_with(kOutputFormatOptionPrefix))
  {
    return std::string(token.substr(kOutputOption.size()));
  }
  return std::nullopt;
}

/// The `-L` value `token` carries, or nothing. Separated (`-L dir`) and
/// joined (`-Ldir`) spellings both understood, mirroring
/// `compile_map.cpp`'s `include_path_value`.
std::string_view search_directory_value(std::string_view token, std::string_view next_token,
                                        bool& consumed_next)
{
  consumed_next = false;
  if (token == kSearchDirectoryOption)
  {
    consumed_next = true;
    return next_token;
  }
  if (token.size() > kSearchDirectoryOption.size() && token.starts_with(kSearchDirectoryOption))
  {
    return token.substr(kSearchDirectoryOption.size());
  }
  return {};
}

/// The `-l` value `token` carries, or nothing. Separated (`-l name`) and
/// joined (`-lname`) spellings both understood, mirroring
/// `compile_map.cpp`'s `include_path_value`.
std::string_view library_name_value(std::string_view token, std::string_view next_token,
                                    bool& consumed_next)
{
  consumed_next = false;
  if (token == kLibraryNameOption)
  {
    consumed_next = true;
    return next_token;
  }
  if (token.size() > kLibraryNameOption.size() && token.starts_with(kLibraryNameOption))
  {
    return token.substr(kLibraryNameOption.size());
  }
  return {};
}

/// `libNAME.so`/`libNAME.a` found under one of `search_directories`, `.so`
/// preferred, or nothing when neither exists anywhere searched. Existence is
/// checked here: unlike a direct `.o`/`.a`/`.so` argument, this path is a
/// GUESS bomwerk constructs, and an unverified guess would be invented
/// evidence, not a fact the trace actually carries. GNU ld applies every
/// `-L` to every `-l` on a line regardless of which came first, so the
/// search does the same.
std::optional<fs::path> resolve_library_name(std::string_view name,
                                             const std::vector<fs::path>& search_directories)
{
  for (const fs::path& directory : search_directories)
  {
    for (const std::string_view suffix : kLibraryNameSuffixes)
    {
      const fs::path candidate = directory / ("lib" + std::string(name) + std::string(suffix));
      std::error_code exists_error;
      if (fs::exists(candidate, exists_error) && !exists_error)
      {
        return candidate;
      }
    }
  }
  return std::nullopt;
}

/// The tool name an archive invocation carries. `ar` is neither
/// `is_compiler_tool_name` nor `kBareLinkerToolName`, so it falls through both
/// existing scans untouched and needs naming here.
constexpr std::string_view kArchiveToolName = "ar";

/// Every key letter and modifier GNU `ar` accepts in its bundled first
/// operand. A character outside this set means bomwerk is not looking at an
/// operand bundle it understands, and the safe answer is then to report no
/// archive rather than to keep counting operands from the wrong place.
constexpr std::string_view kArchiveKeyLetters = "dmpqrstxMabcDfilNoPsSTuUvV";

/// Key letters that pull an operand AHEAD of the archive name: `a`/`b`/`i`
/// each take a relative-position member, `N` takes an occurrence count.
constexpr std::string_view kArchiveKeysTakingOperand = "abiN";

/// MRI script mode reads its commands from stdin and names no archive on the
/// command line at all.
constexpr char kArchiveScriptModeKey = 'M';

/// `ar` long options that swallow the following argument. `--plugin` is not
/// exotic: every GCC LTO build emits `ar --plugin <path> qc lib.a ...`, and a
/// walk that missed it would read the plugin path as the operand bundle.
constexpr std::array<std::string_view, 2> kArchiveOptionsConsumingNextArgument{"--plugin",
                                                                               "--target"};

/// Whether `argument` names an archive or a shared object: the two shapes the
/// binary pass can read something out of. A `.o` is deliberately excluded: a
/// relocatable object has no dynamic section and no members, so opening one
/// would cost a file read to learn nothing.
bool is_archive_or_shared_object(std::string_view argument)
{
  const fs::path path(argument);
  if (core::to_lower_ascii(path.extension().string()) == ".a")
  {
    return true;
  }
  return has_versioned_shared_object_extension(path);
}

/// Resolve `absolute_input` against `canonical_root` and, if it lands under
/// one of `component_roots`, record it there. Mirrors `map_compiles_to_roots`'
/// own per-source attribution.
void attribute_link_input(const fs::path& absolute_input, const fs::path& canonical_root,
                          const std::set<fs::path>& component_roots,
                          std::map<fs::path, std::set<fs::path>>& linked_inputs_by_root)
{
  const std::optional<fs::path> relative_input = to_root_relative(absolute_input, canonical_root);
  if (!relative_input.has_value())
  {
    return;
  }
  const fs::path* root = enclosing_root(relative_input->parent_path(), component_roots);
  if (root != nullptr)
  {
    linked_inputs_by_root[*root].insert(*relative_input);
  }
}

}  // namespace

std::vector<std::string> flatten_linker_tokens(const TraceRecord& record)
{
  std::vector<std::string> tokens;
  // argv[0] is the tool itself, never an input.
  for (std::size_t argument_index = 1; argument_index < record.arguments.size(); ++argument_index)
  {
    const std::string& argument = record.arguments[argument_index];
    if (argument == kXLinkerOption)
    {
      if (argument_index + 1 < record.arguments.size())
      {
        tokens.push_back(record.arguments[argument_index + 1]);
        ++argument_index;
      }
      continue;
    }
    if (argument.starts_with(kWlPrefix))
    {
      std::string_view remainder(argument);
      remainder.remove_prefix(kWlPrefix.size());
      std::size_t segment_start = 0;
      while (segment_start <= remainder.size())
      {
        const std::size_t comma_position = remainder.find(',', segment_start);
        const std::string_view segment =
            comma_position == std::string_view::npos
                ? remainder.substr(segment_start)
                : remainder.substr(segment_start, comma_position - segment_start);
        if (!segment.empty())
        {
          tokens.emplace_back(segment);
        }
        if (comma_position == std::string_view::npos)
        {
          break;
        }
        segment_start = comma_position + 1;
      }
      continue;
    }
    tokens.push_back(argument);
  }
  return tokens;
}

LinkLine scan_link_tokens(const std::vector<std::string>& tokens)
{
  LinkLine line;
  bool inside_whole_archive = false;
  for (std::size_t token_index = 0; token_index < tokens.size(); ++token_index)
  {
    const std::string& token = tokens[token_index];
    if (token.empty())
    {
      continue;
    }
    if (token == kWholeArchiveOption)
    {
      inside_whole_archive = true;
      continue;
    }
    if (token == kNoWholeArchiveOption)
    {
      inside_whole_archive = false;
      continue;
    }
    if (token.front() == kResponseFilePrefix)
    {
      ++line.response_file_count;
      continue;
    }

    const std::string_view next_token = token_index + 1 < tokens.size()
                                            ? std::string_view(tokens[token_index + 1])
                                            : std::string_view{};

    bool consumed_output = false;
    const std::optional<std::string> output_value =
        output_path_value(token, next_token, consumed_output);
    if (output_value.has_value())
    {
      if (!line.output_path.has_value())
      {
        line.output_path = fs::path(*output_value);  // first -o on the line wins
      }
      if (consumed_output)
      {
        ++token_index;
      }
      continue;
    }

    bool consumed_map = false;
    const std::optional<std::string> map_value = map_file_value(token, next_token, consumed_map);
    if (map_value.has_value())
    {
      if (!line.map_file.has_value())
      {
        line.map_file = fs::path(*map_value);  // first -Map on the line wins
      }
      if (consumed_map)
      {
        ++token_index;
      }
      continue;
    }

    bool consumed_search_directory = false;
    const std::string_view search_directory =
        search_directory_value(token, next_token, consumed_search_directory);
    if (!search_directory.empty())
    {
      line.search_directories.emplace_back(search_directory);
      if (consumed_search_directory)
      {
        ++token_index;
      }
      continue;
    }

    bool consumed_library_name = false;
    const std::string_view library_name =
        library_name_value(token, next_token, consumed_library_name);
    if (!library_name.empty())
    {
      line.named_libraries.push_back(LinkName{std::string(library_name), inside_whole_archive});
      if (consumed_library_name)
      {
        ++token_index;
      }
      continue;
    }

    if (token.front() != '-')
    {
      if (has_link_input_extension(token))
      {
        line.direct_inputs.push_back(LinkInput{token, inside_whole_archive});
      }
      continue;
    }

    // Skip the value of any other option known to consume one, whatever it
    // is; an unrecognized flag is simply ignored, the safe direction: a
    // missed input under-claims usage, while a mis-read one invents it.
    if (contains(kLinkOptionsConsumingNextArgument, std::string_view(token)))
    {
      ++token_index;
    }
  }
  return line;
}

LinkLine scan_link_line(const TraceRecord& record)
{
  return scan_link_tokens(flatten_linker_tokens(record));
}

core::Result<LinkMap> map_links_to_roots(const std::vector<TraceRecord>& records,
                                         const fs::path& scan_root,
                                         const std::set<fs::path>& component_roots)
{
  core::Result<LinkMap> outcome;
  for (const fs::path& root : component_roots)
  {
    outcome.value.usage_by_root[root].root = root;
  }

  DirectoryResolver resolver;
  const fs::path canonical_root = resolver.canonical(scan_root);
  std::map<fs::path, std::set<fs::path>> linked_inputs_by_root;

  for (const TraceRecord& record : records)
  {
    if (!is_link_mode_invocation(record))
    {
      continue;
    }
    ++outcome.value.link_invocations;

    const LinkLine line = scan_link_line(record);
    outcome.value.unexpanded_response_files += line.response_file_count;
    const fs::path working_directory = resolver.canonical(fs::path(record.working_directory));

    std::vector<fs::path> resolved_search_directories;
    resolved_search_directories.reserve(line.search_directories.size());
    for (const std::string& directory_argument : line.search_directories)
    {
      resolved_search_directories.push_back(
          resolve_directory_argument(resolver, working_directory, directory_argument));
    }

    for (const LinkInput& input : line.direct_inputs)
    {
      const fs::path absolute_input =
          resolve_file_argument(resolver, working_directory, input.argument);
      attribute_link_input(absolute_input, canonical_root, component_roots, linked_inputs_by_root);
    }

    for (const LinkName& library : line.named_libraries)
    {
      if (resolved_search_directories.empty())
      {
        // No -L on this record to search: a bare `-lNAME` with no explicit
        // search directory almost always resolves through the linker's own
        // default system paths (`-lpthread`, `-lm`, ...), which bomwerk
        // never observes and was never asked to judge. Counting it as
        // unresolved would flag it on virtually every real linked
        // executable, drowning the genuinely actionable case below (a named
        // `-L` that doesn't hold the library it was expected to).
        continue;
      }
      const std::optional<fs::path> resolved =
          resolve_library_name(library.name, resolved_search_directories);
      if (!resolved.has_value())
      {
        ++outcome.value.unresolved_library_names;
        continue;
      }
      attribute_link_input(*resolved, canonical_root, component_roots, linked_inputs_by_root);
    }
  }

  for (const auto& [root, inputs] : linked_inputs_by_root)
  {
    ComponentUsage& usage = outcome.value.usage_by_root[root];
    usage.linked_input_count = inputs.size();
    if (!inputs.empty())
    {
      usage.first_linked_input = *inputs.begin();
      usage.signal = std::max(usage.signal, UsageSignal::Linked);
    }
  }

  // No warning for zero link invocations: unlike the compile scan's "zero compiler
  // invocations" (a real anomaly: an empty or misconfigured trace), a trace
  // with no link-mode records is the normal state for plenty of valid
  // builds (a static-library-only target, an object-only CMake target, a
  // trace scoped to just the compile phase). Warning here would degrade
  // trim's exit code for entirely healthy traces far more often than not.
  if (outcome.value.unresolved_library_names > 0)
  {
    outcome.warn(
        core::WarningCode::kObserveUnresolvedLinkArgument,
        std::to_string(outcome.value.unresolved_library_names) +
            " -l<name> argument(s) did not resolve to a file in any -L directory seen on "
            "the same link line; a component supplied only that way may be reported unused");
  }
  if (outcome.value.unexpanded_response_files > 0)
  {
    outcome.warn(core::WarningCode::kObserveResponseFilesUnexpanded,
                 std::to_string(outcome.value.unexpanded_response_files) +
                     " link argument(s) were response files (@file), which bomwerk does not "
                     "open; a component whose link inputs appear only inside one may be reported "
                     "unused");
  }
  return outcome;
}

std::optional<std::string> scan_archive_output(const TraceRecord& record)
{
  std::size_t argument_index = 1;  // argv[0] is the tool itself
  while (argument_index < record.arguments.size())
  {
    const std::string& argument = record.arguments[argument_index];
    if (contains(kArchiveOptionsConsumingNextArgument, std::string_view(argument)))
    {
      argument_index += 2;
      continue;
    }
    if (argument.starts_with("--"))
    {
      ++argument_index;
      continue;
    }
    break;
  }
  if (argument_index >= record.arguments.size())
  {
    return std::nullopt;
  }

  std::string_view keys(record.arguments[argument_index]);
  if (keys.starts_with('-'))
  {
    keys.remove_prefix(1);
  }
  if (keys.empty())
  {
    return std::nullopt;
  }
  std::size_t operands_before_archive = 0;
  for (const char key : keys)
  {
    if (kArchiveKeyLetters.find(key) == std::string_view::npos)
    {
      return std::nullopt;  // not an operand bundle bomwerk understands
    }
    if (key == kArchiveScriptModeKey)
    {
      return std::nullopt;  // MRI script mode names no archive here
    }
    if (kArchiveKeysTakingOperand.find(key) != std::string_view::npos)
    {
      ++operands_before_archive;
    }
  }

  argument_index += 1 + operands_before_archive;
  if (argument_index >= record.arguments.size())
  {
    return std::nullopt;
  }
  return record.arguments[argument_index];
}

std::vector<fs::path> BuildArtifacts::all_paths() const
{
  std::vector<fs::path> paths;
  paths.reserve(link_outputs.size() + archive_outputs.size() + linked_archives.size());
  paths.insert(paths.end(), link_outputs.begin(), link_outputs.end());
  paths.insert(paths.end(), archive_outputs.begin(), archive_outputs.end());
  paths.insert(paths.end(), linked_archives.begin(), linked_archives.end());
  std::sort(paths.begin(), paths.end());
  paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
  return paths;
}

core::Result<BuildArtifacts> collect_build_artifacts(const std::vector<TraceRecord>& records,
                                                     const fs::path& scan_root)
{
  core::Result<BuildArtifacts> outcome;
  DirectoryResolver resolver;
  const fs::path canonical_root = resolver.canonical(scan_root);

  // One argument -> one root-relative path, or one tally. Everything this
  // function collects goes through here so the out-of-tree rule is applied
  // once rather than at three call sites.
  const auto record_artifact = [&](const fs::path& working_directory, std::string_view argument,
                                   std::set<fs::path>& destination)
  {
    const fs::path absolute = resolve_file_argument(resolver, working_directory, argument);
    const std::optional<fs::path> relative = to_root_relative(absolute, canonical_root);
    if (!relative.has_value())
    {
      ++outcome.value.out_of_tree_artifacts;
      return;
    }
    destination.insert(*relative);
  };

  for (const TraceRecord& record : records)
  {
    const fs::path working_directory = resolver.canonical(fs::path(record.working_directory));

    if (record.tool == kArchiveToolName)
    {
      const std::optional<std::string> archive = scan_archive_output(record);
      if (archive.has_value())
      {
        record_artifact(working_directory, *archive, outcome.value.archive_outputs);
      }
      continue;
    }
    if (!is_link_mode_invocation(record))
    {
      continue;
    }

    const LinkLine line = scan_link_line(record);
    outcome.value.unexpanded_response_files += line.response_file_count;
    if (line.output_path.has_value())
    {
      record_artifact(working_directory, line.output_path->string(), outcome.value.link_outputs);
    }
    for (const LinkInput& input : line.direct_inputs)
    {
      if (is_archive_or_shared_object(input.argument))
      {
        record_artifact(working_directory, input.argument, outcome.value.linked_archives);
      }
    }
  }

  if (outcome.value.out_of_tree_artifacts > 0)
  {
    outcome.warn(core::WarningCode::kObserveEvidenceOutsideRoot,
                 std::to_string(outcome.value.out_of_tree_artifacts) +
                     " build artifact(s) lie outside " + scan_root.string() +
                     "; bomwerk reads no binary evidence from them");
  }
  if (outcome.value.unexpanded_response_files > 0)
  {
    outcome.warn(core::WarningCode::kObserveResponseFilesUnexpanded,
                 std::to_string(outcome.value.unexpanded_response_files) +
                     " link argument(s) were response files (@file), which bomwerk does not "
                     "open; an output named only inside one is not scanned");
  }
  return outcome;
}

void merge_link_evidence(CompileMap& compile_map, const LinkMap& link_map)
{
  for (const auto& [root, link_usage] : link_map.usage_by_root)
  {
    ComponentUsage& usage = compile_map.usage_by_root[root];
    usage.root = root;
    usage.linked_input_count = link_usage.linked_input_count;
    usage.first_linked_input = link_usage.first_linked_input;
    usage.signal = std::max(usage.signal, link_usage.signal);
  }
}

}  // namespace bomwerk::observe
