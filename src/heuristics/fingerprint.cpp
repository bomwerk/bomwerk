#include "heuristics/fingerprint.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <limits>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <string_view>
#include <utility>

#include "core/file_io.hpp"
#include "core/json_utils.hpp"
#include "core/warning_code.hpp"
#include "heuristics/vendor_root.hpp"

namespace fs = std::filesystem;

namespace bomwerk::heuristics::fingerprint
{
namespace
{

/// `Warning::ecosystem`, the field a `--warnings` manifest groups on. These
/// warnings are not about a package ecosystem, they are about this matcher, and
/// grouping them under their own label keeps a corpus problem from looking like
/// a conan or npm problem.
constexpr std::string_view kEcosystem = "fingerprint";

/// Length of an xxh3-64 value written as lowercase hex, the form the index
/// prefilter uses.
constexpr std::size_t kFastHashHexLength = 16u;

/// `const char*` rather than `string_view`: whether nlohmann's object lookup
/// accepts a non-`std::string` key depends on its own build configuration, and
/// every other parser in this repository looks keys up with plain literals.
std::string string_field(const nlohmann::json& object, const char* key)
{
  const auto field = object.find(key);
  if (field == object.end() || !field->is_string())
  {
    return {};
  }
  return field->get<std::string>();
}

/// An unsigned integer field, or nullopt when absent or not an unsigned
/// integer. JSON has one number type, so `is_number_unsigned` is what rejects
/// a negative count and a float alike.
std::optional<std::uint64_t> unsigned_field(const nlohmann::json& object, const char* key)
{
  const auto field = object.find(key);
  if (field == object.end() || !field->is_number_unsigned())
  {
    return std::nullopt;
  }
  return field->get<std::uint64_t>();
}

std::optional<std::uint64_t> fast_hash_from_hex(std::string_view lowercase_hex)
{
  if (lowercase_hex.size() != kFastHashHexLength)
  {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  for (const char character : lowercase_hex)
  {
    unsigned int digit = 0;
    if (character >= '0' && character <= '9')
    {
      digit = static_cast<unsigned int>(character - '0');
    }
    else if (character >= 'a' && character <= 'f')
    {
      digit = static_cast<unsigned int>(character - 'a') + 10u;
    }
    else
    {
      return std::nullopt;
    }
    value = (value << 4u) | digit;
  }
  return value;
}

bool digest_less(const IndexFileEntry& left, const IndexFileEntry& right)
{
  return left.digest < right.digest;
}

/// Human-readable byte count for a cap message, in whole MiB.
std::string mebibytes(std::size_t bytes)
{
  return std::to_string(bytes / (1024u * 1024u)) + " MiB";
}

/// Read `libraries`. Positional, so this is all-or-nothing: see LoadLimits.
/// Returns false when the document must be refused whole, having warned.
bool load_libraries(const nlohmann::json& document, const LoadLimits& limits, Index& index,
                    core::Result<Index>& result)
{
  const auto libraries = document.find("libraries");
  if (libraries == document.end() || !libraries->is_array())
  {
    result.warn(core::WarningCode::kFingerprintIndexUnreadable,
                "fingerprint: corpus index has no libraries array, ignored",
                std::string(kEcosystem));
    return false;
  }
  if (libraries->size() > limits.max_libraries)
  {
    result.warn(core::WarningCode::kFingerprintIndexUnreadable,
                "fingerprint: corpus index declares " + std::to_string(libraries->size()) +
                    " libraries, over the limit of " + std::to_string(limits.max_libraries) +
                    ", ignored",
                std::string(kEcosystem));
    return false;
  }

  index.libraries.reserve(libraries->size());
  for (const nlohmann::json& entry : *libraries)
  {
    IndexLibrary library;
    if (entry.is_object())
    {
      library.name = string_field(entry, "name");
      library.purl_type = string_field(entry, "purl_type");
      library.purl_namespace = string_field(entry, "purl_namespace");
      library.license = string_field(entry, "license");
      library.upstream = string_field(entry, "upstream");
    }
    if (library.name.empty() || library.purl_type.empty())
    {
      result.warn(core::WarningCode::kFingerprintIndexUnreadable,
                  "fingerprint: corpus index library entry " +
                      std::to_string(index.libraries.size()) +
                      " has no name or purl type, index ignored",
                  std::string(kEcosystem));
      return false;
    }
    index.libraries.push_back(std::move(library));
  }
  return true;
}

/// Read `releases`. Positional too, and additionally referenced by `files`.
bool load_releases(const nlohmann::json& document, const LoadLimits& limits, Index& index,
                   core::Result<Index>& result)
{
  const auto releases = document.find("releases");
  if (releases == document.end() || !releases->is_array())
  {
    result.warn(core::WarningCode::kFingerprintIndexUnreadable,
                "fingerprint: corpus index has no releases array, ignored",
                std::string(kEcosystem));
    return false;
  }
  if (releases->size() > limits.max_releases)
  {
    result.warn(core::WarningCode::kFingerprintIndexUnreadable,
                "fingerprint: corpus index declares " + std::to_string(releases->size()) +
                    " releases, over the limit of " + std::to_string(limits.max_releases) +
                    ", ignored",
                std::string(kEcosystem));
    return false;
  }

  index.releases.reserve(releases->size());
  for (const nlohmann::json& entry : *releases)
  {
    IndexRelease release;
    std::optional<std::uint64_t> library_index;
    std::optional<std::uint64_t> file_count;
    if (entry.is_object())
    {
      library_index = unsigned_field(entry, "library");
      file_count = unsigned_field(entry, "file_count");
      release.version = string_field(entry, "version");
      release.ref = string_field(entry, "ref");
      release.commit = string_field(entry, "commit");
      release.order = static_cast<std::uint32_t>(unsigned_field(entry, "order").value_or(0));
    }
    // `file_count` is the denominator of release coverage, the criterion that
    // separates two releases sharing an unchanged header. A release without it
    // cannot be scored, and scoring it as zero would make its coverage
    // infinite, so the index is refused instead.
    if (!library_index.has_value() || *library_index >= index.libraries.size() ||
        !file_count.has_value() || *file_count == 0 || release.version.empty())
    {
      result.warn(core::WarningCode::kFingerprintIndexUnreadable,
                  "fingerprint: corpus index release entry " +
                      std::to_string(index.releases.size()) +
                      " is incomplete or names an unknown library, index ignored",
                  std::string(kEcosystem));
      return false;
    }
    release.library = static_cast<std::uint32_t>(*library_index);
    release.file_count = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(*file_count, std::numeric_limits<std::uint32_t>::max()));
    index.releases.push_back(std::move(release));
  }
  return true;
}

/// Read `files`. NOT positional, so a malformed entry is skipped and counted
/// rather than refusing the corpus: the rest of it still identifies libraries.
void load_files(const nlohmann::json& document, const LoadLimits& limits, Index& index,
                std::size_t& skipped_entries, bool& digest_budget_reached)
{
  const auto files = document.find("files");
  if (files == document.end() || !files->is_object())
  {
    return;
  }

  for (const auto& entry : files->items())
  {
    if (index.files.size() >= limits.max_digests)
    {
      digest_budget_reached = true;
      break;
    }
    const std::optional<core::Sha256Digest> digest = core::sha256_from_hex(entry.key());
    const nlohmann::json& release_list = entry.value();
    if (!digest.has_value() || !release_list.is_array() || release_list.empty() ||
        release_list.size() > limits.max_releases_per_digest)
    {
      ++skipped_entries;
      continue;
    }

    const std::size_t pool_mark = index.release_refs.size();
    bool entry_valid = true;
    for (const nlohmann::json& reference : release_list)
    {
      const std::optional<std::uint64_t> release_index =
          reference.is_number_unsigned()
              ? std::optional<std::uint64_t>(reference.get<std::uint64_t>())
              : std::nullopt;
      if (!release_index.has_value() || *release_index >= index.releases.size())
      {
        entry_valid = false;
        break;
      }
      index.release_refs.push_back(static_cast<std::uint32_t>(*release_index));
    }
    if (!entry_valid)
    {
      index.release_refs.resize(pool_mark);
      ++skipped_entries;
      continue;
    }

    // Sorted and deduplicated so the span a lookup hands back is in index
    // order whatever the document's own ordering was (rule 3).
    const auto pool_begin = index.release_refs.begin() + static_cast<std::ptrdiff_t>(pool_mark);
    std::sort(pool_begin, index.release_refs.end());
    index.release_refs.erase(std::unique(pool_begin, index.release_refs.end()),
                             index.release_refs.end());

    IndexFileEntry file_entry;
    file_entry.digest = *digest;
    file_entry.first_release_ref = static_cast<std::uint32_t>(pool_mark);
    file_entry.release_ref_count =
        static_cast<std::uint32_t>(index.release_refs.size() - pool_mark);
    index.files.push_back(file_entry);
  }

  // Lowercase hex sorts the same way the raw bytes do, so a builder-written
  // index arrives sorted already. Sorted here anyway, because a hand-edited
  // one may not be and the lookup below is a binary search.
  std::sort(index.files.begin(), index.files.end(), digest_less);
}

void load_prefilter(const nlohmann::json& document, Index& index, std::size_t& skipped_entries)
{
  const auto prefilter = document.find("prefilter");
  if (prefilter == document.end() || !prefilter->is_array())
  {
    return;
  }
  index.prefilter.reserve(prefilter->size());
  for (const nlohmann::json& entry : *prefilter)
  {
    const std::optional<std::uint64_t> value =
        entry.is_string() ? fast_hash_from_hex(entry.get<std::string>()) : std::nullopt;
    if (!value.has_value())
    {
      ++skipped_entries;
      continue;
    }
    index.prefilter.push_back(*value);
  }
  std::sort(index.prefilter.begin(), index.prefilter.end());
  index.prefilter.erase(std::unique(index.prefilter.begin(), index.prefilter.end()),
                        index.prefilter.end());
}

/// One vendor root's running tallies. Ordered maps, so iteration is
/// deterministic and every tie-break below is reproducible (rule 3).
struct RootTally
{
  std::map<std::uint32_t, std::size_t> matched_by_release;
  std::map<std::uint32_t, std::size_t> matched_by_library;
  std::vector<std::pair<fs::path, core::Sha256Digest>> matched_files;
  std::vector<fs::path> unmatched_files;
  std::size_t files_considered = 0;
};

/// The library that explains the most files under one root. Ties go to the
/// lexicographically smaller name, which makes the order total and
/// platform-independent.
std::optional<std::uint32_t> best_library(const Index& index, const RootTally& tally)
{
  std::optional<std::uint32_t> best;
  std::size_t best_matches = 0;
  for (const auto& [library_index, matches] : tally.matched_by_library)
  {
    if (!best.has_value() || matches > best_matches ||
        (matches == best_matches &&
         index.libraries[library_index].name < index.libraries[*best].name))
    {
      best = library_index;
      best_matches = matches;
    }
  }
  return best;
}

/// The releases of `library_index` that best explain this root, and the number
/// of files that put them there.
///
/// Criterion 1 is the match count. Criterion 2 is release coverage,
/// `matched / release.file_count`: of two releases explaining the same files,
/// the one whose own file list is more completely accounted for is the one on
/// disk. Because criterion 1 has already equalized the numerators by the time
/// coverage is compared, "higher coverage" reduces exactly to "smaller
/// file_count", so no division or cross-multiplication is needed and no
/// floating point reaches a decision that changes SBOM bytes (rule 3).
///
/// More than one survivor means the evidence genuinely cannot separate them.
std::vector<std::uint32_t> best_releases(const Index& index, const RootTally& tally,
                                         std::uint32_t library_index, std::size_t& matched_files)
{
  std::vector<std::uint32_t> best;
  std::size_t best_matches = 0;
  std::uint32_t best_file_count = 0;
  for (const auto& [release_index, matches] : tally.matched_by_release)
  {
    const IndexRelease& release = index.releases[release_index];
    if (release.library != library_index)
    {
      continue;
    }
    if (best.empty())
    {
      best.push_back(release_index);
      best_matches = matches;
      best_file_count = release.file_count;
      continue;
    }
    if (matches < best_matches)
    {
      continue;  // criterion 1 already rules this release out
    }
    if (matches > best_matches || release.file_count < best_file_count)
    {
      best.assign(1, release_index);  // strictly better on criterion 1 or 2
      best_matches = matches;
      best_file_count = release.file_count;
      continue;
    }
    if (release.file_count == best_file_count)
    {
      best.push_back(release_index);  // indistinguishable on both criteria
    }
  }
  matched_files = best_matches;
  return best;
}

/// `High` is reserved for a cryptographic byte match of several files against
/// one pinned upstream release that also explains most of what is on disk. A
/// version macro cannot earn that, because a fork keeps the macro and changes
/// the code, which is the entire gap this module exists to close.
///
/// A root where only a sliver of the files match never gets this far: see the
/// skip in `match_vendored_files`.
core::Confidence confidence_for(std::size_t matched_files, std::size_t files_considered,
                                std::size_t release_file_count, bool unique_release)
{
  if (!unique_release)
  {
    return core::Confidence::Low;
  }
  const bool explains_most_of_the_root = matched_files * 4u >= files_considered * 3u;
  const bool covers_half_the_release = matched_files * 2u >= release_file_count;
  if (matched_files >= 3u && explains_most_of_the_root && covers_half_the_release)
  {
    return core::Confidence::High;
  }
  return core::Confidence::Medium;
}

}  // namespace

bool may_contain_fast_hash(const Index& index, std::uint64_t fast_hash)
{
  if (index.prefilter.empty())
  {
    return true;
  }
  return std::binary_search(index.prefilter.begin(), index.prefilter.end(), fast_hash);
}

std::span<const std::uint32_t> releases_for_digest(const Index& index,
                                                   const core::Sha256Digest& digest)
{
  IndexFileEntry probe;
  probe.digest = digest;
  const auto found = std::lower_bound(index.files.begin(), index.files.end(), probe, digest_less);
  if (found == index.files.end() || found->digest != digest)
  {
    return {};
  }
  return std::span<const std::uint32_t>(index.release_refs.data() + found->first_release_ref,
                                        found->release_ref_count);
}

core::Result<Index> load_index(const fs::path& index_path, LoadLimits limits)
{
  core::Result<Index> result;

  const core::BoundedFileRead file_read =
      core::read_file_bounded(index_path, limits.max_index_bytes);
  if (!file_read.readable)
  {
    result.warn(core::WarningCode::kFingerprintIndexUnreadable,
                "fingerprint: corpus index could not be opened, scanning without a corpus",
                std::string(kEcosystem));
    return result;
  }
  if (file_read.truncated)
  {
    result.warn(core::WarningCode::kFingerprintIndexUnreadable,
                "fingerprint: corpus index exceeds the " + mebibytes(limits.max_index_bytes) +
                    " cap, ignored",
                std::string(kEcosystem));
    return result;
  }

  const std::string_view json_bytes = core::json_utils::without_utf8_bom(file_read.bytes);
  if (core::json_utils::exceeds_json_nesting_depth(json_bytes, limits.max_json_nesting_depth))
  {
    result.warn(core::WarningCode::kFingerprintIndexUnreadable,
                "fingerprint: corpus index nesting exceeds the depth limit, ignored",
                std::string(kEcosystem));
    return result;
  }
  const nlohmann::json document =
      nlohmann::json::parse(json_bytes, nullptr, /*allow_exceptions=*/false);
  if (document.is_discarded() || !document.is_object())
  {
    result.warn(core::WarningCode::kFingerprintIndexUnreadable,
                "fingerprint: corpus index is not valid JSON, ignored", std::string(kEcosystem));
    return result;
  }

  // Refused WHOLE on a schema it does not know, rather than read field by
  // field: a consumer that guesses at a document it does not understand is
  // worse than one that declines it (binscan/sidecar.hpp states the same rule
  // for the binscan sidecar).
  const std::optional<std::uint64_t> schema_version = unsigned_field(document, "schema_version");
  if (!schema_version.has_value() ||
      *schema_version != static_cast<std::uint64_t>(kIndexSchemaVersion))
  {
    result.warn(core::WarningCode::kFingerprintIndexSchemaUnsupported,
                "fingerprint: corpus index schema version is not " +
                    std::to_string(kIndexSchemaVersion) + ", ignored",
                std::string(kEcosystem));
    return result;
  }

  Index index;
  index.corpus_revision = string_field(document, "corpus_revision");
  if (!load_libraries(document, limits, index, result) ||
      !load_releases(document, limits, index, result))
  {
    return result;
  }

  std::size_t skipped_entries = 0;
  bool digest_budget_reached = false;
  load_files(document, limits, index, skipped_entries, digest_budget_reached);
  load_prefilter(document, index, skipped_entries);

  if (skipped_entries > 0)
  {
    result.warn(core::WarningCode::kFingerprintIndexEntrySkipped,
                "fingerprint: " + std::to_string(skipped_entries) + " corpus index entr" +
                    (skipped_entries == 1 ? "y was" : "ies were") + " malformed and skipped",
                std::string(kEcosystem));
  }
  if (digest_budget_reached)
  {
    result.warn(core::WarningCode::kFingerprintIndexEntrySkipped,
                "fingerprint: corpus index holds more than " + std::to_string(limits.max_digests) +
                    " file digests, the rest were not loaded",
                std::string(kEcosystem));
  }

  spdlog::debug("fingerprint corpus: {} libraries, {} release(s), {} digest(s), revision {}",
                index.libraries.size(), index.releases.size(), index.files.size(),
                index.corpus_revision.empty() ? "unknown" : index.corpus_revision);
  result.value = std::move(index);
  return result;
}

core::Result<std::vector<RootMatch>> match_vendored_files(const core::FileIndex& file_index,
                                                          const fs::path& root, const Index& index,
                                                          MatchLimits limits)
{
  core::Result<std::vector<RootMatch>> result;
  if (index.empty())
  {
    return result;
  }

  // Grouped by the SHARED vendor-root rule, so these roots are exactly the
  // ones the vendored-source heuristic produced components for and `cli` can
  // join the two by path.
  std::map<fs::path, std::vector<fs::path>> files_by_vendor_root;
  for (const fs::path& relative_path : file_index.files)
  {
    const std::optional<fs::path> vendor_root = vendor_root_for(relative_path);
    if (vendor_root.has_value())
    {
      files_by_vendor_root[*vendor_root].push_back(relative_path);
    }
  }

  std::size_t hashed_files = 0;
  bool file_budget_reported = false;

  for (const auto& [vendor_root, files] : files_by_vendor_root)
  {
    RootTally tally;
    for (const fs::path& relative_path : files)
    {
      if (hashed_files >= limits.max_hashed_files)
      {
        if (!file_budget_reported)
        {
          // A warning, and deliberately NOT `complete = false`: the SBOM is
          // whole without fingerprint evidence, so a corpus budget must not
          // turn a good scan into an exit-2 incomplete one.
          result.warn(core::WarningCode::kFingerprintFileBudgetReached,
                      "fingerprint: stopped after hashing " +
                          std::to_string(limits.max_hashed_files) +
                          " vendored file(s), later roots were not matched",
                      std::string(kEcosystem), vendor_root);
          file_budget_reported = true;
        }
        break;
      }

      const fs::path absolute_path = root / relative_path;

      // Pass 1 exists only to spare a SHA-256 on a file the corpus cannot contain,
      // so an index with no prefilter skips it outright. Running it anyway would
      // read every byte of every vendored file for a probe that always answers
      // "maybe", and then read it all again for the digest. An index built
      // without the optional Python xxhash module has no prefilter, so this is
      // the common case, not an edge.
      if (!index.prefilter.empty())
      {
        const core::BoundedFileFastHash fast =
            core::xxh3_file_bounded(absolute_path, limits.max_hashed_file_bytes);
        if (!fast.readable || fast.over_limit || fast.bytes_hashed < limits.min_hashable_bytes)
        {
          continue;
        }
        if (!may_contain_fast_hash(index, fast.hash))
        {
          ++hashed_files;
          ++tally.files_considered;
          tally.unmatched_files.push_back(relative_path);
          continue;
        }
      }

      const core::BoundedFileDigest digest =
          core::sha256_file_bounded(absolute_path, limits.max_hashed_file_bytes);
      // Unreadable, oversized and tiny files are not "unmatched", they were
      // never judged, so they stay out of both numerator and denominator.
      if (!digest.readable || digest.over_limit || digest.bytes_hashed < limits.min_hashable_bytes)
      {
        continue;
      }
      ++hashed_files;
      ++tally.files_considered;
      const std::span<const std::uint32_t> releases = releases_for_digest(index, digest.digest);
      if (releases.empty())
      {
        // The cheap pass said maybe and the real digest said no: an xxh3
        // collision, which costs one wasted read and never an identity.
        tally.unmatched_files.push_back(relative_path);
        continue;
      }

      std::set<std::uint32_t> libraries_for_this_file;
      for (const std::uint32_t release_index : releases)
      {
        ++tally.matched_by_release[release_index];
        libraries_for_this_file.insert(index.releases[release_index].library);
      }
      // Counted once per library, however many of its releases hold the file.
      for (const std::uint32_t library_index : libraries_for_this_file)
      {
        ++tally.matched_by_library[library_index];
      }
      tally.matched_files.emplace_back(relative_path, digest.digest);
    }

    const std::optional<std::uint32_t> library_index = best_library(index, tally);
    if (!library_index.has_value())
    {
      continue;
    }
    std::size_t matched_files = 0;
    const std::vector<std::uint32_t> releases =
        best_releases(index, tally, *library_index, matched_files);
    if (releases.empty() || matched_files == 0)
    {
      continue;
    }

    // A directory where only a sliver of the hashable files match (under one in
    // eight) is a project that CONTAINS some upstream files, not that library: a
    // first-party `third_party/mylib` that vendors one copied header is not
    // uthash. Reporting it would rename the directory and assert a release's
    // version into a document that drives CVE matching, so it is dropped
    // outright rather than demoted to Low. A library nested inside a larger
    // vendor drop (FreeRTOS inside an SDK) is a different problem, attributing
    // sub-roots, which v1 does not attempt. Integer comparison, as everywhere a
    // threshold reaches SBOM bytes (rule 3).
    if (matched_files * 8u < tally.files_considered)
    {
      continue;
    }

    const IndexLibrary& library = index.libraries[*library_index];
    RootMatch match;
    match.vendor_root = vendor_root;
    match.library_name = library.name;
    match.purl_type = library.purl_type;
    match.purl_namespace = library.purl_namespace;
    match.license = library.license;
    match.corpus_revision = index.corpus_revision;
    match.matched_files = matched_files;
    match.files_considered = tally.files_considered;
    match.release_file_count = index.releases[releases.front()].file_count;

    if (releases.size() == 1)
    {
      const IndexRelease& release = index.releases[releases.front()];
      match.version = release.version;
      match.release_ref = release.ref;
      match.release_commit = release.commit;
    }
    else
    {
      // Asserting one of several equally supported releases would write a
      // fabricated version into a document that drives vulnerability
      // matching. The library is named, the version is left open.
      for (const std::uint32_t release_index : releases)
      {
        match.candidate_versions.push_back(index.releases[release_index].version);
      }
      std::sort(match.candidate_versions.begin(), match.candidate_versions.end());
      match.candidate_versions.erase(
          std::unique(match.candidate_versions.begin(), match.candidate_versions.end()),
          match.candidate_versions.end());
      // Two releases of one library can carry the same version string (a
      // re-pinned ref). Then there is nothing undecided to report, so the
      // version is asserted after all and the candidate list goes away.
      if (match.candidate_versions.size() == 1)
      {
        match.version = match.candidate_versions.front();
        match.candidate_versions.clear();
        match.release_ref = index.releases[releases.front()].ref;
        match.release_commit = index.releases[releases.front()].commit;
      }
    }

    match.confidence = confidence_for(matched_files, tally.files_considered,
                                      match.release_file_count, match.candidate_versions.empty());

    // Everything hashable under this root that is not part of the attribution:
    // the files the prefilter or the digest rejected, plus any file that
    // matched some other release. T93 turns this set into a verdict; v1 only
    // reports it.
    const std::set<std::uint32_t> attributed(releases.begin(), releases.end());
    match.unmatched_files = std::move(tally.unmatched_files);
    for (const auto& [relative_path, digest] : tally.matched_files)
    {
      const std::span<const std::uint32_t> file_releases = releases_for_digest(index, digest);
      const bool in_attribution = std::any_of(file_releases.begin(), file_releases.end(),
                                              [&attributed](std::uint32_t release_index)
                                              { return attributed.count(release_index) > 0; });
      if (!in_attribution)
      {
        match.unmatched_files.push_back(relative_path);
      }
    }
    std::sort(match.unmatched_files.begin(), match.unmatched_files.end());

    spdlog::debug("fingerprint: {} -> {} {} ({} of {} files) [{}]", vendor_root.string(),
                  match.library_name, match.version.empty() ? "(ambiguous)" : match.version,
                  match.matched_files, match.files_considered, core::to_string(match.confidence));
    result.value.push_back(std::move(match));
  }

  // Already in sorted-root order from the map above; sorted again so the
  // guarantee is in the code rather than in a reader's head (rule 3).
  std::sort(result.value.begin(), result.value.end(),
            [](const RootMatch& left, const RootMatch& right)
            { return left.vendor_root < right.vendor_root; });
  return result;
}

std::string describe_match(const RootMatch& match)
{
  // "1 of 1 hashed file matches X" and "5 of 6 hashed files match X": the noun
  // agrees with the files considered, the verb with the files matched, because
  // this text goes into an SBOM a person reads.
  std::string detail = std::to_string(match.matched_files) + " of " +
                       std::to_string(match.files_considered) + " hashed file" +
                       (match.files_considered == 1 ? "" : "s") + " match" +
                       (match.matched_files == 1 ? "es " : " ") + match.library_name;
  if (!match.version.empty())
  {
    detail += " " + match.version;
  }
  else if (!match.candidate_versions.empty())
  {
    detail += ", version undecided between";
    for (std::size_t position = 0; position < match.candidate_versions.size(); ++position)
    {
      detail += (position == 0 ? " " : ", ") + match.candidate_versions[position];
    }
  }
  if (!match.corpus_revision.empty())
  {
    detail += " (corpus " + match.corpus_revision + ")";
  }
  return detail;
}

}  // namespace bomwerk::heuristics::fingerprint
