#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/sha256.hpp"

namespace bomwerk::heuristics::fingerprint
{

/// The corpus-index schema this build understands. An index declaring anything
/// else is refused whole rather than read field by field, the same doctrine
/// `binscan::kSidecarSchemaVersion` states: a consumer that guesses at a
/// document it does not understand is worse than one that declines it.
inline constexpr int kIndexSchemaVersion = 1;

/// Byte cap on the index document. A corpus of ~50 libraries is single-digit
/// megabytes, so this leaves generous headroom while keeping the one large
/// allocation this module makes a named, bounded one (rule 1).
inline constexpr std::size_t kMaxIndexBytes = 64u * 1024u * 1024u;

/// Per-file cap for hashing. A vendored source file is kilobytes; something
/// above this is a blob, an archive or a disk image, and reading it would cost
/// more than the identity is worth.
inline constexpr std::uintmax_t kMaxHashedFileBytes = 16u * 1024u * 1024u;

/// Files smaller than this never vote. An empty file, a one-line stub and a
/// 20-byte `#pragma once` header are byte-identical across unrelated projects,
/// so counting them would let any tree "match" any library.
inline constexpr std::uintmax_t kMinHashableBytes = 64u;

/// Caps applied while READING an index. Nothing here ever throws (rule 1), but
/// the two halves of the document degrade differently, and the difference is
/// load-bearing:
///
/// - `libraries` and `releases` are referenced BY POSITION, so they are
///   all-or-nothing. Dropping a malformed entry would shift every later index
///   and silently reattribute files to the wrong library. A bad entry or an
///   over-cap array therefore refuses the whole document.
/// - `files` entries are keyed by digest and referenced by nobody, so a
///   malformed one is skipped and counted, and the rest of the corpus still
///   works.
struct LoadLimits
{
  std::size_t max_index_bytes = kMaxIndexBytes;
  std::size_t max_libraries = 4096u;
  std::size_t max_releases = 262144u;
  std::size_t max_digests = 4000000u;
  std::size_t max_releases_per_digest = 4096u;
  int max_json_nesting_depth = 8;  ///< the schema is flat; 8 is already slack
};

/// Caps applied while MATCHING a tree.
struct MatchLimits
{
  std::size_t max_hashed_files = 100000u;
  std::uintmax_t max_hashed_file_bytes = kMaxHashedFileBytes;
  std::uintmax_t min_hashable_bytes = kMinHashableBytes;
};

/// One upstream library in the corpus.
struct IndexLibrary
{
  std::string name;
  std::string purl_type;       ///< "generic" today; the index carries it so it can change
  std::string purl_namespace;  ///< usually empty
  std::string license;         ///< SPDX id where upstream has one, else empty
  std::string upstream;        ///< provenance for a human, never used for matching
};

/// One pinned release of one library.
struct IndexRelease
{
  std::uint32_t library = 0;  ///< index into `Index::libraries`
  std::string version;
  std::string ref;     ///< the upstream tag, e.g. "v1.2.11"
  std::string commit;  ///< the dereferenced commit the tag pointed at

  /// The builder's own release ordering, so nothing here ever has to parse a
  /// version string (no semver in C++, and no deciding whether `V11.1.0`
  /// precedes `11.1.0`). Read and carried, but NOT consulted by v1's
  /// attribution, which never needs to know which of two releases is newer:
  /// a tie it cannot break asserts no version rather than picking a side. Kept
  /// because the builder writes it and T93's fork verdict will want it.
  std::uint32_t order = 0;

  std::uint32_t file_count = 0;  ///< files the builder hashed for this release
};

/// One file content the corpus knows, and which releases contain it. The same
/// bytes legitimately appear in several releases (a header unchanged between
/// two versions), which is the whole reason release attribution needs more than
/// a vote count.
struct IndexFileEntry
{
  core::Sha256Digest digest{};
  std::uint32_t first_release_ref = 0;  ///< offset into `Index::release_refs`
  std::uint32_t release_ref_count = 0;
};

/// A loaded corpus index.
///
/// `files` is sorted by digest and binary-searched rather than hashed into a
/// map: the lookup is a handful of comparisons against a file read that already
/// cost orders of magnitude more, and a sorted vector keeps both the memory
/// compact and the iteration order fixed (rule 3).
struct Index
{
  std::string corpus_revision;  ///< the manifest's `pinned_at`, for evidence text
  std::vector<IndexLibrary> libraries;
  std::vector<IndexRelease> releases;
  std::vector<IndexFileEntry> files;        ///< sorted by `digest`
  std::vector<std::uint32_t> release_refs;  ///< flat pool `files` points into

  /// Sorted xxh3-64 values of the same contents `files` holds: pass 1's cheap
  /// probe. Derivable from the corpus but not from `files`, so an index may
  /// legitimately omit it, and then pass 1 becomes a no-op and every hashable
  /// file pays for a SHA-256. An optimisation, never an authority.
  std::vector<std::uint64_t> prefilter;

  [[nodiscard]] bool empty() const { return files.empty(); }
};

/// Pass 1: could any corpus file have this content? A false answer is final and
/// costs one cheap hash. A true answer is only a hint, and `releases_for_digest`
/// decides. Always true for an index with no prefilter, so a missing prefilter
/// costs time rather than correctness.
[[nodiscard]] bool may_contain_fast_hash(const Index& index, std::uint64_t fast_hash);

/// Pass 2: the releases whose file list contains exactly these bytes, in index
/// order. Empty when the prefilter produced a false positive. The span points
/// into `index`, so it must not outlive it.
[[nodiscard]] std::span<const std::uint32_t> releases_for_digest(const Index& index,
                                                                 const core::Sha256Digest& digest);

/// Read a corpus index from `index_path`.
///
/// Bounded and schema-checked (see LoadLimits). An unreadable, oversized,
/// malformed or wrong-schema document yields an EMPTY index plus warnings, and
/// a caller treats that as "no corpus" rather than as a failure: the SBOM is
/// complete without one.
///
/// No warning raised here carries `index_path` in `Warning::affected_path`.
/// That field is root-relative by contract and reaches the deterministic
/// `--warnings` sidecar, so an operator-supplied absolute path from outside the
/// scanned tree would make that artifact differ between machines (rule 3).
/// The messages say "corpus index" instead; the path is on stdout, which is
/// product output and not a compared artifact.
[[nodiscard]] core::Result<Index> load_index(const std::filesystem::path& index_path,
                                             LoadLimits limits = {});

/// What the corpus said about one vendor root.
struct RootMatch
{
  std::filesystem::path vendor_root;  ///< root-relative; the join key to a Component::root
  std::string library_name;
  std::string purl_type;
  std::string purl_namespace;
  std::string license;

  /// The attributed version, or EMPTY when the matched files cannot separate
  /// two or more releases. Empty is a deliberate answer, not a failure: see
  /// `candidate_versions`.
  std::string version;

  /// Sorted, and populated ONLY when `version` is empty: the releases the
  /// evidence could not choose between. Asserting one of them would write a
  /// fabricated version into a document that drives vulnerability matching, so
  /// the library is named and the version is left open.
  std::vector<std::string> candidate_versions;

  std::string release_ref;     ///< upstream tag of the attributed release, if unique
  std::string release_commit;  ///< its dereferenced commit, if unique

  /// Copied from the index so `describe_match` is a pure function of the match
  /// and the evidence text says which corpus made the claim.
  std::string corpus_revision;

  std::size_t matched_files = 0;       ///< files under this root matching the attribution
  std::size_t files_considered = 0;    ///< files under this root that were hashable at all
  std::size_t release_file_count = 0;  ///< files the corpus holds for that release

  core::Confidence confidence = core::Confidence::Low;

  /// Hashable files under this root that are NOT part of the attributed
  /// release, sorted. This is the input T93 turns into a "modified" verdict;
  /// v1 only reports the set and draws no conclusion from it.
  std::vector<std::filesystem::path> unmatched_files;
};

/// Hash every hashable file under every vendor root in `file_index` and
/// attribute each root to at most one corpus release.
///
/// Matching is on CONTENT ALONE and is path-independent: a file matches
/// wherever upstream kept it. That is not a nicety. nightmare vendors
/// `include/FreeRTOSConfig.h` from upstream's
/// `examples/template_configuration/FreeRTOSConfig.h`, and vendor SDK drops
/// rearrange trees as a matter of course, so any path-keyed scheme misses them.
///
/// Only files under a vendor root are hashed, decided by the same
/// `heuristics::vendor_root_for` the vendored-source heuristic uses. That keeps
/// the cost proportional to vendored code rather than to the repository, and it
/// is what lets `cli` join these matches onto components by root path.
///
/// Bytes are hashed exactly as they sit on disk, with no line-ending or
/// whitespace normalization. A normalized digest would no longer be a SHA-256
/// anybody else can compute, and an operator has to be able to check a claim
/// with `sha256sum`. The consequence is real and accepted: a checkout that
/// rewrote line endings does not match. Fixing that belongs in the builder,
/// as additional index entries, not here.
///
/// Never throws (rule 1), never shells out and never touches the network
/// (rule 9): it is handed an already-loaded `Index`, never a path to fetch, the
/// same way `binscan` is handed paths and never trace records. Deterministic
/// (rule 3): roots are visited in sorted order, every tie-break is total, and
/// ratio comparisons are integer-only.
///
/// `root` must be the same directory `file_index` was built from.
[[nodiscard]] core::Result<std::vector<RootMatch>> match_vendored_files(
    const core::FileIndex& file_index, const std::filesystem::path& root, const Index& index,
    MatchLimits limits = {});

/// The `core::Evidence::detail` line for one match, e.g.
/// `"11 of 14 hashed files match freertos V11.1.0 (corpus 2026-11-02)"`.
///
/// Separate from the struct so the exact wording that reaches an SBOM is
/// testable without a filesystem. It deliberately contains no index PATH: that
/// is machine-dependent, and two machines scanning one tree must produce
/// byte-identical documents (rule 3).
[[nodiscard]] std::string describe_match(const RootMatch& match);

}  // namespace bomwerk::heuristics::fingerprint
