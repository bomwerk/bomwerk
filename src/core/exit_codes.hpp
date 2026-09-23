#pragma once

namespace bomwerk::core
{

/// Exit-code contract (docs/CONTRIBUTING.md hard rule 2). Every command returns one of
/// these three values; never add or change them without a human decision.
inline constexpr int kExitClean = 0;
inline constexpr int kExitCompletedWithWarnings = 1;
inline constexpr int kExitIncomplete = 2;

/// The three values above are a SEVERITY ORDER, not merely three distinct
/// numbers: at least one call site composes "the worse of two outcomes" as
/// `std::max` over them rather than an explicit
/// if/else chain naming each constant. This assertion is what turns that
/// reliance into an enforced contract instead of an incidental property of
/// three independently-declared values: reordering or renumbering these
/// constants (still a human decision, per the doc comment above) fails the
/// build here rather than silently breaking that one call site.
static_assert(kExitClean < kExitCompletedWithWarnings &&
                  kExitCompletedWithWarnings < kExitIncomplete,
              "exit code severity order is relied upon by std::max-based composition");

/// `scan --fail-on` policy: which outcomes should be visible to
/// a caller as a non-zero exit code. This never decides what IS a warning or
/// an incomplete scan: it only remaps an already-computed exit code, so it
/// composes with the constants above rather than replacing their meaning.
enum class FailOnThreshold
{
  Warnings,    ///< default: exit 1 on any warning, exit 2 if incomplete (today's behavior)
  Incomplete,  ///< exit 0 even with warnings; only exit 2 on a genuinely incomplete scan
  None,        ///< never exit non-zero
};

/// Remaps a command's already-computed exit code per `FailOnThreshold`. Pure
/// and total: a muted exit code must never mute the diagnostics that led to
/// it, so this touches only the return value, never warnings or artifacts.
constexpr int apply_fail_on_threshold(int natural_exit_code, FailOnThreshold fail_on_threshold)
{
  if (fail_on_threshold == FailOnThreshold::None)
  {
    return kExitClean;
  }
  if (fail_on_threshold == FailOnThreshold::Incomplete &&
      natural_exit_code == kExitCompletedWithWarnings)
  {
    return kExitClean;
  }
  return natural_exit_code;
}

}  // namespace bomwerk::core
