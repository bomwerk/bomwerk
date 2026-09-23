#pragma once
#include <cstdint>
#include <string>

namespace bomwerk::core
{

/// Format `epoch_seconds` (Unix epoch, UTC) as "YYYY-MM-DDTHH:MM:SSZ", via
/// `gmtime_r`: never `localtime_r`, so (like `current_timestamp_iso8601`
/// below, which is built on this) no daylight-saving transition can occur.
///
/// Unlike `current_timestamp_iso8601`, this formats a CALLER-SUPPLIED
/// instant and has no `SOURCE_DATE_EPOCH` behavior of its own: it is the
/// right building block for an OPERATIONAL timestamp: a supervised cycle's
/// `observed_at`, a finding's `first_seen_at`/`notified_at`: never for
/// reproducible build output, which stays `current_timestamp_iso8601`'s job.
[[nodiscard]] std::string format_epoch_iso8601(std::int64_t epoch_seconds);

/// Format `epoch_seconds` as an RFC-5322 date-time in UTC, e.g.
/// "Wed, 02 Sep 2026 02:00:00 +0000": the form a mail `Date:` header
/// requires, which ISO-8601 is not accepted in.
///
/// The day and month abbreviations are a fixed English table, NEVER
/// `strftime`'s `%a`/`%b`: those read the C locale, so a host running under a
/// non-English locale would emit a header no mail client can parse. Same
/// `gmtime_r` and same "operational instant, no `SOURCE_DATE_EPOCH`
/// behaviour" contract as `format_epoch_iso8601` above; the `+0000` offset is
/// literal because the conversion is always UTC.
[[nodiscard]] std::string format_epoch_rfc5322(std::int64_t epoch_seconds);

/// ISO-8601 UTC timestamp ("YYYY-MM-DDTHH:MM:SSZ") for the current moment,
/// or for `SOURCE_DATE_EPOCH` when it is set to a valid non-negative integer
/// (reproducible-builds.org): honoring it is rule 3's "two runs must be
/// byte-identical" applied to every timestamp bomwerk emits.
///
/// Always UTC via `gmtime_r` (never `localtime_r`): the epoch-to-UTC
/// conversion has no timezone offset and therefore no daylight-saving
/// transition: DST is strictly a local/zoned-time concept and cannot occur
/// here.
///
/// CAUTION: a self-reported "when this document was generated" value, not a
/// tamper-evident one: like any local clock reading it can be backdated by
/// whoever runs `bomwerk` (via this env var or the system clock itself; this
/// function makes neither easier nor harder than before). It is a
/// build-reproducibility mechanism, not a trust anchor. Never use it as
/// evidence of *when* a vulnerability became known for CRA 24h/72h/14d
/// reporting-clock purposes: that timestamp must come from the future
/// long-running supervisor, anchored to real wall-clock
/// time at the moment it observes a feed match, never to `SOURCE_DATE_EPOCH`.
[[nodiscard]] std::string current_timestamp_iso8601();

}  // namespace bomwerk::core
