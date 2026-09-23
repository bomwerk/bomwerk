#include "core/timestamp.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>

namespace bomwerk::core
{
namespace
{

/// Parses `SOURCE_DATE_EPOCH` per reproducible-builds.org: a non-negative
/// base-10 integer of seconds since the Unix epoch. Anything else (unset,
/// empty, malformed, negative) is not an error: it just means "use the
/// current time": an environment variable must never abort a scan.
bool try_parse_source_date_epoch(std::time_t& epoch_seconds)
{
  const char* raw_value = std::getenv("SOURCE_DATE_EPOCH");
  if (raw_value == nullptr || *raw_value == '\0')
  {
    return false;
  }
  char* parse_end = nullptr;
  const long long parsed_seconds = std::strtoll(raw_value, &parse_end, 10);
  if (parse_end == raw_value || *parse_end != '\0' || parsed_seconds < 0)
  {
    return false;
  }
  epoch_seconds = static_cast<std::time_t>(parsed_seconds);
  return true;
}

}  // namespace

std::string format_epoch_iso8601(std::int64_t epoch_seconds)
{
  const std::time_t time_value = static_cast<std::time_t>(epoch_seconds);

  std::tm utc_time{};
  // POSIX; matches the macOS/Linux CI matrix. gmtime_r converts the epoch
  // straight to UTC broken-down time: no local timezone is consulted, so no
  // daylight-saving transition is possible (DST only affects zoned time).
  gmtime_r(&time_value, &utc_time);

  constexpr std::size_t kIso8601BufferSize = 32;  // "YYYY-MM-DDTHH:MM:SSZ" + slack
  char formatted[kIso8601BufferSize];
  std::strftime(formatted, sizeof(formatted), "%Y-%m-%dT%H:%M:%SZ", &utc_time);
  return std::string(formatted);
}

std::string format_epoch_rfc5322(std::int64_t epoch_seconds)
{
  const std::time_t time_value = static_cast<std::time_t>(epoch_seconds);

  std::tm utc_time{};
  gmtime_r(&time_value, &utc_time);

  // Fixed English tables, never strftime's %a/%b: those read the C locale,
  // and a Date: header a mail client cannot parse is worse than none.
  static constexpr const char* kWeekdayNames[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static constexpr const char* kMonthNames[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  // gmtime_r always fills these in range; clamping rather than trusting keeps
  // a hypothetical bad value from indexing off the end of either table.
  const int weekday_index = (utc_time.tm_wday >= 0 && utc_time.tm_wday <= 6) ? utc_time.tm_wday : 0;
  const int month_index = (utc_time.tm_mon >= 0 && utc_time.tm_mon <= 11) ? utc_time.tm_mon : 0;

  constexpr std::size_t kRfc5322BufferSize = 64;  // "Www, DD Mmm YYYY HH:MM:SS +0000" + slack
  char formatted[kRfc5322BufferSize];
  std::snprintf(formatted, sizeof(formatted), "%s, %02d %s %04d %02d:%02d:%02d +0000",
                kWeekdayNames[weekday_index], utc_time.tm_mday, kMonthNames[month_index],
                utc_time.tm_year + 1900, utc_time.tm_hour, utc_time.tm_min, utc_time.tm_sec);
  return std::string(formatted);
}

std::string current_timestamp_iso8601()
{
  std::time_t epoch_seconds{};
  if (!try_parse_source_date_epoch(epoch_seconds))
  {
    epoch_seconds = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  }
  return format_epoch_iso8601(static_cast<std::int64_t>(epoch_seconds));
}

}  // namespace bomwerk::core
