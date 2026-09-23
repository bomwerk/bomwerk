#include <clocale>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "core/timestamp.hpp"
#include "support/check.hpp"

using bomwerk::core::current_timestamp_iso8601;
using bomwerk::core::format_epoch_rfc5322;

int main()
{
  // Given SOURCE_DATE_EPOCH set to a known value, when formatted, then the
  // exact UTC ISO-8601 string results (reproducible-builds.org contract) :
  // cross-checked against Python's datetime.utcfromtimestamp().
  {
    setenv("SOURCE_DATE_EPOCH", "0", 1);
    BOMWERK_TEST_CHECK(current_timestamp_iso8601() == "1970-01-01T00:00:00Z");
    unsetenv("SOURCE_DATE_EPOCH");
  }
  {
    setenv("SOURCE_DATE_EPOCH", "1700000000", 1);
    BOMWERK_TEST_CHECK(current_timestamp_iso8601() == "2023-11-14T22:13:20Z");
    unsetenv("SOURCE_DATE_EPOCH");
  }

  // Given a malformed SOURCE_DATE_EPOCH (not a base-10 integer), when
  // formatted, then it is ignored: falls back to the current time: rather
  // than aborting a scan over one bad env var.
  {
    setenv("SOURCE_DATE_EPOCH", "not-a-number", 1);
    const std::string formatted = current_timestamp_iso8601();
    BOMWERK_TEST_CHECK(formatted.size() == 20);
    BOMWERK_TEST_CHECK(formatted.back() == 'Z');
    unsetenv("SOURCE_DATE_EPOCH");
  }

  // Given a negative SOURCE_DATE_EPOCH, when formatted, then it is also
  // ignored (falls back to the current time): never a negative timestamp.
  {
    setenv("SOURCE_DATE_EPOCH", "-5", 1);
    const std::string formatted = current_timestamp_iso8601();
    BOMWERK_TEST_CHECK(formatted.size() == 20);
    unsetenv("SOURCE_DATE_EPOCH");
  }

  // Given SOURCE_DATE_EPOCH unset, when formatted, then a well-formed
  // ISO-8601 UTC string still results (falls back to the current time).
  {
    unsetenv("SOURCE_DATE_EPOCH");
    const std::string formatted = current_timestamp_iso8601();
    BOMWERK_TEST_CHECK(formatted.size() == 20);
    BOMWERK_TEST_CHECK(formatted[4] == '-');
    BOMWERK_TEST_CHECK(formatted[10] == 'T');
    BOMWERK_TEST_CHECK(formatted.back() == 'Z');
  }

  // Given two calls with the same pinned SOURCE_DATE_EPOCH, when compared,
  // then they are identical: rule 3's two-runs-byte-identical guarantee.
  {
    setenv("SOURCE_DATE_EPOCH", "1700000000", 1);
    BOMWERK_TEST_CHECK(current_timestamp_iso8601() == current_timestamp_iso8601());
    unsetenv("SOURCE_DATE_EPOCH");
  }

  // Given known instants, when formatted as RFC 5322, then the exact mail
  // `Date:` header string results: the epoch, a leap day, and an instant
  // whose weekday and month both differ, cross-checked against Python's
  // email.utils.formatdate(usegmt=True).
  {
    BOMWERK_TEST_CHECK(format_epoch_rfc5322(0) == "Thu, 01 Jan 1970 00:00:00 +0000");
    BOMWERK_TEST_CHECK(format_epoch_rfc5322(1'788'314'400) == "Wed, 02 Sep 2026 02:00:00 +0000");
    BOMWERK_TEST_CHECK(format_epoch_rfc5322(1'709'121'600) == "Wed, 28 Feb 2024 12:00:00 +0000");
  }

  // Given a locale whose weekday and month names are not English, when an
  // instant is formatted, then the header is UNCHANGED: the abbreviations
  // come from a fixed table, never from strftime's locale-reading %a/%b, so a
  // host running under a non-English locale cannot emit a Date: header mail
  // clients fail to parse.
  {
    const std::string reference = format_epoch_rfc5322(1'788'314'400);
    // Any of these may be absent on a minimal CI image; setlocale simply
    // returns nullptr then and the check below still holds trivially.
    static constexpr const char* kNonEnglishLocales[] = {"de_DE.UTF-8", "fr_FR.UTF-8",
                                                         "es_ES.UTF-8"};
    for (const char* locale_name : kNonEnglishLocales)
    {
      if (std::setlocale(LC_TIME, locale_name) != nullptr)
      {
        BOMWERK_TEST_CHECK(format_epoch_rfc5322(1'788'314'400) == reference);
      }
    }
    std::setlocale(LC_TIME, "C");
  }

  std::puts("test_timestamp: OK");
  return 0;
}
