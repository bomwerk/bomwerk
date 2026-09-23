// ctest unit test for the CVSS v3.0/v3.1 base-score scorer (framework-free).
#include <cmath>
#include <cstdio>
#include <string_view>

#include "core/cvss.hpp"
#include "support/check.hpp"

using bomwerk::core::CvssScore;
using bomwerk::core::score_cvss_vector;
using bomwerk::core::SeverityRating;
using bomwerk::core::to_string;

namespace
{

bool nearly_equal(double left, double right)
{
  return std::fabs(left - right) < 0.05;  // scores carry one decimal place
}

}  // namespace

int main()
{
  // Given the canonical "worst case" vector, when scored, then it is 9.8 /
  // Critical: the known-answer from the CVSS v3.1 specification examples.
  {
    const CvssScore score = score_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    BOMWERK_TEST_CHECK(score.has_score);
    BOMWERK_TEST_CHECK(nearly_equal(score.score, 9.8));
    BOMWERK_TEST_CHECK(score.rating == SeverityRating::Critical);
  }

  // Given a scope-changed vector (CVE-2020-1472 "Zerologon" shape), when
  // scored, then it reaches the 10.0 ceiling: exercises the scope-changed
  // impact/exploitability path and the min(…, 10) clamp.
  {
    const CvssScore score = score_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    BOMWERK_TEST_CHECK(score.has_score);
    BOMWERK_TEST_CHECK(nearly_equal(score.score, 10.0));
    BOMWERK_TEST_CHECK(score.rating == SeverityRating::Critical);
  }

  // Given a mid-range vector, when scored, then it lands in the Medium band :
  // guards the rating thresholds and the scope-unchanged formula.
  {
    const CvssScore score = score_cvss_vector("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
    BOMWERK_TEST_CHECK(score.has_score);
    BOMWERK_TEST_CHECK(nearly_equal(score.score, 5.5));
    BOMWERK_TEST_CHECK(score.rating == SeverityRating::Medium);
  }

  // Given an all-None-impact vector, when scored, then impact is 0 => base
  // score 0.0 / None (not Unknown: it IS scored, and the score is zero).
  {
    const CvssScore score = score_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
    BOMWERK_TEST_CHECK(score.has_score);
    BOMWERK_TEST_CHECK(nearly_equal(score.score, 0.0));
    BOMWERK_TEST_CHECK(score.rating == SeverityRating::None);
  }

  // Given a CVSS v3.0 vector, when scored, then the same formula applies (the
  // prefix is accepted, the score matches its v3.1 twin).
  {
    const CvssScore score = score_cvss_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    BOMWERK_TEST_CHECK(score.has_score);
    BOMWERK_TEST_CHECK(nearly_equal(score.score, 9.8));
  }

  // Given vectors we do not score: a CVSS v2 vector, a v4 vector, a bare
  // score, a vector missing a mandatory metric, and outright garbage: when
  // scored, then each is honestly Unknown/unscored, never a misleading 0.
  {
    BOMWERK_TEST_CHECK(!score_cvss_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P").has_score);  // v2
    BOMWERK_TEST_CHECK(!score_cvss_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N").has_score);
    BOMWERK_TEST_CHECK(!score_cvss_vector("7.5").has_score);                 // numeric, no vector
    BOMWERK_TEST_CHECK(!score_cvss_vector("").has_score);                    // empty
    BOMWERK_TEST_CHECK(!score_cvss_vector("CVSS:3.1/AV:N/AC:L").has_score);  // missing metrics
    BOMWERK_TEST_CHECK(!score_cvss_vector("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
                            .has_score);  // bad AV value
  }

  // Given each rating, when labeled, then the display string round-trips.
  {
    BOMWERK_TEST_CHECK(std::string_view(to_string(SeverityRating::Critical)) == "Critical");
    BOMWERK_TEST_CHECK(std::string_view(to_string(SeverityRating::Unknown)) == "Unknown");
  }

  std::puts("test_cvss: OK");
  return 0;
}
