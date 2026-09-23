#include "vuln/delta.hpp"

namespace bomwerk::vuln
{

bool PurlAdvisoryDelta::is_unchanged() const
{
  return added_advisory_ids.empty() && modified_advisory_ids.empty() &&
         removed_advisory_ids.empty();
}

PurlAdvisoryDelta diff_advisory_revisions(const std::string& purl,
                                          const std::vector<AdvisoryRevision>& previous,
                                          const std::vector<AdvisoryRevision>& current)
{
  PurlAdvisoryDelta delta;
  delta.purl = purl;

  std::size_t previous_index = 0;
  std::size_t current_index = 0;
  while (previous_index < previous.size() && current_index < current.size())
  {
    const AdvisoryRevision& previous_revision = previous[previous_index];
    const AdvisoryRevision& current_revision = current[current_index];
    if (previous_revision.advisory_id == current_revision.advisory_id)
    {
      if (previous_revision.modified != current_revision.modified)
      {
        delta.modified_advisory_ids.push_back(current_revision.advisory_id);
      }
      ++previous_index;
      ++current_index;
    }
    else if (previous_revision.advisory_id < current_revision.advisory_id)
    {
      // Present before, absent now: this advisory no longer applies.
      delta.removed_advisory_ids.push_back(previous_revision.advisory_id);
      ++previous_index;
    }
    else
    {
      // Present now, absent before: newly reported.
      delta.added_advisory_ids.push_back(current_revision.advisory_id);
      ++current_index;
    }
  }
  for (; previous_index < previous.size(); ++previous_index)
  {
    delta.removed_advisory_ids.push_back(previous[previous_index].advisory_id);
  }
  for (; current_index < current.size(); ++current_index)
  {
    delta.added_advisory_ids.push_back(current[current_index].advisory_id);
  }

  // Both inputs are sorted-and-deduplicated by contract, so the merge above
  // already emits each output list in sorted order with no duplicates :
  // nothing further to sort here.
  return delta;
}

}  // namespace bomwerk::vuln
