/* Written by this fixture, not by upstream cJSON, and deliberately absent from
   the corpus index beside it. It is what makes the match PARTIAL: three of the
   four hashed files in this directory are byte-identical to the pinned
   release and this one is not, which is the shape a vendor fork has. v1
   reports that count and draws no conclusion from it; naming it a fork is
   T93's job. */
#include "include/cJSON.h"

int cjson_local_patch_marker(void)
{
  return 1;
}
