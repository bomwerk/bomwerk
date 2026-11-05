/* cJSON implementation, trimmed for this fixture. Stands in for an upstream
   source file whose bytes the corpus knows. */
#include "include/cJSON.h"

#include <stdlib.h>

struct cJSON
{
  struct cJSON *next;
  char *valuestring;
};

cJSON *cJSON_Parse(const char *value)
{
  (void)value;
  return NULL;
}

void cJSON_Delete(cJSON *item)
{
  free(item);
}
