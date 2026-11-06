/* cJSON public header, trimmed for this fixture.
   Upstream writes its version as CJSON_VERSION_MAJOR, _MINOR and _PATCH,
   which the version-header heuristic reads. This copy has those three macros
   removed on purpose, so no header can version this directory and only a
   content match can identify it: the shape this fixture exists to show. */
#ifndef cJSON__h
#define cJSON__h

typedef struct cJSON cJSON;
cJSON *cJSON_Parse(const char *value);
void cJSON_Delete(cJSON *item);

#endif
