/* cJSON public header, trimmed for this fixture.
   The version appears ONLY as three numeric macros, never as one quoted
   string, which is exactly why the version-header heuristic cannot read it
   and why this directory needs a content match to be identified at all. */
#ifndef cJSON__h
#define cJSON__h

#define CJSON_VERSION_MAJOR 1
#define CJSON_VERSION_MINOR 7
#define CJSON_VERSION_PATCH 15

typedef struct cJSON cJSON;
cJSON *cJSON_Parse(const char *value);
void cJSON_Delete(cJSON *item);

#endif
