FetchContent_Declare(${NAME}
  GIT_REPOSITORY https://github.com/${ORG}/${REPO}.git
  GIT_TAG ${VERSION})
FetchContent_MakeAvailable(${NAME})
CPMAddPackage("gh:${ORG}/${REPO}@${VERSION}")
