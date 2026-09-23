CPMAddPackage("gh:owner/repo#a1b2c3d4")
FetchContent_Declare(frag
  GIT_REPOSITORY https://example.com/a/b.git#not-a-comment
  GIT_TAG main)
