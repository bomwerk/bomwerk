// A second translation unit archived into a static library, so the trace
// carries an `ar` invocation and a link line with a `.a` input — the shapes
// The link scan needs to attribute a statically linked component.
const char* greeting(void)
{
  return "hello from bomwerk";
}
