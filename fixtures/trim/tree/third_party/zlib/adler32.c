// Vendored source the fixture's trace compiles: this is what makes zlib's
// verdict "used" rest on evidence rather than on the manifest that declared it.
unsigned long adler32(unsigned long adler) { return adler + 1; }
