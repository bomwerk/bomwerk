/* Stand-in for vendored zlib source. This component has sources but no
   prebuilt binary, so the binary pass has nothing to say about it — which is
   half of what this fixture pins. */
unsigned long adler32(unsigned long adler, const unsigned char* buffer, unsigned length);
