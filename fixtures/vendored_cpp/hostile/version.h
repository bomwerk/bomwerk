/* version.h -- hostile fixture: the macro actually defined here is only a
   longer identifier that happens to start with a table macro name
   (MBEDTLS_VERSION_STRING_FULL vs. the table's MBEDTLS_VERSION_STRING).
   Must be rejected as a non-match rather than matched on the prefix. This
   filename also collides with xz-liblzma's table entry (both use
   "version.h"); neither signature's macro appears here, so both must fail
   cleanly. */
#define MBEDTLS_VERSION_STRING_FULL "mbed TLS 3.5.2"
