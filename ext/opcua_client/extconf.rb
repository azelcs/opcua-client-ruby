require 'mkmf'

# Add the include and library paths for the vendored Mbed TLS
# mbedtls_include = File.expand_path('mbedtls/include', __dir__)
# mbedtls_library = File.expand_path('mbedtls', __dir__)

# $CFLAGS << " -I#{mbedtls_include}"
# $LDFLAGS << " #{mbedtls_library}/libmbedtls.a #{mbedtls_library}/libmbedcrypto.a #{mbedtls_library}/libmbedx509.a"

# # Check for required headers and libraries
# have_header('mbedtls/md.h') || abort('mbedtls/md.h not found. Please ensure Mbed TLS is included.')
create_makefile('opcua_client/opcua_client')
