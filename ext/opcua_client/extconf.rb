require 'mkmf'

# Add the Mbed TLS include and library paths
mbedtls_include = File.expand_path('mbedtls/include', __dir__)
mbedtls_library = File.expand_path('mbedtls', __dir__)  # Path to the .a files

$CFLAGS << " -I#{mbedtls_include}"
$LDFLAGS << " -L#{mbedtls_library} -lmbedtls -lmbedcrypto -lmbedx509"

create_makefile('opcua_client/opcua_client')
