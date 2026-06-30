require 'mkmf'

# Get the absolute path to the mbedtls directory
mbedtls_dir = File.expand_path('mbedtls', __dir__)

# Build the Mbed TLS static libraries
Dir.chdir(mbedtls_dir) do
  system('make clean')  # Clean previous build artifacts
  system('make')        # Build the .a files
end

# Add the Mbed TLS include and library paths
mbedtls_include = File.expand_path('include', mbedtls_dir)
mbedtls_library = mbedtls_dir  # Path to the .a files

$CFLAGS << " -I#{mbedtls_include}"
$LDFLAGS << " -L#{mbedtls_library} -lmbedtls -lmbedcrypto -lmbedx509"

create_makefile('opcua_client/opcua_client')
