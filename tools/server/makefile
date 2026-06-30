# open62541.h (regenerated with encryption support) pulls in mbedtls headers,
# so the test server build mirrors the mbedtls include/link flags that the
# gem's ext/opcua_client/extconf.rb already applies.
MBEDTLS_DIR = ../../ext/opcua_client/mbedtls

all: server

server: open62541.o
	g++ -I../../ext/opcua_client -I$(MBEDTLS_DIR)/include server.cpp open62541.o -o opcua-server -L$(MBEDTLS_DIR) -lmbedtls -lmbedx509 -lmbedcrypto

# gnu99 (not strict c99) + _DARWIN_C_SOURCE so the BSD socket extensions
# open62541 needs (struct ip_mreq, IP_DROP_MEMBERSHIP) are exposed on macOS.
open62541.o:
	gcc -std=gnu99 -D_DARWIN_C_SOURCE -I$(MBEDTLS_DIR)/include -c ../../ext/opcua_client/open62541.c

clean:
	-rm *.o opcua-server
