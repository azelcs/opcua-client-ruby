CC = gcc
AR = ar
CFLAGS = -Iinclude -Wall -Wextra -O2
CFLAGS += -fPIC
LIBDIR = library
OBJDIR = obj

# Source files for each library
SRCS_CRYPTO = $(LIBDIR)/aes.c $(LIBDIR)/aesni.c $(LIBDIR)/arc4.c $(LIBDIR)/aria.c $(LIBDIR)/asn1parse.c \
               $(LIBDIR)/asn1write.c $(LIBDIR)/base64.c $(LIBDIR)/bignum.c $(LIBDIR)/blowfish.c $(LIBDIR)/camellia.c \
               $(LIBDIR)/ccm.c $(LIBDIR)/chacha20.c $(LIBDIR)/chachapoly.c $(LIBDIR)/cipher.c $(LIBDIR)/cipher_wrap.c \
               $(LIBDIR)/constant_time.c $(LIBDIR)/cmac.c $(LIBDIR)/ctr_drbg.c $(LIBDIR)/des.c $(LIBDIR)/dhm.c \
               $(LIBDIR)/ecdh.c $(LIBDIR)/ecdsa.c $(LIBDIR)/ecjpake.c $(LIBDIR)/ecp.c $(LIBDIR)/ecp_curves.c \
               $(LIBDIR)/entropy.c $(LIBDIR)/entropy_poll.c $(LIBDIR)/error.c $(LIBDIR)/gcm.c $(LIBDIR)/havege.c \
               $(LIBDIR)/hkdf.c $(LIBDIR)/hmac_drbg.c $(LIBDIR)/md.c $(LIBDIR)/md2.c $(LIBDIR)/md4.c $(LIBDIR)/md5.c \
               $(LIBDIR)/memory_buffer_alloc.c $(LIBDIR)/nist_kw.c $(LIBDIR)/oid.c $(LIBDIR)/padlock.c $(LIBDIR)/pem.c \
               $(LIBDIR)/pk.c $(LIBDIR)/pk_wrap.c $(LIBDIR)/pkcs12.c $(LIBDIR)/pkcs5.c $(LIBDIR)/pkparse.c \
               $(LIBDIR)/pkwrite.c $(LIBDIR)/platform.c $(LIBDIR)/platform_util.c $(LIBDIR)/poly1305.c \
               $(LIBDIR)/psa_crypto.c $(LIBDIR)/psa_crypto_aead.c $(LIBDIR)/psa_crypto_cipher.c $(LIBDIR)/psa_crypto_client.c \
               $(LIBDIR)/psa_crypto_driver_wrappers.c $(LIBDIR)/psa_crypto_ecp.c $(LIBDIR)/psa_crypto_hash.c \
               $(LIBDIR)/psa_crypto_mac.c $(LIBDIR)/psa_crypto_rsa.c $(LIBDIR)/psa_crypto_se.c $(LIBDIR)/psa_crypto_slot_management.c \
               $(LIBDIR)/psa_crypto_storage.c $(LIBDIR)/psa_its_file.c $(LIBDIR)/ripemd160.c $(LIBDIR)/rsa.c \
               $(LIBDIR)/rsa_internal.c $(LIBDIR)/sha1.c $(LIBDIR)/sha256.c $(LIBDIR)/sha512.c $(LIBDIR)/threading.c \
               $(LIBDIR)/timing.c $(LIBDIR)/version.c $(LIBDIR)/version_features.c $(LIBDIR)/xtea.c

SRCS_X509 = $(LIBDIR)/certs.c $(LIBDIR)/pkcs11.c $(LIBDIR)/x509.c $(LIBDIR)/x509_create.c $(LIBDIR)/x509_crl.c \
             $(LIBDIR)/x509_crt.c $(LIBDIR)/x509_csr.c $(LIBDIR)/x509write_crt.c $(LIBDIR)/x509write_csr.c

SRCS_TLS = $(LIBDIR)/debug.c $(LIBDIR)/net_sockets.c $(LIBDIR)/ssl_cache.c $(LIBDIR)/ssl_ciphersuites.c \
            $(LIBDIR)/ssl_cli.c $(LIBDIR)/ssl_cookie.c $(LIBDIR)/ssl_msg.c $(LIBDIR)/ssl_srv.c $(LIBDIR)/ssl_ticket.c \
            $(LIBDIR)/ssl_tls.c $(LIBDIR)/ssl_tls13_keys.c

# Object files for each library
OBJS_CRYPTO = $(SRCS_CRYPTO:$(LIBDIR)/%.c=$(OBJDIR)/%.o)
OBJS_X509 = $(SRCS_X509:$(LIBDIR)/%.c=$(OBJDIR)/%.o)
OBJS_TLS = $(SRCS_TLS:$(LIBDIR)/%.c=$(OBJDIR)/%.o)

# Output libraries
LIBCRYPTO = libmbedcrypto.a
LIBX509 = libmbedx509.a
LIBTLS = libmbedtls.a

# Default target
all: $(LIBCRYPTO) $(LIBX509) $(LIBTLS)

# Build object files
$(OBJDIR)/%.o: $(LIBDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Build static libraries
$(LIBCRYPTO): $(OBJS_CRYPTO)
	$(AR) rcs $@ $(OBJS_CRYPTO)

$(LIBX509): $(OBJS_X509)
	$(AR) rcs $@ $(OBJS_X509)

$(LIBTLS): $(OBJS_TLS)
	$(AR) rcs $@ $(OBJS_TLS)

# Clean up build artifacts
clean:
	rm -rf $(OBJDIR) $(LIBCRYPTO) $(LIBX509) $(LIBTLS)
