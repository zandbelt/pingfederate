MY_APXS=/opt/local/apache2/bin/apxs
MY_LDFLAGS=-lcurl

MY_SOURCES = \
	src/mod_oidc.c \
	src/oidc_crypto.c \
	src/oidc_config.c \
	src/oidc_util.c \
	src/oidc_authz.c \
	src/oidc_session.c \
	src/oidc_cache.c \
	src/apr_json_decode.c
	
src/mod_oidc.la: $(MY_SOURCES)
	$(MY_APXS) $(MY_LDFLAGS) $(MY_CFLAGS) -c $(MY_SOURCES)

compile: src/mod_oidc.la

install: src/mod_oidc.la
	@echo "-"$*"-" "-"$?"-" "-"$%"-" "-"$@"-" "-"$<"-"
	sudo $(MY_APXS) -i $?

clean:
	-rm -f src/*.o src/*.lo src/*.la src/*.slo 
	-rm -rf src/.libs
