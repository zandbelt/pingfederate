MY_APXS=/opt/local/apache2/bin/apxs
MY_CFLAGS=-DOIDC_DEBUG=APLOG_INFO
MY_LDFLAGS=-lcurl

MY_SOURCES = \
	src/mod_oidc.c \
	src/oidc_proto.c \
	src/oidc_crypto.c \
	src/oidc_config.c \
	src/oidc_util.c \
	src/oidc_authz.c \
	src/oidc_session.c \
	src/oidc_cache.c \
	src/oidc_metadata.c \
	src/apr_json_decode.c

MY_MODULE = src/mod_oidc.la

$(MY_MODULE): $(MY_SOURCES)
	$(MY_APXS) $(MY_LDFLAGS) $(MY_CFLAGS) -c $(MY_SOURCES)

compile: $(MY_MODULE)

install: compile
	@echo "-"$*"-" "-"$?"-" "-"$%"-" "-"$@"-" "-"$<"-"
	sudo $(MY_APXS) -i $(MY_MODULE)

run: install clean
	sudo /opt/local/apache2/bin/apachectl restart
	tail -f /opt/local/apache2/logs/error_log

clean:
	-rm -f src/*.o src/*.lo src/*.la src/*.slo 
	-rm -rf src/.libs
