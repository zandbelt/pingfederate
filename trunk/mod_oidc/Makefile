MY_APXS=/opt/local/apache2/bin/apxs
MY_LDFLAGS=-lcurl

MY_SOURCES = src/apr_json_decode.c src/oidc_crypto.c src/oidc_config.c src/oidc_util.c src/oidc_authz.c
MY_OBJECTS = src/apr_json_decode.slo src/oidc_crypto.slo src/oidc_config.slo src/oidc_util.slo src/oidc_authz.slo

src/mod_oidc.la: src/mod_oidc.c $(MY_OBJECTS)
	$(MY_APXS) $(MY_LDFLAGS) $(MY_CFLAGS) -c $< $(MY_SOURCES)

%.slo: %.c
	$(MY_APXS) $(MY_LDFLAGS) $(MY_CFLAGS) -o $@ -c $<

compile: src/mod_oidc.la

install: src/mod_oidc.la
	@echo "-"$*"-" "-"$?"-" "-"$%"-" "-"$@"-" "-"$<"-"
	sudo $(MY_APXS) -i $?

clean:
	-rm -f src/*.o src/*.lo src/*.la src/*.slo 
	-rm -rf src/.libs
