MY_APXS=/opt/local/apache2/bin/apxs
MY_LDFLAGS=-lcurl

src/mod_oidc.la: src/mod_oidc.c src/apr_json_decode.c
	$(MY_APXS) $(MY_LDFLAGS) $(MY_CFLAGS) -c $< src/apr_json_decode.c

compile: src/mod_oidc.la

install: src/mod_oidc.la
	@echo "-"$*"-" "-"$?"-" "-"$%"-" "-"$@"-" "-"$<"-"
	sudo $(MY_APXS) -i $?

clean:
	-rm -f src/*.o src/*.lo src/*.la src/*.slo 
	-rm -rf src/.libs

