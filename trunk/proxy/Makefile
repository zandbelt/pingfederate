all: clean proxy.zip

proxy.zip: proxy.war
	zip -r $@ README $<
	rm -rf proxy.war

proxy.war:
	mkdir -p proxy.war/WEB-INF/lib
	mkdir -p proxy.war/META-INF
	cp WebContent/WEB-INF/web.xml proxy.war/WEB-INF
	cp WebContent/META-INF/MANIFEST.MF proxy.war/META-INF
	cp WebContent/proxy.properties proxy.war/
	cp WebContent/index.jsp proxy.war/

clean:
	rm -rf proxy.war proxy.zip
