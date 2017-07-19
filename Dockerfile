#!/usr/bin/docker --force-rm -f

FROM alpine:3.6 AS O-Saft
MAINTAINER Achim <achim@owasp.org>

LABEL \
	VERSION="17.06.17"	\
	\
	DESCRIPTION="Build O-Saft docker image (with Peter Mosman's openssl)"	\
	SYNOPSIS="docker build --force-rm --rm -f ./Dockerfile -t owasp/o-saft:17.06.17 -t owasp/o-saft ." \
	DETAILS="Please see https://github.com/OWASP/O-Saft/raw/master/o-saft-docker" \
	SOURCE0="https://github.com/OWASP/O-Saft/raw/master/Dockerfile" \
	SOURCE1="https://github.com/OWASP/O-Saft/raw/master/o-saft.tgz" \
	SOURCE2="https://github.com/PeterMosmans/openssl/archive/1.0.2-chacha.tar.gz" \
	SOURCE3="http://search.cpan.org/CPAN/authors/id/S/SU/SULLR/IO-Socket-SSL-2.049.tar.gz" \
	SID="@(#) Dockerfile 1.2 17/07/20 01:00:14" \
	AUTHOR="Achim Hoffmann"	

# Install required packages
RUN apk update && \
    apk add --no-cache wget perl perl-net-dns perl-net-ssleay tcl tk ncurses

ENV OSAFT_DIR	/O-Saft
ENV OPENSSL_DIR	/openssl
ENV OPENSSL_VERSION  1.0.2-chacha

WORKDIR	/

# Pull O-Saft
RUN \
	mkdir $OSAFT_DIR			&& \
	adduser -D -h ${OSAFT_DIR} osaft	&& \
	\
	wget --no-check-certificate \
		https://github.com/OWASP/O-Saft/raw/master/o-saft.tgz \
		-O o-saft.tgz 			&& \
	echo "a55702d69314b8eda52e921e35b89aef9eef02b14c870b3077fbddf3af91320d  o-saft.tgz" | sha256sum -c && \
	\
	tar   -xzf o-saft.tgz			&& \
	chown -R root:root   $OSAFT_DIR		&& \
	chown -R osaft:osaft $OSAFT_DIR/contrib	&& \
	chown    osaft:osaft $OSAFT_DIR/.o-saft.pl	&& \
	rm    -f o-saft.tgz


# Pull and build IO::Socket::SSL (July/2017: missing in alpine's perl)
RUN \
	# pull and extract module
	mkdir /src_iosocket			&& \
	wget --no-check-certificate \
		http://search.cpan.org/CPAN/authors/id/S/SU/SULLR/IO-Socket-SSL-2.049.tar.gz \
		-O iosocket.tgz 		&& \
	tar   -xzf iosocket.tgz -C /src_iosocket --strip-components=1	&& \
	cd    /src_iosocket			&& \
	# build {
	# install development tools
	apk add --no-cache make			&& \
	echo n | perl Makefile.PL		&& \
	make && make test && make install	&& \
	# cleanup
	apk del --purge make			&& \
	# build }
	cd   /					&& \
	rm   -r /src_iosocket iosocket.tgz

# Pull and build enhanced openssl
RUN \
	# pull and extract module
	mkdir $OPENSSL_DIR /src_openssl		&& \
	wget --no-check-certificate \
		https://github.com/PeterMosmans/openssl/archive/1.0.2-chacha.tar.gz \
		-O openssl.tgz 			&& \
	\
	tar   -xzf openssl.tgz -C /src_openssl --strip-components=1	&& \
	cd    /src_openssl			&& \
	# build {
	# install development tools
	apk add --no-cache musl-dev gcc make zlib-dev	&& \
	./config --prefix=$OPENSSL_DIR --openssldir=$OPENSSL_DIR/ssl \
		enable-zlib enable-ssl3  enable-rc5  enable-rc2  enable-GOST \
		enable-cms  enable-md2   enable-mdc2 enable-ec   enable-ec2m \
		enable-ecdh enable-ecdsa enable-seed enable-idea enable-camellia \
		enable-rfc3779 enable-ec_nistp_64_gcc_128 \
		-static experimental-jpake -DOPENSSL_USE_BUILD_DATE	&& \
	make depend && make && make report && make install	&& \
	# simple test
	echo -e "# number of ciphers $OPENSSL_DIR/bin/openssl: " && \
	$OPENSSL_DIR/bin/openssl ciphers -V ALL:COMPLEMENTOFALL:aNULL|wc -l && \
	# cleanup
	apk del --purge musl-dev gcc make zlib-dev	&& \
	# build }
	cd   /					&& \
	rm   -r /src_openssl openssl.tgz

# Install traditional openssl
# RUN apk add --no-cache openssl

WORKDIR $OSAFT_DIR
ENV     TERM xterm
ENV     PATH ${OSAFT_DIR}:${OSAFT_DIR}/contrib:${OPENSSL_DIR}/bin:$PATH
USER    osaft
#RUN     o-saft-docker usage

ENTRYPOINT ["perl", "/O-Saft/o-saft.pl"]
CMD  ["--help=docker"]

# vim:set ft=dockerfile:
