#!/usr/bin/docker --force-rm -f

FROM alpine:3.6 AS O-Saft
MAINTAINER Achim <achim@owasp.org>

LABEL \
	DESCRIPTION="Build O-Saft docker image"	\
	SYNOPSIS="docker build --force-rm -f ./Dockerfile -t owasp/o-saft:17.07.17" \
	DETAILS="Please see https://github.com/OWASP/O-Saft/raw/master/o-saft-docker" \
	SOURCE="https://github.com/OWASP/O-Saft/raw/master/Dockerfile" \
	SID="@(#) Dockerfile 1.1 17/07/19 00:57:15" \
	VERSION="17.06.17"	\
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
		-O osaft.tgz 			&& \
	echo "a55702d69314b8eda52e921e35b89aef9eef02b14c870b3077fbddf3af91320d  osaft.tgz" | sha256sum -c && \
	\
	tar   -xzf osaft.tgz			&& \
	chown -R root:root   $OSAFT_DIR		&& \
	chown -R osaft:osaft $OSAFT_DIR/contrib	&& \
	chown    osaft:osaft $OSAFT_DIR/.o-saft.pl	&& \
	rm    -f osaft.tgz


# Pull and build IO::Socket::SSL (July/2017: missing in alpine's perl)
RUN \
	# install development tools
	apk add --no-cache make			&& \
	# pull and build module
	mkdir /src_iosocket			&& \
	wget --no-check-certificate \
		http://search.cpan.org/CPAN/authors/id/S/SU/SULLR/IO-Socket-SSL-2.049.tar.gz \
		-O iosocket.tgz 		&& \
	tar   -xzf iosocket.tgz -C /src_iosocket --strip-components=1	&& \
	cd    /src_iosocket			&& \
	echo n | perl Makefile.PL		&& \
	make && make test && make install	&& \
	# cleanup
	cd   /					&& \
	rm   -r /src_iosocket iosocket.tgz	&& \
	apk del --purge make

# Pull and build enhanced openssl
RUN \
	# install development tools
	apk add --no-cache musl-dev gcc make zlib-dev	&& \
	# pull openssl
	mkdir $OPENSSL_DIR /src_openssl		&& \
	wget --no-check-certificate \
		https://github.com/PeterMosmans/openssl/archive/1.0.2-chacha.tar.gz \
		-O openssl.tgz 			&& \
	\
	tar   -xzf openssl.tgz -C /src_openssl --strip-components=1	&& \
	cd    /src_openssl			&& \
	# build openssl
	./config --prefix=$OPENSSL_DIR --openssldir=$OPENSSL_DIR/ssl \
		enable-zlib enable-ssl3  enable-rc5  enable-rc2  enable-GOST \
		enable-cms  enable-md2   enable-mdc2 enable-ec   enable-ec2m \
		enable-ecdh enable-ecdsa enable-seed enable-idea enable-camellia \
		enable-rfc3779 enable-ec_nistp_64_gcc_128 \
		-static experimental-jpake -DOPENSSL_USE_BUILD_DATE	&& \
	make -C /src_openssl depend		&& \
	make -C /src_openssl			&& \
	make -C /src_openssl report		&& \
	make -C /src_openssl install		&& \
	# simple test
	echo -e "# number of ciphers $OPENSSL_DIR/bin/openssl: " && \
	$OPENSSL_DIR/bin/openssl ciphers -V ALL:COMPLEMENTOFALL:aNULL|wc -l && \
	# cleanup
	cd   /					&& \
	rm   -r /src_openssl openssl.tgz	&& \
	apk del --purge musl-dev gcc make zlib-dev

# Install traditional openssl
# RUN apk add --no-cache openssl

WORKDIR $OSAFT_DIR
RUN     o-saft-docker usage
ENV     TERM xterm
ENV     PATH ${OSAFT_DIR}:${OSAFT_DIR}/contrib:${OPENSSL_DIR}/bin:$PATH
USER    osaft

ENTRYPOINT ["perl", "/O-Saft/o-saft.pl"]
CMD  ["--help=docker"]

# vim:set ft=dockerfile:
