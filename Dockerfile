#!/usr/bin/docker build --force-rm --rm -f

FROM alpine:edge
MAINTAINER Achim <achim@owasp.org>

LABEL \
	VERSION="17.07.17"	\
	\
	DESCRIPTION="Build O-Saft docker image (with Peter Mosman's openssl)"	\
	SYNOPSIS="docker build --force-rm --rm -f ./Dockerfile -t owasp/o-saft:17.07.17 -t owasp/o-saft ." \
	DETAILS="Please see https://github.com/OWASP/O-Saft/raw/master/o-saft-docker" \
	SOURCE0="https://github.com/OWASP/O-Saft/raw/master/Dockerfile" \
	SOURCE1="https://github.com/OWASP/O-Saft/raw/master/o-saft.tgz" \
	SOURCE2="https://github.com/PeterMosmans/openssl/archive/1.0.2-chacha.tar.gz" \
	SID="@(#) Dockerfile 1.7 17/07/28 13:59:28" \
	AUTHOR="Achim Hoffmann"	

# parameters passed to build (must be defined after FROM)
ARG OSAFT_DOCKER_SHA256_OSAFT=ff8819f064d1425274d0fa47dbb78313be9984b79a38b5127ace6e6f107d9f08
ARG OSAFT_DOCKER_SHA256_OPENSSL
ARG OSAFT_DOCKER_APT_INSTALL

ENV o-saft-docker-build "Dockerfile 17.07.17 FROM: $OSAFT_DOCKER_FROM"
ENV OSAFT_DIR	/O-Saft
ENV OPENSSL_DIR	/openssl
ENV OPENSSL_VERSION  1.0.2-chacha
ENV TERM xterm
ENV PATH ${OSAFT_DIR}:${OSAFT_DIR}/contrib:${OPENSSL_DIR}/bin:$PATH

# Install required packages
#RUN apk update && \   # no update neded and not wanted
RUN apk add --no-cache wget ncurses $OSAFT_DOCKER_APT_INSTALL \
	perl perl-readonly perl-net-dns perl-io-socket-ssl perl-net-ssleay

WORKDIR	/

# Install O-Saft
RUN \
	mkdir $OSAFT_DIR			&& \
	adduser -D -h ${OSAFT_DIR} osaft	&& \
	\
	wget --no-check-certificate \
		https://github.com/OWASP/O-Saft/raw/master/o-saft.tgz \
		-O o-saft.tgz 			&& \
	# check sha256 if there is one
	[ -n "$OSAFT_DOCKER_SHA256_OSAFT" ]	&& \
		echo "$OSAFT_DOCKER_SHA256_OSAFT  o-saft.tgz" | sha256sum -c ; \
	\
	tar   -xzf o-saft.tgz			&& \
	chown -R root:root   $OSAFT_DIR		&& \
	chown -R osaft:osaft $OSAFT_DIR/contrib	&& \
	chown    osaft:osaft $OSAFT_DIR/.o-saft.pl	&& \
	mv       $OSAFT_DIR/.o-saft.pl $OSAFT_DIR/.o-saft.pl-orig	&& \
	sed -e "s:^#--openssl=.*:--openssl=$OPENSSL_DIR/bin/openssl:" \
		< $OSAFT_DIR/.o-saft.pl-orig \
		> $OSAFT_DIR/.o-saft.pl		&& \
	chmod 666 $OSAFT_DIR/.o-saft.pl		&& \
	rm    -f o-saft.tgz

# Pull and build enhanced openssl
RUN \
	# pull and extract module
	mkdir $OPENSSL_DIR /src_openssl		&& \
	wget --no-check-certificate \
		https://github.com/PeterMosmans/openssl/archive/1.0.2-chacha.tar.gz \
		-O openssl.tgz 			&& \
	# check sha256 if there is one
	echo "oooooooo $OSAFT_DOCKER_SHA256_OPENSSL" && \
	[ -n "$OSAFT_DOCKER_SHA256_OPENSSL" ]	&& \
		echo "$OSAFT_DOCKER_SHA256_OPENSSL  openssl.tgz" | sha256sum -c ; \
	\
	tar   -xzf openssl.tgz -C /src_openssl --strip-components=1	&& \
	cd    /src_openssl			&& \
	# build openssl {
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
	# build openssl }
	cd   /					&& \
	rm   -r /src_openssl openssl.tgz

# Install traditional openssl
# RUN apk add --no-cache openssl

# Install Tcl/Tk support
# RUN apk add --no-cache tcl tk xvfb

WORKDIR $OSAFT_DIR
USER    osaft
RUN     o-saft-docker usage

ENTRYPOINT ["perl", "/O-Saft/o-saft.pl"]
CMD  ["--help=docker"]

# vim:set ft=dockerfile:
