#!/usr/bin/docker build --force-rm --rm -f

#? USAGE
#?      This Dockerfile uses environment variables to build the Docker image,
#?      and to pass SHA256 checksums to the build process. The variables are:
#?
#?          OSAFT_VM_FROM
#?              Base image to be used for this build. Tested images are:
#?                  alpine:3.6  alpine:edge  debian:stretch-slim  debian
#?              default is  alpine:edge.
#?
#?          OSAFT_VM_APT_INSTALL
#?              Additional packages  to be installed in the image.  Note that
#?              the package names depend on the used base image.
#?              Tested packages are:  tcl  tk  xvfb  openssl
#?
#?          OSAFT_VM_SHA_OSAFT
#?              SHA256 checksum for the o-saft.tgz archive.
#?
#?          OSAFT_VM_SHA_OPENSSL
#?              SHA256 checksum for the openssl-1.0.2-chacha.tar.gz archive.
#?
#?          OSAFT_VM_TAR_OSAFT
#?              Name of archive file for O-Saft.
#?              default is  o-saft.tgz
#?
#?          OSAFT_VM_TAR_OPENSSL
#?              Name of archive file for OpenSSL..
#?              default is  openssl.tgz
#?
#? EXAMPLES
#?      Simple build with defaults:  alpine:edge, o-saft.tgz, openssl-chacha
#?          docker build --force-rm --rm \ 
#?                  -f Dockerfile -t owasp/o-saft .
#?
#?      Simple build with base image alpine:3.6
#?          docker build --force-rm --rm \ 
#?                  --build-arg "OSAFT_VM_FROM=alpine:3.6" \ 
#?                  -f Dockerfile -t owasp/o-saft .
#?
#?      Build with base image alpine:3.6 and Tcl/Tk
#?          docker build --force-rm --rm \ 
#?                  --build-arg "OSAFT_VM_FROM=alpine:3.6" \ 
#?                  --build-arg "OSAFT_VM_APT_INSTALL=tcl tk xvfb" \ 
#?                  -f Dockerfile -t owasp/o-saft .
#?
#?      Build with other SHA256 checksum for o-saft.tgz
#?          docker build --force-rm --rm \ 
#?                  --build-arg "OSAFT_VM_SHA_OSAFT=caffee" \ 
#?                  -f Dockerfile -t owasp/o-saft .
#?

ARG     OSAFT_VM_FROM=alpine:edge

FROM    $OSAFT_VM_FROM
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
	SID="@(#) Dockerfile 1.11 17/08/03 22:00:55" \
	AUTHOR="Achim Hoffmann"	

# Parameters passed to build
ARG     OSAFT_VM_FROM
ARG     OSAFT_VM_SHA_OSAFT=ff8819f064d1425274d0fa47dbb78313be9984b79a38b5127ace6e6f107d9f08
ARG     OSAFT_VM_SHA_OPENSSL
ARG     OSAFT_VM_TAR_OSAFT=o-saft.tgz
ARG     OSAFT_VM_TAR_OPENSSL=openssl.tgz
ARG     OSAFT_VM_APT_INSTALL

ENV     osaft_vm_build  "Dockerfile 17.07.17; FROM $OSAFT_VM_FROM"
ENV     OSAFT_DIR	/O-Saft
ENV     OPENSSL_DIR	/openssl
ENV     OPENSSL_VERSION  1.0.2-chacha
ENV     TERM xterm
ENV     PATH ${OSAFT_DIR}:${OSAFT_DIR}/contrib:${OPENSSL_DIR}/bin:$PATH

# Install required packages
#RUN apk update && \   # no update neded and not wanted
RUN     apk add --no-cache wget ncurses $OSAFT_VM_APT_INSTALL \
	perl perl-readonly perl-net-dns perl-io-socket-ssl perl-net-ssleay

WORKDIR	/

# Pull and install O-Saft
RUN \
	mkdir $OSAFT_DIR			&& \
	adduser -D -h ${OSAFT_DIR} osaft	&& \
	\
	wget --no-check-certificate \
		https://github.com/OWASP/O-Saft/raw/master/o-saft.tgz \
		-O $OSAFT_VM_TAR_OSAFT 		&& \
	# check sha256 if there is one
	[ -n "$OSAFT_VM_SHA_OSAFT" ]		&& \
		echo "$OSAFT_VM_SHA_OSAFT  $OSAFT_VM_TAR_OSAFT" | sha256sum -c ; \
	\
	tar   -xzf $OSAFT_VM_TAR_OSAFT		&& \
	chown -R root:root   $OSAFT_DIR		&& \
	chown -R osaft:osaft $OSAFT_DIR/contrib	&& \
	chown    osaft:osaft $OSAFT_DIR/.o-saft.pl	&& \
	mv       $OSAFT_DIR/.o-saft.pl $OSAFT_DIR/.o-saft.pl-orig	&& \
	sed -e "s:^#--openssl=.*:--openssl=$OPENSSL_DIR/bin/openssl:" \
		< $OSAFT_DIR/.o-saft.pl-orig \
		> $OSAFT_DIR/.o-saft.pl		&& \
	chmod 666 $OSAFT_DIR/.o-saft.pl		&& \
	rm    -f $OSAFT_VM_TAR_OSAFT

# Pull, build and install enhanced openssl
RUN \
	# pull and extract module
	mkdir $OPENSSL_DIR /src_openssl		&& \
	wget --no-check-certificate \
		https://github.com/PeterMosmans/openssl/archive/1.0.2-chacha.tar.gz \
		-O $OSAFT_VM_TAR_OPENSSL	&& \
	# check sha256 if there is one
	[ -n "$OSAFT_VM_SHA_OPENSSL" ]		&& \
		echo "$OSAFT_VM_SHA_OPENSSL  $OSAFT_VM_TAR_OPENSSL" | sha256sum -c ; \
	\
	tar   -xzf $OSAFT_VM_TAR_OPENSSL -C /src_openssl --strip-components=1	&& \
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
	rm   -r /src_openssl $OSAFT_VM_TAR_OPENSSL

WORKDIR $OSAFT_DIR
USER    osaft
RUN     o-saft-docker usage

ENTRYPOINT ["perl", "/O-Saft/o-saft.pl"]
CMD     ["--norc",  "--help=docker"]

# vim:set ft=dockerfile:
