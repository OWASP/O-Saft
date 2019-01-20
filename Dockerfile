#!/usr/bin/docker build --force-rm --rm -f

#? USAGE
#?      This Dockerfile uses "buildargs" variables to build the Docker image.
#?      For default settings, please use:  awk '/^ARG/{print $2}' Dockerfile
#?
#?          OSAFT_VERSION
#?              Version of this build (should be used as image tag also).
#?
#?          OSAFT_VM_FROM
#?              Base image to be used for this build. Tested images are:
#?                  (2017) alpine:3.6  alpine:edge  debian:stretch-slim  debian
#?                  (2018) alpine:3.8  debian
#?
#?          OSAFT_VM_APT_INSTALL
#?              Additional packages  to be installed in the image.
#?              Note that the package names depend on the used base image.
#?              Tested packages are:  tcl  tk  xvfb  openssl
#?
#?          OSAFT_VM_SRC_OSAFT
#?              URL to fetch o-saft.tgz archive.
#?
#?          OSAFT_VM_SHA_OSAFT
#?              SHA256 checksum for the o-saft.tgz archive.
#?              Note that the checksum in the Dockerfile provided by this .tgz
#?              archive is wrong (due to hen-egg-problem).
#?              https://github.com/OWASP/O-Saft/blob/master/Dockerfile  is the
#?              most current version and contains proper checksums.
#?
#?          OSAFT_VM_TAR_OSAFT
#?              Name of archive file for O-Saft (during build).
#?
#?          OSAFT_VM_SRC_OPENSSL
#?              URL to fetch openssl.tgz archive.
#?
#?          OSAFT_VM_SHA_OPENSSL
#?              SHA256 checksum for the openssl-1.0.2-chacha.tar.gz archive.
#?
#?          OSAFT_VM_TAR_OPENSSL
#?              Name of archive file for OpenSSL (during build).
#?
#?          OSAFT_VM_DYN_OPENSSL
#?              Build (link) mode of openssl executable: --static or --shared
#?
#?          OSAFT_VM_SRC_SSLEAY
#?              URL to fetch Net-SSLeay.tar.gz archive.
#?
#?          OSAFT_VM_SHA_SSLEAY
#?              SHA256 checksum for the Net-SSLeay.tar.gz archive.
#?
#?          OSAFT_VM_TAR_SSLEAY
#?              Name of archive file for Net-SSLeay.tgz (during build).
#?
#?          OSAFT_VM_SRC_SOCKET
#?              URL to fetch IO-Socket-SSL.tar.gz archive.
#?
#?          OSAFT_VM_SHA_SOCKET
#?              SHA256 checksum for the IO-Socket-SSL.tar.gz archive.
#?
#?          OSAFT_VM_TAR_SOCKET
#?              Name of archive file for IO-Socket-SSL.tgz (during build).
#?
#? ENVIRONMENT VARIABLES
#?      The build image sets environment variables. They are mainly used for
#?      documentation or by other programs to check for the right build.
#?
#?      Following environment variables are set inside the docker image:
#?
#?          osaft_vm_build
#?              Build version of this image, used by o-saft-docker.
#?          OSAFT_DIR
#?              Directory where O-Saft  is installed.
#?          OPENSSL_DIR
#?              Directory where OpenSSL is installed.
#?          OPENSSL_VERSION
#?              Version of installed OpenSSL
#?          TERM
#?              Prefered X-Terminal program.
#?          LD_RUN_PATH
#?              Additional paths for runtime loader, used while linking with
#?              "ld -rpath=..."
#?              Linking of openssl, libssl.so and SSLeay.so will use  -rpath
#?              in LDFLAGS to ensure that the special library will be used.
#?              Default:${OPENSSL_DIR}/lib
#?          PATH
#?              PATH for shell, set to:
#?                  $OSAFT_DIR:$OSAFT_DIR/contrib:$OPENSSL_DIR/bin:$PATH
#?          WORK_DIR
#?              Directory where to build the packages (used for Dockerfile's
#?              WORKDIR  dierective.
#?
#? EXAMPLES
#?      Simple build with defaults:  alpine:edge, o-saft.tgz, openssl-chacha
#?          docker build --force-rm --rm \ 
#?                  -f Dockerfile -t owasp/o-saft .
#?
#?      Simple build with base image alpine:3.8
#?          docker build --force-rm --rm \ 
#?                  --build-arg "OSAFT_VM_FROM=alpine:3.8" \ 
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
#?      Build with development O-Saft download from github
#?          docker build --force-rm --rm \ 
#?                  --build-arg "OSAFT_VM_SRC_OSAFT=https://github.com/OWASP/O-Saft/archive/master.tar.gz" \ 
#?                  --build-arg "OSAFT_VERSION=latest-development" \ 
#?                  -f Dockerfile -t owasp/o-saft .
#?
#?      Note that  o-saft-docker  searches for a Docker image  owasp/o-saft
#?      so don't forget to tag at least one image with this name.
#?

ARG     OSAFT_VM_FROM=alpine:3.8

FROM    $OSAFT_VM_FROM
MAINTAINER Achim <achim@owasp.org>

# Parameters passed to build
	# OSAFT_VM_FROM must be defined again, otherwise its value is not available
ARG     OSAFT_VM_FROM
ARG     OSAFT_VM_SRC_OSAFT="https://github.com/OWASP/O-Saft/raw/master/o-saft.tgz"
ARG     OSAFT_VM_SHA_OSAFT="29d4faa2ed3025ed18d31175e868d6be9312b36ba486c6e5f305afeb34947f68"
ARG     OSAFT_VM_TAR_OSAFT="o-saft.tgz"
ARG     OSAFT_VM_SRC_SSLEAY="http://search.cpan.org/CPAN/authors/id/M/MI/MIKEM/Net-SSLeay-1.85.tar.gz"
ARG     OSAFT_VM_SHA_SSLEAY="9d8188b9fb1cae3bd791979c20554925d5e94a138d00414f1a6814549927b0c8"
ARG     OSAFT_VM_TAR_SSLEAY="Net-SSLeay.tgz"
ARG     OSAFT_VM_SRC_SOCKET="http://search.cpan.org/CPAN/authors/id/S/SU/SULLR/IO-Socket-SSL-2.052.tar.gz"
ARG     OSAFT_VM_SHA_SOCKET="e4897a9b17cb18a3c44aa683980d52cef534cdfcb8063d6877c879bfa2f26673"
ARG     OSAFT_VM_TAR_SOCKET="IO-Socket-SSL.tgz"
ARG     OSAFT_VM_SRC_OPENSSL="https://github.com/PeterMosmans/openssl/archive/1.0.2-chacha.tar.gz"
ARG     OSAFT_VM_SHA_OPENSSL="ad3d99ec091e403a3a7a678ddda38b392e3204515425827c53dc5baa92d61d67"
ARG     OSAFT_VM_TAR_OPENSSL="openssl.tgz"
ARG     OSAFT_VM_DYN_OPENSSL="--shared"
#                             --static  not yet (2017) working 'cause of libkrb5
ARG     OSAFT_VM_APT_INSTALL
ARG     OSAFT_VERSION="undefined"

LABEL \
	VERSION="$OSAFT_VERSION"	\
	\
	DESCRIPTION="Build O-Saft docker image (with Peter Mosman's openssl)"	\
	SYNOPSIS="docker build --force-rm --rm -f ./Dockerfile -t owasp/o-saft:$OSAFT_VERSION -t owasp/o-saft ." \
	DETAILS="Please see https://github.com/OWASP/O-Saft/raw/master/o-saft-docker" \
	SOURCE0="https://github.com/OWASP/O-Saft/raw/master/Dockerfile" \
	SOURCE1="$OSAFT_VM_SRC_OSAFT" \
	SOURCE2="$OSAFT_VM_SRC_OPENSSL" \
	SID="@(#) Dockerfile 1.29 19/01/20 23:25:44" \
	AUTHOR="Achim Hoffmann"	

ENV     osaft_vm_build  "Dockerfile $OSAFT_VERSION; FROM $OSAFT_VM_FROM"
ENV     OSAFT_DIR       /O-Saft
ENV     OPENSSL_DIR     /openssl
ENV     OPENSSL_VERSION  1.0.2-chacha
ENV     TERM            xterm
ENV     LD_RUN_PATH     ${OPENSSL_DIR}/lib
ENV     PATH ${OSAFT_DIR}:${OSAFT_DIR}/contrib:${OPENSSL_DIR}/bin:$PATH
ENV     BUILD_DIR       /tmp_src
ENV     WORK_DIR	/

WORKDIR	$WORK_DIR

RUN \
	#== Install required packages, development tools and libs
	#apk update && \   # no update neded and not wanted
	apk add --no-cache wget ncurses $OSAFT_VM_APT_INSTALL \
		gcc make musl-dev linux-headers \
		krb5-dev zlib-dev perl perl-readonly perl-dev \
		ca-certificates			&& \
		# perl-io-socket-ssl perl-net-ssleay
	\
	#== Pull, build and install enhanced openssl
	apk add --no-cache gmp-dev lksctp-tools-dev	&& \
	cd    $WORK_DIR				&& \
	mkdir -p $BUILD_DIR $OPENSSL_DIR	&& \
	wget --no-check-certificate $OSAFT_VM_SRC_OPENSSL -O $OSAFT_VM_TAR_OPENSSL && \
	# check sha256 if there is one
	[ -n "$OSAFT_VM_SHA_OPENSSL" ]		&& \
		echo "$OSAFT_VM_SHA_OPENSSL  $OSAFT_VM_TAR_OPENSSL" | sha256sum -c ; \
	\
	tar   -xzf $OSAFT_VM_TAR_OPENSSL -C $BUILD_DIR --strip-components=1	&& \
	cd    $BUILD_DIR			&& \
	# patch openssl.cnf for GOST
	sed -i '/RANDFILE/a openssl_conf=openssl_def' apps/openssl.cnf	&& \
	#   using echo instead of cat to avoid problems with stacked commands:
	#   cat -> shell -> docker
	(\
	  echo 'openssl_conf=openssl_def'; \
	  echo '[openssl_def]';		\
	  echo 'engines=engine_section';\
	  echo '[engine_section]';	\
	  echo 'gost=gost_section';	\
	  echo '[gost_section]';	\
	  echo 'engine_id = gost';	\
	  echo 'default_algorithms=ALL';\
	  echo 'CRYPT_PARAMS=id-Gost28147-89-CryptoPro-A-ParamSet'; \
	) >> apps/openssl.cnf			&& \
	# config with all options, even if they are default
	LDFLAGS="-rpath=$LD_RUN_PATH"   && export LDFLAGS	&& \
		# see description for LD_RUN_PATH above
	./config --prefix=$OPENSSL_DIR --openssldir=$OPENSSL_DIR/ssl	\
		$OSAFT_VM_DYN_OPENSSL	\
		--with-krb5-flavor=MIT --with-krb5-dir=/usr/include/krb5/ \
		-fPIC zlib zlib-dynamic enable-zlib enable-npn sctp	\
		enable-deprecated enable-weak-ssl-ciphers	\
		enable-heartbeats enable-unit-test  enable-ssl-trace	\
		enable-ssl3    enable-ssl3-method   enable-ssl2	\
		enable-tls1    enable-tls1-method   enable-tls\
		enable-tls1-1  enable-tls1-1-method enable-tlsext	\
		enable-tls1-2  enable-tls1-2-method enable-tls1-2-client \
		enable-dtls1   enable-dtls1-method	\
		enable-dtls1-2 enable-dtls1-2-method	\
		enable-md2     enable-md4   enable-mdc2	\
		enable-rc2     enable-rc4   enable-rc5	\
		enable-sha0    enable-sha1  enable-sha256 enable-sha512	\
		enable-aes     enable-cms   enable-dh     enable-egd	\
		enable-des     enable-dsa   enable-rsa    enable-rsax	\
		enable-ec      enable-ec2m  enable-ecdh   enable-ecdsa	\
		enable-blake2  enable-bf    enable-cast enable-camellia	\
		enable-gmp     enable-gost  enable-GOST   enable-idea	\
		enable-poly1305 enable-krb5 enable-rdrand enable-rmd160	\
		enable-seed    enable-srp   enable-whirlpool	\
		enable-rfc3779 enable-ec_nistp_64_gcc_128 experimental-jpake \
		-DOPENSSL_USE_BUILD_DATE -DTLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES -DTEMP_GOST_TLS	\
		&& \
	make depend && make && make report -i && make install	&& \
		# make report most likely fails, hence -i
	# simple test
	echo -n "# number of ciphers $OPENSSL_DIR/bin/openssl: " && \
	$OPENSSL_DIR/bin/openssl ciphers -V ALL:COMPLEMENTOFALL:aNULL|wc -l && \
	# cleanup
	apk  del --purge gmp-dev lksctp-tools-dev && \
	cd    $WORK_DIR				&& \
	rm   -rf $BUILD_DIR $OSAFT_VM_TAR_OPENSSL && \
	\
	#== Pull, build and install Net::SSLeay
	cd    $WORK_DIR				&& \
	mkdir -p $BUILD_DIR			&& \
	wget --no-check-certificate $OSAFT_VM_SRC_SSLEAY -O $OSAFT_VM_TAR_SSLEAY && \
	# check sha256 if there is one
	[ -n "$OSAFT_VM_SHA_SSLEAY" ]		&& \
		echo "$OSAFT_VM_SHA_SSLEAY  $OSAFT_VM_TAR_SSLEAY" | sha256sum -c ; \
	\
	tar   -xzf $OSAFT_VM_TAR_SSLEAY -C $BUILD_DIR --strip-components=1	&& \
	# install additional packages for Net-SSLeay ...
	apk add --no-cache perl-net-dns perl-net-libidn perl-mozilla-ca		&& \
	cd    $BUILD_DIR			&& \
	perl -i.orig -pe 'if (m/^#define\s*REM_AUTOMATICALLY_GENERATED_1_09/){print "const SSL_METHOD * SSLv2_method()\n\nconst SSL_METHOD * SSLv3_method()\n\n";}' SSLeay.xs	&& \
		# quick&dirty patch, results in warning, which can be ignored
		# Warning: duplicate function definition 'SSLv2_method' detected in SSLeay.xs, line 4256
	LDFLAGS="-rpath=$LD_RUN_PATH"   && export LDFLAGS	&& \
	echo "n" | env OPENSSL_PREFIX=$OPENSSL_DIR perl Makefile.PL \
		INC=-I$OPENSSL_DIR/include DEFINE=-DOPENSSL_BUILD_UNSAFE=1	&& \
		# Makefile.PL asks for "network tests", hence pipe "n" as answer
		# installation in (default) /usr/local, hence no PREFIX=
	make && make test && make install	&& \
	cd    $WORK_DIR				&& \
	rm   -rf $BUILD_DIR $OSAFT_VM_TAR_SSLEAY && \
	\
	#== Pull, build and install IO::Socket::SSL
	mkdir -p $BUILD_DIR			&& \
	wget --no-check-certificate $OSAFT_VM_SRC_SOCKET -O $OSAFT_VM_TAR_SOCKET && \
	# check sha256 if there is one
	[ -n "$OSAFT_VM_SHA_SOCKET" ]		&& \
		echo "$OSAFT_VM_SHA_SOCKET  $OSAFT_VM_TAR_SOCKET" | sha256sum -c ; \
	\
	tar   -xzf $OSAFT_VM_TAR_SOCKET -C $BUILD_DIR --strip-components=1	&& \
	cd    $BUILD_DIR			&& \
	echo "n" | perl Makefile.PL INC=-I$OPENSSL_DIR/include	&& \
	make && make test && make install	&& \
	cd    $WORK_DIR				&& \
	rm   -r $BUILD_DIR $OSAFT_VM_TAR_SOCKET && \
	\
	#== Pull and install O-Saft
	cd    $WORK_DIR				&& \
	mkdir -p $OSAFT_DIR			&& \
	adduser -D -h ${OSAFT_DIR} osaft	&& \
	\
	wget --no-check-certificate $OSAFT_VM_SRC_OSAFT -O $OSAFT_VM_TAR_OSAFT	&& \
	# check sha256 if there is one
	[ -n "$OSAFT_VM_SHA_OSAFT" ]		&& \
		echo "$OSAFT_VM_SHA_OSAFT  $OSAFT_VM_TAR_OSAFT" | sha256sum -c ; \
	\
	tar   -xzf $OSAFT_VM_TAR_OSAFT		&& \
	# handle master directory from github, mv to $OSAFT_DIR
	# checks fail sometimes, hence in a sub-shell
	(\
	  [ -d "./O-Saft-master" ] && mv ./O-Saft-master/*           $OSAFT_DIR/ ; \
	  [ -d "./O-Saft-master" ] && mv ./O-Saft-master/.[a-zA-Z]*  $OSAFT_DIR/ ; \
	  [ -d "./O-Saft-master" ] && rm -rf ./O-Saft-master/ 	; \
	  exit 0 ; \
	) && \
	chown -R root:root   $OSAFT_DIR		&& \
	chown -R osaft:osaft $OSAFT_DIR/contrib	&& \
	chown    osaft:osaft $OSAFT_DIR/.o-saft.pl && \
	cp       $OSAFT_DIR/.o-saft.pl $OSAFT_DIR/.o-saft.pl-orig	&& \
	perl -i.bak -pe "s:^#?\s*--openssl=.*:--openssl=$OPENSSL_DIR/bin/openssl:;s:^#?\s*--openssl-cnf=.*:--openssl-cnf=$OPENSSL_DIR/ssl/openssl.cnf:;s:^#?\s*--ca-path=.*:--ca-path=/etc/ssl/certs/:;s:^#?\s*--ca-file=.*:--ca-file=/etc/ssl/certs/ca-certificates.crt:" $OSAFT_DIR/.o-saft.pl && \
	chmod 666 $OSAFT_DIR/.o-saft.pl		&& \
	rm    -f $OSAFT_VM_TAR_OSAFT 		&& \
	\
	#== Cleanup
	apk del --purge gcc make musl-dev linux-headers perl-dev
	    # do not delete  krb5-dev zlib-dev  because we need
	    #  libkrb5.so.3, libk5crypto.so.3 and libz.so to run openssl

WORKDIR $OSAFT_DIR
USER    osaft
RUN     o-saft-docker usage

ENTRYPOINT ["/O-Saft/o-saft"]
CMD     ["--norc",  "--help=docker"]

# vim:set ft=dockerfile:
