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
#?                  (2018) alpine:3.8
#?
#?          OSAFT_VM_SRC_WOLFSSL
#?              URL to fetch wolfssl.tgz archive.
#?
#?          OSAFT_VM_SHA_WOLFSSL
#?              SHA256 checksum for the wolfssl archive.
#?
#?          OSAFT_VM_TAR_WOLFSSL
#?              Name of archive file (during build).
#?
#?          OSAFT_VM_DYN_WOLFSSL
#?              Build (link) mode of wolfssl executable: --enable-static or --enable-shared
#?
#?          OSAFT_VM_HOSTNAME
#?              Hostname to be used for running container (/etc/hostname)
#?
#? ENVIRONMENT VARIABLES
#?      The build image sets environment variables. They are mainly used for
#?      documentation or by other programs to check for the right build.
#?
#?      Following environment variables are set inside the docker image:
#?
#?          osaft_vm_build
#?              Build version of this image.
#?          WOLFSSL_DIR
#?              Directory where wolfSSL is installed.
#?          WOLFSSL_VERSION
#?              Version of installed OpenSSL
#?          TERM
#?              Prefered X-Terminal program.
#?          LD_RUN_PATH
#?              Additional paths for runtime loader, used while linking with
#?              "ld -rpath=..."
#?              Linking of wolfssl, libssl.so and SSLeay.so will use  -rpath
#?              in LDFLAGS to ensure that the special library will be used.
#?              Default:${WOLFSSL_DIR}/lib
#?          PATH
#?              PATH for shell, set to:
#?                  $OSAFT_DIR:$OSAFT_DIR/contrib:$WOLFSSL_DIR/bin:$PATH
#?          WORK_DIR
#?              Directory where to build the packages (used for Dockerfile's
#?              WORKDIR  dierective.
#?
#? EXAMPLES
#?      Simple build with defaults:  alpine:3.8, wolfssl
#?          docker build --force-rm --rm \ 
#?                  -f Dockerfile.wolfssl -t o-saft/wolfssl .
#?

ARG     OSAFT_VM_FROM=alpine:3.8

FROM    $OSAFT_VM_FROM
MAINTAINER Achim <achim@owasp.org>

# Parameters passed to build
	# OSAFT_VM_FROM must be defined again, otherwise its value is not available
ARG     OSAFT_VM_FROM
ARG     OSAFT_VM_SRC_WOLFSSL="https://github.com/wolfSSL/wolfssl/archive/v3.15.3-stable.tar.gz"
# -----BEGIN PGP SIGNATURE-----
ARG     OSAFT_VM_SHA_WOLFSSL="\
iQEcBAABCgAGBQJbLXUHAAoJEOvIDkFcopZ3NYMIAJMSsKQQxTHdiO4tjhofhgu2\
uH8QmY4XjyDqVEzID1GTmjS092bh/wNfQLRW5nMNMdS965XzA8gmSqo1bWIfFBG+\
eKZLc4xu+oIEDKfF7r5gkmPQNRVsHmOQK6BeOG0BnXBSdE9E0CIIlk81pZC7HSo7\
U6/I1hVlXyL9Y8ctfL2doDzil1jAvc0tQo/HNU4UikHtcbH2tsYSzjA1wXnjqeXQ\
WYy0TcJ0MbJrnpqX0li6JWc/6FSqM1hgCzrf/7kScdsu2zxMKxuxUvCCRJ1meYKt\
Vf2K6SlLFg5iqxqe+JRTvIiq2EDalsqClW9I1rbkphvYspZ9WI0Jf4YJUp4xPVk=\
=AlNB"
# -----END PGP SIGNATURE-----
ARG     OSAFT_VM_TAR_WOLFSSL="wolfssl.tgz"
ARG     OSAFT_VM_DYN_WOLFSSL="--enable-static"
#                             --enable-static  not yet (2017) working 'cause of
ARG	OSAFT_VM_HOSTNAME

ARG     OSAFT_VERSION="18.10.12"

LABEL \
	VERSION="$OSAFT_VERSION"	\
	\
	DESCRIPTION="Build docker image with wolfssl"	\
	SYNOPSIS="docker build --force-rm --rm -f ./Dockerfile.wolfssl -t o-saft/wolfssl:$OSAFT_VERSION -t o-saft/wolfssl ." \
	SOURCE0="https://github.com/OWASP/O-Saft/raw/master/contrib/Dockerfile.wolfssl" \
	SOURCE2="$OSAFT_VM_SRC_WOLFSSL" \
	SID="@(#) Dockerfile.wolfssl 1.1 18/10/15 23:38:12" \
	AUTHOR="Achim Hoffmann"	

ENV     osaft_vm_build  "Dockerfile $OSAFT_VERSION; FROM $OSAFT_VM_FROM"
ENV     WOLFSSL_DIR     /wolfssl
ENV     WOLFSSL_VERSION  v3.15.3
ENV     TERM            xterm
ENV     LD_RUN_PATH     ${WOLFSSL_DIR}/lib
ENV     PATH ${WOLFSSL_DIR}/bin:$PATH
ENV     BUILD_DIR       /tmp_src
ENV     WORK_DIR	/

WORKDIR	$WORK_DIR

# Install required packages, development tools and libs
#RUN apk update && \   # no update neded and not wanted
RUN     apk add --no-cache wget ncurses linux-headers  \
		 gcc make musl-dev zlib-dev m4 perl autoconf automake libtool file && \
	#
	# Pull, build and install wolfssl
	apk add --no-cache lksctp-tools-dev	&& \
	cd    $WORK_DIR				&& \
	mkdir -p $BUILD_DIR $WOLFSSL_DIR	&& \
	wget --no-check-certificate $OSAFT_VM_SRC_WOLFSSL -O $OSAFT_VM_TAR_WOLFSSL	&& \
	### # check sha256 if there is one
	### [ -n "$OSAFT_VM_SHA_WOLFSSL" ]		&& 
	### 	echo "$OSAFT_VM_SHA_WOLFSSL  $OSAFT_VM_TAR_WOLFSSL" | sha256sum -c ; 
	### 
	tar   -xzf $OSAFT_VM_TAR_WOLFSSL -C $BUILD_DIR --strip-components=1	&& \
	cd    $BUILD_DIR			&& \
	#
	LDFLAGS="-Wl,-rpath=$LD_RUN_PATH"   && export LDFLAGS	&& \
		# see description for LD_RUN_PATH above

### --enable-fips fails with:
###    make[1]: *** No rule to make target 'ctaocrypt/src/fips.c', needed by 'ctaocrypt/src/src_libwolfssl_la-fips.lo'.  Stop.

### --enable-qsh  requires special includes

### --enable-opensslcoexist fails with
### src/ssl.c: In function 'wolfSSL_BIO_new_file':
### src/ssl.c:30496:9: warning: implicit declaration of function 'wolfSSL_BIO_set_fp' [-Wimplicit-function-declaration]
###      if (wolfSSL_BIO_set_fp(bio, fp, BIO_CLOSE) != WOLFSSL_SUCCESS) {
###          ^~~~~~~~~~~~~~~~~~

### missing in v3.15.3: --enable-tls13-draft28 --enable-aescbc --enable-sha2

	./autogen.sh			&& \
	# config with all options, even if they are default
	# using --disable-option-checking in the hope for back- and forward-compatibility
	./configure --prefix=$WOLFSSL_DIR $OSAFT_VM_DYN_WOLFSSL	\
		--disable-option-checking	\
		--enable-rng    --with-libz	\
		--enable-sslv3	--enable-dtls   \
		--enable-tlsv10 --enable-tlsv12 --enable-tls13 --enable-oldtls	\
		--enable-tls13-draft18  --enable-tls13-draft22 --enable-tls13-draft23	\
		--enable-tls13-draft26  --enable-tls13-draft28	\
		--enable-aescbc --enable-aesccm --enable-aesgcm --enable-aesctr	\
		--enable-aescfb	--enable-aesni	\
		--enable-md2    --enable-md4    --enable-md5	\
		--enable-sha2   --enable-sha3   --enable-sha224	--enable-sha512	\
		--enable-cmac   --enable-dsa    --enable-des3  --enable-dh	\
		--enable-ecccustcurves          --enable-ecc   --enable-eccshamir \
		--enable-eccencrypt           --enable-ed25519 --enable-curve25519 \
		--enable-supportedcurves        --enable-fpecc --enable-compkey	\
		--enable-hkdf   --enable-arc4   --enable-psk   --enable-sep	\
		--enable-blake2 --enable-ripemd --enable-camellia --enable-x963kdf	\
		--enable-rabbit --enable-hc128  --enable-anon   --enable-nullcipher	\
		--enable-idea   --enable-chacha --enable-poly1305	\
		--enable-alpn   --enable-sni    --enable-crl    --enable-truncatedhmac	\
		--enable-mcast	--enable-sctp   --enable-srp	\
		--enable-rsa    --enable-rsapss --enable-xts	\
		--enable-coding --enable-base16	--enable-base64encode \
		--enable-oldnames --enable-errorstrings         --enable-enckeys \
		--enable-ocsp   --enable-ocspstapling   --enable-ocspstapling2	\
		--enable-tlsx   --enable-session-ticket --enable-extended-master	\
		--enable-secure-renegotiation	\
		--enable-opensslall --enable-opensslextra \
		--enable-lighty --enable-webclient --enable-earlydata	\
		&& echo "# configure done." || cat ./config.log	&& \
	make && make -i test && make install	&& \
		# make test most likely fails, hence -i
	# manually install tools (without error checks)
	# NOTE: installs the binaries, not the wrapper scripts
	cp examples/echoclient/.libs/echoclient $WOLFSSL_DIR/bin/;	\
	cp examples/echoserver/.libs/echoserver $WOLFSSL_DIR/bin/;	\
	cp examples/client/.libs/client         $WOLFSSL_DIR/bin/;	\
	cp examples/server/.libs/server         $WOLFSSL_DIR/bin/;	\
	cp examples/sctp/.libs/sctp-client-dtls $WOLFSSL_DIR/bin/;	\
	cp examples/sctp/.libs/sctp-server-dtls $WOLFSSL_DIR/bin/;	\
	cp examples/sctp/sctp-client            $WOLFSSL_DIR/bin/;	\
        mv certs/ $WOLFSSL_DIR/bin/;		\
        ln -s $WOLFSSL_DIR/bin/certs /certs ;	\
	# simple test
	echo -n "# number of ciphers $WOLFSSL_DIR/bin/client: " && \
	$WOLFSSL_DIR/bin/client -e|tr ':' '\012'|wc -l && \
	$WOLFSSL_DIR/bin/client -e	&& \
	# cleanup
	apk  del --purge lksctp-tools-dev && \
	cd    $WORK_DIR				&& \
	echo rm   -rf $BUILD_DIR $OSAFT_VM_TAR_WOLFSSL	&& \
	# Cleanup
	apk del --purge gcc make m4 autoconf automake musl-dev linux-headers	\
			perl-dev readline bash libltdl libtool file	&& \
	    # installed by libtool: readline bash libltdl libtool
	    # do not delete  krb5-dev zlib-dev  because we need 
	    #  libkrb5.so.3, libk5crypto.so.3 and libz.so to run openssl
	[ -n "$OSAFT_VM_HOSTNAME" ]		&& \
		echo "$OSAFT_VM_HOSTNAME" > /etc/hostname ; 

WORKDIR $WOLFSSL_DIR
### USER    wolfssl
### RUN     ??

ENTRYPOINT ["/wolfssl/bin"]
EXPOSE  443/tcp

# vim:set ft=dockerfile:
