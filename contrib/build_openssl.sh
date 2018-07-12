#!/bin/sh
#?
#? NAME
#?      $0 - build and install special openssl and Net::SSLeay
#?
#? SYNOPSIS
#?      $0 [OPTIONS]
#?
#? OPTIONS
#?      --h - nice option
#?      --n - do not execute, just show where to install
#?
#? DESCRIPTION
#?      Build special openssl based on Peter Mosman's openssl.  Enables SSLv2
#?      and SSLv3 and all possible ciphers.
#?      Installs build in specified directory; default: /usr/local/openssl .
#?      Additionally builds perl module Net::SSLeay based on special openssl.
#?      Net::SSLeay will be installed in usr/local/lib.
#?      Modifies  .o-saft.pl  .
#?      This script is intended to be executed in the  installation directory
#?      of O-Saft.
#?
#?      Final output should look like (paths may differ):
#?    -------------------------------------------------------------------------
#?    # test o-saft.pl ...
#?    **WARNING: 143: SSL version 'TLSv13': not supported by Net::SSLeay; not checked
#?        Net::SSLeay::
#?           ::OPENSSL_VERSION_NUMBER()    0x100020b0 (268443824)
#?           ::SSLeay()                    0x100020b0 (268443824)
#?        Net::SSLeay::SSLeay_version()    OpenSSL 1.0.2-chacha (1.0.2k-dev)
#?    = openssl =
#?        external executable              /usr/local/openssl/bin/openssl
#?        version of external executable   OpenSSL 1.0.2-chacha (1.0.2k-dev)
#?        full path to openssl.cnf file    /usr/local/openssl/ssl/openssl.cnf
#?        common openssl.cnf files         /usr/lib/ssl/openssl.cnf /etc/ssl/openssl.cnf /System//Library/OpenSSL/openssl.cnf /usr/ssl/openssl.cnf
#?        directory with PEM files for CAs /usr/local/openssl/ssl/certs
#?        common paths to PEM files for CAs /etc/ssl/certs /usr/lib/certs /System/Library/OpenSSL
#?        openssl supported SSL versions   SSLv2 SSLv3 TLSv1 TLSv11 TLSv12
#?        Net::SSLeay            1.82     /usr/local/lib/x86_64-linux-gnu/perl/5.20.2/Net/SSLeay.pm
#?    -------------------------------------------------------------------------
#?
#? WARNING
#?      Note that  compilation and installation of  openssl  and  Net::SSLeay
#?      uses known insecure configurations and features! This is essential to
#?      make  o-saft.pl  able to check for such insecurities.
#?
#?      It's highly recommended to do this installation on a separate testing
#?      system.
#?
#?      DO NOT USE THESE INSTALLATIONS ON PRODUCTIVE SYTEMS.
#?
#? PRECONDITIONS
#?      Script needs write access to installation directories (/usr/local and
#?      /usr/local/lib by default).
#?      Asumes that following perl modules are installed:
#?          Net::DNS Mozilla::CA libidn.so
#?
#? ENVIRONMENT VARIABLES
#?      This script knows about following environment variable, which are the
#?      same as used in the Dockerfile. Use  --n  option to see the defaults.
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
#?      Following environment variables can also be used:
#?
#?          OSAFT_DIR
#?              Installation directory of O-Saft, used to find  .o-saft.pl .
#?
#?          OPENSSL_DIR
#?              Full path to installation directory of newly build openssl.
#?
#?          SSLEAY_DIR
#?              Default installation of Net::SSLeay .
#?
#?          LD_RUN_PATH
#?              Additional paths for runtime loader, used while linking with:
#?              "ld -rpath=..."
#?              Linking of openssl, libssl.so and SSLeay.so  will use  -rpath
#?              in LDFLAGS to ensure that the special library will be used.
#
# HACKER's INFO
#       This file mainly uses the commands from Dockerfile 1.20. Dockerfile's
#       syntax, which does not work in a shell, is deactivated with aliases.
#?
#? EXAMPLES
#?      Simple build with defaults:
#?          $0
#? VERSION
#?      @(#) build_openssl.sh 1.2 18/07/12 23:24:23
#?
#? AUTHOR
#?      18-jun-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

# Parameters passed to build
OSAFT_VM_SRC_SSLEAY=${OSAFT_VM_SRC_SSLEAY:="http://search.cpan.org/CPAN/authors/id/M/MI/MIKEM/Net-SSLeay-1.82.tar.gz"}
OSAFT_VM_SHA_SSLEAY=${OSAFT_VM_SHA_SSLEAY:="5895c519c9986a5e5af88e3b8884bbdc70e709ee829dc6abb9f53155c347c7e5"}
OSAFT_VM_TAR_SSLEAY=${OSAFT_VM_TAR_SSLEAY:="Net-SSLeay.tgz"}
OSAFT_VM_SRC_OPENSSL=${OSAFT_VM_SRC_OPENSSL:="https://github.com/PeterMosmans/openssl/archive/1.0.2-chacha.tar.gz"}
OSAFT_VM_SHA_OPENSSL=${OSAFT_VM_SHA_OPENSSL:="ad3d99ec091e403a3a7a678ddda38b392e3204515425827c53dc5baa92d61d67"}
OSAFT_VM_TAR_OPENSSL=${OSAFT_VM_TAR_OPENSSL:="openssl.tgz"}
OSAFT_VM_DYN_OPENSSL=${OSAFT_VM_DYN_OPENSSL:="--shared"}
#                             --static  not yet (2017) working 'cause of libkrb5

DESCRIPTION="Build special openssl (based on Peter Mosman's openssl)"
OPENSSL_VERSION=1.0.2-chacha

  OSAFT_DIR=${OSAFT_DIR:="."}
OPENSSL_DIR=${OPENSSL_DIR:=/usr/local/openssl}
 SSLEAY_DIR=${SSLEAY_DIR:=/usr/local/lib}
LD_RUN_PATH=${LD_RUN_PATH:=$OPENSSL_DIR/lib}
       PATH=${OPENSSL_DIR}/bin:$PATH
  BUILD_DIR=${BUILD_DIR:=/tmp/_src}

dir=`pwd`
optn=0

   WORK_DIR=$dir

while [ $# -gt 0 ]; do
	ich=${0##*/}
	arg="$1"
	shift
	case "$arg" in
	 '-h' | '--h' | '--help' | '-?')
		sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	  '-n' | '--n')
		optn=1
		cat <<EoT

# start build in WORK_DIR=
	$dir
# get openssl from OSAFT_VM_SRC_OPENSSL=
	$OSAFT_VM_SRC_OPENSSL
# store tar in OSAFT_VM_TAR_OPENSSL=
	$OSAFT_VM_TAR_OPENSSL
# check with OSAFT_VM_SHA_OPENSSL=
	$OSAFT_VM_SHA_OPENSSL
# build OSAFT_VM_DYN_OPENSSL=$OSAFT_VM_DYN_OPENSSL
# get Net-SSLeay from OSAFT_VM_SRC_SSLEAY=
	$OSAFT_VM_SRC_SSLEAY
# store tar in OSAFT_VM_TAR_SSLEAY=
	$OSAFT_VM_TAR_SSLEAY
# check with OSAFT_VM_SHA_SSLEAY=
	$OSAFT_VM_SHA_SSLEAY
# install openssl binary in OPENSSL_DIR=  # (full path)
	$OPENSSL_DIR
# use libraries for openssl from LD_RUN_PATH=
	$LD_RUN_PATH

# build openssl in (temporary dir) BUILD_DIR=$BUILD_DIR
# modify  OSAFT_DIR/.o-saft.pl  OSAFT_DIR=$OSAFT_DIR
# and store in:  $dir/.o-saft.pl

# PATH may be set to:
	${OPENSSL_DIR}/bin:$dir:$PATH

# found perl: `which perl`
# uses @INC=
EoT
		perl -le 'print "\t" . join "\n\t",@INC'
		echo ""
		echo "# required perl modules:"
		echo -n "	Net::DNS "
		perl -MNet::DNS -le 'print $Net::DNS::VERSION' \
		|| echo "**ERROR: Net::DNS missing"
		echo -n "	Mozilla::CA "
		perl -MMozilla::CA -le 'print $Mozilla::CA::VERSION' \
		|| echo "**ERROR: Mozilla::CA missing"
		#echo -n "	libidn.so "
		# TODO: use find in all paths of perl's @INC and search libidn.so
		echo ""
		;;
	  '--n')        optn=1; try=echo; ;;
	esac
done

# preconditions (needs to be checked with or without --n)
[   -e "$BUILD_DIR" ]   && echo "**ERROR: BUILD_DIR=$BUILD_DIR exists; exit"     && exit 2
[   -e "$OPENSSL_DIR" ] && echo "**ERROR: OPENSSL_DIR=$OPENSSL_DIR exists; exit" && exit 2
[ ! -e "$SSLEAY_DIR" ]  && echo "**ERROR: SSLEAY_DIR=$SSLEAY_DIR missing; exit"  && exit 2
[ ! -e "$OSAFT_DIR" ]   && echo "**ERROR: OSAFT_DIR=$OSAFT_DIR missing; exit"    && exit 2
[ $optn -eq 1 ] && exit 0

# create aliases, so Dockerfile's syntax can be used
alias     RUN="\cd $dir && "
alias     apk="\echo #apk"

# Dockerfile 1.20 {

# Pull, build and install enhanced openssl
RUN \
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

# Pull, build and install Net::SSLeay
RUN \
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

echo "# Adapt O-Saft's .o-saft.pl ..."
	cd    $WORK_DIR				&& \
	cp    $OSAFT_DIR/.o-saft.pl $OSAFT_DIR/.o-saft.pl-orig	&& \
	rm   -f ./.o-saft.pl			&& \
	perl -pe "s:^#\s*--openssl=.*:--openssl=$OPENSSL_DIR/bin/openssl:;s:^#?\s*--openssl-cnf=.*:--openssl-cnf=$OPENSSL_DIR/ssl/openssl.cnf:;s:^#?\s*--ca-path=.*:--ca-path=/etc/ssl/certs/:;s:^#?\s*--ca-file=.*:--ca-file=/etc/ssl/certs/ca-certificates.crt:" $OSAFT_DIR/.o-saft.pl-orig > ./.o-saft.pl && \
	chmod 666 ./.o-saft.pl

# Dockerfile 1.20 }

echo "# test o-saft.pl ..."
	$OSAFT_DIR/o-saft.pl +version |egrep -i '(openssl|SSLeay)'

