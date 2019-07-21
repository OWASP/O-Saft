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
#?      --m - install all Perl modules
#?      --n - do not execute, just show where to install
#?
#? DESCRIPTION
#?      Build special openssl based on Peter Mosman's openssl.  Enables SSLv2
#?      and SSLv3 and all possible ciphers.
#?      Installs build in specified directory;  default: /usr/local/openssl .
#?      Additionally builds Perl module Net::SSLeay based on special openssl.
#?      Net::SSLeay will be installed in  /usr/local/lib .
#?      Modifies  .o-saft.pl  (keeping existing one in  .o-saft.pl-orig).
#?      This script is intended to be executed in the  installation directory
#?      of O-Saft.
#?
#?      Finally this script starts  "o-saft.pl +version"  using the installed
#?      openssl binary and the installed Net::SSLeay.  The output should look
#?      like (paths may differ):
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
#?      DO NOT USE THESE INSTALLATIONS ON PRODUCTIVE SYSTEMS.
#?
#? PRECONDITIONS
#?      Script needs write access to installation directories (/usr/local and
#?      /usr/local/lib by default).
#?      To build openssl, following libraries and include files are needed:
#?          gmp krb5 libsctp zlib
#?      Assumes that ca-certificates are install in /etc/ssl/certs/ .
#?      Assumes that following Perl modules are installed:
#?          Module::Build Net::DNS Net::LibIDN1 libidn.so Mozilla::CA
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
#?          PERL_SRC_IOSOCKET
#?              URL to IO::Socket::SSL archive.
#?
#?          PERL_SRC_NET_IDN
#?              URL to Net::LibIDN archive.
#?
#?          PERL_SRC_NET_DNS
#?              URL to Net::DNS archive.
#?
#?          PERL_SRC_MOZILLA
#?              URL to Mozilla::CA archive.
#?
#?          OSAFT_DIR
#?              Installation directory of O-Saft, used to find  .o-saft.pl .
#?
#?          OPENSSL_DIR
#?              Full path to installation directory of newly build openssl .
#?
#?          SSLEAY_DIR
#?              Full path to installation directory of Net::SSLeay .
#?
#?          LD_RUN_PATH
#?              Additional paths for runtime loader, used while linking with:
#?              "ld -rpath=..."
#?              Linking of openssl, libssl.so and SSLeay.so  will use  -rpath
#?              in LDFLAGS to ensure that the special library will be used.
#
# HACKER's INFO
#       This file mainly uses the commands from Dockerfile 1.30. Dockerfile's
#       syntax, which does not work in a shell, is deactivated with aliases.
#       This code is scopend with
#         # Dockerfile 1.30 {
#         ...
#         # Dockerfile 1.30 }
#       Please backport any changes in scope to Dockerfile.
#
#       Each Perl modul to be installed may have its own prerequisites. These
#       are mainly described in the  README  file. This script does not (yet)
#       check or fullfil these prerequisites.
#       Known prerequisites (according tools used 7/2019):
#       * Net::DNS
#           Digest::HMAC, Digest::MD5, Digest::SHA, File::Spec, MIME::Base64,
#           Time::Local, Test::More, Digest::BubbleBabble, Net::DNS::SEC,
#           Net::LibIDN2, IO::Socket, IO::Socket::IP
#       * IO::Socket::SSL
#           Net::SSLeay 1.46 or newer
#?
#? EXAMPLES
#?      Simple build with defaults:
#?          $0
#? VERSION
#?      @(#)  1.13 19/07/22 01:58:58
#?
#? AUTHOR
#?      18-jun-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

dir=`pwd`

# Parameters passed to build
OSAFT_VM_SRC_SSLEAY=${OSAFT_VM_SRC_SSLEAY:="http://search.cpan.org/CPAN/authors/id/M/MI/MIKEM/Net-SSLeay-1.85.tar.gz"}
OSAFT_VM_SHA_SSLEAY=${OSAFT_VM_SHA_SSLEAY:="9d8188b9fb1cae3bd791979c20554925d5e94a138d00414f1a6814549927b0c8"}
OSAFT_VM_TAR_SSLEAY=${OSAFT_VM_TAR_SSLEAY:="Net-SSLeay.tgz"}
OSAFT_VM_SRC_OPENSSL=${OSAFT_VM_SRC_OPENSSL:="https://github.com/PeterMosmans/openssl/archive/1.0.2-chacha.tar.gz"}
OSAFT_VM_SHA_OPENSSL=${OSAFT_VM_SHA_OPENSSL:="ad3d99ec091e403a3a7a678ddda38b392e3204515425827c53dc5baa92d61d67"}
OSAFT_VM_TAR_OPENSSL=${OSAFT_VM_TAR_OPENSSL:="openssl.tgz"}
OSAFT_VM_DYN_OPENSSL=${OSAFT_VM_DYN_OPENSSL:="--shared"}
#                             --static  not yet (2017) working 'cause of libkrb5

DESCRIPTION="Build special openssl (based on Peter Mosman's openssl)"
OPENSSL_VERSION=1.0.2-chacha

# set variables used in the code copied from Dockerfile to build openssl
  OSAFT_DIR=${OSAFT_DIR:="."}
OPENSSL_DIR=${OPENSSL_DIR:=/usr/local/openssl}
 SSLEAY_DIR=${SSLEAY_DIR:=/usr/local/lib}
LD_RUN_PATH=${LD_RUN_PATH:=$OPENSSL_DIR/lib}
       PATH=${OPENSSL_DIR}/bin:$PATH
  BUILD_DIR=${BUILD_DIR:=/tmp/_src}
   WORK_DIR=$dir

# Perl modules from cpan (last check 7/2019):
PERL_SRC_IOSOCKET=${PERL_SRC_IOSOCKET:="https://cpan.metacpan.org/authors/id/S/SU/SULLR/IO-Socket-SSL-2.066.tar.gz"}
#PERL_SRC_NET_IDN=${PERL_SRC_NET_IDN:="https://cpan.metacpan.org/authors/id/T/TH/THOR/Net-LibIDN-0.12.tar.gz"}
PERL_SRC_NET_IDN=${PERL_SRC_NET_IDN:="https://cpan.metacpan.org/authors/id/T/TH/THOR/Net-LibIDN2-1.00.tar.gz"}
PERL_SRC_NET_DNS=${PERL_SRC_NET_DNS:="https://cpan.metacpan.org/authors/id/N/NL/NLNETLABS/Net-DNS-1.20.tar.gz"}
PERL_SRC_MOZILLA=${PERL_SRC_MOZILLA:="https://cpan.metacpan.org/authors/id/A/AB/ABH/Mozilla-CA-20180117.tar.gz"}
# unfortunately metacpan.org does not provide checksums

optm=0
optn=0
while [ $# -gt 0 ]; do
	ich=${0##*/}
	arg="$1"
	shift
	case "$arg" in
	  '-h' | '--h' | '--help' | '-?')
		sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	  '-m' | '--m')
		optm=1
		;;
	  '-n' | '--n')
		optn=1
	        try=echo
	        move_rc=""
		[ -e $dir/.o-saft.pl ] && move_rc="
# move existing  $dir/.o-saft.pl to $dir/.o-saft.pl-orig"
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
# install openssl binary in OPENSSL_DIR=  # (full path)
	$OPENSSL_DIR
# use libraries for openssl from LD_RUN_PATH=
	$LD_RUN_PATH

# get Net-SSLeay from OSAFT_VM_SRC_SSLEAY=
	$OSAFT_VM_SRC_SSLEAY
# store tar in OSAFT_VM_TAR_SSLEAY=
	$OSAFT_VM_TAR_SSLEAY
# check with OSAFT_VM_SHA_SSLEAY=
	$OSAFT_VM_SHA_SSLEAY
# install Net-SSLeay in (path from Net-SSLeay's Makefile)
	/usr/local/lib

# build openssl in (temporary dir) BUILD_DIR=$BUILD_DIR  $move_rc
# modify  OSAFT_DIR/.o-saft.pl  OSAFT_DIR=$OSAFT_DIR
# and store in:  $dir/.o-saft.pl

# consider setting PATH to:
	${OPENSSL_DIR}/bin:$dir:$PATH

# found perl: `which perl`
# uses @INC=
EoT
		perl -le 'print "\t" . join "\n\t",@INC'
		;;
	esac
done

# preconditions (needs to be checked with or without --n)
err=0
echo ""
echo "# required Perl modules:"
for mod in Module::Build IO::Socket::SSL Net::LibIDN Net::DNS Mozilla::CA ; do
	txt=""
	echo -n "	$mod "
	perl -M$mod -le "print ${mod}::Version" || txt="**ERROR: $mod missing"
	echo "$txt"
	[ -n "$txt" ] && err=1
done

echo ""
echo "# required libraries:"
txt=`find /lib -name libidn\.\*`
[ -z "$txt" ] && txt="**ERROR: libidn.so missing" && err=1
echo "	libidn.so $txt"

# FIXME: libidn11-dev also required
txt=`find /usr -name libidn2-0-dev`
[ -z "$txt" ] && txt="**ERROR: libidn2-0-dev missing" && err=1
echo "	libidn2-0-dev $txt"

txt=`find /usr -name libgmp-dev`
[ -z "$txt" ] && txt="**ERROR: libgmp-dev missing" && err=1
echo "	libgmp-dev $txt"

txt=`find /usr -name libsctp-dev`
[ -z "$txt" ] && txt="**ERROR: libsctp-dev missing" && err=1
echo "	libsctp-dev $txt"

# FIXME: check for libkrb5-dev and libzip-dev missing

echo ""
echo "# requred directories:"
[ ! -e "$OSAFT_DIR" ]   && echo "**ERROR: OSAFT_DIR=$OSAFT_DIR missing; exit"    && err=1
[   -e "$BUILD_DIR" ]   && echo "**ERROR: BUILD_DIR=$BUILD_DIR exists; exit"     && err=1
[   -e "$OPENSSL_DIR" ] && echo "**ERROR: OPENSSL_DIR=$OPENSSL_DIR exists; exit" && err=1
[ ! -e "$SSLEAY_DIR" ]  && echo "**ERROR: SSLEAY_DIR=$SSLEAY_DIR missing; exit"  && err=1
echo ""
if [ 0 -ne $err ]; then
	echo "**ERROR: preconditions incomplete; exit"
	echo '!!Hint: install packages like:'
	echo '        perl-net-dns perl-net-libidn perl-mozilla-ca'
	echo '        libnet-dns-perl libnet-libidn-perl libmozilla-ca-perl'
	echo '        libmodule-build-perl'
	echo '        libgmp-dev libsctp-dev libzip-dev libidn11-dev libidn2-0-dev'
	echo '# Note  libgmp-dev libsctp-dev libzip-dev  are only necessary for compiling openssl'
	[ 0 -eq $optm ] && exit 2
fi
[ 1 -eq $optn ] && exit 0

# NOTE: Module::Build is a hard requirement and must be installed in the OS
mod="Module::Build" # hard requirement
txt=""
perl -M$mod -le "print ${mod}::Version" || txt="**ERROR: $mod missing"
[ -n "$txt" ] && echo "$txt" && exit 2

if [ 1 -eq $optm ]; then
	err=0
	mod="Net::LibIDN"
	echo ""
	echo "# install perl modul $mod ..."
	perl -MCPAN -e "install $mod"   || err=1
	mod="Net::LibIDN2"
	echo ""
	echo "# install perl modul $mod ..."
	perl -MCPAN -e "install $mod"   || err=1
	[ 0 -ne $err ] && echo "**ERROR: module »${mod##*/}« installation failed; exit" && exit 2

	err=0
	# TODO: replace installing from -tgz with installing using CPAN
	# TODO: IO::Socket::SSL uses Net::SSLeay, so build it after Net::SSLeay (again?)
	for mod in $PERL_SRC_IOSOCKET $PERL_SRC_NET_DNS $PERL_SRC_MOZILLA ; do
		err=1   # reset if build succeeds
		tar=perllib.tgz
		# TODO: Mozilla-CA-20180117 is in subdirectory
		# IO::Socket::SLL's Makefile.PL ask interactivly, grrr
		echo ""
		cd    /tmp
		echo "# install perl modul ${mod##*/} ..."
		wget  --quiet --no-check-certificate $mod -O $tar	&& \
		rm    -rf $BUILD_DIR       && mkdir $BUILD_DIR		&& \
		tar   -xzf $tar -C $BUILD_DIR --strip-components=1	&& \
		cd    $BUILD_DIR					&& \
		#[ -d Mozilla-CA-20180117 ] && cd Mozilla-CA-20180117	&& \
		[ -f Makefile.PL ] && perl  Makefile.PL --no-online-tests	&& \
			set -x  && \
			make    &&   make test  &&  make install	&& \
			set +x  && \
		err=0 && \
		cd    /tmp  &&  rm -rf $tar
	done

	[ 0 -ne $err ] && echo "**ERROR: module »{mod« installation failed; exit" && exit 2
fi

# create aliases, so Dockerfile's syntax can be used
alias   RUN="\cd $dir && "
alias   apk="\echo '#'apk"

# Dockerfile 1.30 {

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
	[ -e  $OSAFT_DIR/.o-saft.pl ]		&& \
	  mv  $OSAFT_DIR/.o-saft.pl $OSAFT_DIR/.o-saft.pl-orig	&& \
	  cp  $OSAFT_DIR/.o-saft.pl-orig $OSAFT_DIR/.o-saft.pl	&& \
	  rm  -f ./.o-saft.pl			&& \
	  perl -pe "s:^#\s*--openssl=.*:--openssl=$OPENSSL_DIR/bin/openssl:;s:^#?\s*--openssl-cnf=.*:--openssl-cnf=$OPENSSL_DIR/ssl/openssl.cnf:;s:^#?\s*--ca-path=.*:--ca-path=/etc/ssl/certs/:;s:^#?\s*--ca-file=.*:--ca-file=/etc/ssl/certs/ca-certificates.crt:" $OSAFT_DIR/.o-saft.pl-orig > ./.o-saft.pl && \
	  chmod 666 ./.o-saft.pl

# Dockerfile 1.30 }

echo "# test o-saft.pl ..."
	$OSAFT_DIR/o-saft.pl +version |egrep -i '(openssl|SSLeay)'

