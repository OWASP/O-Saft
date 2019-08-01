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
#?      --m - install all required Perl modules also
#?      --n - do not execute, just show preconditions and where to install
#?
#? DESCRIPTION
#?      Build special openssl based on  Peter Mosman's openssl.  Additionally
#?      build Perl module  Net::SSLeay  based on previous build openssl.
#?      Modifies  ./.o-saft.pl  (keeping existing one in  .o-saft.pl-orig).
#?
#?      This script is intended to be executed in the  installation directory
#?      of O-Saft.
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
#? DETAILS
#?
#?    openssl
#?      SSLv2, SSLv3 and all possible ciphers are enabled. All depricated and
#?      known insecure extensions are enabled.
#?      Installs build in specified directory;  default: /usr/local/openssl .
#?
#?    Net::SSLeay
#?      Building  Net::SSLeay  is based on previously configured and compiled
#?      special openssl.
#?      Installs build in specified directory;  default: /usr/local/lib .
#?
#?    Other Perl modules
#?      Additional Perl modules will be install with option  --m . 
#?      These Perl modules are installed using "perl -MCPAN -e "install ".
#?      Installs build in specified directory;  default: /usr/local/share .
#?
#?      Finally this script starts  "o-saft.pl +version"  using the installed
#?      openssl binary and the installed Net::SSLeay.  The output should look
#?      like (paths may differ):
#?    -------------------------------------------------------------------------
#?    ### test o-saft.pl ...
#?           ::OPENSSL_VERSION_NUMBER()    0x100020b0 (268443824)
#?           ::SSLeay()                    0x100020b0 (268443824)
#?        Net::SSLeay::SSLeay_version()    OpenSSL 1.0.2-chacha (1.0.2k-dev)
#?    = openssl =
#?        external executable              /usr/local/openssl/bin/openssl
#?        version of external executable   OpenSSL 1.0.2-chacha (1.0.2k-dev)
#?        full path to openssl.cnf file    /usr/local/openssl/ssl/openssl.cnf
#?        common openssl.cnf files         /usr/lib/ssl/openssl.cnf /etc/ssl/openssl.cnf /System//Library/OpenSSL/openssl.cnf /usr/ssl/openssl.cnf
#?        directory with PEM files for CAs /etc/ssl/certs/
#?        PEM format file with CAs         /etc/ssl/certs/ca-certificates.crt
#?        common paths to PEM files for CAs /etc/ssl/certs /usr/lib/certs /System/Library/OpenSSL
#?        common PEM filenames for CAs     ca-certificates.crt certificates.crt certs.pem
#?        Net::SSLeay::
#?        PEM format file with CAs         /etc/ssl/certs/ca-certificates.crt
#?        common paths to PEM files for CAs /etc/ssl/certs /usr/lib/certs /System/Library/OpenSSL
#?        number of supported ciphers      201
#?        openssl supported SSL versions   SSLv2 SSLv3 TLSv1 TLSv11 TLSv12
#?        o-saft.pl known SSL versions     SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 TLSv13 DTLSv09 DTLSv1 DTLSv11 DTLSv12 DTLSv13
#?        IO::Socket::SSL        2.066    /usr/local/share/perl/5.28.1/IO/Socket/SSL.pm
#?        Net::SSLeay            1.85     /usr/local/lib/x86_64-linux-gnu/perl/5.28.1/Net/SSLeay.pm
#?    -------------------------------------------------------------------------
#?
#?      This script does no cleanup if any building of  Perl modules, openssl
#?      or  Net::SSLeay fails. Sucessfully build parts are not removed. There
#?      may be garbage in  BUILD_DIR  and/or the  CPAN  directory.
#?      Errors when bulding the additional Perl modules are silently ignored.
#?      Failing to build openssl or Net::SSLeay will exit the script.
#?
#? PRECONDITIONS
#?      The script needs write access to installation directories (/usr/local
#?      and /usr/local/lib by default).
#?      To build openssl, following libraries and include files are needed:
#?          gmp krb5 libsctp zlib
#?      Hints about missing packages and libraries are given  if started with
#?      option  --n .
#?      Assumes that ca-certificates are install in /etc/ssl/certs/ .
#?
#? ENVIRONMENT VARIABLES
#?      This script knows about following environment variable, which are the
#?      same as used in the Dockerfile. Use  --n  option to see the defaults.
#?      These variables can be used to:
#?        * adapt the sources and their checksums to be used
#?        * the directory where to find O-Saft
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
#?      Build including required Perl modules:
#?          $0 --m
#? VERSION
#?      @(#)  1.26 19/08/01 09:19:36
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

lib_packages="
	libidn2-0-dev
	libgmp-dev
	libzip-dev
	libsctp-dev
	libkrb5-dev
"
# FIXME: libidn11-dev also required

perl_modules="
	Module::Build
	IO::Socket::SSL
	Net::LibIDN
	Net::LibIDN2
	Net::DNS
	Mozilla::CA
"

# dynamically compute list of Perl modules to be installed
# NOTE: Net::SSLeay must always be istalled after building special openssl
install_modules="
"

optm=0
optn=0
while [ $# -gt 0 ]; do
	ich=${0##*/}
	arg="$1"
	shift
	case "$arg" in
	  '+VERSION')   echo 1.26 ; exit; ;; # for compatibility
	  '--version')
		\sed -ne '/^#? VERSION/{' -e n -e 's/#?//' -e p -e '}' $0
		exit 0
		;;

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

### Configuration

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
# perl uses @INC=
EoT
		perl -le 'print "\t" . join "\n\t",@INC'
		;;
	esac
done

### preconditions (needs to be checked with or without --n)
miss=""
err=0
echo ""
echo "### Preconditions"
echo ""
echo "# required Perl modules (installed with  --m  option):"
for mod in $perl_modules ; do
	txt=""
	echo -n "	$mod "
	perl -M$mod -le "print ${mod}::Version" || txt="**ERROR: $mod missing"
	if [ -z "$txt" ]; then
		# found: print OK followed by directory of used module
		loc=`perl -M$mod -le 'my $idx='$mod'; $idx=~s#::#/#g; print $INC{"${idx}.pm"}'`
		txt="\tOK $loc"
	else
		# not found: add to modules to be installed
		install_modules="$install_modules $mod"
		err=1
	fi
	#[ -z "$txt" ] && txt="\tOK" || err=1
	echo "$txt"
done
[ 1 -eq $err  ] && miss="$miss modules,"
[ 1 -eq $optm ] && err=0 # when --m was given continue even if Perl modules are missing

# FIXME: checked package names are based on debian, and desendents
lib=0
echo ""
echo "# required libraries:"
txt=`find /usr/lib -name libidn\.\*`
[ -z "$txt" ] && txt="**ERROR: libidn.so missing"    && miss="$miss libidn,"
echo "	libidn.so $txt"

for pack in $lib_packages ; do
	ok=1
	txt=`find /usr -name $pack`
	[ -z "$txt" ] && txt="**ERROR: $pack missing" && ok=0 && lib=1
	[ 1 -eq $ok ] && txt="\tOK $txt"
	echo "	$pack $txt"
done
[ 1 -eq $lib ] && miss="$miss libraries," && err=1

echo ""
echo -n "# requred directories:"
txt=""
[ ! -e "$OSAFT_DIR" ]   && txt="$txt\n**ERROR: missing: OSAFT_DIR=$OSAFT_DIR"
[   -e "$BUILD_DIR" ]   && txt="$txt\n**ERROR: exists:  BUILD_DIR=$BUILD_DIR"
[   -e "$OPENSSL_DIR" ] && txt="$txt\n**ERROR: exists:  OPENSSL_DIR=$OPENSSL_DIR"
[ ! -e "$SSLEAY_DIR" ]  && txt="$txt\n**ERROR: missing: SSLEAY_DIR=$SSLEAY_DIR"
[   -n "$txt" ] && miss="$miss directories" && echo $txt.
echo ""
if [ 0 -eq $err ]; then
	echo '# OK all preconditions satisfied'
	echo ''
	[ 1 -eq $optn  ] && exit 0
else
	cat <<EoT

!!Hint: install packages like (examples):
        $lib_packages
        perl-net-dns perl-net-libidn perl-mozilla-ca
        libnet-dns-perl libnet-libidn-perl libmozilla-ca-perl
        libmodule-build-perl
# Note  all lib*-dev  are only necessary for compiling openssl and may be
#       removed afterwards.

!!Hint: Perl modules may also be installed with "perl -MCPAN -e "install ..."
        $perl_modules
**ERROR: preconditions incomplete: $miss; exit
EoT
        # TODO: print only required packages and moduls in Hint above
	exit 2
fi
[ 1 -eq $optn  ] && exit 0  # defensive programming, never reached

### install modules (with --m only)
if [ 1 -eq $optm ]; then
	#[ 1 -eq $optf ] && install_modules="$perl_modules"
	err=0
	for mod in $install_modules ; do
		txt=""
		[ "Module::Build" = $mod ] && continue
		    # cannot be installed, -MCPAN does it automatically if needed
		echo "### install perl modul $mod ..."
		perl -MCPAN -e "install $mod"   || txt="**ERROR: installation failed for $mod"
		[ -n "$txt" ] && err=1
		# FIXME: perl -MCPAN does not return proper error codes; need
		#        to parse output, grrr
	done
	perl -MCPAN -e "install $mod"   || err=1
	[ 0 -ne $err ] && echo "**ERROR: module installation failed"
	# $err no longer used
fi

### install openssl
echo "### install openssl ..."
alias   RUN="\cd $dir && "  # create aliases, so Dockerfile's syntax can be used
alias   apk="\echo '#'apk"  #

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

# NOTE --ca-path and --ca-file are set to /etc/ because special openssl does
#      not provide its on CA files; expects that /etc/ssl/certs/ exists.

### test o-saft.pl
echo "### test o-saft.pl ..."
[ -e  $OSAFT_DIR/.o-saft.pl ] || echo "**WARNING: $OSAFT_DIR/.o-saft.pl not found; testing without"
o_saft=$OSAFT_DIR/o-saft.pl
if [ ! -e  $o_saft ]; then
	echo "**WARNING: $o_saft missing; trying to find in PATH"
	o_saft=o-saft.pl
fi
# --no-rc ensures that all internal defaults are shown
echo "$o_saft +version --no-rc |egrep -i '(SSL|supported)'"
$o_saft +version --no-rc |egrep -i '(SSL|supported|cert)'

