#!/bin/sh
#?
#? NAME
#?      $0 - build and install special openssl and Net::SSLeay
#?
#? SYNOPSIS
#?      $0 [OPTIONS]
#?
#? OPTIONS
#?      --h     nice option
#?      --i     ignore failed preconditions; continue always
#?      --m     install all required Perl modules also
#?      --n     do not execute, just show preconditions and where to install
#?      --debian    install required debian packages first
#?      --list      list required packages, modules, etc.
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
#?      Installation will overwrite existing data in the  specified directory
#?      for installation.
#?
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
#?        list of supported elliptic curves prime192v1 prime256v1 sect163k1 \
#?           sect163r1 sect193r1 sect233k1 sect233r1 sect283k1 sect283r1 \
#?           sect409k1 sect409r1 sect571k1 sect571r1 secp160k1 secp160r1 \
#?           secp160r2 secp192k1 secp224k1 secp224r1 secp256k1 secp384r1 \
#?           secp521r1 brainpoolP256r1 brainpoolP384r1 brainpoolP512r1
#?        list of supported ALPN, NPN      http/1.1,h2c,h2c-14,spdy/1,\
#?           npn-spdy/2,spdy/2,spdy/3,spdy/3.1,spdy/4a2,spdy/4a4,grpc-exp,\
#?           h2-14,h2-15,h2-16,http/2.0,h2
#?    = o-saft.pl +cipher --ciphermode=openssl or --ciphermode=socket =
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
#?      Errors while building the additional modules are silently ignored.
#?      Failing to build  openssl  or  Net::SSLeay  will exit the script.
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
#?              URL to fetch openssl.tgz archive. Can also be a local file.
#?
#?          OSAFT_VM_SHA_OPENSSL
#?              SHA256 checksum for the openssl-1.0.2-chacha.tar.gz archive.
#?              If set empty, cheksum is not verified.
#?
#?          OSAFT_VM_TAR_OPENSSL
#?              Name of archive file for OpenSSL (during build).
#?
#?          OSAFT_VM_DYN_OPENSSL
#?              Build (link) mode of openssl executable: --static or --shared
#?
#?          OSAFT_VM_SRC_SSLEAY
#?              URL to fetch Net-SSLeay.tar.gz archive. Can be local file.
#?
#?          OSAFT_VM_SHA_SSLEAY
#?              SHA256 checksum for the Net-SSLeay.tar.gz archive.
#?              If set empty, cheksum is not verified.
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
#?      Build with installing packages and ignoring check errors:
#?          $0 --debian --i
#?      Build including required Perl modules:
#?          $0 --m
#? VERSION
#?      @(#) install_openssl.sh 3.8 25/03/16 14:37:52
#?
#? AUTHOR
#?      18. January 2018 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

dir=`pwd`

# TODO: on error or interrupt list remaining files and dirs

# Parameters passed to build
#2018 OSAFT_VM_SRC_SSLEAY=${OSAFT_VM_SRC_SSLEAY:="http://search.cpan.org/CPAN/authors/id/M/MI/MIKEM/Net-SSLeay-1.85.tar.gz"}
#2018 OSAFT_VM_SHA_SSLEAY=${OSAFT_VM_SHA_SSLEAY:="9d8188b9fb1cae3bd791979c20554925d5e94a138d00414f1a6814549927b0c8"}
OSAFT_VM_SRC_SSLEAY=${OSAFT_VM_SRC_SSLEAY:="https://cpan.metacpan.org/authors/id/C/CH/CHRISN/Net-SSLeay-1.94.tar.gz"}
OSAFT_VM_SHA_SSLEAY=${OSAFT_VM_SHA_SSLEAY:="9d7be8a56d1bedda05c425306cc504ba134307e0c09bda4a788c98744ebcd95d"}
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

exe_mandatory="
	gcc
	make
"
# packages required for building openssl
# libidn2-0-dev is an ancient package name (back in 2017); it was replaced by
# libidn2-dev in later debian distributions
debian_packages="
	libidn11-dev
	libidn2-dev
	libgmp-dev
	libzip-dev
	libsctp-dev
	libkrb5-dev
"
lib_packages="$debian_packages"

# following not yet used
debian_packages_perl="libnet-dns-perl libnet-libidn-perl libmozilla-ca-perl"
alpine_packages_perl="perl-net-dns    perl-net-libidn    perl-mozilla-ca"

# Perl module names
perl_io_socket="IO::Socket::SSL"
perl_modules="
	Module::Build
	Net::LibIDN
	Net::LibIDN2
	Net::DNS
	Mozilla::CA
"

# dynamically compute list of Perl modules to be installed; see below
# NOTE: Net::SSLeay must always be istalled after building special openssl
install_modules="
"

# TODO: list of installed files and dirs; not yet used
uninstall_data="
	/usr/local/lib/x86_64-linux-gnu/perl/Net/SSLeay
	/usr/local/share/man/man3/IO::Socket::SSL*
	/usr/local/share/man/man3/Net::SSLeay*
	$OPENSSL_DIR
	$BUILD_DIR
"

echo_head       () {
	echo ""
	echo "$@"
} # echo_head

list_data       () {
	echo '# mandatory packages:'
	echo "#\t$exe_mandatory"
	echo "\t$lib_packages"
	echo '# openssl:'
	echo "#\t$OSAFT_VM_SRC_OPENSSL"
	echo '# Perl modules:'
	echo "#\t$OSAFT_VM_SRC_SSLEAY"
	echo "\t$perl_modules"
	echo "\t$perl_io_socket"
	echo ""
	return
} # list_data

apt_install_debian  () {
	err=0
	echo_head '### install debian packages ...'
	for pkg in $exe_mandatory $debian_packages ; do
		apt install --no-install-recommends $pkg
	done
	echo "# installed packages: $exe_mandatory $lib_packages"
	return
} # apt_install_debian

mcpan_install   () {
	#? install module with MCPAN
	_mod=$1
	err=0
	txt=""
	echo "### install perl modul $_mod ..."
	perl -MCPAN -e "install $_mod"   || txt="**ERROR: installation failed for $_mod"
	[ -n "$txt" ] && return 1
	# FIXME: perl -MCPAN does not return proper error codes; need
	#        to parse output, grrr
	return 0
} # mcpan_install

mcpan_modules   () {
	#? install modules (with --m only)
	err=0
	echo_head '### install Perl modules ...'
	for mod in $install_modules ; do
		txt=""
		[ "Module::Build" = $mod ] && continue
		    # cannot be installed, -MCPAN does it automatically if needed
		mcpan_install $mod
		err=$?
	done
	[ 0 -ne $err ] && echo "**ERROR: modules installation failed"
	return
} # mcpan_modules

show_environment () {
	#? show passed environment variables
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
# perl uses @INC=
EoT
	perl -le 'print "\t" . join "\n\t",@INC'
	return
} # show_environment

check_mandatory () {
	err=0
	echo_head "# required mandatory tools:"
	for exe in $exe_mandatory ; do
		txt=""
		echo -n "	$exe "
		exe=$(\command -v $exe)
		if [ -n "$exe" ]; then
			echo "\tOK $exe"
		else
			echo "\tmissing"
			miss="$miss $exe"
			err=1
		fi
	done
	[ 1 -eq $err  ] && echo "**WARNING: development tools need to be installed"
	return
} # check_mandatory

check_modules   () {
	err=0
	echo_head "# required Perl modules (installed with  --m  option):"
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
		echo "$txt"
	done
	[ 1 -eq $err  ] && miss="$miss modules,"
	return
} # check_modules

check_libraries () {
	lib=0
	_log=/tmp/${0##*/}.$$.find_lib.log
	echo_head "# required libraries:"
	txt=`find /usr/lib -name libidn\.\*`
	[ -z "$txt" ] && txt="**ERROR: libidn.so missing, consider installing libidn11-dev" && miss="$miss libidn,"
	echo "	libidn.so $txt"
	for pack in $lib_packages ; do
		ok=1
		txt=`find /usr -name $pack 2>>$_log`
		[ -z "$txt" ] && txt="**ERROR: $pack missing, consider installing $pack" && ok=0 && lib=1
		[ 1 -eq $ok ] && txt="\tOK $txt"
		echo "	$pack $txt"
	done
	[ -s "$_log" ] && echo "**WARNING: searching for libraries returned following errors:" && cat "$_log"
	rm $_log
	[ 1 -eq $lib ] && miss="$miss libraries," && err=1
	return
} # check_libraries

check_directories () {
	echo ""
	echo -n "# requred directories:"
	txt=""
	[   -e "$BUILD_DIR" ]   && txt="$txt\n**WARNING: exists: BUILD_DIR=$BUILD_DIR"
	[   -e "$SSLEAY_DIR" ]  && txt="$txt\n**WARNING: exists: SSLEAY_DIR=$SSLEAY_DIR"
	[   -e "$OPENSSL_DIR" ] && txt="$txt\n**WARNING: exists: OPENSSL_DIR=$OPENSSL_DIR"
	[ ! -e "$OSAFT_DIR" ]   && txt="$txt\n**ERROR:  missing: OSAFT_DIR=$OSAFT_DIR"
	[   -n "$txt" ] && miss="$miss directories" && echo $txt.
	return
} # check_directories

test_osaft      () {
	echo_head "### test o-saft.pl ..."
pwd
	o_saftrc=$OSAFT_DIR/.o-saft.pl
	[ -e  $o_saftrc ] || \
		echo "**WARNING: $o_saftrc not found; testing without"
	o_saft=$OSAFT_DIR/o-saft.pl
	if [ ! -e  $o_saft ]; then
		echo "**WARNING: $o_saft missing; trying to find in PATH"
		o_saft=o-saft.pl
	fi
	# call in installation dir without --no-rc to ensure adapted .o-saft.pl is used
	cd $OSAFT_DIR
	echo "$o_saft +version |egrep -i '(SSL|supported)'"
	$o_saft +version |egrep -i '(SSL|supported|cert)'
	return
} # test_osaft

echo "# $0 $@ ..."
optd=0
opti=0
optm=0
optn=0
while [ $# -gt 0 ]; do
	ich=${0##*/}
	arg="$1"
	shift
	case "$arg" in
	  +VERSION)     echo 3.8 ; exit; ;; # for compatibility
	  --version)    \sed -ne '/^#? VERSION/{' -e n -e 's/#?//' -e p -e '}' $0; exit 0; ;;
	  -h | --h | --help | '-?' | '/?')
		sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	  -list | --list)       list_data; exit 0; ;;
	  -debian | --debian)   optd=1; ;;
	  -i | --i)             opti=1; ;;
	  -m | --m)             optm=1; ;;
	  -n | --n)             optn=1; try=echo;
	        move_rc=""
		[ -e $dir/.o-saft.pl ] && move_rc="
# move existing  $dir/.o-saft.pl to $dir/.o-saft.pl-orig"
		;;
	  *)
		echo "**ERROR: unknown option '$arg'; exit"
		echo "**USAGE: $0 [--h|--m|--n]"
		exit 2
		;;
	esac
done

### install packages first
[ 1 -eq $optd  ] && apt_install_debian

### preconditions (needs to be checked with or without --n)
miss=""
err=0

echo_head "### Configuration"
show_environment
echo_head "### Preconditions"
check_mandatory
check_modules
check_libraries
check_directories
if [ 0 -eq $err ]; then
	echo ''
	echo '# OK all preconditions satisfied'
	echo ''
	if [ 1 -eq $optn  ]; then
		# brief information what will be done
		echo "#    build and install openssl in $OPENSSL_DIR"
		echo "#    build and install Net::SSLeay in $SSLEAY_DIR"
		echo ''
		[ 1 -eq $optm ] &&
		echo '#    build and install Perl modules using:' &&
		echo "#    perl -MCPAN -e install $install_modules"
		exit 0
	fi
else
        # TODO: print only required packages and moduls in Hint below
	cat <<EoT

!!Hint: install packages like (examples):
        $debian_packages_perl
        $alpine_packages_perl
# Note  all lib*-dev  are only necessary for compiling openssl and may be
#       removed afterwards. Same for  gcc  and  make package.

!!Hint: Perl modules may also be installed with "perl -MCPAN -e "install ..."
        $perl_modules
**ERROR: preconditions incomplete: $miss; exit

!!Hint: use  --i  option to ignore errors and continue building opnssl.

EoT
	[ 0 -eq $opti ] && exit 2
	echo ""
	echo "#    continue due to  --i  was given."
	echo ""
fi
[ 1 -eq $optn  ] && exit 0

### install modules
[ 1 -eq $optm  ] && mcpan_modules

### install openssl
echo_head '### install openssl ...'
alias   RUN="\cd $dir && "  # create aliases, so Dockerfile's syntax can be used
alias   apk="\echo '#'apk"  #

# Dockerfile.openssl 3.10 {

#dbx# set -x
RUN \
	echo "#== Pull, build and install enhanced openssl" && \
	apk add --no-cache gmp-dev lksctp-tools-dev	&& \
	cd    $WORK_DIR				&& \
	mkdir -p $BUILD_DIR $OPENSSL_DIR	&& \
	echo "#= get and extract $OSAFT_VM_TAR_OPENSSL" && \
	[   -f "$OSAFT_VM_SRC_OPENSSL" ]        && \
		cp "$OSAFT_VM_SRC_OPENSSL" "$OSAFT_VM_TAR_OPENSSL" ; \
	[ ! -f "$OSAFT_VM_TAR_OPENSSL" ]        && \
		wget --no-check-certificate $OSAFT_VM_SRC_OPENSSL -O $OSAFT_VM_TAR_OPENSSL && \
	echo "#=  check sha256 if there is one" && \
	[ -n "$OSAFT_VM_SHA_OPENSSL" ]		&& \
		echo "$OSAFT_VM_SHA_OPENSSL  $OSAFT_VM_TAR_OPENSSL" | sha256sum -c ; \
	\
	tar   -xzf $OSAFT_VM_TAR_OPENSSL -C $BUILD_DIR --strip-components=1	&& \
	cd    $BUILD_DIR			&& \
	echo "#=  patch openssl.cnf for GOST"   && \
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
	echo "#=  config with all options, even if they are default" && \
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
	echo "#=  make depend ..."      && make depend && \
	echo "#=  make ..."             && make && \
	echo "#=  make report -i ..."   && make report -i && \
	echo "#=  make install ..."     && make install	&& \
		# make report most likely fails, hence -i
	# simple test
	echo -n "# number of ciphers $OPENSSL_DIR/bin/openssl: " && \
	$OPENSSL_DIR/bin/openssl ciphers -V ALL:COMPLEMENTOFALL:aNULL|wc -l && \
	echo "#=  cleanup"                       && \
	apk  del --purge gmp-dev lksctp-tools-dev && \
	cd    $WORK_DIR				&& \
	rm   -rf $BUILD_DIR $OSAFT_VM_TAR_OPENSSL && \
	\
	echo "#== Pull, build and install Net::SSLeay" && \
	cd    $WORK_DIR				&& \
	mkdir -p $BUILD_DIR			&& \
	[   -f "$OSAFT_VM_SRC_SSLEAY" ]         && \
		cp "$OSAFT_VM_SRC_SSLEAY"  "$OSAFT_VM_TAR_SSLEAY" ; \
	[ ! -f "$OSAFT_VM_TAR_SSLEAY" ]         && \
		wget --no-check-certificate $OSAFT_VM_SRC_SSLEAY -O $OSAFT_VM_TAR_SSLEAY && \
	# check sha256 if there is one
	[ -n "$OSAFT_VM_SHA_SSLEAY" ]		&& \
		echo "$OSAFT_VM_SHA_SSLEAY  $OSAFT_VM_TAR_SSLEAY" | sha256sum -c ; \
	\
	tar   -xzf $OSAFT_VM_TAR_SSLEAY -C $BUILD_DIR --strip-components=1	&& \
	echo "#=  install additional packages for Net-SSLeay ..." && \
	apk add --no-cache perl-net-dns perl-net-libidn perl-mozilla-ca		&& \
	echo "#=  configure and make Net-SSLeay" && \
	cd    $BUILD_DIR			&& \
	perl -i.orig -pe 'if (m/^#define\s*REM_AUTOMATICALLY_GENERATED_1_09/){print "const SSL_METHOD * SSLv2_method()\n\";}' SSLeay.xs	&& \
		# quick&dirty patch, results in warning, which can be ignored
		# Warning: duplicate function definition 'SSLv2_method' detected in SSLeay.xs, line 4256
		# Mar/2025: "const SSL_METHOD * SSLv3_method()"  removed as
		#   modern gcc complain with error about duplicate definitions
	LDFLAGS="-rpath=$LD_RUN_PATH"   && export LDFLAGS	&& \
	echo "n" | env OPENSSL_PREFIX=$OPENSSL_DIR \
		   perl Makefile.PL DEFINE=-DOPENSSL_BUILD_UNSAFE=1 \
		   INC=-I$OPENSSL_DIR/include PREFIX=$SSLEAY_DIR && \
		# Makefile.PL asks for "network tests", hence pipe "n" as answer
	make && make test -i && make install	&& \
	cd    $WORK_DIR				&& \
	rm   -rf $BUILD_DIR $OSAFT_VM_TAR_SSLEAY && \
	\
	echo "#== Adapt O-Saft's .o-saft.pl ..." && \
	cd    $WORK_DIR				&& \
	[ -e  $OSAFT_DIR/.o-saft.pl ]		&& \
	  mv  $OSAFT_DIR/.o-saft.pl $OSAFT_DIR/.o-saft.pl-orig	&& \
	  cp  $OSAFT_DIR/.o-saft.pl-orig $OSAFT_DIR/.o-saft.pl	&& \
	  rm  -f ./.o-saft.pl			&& \
	  perl -pe "s:^#\s*--openssl=.*:--openssl=$OPENSSL_DIR/bin/openssl:;s:^#?\s*--openssl-cnf=.*:--openssl-cnf=$OPENSSL_DIR/ssl/openssl.cnf:;s:^#?\s*--ca-path=.*:--ca-path=/etc/ssl/certs/:;s:^#?\s*--ca-file=.*:--ca-file=/etc/ssl/certs/ca-certificates.crt:" $OSAFT_DIR/.o-saft.pl-orig > ./.o-saft.pl && \
	  chmod 666 ./.o-saft.pl

# Dockerfile.openssl 3.10 }

# NOTE --ca-path and --ca-file are set to /etc/ because special openssl does
#      not provide its on CA files; expects that /etc/ssl/certs/ exists.

echo_head "### install IO::Socket::SSL"
mcpan_install $perl_io_socket


echo_head "### test o-saft.pl"
test_osaft

echo_head "### cleanup"
[ -e "$BUILD_DIR" ] && \
	echo "**WARNING: BUILD_DIR=$BUILD_DIR exists after build; removing" && \
	rm -rf $BUILD_DIR

