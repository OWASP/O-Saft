#! /bin/sh
#?
#? NAME
#?      $0 - install script for O-Saft
#?
#? SYNOPSIS
#?      $0 [options] [installation directory]
#?
#? DESCRIPTION
#?      Some people want to have an installation script, in particular named
#?      INSTALL.sh, even O-Saft should work without a specific installation.
#?      Here we go.
#?
#?      This script does nothing except printing some messages unless called
#?      with an argument. The arguments are:
#?
#?          /absolute/path
#?                      - copy all necessary files into specified directory
#?          --check     - check current installation
#?          --clean     - move files not necessary to run O-Saft into subdir
#?                        ./release_information_only
#           This is the behaviour of the old  INSTALL-devel.sh  script.
#?
#? OPTIONS
#?      --h     got it
#?      --n     do not execute, just show
#?      --force install .o-saft.pl  and  .o-saft.tcl  in  $HOME,  overwrites
#?              existing ones
#?
#? EXAMPLES
#?      $0
#?      $0 --clean
#?      $0 --check
#?      $0 /opt/bin/
#?      $0 /opt/bin/ --force
#?
#? VERSION
#?      @(#) INSTALL.sh 1.3 17/11/21 00:38:25
#?
#? AUTHOR
#?      16-sep-16 Achim Hoffmann (at) sicsec .dot. de
#?
# -----------------------------------------------------------------------------

# --------------------------------------------- internal variables; defaults
try=''
ich=${0##*/}
bas=${ich%%.*}
dir=${0%/*}
[ "$dir" = "$0" ] && dir="." # $0 found via $PATH in .
force=0
mode="";        # "", check, clean, dest
dest=""
clean=./release_information_only

text_miss="missing, try installing with ";	# 'cpan $m'"
text_dev="did you run »$0 --clean«?"
text_alt="file from previous installation, try running »$0 --clean« "
text_old="ancient module found, try installing newer version, at least "

files_contrib="
		bash_completion_o-saft dash_completion_o-saft \
		fish_completion_o-saft tcsh_completion_o-saft \
		filter_examples usage_examples lazy_checks.awk \
		HTML-simple.awk HTML-table.awk JSON-array.awk JSON-struct.awk \
		XML-value.awk XML-attribute.awk Cert-beautify.awk Cert-beautify.pl \
		bunt.pl bunt.sh zap_config.xml"
#		critic.sh install_perl_modules.pl gen_standalone.sh \
#		Dockerfile.alpine:3.6 distribution_install.sh \
#

files_install="o-saft.pl o-saft-dbx.pm o-saft-usr.pm o-saft-man.pm \
		osaft.pm OSaft/Ciphers.pm OSaft/error_handler.pm \
		Doc/Rfc.pm Doc/Links.pm Doc/Glossary.pm \
		Net/SSLinfo.pm Net/SSLhello.pm \
		o-saft.pod o-saft.tcl o-saft-img.tcl \
		o-saft-docker checkAllCiphers.pl"
#		OSaft/_ciphers_iana.pm OSaft/_ciphers_osaft.pm \
#		OSaft/_ciphers_openssl_all.pm OSaft/_ciphers_openssl_medium.pm \
#		OSaft/_ciphers_openssl_low.pm OSaft/_ciphers_openssl_high \
#

files_develop=".perlcriticrc o-saft_bench o-saft-docker-dev Dockerfile"

files_ancient="generate_ciphers_hash openssl_h-to-perl_hash o-saft-README INSTALL-devel.sh"

files_info="CHANGES README o-saft.tgz"

# --------------------------------------------- arguments and options
while [ $# -gt 0 ]; do
	case "$1" in
	 '-h' | '--h' | '--help')
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	 '-n' | '--n')  try=echo;   ;;
	  '--check')    mode=check; ;;  # same as bare "check"
	  '--clean')    mode=clean; ;;  # same as bare "clean"
	  '--force')    force=1;    ;;
	  '--version')
		\sed -ne '/^#? VERSION/{' -e n -e 's/#?//' -e p -e '}' $0
		exit 0
		;;
	  '+VERSION')   echo 1.3 ; exit; ;; # for compatibility to o-saft.pl
	  *)            mode=dest; dest="$1";  ;;  # last one wins
	esac
	shift
done


# --------------------------------------------- main

# ------------------------- default mode --------- {
if [ -z "$mode" ]; then
	echo ""
	cat << EoT
# O-Saft does not need a specific installation.  It may be used from this
# directory right away.
#
# If you want to run O-Saft from this directory, then consider calling:

	$0 --clean

# If you want to install O-Saft in a different directory, then please call:

	$0 /path/to/installation/directoy
	$0 /path/to/installation/directoy --force

# To check if O-Saft will work, you may use:

	$0 --check
	o-saft_check_before_install.sh

EoT
	exit 0
fi; # default mode }

# ------------------------- clean mode ----------- {
if [ "$mode" = "clean" ]; then
	# do not move contrib/ as all examples expect contrib/ right here    
	for f in $files_info $files_ancient $files_develop ; do
		[ -e "$clean/$f" ] && $try \rm -f "$clean/$f"
		$try \mv "$f" "$clean"
	done
	exit 0
fi; # clean mode }

# ------------------------- install mode  -------- {
if [ "$mode" = "dest" ]; then
	[ ! -d "$dest" ] && echo "\033[1;31m**ERROR: $dest does not exist; exit\033[0m" && exit 2

	echo "# remove old files ..."
	# TODO: argh, hard-coded list of files ...
	for f in $files_install ; do
		f="$dest/$f"
		if [ -e "$f" ]; then
			$try \rm -f "$f" || exit 3
		fi
	done

	echo "# installing ..."
	$try \mkdir -p "$dest/Net"
	$try \mkdir -p "$dest/OSaft"
	for f in $files_install ; do
		$try \cp "$f" "$dest/$f"  || exit 4
	done

	if [ $force -eq 1 ]; then
		$try \cp .o-saft.pl  "$dest/" || echo "\033[1;31m .o-saft.pl  failed\033[0m"
		$try \cp contrib/.o-saft.tcl "$dest/" || echo "\033[1;31m .o-saft.tcl failed\033[0m"
	fi

	echo "# installation in $dest \033[1;32mcompleted.\033[0m"
	exit 0
fi; # install mode }

# ------------------------- check mode ----------- {
if [ "$mode" != "check" ]; then
	echo "\033[1;31m**ERROR: unknow mode  $dest; exit"
	exit 5
fi

# all following is check mode

err=0

echo ""
echo "# check installation"
echo "# (warnings are ok if git clone will be used for development)"
echo "#--------------------------------------------------------------"
# err=`expr $err + 1` ; # errors not counted here
files="openssl_h-to-perl_hash generate_ciphers_hash o-saft-README"
for f in $files ; do
	[ -e "$f" ] && echo "# found $f ... \t\033[1;33m$text_alt\033[0m"
done
files="$files_develop $files_info "
for f in $files ; do
	[ -e "$f" ] && echo "# found $f ... \t\033[1;33m$text_dev\033[0m"
done
echo "#--------------------------------------------------------------"

echo ""
echo "# check openssl executable"
echo "#--------------------------------------------------------------"
echo -n "# openssl:" && which openssl
echo -n "# openssl version\033[1;32m\t" && openssl version && echo -n "\033[0m"
# TODO: openssl older than 0x01000000 has no SNI
echo "#--------------------------------------------------------------"

echo ""
echo "# check for installed perl modules"
echo "#--------------------------------------------------------------"
modules="Net::DNS Net::SSLeay IO::Socket::SSL Net::SSLinfo Net::SSLhello osaft
OSaft::error_handler"
for m in $modules ; do
	echo -n "# testing for $m ..."
	v=`perl -M$m -le 'printf"\t%s",$'$m'::VERSION' 2>/dev/null`
	if [ -n "$v" ]; then
		case "$m" in
		  'IO::Socket::SSL') expect=1.90; ;; # 1.37 and newer work, somehow ...
		  'Net::SSLeay')     expect=1.49; ;; # 1.33 and newer may work
		  'Net::DNS')        expect=0.80; ;;
		esac
		case "$m" in
		  'Net::SSLinfo' | 'Net::SSLhello') c="green"; ;;
		  'OSaft::error_handler' | 'osaft') c="green"; ;;
		  'OSaft::Ciphers' )                c="green"; ;;
		  *) c=`perl -le "print (($expect > $v) ? 'red' : 'green')"`; ;;
		esac
		[ "$c" = "green" ] && echo "\033[1;32m\t$v\033[0m"
		[ "$c" = "red"   ] && echo "\033[1;31m\t$v , $text_old $expect\033[0m"
		[ "$c" = "red"   ] && err=`expr $err + 1`
	else 
		text_miss="$text_miss 'cpan $m'"
		echo "\033[1;31m $text_miss\033[0m"
		err=`expr $err + 1`
	fi
done
echo "#--------------------------------------------------------------"

echo ""
echo "# check for installed O-Saft"
echo "#--------------------------------------------------------------"
for o in o-saft.pl o-saft.tcl ; do
	for p in `echo $PATH|tr ':' ' '` ; do
		d="$p/$o"
		if [ -e "$d" ]; then
			v=`$p/$o +VERSION`
			echo "# O-Saft found ($v):\033[1;32m\t$d \033[0m"
		fi
	done
done
echo "#--------------------------------------------------------------"

echo ""
echo "# check for installed O-Saft resource files"
echo "#--------------------------------------------------------------"
# currently no version check
rc="$HOME/.o-saft.tcl"
if [ -e "$rc" ]; then
	v=`awk '/RCSID/{print $3}' $rc | tr -d '{};'`
	echo "# $rc found\033[1;32m\t$v \033[0m"
	echo "# $rc exists\t\033[1;33mconsider updating from contrib/.o-saft.tcl\033[0m"
else
	echo "# $rc missing\t\033[1;33mconsider copying  contrib/.o-saft.tcl into your HOME directory: $HOME\033[0m"
fi
rc="$HOME/.o-saft.pl"
if [ -e "$rc" ]; then
	echo "# $rc found\t\033[1;33m which will be used when started in $HOME only \033[0m"
	err=`expr $err + 1`
fi
echo "#--------------------------------------------------------------"

echo ""
echo "# check for contributed files"
echo "#--------------------------------------------------------------"
for c in $files_contrib ; do
	d="contrib/$c"
		if [ -e "$d" ]; then
			echo "# found\t\033[1;32m\t$d \033[0m"
		else
			echo "# not found\t\033[1;33m\t$d \033[0m"
		fi
done
echo "#--------------------------------------------------------------"
echo ""
echo -n "# checks"
if [ $err -eq 0 ]; then
	echo "\033[1;32m\tpassed\033[0m"
else
	echo "\033[1;31m\tfailed , $err error(s) detected\033[0m"
fi

# check mode }

exit $err

