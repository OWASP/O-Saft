#! /bin/sh
#?
#? NAME
#?      $0 - do simple check for O-Saft installation, print recommendations
#?
#? SYNOPSIS
#?      $0 [options]
#?
#? DESCRIPTION
#?      Does simple checks for O-Saft installation and prints recommendations.
#?      This script does not change files or directories.
#?
#? OPTIONS
#?      --h     got it
#?
#? EXAMPLES
#?      $0
#?
#? LIMITATIONS
#?      None known.
#?
#? SEE ALSO
#?      INSTALL-devel.sh
# 
# Hacker's INFO
#
#? VERSION
#?      @(#) o-saft_check_before_install.sh 1.5 16/09/25 19:49:21
#?
#? AUTHOR
#?      03-mar-16 Achim Hoffmann (at) sicsec .dot. de
#?
# -----------------------------------------------------------------------------

# --------------------------------------------- internal variables; defaults
try=''
ich=${0##*/}
bas=${ich%%.*}
dir=${0%/*}
[ "$dir" = "$0" ] && dir="." # $0 found via $PATH in .

text_miss="missing, try installing with ";	# 'cpan $m'"
text_old="ancient module found, try installing newer version, at least "
text_alt="file from previous installation, try running INSTALL-devel.sh "
text_dev="did you run INSTALL-devel.sh?"

# --------------------------------------------- arguments and options
while [ $# -gt 0 ]; do
	case "$1" in
	 '-h' | '--h' | '--help')
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	  '--version')
		\sed -ne '/^#? VERSION/{' -e n -e 's/#?//' -e p -e '}' $0
		exit 0
		;;
	  *)            break;  ;;
	esac
	shift
done


# --------------------------------------------- main
err=0

echo ""
echo "# check installation"
echo "# (warnings are ok if git clone will be used for development)"
echo "#--------------------------------------------------------------"
# err=`expr $err + 1` ; # errors not counted here
files="openssl_h-to-perl_hash generate_ciphers_hash o-saft-README"
for f in $files ; do
	[ -e "$f" ] && echo "# found $f ... \033[1;33m$text_alt\033[0m"
done
files="INSTALL-devel.sh README .perlcriticrc o-saft.*.tgz"
for f in $files ; do
	[ -e "$f" ] && echo "# found $f ... \033[1;33m$text_dev\033[0m"
done
echo "#--------------------------------------------------------------"

echo ""
echo "# check openssl executable"
echo "#--------------------------------------------------------------"
echo -n "# openssl:" && which openssl
echo -n "# openssl version\033[1;32m\t" && openssl version && echo "\033[0m"
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
	echo "# $rc found\033[1;32m\t($v) \033[0m"
fi
rc="$HOME/.o-saft.pl"
if [ -e "$rc" ]; then
	echo "# \033[1;33m $rc found, which will be used when started in $HOME only \033[0m"
	err=`expr $err + 1`
fi
echo "#--------------------------------------------------------------"
echo ""
echo -n "# checks"
if [ $err -eq 0 ]; then
	echo "\033[1;32m\tpassed\033[0m"
else
	echo "\033[1;31m\tfailed , $err errors detected\033[0m"
fi


exit 0

