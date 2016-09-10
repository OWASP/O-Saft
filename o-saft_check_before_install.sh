#! /bin/sh
#?
#? NAME
#?      $0 - do simple check for O-Saft installtion
#?
#? SYNOPSIS
#?      $0 [options]
#?
#? DESCRIPTION
#       ----------------------------------------------------------------------
#?
#? OPTIONS
#?      --h     got it
#?      --n     do not execute, just show what would be done
#?      -       a single hyphen indicates data from STDIN
#?
#? EXAMPLES
#?	    $0 ....
#?
#? LIMITATIONS
#?
#? SEE ALSO
#?
# 
# Hacker's INFO
#
#? VERSION
#?      @(#) o-saft_check_before_install.sh 1.4 16/09/10 12:47:55
#?
#? AUTHOR
#?      03-mar-16 Achim Hoffmann _at_ my -dash- stp .dot. net
#?
# -----------------------------------------------------------------------------

# --------------------------------------------- internal variables; defaults
try=''
ich=${0##*/}
bas=${ich%%.*}
dir=${0%/*}
[ "$dir" = "$0" ] && dir="." # $0 found via $PATH in .
stdin=0

some=""

# --------------------------------------------- internal functions

pwarning () {
	\echo "**WARNING [$ich]: $*" >&2
}
perror   () {
	\echo "**ERROR [$ich]: $*" >&2
}

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

echo -n "# openssl:" && which openssl
echo -n "# openssl version       " && openssl version
# TODO: openssl older than 0x01000000 has no SNI
echo "#--------------------------------------------------------------"
echo ""
echo "# check for installed perl modules"
echo "#--------------------------------------------------------------"
text_miss="missing, try installing with 'cpan $m'"
text_old="ancient module found, try installing newer version, at least "
modules="Net::DNS Net::SSLeay IO::Socket::SSL Net::SSLinfo Net::SSLhello"
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
		  *) c=`perl -le "print (($expect > $v) ? 'red' : 'green')"`; ;;
		esac
		[ "$c" = "green" ] && echo "\033[1;32m$v\033[0m"
		[ "$c" = "red"   ] && echo "\033[1;31m$v , $text_old $expect\033[0m"
	else 
		echo "\033[1;31m missing, try installing with 'cpan $m'\033[0m"
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
			echo "# \033[1;32m O-Saft found ($v): $d \033[0m"
		fi
	done
done
# check for resource file, currently no version check
rc="$HOME/.o-saft.tcl"
if [ -e "$rc" ]; then
    v=`awk '/RCSID/{print $3}' $rc | tr -d '{};'`
    echo "# \033[1;32m $rc found ($v) \033[0m"
fi
rc="$HOME/.o-saft.pl"
if [ -e "$rc" ]; then
    echo "# \033[1;33m $rc found, which will be used when started in $HOME only \033[0m"
fi
exit 0

