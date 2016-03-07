#! /bin/sh
#?
#? NAME
#?      $0 - 
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
#?      @(#) o-saft_check_before_install.sh 1.3 16/03/07 16:00:43
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
echo "#--------------------------------------------------------------"
echo ""
echo "# check for installed perl modules"
echo "#--------------------------------------------------------------"
modules="Net::DNS Net::SSLeay IO::Socket::SSL Net::SSLinfo Net::SSLhello"
for m in $modules ; do
	echo -n "# testing for $m ..."
	v=`perl -M$m -le 'printf"\t%s",$'$m'::VERSION' 2>/dev/null`
	if [ -n "$v" ]; then
		echo "\033[1;32m$v\033[0m"
	else 
		echo "\033[1;31m missing, try installing with 'cpan $m'\033[0m"
	fi
done
echo "#--------------------------------------------------------------"

echo ""
echo "# check for installed O-Saft"
echo "#--------------------------------------------------------------"
for p in `echo $PATH|tr ':' ' '` ; do
	d="$p/o-saft.pl"
	[ -e "$d" ] && echo "\033[1;32m O-Saft found: $d \033[0m"
done
exit 0
