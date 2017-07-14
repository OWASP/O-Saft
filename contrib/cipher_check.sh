#!/bin/sh
#?
#? NAME
#?      $0 - test for ciphers with various methods
#?
#? SYNOPSIS
#?      $0 target
#?
#? OPTIONEN, Argumente
#?      --h     - na sowas
#?      --n     - try, do nothing
#?      --delay - check with --connect-delay=1 also; default: do not check
#?
#? DESCRIPTION
#?      Unfortunately modern systems (2016 and later)  often behave unusual.
#?      Detecting such unusual behaviour is often not possible,  This script
#?      uses different methods (commands and options)  to check for ciphers.
#?      If these methods return different results, the results should be
#?      verified carefully.
#?
#?      This script calls  o-saft.pl  with different commands and options to
#?      check the target for supported ciphers. The purpose is to get a more
#?      accurate list of supported ciphers.
#?      Reasons to do different checks are:
#?      * target supports unusal ciphers (not known by underlaying libssl)
#?      * target behaves strange when connecting to test for ciphers, i.e. a
#?        target may return an TLS alert
#?      * the target is protected by an  IPS,  which blocks further connects
#?        if it detects to many connects within a specific timeframe
#?      * general network problems
#?
#?      This script writes results to various  ./cipher_check__.*.log files.
#?
#? WARNING
#?      With the  --delay  option, the script  will use options to delay the
#?      connetcs to the target. This slows down the script, obviously.
#?      Example: a delay of 1 second will result in a 5 x 200 = 1000 seconds
#?      (200 ciphers for 5 protocols, approx 17 minutes).
#?
# HACKER's INFO
#       The results are analysed programatically to detect differences.
#       Therfore following options are used to generate a parsable output:
#           --tracekey --legacy=compact --noheader --enabled
#       Also, all the tests are done for each SSL protocol separately.  This
#       avoids heavy load (due to many connections)  on the server  and also
#       simplifies the comparison of the generated result files.
#?
#? EXAMPLES
#?      $0 site.tld
#?      $0 site.tld --delay
#?
#? LIMITATIONS
#?
#? SEE ALSO
#?      o-saft.pl
#?
#? VERSION
#?      @(#) cipher_check.sh 1.1 17/07/14 22:23:42
#?
#? AUTHOR
#?      07-jul-17 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

ich=${0##*/}
try=""
log=""
dly=0
exe=o-saft.pl
ini=/tmp/cipher_check.ini
log_ok=cipher_check__.log

methods="
#   +cipher
#	+ciher is the initial test, it's used as reference for following
    +cipher --no-ssl-error
#   +cipher --ssl-error-max=23
    +cipher --connect-delay=1
    +cipher --cipheralpn=,
    +cipher --ciphernpn=,
    +cipher --cipheralpn=, --ciphernpn=,
    +cipher --force-openssl
    +cipher --force-openssl --connect-delay=1
# TODO: following have different output format
#    +cipher-dh
#    +cipherall
"

SSL="sslv2 sslv3 tlsv1 tlsv11 tlsv12 tlsv13 dtlsv1 dtlsv11 dtlsv12 dtlsv13"

echo "" > $log_ok   # write new logfile

logname() {
	echo "cipher_check__"`echo $*|\tr -s ' ' '_'`.txt
}

check_cipher() {
	# use all variables from main, quick&dirty
	echo -n "##{ testing $exe $target --rc=$ini --$ssl $cmd > $log "
	if [ -z $try ] ; then
		$exe $target --rc=$ini --$ssl $cmd \
		| \sed -e 's/0x020701C0/0x0300000A/' \
		> $log
	fi
	echo " ##}"
	return 0
}

check_result() {
	# use all variables from main, quick&dirty
	line="######################################"
	base_log=`logname $ssl +cipher`
	if [ -z $try ] ; then
		(
		#echo ""
		\diff -q $base_log $log 2>&1 > /dev/null
		status=$?
		if [ $status -eq 0 ]; then
			echo "#   OK: $cmd"
		else
			echo "# diff: $cmd  $line"
			echo "diff $base_log $log"
			\diff $base_log $log
			echo ""
		fi
		) >> $log_ok
	fi
	return $status
}

while [ $# -gt 0 ]; do
	arg="$1"
	shift
	case "$arg" in
	 '-h' | '--h' | '--help' | '-?')
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	 '-n' | '--n') try=echo; ;;
	 '--delay')    dly=1; ;;
	 *)     target=$arg; ;;
	esac
done

# generate our private RC-file (to avoid long command line)
\cat > $ini <<EoRC
--openssl=/opt/tools/openssl-chacha/bin/openssl
--trace=key
--legacy=compact
--enabled
--no-header
--no-http
--no-dns
# disable all SSL protocols, will be enabled on command line
EoRC
for ssl in $SSL; do
	echo "--no-$ssl" >> $ini
done

cat $ini

# redefine list of protocols for practical use (2017)
SSL="sslv2 sslv3 tlsv1 tlsv11 tlsv12"

# check ciphers with other methods, separate for each SSL protocol
for ssl in $SSL; do
	cmd="+cipher"  # use +cipher as reference test
	log=`logname $ssl $cmd`
	check_cipher
	echo "$methods" | while read cmd ; do
		[ -z "$cmd" ] && continue
		echo "$cmd"    |\egrep -q '^\s*#'  && continue  # skip comment line
		if [ $dly -eq 0 ] ; then
		    echo "$cmd"|\egrep -q 'delay=' && continue  # skip delay command
		fi
		log=`logname $ssl $cmd`
		check_cipher
		check_result
	done
done

\rm $ini
\cat $log_ok

echo "# see cipher_check__.* files"
echo

