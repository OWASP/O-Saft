#!/bin/sh
#?
#? NAME
#?      $0 - test invalid IPs to be rejected by o-saft.cgi
#?              prints all results on STDERR; should look like (example):
#?          **ERROR: (?^i:[^a-zA-Z0-9,.:_&\!/=\+-]) at o-saft.cgi line 74.
#?
#? VERSION
#?      @(#) test-o-saft.cgi.sh 1.1 18/05/03 00:53:13
#?
#? AUTHOR
#?      17-nov-17 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

ich=${0##*/}
try=
err=0
osaft=../o-saft.cgi
[ -x $osaft ] || osaft=o-saft.cgi

ip4_failed=""
ip6_failed=""
chr_failed=""
cmd_failed=""
opt_failed=""

tests_ok="
	_IPok_tests_
	17.0.0.1
	11.0.0.0
	169.253.0.0
	169.254.1.0
	169.255.0.0
	172.20.0.1
	192.10.0.1
	192.0.0.1
	192.10.2.1
	192.0.3.1
	192.88.98.0
	192.88.100.0
	192.89.99.0
	192.169.0.1
	198.18.2.2
	198.19.0.0
	198.51.101.0
	198.151.100.1
	203.0.14.1
	203.1.13.1
"

# define all test cases, one per line
# test cases are grouped by a heading line (always starts with _ ), these
# heading lines are used to construct the proper arguents for o -saft.cgi
# empty lines are ignored
tests_nok='
	_IPv4_tests_
	10.0.0.0
	10.0.0.1
	10.11.11.11
	10.255.255.255
	100.64.0.0
	100.64.0.1
	100.64.1.255
	localhost
	127.0.0.1
	127.251.251.1
	127.255.255.255
	169.254.0.0
	169.254.0.1
	169.254.0.255
	172.16.0.0
	172.16.0.1
	172.19.255.255
	192.0.0.0
	192.0.0.1
	192.0.0.255
	192.0.2.0
	192.0.2.1
	192.0.2.255
	192.88.99.0
	192.88.99.1
	192.88.99.255
	192.168.0.0
	192.168.1.1
	192.168.255.255
	198.18.0.0
	198.18.0.1
	198.18.0.255
	198.51.100.0
	198.51.100.1
	198.51.100.255
	203.0.13.0
	203.0.13.1
	203.0.13.255
	224.0.0.0
	224.0.0.1
	224.255.255.255

	_IPv6_tests_
	::1
	ffff::1
	7f00:1
	ffff:7f00:1
	fe80:21ab:22cd:2323::1
	fec0:21ab:22cd:2323::1
	feff:21ab:22cd:2323::1
	fc00:21ab:22cd:2323::1
	fdff:21ab:22cd:2323::1
	ff01::1
	ff02::1

	_Opt._tests_
	--env
	--exe
	--lib
	--call
	--openssl

	_Cmd._tests_
	list

	_Chr._tests_
	backtick`
	brace(
	brace)
	bracket[
	bracket]
	caret^
	dollar$
	persent%
	question?
	quote\"
	semicolon;
	pipe|pipe
	hash#hash
	lt<lt
	gt>gt
'
#	version

# testing for "illegal" IP or parameters in o-saft.cgi works as follows:
#  1. exits with status <> 0  if environment variable OSAFT_CGI_TEST is set
#  2. if environment variable OSAFT_CGI_TEST is set, command line arguments
#     are used instead of usual environment variable QUERY_STRING
#  3. for $ip_nok we expect o-saft.cgi to exit with status <> 0
#  4. redirect STDOUT, so only perl's die() message is shown (STDERR)
#     die() prints the matching regex
#
# NOTE: because o-saft.cgi  complains on STDERR and this text is then shown
#       as output here, all output is done on STDERR
#
OSAFT_CGI_TEST=1; export OSAFT_CGI_TEST

exec 1>&2       # print everything on STDERR

for val in $tests_nok ; do
	[ -z "$val" ] && continue
	case "$val" in  # parse our labels in the list
	  _IPv4_tests_) cmd="host"; mod=$val; continue; ;;
	  _IPv6_tests_) cmd="host"; mod=$val; continue; ;;
	  _Opt._tests_) cmd="opt";  mod=$val; continue; ;;
	  _Cmd._tests_) cmd="cmd";  mod=$val; continue; ;;
	  _Chr._tests_) cmd="chr";  mod=$val; continue; ;;
	esac
	case "$cmd" in  # set command or option
		host)   tst="--host=$val";  ;;
		chr)    tst="--bad-chr=$val"; ;;
		cmd)    tst="--cmd=$val";   ;;
		opt)    tst="$val=bad";     ;;
		*)      continue;   # unknown command (programming error)
	esac
	label=`\awk -v txt=$tst 'BEGIN{printf("%-24s",txt);exit}' /dev/null`
	# do the check ...
	\echo -n "# $label " && $try $osaft --cgi +quit $tst > /dev/null
	[ $? -ne 0 ] && continue;   # o-saft.cgi died, that's expected
	case "$mod" in  # o-saft.cgi executed, this means that the test failed
	  _IPv4_tests_) ip4_failed="$ip4_failed $val"; err=1; ;;
	  _IPv6_tests_) ip6_failed="$ip6_failed $val"; err=1; ;;
	  _Opt._tests_) opt_failed="$opt_failed $val"; err=1; ;;
	  _Cmd._tests_) cmd_failed="$cmd_failed $val"; err=1; ;;
	  _Chr._tests_) cmd_failed="$chr_failed $val"; err=1; ;;
	esac
done

# TODO: for ip in $tests_ok ; do

\echo -n "[Chr. tests] "; txt="passed."
[ -n "$chr_failed" ]   && txt="failed: $chr_failed"
\echo $txt

\echo -n "[Cmd. tests] "; txt="passed."
[ -n "$cmd_failed" ]   && txt="failed: $cmd_failed"
\echo $txt

\echo -n "[Opt. tests] "; txt="passed."
[ -n "$opt_failed" ]   && txt="failed: $opt_failed"
\echo $txt

\echo -n "[IPv4 tests] "; txt="passed."
[ -n "$ip4_failed" ]   && txt="failed: $ip4_failed"
\echo $txt

\echo -n "[IPv6 tests] "; txt="passed."
[ -n "$ip6_failed" ]   && txt="failed: $ip6_failed"
\echo $txt

exit $err
