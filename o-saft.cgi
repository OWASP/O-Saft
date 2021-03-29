#!/usr/bin/perl

## no critic qw(RegularExpressions::ProhibitComplexRegexes)
## no critic qw(RegularExpressions::RequireExtendedFormatting)
#  because we use /x as needed for human readability (may change in future)
## no critic qw(RegularExpressions::RequireLineBoundaryMatching)
#  hmm, we're matching only on line here (Severity: 2)
## no critic qw(RegularExpressions::RequireDotMatchAnything)
#  hmm, we're matching only on line here (Severity: 2)
## no critic qw(Variables::ProhibitPunctuationVars)
#  we make regular use of these variables as we know them;-) (Severity: 2)
## no critic qw(ControlStructures::ProhibitPostfixControls)
#  we believe that postfix control make some code more readable (Severity: 2)

=pod

=head1 NAME

o-saft.cgi  - wrapper script to start o-saft.pl as CGI script

=head1 DESCRIPTION

Calls  o-saft.pl  if first parameter is  I<--cgi>  and prints its result
as plain text. The result is prefixed with proper HTTP headers.

Some parameters are silently ignored (removed from argument list), i.e:

  --dump --exec --list --libversion --version --trace* --v --ca*

Some lazy checks according parameters are done, exits silently if any of
following will be found:

=over 4

=item * not allowed characters in parameters, allowed are:

 a-zA-Z0-9,.:_&\!\/=\+-

=item * not allowed options:

--env* --exe* --lib* --call* --openssl*

=item * illegal hostnames or IPs:

localhost, *.local, (0|10|127|169|172|192|224|240|255).X.X.X

=item * any IPv6 addresses in URLs

=item * any octal notation in IP addresses

=back

To get a list of RegEx for invalid parameters, please use:

  grep qr/ o-saft.cgi

where $key is  --(host|url)=

=head1 OPTIONS, PARAMETERS

=over 4

=item --cgi

Must be used as first parameter, otherwise dies.

=item --format=html

Use HTTP header:

  Content-type: text/html;charset=utf-8

=item --cgi-no-header

Omit all HTTP headers (useful if headers are added by web server).

=back

=head1 DEBUG

If the environment variable  I<OSAFT_CGI_TEST>  is set,  detailed  error
messages are printed. In particular, it prints the RegEx matching any of
the dangerous parameters (i.e. hostname or IP).

This is only useful for testing on command line. It's not intended to be
used when run as a CGI script in a web server.

As it is not possible to set environment variables for the CGI script by
the client (browser), the code should be safe.

=head1 EXAMPLES

Call as CGI from command line:

  env QUERY_STRING='--cgi&--host=demo.tld&--cmd=cn'  o-saft.cgi

For testing only, call from command line:

         o-saft.cgi --cgi --host=demo.tld --cmd=cn

For debugging only, call from command line:

  env OSAFT_CGI_TEST=1 --cgi --host=localhost --cmd=cn o-saft.cgi

=head1 SEE ALSO

=head2 L<o-saft.pl(1)|o-saft.pl(1)>

=head1 AUTHOR

12-sep-12 Achim Hoffmann

=cut

use strict;
use warnings;

my $SID_cgi = "@(#) o-saft.cgi 1.55 21/03/29 17:23:44";
my $VERSION = '21.01.12';
my $me      = $0; $me     =~ s#.*/##;
my $mepath  = $0; $mepath =~ s#/[^/\\]*$##;
   $mepath  = './' if ($mepath eq $me);
my $header  = 1;
local $|    = 1;    # don't buffer, synchronize STDERR and STDOUT

##############################################################################
my $osaft   = "$mepath/o-saft.pl";
#  $osaft   = '/bin/o-saft/o-saft.pl';          # <== adapt as needed
my $openssl = '/usr/local/openssl/bin/openssl'; # <== adapt as needed
	# NOTE tainted perl (-T) will complain if the path given in $osaft
	#      or  $openssl  is writable; it also must be an absolute path
##############################################################################

my @argv    = @ARGV;

sub _print_if_test  {
	#? print text if environment variable OSAFT_CGI_TEST is set
	local $\ = "\n";
	print @_ if defined $ENV{'OSAFT_CGI_TEST'};
	return;
} # _print_if_test

sub _warn_and_exit  {
	#? print error and exit
	my $txt = shift;
	_print_if_test "**ERROR: $txt";
	# ####################################################################
	#
	# This function should print an empty string and exit with status 0 in
	# production environments.
	# Printing above detailed error message is safe, see POD above.
	#
	# ####################################################################
	print "";
	exit 0;
} # _warn_and_exit

if (not $ENV{'QUERY_STRING'}) {
	print "**WARNNG: test mode: restart using args as value in QUERY_STRING\n";
	_warn_and_exit "call without parameters" if (1 > $#argv);
	# may be a command line call without QUERY_STRING environment variable
	# call myself with QUERY_STRING to simulate a call from CGI
	# NOTE: this produces output before any HTTP header, which results in a
        #       Server 500 error in the web server; that's ok here for testing
	## no critic qw(Variables::RequireLocalizedPunctuationVars)
	$ENV{'QUERY_STRING'} =  join('&', @argv);
	$ENV{'QUERY_STRING'} =~ s/[+]/%2b/g;
	$ENV{'QUERY_STRING'} =~ s/[ ]/%20/g;
	exec $0;
}

if ($me =~/\.cgi$/) {
	# CGI mode is pretty simple:
	#   * URL-decode QUERY_STRING and POST data and once
	#   * check if data contains suspicious characters, die if so
	#       NOTE that % is suspicious as we decode only once
	#   * check if target is suspicious host or net, die if so
	#   * then split data at & to get our options and arguments
	#   * ready we go by calling $osaft
	# NOTE: in true CGI-mode, QUERY_STRING just contains the form fields,
	#       when used with our own  osaft:  schema, it also contains the
	#       the schema and path, i.e.  osaft:///o-saft.cgi?
	# NOTE: for debugging using system() writing to a file is better than
	#       using perl's print() as it may break the HTTP response
	my $cgi = 0;
	my $typ = 'plain';
	my $qs  = '';
	$qs  = $ENV{'QUERY_STRING'} if (defined $ENV{'QUERY_STRING'});
	#dbx# system "echo  'QS=$qs #'   >> /tmp/osaft.cgi.log";
	$qs  =~ s/^"?(.*?)"?$/$1/;      # remove enclosing " (windows problem)
	$qs  =~ s#^o-?saft://##g;       # remove schema if any (used in o-saft.cgi.html)
	$qs  =~ s#^[^?]*\?##g;          # remove path left of ? if any (used in o-saft.cgi.html)
	$qs  =~ s/[+]/ /g;
	$qs  =~ s/(?:%([0-9a-f]{2,2}))/pack("H2", $1)/egi;  # url-decode once
	undef @argv;
	push(@argv, split(/[&?]/, $qs));
	#dbx# system "echo  'argv=@argv' >> /tmp/osaft.cgi.log";

	$cgi = shift @argv || '';       # remove first argument, which must be --cgi
	                                # || ''   avoids uninitialized value
	push(@argv, "--cgi-exec");      # argument required for some more checks
	die  "**ERROR: CGI mode requires strict settings\n" if ($cgi !~ /^--cgi=?$/);

	$typ    = 'html' if ($qs =~ m/--format=html/); # --format=html already in @argv
	$header = 1 if (0 < (grep{/--cgi.?header/}     $qs));
	$header = 0 if (0 < (grep{/--cgi.?no.?header/} $qs));
	if (0 < $header) {
		print "X-Cite: Perl is a mess. But that's okay, because the problem space is also a mess. Larry Wall\r\n";
		print "X-O-Saft: OWASP – SSL advanced forensic tool 1.55\r\n";
		print "Content-type: text/$typ; charset=utf-8\r\n";# for --usr* only
		print "\r\n";
	}

	_print_if_test "**WARNNG: test mode: die with detailed messages on errors";

	if (defined $ENV{'REQUEST_METHOD'}) { # ToDo: NOT WORKING
		$qs .= <> if ($ENV{'REQUEST_METHOD'} eq 'POST');# add to GET data
	}

	# ignore (remove) potential dangerous commands and options
	my $ignore = qr/
		^--(?:
		      (?:cmd|url)=[+]?(?:dump|exec|list|libversion|version) # illegal commands
		     |(?:cmd|url)=--(?:trace|--v)   # illegal options given as URL
		     |trace|v                       # options with to verbose output
		     |ca.?(?:file|path)|rc=         # may be used to enumerate paths
		)/xi;
	#dbx# system "echo  'argv=@argv' >> /tmp/osaft.cgi.log";
	my @save_argv;
	foreach my $arg (@argv) {
		#dbx# print "#dbx: $arg # sielently ignored\n" if ($arg =~ m#$ignore#);
		next if ($arg =~ m#$ignore#);
		push(@save_argv, $arg);
	}
	@argv = @save_argv;
	#dbx# system "echo  'argv=@argv' >> /tmp/osaft.cgi.log";

	# check for suspicious characters and targets, die if any
        #   Matches against  QUERY_STRING  (in $qs), which still contains the
        #   usual separator & . The first parameter in $qs must be --cgi, all
        #   others must be prefixed with & . Hence most pattern start with  &
        #   to avoid matches inside a valid parameter, for example:
        #       --cgi&--host=a42&--cmd=cn       # ok
        #       --cgi&--host=42&--cmd=cn        # bad
        #       --cgi&--cmd=cn&--host=42        # bad
        #       --cgi&--cmd=cn&=42              # bad
        #       --cgi&--cmd=cn&--other-opt=42   # ok
        # FIXME: last example will be detected as malicious and dies, this is
        #       a false positive, bug here
        # NOTE: technically & may be a ? too, it is not really RFC compliant,
        #       but possible. Someone may sends malicious data.
	my $err = 0;
	my $key = '&--(?:host|url)=';
	foreach my $dangerous (
		qr/[^a-zA-Z0-9,.:_&\!\/=\+-]/i,
			# dangerous characters anywhere
			# above whitelist for allowed characters!
			# FIXME: this blocks also valid IPv6 in URL because of [ and/or ]

		qr/&--(?:env|exe|lib|call|openssl)/i,
			# dangerous commands and options

		# RFC addresses are not allowed, see https://tools.ietf.org/html/rfc5735
		#     0.0.0.0/8       This Network
		#     10.0.0.0/8      Private-Use Networks      # 10.0.0.0    .. 10.255.255.255
		#     100.64.0.0/10   CGN - Carrier- Grade NAT  # 100.64.0.0  .. 100.127.255.255
		#     127.0.0.0/8     Loopback                  # 127.0.0.0   .. 127.255.255.255
		#     169.254.0.0/16  Link local                # 169.254.0.0 .. 169.254.255.255
		#     172.16.0.0/12   Private-Use Networks      # 172.16.0.0  .. 172.31.255.255
		#     192.0.0.0/24    IETF Protocol Assignments # 192.0.0.0   .. 192.0.0.255
		#     192.0.2.0/24    TEST-NET-1                # 192.0.2.0   .. 192.0.2.255
		#     192.88.99.0/24  6to4 Relay Anycast        # 192.88.99.0 .. 192.88.99.255
		#     192.168.0.0/16  Private-Use Networks      # 192.168.0.0 .. 192.168.255.255
		#     198.18.0.0/15   Network Interconnect,
                #                     Device Benchmark Testing  # 198.18.0.0  .. 198.19.255.255
		#     198.51.100.0/24 TEST-NET-2                # 198.51.100.0 .. 198.51.100.255
		#     203.0.13.0/24   TEST-NET-3                # 203.0.13.0  .. 203.0.13.255
		#     224.0.0.0/4     Multicast                 # 224.0.0.0   .. 239.255.255.255
		#       # https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
		#     240.0.0.0/4     Reserved for future use   # 240.0.0.0   .. 255.255.255.255 
		#     255.255.255.255/32 Limited Broadcast

		#     fe80:           IPv6 link local
		#     fe[c-f][0-9a-f]: IPv6 site local
		#     ff0[0-9a-f]|f[c-d][0-9a-f][0-9a-f]:   IPv6 multicast or unique local unicast (RFC6762)
		#     64:::IP         IPv4-mapped IPv6 addresses as NAT64 (RFC6052): 64:ff9b::192.0.2.128
		#     ::::IP          IPv4-mapped IPv6 addresses: ::ffff:192.0.2.128 
		#     127.1  127.0.1  IPv4 abbreviated
		# TODO: better, more accuarte checks
		#     ::1/128         localhost
		#     fe80::/64       link local
		#     ff00::/8        ULA - Unique Local Address
		#     ff00::0/8       Multicast
		#     fd00::/8        Unique Local Address, not routable
		#     fc00::/7        ? Global Unique Address
		#     ::ffff:0:0/96   IPv4 mapped addresses
		#     ::ffff:0:0:0/96 IPv4 translated addresses (SIIT protocol)
		#     64:ff9b::/96    6to4 addressing
		#     2000::/3 
		#     2001::/16       GUA - Global Unique Address, routable!
		#     2001::/32       Teredo tunneling (RFC 4380)
		#     2001:2:::/48    Reserved for Benchmarking Methodology Working Group
		#     2001:20::/28    ORCHIDv2 crypto hash identifiers, not routable
		#     2001:db8::/32   ? Documentation
		#     ff02::2         Neighbor Discovery Protocol 

		# match IPv4: ((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}
		# match IPv6: ([0-9a-f]{0,4}:){1,8}
		# match 1234567890: IP as integer not yet allowed
		# match IPv4: less than 4 parts for dotted IP

		# TODO: build a map of integer ranges for IPs to be denied:
		#        10.x.x.x  =  167772161 ..  184549375
		#       127.x.x.x  = 2130706433 .. 2147483647
		#       ...
		#       then check given host againts this map if conversion to
		#       an integer is succesful.
		#       It will also work for mixed IPv6-IPv4 IPs like:
		#         ::ffff:127.0.0.1 which is an alias for ::ffff:7f00:1. 
		#       This should eliminate some of the restriction (missing)
		#       of RegEx (see NOTEs below).
		#       Unfortunately Math::BigInt is required (breaks usage on
		#       ancient systems).

		# octal IP addresses may look like:
		#   0127.000000002.0.1
		# i.g. each octet is prefixed with 0, followed by any amount of
                # 0, followed by [1-4] (may be missing), followed by [0-7][0-7]
                # NOTE: octal addresses are not bad in general,  but the checks
		#   below expect only  CIDR numbers in decimal notation,  hence
		#   any occourance of octal numbers are rejected

		# NOTE: according following RegExs
		# - grouping with back reference is used insted of  (?: ... )
		#   sometimes, this is because  :  is used literally in RegExs
		# - RegExs are not case sensitive to match FQDN and (hex) IP,
		#   but this also allows --URL= --HOST= (which is ok)
		# - sequence of following RegExs is important,  more specific
		#   ones first
		# - the leeading option like --host= is optional as the word to
		#   be checked may be passed without key, something like:
		#   --cgi&--host=good.FQDN&localhost&--enabled=
		# - IPv4 matching is lazy with [0-9]+

		qr/(?:(?:$key)?[0-9.]*(?:(0+[1-4]?[0-7]{1,2}[.])|([.]0+[1-4]?[0-7]{1,2})))/,
			# octal addresses are always ignored

		qr/(?:&(localhost|10|127|224(.[0-9]){1,3}|(ffff)?::1|(ffff:)?7f00:1)(&|$))/i,
			# first match bare hostname argument without --host=
			# this avoids false positive matches in more lazy RegEx
			# FIXME: probably necessary for all following RegEx
			# NOTE:  also bad 127.666 (= 127.0.2.154)

		qr/(?:(?:$key)?((10|127|224).[0-9]+(.[0-9]{1,3})?))/i,
			# abbreviated IPv4: 127.1 127.41.1 10.0.1 224.1

		qr/(?:(?:$key)(localhost|::1|ffff::1|(ffff:)?7f00:1)(&|$))/i,
			# localhost
			# TODO: IPv6 localhost:   [7f00:1] .. [7fff:ffff]

		qr/(?:(?:$key)?((ffff:)?(100\.64|169.254|172\.(1[6-9]|2\d|3[01])|192\.168|198\.18)\.[\d]+.[\d]+))/i,
			# common Class B RFC networks for private use
			# TODO: to pedantic: 100.64.0.0/10 CGN is not really class B

		qr/(?:(?:$key)?((ffff:)?(192\.0\.[02]|192.88\.99|198\.51\.100|203\.0\.13)\.[\d]+))/i,
			# common class C RFC networks for private use

		qr/(?:(?:$key)?((ffff:)?(0|10|127|22[4-9]|23[0-9]|24[0-9]|25[0-5])\.[\d]+.[\d]+.[\d]+))/i,
			# loopback, mulicast

		qr/(?:(?:$key)?((fe80|fe[c-f][0-9a-f]:)))/i,
			# IPv6 link local or site local

		qr/(?:(?:$key)?((ff0[0-9a-f]|f[c-d][0-9a-f][0-9a-f]:)))/i,
			# IPv6 multicast or unique local unicast (RFC6762)

		qr/(?:(?:$key)?64:([0-9a-f]{1,4}:){1,2}:(&|$))/i,
			# any IPv4-mapped IPv6 addresses as NAT64 (RFC6052): 64:ff9b::

		qr/(?:(?:$key)?64:([0-9a-f]{1,4}:){1,2}:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4})/i,
			# any IPv4-mapped IPv6 addresses as NAT64 (RFC6052): 64:ff9b::192.0.2.128
			# NOTE: would also be matched by next more general RegEx

		qr/(?:(?:$key)?([0-9a-f]{0,4}:){1,3}((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4})/i,
			# any IPv4-mapped IPv6 addresses: ::ffff:192.0.2.128 
			# NOTE: ([0-9a-f]{0,4}:){1,3} is lazy, matches also ffff:IP or :IP

		qr/(?:&[0-9]+(&|$))/i,
			# just 11111; does not match +11111 or -11111 or --host=11111
		qr/(?:(?:$key)[0-9]+(&|$))/i,
			# just --host=11111
			# NOTE: in general not bad, but needs to be mapped to
			#       allowed IPv4 or IPv6 which is not that simple
			# FIXME: i.e. valid 3221225473 = 192.0.0.1 is denied

		qr/(?:(?:$key)?.*?\.local(&|$))/i,
			# multicast domain .local (RFC6762)

		qr{(?:(?:$key)?([a-z0-9:]+)?(//)?\[?([a-f0-9:]+)])}i,
			# IPv6
			# NOTE: final ] not escaped, it's a literal character here!
			# FIXME: blocks any IPv6
			# TODO:  IPv6 still experimental
			# possible formats to be blocked:
			#     ftp://[::ffff:7f00:1]/path
			#         //[::ffff:7f00:1]/path
			#           [::ffff:7f00:1]/path
			#            ::ffff:7f00:1/path    # illegal, but possible
			#   HTTPS://[::ffff:7f00:1]:80/path
			#     any:[::ffff:7f00:1]/path     # also matched
			# FIXME: also blocks FQDN:port like   cafe:4711/path

		) {
		#dbx# print "#dbx: $qs =~ m#$dangerous#\n";
		if ($qs =~ m#$dangerous#) {
			_print_if_test "**ERROR: $dangerous";
			$err++;
		}
	}
	_warn_and_exit "dangerous parameters; aborted" if 0 < $err;
	#dbx# print "\nQS: $qs\n";

	local $ENV{LD_LIBRARY_PATH} = "$openssl/lib/";
	local $ENV{PATH} = "$openssl/bin/" . ':' . $ENV{PATH};
	local $|    = 1;    # don't buffer, synchronize STDERR and STDOUT
	#dbx# system "$osaft @argv >> /tmp/osaft.cgi.log";
	_print_if_test "$osaft  @argv";
	exec  $osaft, @argv;        # exec is ok, as we call ourself only
	# TODO: Win32 not tested: exec 'perl.exe', $osaft, @argv;
}
exit 0; # never reached
