#!/usr/bin/perl

## no critic qw(Documentation::RequirePodSections)
## no critic qw(RegularExpressions::ProhibitComplexRegexes)

=pod

=head1 NAME

o-saft.cgi  - wrapper script to start o-saft.pl as CGI script

=head1 DESCRIPTIONS

Calls ./o-saft.pl if first parameter is  I<--cgi>.
Returns results as:  Content-type: text/plain

Does some lazy checks according parameters:

=over 4

=item parameters may not contain other characters than: a-zA-Z0-9,.:_&\!\/=\+-

=item following options are ignored: --env* --exe* --lib* --call* --openssl*

=item following hosts are ignored:   localhost, (0|10|127|169|172|192|224|240|255).X.X.X

=item all IPv6 addresses in URLs are ignored

=back

=head1 EXAMPLE

Call as CGI from command line:

  env "QUERY_STRING=--cgi&--host=demo.tld&--cmd=cn"   o-saft.cgi

For testing only, call from command line:

         o-saft.cgi --cgi --host=demo.tld --cmd=cn

=head1 SEE ALSO

=head2 L<o-saft.pl(1)|o-saft.pl(1)>

=head1 AUTHOR

12-sep-12 Achim Hoffmann

=cut

use strict;
use warnings;

my $SID     = '@(#) o-saft.cgi 1.19 18/06/07 00:57:33';
my $VERSION = '17.11.23';
my $me      = $0; $me     =~ s#.*/##;
my $mepath  = $0; $mepath =~ s#/[^/\\]*$##;
   $mepath  = './' if ($mepath eq $me);
local $|    = 1;    # don't buffer, synchronize STDERR and STDOUT

##############################################################################
my $osaft   = "$mepath/o-saft.pl";
#  $osaft   = '/bin/o-saft/o-saft.pl';      # <== adapt as needed
my $openssl = '/opt/tools/openssl-chacha';  # <== adapt as needed
        # NOTE tainted perl (-T) will complain if the path given in $osaft
        #      or  $openssl  is writable; it also must be an absolute path
##############################################################################

my @argv    = @ARGV;

sub _warn_and_exit  {
	#? print error and exit
	my $txt = shift;
	die "**ERROR: $txt" if ($ENV{'OSAFT_CGI_TEST'}); ## no critic qw(ErrorHandling::RequireCarping)
	# ####################################################################
	#
	# This function should print an empty string and exit with status 0 in
	# production environments.
	# Above detailed error message is for testing only and not intended to
	# be used and seen when run as a CGI script in a web server.
	# The client (browser) is not not able to set the environment variable
	# hence the code should be safe.
	#
	# ####################################################################
	print "";
	exit 0;
} # _warn_and_exit

if ($ENV{'OSAFT_CGI_TEST'}) {
	print "**WARNNG: test mode: die with detailed messages on errors\n";
}

if (not $ENV{'QUERY_STRING'}) {
	print "**WARNNG: test mode: restart using args as value in QUERY_STRING\n";
	# may be a command line call without QUERY_STRING environment variable
	# call myself with QUERY_STRING to simulate a call from CGI
	# NOTE: this produces output before any HTTP header; that's ok here
	## no critic qw(Variables::RequireLocalizedPunctuationVars)
	$ENV{'QUERY_STRING'} =  join('&', @argv);
	$ENV{'QUERY_STRING'} =~ s/[+]/%2b/g;
	$ENV{'QUERY_STRING'} =~ s/[ ]/%20/g;
	exec $0;
}

my $cgi     = 0;
if ($me =~/\.cgi$/) {
	# CGI mode is pretty simple:
	#   use QUERY_STRING and POST data and URL-decode once
	#   check if data contains suspicious characters, die if so
	#       NOTE that % is suspicious as we decode only once
	#   check if target is suspicious host or net, die if so
	#   then split data at & to get our options and arguments
	#   ready we go with the existing code :)
	my $qs =  '';
	$qs  = $ENV{'QUERY_STRING'} if (defined $ENV{'QUERY_STRING'});
	$qs  =~ s/^"?(.*?)"?$/$1/;      # remove enclosing " (windows problem)
	$qs  =~ s/[+]/ /g;
	$qs  =~ s/(?:%([0-9a-f]{2,2}))/pack("H2", $1)/egi;  # url-decode once
	undef @argv;
	push(@argv, split(/&/, $qs));
	$cgi = shift @argv || '';       # remove first argument, which must be --cgi
	                                # || ''   avoids uninitialized value
	push(@argv, "--cgi-exec");      # some argument which looks like --cgi required for some more checks
	die "**ERROR: CGI mode requires strict settings\n" if ($cgi !~ /^--cgi=?/);
	print "X-Cite: Perl is a mess. But that's okay, because the problem space is also a mess. Larry Wall\r\n";
	print "X-O-Saft: OWASP – SSL advanced forensic tool 1.19\r\n";
	if ($qs =~ m/--cmd=html/) {
		print "Content-type: text/html;  charset=utf-8\r\n";# for --usr* only
	} else {
		print "Content-type: text/plain; charset=utf-8\r\n";# normal results
	}
	print "\r\n";
	if (defined $ENV{'REQUEST_METHOD'}) { # ToDo: NOT WORKING
		$qs .= <> if ($ENV{'REQUEST_METHOD'} eq 'POST');# add to GET data
	}
	foreach my $dangerous (         # check for suspicious characters and targets
		#dbx# print "#dbx: $dangerous # $qs\n";
		qr/[^a-zA-Z0-9,.:_&\!\/=\+-]/i,
			# dangerous characters anywhere
			# above whitelist for allowed characters!
        		# FIXME: this blocks also valid IPv6 in URL because of [ and/or ]

		qr/(cmd=list|--(env|exe|lib|call|openssl))/i,
			# dangerous commands and options

		# RFC addresses are not allowed
		# see https://tools.ietf.org/html/rfc5735
		#     0.0.0.0/8       This Network
		#     10.0.0.0/8      Private-Use Networks
		#     100.64.0.0/10   ?
		#     127.0.0.0/8     Loopback
		#     169.254.0.0/16  Link local
		#     172.16.0.0/12   Private-Use Networks
		#     192.0.0.0/24    IETF Protocol Assignments
		#     192.0.2.0/24    TEST-NET-1
		#     192.88.99.0/24  6to4 Relay Anycast
		#     192.168.0.0/16  Private-Use Networks
		#     198.18.0.0/15   Network Interconnect, Device Benchmark Testing
		#     198.51.100.0/24 TEST-NET-2
		#     203.0.13.0/24   TEST-NET-3
		#     224.0.0.0/4     224.0.0.0 - 239.255.255.255 Multicast
		#       # https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
		#     240.0.0.0/4     240.0.0.0 - 255.255.255.255 Reserved for future use
		#     255.255.255.255/32

		qr/(-(host|url)=(localhost|(ffff)?::1|(ffff:)?7f00:1))/i,
			# localhost

		qr/(-(host|url)=((ffff:)?(0|10|127|22[4-9]|23[0-9]|24[0-9]|25[0-5])\.[\d]+.[\d]+.[\d]+))/i,
			# loopback, mulicast

		qr/(-(host|url)=((ffff:)?(100\.64|169.254|172\.(1[6-9]|2\d|3[01])|192\.168|198\.18)\.[\d]+.[\d]+))/i,
			# common Class B RFC networks for private use
			# TODO: 100.64.0.0/10 is not really class B

		qr/(-(host|url)=((ffff:)?(192\.0\.[02]|192.88\.99|198\.51\.100|203\.0\.13)\.[\d]+))/i,
			# common class C RFC networks for private use

		qr/(-(host|url)=((fe80|fe[c-f][0-9a-f]:)))/i,
			# IPv6 link local or site local

		qr/(-(host|url)=((ff0[0-9a-f]|f[c-d][0-9a-f][0-9a-f]:)))/i,
			# IPv6 multicast or unique local unicast

		qr{(-(host|url)=([a-z0-9:]+)?(//)?\[?([a-f0-9:]+)])}i,
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
		#dbx# print "#dbx: $dangerous # $qs\n";
		_warn_and_exit "$dangerous" if ($qs =~ m#$dangerous#);
	}
	#dbx# print "\nQS: $qs\n";

	local $ENV{LD_LIBRARY_PATH} = "$openssl/lib/";
	local $ENV{PATH} = "$openssl/bin/" . ':' . $ENV{PATH};

	#dbx# print "exec $osaft, @argv\n";
	exec $osaft, @argv;        # exec is ok, as we call ourself only
	#Win32# exec 'perl.exe', $osaft, @argv;
}
exit 0; # never reached
