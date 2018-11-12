#!/usr/bin/perl

## no critic qw(Documentation::RequirePodSections)
## no critic qw(RegularExpressions::ProhibitComplexRegexes)

# HACKER's INFO
#       To get a list of RegEx for invalid hosts, use:
#           grep qr/ $0

=pod

=head1 NAME

o-saft.cgi  - wrapper script to start o-saft.pl as CGI script

=head1 DESCRIPTIONS

Calls ./o-saft.pl if first parameter is  I<--cgi>.
Returns results as:  Content-type: text/plain;charset=utf-8
If parameter  I<--format=html>  is given returns results as:
 Content-type: text/html;charset=utf-8

Does some lazy checks according parameters and exits if found:

=over 4

=item not allowed characters in parameters, except:

 a-zA-Z0-9,.:_&\!\/=\+-

=item not allowed options:

--env* --exe* --lib* --call* --openssl*

=item illegal hostnames or IPs:

localhost, (0|10|127|169|172|192|224|240|255).X.X.X *.local

=item any IPv6 addresses in URLs

=back

Exits silently if any above error is detected.
Exits with verbose error message for detected errors, if environment variable
I<OSAFT_CGI_TEST>  is set.

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

my $SID     = "@(#) o-saft.cgi 1.26 18/11/13 00:05:41";
my $VERSION = '18.11.10';
my $me      = $0; $me     =~ s#.*/##;
my $mepath  = $0; $mepath =~ s#/[^/\\]*$##;
   $mepath  = './' if ($mepath eq $me);
local $|    = 1;    # don't buffer, synchronize STDERR and STDOUT

##############################################################################
my $osaft   = "$mepath/o-saft.pl";
#  $osaft   = '/bin/o-saft/o-saft.pl';          # <== adapt as needed
my $openssl = '/usr/local/openssl/bin/openssl'; # <== adapt as needed
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
	# As the client (browser) is not able to set the environment variable,
	# the code should be safe.
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
	_warn_and_exit "call without parameters" if (0 > $#argv);
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
        # NOTE: in true CGI-mode, QUERY_STRING just contains the form fields,
        #       when used with our own  osaft:  schema, it also contains the
        #       the schema and path, i.e.  osaft:///o-saft.cgi?
        # NOTE: for debugging using system() writing to a file is better than
        #       using perl's print().
	my $qs =  '';
	$qs  = $ENV{'QUERY_STRING'} if (defined $ENV{'QUERY_STRING'});
        #dbx# system "echo  '$qs #' >> /tmp/osaft-handler.log";
	$qs  =~ s/^"?(.*?)"?$/$1/;      # remove enclosing " (windows problem)
	$qs  =~ s#^o-?saft://##g;       # remove schema if any (used in o-saft.cgi.html)
	$qs  =~ s#^[^?]*\?##g;          # remove path left of ? if any (used in o-saft.cgi.html)
	$qs  =~ s/[+]/ /g;
	$qs  =~ s/(?:%([0-9a-f]{2,2}))/pack("H2", $1)/egi;  # url-decode once
	undef @argv;
	push(@argv, split(/[&?]/, $qs));
        #dbx# print join "\n", @argv;
        #dbx# system "echo  '@argv :' >> /tmp/osaft-handler.log";

	$cgi = shift @argv || '';       # remove first argument, which must be --cgi
	                                # || ''   avoids uninitialized value
	push(@argv, "--cgi-exec");      # some argument which looks like --cgi required for some more checks
	die "**ERROR: CGI mode requires strict settings\n" if ($cgi !~ /^--cgi=?$/);
	print "X-Cite: Perl is a mess. But that's okay, because the problem space is also a mess. Larry Wall\r\n";
	print "X-O-Saft: OWASP – SSL advanced forensic tool 1.26\r\n";
	if ($qs =~ m/--format=html/) {
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
		# TODO: IPv6 localhost:   [7f00:1] .. [7fff:ffff]

		qr/(-(host|url)=((ffff:)?(0|10|127|22[4-9]|23[0-9]|24[0-9]|25[0-5])\.[\d]+.[\d]+.[\d]+))/i,
			# loopback, mulicast

		qr/(-(host|url)=((ffff:)?(100\.64|169.254|172\.(1[6-9]|2\d|3[01])|192\.168|198\.18)\.[\d]+.[\d]+))/i,
			# common Class B RFC networks for private use
			# TODO: 100.64.0.0/10 is not really class B

		qr/(-(host|url)=.*?\.local$)/i,
			# multicast domain .local (RFC6762)

		qr/(-(host|url)=((ffff:)?(192\.0\.[02]|192.88\.99|198\.51\.100|203\.0\.13)\.[\d]+))/i,
			# common class C RFC networks for private use

		qr/(-(host|url)=((fe80|fe[c-f][0-9a-f]:)))/i,
			# IPv6 link local or site local

		qr/(-(host|url)=((ff0[0-9a-f]|f[c-d][0-9a-f][0-9a-f]:)))/i,
			# IPv6 multicast or unique local unicast (RFC6762)

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
        local $|    = 1;    # don't buffer, synchronize STDERR and STDOUT
        #dbx# system "$osaft @argv >> /tmp/osaft-handler.log";
	exec $osaft, @argv;        # exec is ok, as we call ourself only
	# TODO: Win32 nost tested: exec 'perl.exe', $osaft, @argv;
}
exit 0; # never reached
