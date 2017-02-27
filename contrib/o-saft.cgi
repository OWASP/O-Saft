#!/usr/bin/perl -T

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

=item following hosts are ignored:   localhost, (0|10|127|172|192|224|255).X.X.X

=back

=head1 EXAMPLE

Call as CGI from command line:

  env "QUERY_STRING=--cgi&--host=demo.tld&--cmd=cn" o-saft.cgi


=head1 SEE ALSO

=head2 L<o-saft.pl(1)>

=head1 AUTHOR

12-sep-12 Achim Hoffmann

=cut

use strict;
use warnings;

## no critic qw(ValuesAndExpressions::ProhibitNoisyQuotes)
## no critic qw(RegularExpressions::ProhibitComplexRegexes)

my $SID     = '@(#) o-saft.cgi 1.1 17/02/27 21:04:28';
my $VERSION = '17.02.17';
my $me      = $0; $me     =~ s#.*/##;
my $mepath  = $0; $mepath =~ s#/[^/]*$##;
   $mepath  = './' if ($mepath eq $me);
my $osaft   = '/usr/local/cgi-bin/o-saft.pl'; # <== adapt as needed
        # NOTE tainted perl (-T) will complain if the path given in $osaft
        #      is writable; it also must be an absolute path

my @argv    = @ARGV;

my $cgi     = 0;
if ($me =~/\.cgi$/) {
        # CGI mode is pretty simple:
        #   use QUERY_STRING and POST data and URL-decode once
        #   check if data contains suspicious characters, die if so
        #       NOTE that % is suspicious as we decode only once
        #   then split data at & to get our options and arguments
        #   ready we go with the existing code :)
        my $qs =  '';
        $qs  = $ENV{'QUERY_STRING'} if (defined $ENV{'QUERY_STRING'});
        $qs  =~ s/[+]/ /g;
        $qs  =~ s/(?:%([0-9a-f]{2,2}))/pack("H2", $1)/egi;      # url-decode once
        undef @argv;
        push(@argv, split('&', $qs));
        $cgi = shift @argv;             # remove first argument, which must be --cgi
        push(@argv, "--cgi-exec");      # some argument which looks like --cgi required for some more checks
        die "**ERROR: CGI mode requires strict settings\n" if ($cgi !~ /^--cgi=?/);
        print "X-O-Saft: OWASP – SSL advanced forensic tool $VERSION\r\n";
        if ($qs =~ m/--cmd=html/) {
            print "Content-type: text/html;  charset=utf-8\r\n";# for --usr* only
        } else {
            print "Content-type: text/plain; charset=utf-8\r\n";# normal results
        }
        print "\r\n";
        if (defined $ENV{'REQUEST_METHOD'}) { # ToDo: NOT WORKING
            $qs .= <> if ($ENV{'REQUEST_METHOD'} eq 'POST');# add to GET data
        }
        if ($qs =~ m/[^a-zA-Z0-9,.:_&\!\/=\+-]/) {
            print "**ERROR: nice hack attempt; $qs ; ignored";
            exit 0;
        }
        if ($qs =~ m/(cmd=list|-host=(localhost|(0|10|127|172|192|224|255).[\d]+.[\d]+.[\d]+)|--(env|exe|lib|call|openssl))/) {
            # dangerous (172.* and 192.* are not realy class A, but anyway ..)
            print "**ERROR: ne, ne, ne";
            exit 0;
        }
        #dbx# print "\nQS: $qs\n";

        # set environment as appropriate; note that taint may complain
        #local $ENV{LD_LIBRARY_PATH} = '/opt/tools/openssl-chacha/lib/';
        #local $ENV{PATH} = '/opt/tools/openssl-chacha/bin/' . ':' . $ENV{PATH};

        exec $osaft, @argv;             # exec is ok, as we call ourself only
}
exit 0;
