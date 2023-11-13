#!/usr/bin/perl

#!#############################################################################
#!#             Copyright (c) 2023, Achim Hoffmann
#!#----------------------------------------------------------------------------
#!# If this tool is valuable for you and we meet some day,  you can spend me an
#!# O-Saft. I'll accept good wine or beer too :-). Meanwhile -- 'til we meet --
#!# your're encouraged to make a donation to any needy child you see.   Thanks!
#!#----------------------------------------------------------------------------
#!# This software is provided "as is", without warranty of any kind, express or
#!# implied,  including  but not limited to  the warranties of merchantability,
#!# fitness for a particular purpose.  In no event shall the  copyright holders
#!# or authors be liable for any claim, damages or other liability.
#!# This software is distributed in the hope that it will be useful.
#!#
#!# This  software is licensed under GPLv2.
#!#
#!# GPL - The GNU General Public License, version 2
#!#                       as specified in:  http://www.gnu.org/licenses/gpl-2.0
#!#      or a copy of it https://github.com/OWASP/O-Saft/blob/master/LICENSE.md
#!# Permits anyone the right to use and modify the software without limitations
#!# as long as proper  credits are given  and the original  and modified source
#!# code are included. Requires  that the final product, software derivate from
#!# the original  source or any  software  utilizing a GPL  component, such  as
#!# this, is also licensed under the same GPL license.
#!#############################################################################

#!# WARNING:
#!# This is no "academically" certified code,  but written to be understood and
#!# modified by humans (you:) easily.  Please see the documentation  in section
#!# "Program Code"  (file coding.txt) if you want to improve the program.

# NOTE: Perl's  `use' and `require' will be used for common and well known Perl
#       modules only. All other modules, in particular our own ones, are loaded
#       using an internal function, see _load_file().  All required modules are
#       included as needed. This keeps away noisy messages and allows to be run
#       and print some information even if installed incompletely.

## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
#  NOTE: SEE Perl:binmode()

## no critic qw(Variables::RequireLocalizedPunctuationVars)
#  NOTE: Perl::Critic seems to be buggy as it does not honor the  allow  option
#        for this policy (see  .perlcriticrc  also).  It even doesn't honor the
#        setting here, hence it's disabled at each line using  $ENV{} = ...

## no critic qw(Variables::ProhibitPackageVars)
#  NOTE: we have a couple of global variables, but do not want to write them in
#        all CAPS (as it would be required by Perl::Critic)

## no critic qw(ErrorHandling::RequireCarping)
#  NOTE: Using carp() is nice in modules,  as it also prints the calling stack.
#        But here it is sufficient to see the line number, hence we use warn().

## no critic qw(Subroutines::ProhibitExcessComplexity)
#  NOTE: It's the nature of checks to be complex, hence don't complain.

## no critic qw(Modules::ProhibitExcessMainComplexity)
#  NOTE: Yes, it's a high, very high complexity here.
#       BUG: this pragma does not work here, needs mccabe value ...

use strict;
use warnings;

our $SID_main   = "@(#) yeast.pl 2.61 23/11/13 14:47:04"; # version of this file
my  $VERSION    = _VERSION();           ## no critic qw(ValuesAndExpressions::RequireConstantVersion)
    # SEE Perl:constant
    # see _VERSION() below for our official version number
use autouse 'Data::Dumper' => qw(Dumper);
#use Encode;    # see _load_modules()

sub _set_binmode    {
    # set discipline for I/O operations (STDOUT, STDERR)
    # SEE Perl:binmode()
    my $layer = shift;
    binmode(STDOUT, $layer);
    binmode(STDERR, $layer);
    return;
} # _set_binmode
_set_binmode(":unix:utf8"); # set I/O layers very early

sub _is_argv    { my $rex = shift; return (grep{/$rex/i} @ARGV); }  # SEE Note:ARGV
    # return 1 if value in command-line arguments @ARGV
sub _is_v_trace { my $rex = shift; return (grep{/--(?:v|trace(?:=\d*)?$)/} @ARGV); }  # case-sensitive! SEE Note:ARGV
    # need to check @ARGV directly as this is called before any options are parsed

# SEE Make:OSAFT_MAKE (in Makefile.pod)
our $time0  = time();   # must be set very early, cannot be done in osaft.pm
    $time0 += ($time0 % 2) if (defined $ENV{'OSAFT_MAKE'});
    # normalise to even seconds, allows small time diffs
sub _yeast_TIME(@)  {
    # print timestamp if --trace-time was given; similar to _y_CMD
    my @txt = @_;
    return if (_is_argv('(?:--trace.?(?:time|cmd))') <= 0);
    my $me  = $0; $me =~ s{.*?([^/\\]+)$}{$1};
    my $now = time();
       $now = time() - ($time0 || 0) if not _is_argv('(?:--time.*absolut)');
       $now +=1 if (0 > $now);  # fix runtime error: $now == -1
       $now += ($now % 2) if (defined $ENV{'OSAFT_MAKE'});
       $now = sprintf("%02s:%02s:%02s", (localtime($now))[2,1,0]);


    if (defined $ENV{'OSAFT_MAKE'}) {   # SEE Make:OSAFT_MAKE (in Makefile.pod)
       $now = "HH:MM:SS (OSAFT_MAKE exists)" if (not $time0);# time0 unset or 0
    }
    printf("#$me %s CMD: %s\n", $now, @txt);
    return;
} # _yeast_TIME
sub _yeast_EXIT($)  {
    # exit if parameter matches given argument in @ARGV
    my $txt =  shift;   # example: INIT0 - initialisation start
    my $arg =  $txt;
       $arg =~ s# .*##; # strip off anything right of a space
    if ((grep{/(?:([+,]|--)$arg).*/i} @ARGV) > 0) { # case-sensitve, cannot use _is_argv()
        printf STDERR ("#o-saft.pl  _yeast_EXIT $txt\n");
        exit 0;
    }
    return;
} # _yeast_EXIT
sub _yeast_NEXT($)  {
    # return 1 if parameter matches given argument in @ARGV; 0 otherwise
    my $txt =  shift;   # example: INIT0 - initialisation start
    my $arg =  $txt;
       $arg =~ s# .*##; # strip off anything right of a space
    if ((grep{/(?:([+,]|--)$arg).*/i} @ARGV) > 0) { # case-sensitve, cannot use _is_argv()
        printf STDERR ("#o-saft.pl  _yeast_EXIT $txt\n");
        return 1;
    }
    return 0;
} # _yeast_NEXT
sub _version_exit   { print _VERSION() . "\n"; exit 0; }
    # print VERSION and exit

#$DB::single=1;          # for debugging; start with: PERL5OPT='-dt' $0

BEGIN {
    # SEE Perl:BEGIN
    # SEE Perl:BEGIN perlcritic
    _yeast_TIME("BEGIN{");
    _yeast_EXIT("exit=BEGIN0 - BEGIN start");
    sub _VERSION { return "23.04.23"; } # <== our official version number
        # get official version (used for --help=* and in private modules)
    my $_me   = $0;     $_me   =~ s#.*[/\\]##;
    my $_path = $0;     $_path =~ s#[/\\][^/\\]*$##;
    my $_pwd  = $ENV{PWD} || ".";   # . as fallback if $ENV{PWD} not defined
    # SEE Perl:@INC
    #unshift(@INC, "..")     if (1 > (grep{/^\.\.$/}   @INC));
    unshift(@INC, "bin")    if (1 > (grep{/^bin$/}    @INC));
    unshift(@INC, "lib")    if (1 > (grep{/^lib$/}    @INC));
    unshift(@INC, $_path)   if (1 > (grep{/^$_path$/} @INC));
    unshift(@INC, $_pwd)    if (1 > (grep{/^$_pwd$/}  @INC));
    unshift(@INC, ".")      if (1 > (grep{/^\.$/}     @INC));
    # handle simple help very quickly; _is_argv() cannot be used because upper case
    if ((grep{/(?:[+]|,|--)VERSION/} @ARGV) > 0) { _version_exit(); }
    # be smart to users if systems behave strange :-/
    print STDERR "**WARNING: 019: on $^O additional option  --v  required, sometimes ...\n" if ($^O =~ m/MSWin32/);
    _yeast_EXIT("exit=BEGIN1 - BEGIN end");
} # BEGIN
_yeast_TIME("BEGIN}");          # missing for +VERSION, however, +VERSION --trace-TIME makes no sense
_yeast_EXIT("exit=INIT0 - initialisation start");

$::osaft_standalone = 0;        # SEE Note:Stand-alone

## PACKAGES         # dummy comment used by some generators, do not remove

#| definitions: include configuration; it's ok to die if missing
#| -------------------------------------
use OSaft::Text     qw(%STR);
use OSaft::Ciphers  qw(%ciphers %ciphers_desc %ciphers_notes $cipher_results);
    # not loaded with _load_modules() because always needed
use osaft;
use OSaft::Data;
# simplify use of variables (because importing fails in o-saft-standalone.pl)
#our %cfg        = %OSaft::Cfg::cfg;
our %checks     = %OSaft::Data::checks;
our %data       = %OSaft::Data::data;
our %data0      = %OSaft::Data::data0;
our %info       = %OSaft::Data::info;
our %shorttexts = %OSaft::Data::shorttexts;
our %check_cert = %OSaft::Data::check_cert;
our %check_conn = %OSaft::Data::check_conn;
our %check_dest = %OSaft::Data::check_dest;
our %check_http = %OSaft::Data::check_http;
our %check_size = %OSaft::Data::check_size;

$cfg{'time0'}   = $time0;
osaft::set_user_agent("$cfg{'me'}/2.61");

#_____________________________________________________________________________
#________________________________________________________________ variables __|

my  $arg    = "";
my  @argv   = ();   # all options, including those from RC-FILE
                    # will be used when ever possible instead of @ARGV

#dbx# print STDERR "#$cfg{'me'} INC=@INC\n";

printf("#$cfg{'me'} %s\n", join(" ", @ARGV)) if _is_argv('(?:--trace[_.-]?(?:CLI$)?)');
    # print complete command-line if any --trace-* was given, it's intended
    # that it works if unknown --trace-* was given, for example --trace-CLI

#| definitions: forward declarations
#| -------------------------------------
sub _is_cfg_intern($);
    # forward ...

#| README if any
#| -------------------------------------
#if (open(my $rc, '<', "o-saft-README")) { print <$rc>; close($rc); exit 0; };
    # SEE Since VERSION 16.06.16

#| CGI
#| -------------------------------------
my  $cgi = 0;
    $cgi = 1 if ((grep{/(?:--cgi-?(?:exec|trace))/i} @ARGV) > 0);
#if ($cfg{'me'} =~/\.cgi$/) { SEE Since VERSION 18.12.18
    #die $STR{ERROR}, "020: CGI mode requires strict settings" if (_is_argv('--cgi=?') <= 0);
#} # CGI

#_____________________________________________________________________________
#________________________________________________________________ functions __|

#| definitions: debug and tracing functions
#| -------------------------------------
# functions and variables used very early in main
sub _dprint { my @txt = @_; local $\ = "\n"; print STDERR $STR{DBX}, join(" ", @txt); return; }
    #? print line for debugging
sub _dbx    { my @txt = @_; _dprint(@txt); return; }
    #? print line for debugging (alias for _dprint)
sub _hint   {
    #? print hint message if wanted
    # don't print if --no-hint given
    # check must be done on ARGV, because $cfg{'out'}->{'hint_info'} may not yet set
    my @txt = @_;
    return if _is_argv('(?:--no.?hint)');
    printf($STR{HINT} . "%s\n", join(" ", @txt));
    return;
} # _hint
sub _warn   {
    #? print warning if wanted; SEE Note:Message Numbers
    # don't print if (not _is_cfg_out('warning'));
    my @txt = @_;
    my $_no =  "@txt";
       $_no =~ s/^\s*([0-9(]{3}):?.*/$1/;   # message number, usually
    return if _is_argv('(?:--no.?warn(?:ings?)$)'); # ugly hack 'cause we won't pass $cfg{use}{warning}
    # other configuration values can be retrieved from %cfg
    if (0 < (grep{/^$_no$/} @{$cfg{out}->{'warnings_no_dups'}})) {
        # SEE  Note:warning-no-duplicates
        return if (0 < (grep{/^$_no$/} @{$cfg{out}->{'warnings_printed'}}));
        push(@{$cfg{out}->{'warnings_printed'}}, $_no);
    }
    local $\ = "\n";
    print($STR{WARN}, join(" ", @txt));
    # TODO: in CGI mode warning must be avoided until HTTP header written
    _yeast_EXIT("exit=WARN - exit on first warning");
    return;
} # _warn

sub _warn_and_exit      {
    #? print warning that --experimental option is required
    #-method:  name of function where this message is called
    #-command: name of command subject to this message
    my @txt = @_;
    if (_is_argv('(?:--experimental)') > 0) {
        my $method = shift;
        _trace("_warn_and_exit $method: " . join(" ", @txt));
    } else {
        printf($STR{WARN} . "099: (%s) --experimental option required to use '%s' functionality. Please send us your feedback about this functionality to o-saft(at)lists.owasp.org\n", @txt);
        exit(1);
    }
    return;
} # _warn_and_exit

sub _warn_nosni         {
    #? print warning and hint message if SNI is not supported by SSL
    my $err = shift;
    my $ssl = shift;
    my $sni = shift;
    return if ($sni < 1);
    return if ($ssl !~ m/^SSLv[23]/);
    # SSLv2 has no SNI; SSLv3 has originally no SNI
    _warn("$err $ssl does not support SNI; cipher checks are done without SNI");
    return;
} # _warn_nosni

sub _print_read         {
    #? print information which file will be read
    #? will only be written if --v or --warn or --trace is given and  --cgi-exec
    #? or  --no-header   are not given
    # $cgi is not (yet) available, hence we use @ARGV to check for options
    # $cfg{'out'}->{'header'} is also not yet properly set, see LIMITATIONS also
    my ($fil, @txt) = @_;
    # TODO: quick&ugly check when to write "reading" depending on given --trace* options
    return if (0 <  (grep{/(?:--no.?header|--cgi)/i}    @ARGV));# --cgi-exec or --cgi-trace
    return if (0 >= (grep{/(?:--warn|--v$|--trace)/i}   @ARGV));
    if (0 >= (grep{/(?:--trace[_.-]?(?:ARG|CMD|TIME|ME)$)/i} @ARGV)) {
        return if (0 <  (grep{/(?:--trace[_.-]?CLI$)/i} @ARGV));# --trace-CLI
    }
    printf("=== reading: %s (%s) ===\n", $fil, @txt);
    return;
} # _print_read

sub _load_file          {
    #? load file with Perl's require using the paths in @INC
    # use `$0 +version --v'  to see which files are loaded
    my $fil = shift;
    my $txt = shift;
    my $err = "";
    # need eval to catch "Can't locate ... in @INC ..."
    eval {require $fil;} or _warn("101: 'require $fil' failed");
    $err = $@;
    chomp $err;
    if ("" eq $err) {
        $fil = $INC{$fil};
        $txt = "$txt done";
    } else {
        $txt = "$txt failed";
    }
    push(@{$dbx{file}}, $fil);
    _print_read($fil, $txt);
    return $err;
} # _load_file

sub __SSLinfo($$$)      {
    #? wrapper for Net::SSLinfo::*() functions
    # Net::SSLinfo::*() return raw data, depending on $cfg{'format'}
    # these values will be converted to o-saft's preferred format
    my ($cmd, $host, $port) = @_;
    my $val = "<<__SSLinfo: unknown command: '$cmd'>>";
    my $ext = "";
    $val =  Net::SSLinfo::fingerprint(      $host, $port) if ($cmd eq 'fingerprint');
    $val =  Net::SSLinfo::fingerprint_hash( $host, $port) if ($cmd eq 'fingerprint_hash');
    $val =  Net::SSLinfo::fingerprint_sha2( $host, $port) if ($cmd eq 'fingerprint_sha2');
    $val =  Net::SSLinfo::fingerprint_sha1( $host, $port) if ($cmd eq 'fingerprint_sha1');
    $val =  Net::SSLinfo::fingerprint_md5(  $host, $port) if ($cmd eq 'fingerprint_md5');
    $val =  Net::SSLinfo::pubkey_value(     $host, $port) if ($cmd eq 'pubkey_value');
    $val =  Net::SSLinfo::sigkey_value(     $host, $port) if ($cmd eq 'sigkey_value');
    $val =  Net::SSLinfo::heartbeat(        $host, $port) if ($cmd eq 'heartbeat');
    $val =  Net::SSLinfo::extensions(       $host, $port) if ($cmd =~ /^ext(?:ensions|_)/);
    $val =  Net::SSLinfo::tlsextdebug(      $host, $port) if ($cmd eq 'tlsextdebug');
    if ($cmd eq 'tlsextensions') {
        $val =  Net::SSLinfo::tlsextensions($host, $port);
        $val =~ s/^\s*//g;
        $val =~ s/([\n\r])/; /g;
    }
    # ::ocspid may return multiple lines, something like:
    #   Subject OCSP hash: 57F4D68F870A1698065F803BE9D967B1B2B9E491
    #   Public key OCSP hash: BF788D39424E219C62538F72701E1C87C4F667EA
    # it's also assumed that both lines are present
    if ($cmd =~ /ocspid/) {
        $val =  Net::SSLinfo::ocspid($host, $port);
        $val =~ s/^\n?\s+//g;           # remove leading spaces
        $val =~ s/([\n\r])/; /g;        # remove newlines
    }
    if ($cmd =~ /ocsp_subject_hash/) {
        $val =  Net::SSLinfo::ocspid($host, $port);
        $val =~ s/^[^:]+:\s*//;
        $val =~ s/.ublic[^:]+:\s*.*//;
    }
    if ($cmd =~ /ocsp_public_hash/) {
        $val =  Net::SSLinfo::ocspid($host, $port);
        $val =~ s/^[^:]+:\s*//;
        $val =~ s/^[^:]+:\s*//;     # TODO: quick&dirty
    }
    if ($cmd =~ m/ext_/) {
        # all following are part of Net::SSLinfo::extensions(), now extract parts
        # The extension section in the certificate starts with
        #    X509v3 extensions:
        # then each extension starts with a string prefixed by  X509v3
        # except following:
        #    Authority Information Access
        #    Netscape Cert Type
        #    CT Precertificate SCTs
        #
        # Example www.microsoft.com (03/2016)
        #    X509v3 extensions:
        #        X509v3 Subject Alternative Name:
        #            DNS:privacy.microsoft.com, DNS:www.microsoft.com, DNS:wwwqa.microsoft.com
        #        X509v3 Basic Constraints:
        #            CA:FALSE
        #        X509v3 Key Usage: critical
        #            Digital Signature, Key Encipherment
        #        X509v3 Extended Key Usage:
        #            TLS Web Server Authentication, TLS Web Client Authentication
        #        X509v3 Certificate Policies:
        #            Policy: 2.16.840.1.113733.1.7.23.6
        #              CPS: https://d.symcb.com/cps
        #              User Notice:
        #                Explicit Text: https://d.symcb.com/rpa
        #        X509v3 Authority Key Identifier:
        #            keyid:0159ABE7DD3A0B59A66463D6CF200757D591E76A
        #        X509v3 CRL Distribution Points:
        #            Full Name:
        #              URI:http://sr.symcb.com/sr.crl
        #        Authority Information Access:
        #            OCSP - URI:http://sr.symcd.com
        #            CA Issuers - URI:http://sr.symcb.com/sr.crt
        #        CT Precertificate SCTs:
        #            Signed Certificate Timestamp:
        #                Version   : v1(0)
        #                Log ID    : DDEB1D2B7A0D4FA6208B81AD8168707E:
        #                            2E8E9D01D55C888D3D11C4CDB6ECBECC
        #                Timestamp : Mar 24 212018.939 2016 GMT
        #                Extensions: none
        #                Signature : ecdsa-with-SHA256
        #                            304602210095B30A493A8E8B253004AD:
        #                            A971E0106BE0CC97B6FF2908FDDBBB3D:
        #                            B8CEBFFCF8022100F37AA34DE5BE38D8:
        #                            5A03EE8B3AAE451C0014A802C079AA34:
        #                            9C20BAF44C54CF36
        #            Signed Certificate Timestamp:
        #                Version   : v1(0)
        #                Log ID    : A4B90990B418581487BB13A2CC67700A:
        #                            3C359804F91BDFB8E377CD0EC80DDC10
        #                Timestamp : Mar 24 212018.983 2016 GMT
        #                Extensions: none
        #                Signature : ecdsa-with-SHA256
        #                            3046022100C877DC1DBBDA2FBC7E5E63:
        #                            60A7EAB31EED42066F91C724963EE0CE:
        #                            80C8EBCE8C022100D5865704F32487CF:
        #                            FF021F1C8A955303E496630CAE3C0F18:
        #                            B8CDDFD4798365FD
        #        ...
        #
        # Example microsoft.com
        #    X509v3 extensions:
        #        X509v3 Key Usage:
        #            Digital Signature, Key Encipherment, Data Encipherment
        #        X509v3 Extended Key Usage:
        #            TLS Web Server Authentication, TLS Web Client Authentication
        #        S/MIME Capabilities:
        #            0000 - 30 69 30 0e 06 08 2a 86-48 86 f7 0d 03   0i0...*.H....
        #            000d - 02 02 02 00 80 30 0e 06-08 2a 86 48 86   .....0...*.H.
        #            001a - f7 0d 03 04 02 02 00 80-30 0b 06 09 60   ........0...`
        #            0027 - 86 48 01 65 03 04 01 2a-30 0b 06 09 60   .H.e...*0...`
        #            0034 - 86 48 01 65 03 04 01 2d-30 0b 06 09 60   .H.e...-0...`
        #            0041 - 86 48 01 65 03 04 01 02-30 0b 06 09 60   .H.e....0...`
        #            004e - 86 48 01 65 03 04 01 05-30 07 06 05 2b   .H.e....0...+
        #            005b - 0e 03 02 07 30 0a 06 08-2a 86 48 86 f7   ....0...*.H..
        #            0068 - 0d 03 07                                 ...
        #        X509v3 Subject Key Identifier:
        #            84C60E3B0FA69BF6EE0640CB02041B5F59340F73
        #        X509v3 Authority Key Identifier:
        #            keyid:51AF24269CF468225780262B3B4662157B1ECCA5
        #        X509v3 CRL Distribution Points:
        #            Full Name:
        #              URI:http://mscrl.microsoft.com/pki/mscorp/crl/msitwww2.crl
        #              URI:http://crl.microsoft.com/pki/mscorp/crl/msitwww2.crl
        #        Authority Information Access:
        #            CA Issuers - URI:http://www.microsoft.com/pki/mscorp/msitwww2.crt
        #            OCSP - URI:http://ocsp.msocsp.com
        #        X509v3 Certificate Policies:
        #            Policy: 1.3.6.1.4.1.311.42.1
        #              CPS: http://www.microsoft.com/pki/mscorp/cps
        #        1.3.6.1.4.1.311.21.10:
        #            0000 - 30 18 30 0a 06 08 2b 06-01 05 05 07 03   0.0...+......
        #            000d - 01 30 0a 06 08 2b 06 01-05 05 07 03 02   .0...+.......
        #        ...
        #
        # Example bsi.bund.de (03/2016)
        #    X509v3 extensions:
        #        X509v3 Authority Key Identifier:
        #            keyid:5404296FA293C6903145C03DDE2BE20A6980925F
        #        X509v3 Key Usage: critical
        #            Digital Signature, Key Encipherment
        #        X509v3 Extended Key Usage:
        #            TLS Web Client Authentication, TLS Web Server Authentication
        #        X509v3 Subject Key Identifier:
        #            1BA42D9746798AE2AE91D60AA60BE40FAA8A299E
        #        X509v3 Certificate Policies:
        #            Policy: 1.3.6.1.4.1.7879.13.2
        #              CPS: http://www.telesec.de/serverpass/cps.html
        #            Policy: 2.23.140.1.2.2
        #        X509v3 CRL Distribution Points:
        #            Full Name:
        #              URI:http://crl.serverpass.telesec.de/rl/TeleSec_ServerPass_DE-2.crl
        #            Full Name:
        #              URI:ldap://ldap.serverpass.telesec.de/cn=TeleSec%20ServerPass%20DE-2,ou=T-Systems%20Trust%20Center,o=T-Systems%20International%20GmbH,c=de?certificateRevocationlist?base?certificateRevocationlist=*
        #        Authority Information Access:
        #            OCSP - URI:http://ocsp.serverpass.telesec.de/ocspr
        #            CA Issuers - URI:http://crl.serverpass.telesec.de/crt/TeleSec_ServerPass_DE-2.cer
        #            CA Issuers - URI:ldap://ldap.serverpass.telesec.de/cn=TeleSec%20ServerPass%20DE-2,ou=T-Systems%20Trust%20Center,o=T-Systems%20International%20GmbH,c=de?cACertificate
        #        X509v3 Basic Constraints: critical
        #            CA:FALSE
        #        X509v3 Subject Alternative Name:
        #            DNS:www.bsi.bund.de
        #
        # Example www.bsi.de (06/2016)
        #    X509v3 CRL Distribution Points:
        #
        #         Full Name:
        #           URI:http://crl.serverpass.telesec.de/rl/TeleSec_ServerPass_DE-2.crl
        #
        #         Full Name:
        #           URI:ldap://ldap.serverpass.telesec.de/cn=TeleSec%20ServerPass%20DE-2,ou=T-Systems%20Trust%20Center,o=T-Systems%20International%20GmbH,c=de?certificateRevocationlist?base?certificateRevocationlist=*
        #     Authority Information Access:
        #         OCSP - URI:http://ocsp.serverpass.telesec.de/ocspr
        #         CA Issuers - URI:http://crl.serverpass.telesec.de/crt/TeleSec_ServerPass_DE-2.cer
        #         CA Issuers - URI:ldap://ldap.serverpass.telesec.de/cn=TeleSec%20ServerPass%20DE-2,ou=T-Systems%20Trust%20Center,o=T-Systems%20International%20GmbH,c=de?cACertificate
        #
        # handled in RegEx below which matches next extension, if any.
        $val .= " X509";# add string to match last extension also
        my $rex = '\s*(.*?)(?:X509|Authority|Netscape|CT Precertificate).*';
            # FIXME: the RegEx should match OIDs also
            # FIXME: otherwise OID extensions are added as value to the
            #        preceding extension, see example above (4/2016)
        # TODO: replace following list of RegEx with a loop over the extensions
        $ext = $val;
        $val =~ s#.*?Authority Information Access:$rex#$1#ms    if ($cmd eq 'ext_authority');
        $val =~ s#.*?Authority Key Identifier:$rex#$1#ms        if ($cmd eq 'ext_authorityid');
        $val =~ s#.*?Basic Constraints:$rex#$1#ms               if ($cmd eq 'ext_constraints');
        $val =~ s#.*?Key Usage:$rex#$1#ms                       if ($cmd eq 'ext_keyusage');
        $val =~ s#.*?Subject Key Identifier:$rex#$1#ms          if ($cmd eq 'ext_subjectkeyid');
        $val =~ s#.*?Certificate Policies:$rex#$1#ms            if ($cmd =~ /ext_cps/);
        $val =~ s#.*?CPS\s*:\s*([^\s\n]*).*#$1#ms               if ($cmd eq 'ext_cps_cps');
        $val =~ s#.*?Policy\s*:\s*(.*?)(?:\n|CPS|User).*#$1#ims if ($cmd eq 'ext_cps_policy');
        $val =~ s#.*?User\s*Notice:\s*(.*?)(?:\n|CPS|Policy).*#$1#ims  if ($cmd eq 'ext_cps_notice');
        $val =~ s#.*?CRL Distribution Points:$rex#$1#ms         if ($cmd eq 'ext_crl');
        $val =~ s#.*?Extended Key Usage:$rex#$1#ms              if ($cmd eq 'ext_extkeyusage');
        $val =~ s#.*?Netscape Cert Type:$rex#$1#ms              if ($cmd eq 'ext_certtype');
        $val =~ s#.*?Issuer Alternative Name:$rex#$1#ms         if ($cmd eq 'ext_issuer');
        if ($cmd eq 'ext_crl') {
            $val =~ s#\s*Full Name:\s*##imsg;   # multiple occourances possible
            $val =~ s#(\s*URI\s*:)# #msg;
        }
        $val =  "" if ($ext eq $val);   # nothing changed, then expected pattern is missing
    }
# TODO: move code for formatting to print*()
    if ($cmd =~ /ext(?:ensions|debug|_)/) {
        # grrr, formatting extensions is special, take care for traps ...
        if ($cfg{'format'} ne "raw") {
            $val =~ s/([0-9a-f]):([0-9a-f])/$1$2/ig; # remove : inside hex (quick&dirty)
            # it was quick&dirty, correct some failures
            $val =~ s/(keyid)/$1:/i;
            $val =~ s/(CA)(FALSE)/$1:$2/i;
            if ($cmd eq 'extensions') {
                # extensions are special as they contain multiple values
                # values are separated by emty lines
                $val =~ s/\n\n+/\n/g;   # remove empty lines
            } else {
                $val =~ s/\s\s+/ /g;    # remove multiple spaces
            }
        }
        return $val; # ready!
    }
# TODO: move code for formatting to print*()
    if ($cfg{'format'} ne "raw") {
        $val =  "" if not defined $val; # avoid warnings
        $val =~ s/^\s+//g;      # remove leading spaces
        $val =~ s/\n\s+//g;     # remove trailing spaces
        $val =~ s/\n/ /g;
        $val =~ s/\s\s+/ /g;    # remove multiple spaces
        $val =~ s/([0-9a-f]):([0-9a-f])/$1$2/ig; # remove : inside hex (quick&dirty)
    }
    return $val;
} # __SSLinfo

#| read RC-FILE if any
#| -------------------------------------
_yeast_TIME("cfg{");
_yeast_EXIT("exit=CONF0 - RC-FILE start");
if (_is_argv('(?:--rc)') > 0) {                 # (re-)compute default RC-File with full path
    $cfg{'RC-FILE'} =  $0;                      # from directory where $0 found
    $cfg{'RC-FILE'} =~ s#($cfg{'me'})$#.$1#;
}
if (_is_argv('(?:--rc=)') > 0) {                # other RC-FILE given
    $cfg{'RC-FILE'} =  (grep{/--rc=.*/} @ARGV)[0];  # get value --rc=*
    $cfg{'RC-FILE'} =~ s#--rc=##;               # stripp off --rc=
    # no check if file exists, will be done below
}
print "#o-saft.pl  RC-FILE: $cfg{'RC-FILE'}\n" if _is_v_trace();
my @rc_argv = "";
if (_is_argv('(?:--no.?rc)') <= 0) {            # only if not inhibited
    # we do not use a function for following to avoid passing @argv, @rc_argv
    if (open(my $rc, '<:encoding(UTF-8)', "$cfg{'RC-FILE'}")) {
        push(@{$dbx{file}}, $cfg{'RC-FILE'});
        _print_read(  "$cfg{'RC-FILE'}", "RC-FILE done");
        ## no critic qw(ControlStructures::ProhibitMutatingListFunctions)
        #  NOTE: the purpose here is to *change the source array"
        @rc_argv = grep{!/\s*#[^\r\n]*/} <$rc>; # remove comment lines
        @rc_argv = grep{s/[\r\n]//} @rc_argv;   # remove newlines
        @rc_argv = grep{s/\s*([+,-]-?)/$1/} @rc_argv;# get options and commands, remove leading spaces
        ## use critic
        close($rc);
        _warn("052: option with trailing spaces '$_'") foreach (grep{m/\s+$/} @rc_argv);
        push(@argv, @rc_argv);
        # _yeast_rcfile();  # function from o-saft-dbx.pm cannot used here
        if (_is_v_trace()) {
            my @cfgs;
            print "#$cfg{'me'}  $cfg{'RC-FILE'}\n";
            print "#$cfg{'me'}: !!Hint: use  --trace  to see complete settings\n";
            print "#$cfg{'me'}: #------------------------------------------------- RC-FILE {\n";
            foreach my $val (@rc_argv) {
                #print join("\n  ", "", @rc_argv);
                $val =~ s/(--cfg[^=]*=[^=]*).*/$1/ if (0 >=_is_argv('(?:--trace)'));
                print "#$cfg{'me'}:      $val\n";
                if ($val =~ m/--cfg[^=]*=[^=]*/) {
                    $val =~ s/--cfg[^=]*=([^=]*).*/+$1/;
                    push(@cfgs, $val);
                }
            }
            print "#$cfg{'me'}: added/modified= @cfgs\n";
            print "#$cfg{'me'}: #------------------------------------------------- RC-FILE }\n";
        }
    } else {
        _print_read("$cfg{'RC-FILE'}", "RC-FILE: $!") if _is_v_trace();
    }
}
_yeast_EXIT("exit=CONF1 - RC-FILE end");
$cfg{'RC-ARGV'} = [@rc_argv];

%{$cfg{'done'}} = (             # internal administration
        'targets'   => 0,
        'dbxfile'   => 0,
        'rc_file'   => 0,
        'init_all'  => 0,
        'ssl_failed'=> 0,       # local counter for SSL connection errors
        'ssl_errors'=> 0,       # total counter for SSL connection errors
        'arg_cmds'  => [],      # contains all commands given as argument
         # all following need to be reset for each host, which is done in
         # _resetchecks()  by matching the key against ^check or ^cipher
        'default_get'   => 0,
        'ciphers_all'   => 0,
        'ciphers_get'   => 0,
        'checkciphers'  => 0,   # not used, as it's called multiple times
        'checkpreferred' => 0,
        'check02102'=> 0,
        'check03116'=> 0,
        'check2818' => 0,
        'check6125' => 0,
        'check7525' => 0,
        'checkdates'=> 0,
        'checksizes'=> 0,
        'checkbleed'=> 0,
        'checkcert' => 0,
        'checkprot' => 0,
        'checkdest' => 0,
        'checkhttp' => 0,
        'checksstp' => 0,
        'checksni'  => 0,
        'checkssl'  => 0,
        'checkalpn' => 0,
        'checkdv'   => 0,
        'checkev'   => 0,
        'check_dh'  => 0,
        'check_url' => 0,       # not used, as it's called multiple times
        'check_certchars' => 0,
);

push(@argv, @ARGV); # got all now
push(@ARGV, "--no-header") if ((grep{/--no-?header/} @argv)); # if defined in RC-FILE, needed in _warn()

#| read DEBUG-FILE, if any (source for trace and verbose)
#| -------------------------------------
my $err = "";
my @dbx =  grep{/--(?:trace|v$|exitcode.?v$|tests?|yeast)/} @argv;  # may have --trace=./file
push(@dbx, grep{/^[+,](?:tests?)/} @argv);  # may have +test*
if (($#dbx >= 0) and (grep{/--cgi=?/} @argv) <= 0) {    # SEE Note:CGI mode
    $arg =  "o-saft-dbx.pm";
    $arg =  $dbx[0] if ($dbx[0] =~ m#/#);
    $arg =~ s#[^=]+=##; # --trace=./myfile.pl
    $err = _load_file($arg, "trace file");
    if ($err ne "") {
        die $STR{ERROR}, "012: $err" unless (-e $arg);
        # no need to continue if file with debug functions does not exist
        # NOTE: if $mepath or $0 is a symbolic link, above checks fail
        #       we don't fix that! Workaround: install file in ./
    }
} else {
    sub _yeast_init   {}
    sub _yeast_exit   {}
    sub _yeast_args   {}
    sub _yeast_data   {}
    sub _yeast_ciphers_list {}
    sub _yeast        {}
    sub _y_ARG        {}
    sub _y_CMD        {}
    sub _v_print      {}
    sub _v2print      {}
    sub _v3print      {}
    sub _v4print      {}
    sub _vprintme     {}
    sub _trace        {}
    sub _trace1       {}
    sub _trace2       {}
    sub _trace3       {}
    sub _trace_cmd    {}
    # debug functions are defined in o-saft-dbx.pm and loaded on demand
    # they must be defined always as they are used whether requested or not
    # NOTE: these comment lines at end of else scope so that some make targets
    #       can produce better human readable results
}

#| read USER-FILE, if any (source with user-specified code)
#| -------------------------------------
if ((grep{/--(?:use?r)/} @argv) > 0) {  # must have any --usr option
    $err = _load_file("o-saft-usr.pm", "user file");
    if ($err ne "") {
        # continue without warning, it's already printed in "=== reading: " line
        # OSAFT_STANDALONE no warnings 'redefine'; # avoid: "Subroutine ... redefined"
        sub usr_version     { return ""; }; # dummy stub, see o-saft-usr.pm
        sub usr_pre_init    {}; #  "
        sub usr_pre_file    {}; #  "
        sub usr_pre_args    {}; #  "
        sub usr_pre_exec    {}; #  "
        sub usr_pre_cipher  {}; #  "
        sub usr_pre_main    {}; #  "
        sub usr_pre_host    {}; #  "
        sub usr_pre_info    {}; #  "
        sub usr_pre_open    {}; #  "
        sub usr_pre_cmds    {}; #  "
        sub usr_pre_data    {}; #  "
        sub usr_pre_print   {}; #  "
        sub usr_pre_next    {}; #  "
        sub usr_pre_exit    {}; #  "
        # user functions are defined in o-saft-user.pm and loaded on demand
    }
}

usr_pre_init();

#| initialise defaults
#| -------------------------------------

# some temporary variables used in main
my $host    = "";       # the host currently processed in main
my $port    = "";       # the port currently used in main
my $legacy  = "";       # the legacy mode used in main
my $verbose = 0;        # verbose mode used in main; option --v
   # above host, port, legacy and verbose are just shortcuts for corresponding
   # values in $cfg{}, used for better human readability
my $test    = "";       # set to argument if --test* or +test* was used
my $info    = 0;        # set to 1 if +info
my $check   = 0;        # set to 1 if +check was used
my $quick   = 0;        # set to 1 if +quick was used
my $cmdsni  = 0;        # set to 1 if +sni  or +sni_check was used
my $sniname = undef;    # will be set to $cfg{'sni_name'} as this changes for each host

# SEE Note:Data Structures
# our %info   = ();
# our %data0  = ();
# our %data   = ();
# our %checks = ();
# our %check_cert = ();
# our %check_conn = ();
# our %check_dest = ();
# our %check_size = ();
# our %check_http = ();
# our %shorttexts = ();

# more initialisation for %data
# add keys from %prot to %data,
$data{'fallback_protocol'}->{'val'} = sub { return $prot{'fallback'}->{val}  };
foreach my $ssl (keys %prot) {
    my $key = lc($ssl); # keys in data are all lowercase (see: convert all +CMD)
    $data{$key}->{val} = sub {    return $prot{$ssl}->{'default'}; };
    $data{$key}->{txt} = "Target default $prot{$ssl}->{txt} cipher";
}
foreach my $ssl (keys %prot) {
    my $key = lc($ssl); # keys in data are all lowercase (see: convert all +CMD)
    $shorttexts{$key} = "Default $prot{$ssl}->{txt} cipher";
}

my %scores = (
    # keys starting with 'check_' are for total values
    # all other keys are for individual score values
    #------------------+-------------+----------------------------------------
    'check_conn'    => {'val' => 100, 'txt' => "SSL connection checks"},
    'check_ciph'    => {'val' => 100, 'txt' => "Ciphers checks"},
    'check_cert'    => {'val' => 100, 'txt' => "Certificate checks"},
    'check_dest'    => {'val' => 100, 'txt' => "Target checks"},
    'check_http'    => {'val' => 100, 'txt' => "HTTP(S) checks"},
    'check_size'    => {'val' => 100, 'txt' => "Certificate sizes checks"},
    'checks'        => {'val' => 100, 'txt' => "Total scoring"},
    #------------------+-------------+----------------------------------------
    # sorting according key name
); # %scores

my %score_ssllabs = (
    # SSL Server Rating Guide:
    #------------------+------------+---------------+-------------------------
    'check_prot'    => {'val' =>  0, 'score' => 0.3, 'txt' => "Protocol support"},        # 30%
    'check_keyx'    => {'val' =>  0, 'score' => 0.3, 'txt' => "Key exchange support"},    # 30%
    'check_ciph'    => {'val' =>  0, 'score' => 0.4, 'txt' => "Cipher strength support"}, # 40%
    # 'score' is a factor here; 'val' will be the score 0..100

    # Letter grade translation
    #                                           Grade  Numerical Score
    #------------------------------------------+------+---------------
    'A' => {'val' => 0, 'score' => 80, 'txt' => "A"}, # score >= 80
    'B' => {'val' => 0, 'score' => 65, 'txt' => "B"}, # score >= 65
    'C' => {'val' => 0, 'score' => 50, 'txt' => "C"}, # score >= 50
    'D' => {'val' => 0, 'score' => 35, 'txt' => "D"}, # score >= 35
    'E' => {'val' => 0, 'score' => 20, 'txt' => "E"}, # score >= 20
    'F' => {'val' => 0, 'score' => 20, 'txt' => "F"}, # score >= 20
     # 'val' is not used above!

    # Protocol support rating guide
    # Protocol                                  Score          Protocol
    #------------------------------------------+-----+------------------
    'SSLv2'         => {'val' =>  0, 'score' =>  20, 'txt' => "SSL 2.0"}, #  20%
    'SSLv3'         => {'val' =>  0, 'score' =>  80, 'txt' => "SSL 3.0"}, #  80%
    'TLSv1'         => {'val' =>  0, 'score' =>  90, 'txt' => "TLS 1.0"}, #  90%
    'TLSv11'        => {'val' =>  0, 'score' =>  95, 'txt' => "TLS 1.1"}, #  95%
    'TLSv12'        => {'val' =>  0, 'score' => 100, 'txt' => "TLS 1.2"}, # 100%
    'TLSv13'        => {'val' =>  0, 'score' => 100, 'txt' => "TLS 1.3"}, # 100%
    'DTLSv09'       => {'val' =>  0, 'score' =>  80, 'txt' => "DTLS 0.9"},#  80%
    'DTLSv1'        => {'val' =>  0, 'score' => 100, 'txt' => "DTLS 1.0"},# 100%
    'DTLSv11'       => {'val' =>  0, 'score' => 100, 'txt' => "DTLS 1.1"},# 100%
    'DTLSv12'       => {'val' =>  0, 'score' => 100, 'txt' => "DTLS 1.2"},# 100%
    'DTLSv13'       => {'val' =>  0, 'score' => 100, 'txt' => "DTLS 1.3"},# 100%
    # 'txt' is not used here!
    #
    #    ( best protocol + worst protocol ) / 2

    # Key exchange rating guide
    #                                           Score          Key exchange aspect                              # Score
    #------------------------------------------+-----+----------------------------------------------------------+------
    'key_debian'    => {'val' =>  0, 'score' =>   0, 'txt' => "Weak key (Debian OpenSSL flaw)"},                #   0%
    'key_anonx'     => {'val' =>  0, 'score' =>   0, 'txt' => "Anonymous key exchange (no authentication)"},    #   0%
    'key_512'       => {'val' =>  0, 'score' =>  20, 'txt' => "Key length < 512 bits"},                         #  20%
    'key_export'    => {'val' =>  0, 'score' =>  40, 'txt' => "Exportable key exchange (limited to 512 bits)"}, #  40%
    'key_1024'      => {'val' =>  0, 'score' =>  40, 'txt' => "Key length < 1024 bits (e.g., 512)"},            #  40%
    'key_2048'      => {'val' =>  0, 'score' =>  80, 'txt' => "Key length < 2048 bits (e.g., 1024)"},           #  80%
    'key_4096'      => {'val' =>  0, 'score' =>  90, 'txt' => "Key length < 4096 bits (e.g., 2048)"},           #  90%
    'key_good'      => {'val' =>  0, 'score' => 100, 'txt' => "Key length >= 4096 bits (e.g., 4096)"},          # 100%
    #
    #
    # Cipher strength rating guide
    #                                           Score          Cipher strength                # Score
    #------------------------------------------+-----+----------------------------------------+------
    'ciph_0'        => {'val' =>  0, 'score' =>   0, 'txt' => "0 bits (no encryption)"},      #   0%
    'ciph_128'      => {'val' =>  0, 'score' =>   0, 'txt' => "< 128 bits (e.g., 40, 56)"},   #  20%
    'ciph_256'      => {'val' =>  0, 'score' =>   0, 'txt' => "< 256 bits (e.g., 128, 168)"}, #  80%
    'ciph_512'      => {'val' =>  0, 'score' =>   0, 'txt' => ">= 256 bits (e.g., 256)"},     # 100%
    #
    #    ( strongest cipher + weakest cipher ) / 2
    #
); # %score_ssllabs

my %score_howsmyssl = (
    # https://www.howsmyssl.com/
    # https://www.howsmyssl.com/s/about.html
    'good'          => {'txt' => "Good"},
    'probably'      => {'txt' => "Probably Okay"},
    'improvable'    => {'txt' => "Improvable"},
        # if they do not support ephemeral key cipher suites,
        # do not support session tickets, or are using TLS 1.1.
    'bad'           => {'txt' => "Bad"},
        # uses TLS 1.0 (instead of 1.1 or 1.2), or worse: SSLv3 or earlier.
        # supports known insecure cipher suites
        # supports TLS compression (that is compression of the encryption
        #     information used to secure your connection) which exposes it
        #     to the CRIME attack.
        # is susceptible to the BEAST attack
); # %score_howsmyssl

my %info_gnutls = ( # NOT YET USED
   # extracted from http://www.gnutls.org/manual/gnutls.html
   #     security   parameter   ECC key
   #       bits       size       size    security    description
   #     ----------+-----------+--------+-----------+------------------
   'I' => "<72      <1008      <160      INSECURE    Considered to be insecure",
   'W' => "72        1008       160      WEAK        Short term protection against small organizations",
   'L' => "80        1248       160      LOW         Very short term protection against agencies",
   'l' => "96        1776       192      LEGACY      Legacy standard level",
   'M' => "112       2432       224      NORMAL      Medium-term protection",
   'H' => "128       3248       256      HIGH        Long term protection",
   'S' => "256       15424      512      ULTRA       Foreseeable future",
); # %info_gnutls

our %cmd = (
    'timeout'       => "timeout",   # to terminate shell processes (timeout 1)
    'openssl'       => "openssl",   # OpenSSL
    'openssl3'      => "openssl",   # OpenSSL which supports TLSv1.3
    'libs'          => [],      # where to find libssl.so and libcrypto.so
    'path'          => [],      # where to find openssl executable
    'extopenssl'    => 1,       # 1: use external openssl; default yes, except on Win32
    'extsclient'    => 1,       # 1: use openssl s_client; default yes, except on Win32
    'extciphers'    => 0,       # 1: use openssl s_client -cipher for connection check
    'envlibvar'     => "LD_LIBRARY_PATH",       # name of environment variable
    'envlibvar3'    => "LD_LIBRARY_PATH",       # for OpenSSL which supports TLSv1.3
    'call'          => [],      # list of special (internal) function calls
                                # see --call=METHOD option in description below
);

#| construct list for special commands: 'cmd-*'
#| -------------------------------------
# SEE Note:Testing, sort
my $old   = "";
my $regex = join("|", @{$cfg{'versions'}}); # these are data only, not commands
foreach my $key (sort {uc($a) cmp uc($b)} keys %data, keys %checks, @{$cfg{'commands_int'}}) {
    next if ($key eq $old);     # unique
    $old  = $key;
    push(@{$cfg{'commands'}},  $key) if ($key !~ m/^(?:$regex)/);
    push(@{$cfg{'cmd-hsts'}},  $key) if ($key =~ m/$cfg{'regex'}->{'cmd-hsts'}/i);
    push(@{$cfg{'cmd-http'}},  $key) if ($key =~ m/$cfg{'regex'}->{'cmd-http'}/i);
    push(@{$cfg{'cmd-sizes'}}, $key) if ($key =~ m/$cfg{'regex'}->{'cmd-sizes'}/);
    push(@{$cfg{'need-checkhttp'}}, $key) if ($key =~ m/$cfg{'regex'}->{'cmd-hsts'}/);
    push(@{$cfg{'need-checkhttp'}}, $key) if ($key =~ m/$cfg{'regex'}->{'cmd-http'}/);
}

push(@{$cfg{'cmd-check'}}, $_) foreach (keys %checks);
push(@{$cfg{'cmd-info--v'}}, 'dump');   # more information
foreach my $key (keys %data) {
    push(@{$cfg{'cmd-info--v'}}, $key);
    next if (_is_cfg_intern($key));     # ignore aliases
    next if ($key =~ m/^(ciphers)/   and $verbose == 0);# Client ciphers are less important
    next if ($key =~ m/^modulus$/    and $verbose == 0);# same values as 'pubkey_value'
    push(@{$cfg{'cmd-info'}},    $key);
}
push(@{$cfg{'cmd-info--v'}}, 'info--v');

# SEE Note:Testing, sort
foreach my $key (qw(commands commands_cmd commands_usr commands_int cmd-info--v)) {
    # TODO: need to test if sorting of cmd-info--v should not be done for --no-rc
    @{$cfg{$key}} = sort(@{$cfg{$key}});    # only internal use
}
if (0 < _is_argv('(?:--no.?rc)')) {
    foreach my $key (qw(do cmd-check cmd-info cmd-quick cmd-vulns)) {
        @{$cfg{$key}} = sort(@{$cfg{$key}});# may be redefined
    }
}

_yeast_TIME("cfg}");

# following defined in OSaft/Ciphers.pm
#   %ciphers_desc();
#   %ciphers();
#   %ciphers_notes();
#   %cipher_results();

our %text = (
    'separator'     => ":",# separator character between label and value
    # texts may be redefined
    'undef'         => "<<undefined>>",
    'response'      => "<<response>>",
    'protocol'      => "<<protocol probably supported, but no ciphers accepted>>",
    'need_cipher'   => "<<check possible in conjunction with +cipher only>>",
    'na'            => "<<N/A>>",
    'na_STS'        => "<<N/A as STS not set>>",
    'na_sni'        => "<<N/A as --no-sni in use>>",
    'na_dns'        => "<<N/A as --no-dns in use>>",
    'na_cert'       => "<<N/A as --no-cert in use>>",
    'na_http'       => "<<N/A as --no-http in use>>",
    'na_tlsextdebug'=> "<<N/A as --no-tlsextdebug in use>>",
    'na_nextprotoneg'=>"<<N/A as --no-nextprotoneg in use>>",
    'na_reconnect'  => "<<N/A as --no_reconnect in use>>",
    'na_openssl'    => "<<N/A as --no-openssl in use>>",
    'disabled'      => "<<N/A as @@ in use>>",     # @@ is --no-SSLv2 or --no-SSLv3
    'disabled_protocol' => "<<N/A as protocol disabled or NOT YET implemented>>",     # @@ is --no-SSLv2 or --no-SSLv3
    'disabled_test' => "tests with/for @@ disabled",  # not yet used
    'miss_cipher'   => "<<N/A as no ciphers found>>",
    'miss_protocol' => "<<N/A as no protocol found>>",
    'miss_RSA'      => " <<missing ECDHE-RSA-* cipher>>",
    'miss_ECDSA'    => " <<missing ECDHE-ECDSA-* cipher>>",
    'missing'       => " <<missing @@>>",
    'enabled_extension' => " <<@@ extension enabled>>",
    'unexpected'    => " <<unexpected @@>>",
    'insecure'      => " <<insecure @@>>",
    'invalid'       => " <<invalid @@>>",
    'bit256'        => " <<keysize @@ < 256>>",
    'bit512'        => " <<keysize @@ < 512>>",
    'bit2048'       => " <<keysize @@ < 2048>>",
    'bit4096'       => " <<keysize @@ < 4096>>",
    'EV_large'      => " <<too large @@>>",
    'EV_subject_CN' => " <<missmatch: subject CN= and commonName>>",
    'EV_subject_host'=>" <<missmatch: subject CN= and given hostname>>",
    'no_reneg'      => " <<secure renegotiation not supported>>",
    'cert_dates'    => " <<invalid certificate date>>",
    'cert_valid'    => " <<certificate validity to large @@>>",
    'cert_chars'    => " <<invalid charcters in @@>>",
    'wildcards'     => " <<uses wildcards:@@>>",
    'gethost'       => " <<gethostbyaddr() failed>>",
    'out_target'    => "\n==== Target: @@ ====\n",
    'out_ciphers'   => "\n=== Ciphers: Checking @@ ===",
    'out_infos'     => "\n=== Information ===",
    'out_scoring'   => "\n=== Scoring Results EXPERIMENTAL ===",
    'out_checks'    => "\n=== Performed Checks ===",
    'out_list'      => "=== List @@ Ciphers ===",
    'out_summary'   => "=== Ciphers: Summary @@ ===",
    # hostname texts
    'host_name'     => "Given hostname",
    'host_IP'       => "IP for given hostname",
    'host_rhost'    => "Reverse resolved hostname",
    'host_DNS'      => "DNS entries for given hostname",
    # misc texts
    'cipher'        => "Cipher",
    'support'       => "supported",
    'security'      => "Security",
    'dh_param'      => "DH Parameters",
    'desc'          => "Description",
    'desc_check'    => "Check Result (yes is considered good)",
    'desc_info'     => "Value",
    'desc_score'    => "Score (max value 100)",
    'anon_text'     => "<<anonymised>>",    # SEE Note:anon-out

    # texts used for legacy mode; DO NOT CHANGE!
    'legacy' => {      #----------------+------------------------+---------------------
        #header     => # not implemented  supported               unsupported
        #              #----------------+------------------------+---------------------
        'compact'   => { 'not' => '-',   'yes' => "yes",         'no' => "no" },
        'simple'    => { 'not' => '-?-', 'yes' => "yes",         'no' => "no" },
        'full'      => { 'not' => '-?-', 'yes' => "Yes",         'no' => "No" },
        'key'       => { 'not' => '-?-', 'yes' => "yes",         'no' => "no" },
        'owasp'     => { 'not' => '-?-', 'yes' => "",            'no' => ""   },
        #              #----------------+------------------------+---------------------
        # following keys are roughly the names of the tool they are used
        #              #----------------+------------------------+---------------------
        'sslaudit'  => { 'not' => '-?-', 'yes' => "successfull", 'no' => "unsuccessfull" },
        'sslcipher' => { 'not' => '-?-', 'yes' => "ENABLED",     'no' => "DISABLED"  },
        'ssldiagnos'=> { 'not' => '-?-', 'yes' => "CONNECT_OK CERT_OK", 'no' => "FAILED" },
        'sslscan'   => { 'not' => '-?-', 'yes' => "Accepted",    'no' => "Rejected"  },
        'ssltest'   => { 'not' => '-?-', 'yes' => "Enabled",     'no' => "Disabled"  },
        'ssltest-g' => { 'not' => '-?-', 'yes' => "Enabled",     'no' => "Disabled"  },
        'sslyze'    => { 'not' => '-?-', 'yes' => "%s",          'no' => "SSL Alert" },
        'testsslserver'=>{'not'=> '-?-', 'yes' => "",            'no' => ""          },
        'thcsslcheck'=>{ 'not' => '-?-', 'yes' => "supported",   'no' => "unsupported"   },
        #              #----------------+------------------------+---------------------
        #                -?- means "not implemented"
        # all other text used in headers titles, etc. are defined in the
        # corresponding print functions:
        #     print_title, print_cipherhead, print_footer, print_cipherpreferred, print_ciphertotals
        # NOTE: all other legacy texts are hardcoded, as there is no need to change them!
    },

    # SEE Note:hints
    'hints' => {       # define hints here only if not feasable in osaft.pm
                       # will be added to $cfg{hints} in _init_all()
    },

    'mnemonic'      => { # NOT YET USED
        'example'   => "TLS_DHE_DSS_WITH_3DES-EDE-CBC_SHA",
        'description'=> "TLS Version _ key establishment algorithm _ digital signature algorithm _ WITH _ confidentility algorithm _ hash function",
        'explain'   => "TLS Version1 _ Ephemeral DH key agreement _ DSS which implies DSA _ WITH _ 3DES encryption in CBC mode _ SHA for HMAC"
    },

    # just for information, some configuration options in Firefox
    'firefox' => { # NOT YET USED
        'browser.cache.disk_cache_ssl'        => "En-/Disable caching of SSL pages",        # false
        'security.enable_tls_session_tickets' => "En-/Disable Session Ticket extension",    # false
        'security.ssl.allow_unrestricted_renego_everywhere__temporarily_available_pref' =>"",# false
        'security.ssl.renego_unrestricted_hosts' => '??',   # list of hosts
        'security.ssl.require_safe_negotiation'  => "",     # true
        'security.ssl.treat_unsafe_negotiation_as_broken' => "", # true
        'security.ssl.warn_missing_rfc5746'      => "",     # true
        'pfs.datasource.url' => '??', #
        'browser.identity.ssl_domain_display'    => "coloured non EV-SSL Certificates", # true
        },
    'IE' => { # NOT YET USED
        'HKLM\\...' => "sequence of ciphers",   #
        },

    # for more information about definitions and RFC, see o-saft-man.pm

); # %text

$cmd{'extopenssl'}  = 0 if ($^O =~ m/MSWin32/); # tooooo slow on Windows
$cmd{'extsclient'}  = 0 if ($^O =~ m/MSWin32/); # tooooo slow on Windows
$cfg{'done'}->{'rc_file'}++ if ($#rc_argv > 0);

#| incorporate some environment variables
#| -------------------------------------
# all OPENSSL* environment variables are checked and assigned in o-saft-lib.pm
$cmd{'openssl'}     = $cfg{'openssl_env'} if (defined $cfg{'openssl_env'});
if (defined $ENV{'LIBPATH'}) {
    _hint("LIBPATH environment variable found, consider using '--envlibvar=LIBPATH'");
    # TODO: avoid hint if --envlibvar=LIBPATH in use
    # $cmd{'envlibvar'} = $ENV{'LIBPATH'}; # don't set silently
}

#_init_all();  # call delayed to prevent warning of prototype check with -w

_yeast_EXIT("exit=INIT1 - initialisation end");
usr_pre_file();

#| definitions: functions to "convert" values
#| -------------------------------------
sub __subst($$)     { my ($is,$txt)=@_; $is=~s/@@/$txt/; return $is; }
    # return given text with '@@' replaced by given value
sub _get_text($$)   { my ($is,$txt)=@_; return __subst($text{$is}, $txt); }
    # for given index of %text return text with '@@' replaced by given value
sub _get_yes_no     { my $val=shift; return ($val eq "") ? 'yes' : 'no (' . $val . ')'; }
    # return 'yes' if given value is empty, return 'no' otherwise

sub _get_base2      {
    # return base-2 of given number
    my $value = shift;
       $value = 1 if ($value !~ /^[0-9]+$/);# defensive programming: quick&dirty check
       return 0   if ($value == 0);         # -''-
       $value = log($value);
    # base-2 = log($value) / log(2)
    # unfortunately this calculation results in  "inf"  for big values
    # to avoid using Math::BigInt for big values, the calculation is done as
    # follows (approximately):
    #   log(2)   = 0.693147180559945;
    #   1/log(2) = 1.44269504088896;
    #   v * 1.44 = v + (v / 100 * 44);
    return ($value + ($value/100*44));
} # _get_base2

sub _hex_like_openssl   {
    # return full hex constant formatted as used by openssl's output
    my $c = shift;
    $c =~ s/0x(..)(..)(..)(..)/0x$2,0x$3,0x$4 - /; # 0x0300C029 ==> 0x00,0xC0,0x29
    $c =~ s/^0x00,// if ($c ne "0x00,0x00,0x00");  # first byte omitted if 0x00
    return sprintf("%22s", $c);
} # _hex_like_openssl

#| definitions: %cfg functions
#| -------------------------------------
sub __need_this($)      {
    # returns >0 if any of the given commands is listed in $cfg{'$_'}
    my $key = shift;
    my $is  = join("|", @{$cfg{'do'}});
       $is  =~ s/\+/\\+/g;      # we have commands with +, needs to be escaped
    return grep{/^($is)$/} @{$cfg{$key}};
} # __need_this
#sub _need_openssl()     { return __need_this('need-openssl');   }
sub _need_cipher()      { return __need_this('need-cipher');    }
sub _need_default()     { return __need_this('need-default');   }
sub _need_checkssl()    { return __need_this('need-checkssl');  }
sub _need_checkalpn()   { return __need_this('need-checkalpn'); }
sub _need_checkbleed()  { return __need_this('need-checkbleed');}
sub _need_checkchr()    { return __need_this('need-checkchr');  }
sub _need_checkdest()   { return __need_this('need-checkdest'); }
sub _need_check_dh()    { return __need_this('need-check_dh');  }
sub _need_checkhttp()   { return __need_this('need-checkhttp'); }
sub _need_checkprot()   { return __need_this('need-checkprot'); }
    # returns >0 if any  of the given commands is listed in $cfg{need-*}
sub _is_hashkey($$)     { my ($is,$ref)=@_; return grep({lc($is) eq lc($_)} keys %{$ref}); }
sub _is_member($$)      { my ($is,$ref)=@_; return grep({lc($is) eq lc($_)}      @{$ref}); }
    # returns list of matching entries in specified array @cfg{*}
sub _is_cfg_do($)       { my  $is=shift;    return _is_member($is, \@{$cfg{'do'}});        }
sub _is_cfg_intern($)   { my  $is=shift;    return _is_member($is, \@{$cfg{'commands_int'}}); }
sub _is_cfg_hexdata($)  { my  $is=shift;    return _is_member($is, \@{$cfg{'data_hex'}});  }
sub _is_cfg_call($)     { my  $is=shift;    return _is_member($is, \@{$cmd{'call'}});      }
    # returns >0 if the given string is listed in $cfg{*}
sub _is_cfg($)          { my  $is=shift;    return $cfg{$is};   }
sub _is_cfg_ssl($)      { my  $is=shift;    return $cfg{$is};   }
    # returns >0 if specified key (protocol like SSLv3) is set $cfg{*}
sub _is_cfg_out($)      { my  $is=shift;    return $cfg{'out'}->{$is};  }
sub _is_cfg_tty($)      { my  $is=shift;    return $cfg{'tty'}->{$is};  }
sub _is_cfg_use($)      { my  $is=shift;    return $cfg{'use'}->{$is};  }
    # returns value for given key in $cfg{*}->{key}; which is 0 or 1 (usually)
sub _is_cfg_verbose()   { return $cfg{'verbose'}; }

sub _set_cfg_out($$)    { my ($is,$val)=@_; $cfg{'out'}->{$is} = $val; return; }
sub _set_cfg_tty($$)    { my ($is,$val)=@_; $cfg{'tty'}->{$is} = $val; return; }
sub _set_cfg_use($$)    { my ($is,$val)=@_; $cfg{'use'}->{$is} = $val; return; }
    # set value for given key in $cfg{*}->{key}

#| definitions: internal wrapper functions for OSaft/Ciphers.pm
#| -------------------------------------
# following wrappers are called with cipher suite name, while OSaft::Ciphers
# methods need to be called with cipher hex key
sub _cipher_get_bits    { return OSaft::Ciphers::get_bits(  OSaft::Ciphers::get_key(shift)); }
sub _cipher_get_sec     { return OSaft::Ciphers::get_sec(   OSaft::Ciphers::get_key(shift)); }
sub _cipher_set_sec     {
    # set cipher's security value in %ciphers; can be called with key or name
    # parameter looks like: 0x030000BA=sec or CAMELLIA128-SHA=sec
    my ($typ, $arg) = @_;
    my ($key, $val) = split(/=/, $arg, 2);  # left of first = is key
        $key = OSaft::Ciphers::get_key($key) if ($key !~ m/^0x[0-9a-fA-F]{8}$/);
                # if is is not a key, try to get the key from a cipher name
    return if not $key; # warning already printed
    OSaft::Ciphers::set_sec($key, $val);
    return;
} # _cipher_set_sec

#| definitions: internal functions
#| -------------------------------------
sub _eval_cipherranges  {
    #? return array of cipher suite hex key, securely evaluated from given range
    # invalid; avoid injection attempts
    my $key = shift;
    return [] if $cfg{'cipherranges'}->{$key} !~ m/^[x0-9A-Fa-f,.\s]+$/; # see osaft.pm
    return (eval($cfg{'cipherranges'}->{$key})); ## no critic qw(BuiltinFunctions::ProhibitStringyEval)
} # _eval_cipherranges

sub __is_number         {
    # return 1 if given parameter is a number; return 0 otherwise
    my $val = shift;
    return 0 if not defined $val;
    return 0 if $val eq '';
    return ($val ^ $val) ? 0 : 1
} # __is_number

use IO::Socket::INET;
sub _load_modules       {
    # load required modules
    # SEE Perl:import include
    my $_err = "";
    if (1 > 0) { # TODO: experimental code
        $_err = _load_file("IO/Socket/SSL.pm", "IO SSL module");
        warn $STR{ERROR}, "005: $_err" if ("" ne $_err);
        # cannot load IO::Socket::INET delayed because we use AF_INET,
        # otherwise we get at startup:
        #    Bareword "AF_INET" not allowed while "strict subs" in use ...
        #$_err = _load_file("IO/Socket/INET.pm", "IO INET module");
        #warn $STR{ERROR}, "006: $_err" if ("" ne $_err);
    }
    if (0 < $cfg{'need_netdns'}) {
        $_err = _load_file("Net/DNS.pm", "Net module'");
        if ("" ne $_err) {
            warn $STR{ERROR}, "007: $_err";
            _warn("111: option '--mx disabled");
            $cfg{'use'}->{'mx'} = 0;
        }
    }
    if (0 < $cfg{'need_timelocal'}) {
        $_err = _load_file("Time/Local.pm", "Time module");
        if ("" ne $_err) {
            warn $STR{ERROR}, "008: $_err";
            _warn("112: value for '+sts_expired' not applicable");
            # TODO: need to remove +sts_expired from cfg{do}
        }
    }
    $_err = _load_file("Encode.pm", "Encode module");  # must be found with @INC
    if ("" ne $_err) {
        warn $STR{ERROR}, "008: $_err";
    }

    return if (0 < $::osaft_standalone);  # SEE Note:Stand-alone

    $_err = _load_file("Net/SSLhello.pm", "O-Saft module");  # must be found with @INC
    if ("" ne $_err) {
        die  $STR{ERROR}, "010: $_err"  if (not _is_cfg_do('version'));
        warn $STR{ERROR}, "010: $_err"; # no reason to die for +version
    }
    if ($cfg{'starttls'}) {
        $cfg{'use'}->{'http'} = 0;      # makes no sense for starttls
        # TODO: not (yet) supported for proxy
    }
    return if (1 > $cfg{'need_netinfo'});
    $_err = _load_file("Net/SSLinfo.pm", "O-Saft module");# must be found
    if ("" ne $_err) {
        die  $STR{ERROR}, "011: $_err"  if (not _is_cfg_do('version'));
        warn $STR{ERROR}, "011: $_err"; # no reason to die for +version
    }
    return;
} # _load_modules

sub _check_modules      {
    # check for minimal version of a module;
    # verbose output with --v=2 ; uses string "yes" for contrib/bunt.*
    # these checks print warnings with warn() not _warn(), SEE Perl:warn
    # SEE Perl:import include
    _y_CMD("  check module versions ...");
    my %expected_versions = (
        'IO::Socket::INET'  => "1.31",
        'IO::Socket::SSL'   => "1.37",
        'Net::SSLeay'       => "1.49",  # 1.46 may also work
        'Net::DNS'          => "0.65",
        'Time::Local'       => "1.23",
        # to simulate various error conditions, simply modify the module name
        # and/or its expected version in above table;  these values are never
        # used elsewhere
    );
    # Comparing version numbers is tricky, 'cause they are no natural numbers
    # Consider for example 1.8 and 1.11 : where the numerical comapre returns
    #   "1.8 > 1.11".
    # Perl has the version module for this, but it's available for Perl > 5.9
    # only. For older Perl, we warn that version checks may not be accurate.
    # Please see "perldoc version" about the logic and syntax.
    my $have_version = 1;
    eval {require version; } or $have_version = 0;
        # $version::VERSION  may have one of 3 values now:
        #   undef   - version module was not available or didn't define VERSION
        #   string  - even "0.42" cannot be compared to integer, bad luck ...
        #   integer - that's the usual and expected value
    if (__is_number($version::VERSION)) {
        $have_version = 0 if ($version::VERSION < 0.77);
            # veriosn module too old, use natural number compare
    } else {
        $have_version = 0;
        $version::VERSION = ""; # defensive programming ..
    }
    if ($have_version == 0) {
        warn $STR{WARN}, "120: ancient perl has no 'version' module; version checks may not be accurate;";
    }
    if ($cfg{verbose} > 1) {
        printf "# %s+%s+%s\n", "-"x21, "-"x7, "-"x15;
        printf "# %-21s\t%s\t%s\n", "module name", "VERSION", "> expected versions";
        printf "# %s+%s+%s\n", "-"x21, "-"x7, "-"x15;
    }
    foreach my $mod (keys %expected_versions) {
        next if (($cfg{'need_netdns'}    == 0) and ($mod eq "Net::DNS"));# don't complain if not used
        next if (($cfg{'need_timelocal'} == 0) and ($mod eq "Time::Local"));# -"-
        no strict 'refs'; ## no critic qw(TestingAndDebugging::ProhibitNoStrict TestingAndDebugging::ProhibitProlongedStrictureOverride)
            # avoid: Can't use string ("Net::DNS::VERSION") as a SCALAR ref while "strict refs" in use
        my $expect = $expected_versions{$mod};
        my $v  = $mod . "::VERSION";
        my $ok = "yes";
        # following eval is safe, as left side value cannot be injected
        eval {$v = $$v;} or $v = 0;     # module was not loaded or has no VERSION
        if ($have_version == 1) {       # accurate checks with version module
            # convert natural numbers to version objects
            $v      = version->parse("v$v");
            $expect = version->parse("v$expect");
        }
        if ($v < $expect) {
            $ok = "no";
            $ok = "missing" if ($v == 0);
            warn $STR{WARN}, "121: ancient $mod $v < $expect detected;";
            # TODO: not sexy: warnings are inside tabular data for --v
        }
        if ($cfg{verbose} > 1) {
            printf "# %-21s\t%s\t> %s\t%s\n", $mod, $v, $expect, $ok;
        }
    }
    # TODO: OCSP and OCSP stapling works since  Net::SSLeay 1.78 , we should
    #       use  Net::SSLeay 1.83  because of some bug fixes there, see:
    #       https://metacpan.org/changes/distribution/Net-SSLeay
    printf "# %s+%s+%s\n", "-"x21, "-"x7, "-"x15 if ($cfg{verbose} > 1);
    return;
} # _check_modules

sub _enable_functions   {
    # enable internal functionality based on available functionality of modules
    # these checks print warnings with warn() not _warn(), SEE Perl:warn
    # verbose messages with --v --v
    # NOTE: don't bother users with warnings, if functionality is not required
    #       hence some additional checks around the warnings
    # NOTE: instead of requiring a specific version with Perl's use,  only the
    #       version of the loaded module is checked; this allows to go on with
    #       this tool even if the version is too old; but  shout out  loud
    my $version_openssl  = shift;
    my $version_ssleay   = shift;
    my $version_iosocket = shift;
    my $txo = sprintf("ancient version openssl 0x%x", $version_openssl);
    my $txs = "ancient version Net::SSLeay $version_ssleay";
    my $txt = "improper Net::SSLeay version;";

    _y_CMD("  enable internal functionality ...");

    if ($cfg{'ssleay'}->{'openssl'} == 0) {
        warn $STR{WARN}, "122: ancient Net::SSLeay $version_ssleay cannot detect openssl version";
    }
    if ($cfg{'ssleay'}->{'iosocket'} == 0) {
        warn $STR{WARN}, "123: ancient or unknown version of IO::Socket detected";
    }

    if ($cfg{'ssleay'}->{'can_sni'} == 0) {
        if((_is_cfg_use('sni')) and ($cmd{'extciphers'} == 0)) {
            $cfg{'use'}->{'sni'} = 0;
            my $txt_buggysni = "does not support SNI or is known to be buggy; SNI disabled;";
            if ($version_iosocket < 1.90) {
                warn $STR{WARN}, "124: ancient version IO::Socket::SSL $version_iosocket < 1.90; $txt_buggysni";
            }
            if ($version_openssl  < 0x01000000) {
                warn $STR{WARN}, "125: $txo < 1.0.0; $txt_buggysni";
            }
            _hint("use '--force-openssl' to disable this check");
        }
    }
    _trace("cfg{use}->{sni} = $cfg{'use'}->{'sni'}");

    if (($cfg{'ssleay'}->{'set_alpn'} == 0) or ($cfg{'ssleay'}->{'get_alpn'} == 0)) {
        # warnings only if ALPN functionality required
        # TODO: is this check necessary if ($cmd{'extciphers'} > 0)?
        if (_is_cfg_use('alpn')) {
            $cfg{'use'}->{'alpn'} = 0;
            warn $STR{WARN}, "126: $txt tests with/for ALPN disabled";
            if ($version_ssleay   < 1.56) {  # is also < 1.46
                warn $STR{WARN}, "127: $txs < 1.56"  if ($cfg{'verbose'} > 1);
            }
            if ($version_openssl  < 0x10002000) {
                warn $STR{WARN}, "128: $txo < 1.0.2" if ($cfg{'verbose'} > 1);
            }
            _hint("use '--no-alpn' to disable this check");
        }
    }
    _trace("cfg{use}->{alpn}= $cfg{'use'}->{'alpn'}");

    if ($cfg{'ssleay'}->{'set_npn'} == 0) {
        # warnings only if NPN functionality required
        if (_is_cfg_use('npn')) {
            $cfg{'use'}->{'npn'}  = 0;
            warn $STR{WARN}, "129: $txt tests with/for NPN disabled";
            if ($version_ssleay   < 1.46) {
                warn $STR{WARN}, "130: $txs < 1.46"  if ($cfg{'verbose'} > 1);
            }
            if ($version_openssl  < 0x10001000) {
                warn $STR{WARN}, "132: $txo < 1.0.1" if ($cfg{'verbose'} > 1);
            }
            _hint("use '--no-npn' to disable this check");
        }
    }
    _trace("cfg{use}->{npn} = $cfg{'use'}->{'npn'}");

    if ($cfg{'ssleay'}->{'can_ocsp'} == 0) {    # Net::SSLeay < 1.59  and  openssl 1.0.0
        warn $STR{WARN}, "133: $txt tests for OCSP disabled";
        #_hint("use '--no-ocsp' to disable this check");
    }

    if ($cfg{'ssleay'}->{'can_ecdh'} == 0) {    # Net::SSLeay < 1.56
        warn $STR{WARN}, "134: $txt setting curves disabled";
        #_hint("use '--no-cipher-ecdh' to disable this check");
    }
    return;
} # _enable_functions

sub _check_functions    {
    # check for required functionality
    # these checks print warnings with warn() not _warn(), SEE Perl:warn
    # verbose messages with --v=2 ; uses string "yes" for contrib/bunt.*

    my $txt = "";
    my $tmp = "";
    my $version_openssl  =  0; # use 0 to avoid 0xffffffffffffffff in warnings
    my $version_ssleay   = -1; # -1 should be always lower than anything else
    my $version_iosocket = -1; # -"-
    my $text_ssleay      = "Net::SSLeay\t$version_ssleay supports";

    # NOTE: $cfg{'ssleay'}->{'can_sni'} set to 1 by default

    _y_CMD("  check required modules ...");
    if (not defined $Net::SSLeay::VERSION) {# Net::SSLeay auto-loaded by IO::Socket::SSL
        if ($cmd{'extopenssl'} == 0) {
            die $STR{ERROR}, "014: Net::SSLeay not found, useless use of SSL advanced forensic tool";
        }
    } else {
        $version_ssleay   = $Net::SSLeay::VERSION;
        $text_ssleay      = "Net::SSLeay\t$version_ssleay supports";
    }
    if (not exists &Net::SSLeay::OPENSSL_VERSION_NUMBER) {
        $cfg{'ssleay'}->{'openssl'} = 0;
    } else {
        $version_openssl  = Net::SSLeay::OPENSSL_VERSION_NUMBER();
    }
    if (not defined $IO::Socket::SSL::VERSION) {
        $cfg{'ssleay'}->{'iosocket'} = 0;
    } else {
        $version_iosocket = $IO::Socket::SSL::VERSION;
    }

    # some functionality is available in  Net::SSLeay  and  IO::Socket::SSL,
    # newer versions of  IO::Socket::SSL  even provides variables for it
    # ancient versions of the modules,  which do not have these functions or
    # variables, should be supported
    # that's why the checks are done here and stored in $cfg{'ssleay'}->*

    _y_CMD("  check for proper SNI support ...");
    # TODO: change to check with: defined &Net::SSLeay::get_servername
    if ($version_iosocket < 1.90) {
        $cfg{'ssleay'}->{'can_sni'} = 0;
    } else {
        _v2print "IO::Socket::SSL\t$version_iosocket OK\tyes";
    }
    if ($version_openssl < 0x01000000) {
        # same as  IO::Socket::SSL->can_client_sni()
        # see section "SNI Support" in: perldoc IO/Socket/SSL.pm
        $cfg{'ssleay'}->{'can_sni'} = 0;
    } else {
        _v2print "$text_ssleay OpenSSL version\tyes";
    }

    _y_CMD("  check if Net::SSLeay is usable ...");
    if ($version_ssleay  < 1.49) {
        warn $STR{WARN}, "135: Net::SSLeay $version_ssleay < 1.49; may throw warnings and/or results may be missing;";
    } else {
        _v2print "$text_ssleay (OK)\tyes";
    }

    _y_CMD("  check for NPN and ALPN support ..."); # SEE Note:OpenSSL Version
    if (($version_ssleay < 1.56) or ($version_openssl < 0x10002000)) {
        $cfg{'ssleay'}->{'set_alpn'} = 0;
        $cfg{'ssleay'}->{'get_alpn'} = 0;
    } else {
        _v2print "$text_ssleay ALPN\tyes";
    }
    if (($version_ssleay < 1.46) or ($version_openssl < 0x10001000)) {
        $cfg{'ssleay'}->{'set_npn'}  = 0;
    } else {
        _v2print "$text_ssleay  NPN\tyes";
    }

    if (not exists &Net::SSLeay::CTX_set_alpn_protos) {
        $cfg{'ssleay'}->{'set_alpn'} = 0;
    } else {
        _v2print "$text_ssleay set ALPN\tyes";
    }

    if (not exists &Net::SSLeay::P_alpn_selected) {
        $cfg{'ssleay'}->{'get_alpn'} = 0;
    } else {
        _v2print "$text_ssleay get ALPN\tyes";
    }

    if (not exists &Net::SSLeay::CTX_set_next_proto_select_cb) {
        $cfg{'ssleay'}->{'set_npn'} = 0;
    } else {
        _v2print "$text_ssleay set  NPN\tyes";
    }

    if (not exists &Net::SSLeay::P_next_proto_negotiated) {
        $cfg{'ssleay'}->{'get_npn'}  = 0;
    } else {
        _v2print "$text_ssleay get  NPN\tyes";
    }

    if (not exists &Net::SSLeay::OCSP_cert2ids) {
        # same as IO::Socket::SSL::can_ocsp() IO::Socket::SSL::can_ocsp_staple()
        $cfg{'ssleay'}->{'can_ocsp'}  = 0;
    } else {
        _v2print "$text_ssleay OSCP\tyes";
    }

    if (not exists &Net::SSLeay::CTX_set_tmp_ecdh) {
        # same as IO::Socket::SSL::can_ecdh()
        $cfg{'ssleay'}->{'can_ecdh'}  = 0;
    } else {
        _v2print "$text_ssleay Curves\tyes";
    }

    $cfg{'ssleay'}->{'can_npn'}  = $cfg{'ssleay'}->{'get_npn'}; # alias
    _enable_functions($version_openssl, $version_ssleay, $version_iosocket);
    return;
} # _check_functions

sub _check_ssl_methods  {
   # check for supported SSL version methods and add them to $cfg{'version'}
   # TODO: anything related to ciphermode=intern can be removed when Net::SSLhello
   #       supports DTLSv1
    my $typ;
    my @list;
    _y_CMD("  check supported SSL versions ...");
    if (_is_cfg_do('cipher_openssl') or _is_cfg_do('cipher_ssleay')) {
        @list = Net::SSLinfo::ssleay_methods();
        # method names do not literally match our version string, hence the
        # cumbersome code below
    }
    _trace("SSLeay methods  = " . join(" ", @list));
    foreach my $ssl (@{$cfg{'versions'}}) {
        next if ($cfg{$ssl} == 0);          # don't check what's disabled by option
        if (_is_cfg_do('cipher_intern') or _is_cfg_do('cipher_dump')) {
            # internal method does not depend on other libraries, but DTLS* not yet supported
            if ($ssl =~ m/^DTLS/) {
                _warn("140: SSL version '$ssl': not supported by '$cfg{'me'} +cipher'; not checked");
                next;
            }
            push(@{$cfg{'version'}}, $ssl);
            next;
        }
        # following checks for these commands only
        $cfg{$ssl} = 0; # reset to simplify further checks
        if ($ssl !~ /$cfg{'regex'}->{'SSLprot'}/) {
            _warn("141: SSL version '$ssl': not supported; not checked");
            next;
        }
        # Net::SSLeay  only supports methods for those SSL protocols which were
        # available at the time of compiling  Net::SSLeay. The support of these
        # protocols is not checked dynamically when building Net::SSLeay.
        # Net::SSLeay's config script simply relies on the definitions found in
        # the specified include files of the underlaying  SSL library (which is
        # openssl usually).
        # Unfortunately,  there are situations where the assumptions at compile
        # time do not match the conditions at runtime. Then  Net::SSLeay  bails
        # out with an error like:
        #   Can't locate auto/Net/SSLeay/CTX_v2_new.al in @INC ...
        # which means that  Net::SSLeay  was build without support for SSLv2.
        # To avoid bothering users with such messages (see above), or even more
        # errors or program aborts, we check for the availability of all needed
        # methods.  Sometimes, for whatever reason,  the user may know that the
        # warning can be avoided.  Therfore the  --ssl-lazy option can be used,
        # which simply disables the check.
        if (_is_cfg_use('ssl_lazy')) {
            push(@{$cfg{'version'}}, $ssl);
            $cfg{$ssl} = 1;
            next;
        }
        next if (not _is_cfg_do('cipher'));
        # Check for high-level API functions, like SSLv2_method, also possible
        # would be    Net::SSLeay::CTX_v2_new,  Net::SSLeay::CTX_tlsv1_2_new
        # and similar calls.
        # Net::SSLeay::SSLv23_method is missing in some  Net::SSLeay versions,
        # as we don't use it, there is no need to check for it.
        # TODO: DTLSv9 which is DTLS 0.9 ; but is this really in use?
        $typ = 0;
        $typ++ if (($ssl eq 'SSLv2')   and (grep{/^SSLv2_method$/}    @list));
        $typ++ if (($ssl eq 'SSLv3')   and (grep{/^SSLv3_method$/}    @list));
        $typ++ if (($ssl eq 'TLSv1')   and (grep{/^TLSv1_method$/}    @list));
        $typ++ if (($ssl eq 'TLSv11')  and (grep{/^TLSv1_1_method$/}  @list));
        $typ++ if (($ssl eq 'TLSv12')  and (grep{/^TLSv1_2_method$/}  @list));
        $typ++ if (($ssl eq 'TLSv13')  and (grep{/^TLSv1_3_method$/}  @list));
        $typ++ if (($ssl eq 'DTLSv1')  and (grep{/^DTLSv1_method$/}   @list));
        $typ++ if (($ssl eq 'DTLSv11') and (grep{/^DTLSv1_1_method$/} @list));
        $typ++ if (($ssl eq 'DTLSv12') and (grep{/^DTLSv1_2_method$/} @list));
        $typ++ if (($ssl eq 'DTLSv13') and (grep{/^DTLSv1_3_method$/} @list));
        $typ++ if (($ssl eq 'SSLv2')   and (grep{/^SSLv23_method$/}   @list));
        $typ++ if (($ssl eq 'SSLv3')   and (grep{/^SSLv23_method$/}   @list));
        # TODO: not sure if SSLv23_method  also supports TLSv1, TLSv11, TLSv12
        if ($typ > 0) {
            push(@{$cfg{'version'}}, $ssl);
            $cfg{$ssl} = 1;
        } else {
            _warn("143: SSL version '$ssl': not supported by Net::SSLeay; not checked");
            _hint("consider using '--ciphermode=intern' instead") if ('intern' ne $cfg{'ciphermode'});
        }
    } # $ssl

    if (not _is_cfg_do('version')) {
        _v_print("supported SSL versions: @{$cfg{'versions'}}");
        _v_print("  checked SSL versions: @{$cfg{'version'}}");
    }
    return;
} # _check_ssl_methods

sub _enable_sclient     {
    # enable internal functionality based on available functionality of openssl s_client
    # SEE Note:OpenSSL s_client
    my $opt = shift;
    _y_CMD("  check openssl s_client cpapbility $opt ...") if ($cfg{verbose} > 0);
    my $txt = $cfg{'openssl'}->{$opt}[1] || $STR{UNDEF}; # may be undefined
    my $val = $cfg{'openssl'}->{$opt}[0];# 1 if supported
    if ($val == 0) {
        if ($opt =~ m/^-(?:alpn|npn|curves)$/) {
            # no warning for external openssl, as -alpn or -npn is only used with +cipher
            if ($cmd{'extciphers'} > 0) {
            _warn("144: 'openssl s_client' does not support '$opt'; $txt") if ($txt ne "");
            }
        } else {
            _warn("145: 'openssl s_client' does not support '$opt'; $txt") if ($txt ne "");
        }
        if ($opt eq '-tlsextdebug') {   # additional warning
            _warn("146: 'openssl -tlsextdebug' not supported; results for following commands may be wrong: +heartbeat, +heartbleed, +session_ticket, +session_lifetime");
        }
        # switch $opt {
        $cfg{'use'}->{'reconnect'}  = $val  if ($opt eq '-reconnect');
        $cfg{'use'}->{'extdebug'}   = $val  if ($opt eq '-tlsextdebug');
        $cfg{'use'}->{'alpn'}       = $val  if ($opt eq '-alpn');
        $cfg{'use'}->{'npn'}        = $val  if ($opt eq '-npn');
        $cfg{'sni'}           = $val  if ($opt eq '-servername');
        $cfg{'ca_file'}       = undef if ($opt =~ /^-CAfile/i);
        $cfg{'ca_path'}       = undef if ($opt =~ /^-CApath/i);
        # }
    }
    # TODO: remove commands, i.e. +s_client, +heartbleed, from $cmd{do}
    #    -fallback_scsv: remove +scsv and +fallback
    return;
} # _enable_sclient

sub _reset_openssl      {
    # reset all %cfg and %cmd settings according openssl executable
    $cmd{'openssl'}     = "";
    $cmd{'extopenssl'}  = 0;
    $cmd{'extsclient'}  = 0;
    $cmd{'extciphers'}  = 0;
    # TODO: Net::SSLinfo not yet included ...
    #foreach my $opt (Net::SSLinfo::s_client_get_optionlist()) {
    #    $cfg{'openssl'}->{$opt}[0] = 0;
    #}
    return;
} # _reset_openssl

sub _check_openssl      {
    # check cpapbilities of openssl
    _y_CMD("  check cpapbilities of openssl ...");
    return if ($cmd{'openssl'} eq "");  # already checked and warning printed
    $Net::SSLinfo::openssl = $cmd{'openssl'};   # this version should be checked
    $Net::SSLinfo::trace   = $cfg{'trace'};
        # save to set $Net::SSLinfo::* here,
        # will be redifined later, see: set defaults for Net::SSLinfo
    if (not defined Net::SSLinfo::s_client_check()) {
        _warn("147: '$cmd{'openssl'}' not available; all openssl functionality disabled");
        _hint("consider using '--openssl=/path/to/openssl'");
        _reset_openssl();
    }
    # NOTE: if loading Net::SSLinfo failed, then we get a Perl warning here:
    #        Undefined subroutine &Net::SSLinfo::s_client_check called at ...
    # SEE Note:OpenSSL s_client
    foreach my $opt (sort(Net::SSLinfo::s_client_get_optionlist())) {
        # SEE Note:Testing, sort
        # Perl warning  "Use of uninitialized value in ..."  here indicates
        # that cfg{openssl} is not properly initialised
        my $val = Net::SSLinfo::s_client_opt_get($opt);
           $val = 0 if ($val eq '<<openssl>>'); # TODO: <<openssl>> from Net::SSLinfo
        # _dbx "$opt $val";
        $cfg{'openssl'}->{$opt}[0] = $val;
        next if ($cfg{'openssl'}->{$opt}[1] eq "<<NOT YET USED>>");
        _enable_sclient($opt);
    }
    # TODO: checks not yet complete
    # TODO: should check openssl with a real connection
    return;
} # _check_openssl

sub _init_opensslexe    {
    # check if openssl exists, return full path
    # i.g. we may rely on bare word  openssl  which then would be found using
    # $PATH, but it's better to have a clear definition right away because it
    # avoids errors
    # $cmd{'openssl'} not passed as parameter, as it will be changed here
    my $exe     = "";
    foreach my $p ("", split(/:/, $ENV{'PATH'})) { # try to find path
        # ""  above ensures that full path in $openssl will be checked
        $exe = "$p/$cmd{'openssl'}";
        last if (-e $exe);
        $exe = "";
    }
    $exe =~ s#//#/#g;           # make a nice path (see first path "" above)
    if ($exe eq "" or $exe eq "/") {
        $exe = "";
        _warn("149: no executable for '$cmd{'openssl'}' found; all openssl functionality disabled");
        _hint("consider using '--openssl=/path/to/openssl'");
        _reset_openssl();
    }
    _v_print("_init_opensslexe: $exe");
    return $exe;
} # _init_opensslexe

sub _init_openssldir    {
    # returns openssl-specific path for CAs; checks if OPENSSLDIR/certs exists
    # resets cmd{'openssl'}, cmd{'extopenssl'} and cmd{'extsclient'} on error
    # SEE Note:OpenSSL CApath
    # $cmd{'openssl'} not passed as parameter, as it will be changed here
    return "" if ($cmd{'openssl'} eq "");       # defensive programming
    my $dir = qx($cmd{'openssl'} version -d);   # get something like: OPENSSLDIR: "/usr/local/openssl"
    chomp $dir;
        # if qx() above failed, we get: "Use of uninitialized value $dir in ..."
    my $status  = $?;
    my $error   = $!;
    my $capath  = "";
    local   $\  = "\n";
    _trace("_init_openssldir: $dir");
    if (($error ne "") && ($status != 0)) { # we ignore error messages for status==0
        # When there is a status and an error message, external call failed.
        # Print error message and disable external openssl.
        # In rare cases (i.e. VM with low memory) external call fails due to
        # malloc() problems, in this case print an additional warning.
        # NOTE: low memory affects external calls only, but not further control
        #       flow herein as Perl already managed to load the script.
        # For defensive programming  print()  is used insted of  _warn().
        print $STR{WARN}, "002: perl returned error: '$error'\n";
        if ($error =~ m/allocate memory/) {
            print $STR{WARN}, "003: using external programs disabled.\n";
            print $STR{WARN}, "003: data provided by external openssl may be shown as:  <<openssl>>\n";
        }
        _reset_openssl();
        $status = 0;  # avoid following warning below
    } else {
        # process only if no errors to avoid "Use of uninitialized value"
        # until 4/2021: path was only returned if $dir/certs exists
        # since 4/2021: path is always returned (because Android does not have certs/ :
        my $openssldir = $dir;
        $dir    =~ s#[^"]*"([^"]*)"#$1#;
        $capath =  $dir;
        unshift(@{$cfg{'ca_paths'}}, $dir); # dosn't harm
        if (-e "$dir/certs") {
            $capath = "$dir/certs";
        } else {
            _warn("148: 'openssl version -d' returned: '$openssldir' which does not contain certs/ ; ignored.");
        }
    }
    if ($status != 0) {                 # on Windoze status may be 256
        $cmd{'openssl'}    = "";
        print $STR{WARN}, "004: perl returned status: '$status' ('" . ($status>>8) . "')\n";
            # no other warning here, see "some checks are missing" later,
            # this is to avoid bothering the user with warnings, when not used
        # $capath = ""; # should still be empty
    }
    _trace("_init_openssldir: ca_paths=@{$cfg{'ca_paths'}} .");
    return $capath;
} # _init_openssldir

sub _init_openssl_ca    {
    # returns openssl-specific path containing CA file
    my $ca_path = shift;
    return $ca_path if (not defined $ca_path or $ca_path eq "");
    # search in given path
    foreach my $f (@{$cfg{'ca_files'}}) {# check if CA exists in 'ca_path'
        my $ca  = "$cfg{'ca_path'}/$f";
        return "$ca" if -e "$ca";
    }
    _warn("058: given path '$ca_path' does not contain a CA file");
    # search for a path from list, use first containing a CA
    foreach my $p (@{$cfg{'ca_paths'}}) {
        foreach my $f (@{$cfg{'ca_files'}}) {
            if (-e "$p/$f") {
                _warn("059: found PEM file for CA; using '--ca-path=$p'");
                return "$p/$f"; # ugly return from inner loop; but exactly what we want
            }
        }
    }
    return; # same as: return undef
} # _init_openssl_ca

sub _init_openssl       {
    # initialisation for openssl executable
    # TODO: Checking for openssl executable and configuration files may print
    #       **WARNINGs, even if openssl is not used at all.
    #       Unfortunately there is no simple rule "openssl needed if ...", so
    #       A userfriendly solution would be to define %cfg{need-openssl}  to
    #       contain all commands which require openssl, following settings
    #       should then check %cfg{need-openssl}.
    #       As long as there is no %cfg{need-openssl}, warnings are printed.
    # TODO: if (_is_needed_openssl()) {

    # openssl executable only requrired for +cipher with --ciphermode=openssl
    # or for advanced check commands
    $cmd{'openssl'} = _init_opensslexe();       # warnings already printed if empty

    if (not defined $cfg{'ca_path'}) {          # not passed as option, use default
        $cfg{'ca_path'} = _init_openssldir();   # warnings already printed if empty
    }

    $cfg{'ca_file'} = _init_openssl_ca($cfg{'ca_path'});
    if (not defined $cfg{'ca_file'} or $cfg{'ca_path'} eq "") {
        $cfg{'ca_file'} = "$cfg{'ca_paths'}[0]/$cfg{'ca_files'}[0]"; # use default
        _warn("060: no PEM file for CA found; using '--ca-file=$cfg{'ca_file'}'");
        _warn("     if default file does not exist, some certificate checks may fail");
        _hint("use '--ca-file=/full/path/$cfg{'ca_files'}[0]'");
    }
    _v_print("_init_openssl: ca_file=$cfg{'ca_file'}");
    return;
} # _init_openssl

sub _initchecks_score   {
    # set all default score values here
    $checks{$_}->{score} = 10 foreach (keys %checks);
    # some special values %checks{'sts_maxage*'}
    $checks{'sts_maxage0d'}->{score} =   0;     # very weak
    $checks{'sts_maxage1d'}->{score} =  10;     # weak
    $checks{'sts_maxage1m'}->{score} =  20;     # low
    $checks{'sts_maxage1y'}->{score} =  70;     # medium
    $checks{'sts_maxagexy'}->{score} = 100;     # high
    $checks{'sts_maxage18'}->{score} = 100;     # high
    foreach (keys %checks) {
        $checks{$_}->{score} = 90 if (m/WEAK/i);
        $checks{$_}->{score} = 30 if (m/LOW/i);
        $checks{$_}->{score} = 10 if (m/MEDIUM/i);
    }
    return;
} # _initchecks_score

sub _initchecks_val     {
    # set all default check values here
    my $notxt = "";
    #my $notxt = $text{'undef'}; # TODO: default should be 'undef'
    $checks{$_}->{val}   = $notxt foreach (keys %checks);
#### temporär, bis alle so gesetzt sind {
   $checks{'heartbeat'}->{val}  = $text{'undef'};
   foreach my $key (qw(krb5 psk_hint psk_identity srp session_ticket session_lifetime)) {
       $checks{$key}->{val}  = $text{'undef'};
   }
#### temporär }
    foreach my $key (keys %checks) {
        $checks{$key}->{val}    =  0 if ($key =~ m/$cfg{'regex'}->{'cmd-sizes'}/);
        $checks{$key}->{val}    =  0 if ($key =~ m/$cfg{'regex'}->{'SSLprot'}/);
    }
    # some special values %checks{'sts_maxage*'}
    $checks{'sts_maxage0d'}->{val}  =        1;
    $checks{'sts_maxage1d'}->{val}  =    86400; # day
    $checks{'sts_maxage1m'}->{val}  =  2592000; # month
    $checks{'sts_maxage1y'}->{val}  = 31536000; # year
    $checks{'sts_maxagexy'}->{val}  = 99999999;
    $checks{'sts_maxage18'}->{val}  = 10886400; # 18 weeks
    # if $data{'https_sts'}->{val}($host) is empty {
        foreach my $key (qw(sts_maxage sts_expired sts_preload sts_subdom hsts_location hsts_refresh hsts_fqdn hsts_samehost hsts_sts)) {
            $checks{$key}       ->{val} = $text{'na_STS'};
        }
        # following can not be set here, because they contain integers, see above
        #foreach my $key (qw(sts_maxage00 sts_maxagexy sts_maxage18 sts_maxage0d)) {
        #    $checks{$key}       ->{val} = $text{'na_STS'};
        #}
        #foreach my $key (qw(sts_maxage1y sts_maxage1m sts_maxage1d)) {
        #    $checks{$key}       ->{val} = $text{'na_STS'};
        #}
    # }
    foreach my $key (@{$cfg{'cmd-vulns'}}) {
        $checks{$key}           ->{val} = $text{'undef'};  # may be refined below
    }
    if (not _is_cfg_use('dns')) {
        $checks{'reversehost'}  ->{val} = $text{'na_dns'};
    }
    if (not _is_cfg_use('http')) {
        $checks{'crl_valid'}    ->{val} = _get_text('disabled', "--no-http");
        $checks{'ocsp_valid'}   ->{val} = _get_text('disabled', "--no-http");
        foreach my $key (keys %checks) {
            $checks{$key}   ->{val} = $text{'na_http'} if (_is_member($key, \@{$cfg{'cmd-http'}}));
        }
    }
    if (not _is_cfg_use('cert')) {
        $cfg{'no_cert_txt'} = $notxt if ("" eq $cfg{'no_cert_txt'});
        foreach my $key (keys %check_cert) {    # anything related to certs
            $checks{$key}   ->{val} = $text{'na_cert'} if (_is_hashkey($key, \%check_cert));
        }
        foreach my $key (qw(hostname certfqdn tr_02102+ tr_02102- tr_03116+ tr_03116- rfc_6125_names rfc_2818_names)) {
            $checks{$key}   ->{val} = $text{'na_cert'};
        }
    }
    if (not _is_cfg_ssl('SSLv2')) {
        $notxt = _get_text('disabled', "--no-SSLv2");
        $checks{'hassslv2'} ->{val} = $notxt;
        $checks{'drown'}    ->{val} = $notxt;
    }
    if (not _is_cfg_ssl('SSLv3')) {
        $notxt = _get_text('disabled', "--no-SSLv3");
        $checks{'hassslv3'} ->{val} = $notxt;
        $checks{'poodle'}   ->{val} = $notxt;
    }
        $checks{'hastls10'} ->{val} = _get_text('disabled', "--no-TLSv1")  if (1 > $cfg{'TLSv1'}) ;
        $checks{'hastls11'} ->{val} = _get_text('disabled', "--no-TLSv11") if (1 > $cfg{'TLSv11'});
        $checks{'hastls12'} ->{val} = _get_text('disabled', "--no-TLSv12") if (1 > $cfg{'TLSv12'});
        $checks{'hastls13'} ->{val} = _get_text('disabled', "--no-TLSv13") if (1 > $cfg{'TLSv13'});
        $checks{'hasalpn'}  ->{val} = _get_text('disabled', "--no-alpn")   if (not _is_cfg_use('alpn'));
        $checks{'hasnpn'}   ->{val} = _get_text('disabled', "--no-npn")    if (not _is_cfg_use('npn'));
        $checks{'sni'}      ->{val} = $text{'na_sni'}           if (not _is_cfg_use('sni'));
        $checks{'certfqdn'} ->{val} = $text{'na_sni'}           if (not _is_cfg_use('sni'));
        $checks{'heartbeat'}->{val} = $text{'na_tlsextdebug'}   if (not _is_cfg_use('extdebug'));
    if (1 > $cmd{'extopenssl'}) {
        foreach my $key (qw(sernumber len_sigdump len_publickey modulus_exp_1 modulus_exp_65537 modulus_exp_oldssl modulus_size_oldssl)) {
            $checks{$key}   ->{val} = $text{'na_openssl'};
        }
    }
    return;
} # _initchecks_val

sub _init_all           {
    # set all default values here
    $cfg{'done'}->{'init_all'}++;
    _trace("_init_all(){}");
    _initchecks_score();
    _initchecks_val();
    $cfg{'hints'}->{$_} = $text{'hints'}->{$_} foreach (keys %{$text{'hints'}});
    # _init_openssldir();
        # not done here because it needs openssl command, which may be set by
        # options, hence the call must be done after reading arguments
    return;
} # _init_all
_init_all();   # initialise defaults in %checks (score, val); parts be done again later

sub _resetchecks        {
    # reset values
    foreach (keys %{$cfg{'done'}}) {
        next if (!m/^check/);  # only reset check*
        $cfg{'done'}->{$_} = 0;
    }
    $cfg{'done'}->{'ciphers_all'} = 0;
    $cfg{'done'}->{'ciphers_get'} = 0;
    _initchecks_val();
    return;
} # _resetchecks

sub _prot_cipher        { my @txt = @_; return " " . join(":", @txt); }
    # return string consisting of given parameters separated by : and prefixed with a space

sub _prot_cipher_or_empty {
    # return string consisting of given parameters separated by : and prefixed with a space
    # returns "" if any parameter is empty
    my $p1 = shift;
    my $p2 = shift;
    return "" if (("" eq $p1) or ("" eq $p2));
    return _prot_cipher($p1, $p2);
} # _prot_cipher_or_empty

sub _getscore           {
    # return score value from given hash; 0 if given value is empty, otherwise score to given key
    my $key     = shift;
    my $value   = shift || "";
    my $hashref = shift;# list of checks
    my %hash    = %$hashref;
    return 0 if ($value eq "");
    my $score   = $hash{$key}->{score} || 0;
    _trace("_getscore($key, '$value')\t= $score");
    return $score;
} # _getscore

sub _cfg_set($$);       # avoid: main::_cfg_set() called too early to check prototype at ...
    # forward ...
sub _cfg_set_from_file  {
    # read values to be set in configuration from file
    my $typ = shift;    # type of config value to be set
    my $fil = shift;    # filename
    _trace("_cfg_set: read $fil \n");
    my $line ="";
    my $fh;
    # NOTE: critic complains with InputOutput::RequireCheckedOpen, which
    #       is a false positive, because  Perl::Critic  seems not to understand
    #       the logic of "open() && do{}; warn();",  hence the code was changed
    #       to use an  if-condition
    if (open($fh, '<:encoding(UTF-8)', $fil)) { ## no critic qw(InputOutput::RequireBriefOpen)
        push(@{$dbx{file}}, $fil);
        _print_read("$fil", "USER-FILE configuration file") if (_is_cfg_out('header'));
        while ($line = <$fh>) {
            #
            # format of each line in file must be:
            #    Lines starting with  =  are comments and ignored.
            #    Anthing following (and including) a hash is a comment
            #    and ignored. Empty lines are ignored.
            #    Settings must be in format:  key=value
            #       where white spaces are allowed around =
            chomp $line;
            $line =~ s/\s*#.*$// if ($typ !~ m/^CFG-text/i);
                # remove trailing comments, but CFG-text may contain hash (#)
            next if ($line =~ m/^\s*=/);# ignore our header lines (since 13.12.11)
            next if ($line =~ m/^\s*$/);# ignore empty lines
            _trace("_cfg_set_from_file: set $line ");
            _cfg_set($typ, $line);
        }
        close($fh);
        return;
    };
    _warn("070: configuration file '$fil' cannot be opened: $! ; file ignored");
    return;
} #  _cfg_set_from_file

sub _cfg_set($$)        {
    # set value in configuration %cfg, %checks, %data, %text
    # $typ must be any of: CFG-text, CFG-score, CFG-cmd-*
    # if given value is a file, read settings from that file
    # otherwise given value must be KEY=VALUE format;
    # NOTE: may define new commands for CFG-cmd
    my $typ = shift;    # type of config value to be set
    my $arg = shift;    # KEY=VAL or filename
    my ($key, $val);
    _trace("_cfg_set($typ, ){");
    if ($typ !~ m/^CFG-$cfg{'regex'}->{'cmd-cfg'}/) {
        _warn("071: configuration key unknown '$typ'; setting ignored");
        goto _CFG_RETURN;
    }
    if (($arg =~ m|^[a-zA-Z0-9,._+#()\/-]+|) and (-f "$arg")) { # read from file
        # we're picky about valid filenames: only characters, digits and some
        # special chars (this should work on all platforms)
        if ($cgi == 1) { # SEE Note:CGI mode
            # should never occour, defensive programming
            _warn("072: configuration files are not read in CGI mode; ignored");
            return;
        }
        _cfg_set_from_file($typ, $arg);
        goto _CFG_RETURN;
    } # read file

    ($key, $val) = split(/=/, $arg, 2); # left of first = is key
    $key =~ s/[^a-zA-Z0-9_?=+-]*//g;    # strict sanitise key
    $val =  "" if not defined $val;     # avoid warnings when not KEY=VALUE
    $val =~ s/^[+]//;                   # remove first + in command liss
    $val =~ s/ [+]/ /g;                 # remove + in commands

    if ($typ eq 'CFG-cmd') {            # set new list of commands $arg
        $typ = 'cmd-' . $key ;  # the command to be set, i.e. cmd-http, cmd-sni, ...
        _trace("_cfg_set: cfg{$typ}, KEY=$key, CMD=$val");
        @{$cfg{$typ}} = ();
        push(@{$cfg{$typ}}, split(/\s+/, $val));
        foreach my $key (@{$cfg{$typ}}){# check for mis-spelled commands
            next if (_is_hashkey($key, \%checks));
            next if (_is_hashkey($key, \%data));
            next if (_is_member( $key, \@{$cfg{'cmd-NL'}}));
            next if (_is_cfg_intern( $key));
            if ($key eq 'protocols') {  # valid before 17.02.26; behave smart for old rc-files
                push(@{$cfg{$typ}}, 'next_protocols');
                next;
            }
            if ($key eq 'default') {    # valid before 14.11.14; behave smart for old rc-files
                push(@{$cfg{$typ}}, 'cipher_selected');
                _warn("073: configuration: please use '+cipher-selected' instead of '+$key'; setting ignored");
                next;
            }
            _warn("074: configuration: unknown command '+$key' for '$typ'; setting ignored");
        }
        # check if it is a known command, otherwise add it and print warning
        if ((_is_member($key, \@{$cfg{'commands'}})
           + _is_member($key, \@{$cfg{'commands_cmd'}})
           + _is_member($key, \@{$cfg{'commands_int'}})
            ) < 1) {
            # NOTE: new commands are added only if they are not yet defined,
            # wether as internal, as summary or as (previously defined) user
            # command. The new command must also consists only of  a-z0-9_.-
            # charchters.  If any of these conditions fail, the command will
            # be ignored silently.
            if (not _is_member("cmd-$key", \@{$cfg{'commands_cmd'}})) {
                # needed more checks, as these commands are defined as cmd-*
                if ($key =~ m/^([a-z0-9_.-]+)$/) {
                    # whitelust check for valid characters; avoid injections
                    push(@{$cfg{'commands_usr'}}, $key);
                    _warn("046: command '+$key' specified by user") if _is_v_trace();
                }
            }
        }
    }

    # invalid keys are silently ignored (Perl is that clever:)

    if ($typ eq 'CFG-score') {          # set new score value
        _trace("_cfg_set: KEY=$key, SCORE=$val");
        if ($val !~ m/^(?:\d\d?|100)$/) {# allow 0 .. 100
            _warn("076: configuration: invalid score value '$val'; setting ignored");
            goto _CFG_RETURN;
        }
        $checks{$key}->{score} = $val if ($checks{$key});
    }

    $val =~ s/(\\n)/\n/g;
    $val =~ s/(\\r)/\r/g;
    $val =~ s/(\\t)/\t/g;
    _trace("_cfg_set: KEY=$key, TYP=$typ, LABEL=$val");
    $checks{$key}->{txt} = $val if ($typ =~ /^CFG-check/);
    $data{$key}  ->{txt} = $val if ($typ =~ /^CFG-data/);
    $data{$key}  ->{txt} = $val if ($typ =~ /^CFG-info/);   # alias for --cfg-data
    $cfg{'hints'}->{$key}= $val if ($typ =~ /^CFG-hint/);   # allows CFG-hints also
    $text{$key}          = $val if ($typ =~ /^CFG-text/);   # allows CFG-texts also
    $scores{$key}->{txt} = $val if ($typ =~ /^CFG-scores/); # BUT: CFG-score is different
    $scores{$key}->{txt} = $val if ($key =~ m/^check_/);    # contribution to lazy usage

    _CFG_RETURN:
    _trace("_cfg_set() }");
    return;
} # _cfg_set

sub _cfg_set_init       {
    # set value in configuration %cfg; for debugging and test only
    my ($typ, $arg) = @_;
    my ($key, $val) = split(/=/, $arg, 2);  # left of first = is key
    _warn("075: TESTING only: setting configuration: 'cfg{$key}=$val';");
    #_dbx "typeof: " . ref($cfg{$key});
    SWITCH: for (ref($cfg{$key})) {
        /^$/     && do {   $cfg{$key}  =  $val ; };     # same as SCALAR
        /SCALAR/ && do {   $cfg{$key}  =  $val ; };
        /ARRAY/  && do { @{$cfg{$key}} = ($val); };
        /HASH/   && do { %{$cfg{$key}} =  $val ; };     # TODO: not yet working
        /CODE/   && do { _warn("999: cannot set CODE"); };
    } # SWITCH
    return;
} # _cfg_set_init

#| definitions: check SSL functions
#| -------------------------------------
sub __readframe     {
    # from https://github.com/noxxi/p5-scripts/blob/master/check-ssl-heartbleed.pl
    my $cl  = shift;
    my $len = 5;
    my $buf = '';
    vec( my $rin = '',fileno($cl),1 ) = 1;
    while ( length($buf)<$len ) {
        select( my $rout = $rin,undef,undef,$cfg{'timeout'} ) or return;
        sysread($cl,$buf,$len-length($buf),length($buf))  or return;
        $len = unpack("x3n",$buf) + 5 if length($buf) == 5;
    }
    (my $type, my $ver,$buf) = unpack("Cnn/a*",$buf);
    my @msg;
    if ( $type == 22 ) {
        while ( length($buf)>=4 ) {
            my $ht;
            ($ht,$len) = unpack("Ca3",substr($buf,0,4,''));
            $len = unpack("N","\0$len");
            push @msg,[ $ht,substr($buf,0,$len,'') ];
            _v_print sprintf("...ssl received type=%d ver=0x%x ht=0x%x size=%d", $type,$ver,$ht,length($msg[-1][1]));
        }
    } else {
        @msg = $buf;
        _v_print sprintf("...ssl received type=%d ver=%x size=%d", $type,$ver,length($buf));
    }
    return ($type,$ver,@msg);
} # __readframe

sub _is_ssl_bleed   {
    #? return "heartbleed" if target supports TLS extension 15 (heartbeat), empty string otherwise
    # SEE Note:heartbleed
    my ($host, $port) = @_;
    my $heartbeats    = 1;
    my $cl  = undef; # TODO: =$Net::SSLinfo::socket;
    my $ret = "";       # empty string as required in %checks
    my ($type,$ver,$buf,@msg) = ("", "", "", ());
    local $\ = undef;   # take care, must not be \n !!

        # open our own connection and close it at end
# TODO: does not work with socket from SSLinfo.pm
# TODO: following unless{}else{} should be same as in _usesocket()
    unless (($cfg{'starttls'}) || (($cfg{'proxyhost'})&&($cfg{'proxyport'}))) {
        # no proxy and not starttls
        $cl = IO::Socket::INET->new(PeerAddr=>"$host:$port", Timeout=>$cfg{'timeout'}) or do {
            _warn("321: _is_ssl_bleed: failed to connect: '$!'");
            _trace("_is_ssl_bleed: fatal exit in IO::Socket::INET->new\n");
            return "failed to connect";
        };
    } else {
        # proxy or starttls
        _trace("_is_ssl_bleed: using 'Net::SSLhello'");
        $cl = Net::SSLhello::openTcpSSLconnection($host, $port);
        if ((not defined $cl) || ($@)) { # No SSL Connection
            local $@ = " Did not get a valid SSL-Socket from Function openTcpSSLconnection -> Fatal Exit of openTcpSSLconnection" unless ($@);
            _warn ("322: _is_ssl_bleed (with openTcpSSLconnection): $@\n");
            _trace("_is_ssl_bleed: fatal exit in _doCheckSSLciphers\n");
            return("failed to connect");
        }
        # NO SSL upgrade needed -> NO else
    }

    # all following code stolen from Steffen Ullrich (08. April 2014):
    #   https://github.com/noxxi/p5-scripts/blob/master/check-ssl-heartbleed.pl
    # code slightly adapted to our own variables: $host, $port, $cfg{'timeout'}
    # also die() replaced by _warn()

    # client hello with heartbeat extension
    # taken from http://s3.jspenguin.org/ssltest.py
    print $cl pack("H*",join('',qw(
                    16 03 02 00  dc 01 00 00 d8 03 02 53
        43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
        bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
        00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
        00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
        c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
        c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
        c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
        c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
        00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
        03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
        00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
        00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
        00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
        00 0f 00 01 01
    )));
    while (1) {
        ($type,$ver,@msg) = __readframe($cl) or do {
            #ORIG die "no reply";
            _warn("323: heartbleed: no reply: '$!'");
            _hint("server does not respond, this does not indicate that it is not vulnerable!");
            return "no reply";
        };
        last if $type == 22 and grep { $_->[0] == 0x0e } @msg; # server hello done
    }
    # heartbeat request with wrong size
    for(1..$heartbeats) {
        _v_print("...send heartbeat#$_");
        print $cl pack("H*",join('',qw(18 03 02 00 03 01 40 00)));
    }
    if ( ($type,$ver,$buf) = __readframe($cl)) {
        if ( $type == 21 ) {
            _v_print("received alert (probably not vulnerable)");
        } elsif ( $type != 24 ) {
            _v_print("unexpected reply type $type");
        } elsif ( length($buf)>3 ) {
            $ret = "heartbleed";
            _v_print("BAD! got ".length($buf)." bytes back instead of 3 (vulnerable)");
            #show_data($buf) if $show;
            #if ( $show_regex ) {
            #    while ( $buf =~m{($show_regex)}g ) {
            #        print STDERR $1."\n";
            #    }
            #}
            # exit 1;
        } else {
            _v_print("GOOD proper heartbeat reply (not vulnerable)");
        }
    } else {
        _v_print("no reply - probably not vulnerable");
    }
    close($cl);
    _trace("_is_ssl_bleed= $ret\n");
    return $ret;
} # _is_ssl_bleed
sub _is_ssl_beast   {
    # return given cipher if vulnerable to BEAST attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return ""      if ($ssl    !~ /(?:SSL|TLSv1$)/); # TLSv11 or later are not vulnerable to BEAST
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'BEAST'}/);
    return "";
} # _is_ssl_beast
### _is_ssl_breach($)        { return "NOT YET IMPLEMEMNTED"; }
sub _is_ssl_breach  {
    # return 'yes' if vulnerable to BREACH
    return "";
# TODO: checks
    # To be vulnerable, a web application must:
    #      Be served from a server that uses HTTP-level compression
    #      Reflect user-input in HTTP response bodies
    #      Reflect a secret (such as a CSRF token) in HTTP response bodies
    #      *  agnostic to the version of TLS/SSL
    #      *  does not require TLS-layer compression
    #      *  works against any cipher suite
    #      *  can be executed in under a minute
} # _is_ssl_breach
sub _is_ssl_ccs     {
    #? return "ccs" if target is vulnerable to CCS Injection, empty string otherwise
    # parameter $ssl must be provided as binary value: 0x00, 0x01, 0x02, 0x03 or 0x04
    # http://ccsinjection.lepidum.co.jp/
    # inspired by http://blog.chris007.de/?p=238
    my ($host, $port, $ssl) = @_;
    my $heartbeats    = 1;
    my $cl  = undef; # TODO: =$Net::SSLinfo::socket;
    my $ret = "";       # empty string as required in %checks
    my ($type,$ver,$buf,@msg) = ("", "", "", ());
    undef $\;           # take care, must not be \n !!

        # open our own connection and close it at end
# TODO: does not work with socket from SSLinfo.pm
    $cl = IO::Socket::INET->new(PeerAddr => "$host:$port", Timeout => $cfg{'timeout'}) or  do {
        _warn("331: _is_ssl_ccs: failed to connect: '$!'");
        return "failed to connect";
    };
#################
# $ccs = _is_ssl_ccs($host, $port, $ssl);
#    'openssl_version_map' => {  # map our internal option to openssl version (hex value)
#        'SSLv2'=> 0x0002, 'SSLv3'=> 0x0300, 'TLSv1'=> 0x0301, 'TLSv11'=> 0x0302, 'TLSv12'=> 0x0303, 'TLSv13'=> 0x0304,  }
#################
#\x14\x03\tls_version\x00\x01\x01    sed 's/tls_version/'"$2"'/g'
#\x01    # ist TLSv1
# 14 03 01 00 01 01
    # client hello with CCS
    #   00..00  # random 32 byte (i.e. Unix time)
    #   00      # Session ID length
    #   00 68   # Cipher suites length
    print $cl pack("H*",join('',qw(
        53 9c b2 cb 4b 42 f9 2d  0b e5 9c 21 f5 a3 89 ca
        7a d9 b4 ab 3f d3 22 21  5e c4 65 0d 1e ce ed c2
        00
        00 68
        c0 13 c0 12 c0 11 c0 10  c0 0f c0 0e c0 0d c0 0c
        c0 0b c0 0a c0 09 c0 08  c0 07 c0 06 c0 05 c0 04
        c0 03 c0 02 c0 01 00 39  00 38 00 37 00 36 00 35
        00 34 00 33 00 32 00 31  00 30 00 2f 00 16 00 15
        00 14 00 13 00 12 00 11  00 10 00 0f 00 0e 00 0d
        00 0c 00 0b 00 0a 00 09  00 08 00 07 00 06 00 05
        00 04 00 03 00 02 00 01  01 00
    )));
    while (1) {
        ($type,$ver,@msg) = __readframe($cl) or do {
            _warn("332: _is_ssl_ccs: no reply: '$!'");
            return "no reply";
        };
        last if $type == 22 and grep { $_->[0] == 0x0e } @msg; # server hello done
    }
    if ( ($type,$ver,$buf) = __readframe($cl)) {
        if ( $type == 21 ) {
            _v_print("received alert (probably not vulnerable)");
        } elsif ( $type != 24 ) {
            _v_print("unexpected reply type $type");
        } elsif ( length($buf)>3 ) {
            $ret = "heartbleed";
            _v_print("BAD! got ".length($buf)." bytes back instead of 3 (vulnerable)");
            #show_data($buf) if $show;
            #if ( $show_regex ) {
            #    while ( $buf =~m{($show_regex)}g ) {
            #        print STDERR $1."\n";
            #    }
            #}
            # exit 1;
        } else {
            _v_print("GOOD proper heartbeat reply (not vulnerable)");
        }
    } else {
        _v_print("no reply - probably not vulnerable");
    }
    close($cl);
    return $ret;
} # _is_ssl_ccs
sub _is_ssl_crime   {
    # return compression or SPDY/3 if available, empty string otherwise
    # $val is usually $data{'compression'}->{val}
    my ($val, $protocols) = @_;
    my $ret  = ($val =~ /$cfg{'regex'}->{'nocompression'}/) ? ""  : $val . " ";
       $ret .= ($protocols =~ /$cfg{'regex'}->{'isSPDY3'}/) ? "SPDY/3 " : "";
    #  http://zoompf.com/2012/09/explaining-the-crime-weakness-in-spdy-and-ssl
    return $ret;
} # _is_ssl_crime
sub _is_ssl_fips    {
    # return given cipher if it is not FIPS-140 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    ne "TLSv1");
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notFIPS-140'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'FIPS-140'}/);
    return "";
} # _is_ssl_fips
sub _is_ssl_freak   {
    # return given cipher if vulnerable to FREAK attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return ""      if ($ssl    !~ /(?:SSLv3)/); # TODO: probably only SSLv3 is vulnerable
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'FREAK'}/);
    return "";
} # _is_ssl_freak
sub _is_ssl_logjam  {
    # return given cipher if vulnerable to logjam attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'Logjam'}/);
    return "";
} # _is_ssl_logjam
sub _is_ssl_lucky   { my $val=shift; return ($val =~ /$cfg{'regex'}->{'Lucky13'}/) ? $val : ""; }
    # return given cipher if vulnerable to Lucky 13 attack, empty string otherwise
sub _is_ssl_nsab    {
    # return given cipher if it is not NSA Suite B compliant, empty string otherwise
# TODO:
} # _is_ssl_nsab
sub _is_ssl_pci     {
    # return given cipher if it is not PCI compliant, empty string otherwise
# TODO: DH 1024+ is PCI compliant
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    eq "SSLv2"); # SSLv2 is not PCI compliant
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notPCI'}/);
    return "";
} # _is_ssl_pci
sub _is_ssl_pfs     { my ($ssl,$c)=@_; return ("$ssl-$c" =~ /$cfg{'regex'}->{'PFS'}/)  ?  $c  : ""; }
    # return given cipher if it supports forward secret connections (PFS)
sub _is_ssl_rc4     { my $val=shift; return ($val =~ /$cfg{'regex'}->{'RC4'}/)  ? $val . " "  : ""; }
    # return given cipher if it is RC4
sub _is_ssl_robot   {
    # return given cipher if vulnerable to ROBOT attack, empty string otherwise
    my ($ssl, $cipher) = @_;
   #return ""      if ($cipher =~ /$cfg{'regex'}->{'notROBOT'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'ROBOT'}/);
    return "";
} # _is_ssl_robot
sub _is_ssl_sloth   {
    # return given cipher if vulnerable to SLOTH attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'SLOTH'}/);
    return "";
} # _is_ssl_sloth
sub _is_ssl_sweet   {
    # return given cipher if vulnerable to Sweet32 attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return ""      if ($cipher =~ /$cfg{'regex'}->{'notSweet32'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'Sweet32'}/);
    return "";
} # _is_ssl_sweet
sub _is_ssl_time    { return 0; } # TODO: checks; good: AES-GCM or AES-CCM
    # return given cipher if vulnerable to TIME attack, empty string otherwise

sub _is_tls12only   {
# NOTE: not yet used
    #? returns empty string if TLS 1.2 is the only protocol used,
    #? returns all used protocols otherwise
    my ($host, $port) = @_;
    my @ret;
    foreach my $ssl (qw(SSLv2 SSLv3 TLSv1 TLSv11)) {
        # If $cfg{$ssl}=0, the check may be disabled, i.e. with --no-sslv3 .
        # If the protocol  is supported by the target,  at least  one cipher
        # must be accpted. So the amount of ciphers must be > 0.
        if ($prot{$ssl}->{'cnt'}  >  0) {
            push(@ret, $ssl);
        }
        if ($cfg{$ssl} == 0) {
            # this condition is never true if ciphers have been detected
            push(@ret, _get_text('disabled', "--no-$ssl"));
        }
    }
#_dbx ": TLS  " . join(" ", @ret);
    return join(" ", @ret);
} # _is_tls12only

sub _is_tr02102         {
    # return given cipher if it is not TR-02102 compliant, empty string otherwise
    # this is valid vor TR-02102 2013 and 2016
    my ($ssl, $cipher) = @_;
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'EXPORT'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notTR-02102'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'TR-02102'}/);
    return "";
} # _is_tr02102
sub _is_tr02102_strict  {
    # return given cipher if it is not TR-02102 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    my $val = _is_tr02102($ssl, $cipher);
    if ($val eq "") {   # strict allows AES*-GCM only and no SHA-1
        return $cipher if ($cipher !~ /$cfg{'regex'}->{'AES-GCM'}/);
        return $cipher if ($cipher =~ /$cfg{'regex'}->{'notTR-02102'}/);
    }
    return $val;
} # _is_tr02102_strict
sub _is_tr02102_lazy    {
    # return given cipher if it is not TR-02102 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    my $val = _is_tr02102($ssl, $cipher);
    return $val;
} # _is_tr02102_lazy
sub _is_tr03116_strict  {
    # return given cipher if it is not TR-03116 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    ne "TLSv12");
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'EXPORT'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notTR-03116'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'TR-03116+'}/);
    return "";
} # _is_tr03116_strict
sub _is_tr03116_lazy    {
    # return given cipher if it is not TR-03116 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    ne "TLSv12");
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'EXPORT'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'TR-03116-'}/);
    return "";
} # _is_tr03116_lazy
sub _is_rfc7525         {
    # return given cipher if it is not RFC 7525 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    my $bit = _cipher_get_bits($cipher);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'RFC7525'}/);
   # /notRFC7525/;
    return $cipher if ($cipher =~ /NULL/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'EXPORT'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'RC4orARC4'}/);
    return ""      if ($bit =~ m/^\s*$/);   # avoid Perl warnings if $bit empty
    return $cipher if ($bit < 128);
    return "";
} # _is_rfc7525

sub _isbeastskipped($$) {
    #? returns protocol names if they are vulnerable to BEAST but the check has been skipped,
    #? returns empty string otherwise.
    my ($host, $port) = @_;
    my @ret;
    foreach my $ssl (qw(SSLv2 SSLv3 TLSv1)) {
        # If $cfg{$ssl}=0, the check may be disabled, i.e. with --no-sslv3 .
        if ($cfg{$ssl} == 0) {
            push(@ret, _get_text('disabled', "--no-$ssl"));
        }
    }
#_dbx ": TLS  " . join(" ", @ret);
    return join(" ", @ret);
} # _isbeastskipped

sub _is_ssl_error($$$)  {
    # returns 1 if probably a SSL connection error occoured; 0 otherwise
    # increments counters in $cfg{'done'}
    my ($anf, $end, $txt) = @_;
    return 0 if (($end - $anf) <= $cfg{'sslerror'}->{'timeout'});
    $cfg{'done'}->{'ssl_errors'}++;     # total counter
    $cfg{'done'}->{'ssl_failed'}++;     # local counter
    return 0 if (not _is_cfg_use('ssl_error'));# no action required
    if ($cfg{'done'}->{'ssl_errors'} > $cfg{'sslerror'}->{'total'}) {
        _warn("301: $txt after $cfg{'sslerror'}->{'total'} total errors");
        _hint("use '--no-ssl-error' or '--ssl-error-max=' to continue connecting");
        return 1;
    }
    if ($cfg{'done'}->{'ssl_failed'} > $cfg{'sslerror'}->{'max'}) {
        _warn("302: $txt after $cfg{'sslerror'}->{'max'} max errors");
        _hint("use '--no-ssl-error' or '--ssl-error-max=' to continue connecting");
        return 1;
    }
    return 0;
} # _is_ssl_error

sub _checkwildcard($$)  {
    # compute usage of wildcard in CN and subjectAltname
    my ($host, $port) = @_;
    my ($cn_host, $rex);
    $cn_host = $data{'cn'}->{val}($host);
    $checks{'wildcard'}->{val} = "<<CN:>>$cn_host" if ($cn_host =~ m/[*]/);
    foreach my $value (split(" ", $data{'altname'}->{val}($host))) {
            $value =~ s/.*://;  # strip prefix, like DNS:
        if ($value =~ m/\*/) {  # * can be anywhere, like a.b*.some.tld
            # NOTE: lazy check, because *.b*.some.tld is invalid, but works here
            $checks{'wildcard'}->{val} .= " " . $value;
            ($rex = $value) =~ s/[*]/[^.]*/;# make RegEx
                # RegEx: missing dots is ok, like a.b.some.tld
                # RegEx: leading dot is ok, like .some.tld
                # then $host must match completely ^$rex$
            $checks{'wildhost'}->{val}  = $value if ($host =~ m/^$rex$/);
            $checks{'cnt_wildcard'}->{val}++;
        }
        $checks{'cnt_altname'}->{val}++;
        $checks{'len_altname'}->{val} = length($value) + 1; # count number of characters + type (int)
    }
    # checking for SNI does not work here 'cause it destroys %data
    return;
} # _checkwildcard

sub _usesocket($$$$)    {
    # return protocol and cipher accepted by SSL connection
    # should return the target's preferred cipher if none are given in $ciphers
    # NOTE: this function is used to check for supported ciphers only, hence
    #       no need for sophisticated options in new() and no certificate checks
    #       $ciphers must be colon (:) separated list
    my ($ssl, $host, $port, $ciphers) = @_;
    my $cipher  = "";   # to be returned
    my $sni     = (not _is_cfg_use('sni'))  ? "" : $host;
    my $npns    = (not _is_cfg_use('npn'))  ? [] : $cfg{'cipher_npns'};
    my $alpns   = (not _is_cfg_use('alpn')) ? [] : $cfg{'cipher_alpns'};
        # --no-alpn or --no-npn is same as --cipher-alpn=, or --cipher-npn=,
    my $version = "";   # version returned by IO::Socket::SSL-new
    my $sslsocket = undef;
    # TODO: dirty hack (undef) to avoid Perl error like:
    #    Use of uninitialized value in subroutine entry at /usr/share/perl5/IO/Socket/SSL.pm line 562.
    # which may occour if Net::SSLeay was not build properly with support for
    # these protocol versions. We only check for SSLv2 and SSLv3 as the *TLSx
    # doesn't produce such warnings. Sigh.
    _trace1("_usesocket($ssl, $host, $port, $ciphers){ sni: $sni");
    # _warn_nosni(); # not here, because too noisy
    # following ugly if conditions: because one or both functions may be there
    if (($ssl eq "SSLv2") && (not defined &Net::SSLeay::CTX_v2_new)) {
        _warn("303: SSL version '$ssl': not supported by Net::SSLeay");
        return "";
    }
    if (($ssl eq "SSLv3") && (not defined &Net::SSLeay::CTX_v3_new)) {
        _warn("304: SSL version '$ssl': not supported by Net::SSLeay");
        return "";
    }
    # FIXME: use Net::SSLeay instead of IO::Socket::SSL
    if (eval {  # FIXME: use something better than eval()
        # NOTE: eval necessary to avoid Perl error like:
        #   invalid SSL_version specified at /usr/share/perl5/IO/Socket/SSL.pm line 492.
        # NOTE: SSL_hostname does not support IPs (at least up to 1.88); check done in IO::Socket::SSL
        #dbx# $IO::Socket::SSL::DEBUG = 1;
        unless (($cfg{'starttls'}) || (($cfg{'proxyhost'})&&($cfg{'proxyport'}))) {
            # no proxy and not starttls
            _trace1("_usesocket: using 'IO::Socket::SSL' with '$ssl'");
            local $? = 0; local $! = undef;
            $sslsocket = IO::Socket::SSL->new(
                PeerAddr        => $host,
                PeerPort        => $port,
                Proto           => "tcp",
                Timeout         => $cfg{'timeout'},
                SSL_hostname    => $sni,        # for SNI
                SSL_verify_mode => 0x0,         # SSL_VERIFY_NONE => Net::SSLeay::VERIFY_NONE(); # 0
                SSL_ca_file     => undef,       # see man IO::Socket::SSL ..
                SSL_ca_path     => undef,       # .. newer versions are smarter and accept ''
                SSL_check_crl   => 0,           # do not check CRL
                SSL_version     => $ssl,        # default is SSLv23 (for empty $ssl)
                SSL_cipher_list => $ciphers,
                SSL_ecdh_curve  => "prime256v1",# OID or NID; ecdh_x448, default is prime256v1, ecdh_x25519
                #SSL_ecdh_curve  => $cfg{'ciphercurves'},# OID or NID; ecdh_x448, default is prime256v1,
                #SSL_ecdh_curve  => [qw(sect163k1 x25519)],
                #SSL_ecdh_curve  => undef, # TODO: cannot be selected by options
                SSL_alpn_protocols  => $alpns,
                SSL_npn_protocols   => $npns,
                #TODO: SSL_honor_cipher_order  => 1,   # useful for SSLv2 only
                #SSL_check_crl   => 1,           # if we want to use a client certificate
                #SSL_cert_file   => "path"       # file for client certificate
            );
            #_trace1("_usesocket: IO::Socket::SSL->new: $? : $! :");
        } else {
            # proxy or starttls
            _trace1("_usesocket: using 'Net::SSLhello'");
            local $? = 0; local $! = undef;
            $sslsocket = Net::SSLhello::openTcpSSLconnection($host, $port);
            if ((not defined ($sslsocket)) || ($@)) { # No SSL Connection
                local $@ = " Did not get a valid SSL-Socket from Function openTcpSSLconnection -> Fatal Exit" unless ($@);
                _warn("305: _usesocket: openTcpSSLconnection() failed: $@\n");
                return ("");
            } else {
                # SSL upgrade
                _trace1("_usesocket: start_SSL ($host, $port, $ciphers)\t= $cipher");
                IO::Socket::SSL->start_SSL($sslsocket,
                  Timeout         => $cfg{'timeout'},
                  SSL_hostname    => $sni,      # for SNI
                  SSL_verify_mode => 0x0,       # SSL_VERIFY_NONE => Net::SSLeay::VERIFY_NONE(); # 0
                  SSL_ca_file     => undef,     # see man IO::Socket::SSL ..
                  SSL_ca_path     => undef,     # .. newer versions are smarter and accept ''
                  SSL_check_crl   => 0,         # do not check CRL
                  SSL_version     => $ssl,      # default is SSLv23
                  SSL_cipher_list => $ciphers,
                  SSL_ecdh_curve  => "prime256v1", # default is prime256v1,
                  SSL_alpn_protocols => $alpns,
                  SSL_npn_protocols  => $npns,
                ) or do {
                    _trace1("_usesocket: ssl handshake failed: $!");
                    return "";
                };
            }
        }
        #dbx# _dbx("_usesocket: $? : $! : $IO::Socket::SSL::SSL_ERROR :"); # more info in rare cases
    }) {        # eval succeded
        if ($sslsocket) {
            # SEE Note:Selected Protocol
            $version = $sslsocket->get_sslversion() if ($IO::Socket::SSL::VERSION > 1.964);
            $cipher  = $sslsocket->get_cipher();
            $sslsocket->close(SSL_ctx_free => 1);
            _trace1("_usesocket: SSL version (for $ssl $ciphers): $version");
        }
    } else {    # eval failed: connect failed
        # we may get hints in $! like:
        #   * empty if cipher was not accepted
        #   * contains an error string if the connection was rejected or there
        #     was an error in IO::Socket::SSL (i.e. timeout)
        _trace1("_usesocket: connection failed (for $ssl $ciphers): $!");
    }
    _trace1("_usesocket()\t= $cipher }");
    return $version, $cipher;
} # _usesocket

sub _useopenssl($$$$)   {
    # return cipher accepted by SSL connection
    # should return the target's preferred cipher if none are given in $ciphers
    # $ciphers must be colon (:) separated list
    # adds all configured options, like -alpn -curves -servername etc. with
    # their proper values
    my ($ssl, $host, $port, $ciphers) = @_;
    my $msg  =  $cfg{'openssl_msg'};
    my $sni  = (not _is_cfg_use('sni'))  ? "" : "-servername $host";
    $ciphers = ($ciphers      eq "") ? "" : "-cipher $ciphers";
    my $curves  = "-curves " . join(":", $cfg{'ciphercurves'}); # TODO: add to command below
    _trace1("_useopenssl($ssl, $host, $port, $ciphers)"); # no { in comment here ; dumm }
    $ssl = ($cfg{'openssl_option_map'}->{$ssl} || '');  # set empty if no protocol given
    my $data = Net::SSLinfo::do_openssl("s_client $ssl $sni $msg $ciphers ", $host, $port, '');
# TODO: hier -alpn $protos_alpn und -nextprotoneg $protos_npn übergeben
# TODO: dann entsprechenden Code in Net::SSLinfo::do_openssl() entfernen
    # we may get for success:
    #   New, TLSv1/SSLv3, Cipher is DES-CBC3-SHA
    # also possible would be Cipher line from:
    #   SSL-Session:
    #       Protocol  : TLSv1.2
    #       Cipher    : DES-CBC3-SHA
    _trace2("_useopenssl: data #{ $data }");
    return "", "", "" if ($data =~ m#New,.*?Cipher is .?NONE#);

    my $version = $data;# returned version
       $version =~ s#^.*[\r\n]+ +Protocol\s*:\s*([^\r\n]*).*#$1#s;
    my $cipher  = $data;
    if ($cipher =~ m#New, [A-Za-z0-9/.,-]+ Cipher is#) {
        $cipher =~ s#^.*[\r\n]+New,\s*##s;
        $cipher =~ s#[A-Za-z0-9/.,-]+ Cipher is\s*([^\r\n]*).*#$1#s;
        my $dh  = osaft::get_dh_paramter($cipher, $data);
        _trace1("_useopenssl()\t= $cipher $dh }");
        return $version, $cipher, $dh;
    }
    # else check for errors ...

    # grrrr, it's a pain that openssl changes error messages for each version
    # we may get any of following errors:
    #   TIME:error:140790E5:SSL routines:SSL23_WRITE:ssl handshake failure:.\ssl\s23_lib.c:177:
    #   New, (NONE), Cipher is (NONE)
    #   connect:errno=11004
    #   TIME:error:14077410:SSL routines:SSL23_GET_SERVER_HELLO:sslv3 alert handshake failure:s23_clnt.c:602:
    #   TIME:error:140740B5:SSL routines:SSL23_CLIENT_HELLO:no ciphers available:s23_clnt.c:367:
    # if SSL version not supported (by openssl):
    #   29153:error:140A90C4:SSL routines:SSL_CTX_new:null ssl method passed:ssl_lib.c:1453:
    # openssl 1.0.1e :
    #   # unknown messages: 139693193549472:error:1407F0E5:SSL routines:SSL2_WRITE:ssl handshake failure:s2_pkt.c:429:
    #   error setting cipher list
    #   139912973481632:error:1410D0B9:SSL routines:SSL_CTX_set_cipher_list:no cipher match:ssl_lib.c:1314:
    return "", "", "" if ($data =~ m#SSL routines.*(?:handshake failure|null ssl method passed|no ciphers? (?:available|match))#); ## no critic qw(RegularExpressions::ProhibitComplexRegexes)

    if ($data =~ m#^\s*$#) {
        _warn("311: SSL version '$ssl': empty result from openssl");
    } else {
        _warn("312: SSL version '$ssl': unknown result from openssl");
        _warn("312: result from openssl: '$data'") if _is_v_trace();
    }
    _trace2("_useopenssl: #{ $data }");
    if ($cfg{'verbose'} < 1) {
        _hint("use '--v' or '--trace'"); # print always
    } else {
        _v_print("_useopenssl: Net::SSLinfo::do_openssl() #{\n$data\n#}");
    }

    return "", "", "";
} # _useopenssl

sub _can_connect        {
    # return 1 if host:port can be connected; 0 otherwise
    my ($host, $port, $sni, $timeout, $ssl) = @_;
    if (not defined $sni) { $sni = $STR{UNDEF}; } # defensive programming
    local $? = 0; local $! = undef;
    my $socket;
    _trace("_can_connect($host, $port', $sni, $timeout, $ssl)");
    if ($ssl == 1) {    # need different method for connecting with SSL
        if ($cfg{'trace'} > 2) { $IO::Socket::SSL::debug3 = 1; my $keep_perl_quiet = $IO::Socket::SSL::debug3; }
        # simple and fast connect: full cipher list, no handshake,
        #    do not verify the certificate and/or CRL, OCSP, which
        # may result in a connection fail
        # SNI is not necessary, as we just want to know if the server responds
        #    however, SNI may be necessary in future ...
        # NOTE: $sni may be undef
        $socket = IO::Socket::SSL->new(
            PeerAddr        => $host,
            PeerPort        => $port,
            Proto           => "tcp",
            Timeout         => $timeout,
           #SSL_hostname    => $sni,
            SSL_version     => "SSLv23",
            SSL_cipher_list => "ALL:NULL:eNULL:aNULL:LOW:EXP",
            SSL_verify_mode => 0x0,     # SSL_VERIFY_NONE => Net::SSLeay::VERIFY_NONE(); # 0
            SSL_check_crl   => 0,       # do not check CRL
            SSL_ocsp_mode   => 0,       # TODO: is 0 the roccect value to disable this check?
            SSL_startHandshake  => 0,
        ) or do { _v_print("_can_connect: IO::Socket::SSL->new(): $! #" .  IO::Socket::SSL::errstr()); };
    } else {
        $socket = IO::Socket::INET->new(
            PeerAddr        => $host,
            PeerPort        => $port,
            Proto           => "tcp",
            Timeout         => $timeout,
        ) or do { _v_print("_can_connect: IO::Socket::INET->new(): $!"); }; # IO::Socket::INET::errstr();
    }
    if (defined $socket) {
        close($socket);
        return 1;
    }
    _warn("324: failed to connect target '$host:$port': '$!'");
    return 0;
} # _can_connect

sub _get_target         {
    # check argument and return array: protocol, host, port, auth
    # allow host, host:port, URL with IPv4, IPv6, FQDN
    #   http://user:pass@f.q.d.n:42/aa*foo=bar:23/
    #    ftp://username:password@hostname/
    #   http://f.q.d.n:42/aa*foo=bar:23/
    #    ftp://f.q.d.n:42/aa*foo=bar:23
    #   ftp:42/no-fqdn:42/aa*foo=bar:23
    #   dpsmtp://authentication@mail:25/queryParameters
    #   //abc/def
    #   abc://def    # scary
    #   http://[2001:db8:1f70::999:de8:7648:6e8]:42/aa*foo=bar:23/
    #   http://2001:db8:1f70::999:de8:7648:6e8:42/aa*foo=bar:23/  # invalid, but works
    #   cafe::999/aa*foo=bar:23/  # invalid, but works
    # NOTE: following regex allow hostnames containing @, _ and many more ...
    my $last  =  shift; # default port if not specified
    my $arg   =  shift;

    # TODO:  ugly and just simple cases, not very perlish code ...
    return ("https", $arg, $last, "", "") if ($arg =~ m#^\s*$#);    # defensive programming
    return ("https", $arg, $last, "", "") if ($arg !~ m#[:@\\/?]#); # seem to be bare name or IP
    # something complicated, analyse ...
    my $prot  =  $arg;
       $prot  =~ s#^\s*([a-z][A-Z0-9]*:)?//.*#$1#i; # get schema (protocol), if any
       # TODO: inherit previous schema if not found
       $prot  = "https" if ($prot eq $arg);         # check before stripping :
       $prot  = "https" if ($prot eq "");
       $prot  =~ s#:##g;                # strip :
    my $auth  =  ""; # TODO
    my $path  =  $arg;
       $path  =~ s#^.*?/#/#;            # get /path/and?more
    my $port  =  "";
    my $host  =  $arg;
       $host  =~ s#^\s*(?:[a-z][A-Z0-9]*:)?//##i;   # strip schema (protocol), if any
       $host  =~ s#^(?:[^@]+@)?##i;     # strip user:pass, if any
       $host  =~ s#/.*$##;              # strip /path/and?more
    ($host, $port)  = split(/:([^:\]]+)$/, $host); # split right most : (remember IPv6)
    $port  =  $last if not defined $port;
    _y_ARG("  target arg=$arg => prot=$prot, host=$host, port=$port");
    #return "" if (($host =~ m/^\s*$/) or ($port =~ m/^\s*$/));
    return ($prot, $host, $port, $auth, $path);
} # _get_target

sub _get_cipherlist_openssl {
    #? return space-separated list of cipher suites according command-line options
    #  this is usefull for display only or for use with openssl
    _trace("_get_cipherlist_openssl(){");
    my @ciphers = ();
    my $range   = $cfg{'cipherrange'};  # default
    _trace(" cipherpattern  = $cfg{'cipherpattern'}, cipherrange= $range");
    my $pattern = $cfg{'cipherpattern'};# default pattern (colon-separated)
       $pattern = join(":", @{$cfg{'cipher'}}) if (0 < scalar(@{$cfg{'cipher'}}));
        # @{$cfg{'cipher'}}) > 0  if option --cipher=* was used
        # can be specified like: --cipher=NULL:RC4  or  --cipher=NULL --cipher=RC4
    _trace(" cipher pattern = $pattern");
    if ($range eq "intern") {
        # default cipher range is 'intern' (see o-saft-lib.pm), then get list of
        # ciphers from Net::SSLinfo
        if ($cmd{'extciphers'} == 1) {
            @ciphers = Net::SSLinfo::cipher_openssl($pattern);
        } else {
            @ciphers = Net::SSLinfo::cipher_list(   $pattern);
        }
    } else {
        # cipher range specified with --cipher-range=* option
        # ranges are defined as numbers, need to get the cipher suite name
        _v_print("cipher range: $range");
        foreach my $c (_eval_cipherranges($range)) {
            my $key = sprintf("0x%08X",$c);
            push(@ciphers, OSaft::Ciphers::get_name($key)||""); # "" avoids some undef
        }
    }
    _trace(" got ciphers    = @ciphers");
    if (@ciphers <= 0) {      # empty list
        _warn("063: given pattern '$pattern' did not return cipher list");
        _y_CMD("  using private cipher list ...");
        @ciphers = OSaft::Ciphers::get_names_list();
    }
    if (@ciphers <= 0) {
        print "Errors: " . Net::SSLinfo::errors();
        die $STR{ERROR}, "015: no ciphers found; may happen with openssl pre 1.0.0 according given pattern";
    }
    @ciphers    = sort grep{!/^\s*$/} @ciphers;   # remove empty names
    _trace("_get_cipherlist_openssl\t= @ciphers }"); # TODO: trace a bit late
    return @ciphers;
} # _get_cipherlist_openssl

sub _get_cipherlist_hex {
    #? return space-separated list of cipher hex keys according command-line options
    my $ssl     = shift;
    my @ciphers = ();
    _trace("_get_cipherlist_hex($ssl){");
    _trace(" cfg{'cipher'}  = " . @{$cfg{'cipher'}} );
    if (0 < scalar(@{$cfg{'cipher'}})) {
        foreach my $name (@{$cfg{'cipher'}}) {
            if ($name =~ m/^(?:0x)?[0-9A-F]+$/i) {
                #_dbx "key = " . OSaft::Ciphers::get_key($name);
                push(@ciphers, OSaft::Ciphers::get_key($name));   # hex key
            } else {
                push(@ciphers, OSaft::Ciphers::find_keys($name)); # name or pattern
            }
        }
    } else {
        _trace("cipherrange= $cfg{'cipherrange'}"); # default
        @ciphers = osaft::get_ciphers_range($ssl, $cfg{'cipherrange'});
    }
    _trace(" no. of ciphers = " . scalar(@ciphers));
    _trace("_get_cipherlist_hex()\t= @ciphers }");
    return @ciphers;
} # _get_cipherlist_hex

sub _get_default($$$$)  {
    # return list of offered (default) cipher from target
    # mode defines how to retrieve the preferred cipher
    #   strong:  pass cipher list sorted with strongest first
    #   weak:    pass cipher list sorted with weakest first
    #   default: pass no cipher list which then uses system default

    # To get the target's preferred cipher, all known ciphers are send so that
    # the target should select the most secure one.
    # Both, openssl and sockets (IO::Socket::SSL), use the underlaying libssl
    # which works with the compiled in ciphers only.  Hence all known ciphers
    # (by libssl) are passed:  @{$cfg{'ciphers'}}, we cannot pass all ciphers
    # like: keys %ciphers. +cipher --ciphermode=intern must be used, if other
    # ciphers than the local available should be checked.

    my ($ssl, $host, $port, $mode) = @_;
    _trace("_get_default($ssl, $host, $port, $mode){");
    $cfg{'done'}->{'default_get'}++;
    my $dh      = "";   # returned DH parameters (not yet used)
    my $version = "";   # returned protocol version
    my $cipher  = "";
    my @list = ();   # mode == default
       @list =         OSaft::Ciphers::sort_names(@{$cfg{'ciphers'}}) ;#if ($mode eq 'strong');
       @list = reverse OSaft::Ciphers::sort_names(@{$cfg{'ciphers'}}) if ($mode eq 'weak');
    my $cipher_list = join(":", @list);

    if (0 == $cmd{'extciphers'}) {
        ($version, $cipher)     = _usesocket( $ssl, $host, $port, $cipher_list);
    } else { # force openssl
        ($version, $cipher, $dh)= _useopenssl($ssl, $host, $port, $cipher_list);
           # NOTE: $ssl will be converted to corresponding option for openssl,
           #       for example: DTLSv1 becomes -dtlsv1
           # Unfortunately openssl (or Net::SSLinfo) returns a cipher even if
           # the protocoll is not supported. Reason (aka bug) yet unknown.
           # Hence the caller should ensure that openssl supports $ssl .
    }

    $cipher = "" if not defined $cipher;
    if ($cipher =~ m#^\s*$#) {
        my $txt = "SSL version '$ssl': cannot get preferred cipher; ignored";
        # SSLv2 is special, see _usesocket "dirty hack"; don't print
        _v_print($txt) if ($ssl !~ m/SSLv[2]/);
    } else {
        _v2print("preferred cipher: $ssl:\t$cipher");
    }
    _trace("_get_default()\t= $cipher }"); # TODO: trace a bit late
    return $cipher;
} # _get_default

sub _get_data0          {
    #? get %data for connection without SNI
    #  this function currently only returns data for:  cn_nosni, session_ticket
    my ($host, $port) = @_;
    _y_CMD("test without SNI (disable with --no-sni) ...");
    # check if SNI supported, also copy some data to %data0
        # to do this, we need a clean SSL connection with SNI disabled
        # see SSL_CTRL_SET_TLSEXT_HOSTNAME in NET::SSLinfo
        # finally we close the connection to be clean for all other tests
    _trace(" cn_nosni: {");
    _yeast_TIME("no SNI{");
    $Net::SSLinfo::use_SNI  = 0;    # no need to save current value
    if (defined Net::SSLinfo::do_ssl_open(
                    $host, $port,
                    (join(" ", @{$cfg{'version'}})),
                     join(" ", @{$cfg{'ciphers'}}))
       ) {
        _y_CMD("  open with no SNI.");
        _trace(" cn_nosni: method= $Net::SSLinfo::method");
        $data{'cn_nosni'}->{val}        = $data{'cn'}->{val}($host, $port);
        $data0{'session_ticket'}->{val} = $data{'session_ticket'}->{val}($host, $port);
# TODO:  following needs to be improved, because there are multipe openssl
        # calls which may produce unexpected results (10/2015) {
        # 'sort' is used to make tests comparable
        foreach my $key (sort keys %data) { # copy to %data0
            next if ($key =~ m/$cfg{'regex'}->{'commands_int'}/i);
            $data0{$key}->{val} = $data{$key}->{val}($host, $port);
        }
# }
    } else {
        _warn("204: Can't make a connection to '$host:$port' without SNI; no initial data (compare with and without SNI not possible)");
    }
    if (0 < (length Net::SSLinfo::errors())) {
        _warn("203: connection without SNI succeded with errors; errors ignored");
            # fails often with: Error in cipher list; SSL_CTX_set_cipher_list:no cipher match
            # TODO: don't show warning 203 if only this in Net::SSLinfo::errors
        if (0 < ($cfg{'verbose'} + $cfg{'trace'})) {
            _warn("206: $_") foreach Net::SSLinfo::errors();
            # following OK, i.e. if SSLv2 or SSLv3 is not supported:
            #   **WARNING: 206: do_openssl(ciphers localhost) failed: Error in cipher list
            #   ....SSL routines:SSL_CTX_set_cipher_list:no cipher match:ssl_lib.c:1383:
        } else {
            _hint("use '--v' to show more information about Net::SSLinfo::do_ssl_open() errors");
        }
    }
    _yeast_TIME("no SNI}");         # should be before if {}, but also ok here
    # now close connection, which also resets Net::SSLinfo's internal data
    # structure,  Net::SSLinfo::do_ssl_close() is clever enough to work if
    # the connection failed and does nothing (except resetting data)
    Net::SSLinfo::do_ssl_close($host, $port);
    $Net::SSLinfo::use_SNI  = $cfg{'use'}->{'sni'};
    _trace(" cn_nosni: $data{'cn_nosni'}->{val}  }");
    return;
} # _get_data0

sub ciphers_scan_prot   {
    #? test target if given ciphers are accepted, returns array with accepted ciphers
    #? scans for ciphers with given protocol only
    my ($ssl, $host, $port, $arr) = @_;
    my @ciphers = @{$arr};      # ciphers to be checked
    my $version = "";           # returned protocol version
    my $dh      = "";           # returned DH parameters (not yet used)

    _trace("ciphers_scan_prot($ssl, $host, $port, @ciphers){");
    my @res     = ();       # return accepted ciphers
    $cfg{'done'}->{'ssl_failed'} = 0;   # SEE Note:--ssl-error
    _v_print("connect delay: $cfg{'connect_delay'} second(s)") if ($cfg{'connect_delay'} > 0);
    my $cnt     = 0;
    foreach my $c (@ciphers) {
        next if ($c =~ m/^\s*$/);
        my $anf = time();
        my $supported = "";
        $cnt++;
        my $txt = "$ssl: ($cnt of " . scalar(@ciphers) . " ciphers checked) abort connection attempts";
        printf("#   cipher %3d/%d %s%s\r", $cnt, scalar @ciphers, $c, " "x42) if ($cfg{'verbose'} > 0);
            # no \n at end of line, hence all messages print to same line
            # wipe previous trailing text with  " "x42
            # cannot use _v_print() because it prints with \n
        if (0 == $cmd{'extciphers'}) {
            if (0 >= $cfg{'cipher_md5'}) {
                # Net::SSLeay:SSL supports *MD5 for SSLv2 only
                # detailled description see OPTION  --no-cipher-md5
                #_hint("use '--no-cipher-md5' to disable checks with MD5 ciphers");
                _v4print("check cipher (MD5): $ssl:$c\n");
                next if (($ssl ne "SSLv2") && ($c =~ m/MD5/));
            }
            ($version, $supported)      = _usesocket( $ssl, $host, $port, $c);
        } else { # force openssl
            ($version, $supported, $dh) = _useopenssl($ssl, $host, $port, $c);
        }
        $supported = "" if not defined $supported;
        sleep($cfg{'connect_delay'});
        last if (_is_ssl_error($anf, time(), $txt) > 0);
        if (($c !~ /(?:HIGH|ALL)/) and ($supported ne "")) { # given generic names is ok
            if (($c !~ $supported) and ($ssl ne "SSLv2")) {
                # mismatch: name asked for and the name returned by server
                # this may indicate wrong cipher name in our configuration
                # or the server returned no data  or closed TCP connection
                # or connection timed out, see _is_ssl_error()
                # no complain for SSLv2, which may return an empty string
                _warn("411: checked $ssl cipher '$c' does not match returned cipher '$supported'");
            }
        }
        push(@res, "$version:$supported") if ($supported ne "");
        my $yesno = ($supported eq "") ? "no" : "yes";
        _v2print("check cipher: $ssl:$c\t$yesno");
        # TODO: should close dangling sockets here
    } # foreach @ciphers
    _v_print("connection errors: $cfg{'done'}->{'ssl_errors'}                  ");
    #    spaces to overwrite remaining cipher suite names
    _trace("ciphers_scan_prot()\t= " . $#res . " @res }");
    return @res;
} # ciphers_scan_prot

sub ciphers_scan_raw    {
    #? scan target for ciphers for all protocols
    # returns array with accepted ciphers
    my ($host, $port) = @_;
    _trace("ciphers_scan_raw($host, $port){");
    my $total   = 0;
    my $enabled = 0;
    my $_printtitle = 0;    # count title lines; 0 = no ciphers checked
    my $results = {};       # hash with cipher list to be returned
    my $usesni  = $Net::SSLhello::usesni;           # store SNI for recovery later
    my $typ     = "raw";    # used for --trace only
       $typ     = "all" if (_is_cfg_do('cipher_intern'));
    _y_CMD("  use SSLhello +cipher$typ ...");
    foreach my $ssl (@{$cfg{'version'}}) {
        $_printtitle++;
        next if ($cfg{$ssl} == 0);
        if ($usesni >= 1) { # Do not use SNI with SSLv2 and SSLv3
            # SSLv2 has no SNI; SSLv3 has originally no SNI
            # using $Net::SSLhello::usesni instead of $cfg{'usesni'} (even they
            # should be the same) because Net::SSLhello functions are called
            $Net::SSLhello::usesni = $usesni;
            if ($ssl =~ m/^SSLv/) {
                _warn_nosni("409:", $ssl, $usesni);
                $Net::SSLhello::usesni = 0;
            }
        }
        my @accepted = [];  # accepted ciphers (cipher keys)
        my @all = _get_cipherlist_hex($ssl);
        _y_CMD("    checking " . scalar(@all) . " ciphers for $ssl ... (SSLhello)");
        $total += scalar @all;
        if ("@all" =~ /^\s*$/) {
            _warn("407: no valid ciphers specified; no check done for '$ssl'");
            next;           # ensure warning for all protocols
            #return $results;# only one warning
        }
        if (_is_cfg_do('cipher_intern')) {  # may be called for cipher_dump too
            _v_print("cipher range: $cfg{'cipherrange'}, checking " . scalar(@all) . " ciphers ...");
        }
        @accepted = Net::SSLhello::checkSSLciphers($host, $port, $ssl, @all);
        if (_is_cfg_do('cipher_dump')) {
            _v_print(sprintf("total number of accepted ciphers: %4d",
                         (scalar(@accepted) - (scalar(@accepted) >= 2 && ($accepted[0] eq $accepted[1]))) )
                    );
            # correct total number if first 2 ciphers are identical (this
            # indicates cipher order by the server);  delete first one
        }

        # prepare for printing, list, needed for summary checks
        my $last_a  = "";   # avoid duplicates
        foreach my $key (@accepted) {
            next if ($last_a eq $key);
            $results->{$ssl}{$key} = "yes";
            $last_a = $key;
        }
        if (0 < scalar @accepted) {
            my $cipher = OSaft::Ciphers::get_name($accepted[0]) || $STR{UNDEF}; # may return undef
            # SEE Note:+cipherall
            $prot{$ssl}->{'cipher_strong'}  = $cipher;
            $prot{$ssl}->{'default'}        = $cipher;
        }

        # print ciphers
        # NOTE: rest of code (print*()) should be moved to calling place,
        #       but as the variables @all, @accepted are only available here
        #       (or must be computed again), printing is done here      11/2020
        if (_is_cfg_do('cipher') or _is_cfg_do('check')) {
            print_title($legacy, $ssl, $host, $port, $cfg{'out'}->{'header'});
            if (_is_cfg_do('cipher_intern')) {
                $enabled += printcipherall($legacy, $ssl, $host, $port,
                    ($legacy eq "sslscan")?($_printtitle):0, @accepted);
                if ($cfg{'legacy'} =~ m/simple|openssl/) {
                    printf("%-36s\t%s\n", "=   $checks{'cnt_totals'}->{txt}", scalar(@all));
                        # FIXME: should use print_line() instead of hardcoded printf
                }
                next if (scalar @accepted < 1); # defensive programming ..
                #push(@{$prot{$ssl}->{'ciphers_pfs'}}, $c) if ("" ne _is_ssl_pfs($ssl, $c));  # add PFS cipher
            } else {
                Net::SSLhello::printCipherStringArray('compact', $host, $port, $ssl, $Net::SSLhello::usesni, @accepted);
            }
        }
    } # $ssl
    if (1 < $cfg{'trace'}) { # avoid huge verbosity in simple cases
        _trace("ciphers_scan_raw()\t= $results }");
    } else {
        _trace("ciphers_scan_raw()\t= <<result prined with --trave=2>> }");
    }
    return $results;
} # ciphers_scan_raw

sub ciphers_scan        {
    #? scan target for ciphers for all protocols
    # returns hash with accepted ciphers
    my ($host, $port) = @_;
    _trace("ciphers_scan($host, $port){");
# FIXME: 6/2015 es kommt eine Fehlermeldung wenn openssl 1.0.2 verwendet wird:
# Use of uninitialized value in subroutine entry at /usr/share/perl5/IO/Socket/SSL.pm line 562.
# hat mit den Ciphern aus @{$cfg{'ciphers'}} zu tun
#    IDEA-CBC-MD5 RC2-CBC-MD5 DES-CBC3-MD5 RC4-64-MD5 DES-CBC-MD5 :
# Ursache in _usesocket() das benutzt IO::Socket::SSL->new()
    my $cnt = scalar(@{$cfg{'ciphers'}});
    my $results = {};       # hash of cipher list to be returned
    foreach my $ssl (@{$cfg{'version'}}) {
        my $__openssl   = ($cmd{'extciphers'} == 0) ? 'socket' : 'openssl';
        my $usesni  = $cfg{'use'}->{'sni'};
        if (($cfg{'verbose'} + $cfg{'trace'} > 0) or _is_cfg_out('traceCMD')) {
            # optimise output: instead using 3 lines with _y_CMD(), _trace() and _v_print()
            my $_me = "";
               $_me = $cfg{'me'} . "   CMD:" if (_is_cfg_out('traceCMD')); # TODO: _yTIME() missing
               $_me = $cfg{'me'} . "::"      if ($cfg{'trace'}    > 0);
            print("#$_me     checking $cnt ciphers for $ssl ... ($__openssl)");
        }
        if ($ssl =~ m/^SSLv[23]/) {
            # SSLv2 has no SNI; SSLv3 has originally no SNI
            if (_is_cfg_do('cipher') or $cfg{'verbose'} > 0) {
                _warn_nosni("410:", $ssl, $cfg{'use'}->{'sni'});
                # ciphers are collected for various checks, this would result
                # in above warning, even then if  SSLv3 is not needed for the
                # requested check;  to avoid these noicy warnings, it is only
                # printend for  +cipher  command or with --v option
                # NOTE: applies to --ciphermode=openssl|ssleay only
            }
            $cfg{'use'}->{'sni'} = 0; # do not use SNI for this $ssl
        }
        my $__verbose   = $cfg{'verbose'};
            # $cfg{'v_cipher'}  should only print cipher checks verbosely,
            # ciphers_scan_prot()  uses  $cfg{'verbose'}, hence we need to save
            # the current value and reset after calling ciphers_scan_prot()
        $cfg{'verbose'} = 2 if ($cfg{'v_cipher'} > 0);
        my @supported = ciphers_scan_prot($ssl, $host, $port, \@{$cfg{'ciphers'}});
        $cfg{'verbose'} = $__verbose if ($__verbose != 2);
        # remove  protocol: in each item
        #foreach my $i (keys @supported) { $supported[$i] =~ s/^[^:]*://; } # for Perl > 5.12
        for my $i (0..$#supported) { $supported[$i] =~ s/^[^:]*://; }       # for Perl < 5.12 and Perl::Critic
            # map({s/^[^:]*://} @supported); # is the perlish way (all Perl 5.x)
            # but discarted by Perl::Critic, hence the less readable for loop
        # now build line in %results
        foreach my $cipher (@{$cfg{'ciphers'}}) {  # might be done more perlish ;-)
            my $key = OSaft::Ciphers::get_key($cipher);
            $results->{$ssl}{$key} = ((grep{/^$cipher$/} @supported)>0) ? "yes" : "no";
        }
        $cfg{'use'}->{'sni'} = $usesni;
    } # $ssl
    if (1 < $cfg{'trace'}) { # avoid huge verbosity in simple cases
        _trace("ciphers_scan()\t= $results }");
    } else {
        _trace("ciphers_scan()\t= <<result prined with --trave=2>> }");
    }
    return $results;
} # ciphers_scan

sub check_certchars     {
    #? check for invalid characters in certificate
    my ($host, $port) = @_;
    _y_CMD("check_certchars() ". $cfg{'done'}->{'check_certchars'});
    $cfg{'done'}->{'check_certchars'}++;
    return if (1 < $cfg{'done'}->{'check_certchars'});
    my $value;
    my $txt;

    # check vor invald charaters
    foreach my $label (@{$cfg{'need-checkchr'}}, qw(email aux)) {
        $value = $data{$label}->{val}($host);
        if ($value ne "") {
            $checks{'nonprint'}->{val} .= " $label" if ($value =~ m/$cfg{'regex'}->{'nonprint'}/);
            $checks{'crnlnull'}->{val} .= " $label" if ($value =~ m/$cfg{'regex'}->{'crnlnull'}/);
        }
    }

    # valid characters (probably only relevant for DV and EV)
    #_dbx "EV: keys: " . join(" ", @{$cfg{'need-checkchr'}} . "extensions";
    #_dbx "EV: regex:" . $cfg{'regex'}->{'notEV-chars'};
    # not checked explicitly: CN, O, U (should already be part of others, like subject)
    foreach my $label (@{$cfg{'need-checkchr'}}, qw(extensions)) {
        $value =  $data{$label}->{val}($host);
        $value =~ s#[\r\n]##g;         # CR and NL are most likely added by openssl
        if ($value =~ m/$cfg{'regex'}->{'notEV-chars'}/) {
            $txt = _get_text('cert_chars', $label);
            $checks{'ev_chars'}->{val} .= $txt;
            $checks{'ev+'}->{val}      .= $txt;
            $checks{'ev-'}->{val}      .= $txt;
            $checks{'dv'}->{val}       .= $txt;
             if ($cfg{'verbose'} > 0) {
                 $value =~ s#($cfg{'regex'}->{'EV-chars'}+)##msg;
                 _v2print("EV:  wrong characters in $label: $value");
             }
        }
    }

    return;
} # check_certchars

sub check_dh            {
    #? check if target is vulnerable to Logjam attack; uses \$cipher_results
    my ($host, $port) = @_;
    _y_CMD("check_dh() ". $cfg{'done'}->{'check_dh'});
    $cfg{'done'}->{'check_dh'}++;
    return if (1 < $cfg{'done'}->{'check_dh'});

    # Logjam check is a bit ugly: DH Parameter may be missing
    # TODO: implement own check for DH parameters instead relying on openssl
    my $txt = $data{'dh_parameter'}->{val}($host);
    if ($txt eq "") {
        $txt = "<<openssl did not return DH Paramter>>";
        checkciphers($host, $port, $cipher_results); # need EXPORT ciphers for logjam
        # TODO: calling checkciphers() is bad, it may even not contain ciphers
        my $exp = $checks{'logjam'}->{val};
        $checks{'logjam'}->{val}   .=  $txt;
        $checks{'logjam'}->{val}   .=  "; but has WEAK ciphers: $exp" if ($exp ne "");
        $checks{'dh_512'}->{val}    =  $txt;
        $checks{'dh_2048'}->{val}   =  $txt;
        $checks{'ecdh_256'}->{val}  =  $txt;
        $checks{'ecdh_512'}->{val}  =  $txt;
        return; # no more checks possible
    }
    my $dh  = $txt;
       $dh  =~ s/.*?[^\d]*(\d+) *bits.*/$1/i;   # just get number
       # DH, 512 bits
       # DH, 1024 bits
       # DH, 2048 bits
       # ECDH, P-256, 128 bits
       # ECDH, P-256, 256 bits
       # ECDH, P-384, 384 bits
       # TODO: ECDH should also have 256 bits or more
    if ($dh =~ m/^\d+$/) {      # a number, check size
        if ($txt !~ m/ECDH/) {
            $checks{'dh_512'}->{val}    =  $txt if ($dh < 512);
            $checks{'dh_2048'}->{val}   =  $txt if ($dh < 2048);
        } else {                # ECDH is different
            $checks{'ecdh_256'}->{val}  =  $txt if ($dh < 256);
            $checks{'ecdh_512'}->{val}  =  $txt if ($dh < 512);
        }
        # lazy check: logjam if bits < 256 only
        my $val = $checks{'dh_512'}->{val} . $checks{'dh_2048'}->{val} . $checks{'ecdh_256'}->{val};
        $checks{'logjam'}->{val} = $val if ($val ne "");
    } else {                    # not a number, probably suspicious
        $checks{'logjam'}->{val}=  $txt;
    }
    return;
} # check_dh

sub check_url           {
    #? request given URL and check if it is a valid CRL or OCSP site
    #? returns result of check; empty string if anything OK
    my ($uri, $type) = @_;      # type is 'ext_crl' or 'ocsp_uri'
   _y_CMD("check_url() ". $cfg{'done'}->{'check_url'});
    $cfg{'done'}->{'check_url'}++;
    _trace("check_url($uri, $type)");

    return " " if ($uri =~ m#^\s*$#);   # no URI, no more checks

    # Net::SSLeay::get_http() is used as we already include Net::SSLeay
    # NOTE: must be rewritten if Net::SSLeay is removed

    # NOTE: all following examples show only the headers checked herein
    # for CRL  we expect something like:
    # example: http://crl.entrust.net/level1k.crl
    #     HTTP/1.1 200 OK
    #     Accept-Ranges: bytes
    #     Content-Type: application/x-pkcs7-crl
    #     Content-Length: 1101367
    #
    # example: http://pki.google.com/GIAG2.crl
    #     HTTP/1.1 200 OK
    #     Accept-Ranges: none
    #     Transfer-Encoding: chunked
    #     Content-Type: application/pkix-crl
    #
    # bad example: http://pki.google.com
    #     HTTP/1.1 200 OK
    #     Accept-Ranges: none
    #     Transfer-Encoding: chunked
    #     Content-Type: text/html
    #
    # example: http://crl.startssl.com/crt2-crl.crl
    #     HTTP/1.1 200 OK
    #     Accept-Ranges: bytes
    #     Content-Type: application/pkix-crl
    #     Content-Length: 58411
    #
    # example: http://mscrl.microsoft.com/pki/mscorp/crl/msitwww2.crl
    #     HTTP/1.1 200 OK
    #     Content-Type: application/pkix-crl
    #     Content-Length: 179039
    #     Accept-Ranges: bytes
    #
    # for OCSP we expect something like:
    # example: http://sr.symcd.com
    #     HTTP/1.1 200 OK
    #     Content-Type: application/ocsp-response
    #     Content-Length: 5
    #     content-transfer-encoding: binary
    #
    # example (?/2019): http://sr.symcb.com/sr.crl
    #     HTTP/1.1 200 OK
    #     Content-Type: application/pkix-crl
    #     Transfer-Encoding:  chunked
    #     Connection: Transfer-Encoding
    #
    # example (12/2020): http://sr.symcb.com/sr.crl
    #     HTTP/1.1 200 OK
    #     Content-Type: application/x-pkcs7-crl
    #     Content-Length: 540
    #
    # example (12/2020): http://ocsp.msocsp.com
    #     HTTP/1.1 200 OK
    #     Content-Type: application/ocsp-response
    #     Content-Length: 5
    #
    # example (3/2021): http://r3.i.lencr.org
    #     HTTP/1.1 200 OK
    #     Content-Type: application/pkix-cert
    #     Content-Length: 1129
    #
    # bad example (12/2020): http://clients1.google.com/ocsp
    #     HTTP/1.1 404 Not Found
    #     Date: Sun, 17 Apr 2016 10:24:46 GMT
    #     Server: ocsp_responder
    #     Content-Type: text/html; charset=UTF-8
    #     Content-Length: 1565
    #
    # bad example (12/2020): http://ocsp.entrust.net
    #     HTTP/1.1 200 OK
    #     Content-Length: 0
    #
    # bad example (??/2019): http://ocsp.entrust.net
    #     HTTP/1.1 200 OK
    #     Content-Type: text/html
    #     Content-Length: 68
    #
    #     meta HTTP-EQUIV="REFRESH" content="0; url=http://www.entrust.net">
    #
    # bad example (12/2020): http://ocsp.pki.goog/gts1o1core
    # bad example (12/2020): http://ocsp.pki.goog/
    #     HTTP/1.1 404 Not Found
    #     Server: ocsp_responder
    #     Content-Type: text/html; charset=UTF-8
    #     Content-Length: 1561
    #
    # for AIA we expect something like:
    # example: http://www.microsoft.com/pki/mscorp/msitwww2.crt
    #      HTTP/1.1 200 OK
    #      Accept-Ranges: bytes
    #      Content-Type: application/x-x509-ca-cert
    #      Content-Length: 1418
    #

    my ($accept, $binary, $ctype, $chunk, $length);
    my $txt = "<<unexpected type: $type>>"; # this is a programming error
    my $src = 'Net::SSLeay::get_http()';
    # got an URI, extract host, port and URL
       $uri =~ m#^\s*(?:(?:http|ldap)s?:)?//([^/]+)(/.*)?$#;
      #  NOTE: it's ok here
    my $host=  $1;                          ## no critic qw(RegularExpressions::ProhibitCaptureWithoutTest)
    my $url =  $2 || "/";                   ## no critic qw(RegularExpressions::ProhibitCaptureWithoutTest)
    return "" if not defined $host;         # wrong URI may be passed
       $host=~ m#^([^:]+)(?::[0-9]{1,5})?#;
       $host=  $1;                          ## no critic qw(RegularExpressions::ProhibitCaptureWithoutTest)
    my $port=  $2 || 80;  $port =~ s/^://;  ## no critic qw(RegularExpressions::ProhibitCaptureWithoutTest)
    # TODO: add 'Authorization:'=>'Basic ZGVtbzpkZW1v',
    # NOTE: Net::SSLeay always sets  Accept:*/*

    _trace2("check_url: use_http " . _is_cfg_use('http'));
    _trace2("check_url: get_http($host, $port, $url)");
    my ($response, $status, %headers) = Net::SSLeay::get_http($host, $port, $url,
            Net::SSLeay::make_headers(
                'Host'       => $host,
                'Connection' => 'close',
            )
    );
    _trace2("check_url: STATUS= $status");

    if ($status !~ m#^HTTP/... (?:[1234][0-9][0-9]|500) #) {
        return "<<connection to '$host:$port$url' failed>>";
    }
    _trace2("check_url: header= #{ " .  join(": ", %headers) . " }"); # a bit ugly :-(
    if ($status =~ m#^HTTP/... 200 #) {
        $accept = $headers{(grep{/^Accept-Ranges$/i}     keys %headers)[0] || ""}  || " ";
        $ctype  = $headers{(grep{/^Content-Type$/i}      keys %headers)[0] || ""}  || " ";
        $length = $headers{(grep{/^Content-Length$/i}    keys %headers)[0] || ""}  || "-1";
        $binary = $headers{(grep{/^Content-transfer-encoding$/i} keys %headers)[0] || ""};
        $chunk  = $headers{(grep{/^Transfer-Encoding$/i} keys %headers)[0] || ""}  || " ";
        _trace2("check_url: length=$length, accept=$accept, ctype=$ctype");
    } else {
        return _get_text('unexpected', "response from '$host:$port$url': $status");
        # FIXME: 30x status codes are ok; we should then call ourself again
    }

    if ($type eq 'ocsp_uri') {
        _trace2("check_url: ocsp_uri ...");
        return  _get_text('invalid', "Content-Type: $ctype")    if ($ctype !~ m:application/ocsp-response:i);
        return  _get_text('invalid', "Content-Length: $length") if ($length < 4);
        return ""; # valid
    } # OCSP

    if ($type eq 'ext_crl') {
        _trace2("check_url: ext_crl ...");
        if ((defined $accept) && (defined $chunk)) {
            if ($accept !~ m/bytes/i) {
                if (($accept !~ m/^none/i) && ($chunk !~ m/^chunked/i)) {
                    return _get_text('invalid', "Accept-Ranges: $accept");
                }
            }
        }
#if ($ctype !~ m#application/(?:pkix-cert|pkcs7-mime)#i)   # for CA Issuers; see rfc5280#section-4.2.1.13
        if ($ctype !~ m#application/(?:pkix-crl|x-pkcs7-crl)#i) {
                return _get_text('invalid', "Content-Type: $ctype");
        }
        return "";      # valid
    } # CRL

    return $txt;
} # check_url

sub check_nextproto     {
    #? check target for ALPN or NPN support; returns list of supported protocols
    my ($host, $port, $type, $mode) = @_;
    # $type is ALPN or NPN; $mode is all or single
    # in single mode, each protocol specified in $cfg{'protos_next'} is tested
    # for its own, while in all mode all protocols are set at once
    # Also SEE Note:ALPN, NPN
    _trace("check_nextproto($host, $port, $type, $mode){");
    my @protos = split(",", $cfg{'protos_next'});
       @protos = $cfg{'protos_next'}   if ($mode eq 'all'); # pass all at once
    my @npn;
    my ($ssl, $ctx, $method);
    my $socket; # = undef;
    foreach my $proto (@protos) {
        #_trace("  do_ssl_new(..., ".(join(" ", @{$cfg{'version'}}))
        #     . ", $cfg{'cipherpattern'}, $proto, $proto, socket)");
        $ssl   = undef;
        $ctx   = undef;
        $socket= undef;
        ($ssl, $ctx, $socket, $method) = Net::SSLinfo::do_ssl_new(
                $host, $port,
                (join(" ", @{$cfg{'version'}})), $cfg{'cipherpattern'},
                (($type eq 'ALPN') ? $proto : ""),
                (($type eq 'NPN')  ? $proto : ""),
                $socket
            );
        if (not defined $ssl) {
            _warn("601: $type connection failed with '$proto'");
        } else {
            # Net::SSLeay's functions are crazy, both P_next_proto_negotiated()
            # and P_alpn_selected() return undef if not supported by server and
            # for any error. Anyway, we only want to know if $proto supported.
            # As we check protocols one by one, this information is sufficient.
            my $np;
            $np = Net::SSLeay::P_alpn_selected($ssl)         if ($type eq 'ALPN');
            $np = Net::SSLeay::P_next_proto_negotiated($ssl) if ($type eq 'NPN');
            if (defined $np && $mode eq 'single') {
                _warn("602: $type name mismatch: (send) $proto <> $np (returned)")  if ($proto ne $np);
            }
            _trace("check_nextproto: $type $np") if (defined $np) ;
            if (defined $np) {
                push(@npn, $np) if ($proto eq $np); # only if matched
            }
        }
        # TODO: need to check if ($cfg{'socket_reuse'} > 0); then do not call do_ssl_free
        Net::SSLinfo::do_ssl_free($ctx, $ssl, $socket);
        #{
        #TODO: if ($cfg(extopenssl) > 0)
        #my $data = Net::SSLinfo::do_openssl("s_client -alpn $proto -connect", $host, $port, "");
        #my $np = grep{/^ALPN protocol:.*/} split("\n", $data);
        #my $data = Net::SSLinfo::do_openssl("s_client -nextprotoneg $proto -connect", $host, $port, "");
        #my $np = grep{/^Next protocol:.*/} split("\n", $data);
        #my $np = grep{/^Protocols advertised by:.*/} split("\n", $data);
        #print "$proto : $np";
        #}
    }
    _trace("check_nextproto()\t= @npn }");
    return @npn;
} # check_nextproto

sub checkalpn           {
    #? check target for ALPN or NPN support; returns void
    # stores list of supported protocols in corresponding $info{}
    # uses protocols from $cfg{'protos_next'} only
    my ($host, $port) = @_;
    _y_CMD("checkalpn($host,$port) ");
    $cfg{'done'}->{'checkalpn'}++;
    return if (1 < $cfg{'done'}->{'checkalpn'});
    # _trace("trace not necessary, output from check_nextproto() is sufficient");
    if ($cfg{'ssleay'}->{'get_alpn'} > 0) {
        $info{'alpns'} = join(",", check_nextproto($host, $port, 'ALPN', 'single'));
        $info{'alpn'}  = join(",", check_nextproto($host, $port, 'ALPN', 'all'));
    }
    # else warning already printed
    if ($cfg{'ssleay'}->{'get_npn'} > 0) {
        $info{'npns'}  = join(",", check_nextproto($host, $port, 'NPN',  'single'));
        $info{'npn'}   = join(",", check_nextproto($host, $port, 'NPN',  'all'));
    }
    # else warning already printed
    # TODO: 'next_protocols' should be retrieved here too
    return;
} # checkalpn

sub checkpreferred      {
    #? test if target prefers strong ciphers, aka SSLHonorCipherOrder
    my ($host, $port) = @_;     # not yet used
    _y_CMD("checkpreferred() " . $cfg{'done'}->{'checkpreferred'});
    $cfg{'done'}->{'checkpreferred'}++;
    return if (1 < $cfg{'done'}->{'checkpreferred'});
    _trace("checkpreferred($host, $port){");
    foreach my $ssl (@{$cfg{'version'}}) {      # check all SSL versions
        my $strong = $prot{$ssl}->{'cipher_strong'};
        my $weak   = $prot{$ssl}->{'cipher_weak'};
        my $txt = ($weak ne $strong) ? _prot_cipher($ssl, "$strong,$weak") : "";
        $checks{'cipher_strong'}->{val} .= $txt;  # assumtion wrong if only one cipher accepted
        $checks{'cipher_order'}->{val}  .= $txt;  # NOT YET USED
        $checks{'cipher_weak'}->{val}   .= $txt;  # remember: eq !
        if ($weak eq $strong) {
            # FIXME: assumtion wrong if target returns always strongest cipher;
            #        meanwhile print hint (set hint here, printed later)
            _cfg_set('CFG-hint', 'cipher_weak=check if "weak" cipher was returned may be misleading if the strongest cipher is returned always');
        }
    }
    _trace("checkpreferred() }");
    return;
} # checkpreferred

sub checkcipher         {
    #? test given cipher and add result to %checks and %prot
    my ($ssl, $key) = @_;
    my $c    = OSaft::Ciphers::get_name($key);  # $cipher = $c;
    my $risk = OSaft::Ciphers::get_sec($key);
    _trace("checkcipher($host, $port){");
    # check weak ciphers
    $checks{'cipher_null'}->{val}  .= _prot_cipher($ssl, $c) if ($c =~ /NULL/);
    $checks{'cipher_adh'}->{val}   .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'ADHorDHA'}/);
    $checks{'cipher_exp'}->{val}   .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'EXPORT'}/);
    $checks{'cipher_cbc'}->{val}   .= _prot_cipher($ssl, $c) if ($c =~ /CBC/);
    $checks{'cipher_des'}->{val}   .= _prot_cipher($ssl, $c) if ($c =~ /DES/);
    $checks{'cipher_rc4'}->{val}   .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'RC4orARC4'}/);
    $checks{'cipher_edh'}->{val}   .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'DHEorEDH'}/);
# TODO: lesen: http://www.golem.de/news/mindeststandards-bsi-haelt-sich-nicht-an-eigene-empfehlung-1310-102042.html
    # check compliance
    $checks{'ism'}      ->{val}    .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'notISM'}/);
    $checks{'pci'}      ->{val}    .= _prot_cipher_or_empty($ssl, _is_ssl_pci(  $ssl, $c));
    $checks{'fips'}     ->{val}    .= _prot_cipher_or_empty($ssl, _is_ssl_fips( $ssl, $c));
    $checks{'rfc_7525'} ->{val}    .= _prot_cipher_or_empty($ssl, _is_rfc7525(  $ssl, $c));
    $checks{'tr_02102+'}->{val}    .= _prot_cipher_or_empty($ssl, _is_tr02102_strict($ssl, $c));
    $checks{'tr_02102-'}->{val}    .= _prot_cipher_or_empty($ssl, _is_tr02102_lazy(  $ssl, $c));
    $checks{'tr_03116+'}->{val}    .= _prot_cipher_or_empty($ssl, _is_tr03116_strict($ssl, $c));
    $checks{'tr_03116-'}->{val}    .= _prot_cipher_or_empty($ssl, _is_tr03116_lazy(  $ssl, $c));
    # check attacks
    $checks{'rc4'}      ->{val}     = $checks{'cipher_rc4'}->{val}; # these are the same checks
    $checks{'beast'}    ->{val}    .= _prot_cipher_or_empty($ssl, _is_ssl_beast($ssl, $c));
    $checks{'breach'}   ->{val}    .= _prot_cipher_or_empty($ssl, _is_ssl_breach($c));
    $checks{'freak'}    ->{val}    .= _prot_cipher_or_empty($ssl, _is_ssl_freak($ssl, $c));
    $checks{'lucky13'}  ->{val}    .= _prot_cipher_or_empty($ssl, _is_ssl_lucky($c));
    $checks{'robot'}    ->{val}    .= _prot_cipher_or_empty($ssl, _is_ssl_robot($ssl, $c));
    $checks{'sloth'}    ->{val}    .= _prot_cipher_or_empty($ssl, _is_ssl_sloth($ssl, $c));
    $checks{'sweet32'}  ->{val}    .= _prot_cipher_or_empty($ssl, _is_ssl_sweet($ssl, $c));
    push(@{$prot{$ssl}->{'ciphers_pfs'}}, $c) if ("" ne _is_ssl_pfs($ssl, $c));  # add PFS cipher
    # counters
    $prot{$ssl}->{'-?-'}++         if ($risk =~ /-\?-/);   # private marker
    $prot{$ssl}->{'WEAK'}++        if ($risk =~ /WEAK/i);
    $prot{$ssl}->{'LOW'}++         if ($risk =~ /LOW/i);
    $prot{$ssl}->{'MEDIUM'}++      if ($risk =~ /MEDIUM/i);
    $prot{$ssl}->{'HIGH'}++        if ($risk =~ /HIGH/i);
    $risk = osaft::get_cipher_owasp($c);
    $prot{$ssl}->{'OWASP_miss'}++  if ($risk eq 'miss');
    $prot{$ssl}->{'OWASP_NA'}++    if ($risk eq '-?-');
    $prot{$ssl}->{'OWASP_D'}++     if ($risk eq 'D');
    $prot{$ssl}->{'OWASP_C'}++     if ($risk eq 'C');
    $prot{$ssl}->{'OWASP_B'}++     if ($risk eq 'B');
    $prot{$ssl}->{'OWASP_A'}++     if ($risk eq 'A');
    _trace("checkcipher() }");
    return;
} # checkcipher

sub _checkcipher_init   {
    # initialise $check{...}-{val} with empty string, because they will be
    # extended per $ssl (protocol)
    foreach my $key (qw(
        cipher_null cipher_adh cipher_exp cipher_cbc cipher_des cipher_rc4
        cipher_edh ciphers_pfs cipher_pfsall
        beast breach freak logjam lucky13 rc4 robot sloth sweet32
        ism pci fips rfc_7525 tr_02102+ tr_02102- tr_03116+ tr_03116-
    )) {
        $checks{$key}->{val} = "";
    }
    return;
} # _checkcipher_init

sub checkciphers        {
    #? test target if given ciphers are accepted, results stored in global %checks
    my ($host, $port, $results) = @_;

    _y_CMD("checkciphers() " . $cfg{'done'}->{'checkciphers'});
    $cfg{'done'}->{'checkciphers'}++;
    return if (1 < $cfg{'done'}->{'checkciphers'});
    _trace("checkciphers($host, $port){");

    _checkcipher_init();        # values are set to <<undefined>>, initialise with ""
    if (1 > scalar %$results) { # no ciphers found; avoid misleading values
        foreach my $key (@{$cfg{'need-cipher'}}) {
            if ($key =~ m/(drown|poodle|has(?:ssl|tls))/) {
                # keep "disabled ..." message if corresponding -no-SSL option was used
                next if ($checks{$key}->{val} !~ m/$text{'undef'}/);
            }
            $checks{$key}->{val} = _get_text('miss_cipher', "");
        }
        foreach my $ssl (@{$cfg{'version'}}) {  # check all SSL versions
            @{$prot{$ssl}->{'ciphers_pfs'}} = _get_text('miss_cipher', "");
        }
        _trace("checkciphers() }");
        return;
    }

    my %hasecdsa;   # ECDHE-ECDSA is mandatory for TR-02102-2, see 3.2.3
    my %hasrsa  ;   # ECDHE-RSA   is mandatory for TR-02102-2, see 3.2.3
    foreach my $ssl (sort keys %$results) { # check all accepted ciphers
      next if not $results->{$ssl};         # defensive programming .. (unknown how this can happen)
      foreach my $key (sort keys %{$results->{$ssl}}) {
        # SEE Note:Testing, sort
        next if ($key =~ m/^\s*$/);         # defensive programming (key missing in %ciphers)
        next if not $results->{$ssl}{$key}; # defensive programming ..
        my $yesno  = $results->{$ssl}{$key};
        my $cipher = OSaft::Ciphers::get_name($key);
        if (($cipher =~ m/^\s*$/) || ($yesno =~ m/^\s*$/)) {
            # defensive programming .. probably programming error
            _warn("420: empty value for $key => '$cipher: [$yesno]'; check ignored");
            next;
        }
        if ($yesno =~ m/yes/i) {    # cipher accepted
            $prot{$ssl}->{'cnt'}++;
            checkcipher($ssl, $key);
            $checks{'logjam'}->{val}   .= _prot_cipher_or_empty($ssl, _is_ssl_logjam($ssl, $cipher));
        }
        $hasrsa{$ssl}   = 1 if ($cipher =~ /$cfg{'regex'}->{'EC-RSA'}/);
        $hasecdsa{$ssl} = 1 if ($cipher =~ /$cfg{'regex'}->{'EC-DSA'}/);
      }
    }

    # additional BEAST check: checks for vulnerable protocols are disabled?
    my $beastskipped = _isbeastskipped($host, $port);
    $checks{'beast'}->{val} .= " " . ${beastskipped} if "" ne $beastskipped;

    $checks{'breach'}->{val} = "<<NOT YET IMPLEMENTED>>";

    my $cnt_pfs = 0;
    foreach my $ssl (@{$cfg{'version'}}) {      # check all SSL versions
        $cnt_pfs   += scalar @{$prot{$ssl}->{'ciphers_pfs'}};
        $hasrsa{$ssl}  = 0 if not defined $hasrsa{$ssl};    # keep Perl silent
        $hasecdsa{$ssl}= 0 if not defined $hasecdsa{$ssl};  #  -"-
        # TR-02102-2, see 3.2.3
        if ($prot{$ssl}->{'cnt'} > 0) { # checks do not make sense if there're no ciphers
            $checks{'tr_02102+'}->{val} .= _prot_cipher($ssl, $text{'miss_RSA'})   if ($hasrsa{$ssl}   != 1);
            $checks{'tr_02102+'}->{val} .= _prot_cipher($ssl, $text{'miss_ECDSA'}) if ($hasecdsa{$ssl} != 1);
            $checks{'tr_03116+'}->{val} .= $checks{'tr_02102+'}->{val}; # same as TR-02102
            $checks{'tr_03116-'}->{val} .= $checks{'tr_02102-'}->{val}; # -"-
        }
        $checks{'cnt_ciphers'}  ->{val} += $prot{$ssl}->{'cnt'};    # need this with cnt_ prefix
    }
    $checks{'cipher_edh'}->{val} = "" if ($checks{'cipher_edh'}->{val} ne "");  # good if we have them

    # we need our well known string, hence 'sslversion'; SEE Note:Selected Protocol
#    $ssl    = $data{'sslversion'}->{val}($host, $port);     # get selected protocol
#    $cipher = $data{'cipher_selected'}->{val}($host, $port);# get selected cipher
    # TODO: $checks{'cipher_pfs'}->{val} = (1 > $cnt_pfs) ? " " : "";

    $checks{'cipher_pfsall'}->{val} = ($checks{'cnt_ciphers'}->{val} > $cnt_pfs) ? " " : "";
    $checks{'cipher_pfsall'}->{val} = $text{'na'} if (1 > $checks{'cnt_ciphers'});
    _trace("checkciphers() }");
    return;
} # checkciphers

sub checkbleed($$)  {
    #? check if target supports vulnerable TLS extension 15 (hearbeat)
    # SEE Note:heartbleed
    my ($host, $port) = @_;
    _y_CMD("checkbleed() ". $cfg{'done'}->{'checkbleed'});
    $cfg{'done'}->{'checkbleed'}++;
    return if (1 < $cfg{'done'}->{'checkbleed'});
    my $bleed = _is_ssl_bleed($host, $port);
    if ($cfg{'ignorenoreply'} > 0) {
        return if ($bleed =~ m/no reply/);
    }
    $checks{'heartbleed'}->{val}  = $bleed;
    return;
} # checkbleed

sub checkdates($$)  {
    # check validation of certificate's before and after date
    my ($host, $port) = @_;
    _y_CMD("checkdates() " . $cfg{'done'}->{'checkdates'});
    $cfg{'done'}->{'checkdates'}++;
    return if (1 < $cfg{'done'}->{'checkdates'});
    _trace("checkdates($host, $port){");

    # NOTE: all $data{'valid_*'} are values, not functions

    my $before= $data{'before'}->{val}($host, $port);
    my $after = $data{'after'} ->{val}($host, $port);
    my @since = split(/ +/, $before);
    my @until = split(/ +/, $after);
    if ("$before$after" =~ m/^\s*$/) {
        # if there's no data from the certificate, set undef values and return
        $checks{'dates'}->{val}         = $text{'na'};
        $checks{'expired'}->{val}       = $text{'na'};
        $checks{'sts_expired'}->{val}   = $text{'na'};
        $checks{'valid_years'}->{val}   = 0;
        $checks{'valid_months'}->{val}  = 0;
        $checks{'valid_days'}->{val}    = 0;
        _trace("checkdates() }");
        return;
    }

   # Note about calculating dates:
   # Calculation should be done without using additional Perl modules like
   #   Time::Local, Date::Calc, Date::Manip, ...
   # Hence we convert dates given by the certificate's before and after value
   # to the format  YYYYMMDD.  The format given in the certificate  is always
   # GMT and in fixed form: MMM DD hh:mm:ss YYYY GMT. So a split() gives year
   # and day as integer.  Just the month is a string, which must be converted
   # to an integer using the map() function on @mon array.
   # The same format is used for the current date given by gmtime(), but
   # convertion is much simpler as no strings exist here.
    my @now = gmtime(time);
    my @mon = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my $m   = 0;
    my $s_mon = 0; my $u_mon = 0;
    if (@since) { my $dum = map({$m++; $s_mon=$m if/$since[0]/} @mon); $m = 0; }
    if (@until) { my $dum = map({$m++; $u_mon=$m if/$until[0]/} @mon); $m = 0; }
        # my $dum =   keeps Perl::Critic happy
    my $now   = sprintf("%4d%02d%02d", $now[5]+1900, $now[4]+1, $now[3]);
    my $start = sprintf("%s%02s%02s",  $since[3], $s_mon, $since[1]);
    my $end   = sprintf("%s%02s%02s",  $until[3], $u_mon, $until[1]);
    my $txt   = "";
    # end date magic, do checks ..
    $checks{'dates'}->{val}         =          $before if ($now < $start);
    $checks{'dates'}->{val}        .= " .. " . $after  if ($now > $end);
    $checks{'expired'}->{val}       =          $after  if ($now > $end);
    $data{'valid_years'}->{val}     = ($until[3]       -  $since[3]);
    $data{'valid_months'}->{val}    = ($until[3] * 12) - ($since[3] * 12) + $u_mon - $s_mon;
    $data{'valid_days'}->{val}      = ($data{'valid_years'}->{val}  *  5) + ($data{'valid_months'}->{val} * 30); # approximately
    $data{'valid_days'}->{val}      = ($until[1] - $since[1]) if ($data{'valid_days'}->{val} < 60); # more accurate

    # The current timestamp is added to the  STS max-age  to check if the STS
    # max-age exceeds the certificate's expire date. All timestamps are given
    # in epoch timestamp format.
    # The  after  value from the certificate must be converted to epoch time-
    # stamp format, and then can be compared to STS max-age.
    # Unfortunately there exist  no simple method to convert a human readable
    # timestamps (like certificate's  after) into epoch timestamp format.
    # Perl's  Time::Local module is used for that in the hope that it is part
    # of most Perl installations. Existance of Time::Local module was already
    # done at startup (see _warn 112:).
    # SEE Perl:import include
    MAXAGE_CHECK: {
        $txt = $text{'na_STS'};
        last MAXAGE_CHECK if ($data{'https_sts'}->{val}($host) eq "");
        $txt = $STR{UNDEF};
        last MAXAGE_CHECK if (not _is_cfg_do('sts_expired'));
        $txt = "";
        $now = time();  # we need epoch timestamp here
        my $maxage = $data{'hsts_maxage'}->{val}($host);
        my $ts = "@until";
        if (exists &Time::Local::timelocal) {
            # compute epoch timestamp from 'after', example: Feb 16 10:23:42 2012 GMT
            $ts = Time::Local::timelocal(reverse(split(/:/, $until[2])), $until[1], $u_mon - 1, $until[3]);
            $txt = "$now + $maxage > $ts" if ($now + $maxage > $ts);
        } else {
            $txt = "$now + $maxage > $ts ??";
        }
    }
    $checks{'sts_expired'} ->{val}  = $txt;

    _trace("checkdates: start, now, end= $start, $now, $end");
    _trace("checkdates: valid       = " . $checks{'dates'}->{val});
    _trace("checkdates: valid-years = " . $data{'valid_years'}->{val});
    _trace("checkdates: valid-month = " . $data{'valid_months'}->{val} . "  = ($until[3]*12) - ($since[3]*12) + $u_mon - $s_mon");
    _trace("checkdates: valid-days  = " . $data{'valid_days'}->{val}   . "  = (" . $data{'valid_years'}->{val} . "*5) + (" . $data{'valid_months'}->{val} . "*30)");
    _trace("checkdates() }");
    return;
} # checkdates

sub checkcert($$)   {
    #? check certificate settings
    my ($host, $port) = @_;
    my ($value, $label);
    _y_CMD("checkcert() " . $cfg{'done'}->{'checkcert'});
    $cfg{'done'}->{'checkcert'}++;
    return if (1 < $cfg{'done'}->{'checkcert'});
    _trace("checkcert($host, $port){");

    # wildcards (and some sizes)
    _checkwildcard($host, $port);
    # $checks{'certfqdn'}->{val} ... done in checksni()

    $checks{'rootcert'}->{val}  = $data{'issuer'}->{val}($host) if ($data{'subject'}->{val}($host) eq $data{'issuer'}->{val}($host));
    $checks{'ocsp_uri'}->{val}  = " " if ($data{'ocsp_uri'}->{val}($host) eq "");
    $checks{'cps'}->{val}       = " " if ($data{'ext_cps'}->{val}($host)  eq "");
    $checks{'crl'}->{val}       = " " if ($data{'ext_crl'}->{val}($host)  eq "");

    if (_is_cfg_use('http')) {
        # at least 'ext_crl' may contain more than one URL
        $checks{'crl_valid'}->{val} = "";
        $value = $data{'ext_crl'}->{val}($host);
        if ($value eq '<<openssl>>') {  # TODO: <<openssl>> from Net::SSLinfo
            $checks{'crl_valid'}->{val} = $text{'na_openssl'};
        } else {
            _trace("ext_crl: $value");  # may have something other than http://...
            foreach my $url (split(/\s+/, $value)) {
                next if ($url =~ m/^\s*$/);     # skip empty url
                if ($url !~ m/^\s*http$/) {
                    _trace("ext_uri skipped: $url");
                    next;
                }
                $checks{'crl_valid'}->{val}  .= check_url($url, 'ext_crl') || "";
            }
        }
    } else {
        $checks{'crl_valid'}->{val} = _get_text('disabled', "--no-http");
    }
    # NOTE: checking OCSP is most likely with http: ; done even if --no-http in use
    if ($checks{'ocsp_uri'}->{val} eq '') {
        $checks{'ocsp_valid'}->{val} = "";
        $value = $data{'ocsp_uri'}->{val}($host);
        if ($value eq '<<openssl>>') {
            $checks{'crl_valid'}->{val} = $text{'na_openssl'};
        } else {
            _trace("ocsp_uri: $value");
            foreach my $url (split(/\s+/, $value)) {
                next if ($url =~ m/^\s*$/);     # skip empty url
                if ($url !~ m/^\s*http/) {
                    _trace("ocsp_uri skipped: $url");
                    next;
                }
                $checks{'ocsp_valid'}->{val} .= check_url($url, 'ocsp_uri') || "";
            }
        }
    } else {
        $checks{'ocsp_valid'}->{val}= " ";  # _get_text('missing', "OCSP URL");
    }
    # FIXME: more OCSP checks missing, see ../Net/SSLinfo.pm  "probably complete OCSP Response Data:"
    #    https://raymii.org/s/articles/OpenSSL_Manually_Verify_a_certificate_against_an_OCSP.html

    $value = $data{'ext_constraints'}->{val}($host);
    $checks{'constraints'}->{val}   = " "    if ($value eq "");
    $checks{'constraints'}->{val}   = $value if ($value !~ m/CA:FALSE/i);
    # TODO: more checks necessary:
    #    KeyUsage field must set keyCertSign and/or the BasicConstraints field has the CA attribute set TRUE.

    check_certchars($host, $port);

    # certificate
    if ($cfg{'verbose'} > 0) { # TODO
        foreach my $label (qw(verify selfsigned)) {
            #dbx# _dbx "$label : $value #";
            $value = $data{$label}->{val}($host);
            $checks{$label}->{val}   = $value if ($value eq "");

# FIXME:  $data{'verify'} $data{'error_verify'} $data{'error_depth'}
#   if (_is_cfg_do('verify')) {
#       print "";
#       print "Hostname validity:       "  . $data{'verify_hostname'}->{val}($host);
#       print "Alternate name validity: "  . $data{'verify_altname'}->{val}( $host);
#   }
#
#   if (_is_cfg_do('altname')) {
#       print "";
#       print "Certificate AltNames:    "  . $data{'altname'}->{val}(        $host);
#       print "Alternate name validity: "  . $data{'verify_altname'}->{val}( $host);
#   }
        }
    }
    $value = $data{'selfsigned'}->{val}($host); # may contain:  0 (ok)
    $checks{'selfsigned'}    ->{val} = $value if ($value !~ m/^(?:0\s+.ok.)*$/);
    $checks{'fp_not_md5'}    ->{val} = $data{'fingerprint'} if ('MD5' eq $data{'fingerprint'});
    $value = $data{'signame'}->{val}($host);
    $checks{'sha2signature'} ->{val} = $value if ($value !~ m/^$cfg{'regex'}->{'SHA2'}/);
    $checks{'sig_encryption'}->{val} = $value if ($value !~ m/$cfg{'regex'}->{'encryption'}/i);
    $checks{'sig_enc_known'} ->{val} = $value if ($value !~ m/^$cfg{'regex'}->{'encryption_ok'}|$cfg{'regex'}->{'encryption_no'}$/i); ## no critic qw(RegularExpressions::ProhibitComplexRegexes)
    $value = $data{'pubkey_algorithm'}->{val}($host);
    $checks{'pub_encryption'}->{val} = $value if ($value !~ m/$cfg{'regex'}->{'encryption'}/i);
    $checks{'pub_enc_known'} ->{val} = $value if ($value !~ m/^$cfg{'regex'}->{'encryption_ok'}|$cfg{'regex'}->{'encryption_no'}$/i); ## no critic qw(RegularExpressions::ProhibitComplexRegexes)

# TODO: ocsp_uri pruefen; Soft-Fail, Hard-Fail

# TODO: check: serialNumber: Positive number up to a maximum of 20 octets.
# TODO: check: Signature: Must be the same OID as that defined in SignatureAlgorithm below.
# TODO: check: Version
# TODO: check: validity (aka dates)
# TODO: check: Issuer
#        Only CN=, C=, ST=, O=, OU= and serialNumber= must be supported the rest are optional
# TODO: check: Subject
#        The subject field can be empty in which case the entity being authenticated is defined in the subjectAltName.

    _trace("checkcert() }");
    return;
} # checkcert

sub checksni($$)    {
    #? check if given FQDN needs to use SNI
    # sets $checks{'sni'}, $checks{'certfqdn'}
    # DNS strings are case insensitive, hence values are compared lowercase
    my ($host, $port) = @_;
    _y_CMD("checksni() "  . $cfg{'done'}->{'checksni'});
    $cfg{'done'}->{'checksni'}++;
    return if (1 < $cfg{'done'}->{'checksni'});

    my $cn          =    $data{'cn'}->{val}($host, $port);
    my $lc_nosni    = lc($data{'cn_nosni'}->{val});
    my $lc_host     = lc($host);
    my $lc_cn       = lc($cn);
    my $rex_cn      =    $cn;
       $rex_cn      =~ s/[*][.]/(?:.*\\.)?/g;   # convert DNS wildcard to Perl regex

    if (_is_cfg_use('sni')) {   # useless check for --no-sni
        if ($lc_host eq $lc_nosni) {
            $checks{'sni'}->{val}   = "";
        } else {
            $checks{'sni'}->{val}   = $data{'cn_nosni'}->{val};
        }
    }
    if (not _is_cfg_use('cert')) {
        $checks{'certfqdn'}->{val}  = $cfg{'no_cert_txt'};
        $checks{'hostname'}->{val}  = $cfg{'no_cert_txt'};
        return;
    }
    if ($lc_host eq $lc_cn) {
        $checks{'hostname'}->{val}  = "";
    } else {
        $checks{'hostname'}->{val}  = $host . " <> " . $data{'cn'}->{val}($host);
    }
    if ($host =~ m/$rex_cn/i) {
        $checks{'certfqdn'}->{val}  = "";
    } else {
        $checks{'certfqdn'}->{val}  = $data{'cn_nosni'}->{val} . " <> " . $host;
    }
    #dbx# _dbx "host:\t\t"           . $host;
    #dbx# _dbx "data{cn}:\t\t"       . $data{'cn'}->{val}($host);
    #dbx# _dbx "data{cn_nosni}:\t"   . $data{'cn_nosni'}->{val};
    #dbx# _dbx "checks{hostname}:\t" . $checks{'hostname'}->{val};
    #dbx# _dbx "checks{certfqdn}:\t" . $checks{'certfqdn'}->{val};
    return;
} # checksni

sub checksizes($$)  {
    #? compute some lengths and counts from certificate values
    # sets %checks
    my ($host, $port) = @_;
    my $value;
    _y_CMD("checksizes() " . $cfg{'done'}->{'checksizes'});
    $cfg{'done'}->{'checksizes'}++;
    return if (1 < $cfg{'done'}->{'checksizes'});
    _trace("checksizes($host, $port){");

    checkcert($host, $port) if (_is_cfg_use('cert')); # in case we missed it before
    $value =  $data{'pem'}->{val}($host);
    $checks{'len_pembase64'}->{val} = length($value);
    $value =~ s/(----.+----\n)//g;
    chomp $value;
    $checks{'len_pembinary'}->{val} = sprintf("%d", length($value) / 8 * 6) + 1; # simple round()
    $checks{'len_subject'}  ->{val} = length($data{'subject'} ->{val}($host));
    $checks{'len_issuer'}   ->{val} = length($data{'issuer'}  ->{val}($host));
    $checks{'len_cps'}      ->{val} = length($data{'ext_cps'} ->{val}($host));
    $checks{'len_crl'}      ->{val} = length($data{'ext_crl'} ->{val}($host));
    #$checks{'len_crl_data'} ->{val} = length($data{'crl'}     ->{val}($host));
    $checks{'len_ocsp'}     ->{val} = length($data{'ocsp_uri'}->{val}($host));
    #$checks{'len_oids'}     ->{val} = length($data{'oids'}->{val}($host));
    $checks{'len_sernumber'}->{val} = int(length($data{'serial_hex'}->{val}($host)) / 2); # value are hex octets
        # NOTE: RFC 5280 limits the serial number to an integer with not more
        #       than 20 octets. It should also be not a negative number.
        # It's assumed that a octet equals one byte.

    if ($cmd{'extopenssl'} == 1) {
        # TODO: find a better way to do this ugly check
        $value = $data{'modulus_len'}->{val}($host);
        $checks{'len_publickey'}->{val} = (($value =~ m/^\s*$/) ? 0 : $value);
        $value = $data{'modulus_exponent'}->{val}($host);  # i.e. 65537 (0x10001) or prime256v1
        if ($value =~ m/prime/i) {      # public key uses EC with primes
            $value =~ s/\n */ /msg;
            $checks{'modulus_exp_1'}     ->{val}    = "<<N/A $value>>";
            $checks{'modulus_exp_65537'} ->{val}    = "<<N/A $value>>";
            $checks{'modulus_exp_oldssl'}->{val}    = "<<N/A $value>>";
            $checks{'modulus_size_oldssl'}->{val}   = "<<N/A $value>>";
        } else  {                       # only traditional exponent needs to be checked
            if ($value eq '<<openssl>>') {  # TODO: <<openssl>> from Net::SSLinfo
                $checks{'modulus_exp_1'}     ->{val}= $text{'na_openssl'};
                $checks{'modulus_exp_65537'} ->{val}= $text{'na_openssl'};
                $checks{'modulus_exp_oldssl'}->{val}= $text{'na_openssl'};
            } else {
                $value =~ s/^(\d+).*/$1/;
                if ($value =~ m/^\d+$/) {   # avoid Perl warning "Argument isn't numeric"
                    $checks{'modulus_exp_1'}     ->{val}= $value if ($value == 1);
                    $checks{'modulus_exp_65537'} ->{val}= $value if ($value != 65537);
                    $checks{'modulus_exp_oldssl'}->{val}= $value if ($value >  65536);
                } else {
                    $checks{'modulus_exp_1'}     ->{val}= $text{'na'};
                    $checks{'modulus_exp_65537'} ->{val}= $text{'na'};
                    $checks{'modulus_exp_oldssl'}->{val}= $text{'na'};
                }
            }
            $value = $data{'modulus'}->{val}($host);    # value consist of hex digits
            if ($value eq '<<openssl>>') {
                $checks{'modulus_size_oldssl'}->{val}   = $text{'na_openssl'};
            } else {
                $value = length($value) * 4;
                $checks{'modulus_size_oldssl'}->{val}   = $value if ($value > 16384);
            }
        }
        $value = $data{'serial_int'}->{val}($host);
        $value = 0 if ($value =~ m/^\s*$/);     # avoid Perl warning "Argument isn't numeric"
        $value += 0;
        my $bits_of_value = _get_base2($value);
        $checks{'sernumber'}    ->{val} = "$bits_of_value  > 160" if ($bits_of_value > 160);
        $value = $data{'sigkey_len'}->{val}($host);
        $checks{'len_sigdump'}  ->{val} = (($value =~ m/^\s*$/) ? 0 : $value); # missing without openssl
    } else { # missing without openssl
        $checks{'sernumber'}    ->{val} = $text{'na_openssl'};
        $checks{'len_sigdump'}  ->{val} = $text{'na_openssl'};
        $checks{'len_publickey'}->{val} = $text{'na_openssl'};
        $checks{'modulus_exp_1'}->{val} = $text{'na_openssl'};
        $checks{'modulus_exp_65537'} ->{val} = $text{'na_openssl'};
        $checks{'modulus_exp_oldssl'}->{val} = $text{'na_openssl'};
        $checks{'modulus_size_oldssl'}->{val}= $text{'na_openssl'};
    }
    _trace("checksizes() }");
    return;
} # checksizes

sub check02102($$)  {
    #? check if target is compliant to BSI TR-02102-2 2016-01
    # assumes that checkciphers() and checkdest() already done
    my ($host, $port) = @_;
    _y_CMD("check02102() " . $cfg{'done'}->{'check02102'});
    $cfg{'done'}->{'check02102'}++;
    return if (1 < $cfg{'done'}->{'check02102'});
    my $txt = "";
    my $val = "";

    # description (see CHECK in o-saft-man.pm) ...
    # lines starting with #! are headlines from TR-02102-2

    # All checks according ciphers already done in checkciphers() and stored
    # in $checks{'tr_02102.'}. We need to do checks according certificate and
    # protocol and fill other %checks values according requirements.

    #! TR-02102-2 3.2 SSL/TLS-Versionen
    # use 'session_protocol' instead of 'sslversion' as its string matches the
    # TR-02102 requirements better; SEE Note:Selected Protocol
    $val  = ($data{'session_protocol'}->{val}($host, $port) !~ m/TLSv1.?2/) ? " <<not TLSv12>>" : "" ;
    $val .= ($prot{'SSLv2'}->{'cnt'}  > 0) ? _get_text('insecure', "protocol SSLv2") : "";
    $val .= ($prot{'SSLv3'}->{'cnt'}  > 0) ? _get_text('insecure', "protocol SSLv3") : "";
    $val .= ($prot{'TLSv1'}->{'cnt'}  > 0) ? _get_text('insecure', "protocol TLSv1") : "";
    $checks{'tr_02102-'}->{val}.= $val;
    $val .= ($prot{'TLSv11'}->{'cnt'} > 0) ? _get_text('insecure', "protocol TLSv11") : "";
    $checks{'tr_02102+'}->{val}.= $val;

    #! TR-02102-2 3.3.1 Empfohlene Cipher Suites
    #! TR-02102-2 3.3.2 Übergangsregelungen
        # cipher checks are already done in checkciphers()

    #! TR-02102-2 3.4.1 Session Renegotation
    $val = ($checks{'renegotiation'}->{val} ne "") ? $text{'no_reneg'} : "";
    $checks{'tr_02102+'}->{val}.= $val;
    $checks{'tr_02102-'}->{val}.= $val;

    #! TR-02102-2 3.4.2 Verkürzung der HMAC-Ausgabe
        # FIXME: cannot be tested because openssl does not suppot it (11/2016)
    $val = ($data{'tlsextensions'}->{val}($host, $port) =~ m/truncated.*hmac/i)
           ? _get_text('enabled_extension', 'truncated HMAC') : "" ;
    $checks{'tr_02102+'}->{val}.= $val;
    $checks{'tr_02102-'}->{val}.= $val;

    #! TR-02102-2 3.4.3 TLS-Kopression und CRIME
    $checks{'tr_02102+'}->{val}.= $checks{'crime'}->{val};
    $checks{'tr_02102-'}->{val}.= $checks{'crime'}->{val};

    #! TR-02102-2 3.4.4 Der Lucky 13-Angriff
    $val = $checks{'lucky13'}->{val};
    $val = ($val ne "") ? _get_text('insecure', "cipher $val; Lucky13") : "" ;
    $checks{'tr_02102+'}->{val}.= $val;
    # check for Lucky 13 in strict mode only (requires GCM)

    #! TR-02102-2 3.4.5 Die "Encrypt-then-MAC"-Erweiterung
        # FIXME: cannot be tested because openssl does not suppot it (11/2016)

    #! TR-02102-2 3.4.6 Die Heartbeat-Erweiterung
    $val = "";
    $val = ($data{'heartbeat'}->{val}($host, $port) ne "")
           ? _get_text('enabled_extension', 'heartbeat') : "";
    $checks{'tr_02102+'}->{val}.= $val;
    $checks{'tr_02102-'}->{val}.= $val;

    #! TR-02102-2 3.4.7 Die Extended Master Secret Extension
        # FIXME: cannot be tested because openssl does not suppot it (11/2016)

    #! TR-02102-2 3.5 Authentisierung der Kommunikationspartner
        # check are not possible from remote

    #! TR-02102-2 3.6 Domainparameter und Schlüssellängen
    $val = $checks{'len_sigdump'}->{val};
    if ($val =~ m/\d+/) {       # avoid Perl warning "Argument isn't numeric"
        $val = ($val < 2000) ? _get_text('bit2048', $val) : "";
        # FIXME: lazy check does not honor used cipher
    } else {
        $val = " len_sigdump missing $val";
    }
    $checks{'tr_02102+'}->{val}.= $val;
    $checks{'tr_02102-'}->{val}.= $val;

    #check_dh($host, $port);    # need DH Parameter
        # FIXME: check see for example check7525()

    #! TR-02102-2 3.6.1 Verwendung von elliptischen Kurven
        # brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 (vgl. [RFC5639] und [RFC7027])
        # lazy allows: secp256r1, secp384r1
        # verboten:    secp224r1
    # TODO: cipher bit length check

    #! TR-02102-2 4.1 Schlüsselspeicherung
    #! TR-02102-2 4.2 Umgang mit Ephemeralschlüsseln
    #! TR-02102-2 4.3 Zufallszahlen
        # these checks are not possible from remote

    return;
} # check02102

sub check2818($$)   {
    #? check if subjectAltNames is RFC 2818 compliant
    my ($host, $port) = @_;
    _y_CMD("check2818() " . $cfg{'done'}->{'check2818'});
    $cfg{'done'}->{'check2818'}++;
    return if (1 < $cfg{'done'}->{'check2818'});
    my $val = $data{'verify_altname'}->{val}($host);
    $checks{'rfc_2818_names'}->{val} = $val if ($val !~ m/matches/); # see Net::SSLinfo.pm
    return;
} # check2818

sub check03116($$)  {
    #? check if target is compliant to BSI TR-03116-4
    my ($host, $port) = @_;
    # BSI TR-03116-4 is similar to BSI TR-02102-2
    _y_CMD("check03116() " . $cfg{'done'}->{'check03116'});
    $cfg{'done'}->{'check03116'}++;
    return if (1 < $cfg{'done'}->{'check03116'});
    my $txt = "";

    # All checks according ciphers already done in checkciphers() and stored
    # in $checks{'tr_03116'}. We need to do checks according certificate and
    # protocol and fill other %checks values according requirements.

    #! TR-03116-4 2.1.1 TLS-Versionen und Sessions
        # muss mindestens die TLS-Version 1.2 unterstützt werden

    # use 'session_protocol' instead of 'sslversion' as its string matches the
    # TR-03116 requirements better; SEE Note:Selected Protocol
    $txt  = ($data{'session_protocol'}->{val}($host, $port) !~ m/TLSv1.?2/) ? " <<not TLSv12>>" : "" ;
    $txt .= ($prot{'SSLv2'}->{'cnt'}  > 0) ? _get_text('insecure', "protocol SSLv2") : "";
    $txt .= ($prot{'SSLv3'}->{'cnt'}  > 0) ? _get_text('insecure', "protocol SSLv3") : "";
    $txt .= ($prot{'TLSv1'}->{'cnt'}  > 0) ? _get_text('insecure', "protocol TLSv1") : "";
    $txt .= ($prot{'TLSv11'}->{'cnt'} > 0) ? _get_text('insecure', "protocol TLSv11") : "";
    $checks{'tr_03116-'}->{val}.= $txt;
    $checks{'tr_03116+'}->{val}.= $txt;

    #! TR-03116-4 2.1.2 Cipher Suites
    $checks{'tr_03116+'}->{val}.= $checks{'tr_03116+'}->{val};
    $checks{'tr_03116-'}->{val}.= $checks{'tr_03116-'}->{val};

    #! TR-03116-4 2.1.1 TLS-Versionen und Sessions
        # TLS Session darf eine Lebensdauer von 2 Tagen nicht überschreiten
    #! TR-03116-4 2.1.4.2 Encrypt-then-MAC-Extension
    #! TR-03116-4 2.1.4.3 OCSP-Stapling
    $checks{'tr_03116+'}->{val} .= _get_text('missing', 'OCSP') if ($data{'ocsp_uri'}->{val}($host)  eq "");

    #! TR-03116-4 4.1.1 Zertifizierungsstellen/Vertrauensanker
        # muss für die Verifikation von Zertifikaten einen oder mehrere Vertrauensanker vorhalten
        # Die Zahl der Vertrauensanker sollte so gering wie möglich gehalten werden.
# FIXME:

    #! TR-03116-4 4.1.2 Zertifikate
        # müssen die folgenden Anforderungen erfüllen:
        # * Alle Zertifikate müssen ...
        # ** jederzeit aktuelle CRLs zur Verfügung stehen, oder
        # ** eine AuthorityInfoAccess-Extension mit OCSP
        # * Endnutzerzertifikate dürfen eine Gültigkeitsdauer von höchstens drei,
        #   CA-Zertifikate von höchstens fünf Jahren haben.
        # * CA-Zertifikate müssen eine BasicConstraints-Extension enthalten.
        # * Das in der Extension enthaltene Feld pathLenConstraint muss
        #   vorhanden sein und auf einen möglichst kleinen Wert gesetzt werden.
        # * Alle Zertifikate müssen eine KeyUsage-Extension enthalten.
        # * Zertifikate dürfen keine Wildcards CommonName des Subject oder
        #   SubjectAltName enthalten.
        # Verwendung von Extended-Validation-Zertifikaten wird empfohlen
    $txt = _get_text('cert_valid', $data{'valid_years'}->{val}); # NOTE: 'valid_years' is special value
    $checks{'tr_03116+'}->{val} .= $txt                if ($data{'valid_years'}->{val} > 3);
# FIXME: cert itself and CA-cert have different validity: 3 vs. 5 years
    $txt = $checks{'wildcard'}->{val};
    if (($data{'ext_crl'}->{val}($host) eq "") && ($data{'ext_authority'}->{val}($host) eq "")) {
        $checks{'tr_03116+'}->{val} .= _get_text('missing', 'AIA or CRL');
    }
# FIXME: need to verify provided CRL and OCSP
    $checks{'tr_03116+'}->{val} .= _get_text('wildcards', $txt) if ($txt ne "");
    # _checkwildcard() checks for CN and subjectAltname only, we need Subject also
    $txt = $data{'subject'}->{val}($host);
    $checks{'tr_03116+'}->{val} .= _get_text('wildcards', "Subject:$txt") if ($txt =~ m/[*]/);
# FIXME: need to check wildcards in all certificates

    #! TR-03116-4 4.1.3 Zertifikatsverifikation
        # * vollständige Prüfung der Zertifikatskette bis zu einem für die
        #   jeweilige Anwendung vertrauenswürdigen und als authentisch
        #   bekannten Vertrauensanker
# FIXME:
        # * Prüfung auf Gültigkeit (Ausstellungs- und Ablaufdatum)
        # * Rückrufprüfung aller Zertifikate
    $txt = $checks{'dates'}->{val};
    $checks{'tr_03116+'}->{val} .= _get_text('cert_dates', $txt) if ($txt ne "");
    $txt = $checks{'expired'}->{val};
    $checks{'tr_03116+'}->{val} .= _get_text('cert_valid', $txt) if ($txt ne "");

    #! TR-03116-4 4.1.4 Domainparameter und Schlüssellängen
        # ECDSA 224 Bit; DSA 2048 Bit; RSASSA-PSS 2048 Bit; alle SHA-224
        # empfohlene ECC:
        # * BrainpoolP224r1 3 , BrainpoolP256r1, BrainpoolP384r1, BrainpoolP512r1
        # * NIST Curve P-224, NIST Curve P-256, NIST Curve P-384, NIST Curve P-521
# FIXME:

    #! TR-03116-4 5.2 Zufallszahlen
        # these checks are not possible from remote

    $checks{'tr_03116-'}->{val} .= $checks{'tr_03116+'}->{val};

    return;
} # check03116

sub check6125($$)   {
    #? check if certificate identifiers are RFC 6125 compliant
    my ($host, $port) = @_;
    _y_CMD("check6125() " . $cfg{'done'}->{'check6125'});
    $cfg{'done'}->{'check6125'}++;
    return if (1 < $cfg{'done'}->{'check6125'});

    my $txt = "";
    my $val = "";

    #from: https://www.rfc-editor.org/rfc/rfc6125.txt
    #   ... only references which are relevant for checks here
    # 6.4.  Matching the DNS Domain Name Portion
    #   (collection of descriptions for following rules)
    # 6.4.1.  Checking of Traditional Domain Names
    #   domain name labels using a case-insensitive ASCII comparison, as
    #   clarified by [DNS-CASE] (e.g., "WWW.Example.Com" would be lower-cased
    #   to "www.example.com" for comparison purposes).  Each label MUST match
    #   in order for the names to be considered to match, except as
    #   supplemented by the rule about checking of wildcard labels
    #   (Section 6.4.3).
    # 6.4.2.  Checking of Internationalized Domain Names
    # 6.4.3.  Checking of Wildcard Certificates
    #   ...
    #   1.  The client SHOULD NOT attempt to match a presented identifier in
    #       which the wildcard character comprises a label other than the
    #       left-most label (e.g., do not match bar.*.example.net).
    #   2.  If the wildcard character is the only character of the left-most
    #       label in the presented identifier, the client SHOULD NOT compare
    #       against anything but the left-most label of the reference
    #       identifier (e.g., *.example.com would match foo.example.com but
    #       not bar.foo.example.com or example.com).
    #   3.  The client MAY match a presented identifier in which the wildcard
    #       character is not the only character of the label (e.g.,
    #       baz*.example.net and *baz.example.net and b*z.example.net would
    #       be taken to match baz1.example.net and foobaz.example.net and
    #       buzz.example.net, respectively).  However, the client SHOULD NOT
    #       attempt to match a presented identifier where the wildcard
    #       character is embedded within an A-label or U-label [IDNA-DEFS] of
    #       an internationalized domain name [IDNA-PROTO].
    # 6.5.2.  URI-ID
    #   The scheme name portion of a URI-ID (e.g., "sip") MUST be matched in
    #   a case-insensitive manner, in accordance with [URI].  Note that the
    #   ":" character is a separator between the scheme name and the rest of
    #   the URI, and thus does not need to be included in any comparison.
    # TODO: nothing
    # 7.2.  Wildcard Certificates
    #   o  There is no specification that defines how the wildcard character
    #      may be embedded within the A-labels or U-labels [IDNA-DEFS] of an
    #      internationalized domain name [IDNA-PROTO]; as a result,
    #      implementations are strongly discouraged from including or
    #      attempting to check for the wildcard character embedded within the
    #      A-labels or U-labels of an internationalized domain name (e.g.,
    #      "xn--kcry6tjko*.example.org").  Note, however, that a presented
    #      domain name identifier MAY contain the wildcard character as long
    #      as that character occupies the entire left-most label position,
    #      where all of the remaining labels are valid NR-LDH labels,
    #      A-labels, or U-labels (e.g., "*.xn--kcry6tjko.example.org").
    # 7.3.  Internationalized Domain Names
    #   Allowing internationalized domain names can lead to the inclusion of
    #   visually similar (so-called "confusable") characters in certificates;
    #   for discussion, see for example [IDNA-DEFS].

    # NOTE: wildcards itself are checked in   checkcert() _checkwildcard()
    $txt = $data{'cn'}->{val}($host);
    $val     .= " <<6.4.2:cn $txt>>"      if ($txt !~ m!$cfg{'regex'}->{'isDNS'}!);
    $val     .= " <<6.4.3:cn $txt>>"      if ($txt =~ m!$cfg{'regex'}->{'doublewild'}!);
    $val     .= " <<6.4.3:cn $txt>>"      if ($txt =~ m!$cfg{'regex'}->{'invalidwild'}!);
    $val     .= " <<7.2.o:cn $txt>>"      if ($txt =~ m!$cfg{'regex'}->{'invalidIDN'}!);
    $val     .= " <<7.3:cn $txt>>"        if ($txt =~ m!$cfg{'regex'}->{'isIDN'}!);
    $txt = $data{'subject'}->{val}($host);
    $txt =~ s!^.*CN=!!;         # just value of CN=
    $val     .= " <<6.4.2:subject $txt>>" if ($txt !~ m!$cfg{'regex'}->{'isDNS'}!);
    $val     .= " <<6.4.3:subject $txt>>" if ($txt =~ m!$cfg{'regex'}->{'doublewild'}!);
    $val     .= " <<6.4.3:subject $txt>>" if ($txt =~ m!$cfg{'regex'}->{'invalidwild'}!);
    $val     .= " <<7.2.o:subject $txt>>" if ($txt =~ m!$cfg{'regex'}->{'invalidIDN'}!);
    $val     .= " <<7.3:subject $txt>>"   if ($txt =~ m!$cfg{'regex'}->{'isIDN'}!);
    foreach my $txt (split(" ", $data{'altname'}->{val}($host))) {
        $txt  =~ s!.*:!!;        # strip prefix
        $val .= " <<6.4.2:altname $txt>>" if ($txt !~ m!$cfg{'regex'}->{'isDNS'}!);
        $val .= " <<6.4.3:altname $txt>>" if ($txt =~ m!$cfg{'regex'}->{'doublewild'}!);
        $val .= " <<6.4.3:altname $txt>>" if ($txt =~ m!$cfg{'regex'}->{'invalidwild'}!);
        $val .= " <<7.2.o:altname $txt>>" if ($txt =~ m!$cfg{'regex'}->{'invalidIDN'}!);
        $val .= " <<7.3:altname $txt>>"   if ($txt =~ m!$cfg{'regex'}->{'isIDN'}!);
    }
    $checks{'rfc_6125_names'}->{val} = $val;

    return;
} # check6125

sub check7525       {
    #? check if target is RFC 7525 compliant
    my ($host, $port) = @_;
    _y_CMD("check7525() " . $cfg{'done'}->{'check7525'});
    $cfg{'done'}->{'check7525'}++;
    return if (1 < $cfg{'done'}->{'check7525'});
    my $val = "";

    # All checks according ciphers already done in checkciphers() and stored
    # in $checks{'rfc_7525'}. We need to do checks according certificate and
    # protocol and fill other %checks values according requirements.

    # descriptions from: https://www.rfc-editor.org/rfc/rfc7525.txt

    # 3.1.1.  SSL/TLS Protocol Versions
    #    Implementations MUST support TLS 1.2 [RFC5246] and MUST prefer to
    #    negotiate TLS version 1.2 over earlier versions of TLS.
    #    Implementations SHOULD NOT negotiate TLS version 1.1 [RFC4346];
    #    the only exception is when no higher version is available in the
    #    negotiation.
    # TODO: for lazy check

    # use 'session_protocol' instead of 'sslversion' as its string matches the
    # RFC requirements better; SEE Note:Selected Protocol
    $val  = " <<not TLSv12>>" if ($data{'session_protocol'}->{val}($host, $port) !~ m/TLSv1.?2/);
    $val .= " SSLv2"   if ( $prot{'SSLv2'}->{'cnt'}   > 0);
    $val .= " SSLv3"   if ( $prot{'SSLv3'}->{'cnt'}   > 0);
    $val .= " TLSv1"   if (($prot{'TLSv11'}->{'cnt'} + $prot{'TLSv12'}->{'cnt'}) > 0);
    $val .= " TLSv11"  if (($prot{'TLSv11'}->{'cnt'}  > 0) and ($prot{'TLSv12'}->{'cnt'} > 0));

    # 3.1.2.  DTLS Protocol Versions
    #    Implementations SHOULD NOT negotiate DTLS version 1.0 [RFC4347].
    #    Implementations MUST support and MUST prefer to negotiate DTLS
    #    version 1.2 [RFC6347].

    $val .= " DTLSv1"  if ( $prot{'DTLSv1'}->{'cnt'}  > 0);
    $val .= " DTLSv11" if ( $prot{'DTLSv11'}->{'cnt'} > 0);
    # TODO: we currently (5/2015) do not support DTLSv1x

    # 3.1.3.  Fallback to Lower Versions
    # no checks, as already covered by 3.1.1 checks

    # 3.2.  Strict TLS
    #    ... TLS-protected traffic (such as STARTTLS),
    #    clients and servers SHOULD prefer strict TLS configuration.
    #
    #    HTTP client and server implementations MUST support the HTTP
    #    Strict Transport Security (HSTS) header [RFC6797]

    # FIXME: what to check for STARTTLS?

    $val .= " DTLSv11" if ( $prot{'DTLSv11'}->{'cnt'} > 0);
    checkhttp($host, $port);    # need http_sts
    $val .= _get_text('missing', 'STS') if ($checks{'hsts_sts'} eq "");
    # TODO: strict TLS checks are for STARTTLS only, not necessary here

    # 3.3.  Compression
    #    ... implementations and deployments SHOULD
    #    disable TLS-level compression (Section 6.2.2 of [RFC5246]), unless
    #    the application protocol in question has been shown not to be open to
    #    such attacks.

    if ($data{'compression'}->{val}($host) =~ /$cfg{'regex'}->{'nocompression'}/) {
        $val .= $data{'compression'}->{val}($host);
    }

    # 3.4.  TLS Session Resumption
    #    ... the resumption information MUST be authenticated and encrypted ..
    #    A strong cipher suite MUST be used when encrypting the ticket (as
    #    least as strong as the main TLS cipher suite).
    #    Ticket keys MUST be changed regularly, e.g., once every week, ...
    #    For similar reasons, session ticket validity SHOULD be limited to
    #    a reasonable duration (e.g., half as long as ticket key validity).

    if ($data{'resumption'}->{val}($host) eq "") {
        $val .= _get_text('insecure', 'resumption');
        $val .= _get_text('missing',  'session ticket') if ($data{'session_ticket'}->{val}($host) eq "");
        $val .= _get_text('insecure', 'randomness of session') if ($checks{'session_random'}->{val} ne "");
    }
    # TODO: session ticket must be random
    # FIXME: session ticket must be authenticated and encrypted

    # 3.5.  TLS Renegotiation
    #    ... both clients and servers MUST implement the renegotiation_info
    #    extension, as defined in [RFC5746].

    $val .= _get_text('missing',  'renegotiation_info extension') if ($data{'tlsextensions'}->{val}($host, $port) !~ m/renegotiation info/);
    $val .= _get_text('insecure', 'renegotiation') if ($data{'renegotiation'}->{val}($host)  eq "");

    # 3.6.  Server Name Indication
    #    TLS implementations MUST support the Server Name Indication (SNI)

    checksni($host, $port);    # need sni
    $val .= "<<SNI not supported>>" if ($checks{'sni'}->{val} eq "");
    # TODO: need a reliable check if SNI is supported

    # 4.  Recommendations: Cipher Suites
    # 4.1.  General Guidelines
    #    Implementations MUST NOT negotiate the cipher suites with NULL encryption.
    #    Implementations MUST NOT negotiate RC4 cipher suites.
    #    Implementations MUST NOT negotiate cipher suites offering less
    #    than 112 bits of security, ...
    #    Implementations SHOULD NOT negotiate cipher suites that use
    #    algorithms offering less than 128 bits of security.
    # TODO: for lazy check
    #    Implementations SHOULD NOT negotiate cipher suites based on RSA
    #    key transport, a.k.a. "static RSA".
    #    Implementations MUST support and prefer to negotiate cipher suites
    #    offering forward secrecy, ...
    #
    # 4.2.  Recommended Cipher Suites
    #    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    #    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

    #  ==> done in checkcipher() with _is_rfc7525

    # 4.3.  Public Key Length
    #    ... DH key lengths of at least 2048 bits are RECOMMENDED.
    #    ... Curves of less than 192 bits SHOULD NOT be used.

    check_dh($host, $port);     # need DH Parameter
    if ($data{'dh_parameter'}->{val}($host) =~ m/ECDH/) {
        $val .= _get_text('insecure', "DH Parameter: $checks{'ecdh_256'}->{val}") if ($checks{'ecdh_256'}->{val} ne "");
    } else {
        $val .= _get_text('insecure', "DH Parameter: $checks{'dh_2048'}->{val}")  if ($checks{'dh_2048'}->{val}  ne "");
        # TODO: $check...{val} may already contain "<<...>>"; remove it
    }
    # TODO: use osaft::get_dh_paramter() for more reliable check

    # 4.5.  Truncated HMAC
    #    Implementations MUST NOT use the Truncated HMAC extension, defined in
    #    Section 7 of [RFC6066].

    $val .= _get_text('missing', 'truncated HMAC extension') if ($data{'tlsextensions'}->{val}($host, $port) =~ m/truncated.*hmac/i);
    #$val .= _get_text('missing', 'session ticket extension') if ($data{'tlsextensions'}->{val}($host, $port) !~ m/session.*ticket/);
    #$val .= _get_text('missing', 'session ticket lifetime extension') if ($data{'session_lifetime'}->{val}($host, $port) eq "");

    # 6.  Security Considerations
    # 6.1.  Host Name Validation
    #    If the host name is discovered indirectly and in an insecure manner
    #    (e.g., by an insecure DNS query for an MX or SRV record), it SHOULD
    #    NOT be used as a reference identifier [RFC6125] even when it matches
    #    the presented certificate.  This proviso does not apply if the host
    #    name is discovered securely (for further discussion, see [DANE-SRV]
    #    and [DANE-SMTP]).

    $val .=  $text{'EV_subject_host'} if ($checks{'hostname'}->{val} ne "");

    # 6.2.  AES-GCM
    # FIXME: implement

    # 6.3.  Forward Secrecy
    #    ... therefore advocates strict use of forward-secrecy-only ciphers.
    # FIXME: implement

    # 6.4.  Diffie-Hellman Exponent Reuse
    # FIXME: implement

    # 6.5.  Certificate Revocation
    #    ... servers SHOULD support the following as a best practice
    #    OCSP [RFC6960]
    #    The OCSP stapling extension defined in [RFC6961]

    $val .= _get_text('missing', 'OCSP') if ($checks{'ocsp_uri'}->{val}  ne "");
    $val .= $checks{'ocsp_valid'}->{val};
    $val .= _get_text('missing', 'CRL in certificate') if ($checks{'crl'}->{val} ne "");
    $val .= $checks{'crl_valid'}->{val};

    # All checks for ciphers were done in _is_rfc7525() and already stored in
    # $checks{'rfc_7525'}. Because it may be a huge list, it is appended.
    $checks{'rfc_7525'}->{val} = $val . " " . $checks{'rfc_7525'}->{val};

    return;
} # check7525

sub checkdv($$)     {
    #? check if certificate is DV-SSL
    my ($host, $port) = @_;
    _y_CMD("checkdv() "   . $cfg{'done'}->{'checkdv'});
    $cfg{'done'}->{'checkdv'}++;
    return if (1 < $cfg{'done'}->{'checkdv'});

    # DV certificates must have:
    #    CN= value in either the subject or subjectAltName
    #    C=, ST=, L=, OU= or O= should be either blank or contain appropriate
    #        text such as "not valid".  # TODO: match $cfg{'regex'}->{'EV-empty'}
    # TODO: reference missing

    my $cn      = $data{'cn'}->{val}($host);
    my $subject = $data{'subject'}->{val}($host);
    my $altname = $data{'altname'}->{val}($host); # space-separated values
    my $oid     = '2.5.4.3';                      # /CN= or commonName
    my $txt     = "";

       # following checks work like:
       #   for each check add descriptive failture text (from %text)
       #   to $checks{'dv'}->{val} if check fails

    check_certchars($host, $port);      # should already be done in checkcert()

    # required CN=
    if ($cn =~ m/^\s*$/) {
        $checks{'dv'}->{val} .= _get_text('missing', "Common Name");
        return; # .. as all other checks will fail too now
    }

    # CN= in subject or subjectAltname,  $1 is matched FQDN
    if (($subject !~ m#/$cfg{'regex'}->{$oid}=(?:[^/\n]*)#)
    and ($altname !~ m#/$cfg{'regex'}->{$oid}=(?:[^\s\n]*)#)) {
        $checks{'dv'}->{val} .= _get_text('missing', $data_oid{$oid}->{txt});
        return; # .. as ..
    }
    ($txt = $subject) =~ s#/.*?$cfg{'regex'}->{$oid}=##;
    $txt = "" if not defined $txt;  # defensive programming ..

# TODO: %data_oid not yet used
    $data_oid{$oid}->{val} = $txt if ($txt !~ m/^\s*$/);
    $data_oid{$oid}->{val} = $cn  if ($cn  !~ m/^\s*$/);

    # there's no rule that CN's value must match the hostname, somehow ..
    # we check at least if subject or subjectAltname match hostname
    if ($txt ne $cn) {  # mismatch
        $checks{'dv'}->{val} .= $text{'EV_subject_CN'};
    }
    if ($txt ne $host) {# mismatch
        if (0 >= (grep{/^DNS:$host$/} split(/[\s]/, $altname))) {
            $checks{'dv'}->{val} .= $text{'EV_subject_host'};
        }
    }

    return;
} # checkdv

sub checkev($$)     {
    #? check if certificate is EV-SSL
    my ($host, $port) = @_;
    _y_CMD("checkev() "   . $cfg{'done'}->{'checkev'});
    $cfg{'done'}->{'checkev'}++;
    return if (1 < $cfg{'done'}->{'checkev'});

    # most information must be provided in `subject' field
    # unfortunately the specification is a bit vague which X509  keywords
    # must be used, hence we use RegEx to math the keyword assigned value
    #
    # { According EV Certificate Guidelines - Version 1.0 https://www.cabforum.org/contents.html
    # == Required ==
    # Organization name:   subject:organizationName (OID 2.5.4.10 )
    # Business Category:   subject:businessCategory (OID 2.5.4.15)
    # Domain name:         subject:commonName (OID 2.5.4.3) or SubjectAlternativeName:dNSName
    #     This field MUST contain one of the following strings in UTF-8
    #     English: 'V1.0, Clause 5.(b)', 'V1.0, Clause 5.(c)' or 'V1.0, Clause 5.(d)',
    #     depending whether the Subject qualifies under the terms of Section 5b, 5c, or
    #     5d of the Guidelines, respectively.
    # Jurisdiction of Incorporation or Registration:
    #     Locality:        subject:jurisdictionOfIncorporationLocalityName (OID 1.3.6.1.4.1.311.60.2.1.1)
    #     State or Province:subject:jurisdictionOfIncorporationStateOrProvinceName (OID 1.3.6.1.4.1.311.60.2.1.2)
    #     Country:         subject:jurisdictionOfIncorporationCountryName (OID 1.3.6.1.4.1.311.60.2.1.3)
    # Registration Number: subject:serialNumber (OID 2.5.4.5)
    # Physical Address of Place of Business
    #     City or town:    subject:localityName (OID 2.5.4.7)
    #     State or province: subject:stateOrProvinceName (OID 2.5.4.8)
    #     Number & street: subject:streetAddress (OID 2.5.4.9)
    #
    # Maximum Validity Period  27 months (recommended: EV Subscriber certificate 12 months)
    #
    # == Optional ==
    # Physical Address of Place of Business
    #     Country:         subject:countryName (OID 2.5.4.6)
    #     Postal code:     subject:postalCode (OID 2.5.4.17)
    # Compliance with European Union Qualified Certificates Standard In addition,
    # CAs MAY include a qcStatements extension per RFC 3739. The OID for
    #                      qcStatements:qcStatement:statementId is 1.3.6.1.4.1.311.60.2.1
    #
    # }
    # Issuer Domain Component: issuer:domainComponent (OID 0.9.2342.19200300.100.1.25)
    #
    # See also: http://www.evsslcertificate.com

    my $oid     = "";
    my $subject = $data{'subject'}->{val}($host);
    my $cn      = $data{'cn'}->{val}($host);
    my $alt     = $data{'altname'}->{val}($host);
    my $txt     = "";
    my $key     = "";

       # following checks work like:
       #   for each check add descriptive failture text (from %text)
       #   to $checks{'ev+'}->{val} if check fails

    check_certchars($host, $port);      # should already be done in checkcert()
    checkdv($host, $port);
    $checks{'ev+'}->{val} = $checks{'dv'}->{val}; # wrong for DV then wrong for EV too

    # required OID
    foreach my $oid (qw(
        1.3.6.1.4.1.311.60.2.1.1   1.3.6.1.4.1.311.60.2.1.3
        2.5.4.5    2.5.4.7   2.5.4.10   2.5.4.15
        )) {
        if ($subject =~ m#/$cfg{'regex'}->{$oid}=([^/\n]*)#) {
            $data_oid{$oid}->{val} = $1;
            _v2print("EV: " . $cfg{'regex'}->{$oid} . " = $1");
        } else {
            _v2print("EV: " . _get_text('missing', $cfg{'regex'}->{$oid}) . "; required");
            $txt = _get_text('missing', $data_oid{$oid}->{txt});
            $checks{'ev+'}->{val} .= $txt;
            $checks{'ev-'}->{val} .= $txt;
        }
    }
    $oid = '1.3.6.1.4.1.311.60.2.1.2';  # or /ST=
    if ($subject !~ m#/$cfg{'regex'}->{$oid}=(?:[^/\n]*)#) {
        $txt = _get_text('missing', $data_oid{$oid}->{txt});
        $checks{'ev+'}->{val} .= $txt;
        $oid = '2.5.4.8';               # or /ST=
        if ($subject =~ m#/$cfg{'regex'}->{'2.5.4.8'}=([^/\n]*)#) {
            $data_oid{$oid}->{val} = $1;
        } else {
            $checks{'ev-'}->{val} .= $txt;
            _v2print("EV: " . _get_text('missing', $cfg{'regex'}->{$oid}) . "; required");
        }
    }
    $oid = '2.5.4.9'; # may be missing
    if ($subject !~ m#/$cfg{'regex'}->{$oid}=(?:[^/\n]*)#) {
        $txt = _get_text('missing', $data_oid{$oid}->{txt});
        $checks{'ev+'}->{val} .= $txt;
        _v2print("EV: " . $cfg{'regex'}->{$oid} . " = missing+");
        _v2print("EV: " . _get_text('missing', $cfg{'regex'}->{$oid}) . "; required");
    }
    # optional OID
    foreach my $oid (qw(2.5.4.6 2.5.4.17)) {
    }
    if (64 < length($data_oid{'2.5.4.10'}->{val})) {
        $txt = _get_text('EV_large', "64 < " . $data_oid{$oid}->{txt});
        $checks{'ev+'}->{val} .= $txt;
        _v2print("EV: " . $txt);
    }
    # validity <27 months
    if ($data{'valid_months'}->{val} > 27) {
        $txt = _get_text('cert_valid', "27 < " . $data{'valid_months'}->{val});
        $checks{'ev+'}->{val} .= $txt;
        _v2print("EV: " . $txt);
    }

    # TODO: wildcard no, SAN yes
    # TODO: cipher 2048 bit?
    # TODO: potential dangerous OID: '1.3.6.1.4.1.311.60.1.1'
    # TODO: Scoring: 100 EV+SGC; 80 EV; 70 EV-; 50 OV; 30 DV
    return;
} # checkev

sub checkroot($$)   {
    #? check if certificate is root CA
    my ($host, $port) = @_;
    $cfg{'done'}->{'checkroot'}++;
    return if (1 < $cfg{'done'}->{'checkroot'});

    # SEE Note:root-CA

    return;
} # checkroot

sub checkprot($$)   {
    #? check anything related to SSL protocol versions and ALPN, NPN
    my ($host, $port) = @_;
    my $ssl;
    _y_CMD("checkprot() " . $cfg{'done'}->{'checkprot'});
    $cfg{'done'}->{'checkprot'}++;
    return if (1 < $cfg{'done'}->{'checkprot'});
    # remember: check is 'yes' for empty value ""
    _trace("checkprot($host, $port){");

    # SSLv2 and SSLv3 are special:
    #   The protocol may supported by the target, but no ciphers offered. Only
    #   if at least one ciphers is supported, vulnerabilities may there, hence
    #   check if amount of ciphers > 0.
    if (_is_cfg_ssl('SSLv2')) {
        my $notxt = (0 < $prot{'SSLv2'}->{'cnt'}) ? " " : "";
        $checks{'hassslv2'} ->{val} = (_is_cfg_use('nullssl2')) ? $notxt : "";
            # SSLv2 enabled, but no ciphers is ok (aka 'yes') for --nullssl2
        $checks{'drown'}    ->{val} = $notxt;  # SSLv2 there, then potentially vulnerable to DROWN
    }
    if (_is_cfg_ssl('SSLv3')) {
        my $notxt = (0 < $prot{'SSLv3'}->{'cnt'}) ? " " : "";
        $checks{'hassslv3'} ->{val} = $notxt;
        $checks{'poodle'}   ->{val} = (0 < $prot{'SSLv3'}->{'cnt'}) ? "SSLv3" : "";  # POODLE if SSLv3 and ciphers
        # FIXME: should uses $cfg{'regex'}->{'POODLE'}, hence check in checkcipher() would be better
        # FIXME: TLSv1 is vulnerable too, but not TLSv11
        # FIXME: OSaft/Doc/help.txt ok now, but needs to be fixed too
    }
    if (_is_cfg_ssl('TLSv1')) {
        $checks{'hastls10'}->{val}  = " " if ($prot{'TLSv1'}->{'cnt'}  <= 0);
    }
    if (_is_cfg_ssl('TLSv11')) {
        $checks{'hastls11'}->{val}  = " " if ($prot{'TLSv11'}->{'cnt'} <= 0);
    }
    if (_is_cfg_ssl('TLSv12')) {
        $checks{'hastls12'}->{val}  = " " if ($prot{'TLSv12'}->{'cnt'} <= 0);
    }
    if (_is_cfg_ssl('TLSv13')) {
        $checks{'hastls13'}->{val}  = " " if ($prot{'TLSv13'}->{'cnt'} <= 0);
    }

    # check ALPN and NPN support
    checkalpn($host, $port);    #
    my ($key, $value);
    $key    = 'alpns';
    $value  = $data{$key}->{val}($host, $port);
    $checks{'hasalpn'}->{val}   = " " if ($value eq "");
    $key    = 'npns';
    $value  = $data{$key}->{val}($host, $port);
    $checks{'hasnpn'}->{val}    = " " if ($value eq "");
    _trace("checkprot() }");
    return;
} # checkprot


sub checkdest($$)   {
    #? check anything related to target and connection
    my ($host, $port) = @_;
    my $ciphers = shift;
    my ($key, $value, $ssl, $cipher, $cnt);
    _y_CMD("checkdest() " . $cfg{'done'}->{'checkdest'});
    $cfg{'done'}->{'checkdest'}++;
    return if (1 < $cfg{'done'}->{'checkdest'});
    # remember: check is 'yes' for empty value ""
    _trace("checkdest($host, $port){");

    checksni($host, $port);     # set checks according hostname
    # $cfg{'IP'} and $cfg{'rhost'} already contain $text{'disabled'}
    # if --proxyhost was used; hence no need to check for proxyhost again
    $checks{'reversehost'}->{val}   = $host . " <> " . $cfg{'rhost'} if ($cfg{'rhost'} ne $host);
    $checks{'reversehost'}->{val}   = $text{'na_dns'}   if (not _is_cfg_use('dns'));
    #$checks{'ip'}->{val}            = $cfg{'IP'}; # 12/2019: disabled
    # 12/2019: only relevant when target was IP, then $cfg{'ip'} must be identical to $cfg{'IP'}

    # SEE Note:Selected Protocol
    # get selected cipher and store in %checks, also check for PFS
    $cipher = $data{'cipher_selected'} ->{val}($host, $port);
    $ssl    = $data{'session_protocol'}->{val}($host, $port);
    $ssl    =~ s/[ ._-]//g;     # convert TLS1.1, TLS 1.1, TLS-1_1, etc. to TLS11
    $cnt    = 0;
    $cnt   += $prot{$_}->{'cnt'} foreach (@{$cfg{'version'}}); # count ciphers
    my @prot = grep{/(^$ssl$)/i} @{$cfg{'versions'}};
    if (1 > $cnt) {             # no protocol with ciphers found
            $checks{'cipher_pfs'}->{val}= $text{'miss_protocol'};
    } else {
        if (1 > $#prot) {       # found exactly one matching protocol
            $checks{'cipher_pfs'}->{val}= ("" eq _is_ssl_pfs($ssl, $cipher)) ? $cipher : "";
        } else {
            _warn("631: protocol '". join(';', @prot) . "' does not match; no selected protocol available");
        }
    }

    # PFS is scary if the TLS session ticket is not random
    #  we should have different tickets in %data0 and %data
    #  it's ok if both are empty 'cause then no tickets are used
    $key   = 'session_ticket';
    $value = $data{$key}->{val}($host, $port);
    if (defined $data0{$key}->{val}) {  # avoid Perl warning "Use uninitialized value in string"
        $checks{'session_random'}->{val} = $value if ($value eq $data0{$key}->{val});
    } else {
        $checks{'session_random'}->{val} = $text{'na'};
    }

    checkprot($host, $port);

    # vulnerabilities
    check_dh($host,$port);  # Logjam vulnerability
    #$checks{'ccs'}->{val}       = _isccs($host, $port); # TODO:
    $checks{'ccs'}->{val}       = "<<NOT YET IMPLEMENTED>>";
    $key    = 'compression';
    $value  = $data{$key}->{val}($host);
    $checks{$key}->{val}        = ($value =~ m/$cfg{'regex'}->{'nocompression'}/) ? "" : $value;
    $checks{'crime'}->{val}     = _is_ssl_crime($value, $data{'next_protocols'}->{val}($host));
    foreach my $key (qw(resumption renegotiation)) {
        next if ($checks{$key}->{val} !~ m/$text{'undef'}/);
        $value = $data{$key}->{val}($host);
        $checks{$key}->{val}    = ($value eq "") ? " " : "";
    }
    #     Secure Renegotiation IS NOT supported
    $value = $data{'renegotiation'}->{val}($host);
    $checks{'renegotiation'}->{val} = $value if ($value =~ m/ IS NOT /i);
    $value = $data{'resumption'}->{val}($host);
    $checks{'resumption'}->{val}    = $value if ($value !~ m/^Reused/);

    # check target specials
    foreach my $key (qw(krb5 psk_hint psk_identity master_secret srp session_ticket session_lifetime)) {
            # master_key session_id: see %check_dest above also
        next if ($checks{$key}->{val} !~ m/$text{'undef'}/);
        $value = $data{$key}->{val}($host);
        $checks{$key}->{val}    = ($value eq "") ? " " : "";
        $checks{$key}->{val}    = "None" if ($value =~ m/^\s*None\s*$/i);
        # if supported we have a value
        # TODO: see ZLIB also (seems to be wrong currently)
    }

    # time on server differs more than +/- 5 seconds?
    my $currenttime = time();
    $key    = 'session_starttime';
    $value  = $data{$key}->{val}($host);
    $checks{$key}->{val}        = "$value < $currenttime" if ($value < ($currenttime - 5));
    $checks{$key}->{val}        = "$value > $currenttime" if ($value > ($currenttime + 5));

    foreach my $key (qw(heartbeat)) {   # these are good if there is no value
        next if ($checks{$key}->{val} !~ m/$text{'undef'}/);
        $checks{$key}->{val}    = $data{$key}->{val}($host);
        $checks{$key}->{val}    = "" if ($checks{$key}->{val} =~ m/^\s*$/);
    }
    $value = $data{'ocsp_response'}->{val}($host);
    $checks{'ocsp_stapling'}->{val} = ($value =~ /.*no\s*response.*/i) ? $value : "";
        # for valid ocsp_stapling, ocsp_response should be something like:
        # Response Status: successful (0x0); Cert Status: good; This Update: Jan 01 00:23:42 2021 GMT; Next Update:
    _trace("checkdest() }");
    return;
} # checkdest

sub checkhttp($$)   {
    #? HTTP(S) checks
    my ($host, $port) = @_;
    my $key = "";
    _y_CMD("checkhttp() " . $cfg{'done'}->{'checkhttp'});
    $cfg{'done'}->{'checkhttp'}++;
    return if (1 < $cfg{'done'}->{'checkhttp'});
    # remember: check is 'yes' for empty value ""
    _trace("checkhttp($host, $port){");

    # collect information
    my $notxt = " "; # use a variable to make assignments below more human readable
    my $https_body    = $data{'https_body'}    ->{val}($host) || "";
    my $http_sts      = $data{'http_sts'}      ->{val}($host) || ""; # value may be undefined, avoid Perl error
    my $http_location = $data{'http_location'} ->{val}($host) || ""; #
    my $hsts_equiv    = $data{'hsts_httpequiv'}->{val}($host) || ""; #
    my $hsts_maxage   = $data{'hsts_maxage'}   ->{val}($host);       # 0 is valid here, hence || does not work
       $hsts_maxage   = -1 if ($hsts_maxage =~ m/^\s*$/);
    my $hsts_fqdn     = $http_location;
       $hsts_fqdn     =~ s|^(?:https:)?//([^/]*)|$1|i;  # get FQDN even without https:
       $hsts_fqdn     =~ s|/.*$||;                      # remove trailing path

    if ($https_body =~ /^<</) { # private string, see Net::SSLinfo
        _warn("641: HTTPS response failed, some information and checks are missing");
        _hint("consider using '--proto-alpn=,' also")   if ($https_body =~ /bad client magic byte string/);
    }

    $checks{'hsts_is301'}   ->{val} = $data{'http_status'}->{val}($host) if ($data{'http_status'}->{val}($host) !~ /301/); # RFC 6797 requirement
    $checks{'hsts_is30x'}   ->{val} = $data{'http_status'}->{val}($host) if ($data{'http_status'}->{val}($host) =~ /30[0235678]/); # not 301 or 304
    # perform checks
    # sequence important: first check if redirect to https, then check if empty
    $checks{'http_https'}   ->{val} = ($http_location !~ m/^\s*https:/) ? $http_location : "";
    $checks{'http_https'}   ->{val} = $notxt if ($http_location =~ m/^\s*$/); # if missing
    $checks{'hsts_redirect'}->{val} = $http_sts;  # 'yes' if empty
    if ($data{'https_sts'}->{val}($host) ne "") {
        my $fqdn =  $hsts_fqdn;
        $checks{'hsts_location'}->{val} = $data{'https_location'}->{val}($host);# 'yes' if empty
        $checks{'hsts_refresh'} ->{val} = $data{'https_refresh'} ->{val}($host);# 'yes' if empty
        $checks{'hsts_ip'}      ->{val} = ($host =~ m/\d+\.\d+\.\d+\.\d+/) ? $host : ""; # RFC 6797 requirement
        $checks{'hsts_fqdn'}    ->{val} = $hsts_fqdn   if ($http_location !~ m|^https://$host|i);
        $checks{'hsts_samehost'}->{val} = $hsts_fqdn   if ($fqdn ne $host);
        $checks{'hsts_sts'}     ->{val} = ($data{'https_sts'}   ->{val}($host) ne "") ? "" : $notxt;
        $checks{'sts_subdom'}   ->{val} = ($data{'hsts_subdom'} ->{val}($host) ne "") ? "" : $notxt;
        $checks{'sts_preload'}  ->{val} = ($data{'hsts_preload'}->{val}($host) ne "") ? "" : $notxt;
        $checks{'sts_maxage'}   ->{val} = (($hsts_maxage < $checks{'sts_maxage1m'}->{val}) or ($hsts_maxage > 1)) ? "" : $hsts_maxage;
        $checks{'sts_maxage'}   ->{val}.= ($checks{'sts_maxage'}->{val} eq "" ) ? "" : " = " . int($hsts_maxage / $checks{'sts_maxage1d'}->{val}) . " days" ; # pretty print
        $checks{'sts_maxagexy'} ->{val} = ($hsts_maxage > $checks{'sts_maxagexy'}->{val}) ? "" : "< $checks{'sts_maxagexy'}->{val}";
        $checks{'sts_maxage18'} ->{val} = ($hsts_maxage > $checks{'sts_maxage18'}->{val}) ? "" : "< $checks{'sts_maxage18'}->{val}";
        $checks{'sts_maxage0d'} ->{val} = ($hsts_maxage == 0) ? "0" : "";
        $checks{'hsts_httpequiv'}->{val} = $hsts_equiv; # RFC 6797 requirement; 'yes' if empty
        # other sts_maxage* are done below as they change {val}
        checkdates($host,$port);        # computes check{'sts_expired'}
    } else {
        # sts_maxage* are integers, must be set here to N/A
        foreach my $key (qw(sts_maxage00 sts_maxage0d sts_maxagexy sts_maxage18 sts_maxage1d sts_maxage1m sts_maxage1y )) {
            $checks{$key}   ->{val} = $text{'na_STS'};
        }
    }
    $checks{'hsts_fqdn'}    ->{val} = $text{'na'} if ($http_location eq "");  # useless without redirect
# TODO: invalid certs are not allowed for HSTS
    $checks{'https_pins'}   ->{val} = $notxt      if ($data{'https_pins'}->{val}($host) eq "");
# TODO: pins= ==> fingerprint des Zertifikats

    $notxt = $text{'na_STS'};
    $notxt = $text{'na_http'} if (not _is_cfg_use('http'));
    # NOTE: following sequence is important!
    foreach my $key (qw(sts_maxage1y sts_maxage1m sts_maxage1d)) {
        if ($data{'https_sts'}->{val}($host) ne "") {
            $checks{'sts_maxage'}->{score} = $checks{$key}->{score} if ($hsts_maxage < $checks{$key}->{val});
            $checks{$key}->{val}    = ($hsts_maxage < $checks{$key}->{val}) ? "" : "> $checks{$key}->{val}";
        } else {
            $checks{$key}->{val}    = $notxt;
            $checks{$key}->{score}  = 0;
        }
    }
    _trace("checkhttp() }");
    return;
} # checkhttp

sub _get_sstp_https {
    #? get result for SSTP request to host:port; returns '' for success, error otherwise
    my ($host, $port) = @_;
    my $ulonglong_max = '18446744073709551615';
    my $url     = '/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/';
    my $length  = "";
    my $server  = "";
    my ($status, %headers);
    my $request = << "EoREQ";
SSTP_DUPLEX_POST $url HTTP/1.1
SSTPCORRELATIONID:{deadbeef-cafe-affe-caba-0000000000}
Content-Length:   $ulonglong_max
Connection:       close
Host:             $host

EoREQ

    #_dbx "_get_sstp_https: request {\n$request#}";
    $Net::SSLeay::slowly = 1;   # otherwise some server respond with "400 Bad Request"
    my $dum      = $Net::SSLeay::slowly;    # keeps Perl happy
    my $response = Net::SSLeay::sslcat($host, $port, $request);
    _trace2("_get_sstp_https: response {\n$response#}");

    # if SSTP supported, we expect something like::
    #   HTTP/1.1 200
    #   Content-Length: 18446744073709551615
    #   Server: Microsoft-HTTPAPI/2.0
    #   Date: Mon, 19 May 2019 23:42:42 GMT
    #   Connection: close

    # convert response to hash; only HTTP header lines are expected, so each
    # line is a key:value pair, except the very first status line
    $response =~ s#HTTP/1.. #STATUS: #; # first line is status line, add :
    $response =~ s#(?:\r\n\r\n|\n\n|\r\r).*$##ms;   # remove HTTP body
    _trace2("_get_sstp_https: response= #{\n$response\n#}");
    return "<<empty response>>" if ($response =~ m/^\s*-1/);    # something wrong
    %headers  = map { split(/:/, $_, 2) } split(/[\r\n]+/, $response);
    # FIXME: map() fails if any header contains [\r\n] (split over more than one line)
    # use elaborated trace with --trace=3 because some servers return strange results
    _trace2("_get_sstp_https: headers= " . keys %headers);
    foreach my $key (keys %headers) {
        _trace2("_get_sstp_https: headers: $key=$headers{$key}");
    }
    return '401' if ($headers{'STATUS'} =~ m#^\s*401*#); # Microsoft: no SSTP supported
    return '400' if ($headers{'STATUS'} =~ m#^\s*400*#); # other: no SSTP supported
        # lazy checks, may also match 4000 etc.
    if ($headers{'STATUS'} !~ m#^\s*(?:[1234][0-9][0-9]|500)\s*$#) {
        return "<<connection to '$url' failed>>";
    }
    if ($headers{'STATUS'} =~ m#^\s*200\s*$#) {
        $server = $headers{'Server'};
        $length = $headers{'Content-Length'};
        return _get_text('invalid', "Content-Length: $length")  if ($length != $ulonglong_max);
        return _get_text('invalid', "Server: $server")          if ($server !~ /Microsoft-HTTPAPI/);
    } else {
        return "<<unexpected response: $headers{'STATUS'}>>";
    }
    return '';
} # _get_sstp_https

sub checksstp       {
    #? check if host:port supports SSTP
    my ($host, $port) = @_;
    _y_CMD("checksstp() " . $cfg{'done'}->{'checksstp'});
    $cfg{'done'}->{'checksstp'}++;
    return if (1 < $cfg{'done'}->{'checksstp'});
    return if not defined $host;
    my $value = _get_sstp_https($host, $port);
    $checks{'sstp'}->{val} = (0 < length($value)) ? "" : " ";
    _v_print("checksstp: $value") if length($value);   # reason why not supported
    return;
} # checksstp

sub checkssl($$)    {
    #? SSL checks
    my ($host, $port) = @_;
    my $ciphers = shift;
    _y_CMD("checkssl() "  . $cfg{'done'}->{'checkssl'});
    $cfg{'done'}->{'checkssl'}++;
    return if (1 < $cfg{'done'}->{'checkssl'});
    _trace("checkssl($host, $port){");

    $cfg{'no_cert_txt'} = $text{'na_cert'} if ($cfg{'no_cert_txt'} eq ""); # avoid "yes" results
    if (_is_cfg_use('cert')) {
        # all checks based on certificate can't be done if there was no cert, obviously
        checkcert( $host, $port);       # SNI, wildcards and certificate
        checkdates($host, $port);       # check certificate dates (since, until, exired)
        checkdv(   $host, $port);       # check for DV
        checkev(   $host, $port);       # check for EV
        check02102($host, $port);       # check for BSI TR-02102-2
        check03116($host, $port);       # check for BSI TR-03116-4
        check7525( $host, $port);       # check for RFC 7525
        check6125( $host, $port);       # check for RFC 6125 (identifiers only)
        check2818( $host, $port);       # check for RFC 2818 (subjectAltName only)
        checksni(  $host, $port);       # check for SNI
        checksizes($host, $port);       # some sizes
    } else {
        $cfg{'done'}->{'checksni'}++;   # avoid checking again
        $cfg{'done'}->{'checkdates'}++; # "
        $cfg{'done'}->{'checksizes'}++; # "
        $cfg{'done'}->{'check02102'}++; # "
        $cfg{'done'}->{'check03116'}++; # "
        $cfg{'done'}->{'check7525'}++;  # "
        $cfg{'done'}->{'check6125'}++;  # "
        $cfg{'done'}->{'check2818'}++;  # "
        $cfg{'done'}->{'checkdv'}++;    # "
        $cfg{'done'}->{'checkev'}++;    # "
        foreach my $key (sort keys %checks) {   # anything related to certs need special setting
            $checks{$key}->{val} = $cfg{'no_cert_txt'} if (_is_member($key, \@{$cfg{'check_cert'}}));
        }
        $checks{'hostname'} ->{val} = $cfg{'no_cert_txt'};
        $checks{'tr_02102+'}->{val} = $cfg{'no_cert_txt'};
        $checks{'tr_02102-'}->{val} = $cfg{'no_cert_txt'};
        $checks{'tr_03116+'}->{val} = $cfg{'no_cert_txt'};
        $checks{'tr_03116-'}->{val} = $cfg{'no_cert_txt'};
        $checks{'rfc_6125_names'}->{val} = $cfg{'no_cert_txt'};
        $checks{'rfc_2818_names'}->{val} = $cfg{'no_cert_txt'};
    }

    if (_is_cfg_use('http')) {
        checkhttp( $host, $port);
    } else {
        $cfg{'done'}->{'checkhttp'}++;
        foreach my $key (sort keys %checks) {
            $checks{$key}->{val} = $text{'na_http'} if (_is_member($key, \@{$cfg{'cmd-http'}}));
        }
    }
    # some checks accoring ciphers and compliance are done in checkciphers()
    # and check02102(); some more are done in checkhttp()
    # now do remaining for %checks
    checkdest( $host, $port);

# TODO: to be implemented
    foreach my $key (qw(verify_hostname verify_altname verify dates fingerprint)) {
# TODO: only if( not _is_cfg_use('cert'))
    }

    _trace("checkssl() }");
    return;
} # checkssl

sub check_exitcode  {
    #? compute exitcode; returns number of failed checks or insecure settings
    # SEE Note:--exitcode
    _y_CMD("check_exitcode()");
    my $exitcode   = 0; # total count
    my $cnt_prot   = 0; # number of insecure protocol versions
                        # only TLSv12 is considered secure
    my $cnt_ciph   = 0; # number of insecure ciphers per protocol
    my $cnt_ciphs  = 0; # total number of insecure ciphers
    my $cnt_pfs    = 0; # number ciphers without PFS per protocol
    my $cnt_nopfs  = 0; # total number ciphers without PFS
    my $old_verbose= $cfg{'verbose'};       # save global verbose
    $cfg{'verbose'} += $cfg{'out'}->{'exitcode'};  # --v and/or --exitcode-v
    if (_is_cfg_out('exitcode_checks')) {
        $exitcode  = $checks{'cnt_checks_no'} ->{val};
        $exitcode -= $checks{'cnt_checks_noo'}->{val};
    }
# TODO: $cfg{'exitcode_sizes'}
    my $__tableline = "-------------+---+---+---+---+------+------------";
    my $__exitline  = "---------------------------------------------------- exitcode";
    _v_print("$__exitline {");
    _v_print(sprintf("%s\t%3s %3s %3s %3s %7s %s", qw(protocol H M L W no-PFS insecure)));
    _v_print($__tableline);
    foreach my $ssl (@{$cfg{'versions'}}) { # SEE Note:%prot
        next if (0 == $cfg{$ssl});      # not requested, don't count
# TODO: counts protocol even if no cipher was supported, is this insecure?
        $cnt_prot++ if (0 < $cfg{$ssl});
        $cnt_pfs   = $prot{$ssl}->{'cnt'} - $#{$prot{$ssl}->{'ciphers_pfs'}};
        $cnt_pfs   = 0 if (0 >= $prot{$ssl}->{'cnt'});  # useless if there're no ciphers
        $exitcode += $cnt_pfs                if (_is_cfg_out('exitcode_pfs'));
        $cnt_ciph  = 0;
        $cnt_ciph += $prot{$ssl}->{'MEDIUM'} if (_is_cfg_out('exitcode_medium'));
        $cnt_ciph += $prot{$ssl}->{'WEAK'}   if (_is_cfg_out('exitcode_weak'));
        $cnt_ciph += $prot{$ssl}->{'LOW'}    if (_is_cfg_out('exitcode_low'));
        $exitcode += $cnt_ciph;
        _v_print(sprintf("%-7s\t%3s %3s %3s %3s %3s\t%s", $ssl,
                $prot{$ssl}->{'HIGH'}, $prot{$ssl}->{'MEDIUM'},
                $prot{$ssl}->{'LOW'},  $prot{$ssl}->{'WEAK'},
                $cnt_pfs, $cnt_ciph,
        ));
        $cnt_ciphs += $cnt_ciph;
        $cnt_nopfs += $cnt_pfs;
    }
    # print overview of calculated exitcodes;
    # for better human readability, counts disabled by --exitcode-no-* options
    # are marked as "ignored"
    #my $ign_ciphs   = (0 < ($cfg{'out'}->{'exitcode_low'} + $cfg{'out'}->{'exitcode_weak'} + $cfg{'out'}->{'exitcode_medium'}))   ? "" : " (count ignored)";
    my $ign_ciphs   = (_is_cfg_out('exitcode_low') or _is_cfg_out('exitcode_weak') or _is_cfg_out('exitcode_medium'))   ? "" : " (count ignored)";
    my $ign_checks  = (_is_cfg_out('exitcode_checks')) ? "" : " (count ignored)";
    my $ign_prot    = (_is_cfg_out('exitcode_prot'))   ? "" : " (count ignored)";
    my $ign_pfs     = (_is_cfg_out('exitcode_pfs'))    ? "" : " (count ignored)";
    _v_print($__tableline);
    $cnt_prot-- if (0 < $cfg{'TLSv12'});
    $cnt_prot-- if (0 < $cfg{'TLSv13'});
    $exitcode += $cnt_prot if (_is_cfg_out('exitcode_prot'));
    $checks{'cnt_exitcode'}->{val} = $exitcode;
    _v_print(sprintf("%s\t%5s%s", "Total number of insecure protocols",  $cnt_prot,  $ign_prot));
    _v_print(sprintf("%s\t%5s%s", "Total number of insecure ciphers",    $cnt_ciphs, $ign_ciphs));
    _v_print(sprintf("%s\t%5s%s", "Total number of ciphers without PFS", $cnt_nopfs, $ign_pfs));
    _v_print(sprintf("%s\t%5s%s", $checks{'cnt_checks_no'} ->{txt}, $checks{'cnt_checks_no'} ->{val}, $ign_checks));
    _v_print(sprintf("%s %3s%s",  $checks{'cnt_checks_noo'}->{txt}, "-".$checks{'cnt_checks_noo'}->{val}, $ign_checks));
    _v_print(sprintf("%s\t%5s",   $checks{'cnt_exitcode'}  ->{txt}, $checks{'cnt_exitcode'}  ->{val}));
    _v_print("$__exitline }");
    $cfg{'verbose'} = $old_verbose; # restore
    return $checks{'cnt_exitcode'}->{val};
} # check_exitcode

sub scoring         {
    #? compute scoring of all checks; sets values in %scores
    my ($host, $port) = @_;
    my $value;

    # http
    #  some scores are set in checkhttp()
    my $http_location = $data{'http_location'}->{val}($host) || "";
    $scores{'check_http'}->{val}    = 100;
    $checks{'hsts_fqdn'}->{score}   = 0 if ($http_location eq "");

    foreach my $key (sort keys %checks) {
        next if ($key =~ m/^(ip|reversehost)/); # not scored
        next if ($key =~ m/^(sts_)/);           # needs special handlicg
        next if ($key =~ m/^(closure|fallback|cps|krb5|lzo|open_pgp|order|https_pins|psk_|rootcert|srp|zlib)/); ## no critic qw(RegularExpressions::ProhibitComplexRegexes)
          # FIXME: not yet scored
        next if ($key =~ m/^TLSv1[123]/); # FIXME:
        $value = $checks{$key}->{val};
        # TODO: go through @cipher_results
# TODO   foreach my $sec (qw(LOW WEAK MEDIUM HIGH -?-)) {
# TODO       # keys in %prot look like 'SSLv2->LOW', 'TLSv11->HIGH', etc.
# TODO       $key = $ssl . '-' . $sec;
# TODO       if ($checks{$key}->{val} != 0) {    # if set, decrement score
# TODO           $scores{'check_ciph'}->{val} -= _getscore($key, 'egal', \%checks);
# TODO printf "%20s: %4s %s\n", $key, $scores{'check_ciph'}->{val}, _getscore($key, 'egal', \%checks);
# TODO       }
# TODO   }
        $scores{'check_size'}->{val} -= _getscore($key, $value, \%checks) if ($checks{$key}->{typ} eq "sizes");
#       $scores{'check_ciph'}->{val} -= _getscore($key, $value, \%checks) if ($checks{$key}->{typ} eq "cipher");
        $scores{'check_http'}->{val} -= _getscore($key, $value, \%checks) if ($checks{$key}->{typ} eq "https"); # done above
        $scores{'check_cert'}->{val} -= _getscore($key, $value, \%checks) if ($checks{$key}->{typ} eq "certificate");
        $scores{'check_conn'}->{val} -= _getscore($key, $value, \%checks) if ($checks{$key}->{typ} eq "connection");
        $scores{'check_dest'}->{val} -= _getscore($key, $value, \%checks) if ($checks{$key}->{typ} eq "destination");
#_dbx "$key " . $checks{$key}->{val} if($checks{$key}->{typ} eq "connection");
#_dbx "score certificate $key : ".$checks{$key}->{val}." - ". $checks{$key}->{score}." = ".$scores{'check_cert'}->{val} if($checks{$key}->{typ} eq "certificate");
#_dbx "score connection  $key : ".$checks{$key}->{val}." - ". $checks{$key}->{score}." = ".$scores{'check_conn'}->{val} if($checks{$key}->{typ} eq "connection");
#_dbx "score destination $key : ".$checks{$key}->{val}." - ". $checks{$key}->{score}." = ".$scores{'check_dest'}->{val} if($checks{$key}->{typ} eq "destination");
#_dbx "score http/https  $key : ".$checks{$key}->{val}." - ". $checks{$key}->{score}." = ".$scores{'check_http'}->{val} if($checks{$key}->{typ} eq "https");
    }
    return;
} # scoring

#| definitions: print functions
#| -------------------------------------

sub _cleanup_data   {
    # cleanup some values (strings) in data
    my ($key, $value) = @_;
    if ($key eq "https_status") {
        # remove non-printables from HTTP Status line
        # such bytes may occour if SSL connection failed
        #_v_print("# removing non-printable characters from $data{$key}->{txt}:");
        _v_print("removing non-printable characters from $key: $value");
        $value =~ s/[^[:print:]]+//g;   # FIXME: not yet perfect
    }
    if ($key =~ m/X509$/) {
        $value =~ s#/([^=]*)#\n   ($1)#g;
        $value =~ s#=#\t#g;
    }
    return $value;
} # _cleanup_data

sub _printdump      {
    my ($label, $value) = @_;
        $label =~ s/\n//g;
        $label = sprintf("%s %s", $label, '_' x (75 -length($label)));
    $value = "" if not defined $value;  # value parameter is optional
    printf("#{ %s\n\t%s\n#}\n", $label, $value);
    # using curly brackets 'cause they most likely are not part of any data
    return;
} # _printdump
sub printdump       {
    #? just dumps internal database %data and %check_*
    my ($legacy, $host, $port) = @_;   # NOT IMPLEMENTED
    print '######################################################################### %data';
    foreach my $key (keys %data) {
        next if (_is_cfg_intern($key) > 0);  # ignore aliases
        _printdump($data{$key}->{txt}, $data{$key}->{val}($host));
    }
    print '######################################################################## %check';
    foreach my $key (keys %checks) { _printdump($checks{$key}->{txt}, $checks{$key}->{val}); }
    return;
} # printdump

sub print_ruler     { printf("=%s+%s\n", '-'x38, '-'x35) if (_is_cfg_out('header')); return; }
    #? print header ruler line

sub print_header    {
    #? print title line and table haeder line if second argument given
    my ($txt, $desc, $rest, $header) = @_;
    return if (0 >= $header);
    printf("$txt\n");
    return if ($desc =~ m/^ *$/); # title only if no more arguments
    printf("= %-37s %s\n", $text{'desc'}, $desc);
    print_ruler();
    return;
} # print_header

sub print_footer    {
    #? print footer line according given legacy format
    my $legacy  = shift;
    if ($legacy eq 'sslyze')    { print "\n\n SCAN COMPLETED IN ...\n\n"; }
    # all others are empty, no need to do anything
    return;
} # print_footer

sub print_title     {
    #? print title according given legacy format
    my ($legacy, $ssl, $host, $port, $header) = @_;
    local    $\ = "\n";
    if ($legacy eq 'sslyze')    {
        my $txt = " SCAN RESULTS FOR " . $host . " - " . $cfg{'IP'};
        print "$txt";
        print " " . "-" x length($txt);
    }
    my $txt     = _get_text('out_ciphers', $ssl);
    if ($legacy eq 'sslaudit')  {} # no title
    if ($legacy eq 'sslcipher') { print "Testing $host ..."; }
    if ($legacy eq 'ssldiagnos'){
        print
            "----------------TEST INFO---------------------------\n",
            "[*] Target IP: $cfg{'IP'}\n",
            "[*] Target Hostname: $host\n",
            "[*] Target port: $port\n",
            "----------------------------------------------------\n";
    }
    if ($legacy eq 'sslscan')   { $host =~ s/;/ on port /; print "Testing SSL server $host\n"; }
    if ($legacy eq 'ssltest')   { print "Checking for Supported $ssl Ciphers on $host..."; }
    if ($legacy eq 'ssltest-g') { print "Checking for Supported $ssl Ciphers on $host..."; }
    if ($legacy eq 'testsslserver') { print "Supported cipher suites (ORDER IS NOT SIGNIFICANT):\n  " . $ssl; }
    if ($legacy eq 'thcsslcheck'){print "\n[*] now testing $ssl\n" . "-" x 76; }
    if ($legacy =~ /(compact|full|owasp|quick|simple)/) {
        print_header($txt, "", "", 1);  # SEE Note:Cipher and Protocol
    }
    return;
} # print_title

sub print_line($$$$$$)  {
    #? print label and value separated by separator
    #? print hostname and key depending on --showhost and --trace-key option
    my ($legacy, $host, $port, $key, $text, $value) = @_;
        $text   = $STR{NOTXT} if not defined $text; # defensive programming ..
        $value  = $STR{UNDEF} if not defined $value;# .. missing variable declaration
        $value  = Encode::decode("UTF-8", $value);
    # general format of a line is:
    #       host:port:#[key]:label: \tvalue
    # legacy=_cipher is special: does not print label and value
    my  $label  = "";
        $label  = sprintf("%s:%s%s", $host, $port, $text{'separator'}) if (_is_cfg_out('hostname'));
    if ($legacy eq '_cipher') {
        printf("%s", $label)                        if (_is_cfg_out('hostname'));
        printf("#[%s]%s", $key, $text{'separator'}) if (_is_cfg_out('traceKEY'));
        return;
    }
        $label .= sprintf("#[%-18s", $key . ']'  . $text{'separator'}) if (_is_cfg_out('traceKEY'));
    if ($legacy =~ m/(compact|full|quick)/) {
        $label .= sprintf("%s",    $text . $text{'separator'});
    } else {
        if ($cfg{'label'} eq 'key') {
            $label .= sprintf("[%s]",  $key);
        } else {
            $label .= sprintf("%-36s", $text . $text{'separator'});
        }
    }
    # formats full, quick and compact differ in separator
    my $sep = "\t";
       $sep = "\n\t" if ($legacy eq 'full');
       $sep = ""     if ($legacy =~ m/(compact|quick)/);
    printf("%s%s%s\n", $label, $sep, $value);
    return;
} # print_line

sub print_data($$$$)    {
    # print given label and text from %data according given legacy format
    my ($legacy, $host, $port, $key) = @_;
    if (_is_hashkey($key, \%data) < 1) {        # silently ignore unknown labels
        _warn("801: unknown label '$key'; output ignored"); # seems to be a programming error
        return;
    }
    my $label = ($data{$key}->{txt} || "");     # defensive programming ..
    my $value =  $data{$key}->{val}($host, $port) || "";
       $value = _cleanup_data($key, $value);
    if ($key =~ m/X509$/) {                     # always pretty print
        $key =~ s/X509$//;
        # $value done in _cleanup_data()
        print_line($legacy, $host, $port, $key, $data{$key}->{txt}, $value);
        return;
    }
    if ((1 == _is_cfg_hexdata($key)) && ($value !~ m/^\s*$/)) {
        # check for empty $value to avoid warnings with -w
        # pubkey_value may look like:
        #   Subject Public Key Info:Public Key Algorithm: rsaEncryptionPublic-Key: (2048 bit)Modulus=00c11b:...
        # where we want to convert the key value only but not its prefix
        # hence the final : is converted to =
        # (seems to happen on Windows only; reason yet unknown)
        $value =~ s/([Mm]odulus):/$1=/; #
        my ($k, $v) = split(/=/, $value);
        if (defined $v) {       # i.e SHA Fingerprint=
            $k .= "=";
        } else {
            $v  = $k;
            $k  = "";
        }
        if ($cfg{'format'} eq "hex") {
            $v =~ s#(..)#$1:#g;
            $v =~ s#:$##;
        }
        if ($cfg{'format'} eq "esc") {
            $v =~ s#(..)#\\x$1#g;
        }
        if ($cfg{'format'} eq "0x") {
            $v =~ s#(..)#0x$1 #g;
            $v =~ s# $##;
        }
        $value = $k . $v;
    }
    $value = "\n" . $value if (_is_member($key, \@{$cfg{'cmd-NL'}})); # multiline data
    if ($legacy eq 'compact') {
        $value =~ s#:\n\s+#:#g; # join lines ending with :
        $value =~ s#\n\s+# #g;  # squeeze leading white spaces
        $value =~ s#[\n\r]#; #g;# join all lines
        $label =~ s#[\n]##g;
    }
    if ($legacy eq 'full') {    # do some pretty printing
        if ($label =~ m/(^altname)/) { $value =~ s#^ ##;       $value =~ s# #\n\t#g; }
        if ($label =~ m/(subject)/)  { $value =~ s#/#\n\t#g;   $value =~ s#^\n\t##m; }
        if ($label =~ m/(issuer)/)   { $value =~ s#/#\n\t#g;   $value =~ s#^\n\t##m; }
        if ($label =~ m/(serial|modulus|sigkey_value)/) {
                                       $value =~ s#(..)#$1:#g; $value =~ s#:$##; }
        if ($label =~ m/((?:pubkey|sigkey)_algorithm|signame)/) {
            $value =~ s#(with)# $1 #ig;
            $value =~ s#(encryption)# $1 #ig;
        }
    }
    print_line($legacy, $host, $port, $key, $label, $value);
    osaft::printhint($key) if (_is_cfg_out('hint_info'));   # SEE Note:hints
    return;
} # print_data

sub print_check($$$$$)  {
    #? print label and result of check
    my ($legacy, $host, $port, $key, $value) = @_;
    $value = $checks{$key}->{val} if not defined $value;# defensive programming ..
    my $label = "";
    $label = $checks{$key}->{txt} if ($cfg{'label'} ne 'key'); # TODO: $cfg{'label'} should be parameter
    print_line($legacy, $host, $port, $key, $label, $value);
    osaft::printhint($key) if (_is_cfg_out('hint_check'));  # SEE Note:hints
    return;
} # print_check

sub print_size($$$$)    {
    #? print label and result for length, count, size, ...
    my ($legacy, $host, $port, $key) = @_;
    my $value = "";
    $value = " bytes" if ($key =~ /^(len)/);
    $value = " bits"  if ($key =~ /^len_(modulus|publickey|sigdump)/);
    print_check($legacy, $host, $port, $key, $checks{$key}->{val} . $value);
    return;
} # print_size

sub print_cipherruler_dh {printf("=   %s+%s\n", "-"x35, "-"x25) if (_is_cfg_out('header')); return; }
    #? print header ruler line for ciphers with DH parameters
sub print_cipherruler   { printf("=   %s+%s+%s\n", "-"x35, "-"x7, "-"x8) if (_is_cfg_out('header')); return; }
    #? print header ruler line for ciphers
sub print_cipherhead($) {
    #? print header line according given legacy format
    my $legacy  = shift;
    return if (not _is_cfg_out('header'));
    if ($legacy eq 'sslscan')   { print "\n  Supported Server Cipher(s):"; }
    if ($legacy eq 'ssltest')   { printf("   %s, %s (%s)\n",  'Cipher', 'Enc, bits, Auth, MAC, Keyx', 'supported'); }
    #if ($legacy eq 'ssltest-g') { printf("%s;%s;%s;%s\n", 'compliant', 'host:port', 'protocol', 'cipher', 'description'); } # old version
    if ($legacy eq 'ssltest-g') { printf("Status(Compliant,Non-compliant,Disabled);Hostname:Port;SSL-Protocol;Cipher-Name;Cipher-Description\n"); }
    if ($legacy eq 'simple')    { printf("=   %-34s%s\t%s\n", $text{'cipher'}, $text{'support'}, $text{'security'});
                                  print_cipherruler(); }
    if ($legacy eq 'owasp')     { printf("=   %-34s\t%s\n", $text{'cipher'}, $text{'security'});
                                  print_cipherruler(); }  # TODO: ruler is same as for legacy=simple
    if ($legacy eq 'cipher_dh') { printf("=   %-34s\t%s\n", $text{'cipher'}, $text{'dh_param'});
                                  print_cipherruler_dh(); }
    if ($legacy eq 'full')      {
        # my @heads =  @{$ciphers_desc{'head'}};# not used because not all parts wanted
        printf("= host:port\tsupport\tprot.\tsec\tkeyx\tauth\tenc      bits\tmac\tcipher key\tcipher name\tcomment\n");
    }
    # all others are empty, no need to do anything
    return;
} # print_cipherhead

sub print_cipherline($$$$$$) {
    #? print cipher check result according given legacy format
    my ($legacy, $ssl, $host, $port, $key, $support) = @_;
    my $cipher= OSaft::Ciphers::get_name($key);
    my $bits  = OSaft::Ciphers::get_bits($key);
    my $sec   = OSaft::Ciphers::get_sec($key); # will be changed for --legacy=owasp
       $sec   = osaft::get_cipher_owasp($cipher) if ('owasp' eq $legacy);
       $sec   = "-"    if (('no' eq $support)  and  ('owasp' eq $legacy));
   #my $desc  = OSaft::Ciphers::get_data($key);# not yet used
    my $yesno = $text{'legacy'}->{$legacy}->{$support};
    # first our own formats
    if ($legacy =~ m/compact|full|owasp|quick|simple|key/) {
        my $k = sprintf("%s", OSaft::Ciphers::get_key($cipher));
        print_line('_cipher', $host, $port, $key, $cipher, ""); # just host:port:#[key]:
        if ('key' eq $cfg{'label'}) {   # TODO: $cfg{'label'} should be a parameter
            $k = "[$key]\t";
        } else {
            $k = "    ";
        }
        #printf("%s%-28s\t%s\t%s\n",     $k, $cipher, $yesno, $sec) if ($legacy eq 'full');
        printf("%s%-28s\t%s\n",         $k, $cipher, $sec        ) if ($legacy eq 'owasp');
        printf("%s%-28s\t(%s)\t%s\n",   $k, $cipher, $bits,  $sec) if ($legacy eq 'quick');
        printf("%s%-28s\t%s\t%s\n",     $k, $cipher, $yesno, $sec) if ($legacy eq 'simple');
        printf("%s %s %s\n",                $cipher, $yesno, $sec) if ($legacy eq 'compact');
        printf("%s%s:%s\t%s\t%s\t%s\t%s\t%s\t%s%7s\t%s\t%s\t%s\t%s\n",
                $k, $host, $port, $yesno, $ssl, $sec,
                OSaft::Ciphers::get_keyx($key),
                OSaft::Ciphers::get_auth($key),
                OSaft::Ciphers::get_enc( $key),
                $bits,
                OSaft::Ciphers::get_mac( $key),
                $key,
                $cipher,
                OSaft::Ciphers::get_const($key),
             ) if ($legacy eq 'full');
        # TODO: check if  OSaft::Ciphers::get_ssl($key) matches $ssl
        return;
    }
    # now legacy formats  # TODO: should be moved to postprocessor
    if ($legacy eq 'sslyze')    {
        if ($support eq 'yes')  {
            $support = sprintf("%4s bits", $bits) if ($support eq 'yes');
        } else {
            $support = $yesno;
        }
        printf("\t%-24s\t%s\n", $cipher, $support);
    }
    if ($legacy eq 'sslaudit')  {
        # SSLv2 - DES-CBC-SHA - unsuccessfull
        # SSLv3 - DES-CBC3-SHA - successfull - 80
        printf("%s - %s - %s\n", $ssl, $cipher, $yesno);
    }
    if ($legacy eq 'sslcipher') {
        #   TLSv1:EDH-RSA-DES-CBC3-SHA - ENABLED - STRONG 168 bits
        #   SSLv3:DHE-RSA-AES128-SHA - DISABLED - STRONG 128 bits
        $sec = 'INTERMEDIATE:' if ($sec =~ /LOW/i);
        $sec = 'STRONG'        if ($sec =~ /high/i);
        $sec = 'WEAK'          if ($sec =~ /weak/i);
        printf("   %s:%s - %s - %s %s bits\n", $ssl, $cipher, $yesno, $sec, $bits);
    }
    if ($legacy eq 'ssldiagnos') {
        # [+] Testing WEAK: SSL 2, DES-CBC3-MD5 (168 bits) ... FAILED
        # [+] Testing STRONG: SSL 3, AES256-SHA (256 bits) ... CONNECT_OK CERT_OK
        $sec = ($sec =~ /high/i) ? 'STRONG' : 'WEAK';
        printf("[+] Testing %s: %s, %s (%s bits) ... %s\n", $sec, $ssl, $cipher, $bits, $yesno);
    }
    if ($legacy eq 'sslscan')   {
        #    Rejected  SSLv3   256 bits  ADH-AES256-SHA
        #    Accepted  TLSv1.2 256 bits  AES256-SHA256
        $bits = sprintf("%3s bits", $bits);
#        printf("    %s  %s  %s\n", $ssl, $bit, $cipher);
# TODO: new format 1.11.0
        printf("Accepted  %s    %s bits  %s\n", $ssl, $bits, $cipher);
    }
    if ($legacy eq 'thcsslcheck') {
        # AES256-SHA - 256 Bits -   supported
        printf("%30s - %3s Bits - %11s\n", $cipher, $bits, $yesno);
    }
        # compliant;host:port;protocol;cipher;description
    if ($legacy eq 'ssltest')   {
        # cipher, description, (supported)
        return if ("" eq $cipher);  # defensive programming ..
            # TODO: analyse when $cipher could be "", should not happen
        printf("   %s, %s %s bits, %s Auth, %s MAC, %s Kx (%s)\n", $cipher,
                OSaft::Ciphers::get_enc( $key), $bits,
                OSaft::Ciphers::get_auth($key), OSaft::Ciphers::get_mac( $key),
                OSaft::Ciphers::get_keyx($key), $yesno
              );
    }
    if ($legacy eq 'ssltest-g') {
        return if ("" eq $cipher);  # defensive programming ..
        printf("%s;%s;%s;%s;%s %s bits, %s Auth, %s MAC, %s Kx\n",
                'C', $host . ":" . $port, $ssl, $cipher,
                OSaft::Ciphers::get_enc( $key), $bits,
                OSaft::Ciphers::get_auth($key), OSaft::Ciphers::get_mac( $key),
                OSaft::Ciphers::get_keyx($key), 
              );
    }
    if ($legacy eq 'testsslserver') { printf("    %s\n", $cipher); }
    return;
} # print_cipherline

sub print_cipherpreferred($$$$) {
    #? print preferred cipher according given legacy format
    my ($legacy, $ssl, $host, $port) = @_;
    my $yesno   = 'yes';
    if ($legacy eq 'sslyze')    { print "\n\n      Preferred Cipher Suites:"; }
    if ($legacy eq 'sslaudit')  {} # TODO: cipher name should be DEFAULT
    if ($legacy eq 'sslscan')   { print "\n  Preferred Server Cipher(s):"; $yesno = "";}
    # all others are empty, no need to do anything
    my $key = OSaft::Ciphers::get_key($data{'cipher_selected'}->{val}($host)); # TODO use key
    print_cipherline($legacy, $ssl, $host, $port, $key, $yesno);
    return;
} # print_cipherpreferred

sub print_ciphertotals($$$$) {
    #? print total number of ciphers supported for SSL version according given legacy format
    my ($legacy, $ssl, $host, $port) = @_;
    if ($legacy eq 'ssldiagnos') {
        print "\n-= SUMMARY =-\n";
        printf("Weak:         %s\n", $prot{$ssl}->{'WEAK'});
        printf("Intermediate: %s\n", $prot{$ssl}->{'MEDIUM'}); # MEDIUM
        printf("Strong:       %s\n", $prot{$ssl}->{'HIGH'});   # HIGH
    }
    if ($legacy =~ /(compact|full|owasp|quick|simple)/) {
        print_header(_get_text('out_summary', $ssl), "", $cfg{'out'}->{'header'});
        _trace_cmd('%checks');
        foreach my $key (qw(LOW WEAK MEDIUM HIGH -?-)) {
            print_line($legacy, $host, $port, "$ssl-$key", $prot_txt{$key}, $prot{$ssl}->{$key});
            # NOTE: "$ssl-$key" does not exist in %checks or %prot
        }
    }
    return;
} # print_ciphertotals

sub _is_print_cipher    {
    #? return 1 if parameter indicate printing
    my $enabled = shift;
    my $print_disabled = shift;
    my $print_enabled  = shift;
    return 1 if ($print_disabled == $print_enabled);
    return 1 if ($print_disabled && ($enabled eq 'no' ));
    return 1 if ($print_enabled  && ($enabled eq 'yes'));
    return 0;
} # _is_print_cipher

#  NOTE: Perl::Critic's violation for next 2 subs are false positives
sub _print_cipher_results       {
    #? print all ciphers from %results of $ssl if match $yesno; returns number of checked ciphers for $ssl
    my $legacy  = shift;
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my $yesno   = shift;    # only print these results, print all if empty
    my $results = shift;    # reference to hash with cipher keys for $ssl
    my $total   = 0;
    # list of ciphers in $results->{'sorted'} is sorted according strength
    # most strong ciphers should be printed first, hence loop over list of
    # keys in 'sorted' instead of (keys %$results).
    foreach my $key (@{$results->{'sorted'}}) {
        if (not $results->{$key}) { # defensive programming ..
            _warn("863: unknown cipher key '$key'; key ignored");
            next;
        }
        my $r_yesno = $results->{$key}; # [0];
        $total++;
        next if (($r_yesno ne $yesno) and ("" ne $yesno));
        next if not _is_print_cipher($r_yesno, $cfg{'out'}->{'disabled'}, $cfg{'out'}->{'enabled'});
        print_cipherline($legacy, $ssl, $host, $port, $key, $r_yesno);
    }
    return $total;
} # _print_cipher_results

sub printcipherall      { ## no critic qw(Subroutines::RequireArgUnpacking)
    #? print all cipher check results from Net::SSLhello::checkSSLciphers()
    #? returns number of unique (enabled) ciphers
    # FIXME: $legacy, --enabled and --disabled not fully supported
    my $legacy  = shift;
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my $outtitle= shift;    # print title line if 0
    my @results = @_;       # contains only accepted cipher keys
    my $unique  = 0;        # count unique ciphers
    my $last_r  = "";       # avoid duplicates (may be added by checkSSLciphers())
    print_cipherhead( $legacy) if ($outtitle == 0);
    foreach my $key (@results) {
        next if ($last_r eq $key);
        print_cipherline($legacy, $ssl, $host, $port, $key, "yes");
        $last_r = $key;
        $unique++;
    }
    print_cipherruler() if ($legacy =~ /(?:owasp|simple)/);
    print_footer($legacy);
    return $unique;
} # printcipherall

sub printciphercheck    {
    #? print all cipher check results for given $ssl according given legacy format
    my $legacy  = shift;
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my $count   = shift;    # print title line if 0
    my $results = shift;    # reference to hash with cipher keys for all $ssl
    my $total   = 0;
    print_cipherhead( $legacy) if ($count == 0);
    print_cipherpreferred($legacy, $ssl, $host, $port) if ($legacy eq 'sslaudit');

    my @sorted  = OSaft::Ciphers::sort_results($results->{$ssl}); # sorting has no impact on severity
    _trace2("printciphercheck: sorted $#sorted : @sorted");
    $results->{$ssl}{'sorted'} = \@sorted;   # pass sorted list to subroutines
    if ($legacy ne 'sslyze') {
        $total = _print_cipher_results($legacy, $ssl, $host, $port, "", $results->{$ssl});
            # NOTE: $checks{'cnt_totals'}->{val}  is the number of all checked
            #       ciphers for all protocols, here only the number of ciphers
            #       for the protocol $ssl should be printed
        print_cipherruler() if ($legacy =~ /(?:owasp|simple)/);
        print_check($legacy, $host, $port, 'cnt_totals', $total) if ($cfg{'verbose'} > 0);
    } else {
        print "\n  * $ssl Cipher Suites :";
        print_cipherpreferred($legacy, $ssl, $host, $port);
        if (_is_cfg_out('enabled')  or (_is_cfg_out('disabled') == _is_cfg_out('enabled'))) {
            print "\n      Accepted Cipher Suites:";
            $total = _print_cipher_results($legacy, $ssl, $host, $port, "yes", $results->{$ssl});
        }
        if (_is_cfg_out('disabled') or (_is_cfg_out('disabled') == _is_cfg_out('enabled'))) {
            print "\n      Rejected Cipher Suites:";
            $total = _print_cipher_results($legacy, $ssl, $host, $port, "no", $results->{$ssl});
        }
    }
    #print_ciphertotals($legacy, $ssl, $host, $port);  # up to version 15.10.15
    print_footer($legacy);
    return;
} # printciphercheck

sub printciphers_dh     {
    #? print ciphers and DH parameter from target (available with openssl only)
    # currently DH parameters requires openssl, check must be done in caller
    my ($legacy, $host, $port) = @_;
    my $openssl_version = osaft::get_openssl_version($cmd{'openssl'});
    _trace1("printciphers_dh: openssl_version= $openssl_version");
    if ($openssl_version lt "1.0.2") { # yes Perl can do this check  # TODO: move this check to _check_openssl()
        _warn("811: ancient openssl $openssl_version: using '-msg' option to get DH parameters");
        $cfg{'openssl_msg'} = '-msg' if (1 == $cfg{'openssl'}->{'-msg'}[0]);
        require Net::SSLhello;  # to parse output of '-msg'; ok here, as Perl handles multiple includes proper
            # SEE Note:Stand-alone
    }
    foreach my $ssl (@{$cfg{'version'}}) {
        print_title($legacy, $ssl, $host, $port, $cfg{'out'}->{'header'});
        print_cipherhead( 'cipher_dh');
        foreach my $c (@{$cfg{'ciphers'}}) {
            #next if ($c !~ /$cfg{'regex'}->{'EC'}/);
            my ($version, $supported, $dh) = _useopenssl($ssl, $host, $port, $c);
            next if ($supported =~ /^\s*$/);
            # TODO: use print_cipherline();
            # TODO: perform check like check_dh()
            printf("    %-28s\t%s\n", $c, $dh);
        }
# TODO: {
# -------
# cipher dhe oder edh, ecdh dann muss server temp key da sein
# sonst kommt kein temp key z.B RSA oder camellia
#
# wenn dh kommen muesste aber fehlt, dann bei openssl -msg probieren
# -------
# RFC 4492 wenn im cert ec oder ecdsa steht (extension) dann duerfen nur solche
# akzeptiert werden; wenn nix im cert steht dann durfen nur rsa akzeptiert werden
# siehe RFC 4492 Table 3
# -------
# cipherPcurve ...P256
# TODO: }

        print_cipherruler_dh();
    }
    return;
} # printciphers_dh

sub printcipherpreferred {
    #? print table with preferred/selected (default) cipher per protocol
    my ($legacy, $host, $port) = @_;
    local $\ = "\n";
    if (_is_cfg_out('header')) {
        printf("= prot.\t%-31s\t%s\n", "preferred cipher (strong first)", "preferred cipher (weak first)");
        printf("=------+-------------------------------+-------------------------------\n");
    }
    foreach my $ssl (@{$cfg{'versions'}}) { # SEE Note:%prot
        next if (($cfg{$ssl} == 0) and ($verbose <= 0));  # not requested with verbose only
        next if ($ssl =~ m/^SSLv2/);    # SSLv2 has no server selected cipher
        my $key = $ssl . $text{'separator'};
           $key = sprintf("[0x%x]", $prot{$ssl}->{hex}) if ($legacy eq 'key');
        printf("%-7s\t%-31s\t%s\n", $key,
                $prot{$ssl}->{'cipher_strong'}, $prot{$ssl}->{'cipher_weak'},
        );
    }
    if (_is_cfg_out('header')) {
        printf("=------+-------------------------------+-------------------------------\n");
    }
    print_data($legacy, $host, $port, 'cipher_selected');  # SEE Note:Selected Cipher
    return;
} # printcipherpreferred

sub printprotocols      {
    #? print table with cipher information per protocol
    # number of found ciphers, various risks ciphers, default cipher and PFS cipher
    # prints information stored in %prot
    my ($legacy, $host, $port) = @_;
    my @score = qw(A B C D);
    local $\ = "\n";
    if (_is_cfg_out('header')) {
        printf("# amount of detected ciphers for:\n");
        if ('owasp' eq $legacy) {
            @score = qw(A B C D);
            printf("#   A, B, C OWASP rating;  D=known broken;  tot=total enabled ciphers\n");
        } else {
            @score = qw(H M L W);
            printf("#   H=HIGH  M=MEDIUM  L=LOW  W=WEAK;  tot=total enabled ciphers\n");
        }
        printf("#   preferred=offered by server;   PFS=enabled cipher with PFS\n");
        printf("%s\t%3s %3s %3s %3s %3s %3s %-31s %s\n", "=", @score, qw(PFS tot preferred-strong-cipher PFS-cipher));
        printf("=------%s%s\n", ('+---' x 6), '+-------------------------------+---------------');
    }
    #   'PROT-LOW'      => {'txt' => "Supported ciphers with security LOW"},
    foreach my $ssl (@{$cfg{'versions'}}) { # SEE Note:%prot
        next if (($cfg{$ssl} == 0) and ($verbose <= 0));   # not requested with verbose only
        next if ($ssl =~ m/^SSLv2/);    # SSLv2 has no server selected cipher
        my $cnt = ($#{$prot{$ssl}->{'ciphers_pfs'}} + 1);
        my $key = $ssl . $text{'separator'};
           $key = sprintf("[0x%x]", $prot{$ssl}->{hex}) if ($legacy eq 'key');
        my $cipher_strong = $prot{$ssl}->{'cipher_strong'};
        my $cipher_pfs    = $prot{$ssl}->{'cipher_pfs'};  # FIXME: fails for --ciphermode=intern
        if ($cfg{'trace'} <= 0) {
           # avoid internal strings, pretty print for humans
           $cipher_strong = "" if ($STR{UNDEF} eq $cipher_strong);
           $cipher_pfs    = "" if ($STR{UNDEF} eq $cipher_pfs);
        }
        if ((@{$prot{$ssl}->{'ciphers_pfs'}}) and
            (${$prot{$ssl}->{'ciphers_pfs'}}[0] =~ m/^\s*<</)) { # something went wrong
           #$cipher_pfs   # should be empty
           $cipher_strong = ${$prot{$ssl}->{'ciphers_pfs'}}[0];
           $cnt = 0;
        }
        print_line('_cipher', $host, $port, $ssl, $ssl, ""); # just host:port:#[key]:
        if ('owasp' eq $legacy) {
            printf("%-7s\t%3s %3s %3s %3s %3s %3s %-31s %s\n", $key,
                    $prot{$ssl}->{'OWASP_A'}, $prot{$ssl}->{'OWASP_B'},
                    $prot{$ssl}->{'OWASP_C'}, $prot{$ssl}->{'OWASP_D'},
                    $cnt, $prot{$ssl}->{'cnt'}, $cipher_strong, $cipher_pfs
            );
        } else {
            printf("%-7s\t%3s %3s %3s %3s %3s %3s %-31s %s\n", $key,
                    $prot{$ssl}->{'HIGH'}, $prot{$ssl}->{'MEDIUM'},
                    $prot{$ssl}->{'LOW'},  $prot{$ssl}->{'WEAK'},
                    $cnt, $prot{$ssl}->{'cnt'}, $cipher_strong, $cipher_pfs
            );
        }
        # not yet printed: $prot{$ssl}->{'cipher_weak'}, $prot{$ssl}->{'default'}
    }
    if (_is_cfg_out('header')) {
        printf("=------%s%s\n", ('+---' x 6), '+-------------------------------+---------------');
    }
    return;
} # printprotocols

sub printciphersummary  {
    #? print summary of cipher check +cipher
    my ($legacy, $host, $port, $total) = @_;
    if ($legacy =~ /(compact|full|owasp|quick|simple)/) {   # but only our formats
        print_header("\n" . _get_text('out_summary' , ""), "", "", $cfg{'out'}->{'header'});
        print_check(   $legacy, $host, $port, 'cnt_totals', $total) if ($cfg{'verbose'} > 0);
        printprotocols($legacy, $host, $port);
    }
    _y_CMD("printciphersummary() ");
    if (0 < $cfg{'need_netinfo'}) {
        my $key;
        my $_verbose = $Net::SSLinfo::verbose;  # save
        if (2 > $_verbose) {    # avoid huge verbosity in simple cases
            $Net::SSLinfo::verbose = 0 if 2 > $_verbose;
            if (0 < $_verbose) {
                _hint("use --v --v for verbose output of 'cipher_selected' or use '+cipher_selected'");
            }
        }
        my $cipher = $data{'cipher_selected'}->{val}($host, $port);
        print_line($legacy, $host, $port, 'cipher_selected',
                   $data{'cipher_selected'}->{txt}, "$cipher "
                   . _cipher_get_sec($cipher)
                  );
        $Net::SSLinfo::verbose = $_verbose;     # restore
    } else {
        _hint("'cipher_selected' temporarily disabled");  # TODO: adapte to new SSLhello (2/2021)
    }
    _hint("consider using '--cipheralpn=, --ciphernpn=,' also") if ($cfg{'verbose'} > 0);
    return;
} # printciphersummary

sub printdata($$$)      {
    #? print information stored in %data
    my ($legacy, $host, $port) = @_;
    local $\ = "\n";
    print_header($text{'out_infos'}, $text{'desc_info'}, "", $cfg{'out'}->{'header'});
    _trace_cmd('%data');
    if (_is_cfg_do('cipher_selected')) {    # value is special
        my $key = $data{'cipher_selected'}->{val}($host, $port);
        print_line($legacy, $host, $port, 'cipher_selected',
                   $data{'cipher_selected'}->{txt}, "$key " . _cipher_get_sec($key));
    }
    foreach my $key (@{$cfg{'do'}}) {
        next if (_is_member( $key, \@{$cfg{'commands_notyet'}}));
        next if (_is_member( $key, \@{$cfg{'ignore-out'}}));
        next if (not _is_hashkey($key, \%data));
        next if ($key eq 'cipher_selected');# value is special, done above
        if (not _is_cfg_use('experimental')) {
            next if (_is_member( $key, \@{$cfg{'commands_exp'}}));
        }
        # special handling vor +info--v
        if (_is_cfg_do('info--v')) {
            next if ($key eq 'info--v');
            next if ($key =~ m/$cfg{'regex'}->{'commands_int'}/i);
        } else {
            next if (_is_cfg_intern($key));
        }
        _y_CMD("(%data)   +" . $key);
        my $value = $data{$key}->{val}($host);
        if (_is_member( $key, \@{$cfg{'cmd-NL'}})) {
            # for +info print multiline data only if --v given
            # if command given explicitly, i.e. +text, print
            if (_is_cfg_do('info') and (0 >= $cfg{'verbose'})) {
                _hint("use '--v' to print multiline data of '+$key' for '+info'");
                next;
            }
        }
        if ($cfg{'format'} eq "raw") {      # should be the only place where format=raw counts
            print $value;
        } else {
            print_data($legacy, $host, $port, $key);
        }
    }
    return;
} # printdata

sub printchecks($$$)    {
    #? print results stored in %checks
    my ($legacy, $host, $port) = @_;
    my $value = "";
    local $\ = "\n";
    print_header($text{'out_checks'}, $text{'desc_check'}, "", $cfg{'out'}->{'header'});
    _trace_cmd(' printchecks: %checks');
    _warn("821: can't print certificate sizes without a certificate (--no-cert)") if (not _is_cfg_use('cert'));
    foreach my $key (@{$cfg{'do'}}) {
        _trace("printchecks: (%checks) ?" . $key);
        next if (_is_member( $key, \@{$cfg{'commands_notyet'}}));
        next if (_is_member( $key, \@{$cfg{'ignore-out'}}));
        next if (not _is_hashkey($key, \%checks));
        next if (_is_cfg_intern( $key));# ignore aliases
        next if ($key =~ m/$cfg{'regex'}->{'SSLprot'}/); # these counters are already printed
        if (not _is_cfg_use('experimental')) {
            next if (_is_member( $key, \@{$cfg{'commands_exp'}}));
        }
        $value = _get_yes_no($checks{$key}->{val});
        _y_CMD("(%checks) +" . $key);
        if ($key =~ /$cfg{'regex'}->{'cmd-sizes'}/) {   # sizes are special
            print_size($legacy, $host, $port, $key) if (_is_cfg_use('cert'));
        } else {
            # increment counter only here, avoids counting the counter itself
            $checks{'cnt_checks_yes'}->{val}++ if ($value eq "yes");
            $checks{'cnt_checks_no'} ->{val}++ if ($value =~ /^no/);
            $checks{'cnt_checks_noo'}->{val}++ if ($value =~ /^no\s*\(<</);
            print_check($legacy, $host, $port, $key, $value);
        }
    }
    return;
} # printchecks

#| definitions: print functions for help and information
#| -------------------------------------

sub printquit           {
    #? print internal data
    # call this function with:
    #    $0 `\
    #      gawk '/--(help|trace-sub)/{next}/--h$/{next}/($2~/^-/){$1="";print}' o-saft-man.pm\
    #      |tr ' ' '\012' \
    #      |sort -u \
    #      |egrep '^(--|\+)' \
    #      |egrep -v '^--[v-]-' \
    #      |egrep -v '--user-*' \
    #      |egrep -v 'cipher=*' \
    #     ` \
    #     +quit --trace-key
    #
    # NOTE: This extracts all options, but does not use all variants these
    #        options can be written. So just a rough test ...
    #
    # NOTE: Some commands may have invalid arguments (i.e. --sep=CHAR ) or
    #       the commands may be unknown. This results in  **WARNING  texts
    #       for the correspoding commands.

    if (($cfg{'trace'} + $cfg{'verbose'} <= 0) and not _is_cfg_out('traceARG')) {
        _warn("831: '+quit' command should be used with '--trace=arg' option");
    }
    $cfg{'verbose'} = 2 if ($cfg{'verbose'} < 2);   # dirty hack
    $cfg{'trace'}   = 2 if ($cfg{'trace'}   < 2);   # -"-
    _set_cfg_out('traceARG', 1);    # for _yeast_args(); harmless change as +quit exits
    print("\n# +quit using:  --verbode=2 --trace=2 --traceARG");
    _v_print("\n# +quit : some information may appear multiple times\n#");
    _yeast_init();
    # _yeast_args();  # duplicate call, see in main at "set environment"
    print "# TEST done.";
    return;
} # printquit

sub __SSLeay_version    {
    #? internal wrapper for Net::SSLeay::SSLeay()
    if (1.49 > $Net::SSLeay::VERSION) {
        my $txt  = "ancient version Net::SSLeay $Net::SSLeay::VERSION < 1.49;";
           $txt .= " cannot compare SSLeay with openssl version";
        warn $STR{WARN}, "080: $txt";    # not _warn(), SEE Perl:warn
        return "$Net::SSLeay::VERSION";
    } else {
        return Net::SSLeay::SSLeay();
    }
} # __SSLeay_version

sub printversionmismatch {
    #? check if openssl and compiled SSLeay are of same version
    my $o = Net::SSLeay::OPENSSL_VERSION_NUMBER();
    my $s = __SSLeay_version();
    if ($o ne $s) {
        _warn("841: used openssl version '$o' differs from compiled Net:SSLeay '$s'; ignored");
    }
    return;
} # printversionmismatch

## no critic qw(Subroutines::ProhibitExcessComplexity)
#  NOTE: yes, it is high complexity, but that's the nature of printing all information
sub printversion        {
    #? print program and module versions
    local $\ = "\n";
    if ($cfg{'verbose'} > 0) {
        print "# perl $^V";
        print '# @INC = ' . join(" ", @INC) . "\n";
    }
    if (defined $ENV{PWD}) {
    print( "=== started in: $ENV{PWD} ===");    # avoid "use Cwd;" or `pwd`
    } # quick&dirty check, should rarely occour (i.e. when used as CGI)
    # SEE Note:OpenSSL Version
    my $version_openssl  = Net::SSLeay::OPENSSL_VERSION_NUMBER() || $STR{UNDEF};
    my $me = $cfg{'me'};
    print( "=== $0 " . _VERSION() . " ===");
    print( "    osaft_vm_build = $ENV{'osaft_vm_build'}") if (defined $ENV{'osaft_vm_build'});
    print( "    Net::SSLeay::");# next two should be identical
    printf("       ::OPENSSL_VERSION_NUMBER()    0x%x (%s)\n", $version_openssl, $version_openssl);
    printf("       ::SSLeay()                    0x%x (%s)\n", __SSLeay_version(), __SSLeay_version());
    if (1.49 > $Net::SSLeay::VERSION) {
        _warn("851: ancient version Net::SSLeay $Net::SSLeay::VERSION < 1.49; detailed version not available");
    } else {
      if ($cfg{'verbose'} > 0) {
        # TODO: not all versions of Net::SSLeay have constants like
        # Net::SSLeay::SSLEAY_CFLAGS, hence we use hardcoded integers
        print "       ::SSLEAY_DIR                  " . Net::SSLeay::SSLeay_version(5);
        print "       ::SSLEAY_BUILD_ON             " . Net::SSLeay::SSLeay_version(3);
        print "       ::SSLEAY_PLATFORM             " . Net::SSLeay::SSLeay_version(4);
        print "       ::SSLEAY_CFLAGS               " . Net::SSLeay::SSLeay_version(2);
      }
      print "    Net::SSLeay::SSLeay_version()    " . Net::SSLeay::SSLeay_version(); # no parameter is same as parameter 0
      # TODO: print "   *SSL version mismatch" if Net::SSLeay::SSLeay_version() ne Net::SSLinfo::do_openssl('version','','','');
    }

    $Net::SSLinfo::verbose = 0; # do not set here; will not be used later
    print "= openssl =";
    print "    external executable              " . (($cmd{'openssl'} eq "")  ? "<<executable not found>>" : $cmd{'openssl'});
    print "    external executable (TLSv1.3)    " . (($cmd{'openssl3'} eq "") ? "<<executable not found>>" : $cmd{'openssl3'});
    print "    version of external executable   " . Net::SSLinfo::do_openssl('version', '', '', '');
    print "    used environment variable (name) " . $cmd{'envlibvar'};
   #print "    used environment variable 3(name)" . $cmd{'envlibvar3'};
    print "    environment variable (content)   " . ($ENV{$cmd{'envlibvar'}} || $STR{UNDEF});
    print "    path to shared libraries         " . join(" ", @{$cmd{'libs'}});
    if (scalar @{$cmd{'libs'}} > 0) {
        foreach my $l (qw(libcrypto.a libcrypto.so libssl.a libssl.so)) {
           foreach my $p (@{$cmd{'libs'}}) {
               my $lib = "$p/$l";
                  $lib = "<<$p/$l not found>>" if (! -e $lib);
               print "    library                          " . $lib;
               if ($cfg{'verbose'} > 1) {
                   print "#   strings $lib | grep 'part of OpenSSL')";
                   print qx(strings $lib | grep 'part of OpenSSL');
               }
           }
        }
    }
    print "    full path to openssl.cnf file    " . ($cfg{'openssl_cnf'} || $STR{UNDEF});
    print "    common openssl.cnf files         " . join(" ", @{$cfg{'openssl_cnfs'}});
    print "    URL where to find CRL file       " . ($cfg{'ca_crl'}      || $STR{UNDEF});
    print "    directory with PEM files for CAs " . ($cfg{'ca_path'}     || $STR{UNDEF});
    print "    PEM format file with CAs         " . ($cfg{'ca_file'}     || $STR{UNDEF});
    print "    common paths to PEM files for CAs ". join(" ", @{$cfg{'ca_paths'}});
    if ($cfg{'verbose'} > 0) {
        foreach my $p (@{$cfg{'ca_paths'}}) {
            print "       existing path to CA PEM files " . $p if -e $p;
        }
    }
    print "    common PEM filenames for CAs     " . join(" ", @{$cfg{'ca_files'}});
    if ($cfg{'verbose'} > 0) {
        foreach my $p (@{$cfg{'ca_paths'}}) {
            foreach my $f (@{$cfg{'ca_files'}}) {
                print "       existing PEM file for CA      " . "$p/$f" if -e "$p/$f";
            }
        }
    }

    print "= $me =";
    print "    list of supported elliptic curves " . join(" ", @{$cfg{'ciphercurves'}});
    print "    list of supported ALPN, NPN      " . join(" ", $cfg{'protos_next'});
    if ($cfg{'verbose'} > 0) {
        print "    list of supported ALPN       " . join(" ", @{$cfg{'protos_alpn'}});
        print "    list of supported NPN        " . join(" ", @{$cfg{'protos_npn'}});
    }

    print "= $me +cipher --ciphermode=openssl or --ciphermode=ssleay =";
    my @ciphers= Net::SSLinfo::cipher_openssl();# openssl ciphers ALL:aNULL:eNULL
    my $cnt    = 0;
       $cnt    = @ciphers if (not grep{/<<openssl>>/} @ciphers);# if executable found
    print "    number of supported ciphers      " . $cnt;
    print "    list of supported ciphers        " . join(" ", @ciphers) if (0 < $cfg{'verbose'});
    _hint("use '--v' to get list of ciphers") if (0 == $cfg{'verbose'});
    print "    openssl supported SSL versions   " . join(" ", @{$cfg{'version'}});
    print "    $me known SSL versions     "       . join(" ", @{$cfg{'versions'}});
    printversionmismatch();

    print "= $me +cipher --ciphermode=intern =";
    my @cnt = (_eval_cipherranges($cfg{'cipherrange'}));
    my $list= $cfg{'cipherranges'}->{$cfg{'cipherrange'}};
       $list=~ s/     */        /g; # squeeze leading spaces
    print "    used cipherrange                 " . $cfg{'cipherrange'};
    print "    number of supported ciphers      " . scalar @cnt;
    print "    default list of ciphers          " . $list;
    if ($cfg{'verbose'} > 0) {
        # these lists are for special purpose, so with --v only
        print "    long list of ciphers         " . $cfg{'cipherranges'}->{'long'};
        print "    huge list of ciphers         " . $cfg{'cipherranges'}->{'huge'};
        print "    safe list of ciphers         " . $cfg{'cipherranges'}->{'safe'};
        print "    full list of ciphers         " . $cfg{'cipherranges'}->{'full'};
        print "    C0xx list, range C0xx..C0FF  " . $cfg{'cipherranges'}->{'c0xx'};
        print "    CCxx list, range CCxx..CCFF  " . $cfg{'cipherranges'}->{'c0xx'};
        print "    ECC list, ephermeral ciphers " . $cfg{'cipherranges'}->{'ecc'};
        print "    SSLv2 list of ciphers        " . $cfg{'cipherranges'}->{'SSLv2'};
        print "    SSLv2_long list of ciphers   " . $cfg{'cipherranges'}->{'SSLv2_long'};
        print "    shifted list of ciphers      " . $cfg{'cipherranges'}->{'shifted'};
    }

# TODO: i.g. OPENSSL_VERSION_NUMBER() returns same value as SSLeay()
#       but when using libraries with LD_LIBRARY_PATH or alike, these
#       versions differ

    # get a quick overview also
    # SEE Perl:import include
    print "= Required (and used) Modules =";
    print '    @INC                 ', "@INC";
    my ($d, $v, %p);
    printf("=   %-22s %-9s%s\n", "module name", "VERSION", "found in");
    printf("=   %s+%s+%s\n",     "-"x22,        "-"x8,     "-"x42);
    # TODO: following list should be same as in _check_modules()
    foreach my $m (qw(IO::Socket::INET IO::Socket::SSL Time::Local Net::DNS Net::SSLeay Net::SSLinfo Net::SSLhello OSaft::Ciphers osaft)) {
        no strict 'refs';   ## no critic qw(TestingAndDebugging::ProhibitNoStrict TestingAndDebugging::ProhibitProlongedStrictureOverride)
            # avoid: Can't use string ("Net::DNS") as a HASH ref while "strict refs" in use
        # we expect ::VERSION in all these modules
        ($d = $m) =~ s#::#/#g;  $d .= '.pm';    # convert string to key for %INC
        $v  = $m . "::VERSION";                 # compute module's VERSION variable
        printf("    %-22s %-9s%s\n", $m, ($$v || " "), ($INC{$d} || " "));
            # use a single space if value is not defined
    }
    if ($cfg{'verbose'} > 0) {
        print "\n= Loaded Modules =";
        foreach my $m (sort keys %INC) {
            $d = $INC{$m} || $STR{UNDEF};   # defensive progamming; sometimes undefined, reason unknown
            printf("    %-22s %6s\n", $m, $d);
            $d =~ s#$m$##; $p{$d} = 1;
        }
        print "\n= Loaded Module Versions =";
        no strict 'refs';   ## no critic qw(TestingAndDebugging::ProhibitNoStrict)
            # avoid: Can't use string ("AutoLoader::") as a HASH ref while "strict refs" in use
        foreach my $m (sort keys %main:: ) {
            next if $m !~ /::/;
            $d = "?";       # beat the "Use of uninitialized value" dragon
            $d = ${$$m{'VERSION'}} if defined ${$$m{'VERSION'}};
            printf("    %-22s %6s\n", $m, $d);
        }
    }
    return if ($^O =~ m/MSWin32/);      # not Windows
    if ($cfg{'verbose'} > 1) {
        print "\n= Used Shared Objects =";
        # quick&dirty, don't want to use ::Find module
        foreach my $d (sort keys %p) {
             next if ($d =~ m/^\s*$/);
             print "# find $d -name SSLeay.so\\* -o -name libssl.so\\* -o -name libcrypto.so\\*";
             print qx(find $d -name SSLeay.so\\* -o -name libssl.so\\* -o -name libcrypto.so\\*);
        }
    }
    return;
} # printversion

sub printciphers        {
    #? print cipher descriptions from internal database
    # uses settings from --legacy= and option -v or -V to select output format
    if (_is_cfg_do('ciphers')) {
        # output looks like: openssl ciphers
       _y_CMD("simulate 'openssl ciphers'");
        $cfg{'out'}->{'header'} = 0;
        $cfg{'legacy'} = 'openssl';
        $cfg{'legacy'} = 'openssl-v' if (0 < $cfg{'opt-v'});
        $cfg{'legacy'} = 'openssl-V' if (0 < $cfg{'opt-V'});
    }
    # anything else prints user-specified formats
    _trace("printciphers: +list");  # late, to not disturb output of plain "ciphers"
    _v_print("command: " . join(" ", @{$cfg{'do'}}));
    _v_print("database version: ", _VERSION());
    _v_print("options: --legacy=$cfg{'legacy'} , --format=$cfg{'format'} , --header=$cfg{'out'}->{'header'}");
    _v_print("options: --v=$cfg{'verbose'}, -v=$cfg{'opt-v'} , -V=$cfg{'opt-V'}");
    OSaft::Ciphers::show($cfg{'legacy'});
    return;
} # printciphers

sub printscores         {
    #? print calculated score values
    my ($legacy, $host, $port) = @_;
    scoring($host, $port);
    # simple rounding in Perl: $rounded = int($float + 0.5)
    $scores{'checks'}->{val} = int(
            ((
              $scores{'check_cert'}->{val}
            + $scores{'check_conn'}->{val}
            + $scores{'check_dest'}->{val}
            + $scores{'check_http'}->{val}
            + $scores{'check_size'}->{val}
            ) / 5 ) + 0.5);
    print_header($text{'out_scoring'}."\n", $text{'desc_score'}, "", $cfg{'out'}->{'header'});
    _trace_cmd('%scores');
    foreach my $key (sort keys %scores) {
        next if ($key !~ m/^check_/);   # print totals only
        print_line($legacy, $host, $port, $key, $scores{$key}->{txt}, $scores{$key}->{val});
    }
    print_line($legacy, $host, $port, 'checks', $scores{'checks'}->{txt}, $scores{'checks'}->{val});
    print_ruler();
    if (_is_cfg_out('traceKEY') and (0 < $verbose)) {
        _y_CMD("verbose score table");
        print "\n";
        printtable('score');
        print_ruler();
    }
    return;
} # printscores

sub printopenssl        {
    #? print openssl version
    print Net::SSLinfo::do_openssl('version', '', '', '');
    printversionmismatch();
    return;
} # printopenssl

sub printusage_exit     {
    #? print simple usage, first line with passed text
    my @txt = @_;
    local $\ = "\n";
    print $STR{USAGE}, @txt;
    print "# most common usage:
  $cfg{'me'} +info     your.tld
  $cfg{'me'} +check    your.tld
  $cfg{'me'} +cipher   your.tld
# for more help use:
  $cfg{'me'} --h
  $cfg{'me'} --help
    ";
    exit 2;
} # printusage_exit

usr_pre_args();

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

#| scan options and arguments
#| -------------------------------------
# All arguments are  inspected here.  We do not use any module,  like Getopt,
# 'cause we want to support various variants of the same argument,  like case
# sensitive or additional characters i.e.  .  -  _  to be ignored, and so on.
# This also allows to use  different options and commands easily for the same
# functionality without defining each variant. Grep for "alias" below ...
# Even most commands are also the key in our own data structure (%data, %cfg)
# we do not use any argument as key drectly, but always compare with the keys
# and assign values using keys literally, like: $cfg{'key'} = $arg .

my $typ = 'HOST';
push(@argv, "");# need one more argument otherwise last --KEY=VALUE will fail
while ($#argv >= 0) {
    $arg = shift @argv;
    _y_ARG("cli_arg= $arg");
    push(@{$dbx{argv}}, $arg) if (($arg !~ m/^--cfg[_-]/) && (($arg =~ m/^[+-]/) || ($typ ne "HOST")));
    push(@{$dbx{cfg}},  $arg) if  ($arg =~ m/^--cfg[_-]/);    # both aprox. match are sufficient for debugging

    # First check for arguments of options.
    # Options are not case sensitive.  Options may contain  .  and  -  and  _
    # anywhere in its name. These characters are silently ignored.  These are
    # all the same:  --no-DNS  --no_DNS  --no.dns  --NoDns  --n-o_D.N.s
    # Options may have an argument, either as separate word or as part of the
    # option parameter itself: --opt argument   or   --opt=argument .
    # Such an argument is handled using $typ. All types except HOST, which is
    # the default, are handled at the begining here (right below). After pro-
    # cessing the argument, $typ is set to HOST again  and next argument will
    # be taken from command-line.
    # $typ='HOST' is handled at end of loop, as it may appear anywhere in the
    # command-line and does not require an option.
    # Commands are case sensitive  because they are used directly as key in a
    # hash (see %_SSLinfo Net::SSLinfo.pm). Just commands for the tool itself
    # (not those returning collected data) are case insensitive.
    # NOTE: the sequence of following code must be:
    #   1. check argument (otherwise relooped before)
    #   2. check for options (as they may have arguments)
    #      unknown remaining options here  are silently ignored, because they
    #      cannot easily be distinguished from known ones
    #   3. check for commands (as they all start with '+' and we don't expect
    #      any argument starting with '+')
    #   4. check for HOST argument
    # Parsing options see OPTIONS below, parsing commands see COMMANDS below.

    if ($typ ne 'HOST') { # option arguments
        # Note that $arg already contains the argument
        # hence `next' at end of surrounding if()
        # $type is set at end of  each matching if condition,  hence only the
        # first matching if condition is executed; sequence is important!
        _y_ARG("argument? $arg, typ= $typ");
        push(@{$dbx{exe}}, join("=", $typ, $arg)) if ($typ =~ m/OPENSSL|ENV|EXE|LIB/);
        # programming: for better readability  "if($typ eq CONST)"  is used
        #              instead of recommended  "if(CONST eq $typ)"  below
        #  $typ = '????'; # expected next argument
        #  +---------+--------------+------------------------------------------
        #   argument to process   what to do
        #  +---------+--------------+------------------------------------------
        if ($typ eq 'CFG_INIT')     { _cfg_set_init(  $typ, $arg);  }
        if ($typ eq 'CFG_CIPHER')   { _cipher_set_sec($typ, $arg); $typ = 'HOST'; } # $typ set to avoid next match
        if ($typ =~ m/^CFG/)        { _cfg_set(       $typ, $arg);  }
           # backward compatibility removed to allow mixed case texts;
           # until 16.01.31 lc($arg) was used for pre 14.10.13 compatibility
        if ($typ eq 'LD_ENV')       { $cmd{'envlibvar'}   = $arg;   }
        if ($typ eq 'LD_ENV3')      { $cmd{'envlibvar3'}  = $arg;   }
        if ($typ eq 'OPENSSL')      { $cmd{'openssl'}     = $arg;   }
        if ($typ eq 'OPENSSL3')     { $cmd{'openssl3'}    = $arg;   }
        if ($typ eq 'OPENSSL_CNF')  { $cfg{'openssl_cnf'} = $arg;   }
        if ($typ eq 'OPENSSL_FIPS') { $cfg{'openssl_fips'}= $arg;   }
        if ($typ eq 'VERBOSE')      { $cfg{'verbose'}     = $arg;   }
        if ($typ eq 'DO')           { push(@{$cfg{'do'}},   $arg);  } # treat as command,
        if ($typ eq 'EXE')          { push(@{$cmd{'path'}}, $arg);  }
        if ($typ eq 'LIB')          { push(@{$cmd{'libs'}}, $arg);  }
        if ($typ eq 'CALL')         { push(@{$cmd{'call'}}, $arg);  }
        if ($typ eq 'SEP')          { $text{'separator'}  = $arg;   }
        if ($typ eq 'OPT')          { $cfg{'sclient_opt'}.= " $arg";}
        if ($typ eq 'TIMEOUT')      { $cfg{'timeout'}     = $arg;   }
        if ($typ eq 'CERT_TEXT')    { $cfg{'no_cert_txt'} = $arg;   }
        if ($typ eq 'CA_FILE')      { $cfg{'ca_file'}     = $arg;   }
        if ($typ eq 'CA_PATH')      { $cfg{'ca_path'}     = $arg;   }
        if ($typ eq 'CA_DEPTH')     { $cfg{'ca_depth'}    = $arg;   }
        # TODO: use cfg{'targets'} for proxy*
        if ($typ eq 'PROXY_PORT')   { $cfg{'proxyport'}   = $arg;   }
        if ($typ eq 'PROXY_USER')   { $cfg{'proxyuser'}   = $arg;   }
        if ($typ eq 'PROXY_PASS')   { $cfg{'proxypass'}   = $arg;   }
        if ($typ eq 'PROXY_AUTH')   { $cfg{'proxyauth'}   = $arg;   }
        if ($typ eq 'SNINAME')      { $cfg{'sni_name'}    = $arg;   }
        if ($typ eq 'TTY_ARROW')    { _set_cfg_tty('arrow', $arg);  }
        if ($typ eq 'TTY_IDENT')    { _set_cfg_tty('ident', $arg);  }
        if ($typ eq 'TTY_WIDTH')    { _set_cfg_tty('width', $arg);  }
        if ($typ eq 'ANON_OUT')     { $cfg{'regex'}->{'anon_output'}  = qr($arg); }
        if ($typ eq 'FILE_SCLIENT') { $cfg{'data'}->{'file_sclient'}  = $arg; }
        if ($typ eq 'FILE_CIPHERS') { $cfg{'data'}->{'file_ciphers'}  = $arg; }
        if ($typ eq 'FILE_PCAP')    { $cfg{'data'}->{'file_pcap'}     = $arg; }
        if ($typ eq 'FILE_PEM')     { $cfg{'data'}->{'file_pem'}      = $arg; }
        if ($typ eq 'SSLHELLO_RETRY'){$cfg{'sslhello'}->{'retry'}     = $arg; }
        if ($typ eq 'SSLHELLO_TOUT'){ $cfg{'sslhello'}->{'timeout'}   = $arg; }
        if ($typ eq 'SSLHELLO_MAXC'){ $cfg{'sslhello'}->{'maxciphers'}= $arg; }
        if ($typ eq 'SSLERROR_MAX') { $cfg{'sslerror'}->{'max'}       = $arg; }
        if ($typ eq 'SSLERROR_TOT') { $cfg{'sslerror'}->{'total'}     = $arg; }
        if ($typ eq 'SSLERROR_DLY') { $cfg{'sslerror'}->{'delay'}     = $arg; }
        if ($typ eq 'SSLERROR_TOUT'){ $cfg{'sslerror'}->{'timeout'}   = $arg; }
        if ($typ eq 'SSLERROR_PROT'){ $cfg{'sslerror'}->{'per_prot'}  = $arg; }
        if ($typ eq 'CONNECT_DELAY'){ $cfg{'connect_delay'}           = $arg; }
        if ($typ eq 'STARTTLS')     { $cfg{'starttls'}                = $arg; }
        if ($typ eq 'TLS_DELAY')    { $cfg{'starttls_delay'}          = $arg; }
        if ($typ eq 'SLOW_DELAY')   { $cfg{'slow_server_delay'}       = $arg; }
        if ($typ eq 'STARTTLSE1')   { $cfg{'starttls_error'}[1]       = $arg; }
        if ($typ eq 'STARTTLSE2')   { $cfg{'starttls_error'}[2]       = $arg; }
        if ($typ eq 'STARTTLSE3')   { $cfg{'starttls_error'}[3]       = $arg; }
        if ($typ eq 'STARTTLSP1')   { $cfg{'starttls_phase'}[1]       = $arg; }
        if ($typ eq 'STARTTLSP2')   { $cfg{'starttls_phase'}[2]       = $arg; }
        if ($typ eq 'STARTTLSP3')   { $cfg{'starttls_phase'}[3]       = $arg; }
        if ($typ eq 'STARTTLSP4')   { $cfg{'starttls_phase'}[4]       = $arg; }
        if ($typ eq 'STARTTLSP5')   { $cfg{'starttls_phase'}[5]       = $arg; }
        if ($typ eq 'PORT')         { $cfg{'port'}                    = $arg; }
        #if ($typ eq 'HOST')    # not done here, but at end of loop
        if ($typ eq 'HTTP_USER_AGENT')  { $cfg{'use'}->{'user_agent'} = $arg; }
        #  +---------+--------------+------------------------------------------
        if ($typ eq 'NO_OUT') {
            if ($arg =~ /^[,:]*$/) {            # special to set empty string
                $cfg{'ignore-out'} = [];
            } else {
                push(@{$cfg{'ignore-out'}}, $arg);
            }
        }
        if ($typ eq 'CIPHER_ITEM')  {
            # $arg = lc($arg);   # case-sensitive
#TODO: cipherpatterns nur bei cipher_openssl benutzen
            if (defined $cfg{'cipherpatterns'}->{$arg}) { # our own aliases ...
                $arg  = $cfg{'cipherpatterns'}->{$arg}[1];
            } else {    # anything else,
#TODO: Prüfung weg, damit auch SSLv2_long möglich
                if ($arg !~ m/^[XxA-Z0-9-]+$/) { # must be upper case
                     # x in RegEx to allow hex keys of ciphers like 0x0300C014
                    _warn("062: given pattern '$arg' for cipher unknown; setting ignored");
                    $arg = "";
                }
            }
            push(@{$cfg{'cipher'}}, $arg) if ($arg !~ m/^\s*$/);
        }
        if ($typ eq 'STD_FORMAT') {
            $arg = lc($arg);
            if ($arg =~ /$cfg{'regex'}->{'std_format'}/) {
                _set_binmode($arg);
            } else {
                _set_binmode(":encoding($arg)") if ($arg =~ /^[a-zA-Z0-9_.-]+$/);
                    # simple input validation
            }
        }
        if ($typ eq 'PROTOCOL') {
            if ($arg =~ /^?sslv?2$/i)         { $cfg{'SSLv2'}   = 1; }
            if ($arg =~ /^?sslv?3$/i)         { $cfg{'SSLv3'}   = 1; }
            if ($arg =~ /^?tlsv?1$/i)         { $cfg{'TLSv1'}   = 1; }
            if ($arg =~ /^?tlsv?1[-_.]?1$/i)  { $cfg{'TLSv11'}  = 1; }
            if ($arg =~ /^?tlsv?1[-_.]?2$/i)  { $cfg{'TLSv12'}  = 1; }
            if ($arg =~ /^?tlsv?1[-_.]?3$/i)  { $cfg{'TLSv13'}  = 1; }
            if ($arg =~ /^dtlsv?0[-_.]?9$/i)  { $cfg{'DTLSv09'} = 1; }
            if ($arg =~ /^dtlsv?1[-_.]?0?$/i) { $cfg{'DTLSv1'}  = 1; }
            if ($arg =~ /^dtlsv?1[-_.]?1$/i)  { $cfg{'DTLSv11'} = 1; }
            if ($arg =~ /^dtlsv?1[-_.]?2$/i)  { $cfg{'DTLSv12'} = 1; }
            if ($arg =~ /^dtlsv?1[-_.]?3$/i)  { $cfg{'DTLSv13'} = 1; }
        }
        if ($typ eq 'PROXY_HOST')    {
            # TODO: use cfg{'targets'} for proxy
            # allow   user:pass@f.q.d.n:42
            $cfg{'proxyhost'} = $arg;
            if ($arg =~ m#([^@]*)@(.*)#) {      # got username:password
                $arg =  $2;
                if ($1 =~ m#([^:@]*?):([^@]*)#) {
                    $cfg{'proxyuser'} = $1;
                    $cfg{'proxypass'} = $2;
                }
            }
            if ($arg =~ m#([^:]*):(\d+)#) {     # got a port too
                $cfg{'proxyhost'} = $1;
                $cfg{'proxyport'} = $2;
            # else port must be given by --proxyport
            }
        }
        # following ($arg !~ /^\s*$/) check avoids warnings in CGI mode
        if ($typ eq 'LABEL')   {
            $arg = lc($arg);
            if (1 == (grep{/^$arg$/i} @{$cfg{'labels'}})) {
                $cfg{'label'} = lc($arg);
            } else {
                _warn("051: option with unknown label '$arg'; setting ignored") if ($arg !~ /^\s*$/);
            }
        }
        if ($typ eq 'LEGACY')   {
            $arg = lc($arg);
            $arg = 'sslcipher' if ($arg eq 'ssl-cipher-check'); # alias
            if (1 == (grep{/^$arg$/i} @{$cfg{'legacys'}})) {
                $cfg{'legacy'} = lc($arg);
            } else {
                _warn("054: option with unknown legacy '$arg'; setting ignored") if ($arg !~ /^\s*$/);
            }
        }
        if ($typ eq 'FORMAT')   {
            $arg = lc($arg);
            $arg = 'esc' if ($arg =~ m#^[/\\]x$#);      # \x and /x are the same
            if (1 == (grep{/^$arg$/}  @{$cfg{'formats'}})) {
                $cfg{'format'} = $arg;
            } else {
                _warn("055: option with unknown format '$arg'; setting ignored") if ($arg !~ /^\s*$/);
            }
        }
        if ($typ eq 'CIPHER_RANGE') {
            if (1 == (grep{/^$arg$/i} keys %{$cfg{'cipherranges'}})) {
                $cfg{'cipherrange'} = $arg; # case-sensitive
            } else {
                _warn("056: option with unknown cipher range '$arg'; setting ignored") if ($arg !~ /^\s*$/);
            }
        }
        if ($typ eq 'CIPHER_MODE')  {
            $arg = lc($arg);
            if (1 == (grep{/^$arg$/i} @{$cfg{'ciphermodes'}})) {
                $cfg{'ciphermode'} = $arg;
            } else {
                _warn("057: option with unknown cipher mode '$arg'; setting ignored") if ($arg !~ /^\s*$/);
            }
        }
        if ($typ eq 'CIPHER_CURVES') {
            $arg = lc($arg);
            $cfg{'ciphercurves'} = [""] if ($arg =~ /^[,:][,:]$/);# special to set empty string
            if ($arg =~ /^[,:]$/) {
                $cfg{'ciphercurves'} = [];
            } else {
                push(@{$cfg{'ciphercurves'}}, split(/,/, lc($arg)));
            }
        }

        # SEE Note:ALPN, NPN
        # --protos* is special to simulate empty and undefined arrays
        #   --protosnpn=value   - add value to array
        #   --protosnpn=,       - set empty array
        #   --protosnpn=,,      - set array element to ""
        # NOTE: distinguish:  [], [""], [" "]
        if ($typ eq 'CIPHER_ALPN'){
            $arg = lc($arg);
            $cfg{'cipher_alpns'} = [""] if ($arg =~ /^[,:][,:]$/);# special to set empty string
            if ($arg =~ /^[,:]$/) {
                $cfg{'cipher_alpns'} = [];
            } else {
                push(@{$cfg{'cipher_alpns'}}, split(/,/, $arg));
            }
            # TODO: checking names of protocols needs a sophisticated function
            #if (1 == (grep{/^$arg$/} split(/,/, $cfg{'protos_next'})) { }
        }
        if ($typ eq 'CIPHER_NPN'){
            $cfg{'cipher_npns'} = [""] if ($arg =~ /^[,:][,:]$/);# special to set empty string
            if ($arg =~ /^[,:]$/) {
                $cfg{'cipher_npns'} = [];
            } else {
                push(@{$cfg{'cipher_npns'}},  split(/,/, $arg));
            }
            # TODO: checking names of protocols needs a sophisticated function
        }
        if ($typ eq 'PROTO_ALPN'){
            $arg = lc($arg);
            $cfg{'protos_alpn'} = [""] if ($arg =~ /^[,:][,:]$/);# special to set empty string
            if ($arg =~ /^[,:]$/) {
                $cfg{'protos_alpn'} = [];
            } else {
                push(@{$cfg{'protos_alpn'}}, split(/,/, $arg));
            }
            # TODO: checking names of protocols needs a sophisticated function
            #if (1 == (grep{/^$arg$/} split(/,/, $cfg{'protos_next'})) { }
        }
        if ($typ eq 'PROTO_NPN'){
            $arg = lc($arg);
            $cfg{'protos_npn'} = [""] if ($arg =~ /^[,:][,:]$/);# special to set empty string
            if ($arg =~ /^[,:]$/) {
                $cfg{'protos_npn'} = [];
            } else {
                push(@{$cfg{'protos_npn'}},  split(/,/, $arg));
            }
            # TODO: checking names of protocols needs a sophisticated function
        }
        _y_ARG("argument= $arg");

        # --trace is special for historical reason, we allow:
        #   --traceARG
        #   --tracearg
        #   --trace=arg
        #   --trace arg
        #   --trace=2
        #   --trace 2
        #   --trace=me
        #   --traceME
        # problem is that we historically allow also
        #   --trace
        # which has no argument, hence following checks for valid arguments
        # and pass it to further examination if it not matches
        if ($typ eq 'TRACE')    {
            $typ = 'HOST';      # expect host as next argument
            _set_cfg_out('traceARG',  1)    if ($arg =~ m#^ARG$#i);
            _set_cfg_out('traceCMD',  1)    if ($arg =~ m#^CMD$#i);
            _set_cfg_out('traceKEY',  1)    if ($arg =~ m#^KEY$#i);
            _set_cfg_out('traceTIME', 1)    if ($arg =~ m#^TIME$#i);
            $cfg{'traceME'}++    if ($arg =~ m#^ME(?:only)?#i);
            $cfg{'traceME'}--    if ($arg =~ m#^notme$#i);
            $cfg{'trace'} = $arg if ($arg =~ m#^\d+$#i);
            # now magic starts ...
            next if ($arg =~ m#^(ARG|CMD|KEY|ME|TIME|\d+)$#i); # matched before
            # if we reach here, argument did not match valid value for --trace,
            # then simply increment trace level and push back argument
            $cfg{'trace'}++;
            unshift(@argv, $arg);
        } # else $typ handled before if-condition
        $typ = 'HOST';          # expect host as next argument
        next;
    } # ne 'HOST' option arguments

    next if ($arg =~ /^\s*$/);  # ignore empty arguments

    _y_ARG("arg_val? $arg");
    # remove trailing = for all options
    # such options are incorrectly used, or are passed in in CGI mode
    # NOTE: this means that we cannot have empty strings as value
    if ($arg =~ m/^-[^=]*=$/) {
        # SEE Note:Option in CGI mode
        # only options in RegEx are ignored if the value is empty
        if ($arg =~ /$cfg{'regex'}->{'opt_empty'}/) {
            _warn("050: option with empty argument '$arg'; option ignored") if ($cgi == 0);
            next;
        }
        $arg =~ s/=+$//;
    }

    # first handle some old syntax for backward compatibility
    _y_ARG("opt_old? $arg");
    if ($arg =~ /^--cfg(cmd|score|text)-([^=]*)=(.*)/) {
        $typ = 'CFG-'.$1; unshift(@argv, $2 . "=" . $3);   # convert to new syntax
        _warn("022: old (pre 13.12.12) syntax '--cfg-$1-$2'; converted to '--cfg-$1=$2'; please consider changing your files");
        next; # no more normalisation!
    }
    if ($arg =~ /^--set[_-]?score=(.*)/) {
        _warn("021: old (pre 13.12.11) syntax '--set-score=*' obsolete, please use '--cfg-score=*'; option ignored");
        next;
    }
    if ($arg =~ /^--legacy=key/) {
        _warn("023: old (pre 19.01.14) syntax '--legacy=key' obsolete, please use '--label=key'; option ignored");
        next;
    }
    # ignore -post= option passed from shell script; ugly but defensive programming
    next if ($arg =~ /^-post=(.*)/);

    # all options starting with  --usr or --user  are not handled herein
    # push them on $cfg{'usr_args'} so they can be accessd in o-saft-*.pm
    _y_ARG("opt_usr? $arg");
    if ($arg =~ /^--use?r/) {
        $arg =~ s/^(?:--|\+)//; # strip leading chars
        push(@{$cfg{'usr_args'}}, $arg);
        next;
    }

    # all options starting with  --h or --help or +help  are not handled herein
    _y_ARG("opt_--h? $arg");
    if ($arg =~ /^--h$/)                            { $arg = "--help=help_brief"; } # --h  is special
    if ($arg =~ /^(?:--|\+)help$/)                  { $arg = "--help=NAME"; }   # --help
    if ($arg =~ /^[+,](abbr|abk|glossar|todo)$/i)   { $arg = "--help=$1"; }     # for historic reason
    # get matching string right of =
    if ($arg =~ /^(?:--|\+|,)help=?(.*)?$/) {
        # we allow:  --help=SOMETHING  or  +help=SOMETHING
        if (defined $1) {
            $arg = $1 if ($1 !~ /^\s*$/);   # pass bare word, if it was --help=*
        }
        # TODO: _load_file() does not yet work, hence following require
        require q{o-saft-man.pm};   ## no critic qw(Modules::RequireBarewordIncludes)
            # include if necessary only; dies if missing
        if ($arg =~ /^gen[._=-]?docs$/) {   # --help=gen-docs
            man_docs_write($arg);
        } else {
            printhelp($arg);
        }
        exit 0;
    }

    #{ handle some specials
    _y_ARG("optmisc? $arg");
    #!#--------+------------------------+--------------------------+------------
    #!#           argument to check       what to do             what to do next
    #!#--------+------------------------+--------------------------+------------
    if ($arg eq  '--trace--')         { _set_cfg_out('traceARG',1); next; } # for backward compatibility
    if ($arg =~ /^--trace.?CLI$/)       {                           next; } # ignore, already handled
    if ($arg =~ /^--v(?:erbose)?$/)     { $cfg{'verbose'}++;        next; } # --v and --v=X allowed
    if ($arg =~ /^--?starttls$/i)       { $cfg{'starttls'} ="SMTP"; next; } # shortcut for  --starttls=SMTP
    if ($arg =~ /^--cgi.?(?:exec|trace)/){$cgi = 1;                 next; } # SEE Note:CGI mode
    if ($arg =~ /^--exit=(.*)/)         {                           next; } # -"-
    if ($arg =~ /^--cmd=\+?(.*)/)       { $arg = '+' . $1;                } # no next;
    if ($arg =~ /^--rc/)                {                           next; } # nothing to do, already handled
    if ($arg eq  '+VERSION')            { _version_exit();        exit 0; } # used with --cgi-exec
    if ($arg eq  '--yeast')             { $arg = '--test-data';           } # TODO: should become a more general check
    if ($arg =~ /^--yeast[_.-]?(.*)/)   { $arg = "--test-$1";             } # -"-
        # in CGI mode commands need to be passed as --cmd=* option
    if ($arg eq  '--openssl')           { $arg = '--extopenssl';          } # no next; # dirty hack for historic option --openssl
    #!#--------+------------------------+--------------------------+------------
    #} specials

    # normalise options with arguments:  --opt=name --> --opt name
    if ($arg =~ m/(^-[^=]*)=(.*)/) {
        $arg = $1;
        unshift(@argv, $2);
        #_dbx("push to ARGV $2");
    } # $arg now contains option only, no argument

    # normalise option strings:
    #    --opt-name     --> --optname
    #    --opt_name     --> --optname
    #    --opt.name     --> --optname
    $arg =~ s/([a-zA-Z0-9])(?:[_.-])/$1/g if ($arg =~ /^-/);
    #_dbx("normalised= $arg");

    # Following checks use exact matches with 'eq' or RegEx matches with '=~'

    _y_ARG("option?  $arg");
    #{ OPTIONS
    #  NOTE: that strings miss - and _ characters (see normalisation above)
    #!# You may read the lines as table with columns like: SEE Note:alias
    #!#--------+------------------------+---------------------------+----------
    #!#           option to check         alias for ...               # used by ...
    #!#--------+------------------------+---------------------------+----------
    # first all aliases
    if ($arg eq  '-t')                  { $arg = '--starttls';      } # alias: testssl.sh
    if ($arg eq  '-b')                  { $arg = '--enabled';       } # alias: ssl-cert-check
    if ($arg eq  '-c')                  { $arg = '--capath';        } # alias: ssldiagnose.exe
    if ($arg =~ /^--?CApath/)           { $arg = '--capath';        } # alias: curl, openssl
    if ($arg =~ /^--?CAfile/)           { $arg = '--cafile';        } # alias: openssl
    if ($arg =~ /^--ca(?:cert(?:ificate)?)$/i)  { $arg = '--cafile';} # alias: curl, openssl, wget, ...
    if ($arg =~ /^--cadirectory$/i)     { $arg = '--capath';        } # alias: curl, openssl, wget, ...
    if ($arg =~ /^--fuzz/i)             { $arg = '--cipherrange'; unshift(@argv, 'huge'); } # alias: sslmap
    if ($arg =~ /^--httpget/i)          { $arg = '--http';          } # alias: sslyze
    if ($arg =~ /^--httpstunnel/i)      { $arg = '--proxyhost';     } # alias: sslyze
    if ($arg eq  '--hiderejectedciphers'){$arg = '--nodisabled';    } # alias: sslyze
    if ($arg eq  '--regular')           { $arg = '--http';          } # alias: sslyze
    if ($arg =~ /^--?interval$/)        { $arg = '--timeout';       } # alias: ssldiagnos.exe
    if ($arg =~ /^--?nofailed$/)        { $arg = '--enabled';       } # alias: sslscan
    if ($arg =~ /^--show-?each$/)       { $arg = '--disabled';      } # alias: testssl.sh
    if ($arg =~ /^--(?:no|ignore)cmd$/) { $arg = '--ignoreout';     } # alias:
        # SEE Note:ignore-out
    # /-- next line is a dummy for extracting aliases
   #if ($arg eq  '--protocol')          { $arg = '--SSL';           } # alias: ssldiagnose.exe
    if ($arg eq  '--range')             { $arg = '--cipherrange';   } # alias:
    if ($arg =~ /^--?servername/i)      { $arg = '--sniname';       } # alias: openssl
    # options form other programs which we treat as command; see Options vs. Commands also
    if ($arg =~ /^-(e|-each-?cipher)$/) { $arg = '+cipher';         } # alias: testssl.sh
    if ($arg =~ /^-(E|-cipher-?perproto)$/) { $arg = '+cipher';     } # alias: testssl.sh
    if ($arg =~ /^-(f|-ciphers)$/)      { $arg = '+ciphercheck';    } # alias: testssl.sh (+ciphercheck defined in .o-saft.pl)
    if ($arg =~ /^-(x|-single-cipher)$/){ $typ = 'CIPHER_ITEM';     } # alias: testssl.sh (must be used together with +cipher)
    if ($arg =~ /^-(p|-protocols)$/)    { $arg = '+protocols';      } # alias: testssl.sh
    if ($arg =~ /^-(y|-spdy)$/)         { $arg = '+spdy';           } # alias: testssl.sh
    if ($arg =~ /^-(Y|-http2)$/)        { $arg = '+spdy';           } # alias: testssl.sh
    if ($arg =~ /^-(U|-vulnerable)$/)   { $arg = '+vulns';          } # alias: testssl.sh
    if ($arg =~ /^-(B|-heartbleed)$/)   { $arg = '+heartbleed';     } # alias: testssl.sh
    if ($arg =~ /^-(I|-ccs(?:-?injection))$/) { $arg = '+ccs';      } # alias: testssl.sh
    if ($arg =~ /^-(C|-compression|-crime)$/) { $arg = '+compression';# alias: testssl.sh
                                          push(@{$cfg{'do'}}, @{$cfg{'cmd-crime'}}); }
    if ($arg =~ /^-(T|-breach)$/)       { $arg = '+breach';         } # alias: testssl.sh
    if ($arg =~ /^-(O|-poodle)$/)       { $arg = '+poodle';         } # alias: testssl.sh
    if ($arg =~ /^-(F|-freak)$/)        { $arg = '+freak';          } # alias: testssl.sh
    if ($arg =~ /^-(A|-beast)$/)        { $arg = '+beast';          } # alias: testssl.sh
    if ($arg =~ /^-(BB|-robot)$/)       { $arg = '+robot';          } # alias: testssl.sh
    if ($arg =~ /^-(J|-logjam)$/)       { $arg = '+logjam';         } # alias: testssl.sh
    if ($arg =~ /^-(D|-drown)$/)        { $arg = '+drown';          } # alias: testssl.sh
    if ($arg =~ /^-(Z|-tls-fallback)$/) { $arg = '+fallback_protocol';  } # alias: testssl.sh
    if ($arg =~ /^-(s|4)$/)             { $arg = '+pfs';            } # alias: testssl.sh
    if ($arg =~ /^--(p?fs|nsa)$/)       { $arg = '+pfs';            } # alias: testssl.sh
    if ($arg =~ /^--(?:rc4|appelbaum)$/){ $arg = '+pfs';            } # alias: testssl.sh
    if ($arg eq  '-R')                  { $arg = '+renegotiation';  } # alias: testssl.sh
    if ($arg =~ /^--reneg(?:otiation)?/){ $arg = '+renegotiation';  } # alias: sslyze, testssl.sh
    if ($arg =~ /^--resum(?:ption)?$/)  { $arg = '+resumption';     } # alias: sslyze
    if ($arg eq  '--chain')             { $arg = '+chain';          } # alias:
    if ($arg eq  '--default')           { $arg = '+default';        } # alias:
    if ($arg eq  '--fingerprint')       { $arg = '+fingerprint';    } # alias:
    if ($arg eq  '--fips')              { $arg = '+fips';           } # alias:
    if ($arg eq  '-i')                  { $arg = '+issuer';         } # alias: ssl-cert-check
    if ($arg eq  '--ism')               { $arg = '+ism';            } # alias: ssltest.pl
    if ($arg eq  '--list')              { $arg = '+list';           } # alias: ssltest.pl
    if ($arg eq  '--quit')              { $arg = '+quit';           } # alias:
    if ($arg eq  '--pci')               { $arg = '+pci';            } # alias: ssltest.pl
    if ($arg eq  '--printavailable')    { $arg = '+ciphers';        } # alias: ssldiagnose.exe
    if ($arg eq  '--printcert')         { $arg = '+text';           } # alias: ssldiagnose.exe
    if ($arg =~ /^--showkeys?/i)        { $arg = '--traceKEY';      } # alias:
    if ($arg eq  '--version')           { $arg = '+version';        } # alias: various programs
    if ($arg eq  '--forceopenssl')      { $arg = '--opensslciphers';    } # alias:
    if ($arg eq  '--cipheropenssl')     { $arg = '--opensslciphers';    } # alias:
    if ($arg eq  '--sclient')           { $arg = '--opensslsclient';    } # alias:
    if ($arg eq  '--nosclient')         { $arg = '--noopensslsclient';  } # alias:
    if ($arg eq  '--sslnouseecc')       { $arg = '--nossluseecc';       } # alias:
    if ($arg eq  '--sslnouseecpoint')   { $arg = '--nossluseecpoint';   } # alias:
    if ($arg eq  '--sslnousereneg')     { $arg = '--nosslusereneg';     } # alias:
    if ($arg eq  '--sslnodoublereneg')  { $arg = '--nossldoublereneg';  } # alias:
    if ($arg eq  '--sslnodatanocipher') { $arg = '--nodataeqnocipher';  } # alias:
    if ($arg eq  '--sslnodataeqnocipher'){$arg = '--nodataeqnocipher';  } # alias:
    if ($arg eq  '--nosslnodataeqnocipher'){$arg = '--nosslnodatanocipher'; } # alias:
    if ($arg eq  '--nomd5cipher')       { $arg = '--nociphermd5';       } # alias: used until VERSION 17.04.17
    if ($arg eq  '--md5cipher')         { $arg = '--ciphermd5';         } # alias: used until VERSION 17.04.17
    #!#--------+------------------------+---------------------------+----------
    #!#           option to check         what to do                  comment
    #!#--------+------------------------+---------------------------+----------
    # options for trace and debug
    if ($arg =~ /^--v(?:erbose)?$/)     { $typ = 'VERBOSE';         }
    if ($arg =~ /^--ciphers?-?v$/)      { $arg = '--v-ciphers';     } # alias:
    if ($arg =~ /^--ciphers?--?v$/)     { $arg = '--v-ciphers';     } # alias:
    if ($arg =~ /^--v-?ciphers?$/)      { $cfg{'v_cipher'}++;       }
    if ($arg =~ /^--warnings?$/)        { _set_cfg_out('warning',      1);  }
    if ($arg =~ /^--nowarnings?$/)      { _set_cfg_out('warning',      0);  }
    if ($arg =~ /^--warningsdups?$/)    { _set_cfg_out('warnings_no_dups', []); }
    if ($arg =~ /^--nowarningsnodups?$/){ _set_cfg_out('warnings_no_dups', []); }
    if ($arg eq  '--n')                 { $cfg{'try'}       = 1;    }
    if ($arg eq  '--dryrun')            { $cfg{'try'}       = 1;    } # alias: --n
    if ($arg =~ /^--tracearg/i)         { _set_cfg_out('traceARG',     1);  } # special internal tracing
    if ($arg =~ /^--tracecmd/i)         { _set_cfg_out('traceCMD',     1);  } # ..
    if ($arg =~ /^--trace(?:@|key)/i)   { _set_cfg_out('traceKEY',     1);  } # ..
    if ($arg =~ /^--tracetime/i)        { _set_cfg_out('traceTIME',    1);  } # ..
    if ($arg =~ /^--traceme/i)          { $cfg{'traceME'}++;        } # ..
    if ($arg =~ /^--tracenotme/i)       { $cfg{'traceME'}--;        } # ..
    if ($arg eq  '--trace')             { $typ = 'TRACE';           }
    if ($arg =~ /^--timeabsolute?/i)    { _set_cfg_out('time_absolut', 1);  }
    if ($arg eq  '--timerelative')      { _set_cfg_out('time_absolut', 0);  }
    if ($arg eq  '--linuxdebug')        { $cfg{'linux_debug'}++;    }
    if ($arg eq  '--slowly')            { $cfg{'slowly'}    = 1;    }
    if ($arg =~ /^--exp(?:erimental)?$/){ _set_cfg_use('experimental', 1);  }
    if ($arg =~ /^--noexp(erimental)?$/){ _set_cfg_use('experimental', 0);  }
    if ($arg eq  '--filesclient')       { $typ = 'FILE_SCLIENT';    }
    if ($arg eq  '--fileciphers')       { $typ = 'FILE_CIPHERS';    }
    if ($arg eq  '--filepcap')          { $typ = 'FILE_PCAP';       }
    if ($arg eq  '--filepem')           { $typ = 'FILE_PEM';        }
    if ($arg eq  '--anonoutput')        { $typ = 'ANON_OUT';        } # SEE Note:anon-out
    if ($arg =~ /^--tests?/)            { $test = $arg;             } # SEE Note:--test-*
    if ($arg =~ /^[+,]tests?/)          { $test = $arg;       next; } # SEE Note:--test-*
        # handles also --test-* and --tests-*; no further check if +test*
    # proxy options
    if ($arg =~ /^--proxy(?:host)?$/)   { $typ = 'PROXY_HOST';      }
    if ($arg eq  '--proxyport')         { $typ = 'PROXY_PORT';      }
    if ($arg eq  '--proxyuser')         { $typ = 'PROXY_USER';      }
    if ($arg eq  '--proxypass')         { $typ = 'PROXY_PASS';      }
    if ($arg eq  '--proxyauth')         { $typ = 'PROXY_AUTH';      }
    if ($arg =~ /^--?starttls$/i)       { $typ = 'STARTTLS';        }
    if ($arg =~ /^--starttlsdelay$/i)   { $typ = 'TLS_DELAY';       }
    if ($arg =~ /^--slowserverdelay$/i) { $typ = 'SLOW_DELAY';      }
    if ($arg =~ /^--starttlserror1$/i)  { $typ = 'STARTTLSE1';      }
    if ($arg =~ /^--starttlserror2$/i)  { $typ = 'STARTTLSE2';      }
    if ($arg =~ /^--starttlserror3$/i)  { $typ = 'STARTTLSE3';      }
    if ($arg =~ /^--starttlsphase1$/i)  { $typ = 'STARTTLSP1';      }
    if ($arg =~ /^--starttlsphase2$/i)  { $typ = 'STARTTLSP2';      }
    if ($arg =~ /^--starttlsphase3$/i)  { $typ = 'STARTTLSP3';      }
    if ($arg =~ /^--starttlsphase4$/i)  { $typ = 'STARTTLSP4';      }
    if ($arg =~ /^--starttlsphase5$/i)  { $typ = 'STARTTLSP5';      }
    # options form other programs for compatibility
#   if ($arg eq  '-v')                  { $typ = 'PROTOCOL';        } # ssl-cert-check # NOTE: not supported
#   if ($arg eq  '-V')                  { $cfg{'opt-V'}     = 1;    } # ssl-cert-check; will be out->header, # TODO not supported
    if ($arg eq  '-v')                  { $cfg{'opt-v'}     = 1;    } # openssl, ssl-cert-check
    if ($arg eq  '-V')                  { $cfg{'opt-V'}     = 1;    } # openssl, ssl-cert-check
    if ($arg eq  '--V')                 { $cfg{'opt-V'}     = 1;    } # alias: for lazy people, not documented
    # options form other programs which we treat as command; see Options vs. Commands also
    if ($arg =~ /^--checks?$/)          { $typ = 'DO';              } # tls-check.pl
    if ($arg =~ /^--(fips|ism|pci)$/i)  {}
    # options to handle external openssl
    if ($arg eq  '--openssl')           { $typ = 'OPENSSL';         }
    if ($arg eq  '--openssl3')          { $typ = 'OPENSSL3';        }
    if ($arg =~  '--opensslco?nf')      { $typ = 'OPENSSL_CNF';     }
    if ($arg eq  '--opensslfips')       { $typ = 'OPENSSL_FIPS';    }
    if ($arg eq  '--extopenssl')        { $cmd{'extopenssl'}= 1;    }
    if ($arg eq  '--noopenssl')         { $cmd{'extopenssl'}= 0;    }
    if ($arg eq  '--opensslciphers')    { $cmd{'extciphers'}= 1;    }
    if ($arg eq  '--noopensslciphers')  { $cmd{'extciphers'}= 0;    }
    if ($arg eq  '--opensslsclient')    { $cmd{'extsclient'}= 1;    }
    if ($arg eq  '--noopensslsclient')  { $cmd{'extsclient'}= 0;    }
    if ($arg eq  '--alpn')              { _set_cfg_use('alpn',   1);}
    if ($arg eq  '--noalpn')            { _set_cfg_use('alpn',   0);}
    if ($arg eq  '--npn')               { _set_cfg_use('npn',    1);}
    if ($arg eq  '--nonpn')             { _set_cfg_use('npn',    0);}
    if ($arg =~ /^--?nextprotoneg$/)    { _set_cfg_use('npn',    1);} # openssl
    if ($arg =~ /^--nonextprotoneg/)    { _set_cfg_use('npn',    0);}
    if ($arg =~ /^--?comp(?:ression)?$/){ $arg = '--sslcompression';     } # alias:
    if ($arg =~ /^--?nocomp(ression)?$/){ $arg = '--nosslcompression';   } # alias:
    if ($arg =~ /^--sslcompression$/)   { _set_cfg_use('no_comp',    0); } # openssl s_client -comp
    if ($arg =~ /^--nosslcompression$/) { _set_cfg_use('no_comp',    1); } # openssl s_client -no_comp
    if ($arg =~ /^--?tlsextdebug$/)     { _set_cfg_use('extdebug',   1); }
    if ($arg =~ /^--notlsextdebug/)     { _set_cfg_use('extdebug',   0); }
    if ($arg =~ /^--?reconnect$/)       { _set_cfg_use('reconnect',  1); }
    if ($arg =~ /^--noreconnect$/)      { _set_cfg_use('reconnect',  0); }
    if ($arg eq  '--sclientopt')        { $typ = 'OPT';             }
    # various options
    if ($arg eq  '--forcesni')          { _set_cfg_use('forcesni',   1); }
    if ($arg =~ /^--ignorenoconn(ect)?/){ $cfg{'sslerror'}->{'ignore_no_conn'}  = 1;}
    if ($arg =~ /^--ignorehandshake/)   { $cfg{'sslerror'}->{'ignore_handshake'}= 1;}
    if ($arg =~ /^--noignorehandshake/) { $cfg{'sslerror'}->{'ignore_handshake'}= 0;}
    if ($arg eq  '--lwp')               { _set_cfg_use('lwp',    1);}
    if ($arg eq  '--sni')               { _set_cfg_use('sni',    1);}
    if ($arg eq  '--nosni')             { _set_cfg_use('sni',    0);}
    if ($arg eq  '--snitoggle')         { _set_cfg_use('sni',    3);}
    if ($arg eq  '--togglesni')         { _set_cfg_use('sni',    3);}
    if ($arg eq  '--nocert')            { _set_cfg_use('cert',   0);}
    if ($arg eq  '--noignorecase')      { $cfg{'ignorecase'}    = 0;}
    if ($arg eq  '--ignorecase')        { $cfg{'ignorecase'}    = 1;}
    if ($arg eq  '--noignorenoreply')   { $cfg{'ignorenoreply'} = 0;}
    if ($arg eq  '--ignorenoreply')     { $cfg{'ignorenoreply'} = 1;}
    if ($arg eq  '--noexitcode')        { _set_cfg_use('exitcode',        0); }
    if ($arg eq  '--exitcode')          { _set_cfg_use('exitcode',        1); } # SEE Note:--exitcode
    if ($arg =~ /^--exitcodev/)         { _set_cfg_out('exitcode',        1); } #
    if ($arg =~ /^--traceexit/)         { _set_cfg_out('exitcode',        1); } # alias: --exitcode
    if ($arg =~ /^--exitcodequiet/)     { _set_cfg_out('exitcode_quiet',  1); } #
    if ($arg =~ /^--exitcodesilent/)    { _set_cfg_out('exitcode_quiet',  1); } # alias: --exitcode-quiet
    if ($arg =~ /^--exitcodenochecks?/) { _set_cfg_out('exitcode_checks', 0); } # -"-
    if ($arg =~ /^--exitcodenomedium/)  { _set_cfg_out('exitcode_medium', 0); } # -"-
    if ($arg =~ /^--exitcodenoweak/)    { _set_cfg_out('exitcode_weak',   0); } # -"-
    if ($arg =~ /^--exitcodenolow/)     { _set_cfg_out('exitcode_low',    0); } # -"-
    if ($arg =~ /^--exitcodenopfs/)     { _set_cfg_out('exitcode_pfs',    0); } # -"-
    if ($arg =~ /^--exitcodenoprot/)    { _set_cfg_out('exitcode_prot',   0); } # -"-
    if ($arg =~ /^--exitcodenosizes/)   { _set_cfg_out('exitcode_sizes',  0); } # -"-
    if ($arg =~ /^--exitcodenociphers?/){   # shortcut options for following
        _set_cfg_out('exitcode_cipher', 0);
        _set_cfg_out('exitcode_medium', 0);
        _set_cfg_out('exitcode_weak',   0);
        _set_cfg_out('exitcode_low',    0);
    }
    # some options are for compatibility with other programs
    #   example: -tls1 -tlsv1 --tlsv1 --tls1_1 --tlsv1_1 --tls11 -no_SSL2
    if ($arg =~ /^--?sslv?2$/i)         { $cfg{'SSLv2'}     = 1;    } # allow case insensitive
    if ($arg =~ /^--?sslv?3$/i)         { $cfg{'SSLv3'}     = 1;    } # -"-
    if ($arg =~ /^--?tlsv?1$/i)         { $cfg{'TLSv1'}     = 1;    }
    if ($arg =~ /^--?tlsv?11$/i)        { $cfg{'TLSv11'}    = 1;    }
    if ($arg =~ /^--?tlsv?12$/i)        { $cfg{'TLSv12'}    = 1;    }
    if ($arg =~ /^--?tlsv?13$/i)        { $cfg{'TLSv13'}    = 1;    }
    if ($arg =~ /^--dtlsv?09$/i)        { $cfg{'DTLSv09'}   = 1;    }
    if ($arg =~ /^--dtlsv?10?$/i)       { $cfg{'DTLSv1'}    = 1;    }
    if ($arg =~ /^--dtlsv?11$/i)        { $cfg{'DTLSv11'}   = 1;    }
    if ($arg =~ /^--dtlsv?12$/i)        { $cfg{'DTLSv12'}   = 1;    }
    if ($arg =~ /^--dtlsv?13$/i)        { $cfg{'DTLSv13'}   = 1;    }
    if ($arg =~ /^--nosslv?2$/i)        { $cfg{'SSLv2'}     = 0;    }
    if ($arg =~ /^--nosslv?3$/i)        { $cfg{'SSLv3'}     = 0;    }
    if ($arg =~ /^--notlsv?1$/i)        { $cfg{'TLSv1'}     = 0;    }
    if ($arg =~ /^--notlsv?11$/i)       { $cfg{'TLSv11'}    = 0;    }
    if ($arg =~ /^--notlsv?12$/i)       { $cfg{'TLSv12'}    = 0;    }
    if ($arg =~ /^--notlsv?13$/i)       { $cfg{'TLSv13'}    = 0;    }
    if ($arg =~ /^--nodtlsv?09$/i)      { $cfg{'DTLSv09'}   = 0;    }
    if ($arg =~ /^--nodtlsv?10?$/i)     { $cfg{'DTLSv1'}    = 0;    }
    if ($arg =~ /^--nodtlsv?11$/i)      { $cfg{'DTLSv11'}   = 0;    }
    if ($arg =~ /^--nodtlsv?12$/i)      { $cfg{'DTLSv12'}   = 0;    }
    if ($arg =~ /^--nodtlsv?13$/i)      { $cfg{'DTLSv13'}   = 0;    }
    if ($arg =~ /^--notcp/i)            { $cfg{$_} = 0 foreach (qw(SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 TLSv13)); }
    if ($arg =~ /^--tcp/i)              { $cfg{$_} = 1 foreach (qw(SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 TLSv13)); }
    if ($arg =~ /^--noudp/i)            { $cfg{$_} = 0 foreach (qw(DTLSv09 DTLSv1 DTLSv11 DTLSv12 DTLSv13)); }
    if ($arg =~ /^--udp/i)              { $cfg{$_} = 1 foreach (qw(DTLSv09 DTLSv1 DTLSv11 DTLSv12 DTLSv13)); }
    # options for +cipher
    if ($arg eq   '-cipher')            { $typ = 'CIPHER_ITEM';     } # openssl
    if ($arg eq  '--cipher')            { $typ = 'CIPHER_ITEM';     }
    if ($arg eq  '--ciphermode')        { $typ = 'CIPHER_MODE';     }
    if ($arg eq  '--cipherrange')       { $typ = 'CIPHER_RANGE';    }
    if ($arg =~ /^--ciphercurves?/)     { $typ = 'CIPHER_CURVES';   }
    if ($arg =~ /^--cipheralpns?/)      { $typ = 'CIPHER_ALPN';     }
    if ($arg =~ /^--ciphernpns?/)       { $typ = 'CIPHER_NPN';      }
    if ($arg eq  '--nociphermd5')       { $cfg{'cipher_md5'}= 0;    }
    if ($arg eq  '--ciphermd5')         { $cfg{'cipher_md5'}= 1;    }
    if ($arg eq  '--nocipherdh')        { $cfg{'cipher_dh'} = 0;    }
    if ($arg eq  '--cipherdh')          { $cfg{'cipher_dh'} = 1;    }
    # our options
    if ($arg eq  '--nodns')             { _set_cfg_use('dns',    0);}
    if ($arg eq  '--dns')               { _set_cfg_use('dns',    1);}
    if ($arg eq  '--http')              { _set_cfg_use('http',   1);}
    if ($arg eq  '--httpanon')          { _set_cfg_use('http',   2);} # NOT YET USED
    if ($arg eq  '--nohttp')            { _set_cfg_use('http',   0);}
    if ($arg eq  '--https')             { _set_cfg_use('https',  1);}
    if ($arg eq  '--httspanon')         { _set_cfg_use('https',  2);} # NOT YET USED
    if ($arg eq  '--nohttps')           { _set_cfg_use('https',       0); }
    if ($arg =~ /^\--https?body$/i)     { _set_cfg_out('http_body',   1); } # SEE Note:--https_body
    if ($arg eq  '--nosniname')         { _set_cfg_use('sni',         0); } # 0: don't use SNI, different than empty string
    if ($arg eq  '--norc')              {                                 } # simply ignore
    if ($arg eq  '--sslerror')          { _set_cfg_use('ssl_error',   1); }
    if ($arg eq  '--nosslerror')        { _set_cfg_use('ssl_error',   0); }
    if ($arg eq  '--ssllazy')           { _set_cfg_use('ssl_lazy',    1); }
    if ($arg eq  '--nossllazy')         { _set_cfg_use('ssl_lazy',    0); }
    if ($arg =~ /^--nullsslv?2$/i)      { _set_cfg_use('nullssl2',    1); }
    if ($arg =~ /^--sslv?2null$/i)      { _set_cfg_use('nullssl2',    1); }
    # SEE Note:--enabled --disabled
    if ($arg eq  '--noenabled')         { _set_cfg_out('enabled',     0); }
    if ($arg eq  '--enabled')           { _set_cfg_out('enabled',     1); _set_cfg_out('disabled',   0); }
    if ($arg eq  '--disabled')          { _set_cfg_out('disabled',    1); _set_cfg_out('enabled',    0); }
    if ($arg eq  '--nodisabled')        { _set_cfg_out('disabled',    0); }
    if ($arg =~ /^--headers?$/)         { _set_cfg_out('header',      1); } # some people type --headers
    if ($arg =~ /^--noheaders?$/)       { _set_cfg_out('header',      0); }
    if ($arg =~ /^--hints?$/)           { _set_cfg_out('hint_info',   1); _set_cfg_out('hint_check', 1); }
    if ($arg =~ /^--nohints?$/)         { _set_cfg_out('hint_info',   0); _set_cfg_out('hint_check', 0); }
    if ($arg =~ /^--hints?infos?/)      { _set_cfg_out('hint_info',   1); }
    if ($arg =~ /^--nohints?infos?/)    { _set_cfg_out('hint_info',   0); }
    if ($arg =~ /^--hints?checks?/)     { _set_cfg_out('hint_check',  1); }
    if ($arg =~ /^--nohints?checks?/)   { _set_cfg_out('hint_check',  0); }
    if ($arg =~ /^--hints?cipher/)      { _set_cfg_out('hint_cipher', 1); }
    if ($arg =~ /^--nohints?cipher/)    { _set_cfg_out('hint_cipher', 0); }
    if ($arg =~ /^--showhosts?/i)       { _set_cfg_out('hostname',    1); }
    if ($arg eq  '--score')             { _set_cfg_out('score',       1); }
    if ($arg eq  '--noscore')           { _set_cfg_out('score',       0); }
    if ($arg eq  '--tab')               { $text{'separator'}= "\t"; } # TAB character
    if ($arg eq  '--protocol')          { $typ = 'PROTOCOL';        } # ssldiagnose.exe
#   if ($arg eq  '--serverprotocol')    { $typ = 'PROTOCOL';        } # ssldiagnose.exe; # not implemented 'cause we do not support server mode
    if ($arg =~ /^--protoalpns?/)       { $typ = 'PROTO_ALPN';      } # some people type --protoalpns
    if ($arg =~ /^--protonpns?/)        { $typ = 'PROTO_NPN';       } # some people type --protonpns
    if ($arg =~ /^--?h(?:ost)?$/)       { $typ = 'HOST';            } # --h already catched above
    if ($arg =~ /^--?p(?:ort)?$/)       { $typ = 'PORT';            }
    if ($arg =~ /^--exe(?:path)?$/)     { $typ = 'EXE';             }
    if ($arg =~ /^--lib(?:path)?$/)     { $typ = 'LIB';             }
    if ($arg eq  '--envlibvar')         { $typ = 'LD_ENV';          }
    if ($arg eq  '--envlibvar3')        { $typ = 'LD_ENV3';         }
    if ($arg =~ /^--(?:no|ignore)out(?:put)?$/) { $typ = 'NO_OUT';  }
    if ($arg =~ /^--cfg(cmd|check|data|hint|info|text)$/)   { $typ = 'CFG-' . $1; }
    if ($arg =~ /^--cfgcipher$/)        { $typ = 'CFG_CIPHER';      }
    if ($arg =~ /^--cfginit$/)          { $typ = 'CFG_INIT';        }
    if ($arg eq  '--call')              { $typ = 'CALL';            }
    if ($arg eq  '--legacy')            { $typ = 'LEGACY';          }
    if ($arg eq  '--label')             { $typ = 'LABEL';           }
    if ($arg eq  '--format')            { $typ = 'FORMAT';          }
    if ($arg eq  '--formatident')       { $typ = 'TTY_IDENT';       }
    if ($arg eq  '--formatwidth')       { $typ = 'TTY_WIDTH';       }
    if ($arg eq  '--formatarrow')       { $typ = 'TTY_ARROW';       }
    if ($arg =~ /^--(?:format)?tty$/)   { _set_cfg_tty('width', 0) if not defined $cfg{'tty'}->{'width'}; } # SEE Note:tty
    if ($arg =~ /^--short(?:te?xt)?$/)  { $cfg{'label'} = 'short';  } # ancient sinc 19.01.14
    if ($arg =~ /^--sep(?:arator)?$/)   { $typ = 'SEP';             }
    if ($arg =~ /^--?timeout$/)         { $typ = 'TIMEOUT';         }
    if ($arg =~ /^--nocertte?xt$/)      { $typ = 'CERT_TEXT';       }
    if ($arg =~ /^--sniname/i)          { $typ = 'SNINAME';         }
    if ($arg =~ /^--sslerrormax/i)      { $typ = 'SSLERROR_MAX';    }
    if ($arg =~ /^--sslerrortotal/i)    { $typ = 'SSLERROR_TOT';    }
    if ($arg =~ /^--sslerrortotal(?:max)?/i){ $typ = 'SSLERROR_TOT';}
    if ($arg =~ /^--sslerrordelay/i)    { $typ = 'SSLERROR_DLY';    }
    if ($arg =~ /^--sslerrortimeout/i)  { $typ = 'SSLERROR_TOUT';   }
    if ($arg =~ /^--sslerrorperprot/i)  { $typ = 'SSLERROR_PROT';   }
    if ($arg =~ /^--connectdelay/i)     { $typ = 'CONNECT_DELAY';   }
    if ($arg eq  '--socketreuse')       { $cfg{'socket_reuse'}  = 1;}
    if ($arg eq  '--nosocketreuse')     { $cfg{'socket_reuse'}  = 0;}
    # options for Net::SSLhello
    if ($arg =~ /^--no(?:dns)?mx/)      { $cfg{'use'}->{'mx'}   = 0;}
    if ($arg =~ /^--(?:dns)?mx/)        { $cfg{'use'}->{'mx'}   = 1;}
#   if ($arg =~ /^--useragent/)         { $typ = 'HTTP_USER_AGENT'; } # TODO not working
    if ($arg =~ /^--(?:http)?useragent/){ $typ = 'HTTP_USER_AGENT'; } # TODO: (?:http)? not working
    if ($arg eq  '--sslretry')          { $typ = 'SSLHELLO_RETRY';  }
    if ($arg eq  '--ssltimeout')        { $typ = 'SSLHELLO_TOUT';   }
    if ($arg eq  '--sslmaxciphers')     { $typ = 'SSLHELLO_MAXC';   }
    if ($arg eq  '--usesignaturealg')   { $cfg{'sslhello'}->{'usesignaturealg'} = 1; }
    if ($arg eq  '--nousesignaturealg') { $cfg{'sslhello'}->{'usesignaturealg'} = 0; }
    if ($arg eq  '--nossluseecc')       { $cfg{'sslhello'}->{'useecc'}   = 0; }
    if ($arg eq  '--ssluseecc')         { $cfg{'sslhello'}->{'useecc'}   = 1; }
    if ($arg eq  '--nossluseecpoint')   { $cfg{'sslhello'}->{'useecpoint'} = 0; }
    if ($arg eq  '--ssluseecpoint')     { $cfg{'sslhello'}->{'useecpoint'} = 1; }
    if ($arg eq  '--nosslusereneg')     { $cfg{'sslhello'}->{'usereneg'} = 0; }
    if ($arg eq  '--sslusereneg')       { $cfg{'sslhello'}->{'usereneg'} = 1; }
    if ($arg eq  '--nossldoublereneg')  { $cfg{'sslhello'}->{'double_reneg'}   = 0; }
    if ($arg eq  '--ssldoublereneg')    { $cfg{'sslhello'}->{'double_reneg'}   = 1; }
    if ($arg eq  '--nodataeqnocipher')  { $cfg{'sslhello'}->{'nodatanocipher'} = 1; }
    if ($arg eq  '--nosslnodatanocipher') { $cfg{'sslhello'}->{'nodatanocipher'} = 0; }
    #!#--------+------------------------+---------------------------+----------
    if ($arg =~ /^--cadepth$/i)         { $typ = 'CA_DEPTH';        } # some tools use CAdepth
    if ($arg =~ /^--cafile$/i)          { $typ = 'CA_FILE';         }
    if ($arg =~ /^--capath$/i)          { $typ = 'CA_PATH';         }
    if ($arg =~ /^--stdformat/i)        { $typ = 'STD_FORMAT';      }
    if ($arg =~ /^--winCR/i)            { _set_binmode(":crlf:utf8"); } # historic alias
    # ignored options
    if ($arg =~ /^-connect$/)           {}
    if ($arg eq  '--insecure')          {}
    if ($arg =~ /^--use?r$/)            {}
    if ($arg =~ /^--(?:ciscospeshul|nocolor|nopct|strictpcigrade|UDP)$/)  {} # ssldiagnos.exe
    if ($arg =~ /^--server(cert|certkey|certpass|cipher|protocol|mode)$/) {} #  "
    if ($arg =~ /^-(?:H|r|s|t|url|u|U|x)$/) {}
                # -s HOST   # ssl-cert-check: -s ignored hence HOST parsed as expected
                # -x DAYS   # ssl-cert-check: -x ignored hence DAYS taken as host # FIXME
    #} --------+------------------------+---------------------------+----------

    _y_ARG("option=  $arg") if ($arg =~ /^-/);
    next if ($arg =~ /^-/); # all options handled, remaining are ignored
        # i.e. from sslscan: --no-renegotiation --no-compression ...
        # TODO: means that targets starting with '-' are not possible,
        #       however, such FQDN are illegal

    #{ COMMANDS
    my $p = qr/[._-]/;  # characters used as separators in commands keys
                        # this will always be used as $p? below
    _y_ARG("command? $arg");
    $arg =~ s/^,/+/;    # allow +command and ,command
    # The following sequence of conditions is important: commands which are an
    # alias for another command are listed first. These aliases should contain
    # the comment  "# alias"  somewhere in the line, so it can be extracted by
    # other tools easily.  The comment  "# alias:"  is used by  --help=alias .
    # the command assigned to $arg should be enclosed in ' (single quote), see
    # o-saft-man.pm' man_alias() for more details.
    # You may read the lines as table with columns like:
    #!#+---------+----------------------+---------------------------+-------------
    #!#           command to check       aliased to                  comment/traditional name
    #!#+---------+----------------------+---------------------------+-------------
    if ($arg =~ /^\+targets?$/)         { $arg = '+host';           } # alias: print host and DNS information
    if ($arg =~ /^\+host$p/)            { $arg = '+host';           } # alias: until indiidual +host-* commands available
    # check protocol commands
    if ($arg eq  '+check')              { $check  = 1;              }
    if ($arg eq  '+info')               { $info   = 1;              } # needed 'cause +info and ..
    if ($arg eq  '+quick')              { $quick  = 1;              } # .. +quick convert to list of commands
    if ($arg eq  '+sni')                { $cmdsni = 1;              }
    if ($arg eq  '+http2')              { $arg = '+protocols';      } # alias: HTTP/2.0; TODO: may be changed in future
    if ($arg eq  '+spdy')               { $arg = '+protocols';      } # alias: spdy; TODO: may be changed in future
    if ($arg eq  '+spdy3')              { $arg = '+protocols';      } # alias: SPDY/3.0; TODO: may be changed in future
    if ($arg eq  '+spdy31')             { $arg = '+protocols';      } # alias: SPDY/3.1; TODO: may be changed in future
    if ($arg eq  '+spdy4')              { $arg = '+protocols';      } # alias: SPDY/4.0; TODO: may be changed in future
    if ($arg eq  '+prots')              { $arg = '+protocols';      } # alias:
    if ($arg eq  '+tlsv10')             { $arg = '+tlsv1';          } # alias:
    if ($arg eq  '+dtlsv10')            { $arg = '+dtlsv1';         } # alias:
    # check cipher commands
    if ($arg =~ /^\+ciphers?$p?adh/i)   { $arg = '+cipher_adh';     } # alias:
    if ($arg =~ /^\+ciphers?$p?cbc/i)   { $arg = '+cipher_cbc';     } # alias:
    if ($arg =~ /^\+ciphers?$p?des/i)   { $arg = '+cipher_des';     } # alias:
    if ($arg =~ /^\+ciphers?$p?edh/i)   { $arg = '+cipher_edh';     } # alias:
    if ($arg =~ /^\+ciphers?$p?exp/i)   { $arg = '+cipher_exp';     } # alias:
    if ($arg =~ /^\+ciphers?$p?export/i){ $arg = '+cipher_exp';     } # alias:
    if ($arg =~ /^\+ciphers?$p?null/i)  { $arg = '+cipher_null';    } # alias:
    if ($arg =~ /^\+ciphers?$p?weak/i)  { $arg = '+cipher_weak';    } # alias:
    if ($arg =~ /^\+ciphers?$p?order/i) { $arg = '+cipher_order';   } # alias:
    if ($arg =~ /^\+ciphers?$p?strong/i){ $arg = '+cipher_strong';  } # alias:
    if ($arg =~ /^\+ciphers?$p?pfs/i)   { $arg = '+cipher_pfs';     } # alias:
    if ($arg =~ /^\+ciphers?$p?pfsall/i){ $arg = '+cipher_pfsall';  } # alias:
    if ($arg =~ /^\+ciphers?$p?selected/i){$arg= '+cipher_selected';} # alias:
    if ($arg =~ /^\+ciphers$p?openssl/i){ $arg = '+ciphers_local';  } # alias: for backward compatibility
    if ($arg =~ /^\+ciphers$p?local/i)  { $arg = '+ciphers_local';  } # alias:
    if ($arg =~ /^\+ciphers?$p?preferr?ed/i){ $arg = '+cipher_default'; }
    if ($arg =~ /^\+ciphers?$p?defaults?/i){  $arg = '+cipher_default'; } # alias:
    if ($arg =~ /^\+ciphers?$p?dh/i)    { $arg = '+cipher_dh';      } # alias:
    if ($arg =~ /^\+cipher--?v$/)       { $arg = '+cipher'; $cfg{'v_cipher'}++; } # alias: shortcut for: +cipher --cipher-v
    if ($arg =~ /^\+adh$p?ciphers?/i)   { $arg = '+cipher_adh';     } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+cbc$p?ciphers?/i)   { $arg = '+cipher_cbc';     } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+des$p?ciphers?/i)   { $arg = '+cipher_des';     } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+edh$p?ciphers?/i)   { $arg = '+cipher_edh';     } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+exp$p?ciphers?/i)   { $arg = '+cipher_exp';     } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+export$p?ciphers?/i){ $arg = '+cipher_exp';     } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+null$p?ciphers?/i)  { $arg = '+cipher_null';    } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+weak$p?ciphers?/i)  { $arg = '+cipher_weak';    } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+order$p?ciphers?/i) { $arg = '+cipher_order';   } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+strong$p?ciphers?/i){ $arg = '+cipher_strong';  } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+selected$p?ciphers?/i){$arg= '+cipher_selected';} # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+session$p?ciphers?/i) {$arg= '+cipher_selected';} # alias: backward compatibility < 17.06.17
    if ($arg eq  '+selected')           { $arg = '+cipher_selected';} # alias: backward compatibility < 17.06.17
    if ($arg eq  '+adh')                { $arg = '+cipher_adh';     } # alias:
    if ($arg eq  '+cbc')                { $arg = '+cipher_cbc';     } # alias:
    if ($arg eq  '+des')                { $arg = '+cipher_des';     } # alias:
    if ($arg eq  '+edh')                { $arg = '+cipher_edh';     } # alias:
    if ($arg eq  '+exp')                { $arg = '+cipher_exp';     } # alias:
    if ($arg eq  '+export')             { $arg = '+cipher_exp';     } # alias:
    if ($arg eq  '+null')               { $arg = '+cipher_null';    } # alias:
    if ($arg eq  '+weak')               { $arg = '+cipher_weak';    } # alias:
    # alias commands for CVEs
    if ($arg =~ /^[+]cve.?2009.?3555/i) { $arg = '+renegotiation';  } # alias:
    if ($arg =~ /^[+]cve.?2011.?3389/i) { $arg = '+beast';          } # alias:
    if ($arg =~ /^[+]cve.?2012.?4929/i) { $arg = '+crime';          } # alias:
    if ($arg =~ /^[+]cve.?2013.?3587/i) { $arg = '+breach';         } # alias:
    if ($arg =~ /^[+]cve.?2014.?0160/i) { $arg = '+heartbleed';     } # alias:
    if ($arg =~ /^[+]cve.?2014.?0224/i) { $arg = '+ccs';            } # alias:
    if ($arg =~ /^[+]cve.?2014.?3566/i) { $arg = '+poodle';         } # alias:
    if ($arg =~ /^[+]cve.?2015.?0204/i) { $arg = '+freak';          } # alias:
    if ($arg =~ /^[+]cve.?2016.?0703/i) { $arg = '+drown';          } # alias:
    if ($arg =~ /^[+]cve.?2015.?4000/i) { $arg = '+logjam';         } # alias:
    if ($arg =~ /^[+]cve.?2013.?2566/i) { $arg = '+rc4';            } # alias:
    if ($arg =~ /^[+]cve.?2015.?2808/i) { $arg = '+rc4';            } # alias:
    # check and info commands
    if ($arg eq  '+owner')              { $arg = '+subject';        } # alias:
    if ($arg eq  '+authority')          { $arg = '+issuer';         } # alias:
    if ($arg eq  '+expire')             { $arg = '+after';          } # alias:
    if ($arg eq  '+extension')          { $arg = '+extensions';     } # alias:
    if ($arg eq  '+sts')                { $arg = '+hsts';           } # alias:
    if ($arg eq  '+sigkey')             { $arg = '+sigdump';        } # alias:
    if ($arg =~ /^\+sigkey$p?algorithm/i){$arg = '+signame';        } # alias:
    if ($arg eq  '+protocol')           { $arg = '+session_protocol'; } # alias:
    if ($arg =~ /^\+selected$p?protocol/i){$arg= '+session_protocol'; } # alias:
    if ($arg =~ /^\+rfc$p?2818$/i)      { $arg = '+rfc_2818_names'; } # alias:
    if ($arg =~ /^\+rfc$p?2818$p?names/i){$arg = '+rfc_2818_names'; } # alias:
    if ($arg =~ /^\+rfc$p?6125$/i)      { $arg = '+rfc_6125_names'; } # alias: # TODO until check is improved (6/2015)
    if ($arg =~ /^\+rfc$p?6125$p?names/i){$arg = '+rfc_6125_names'; } # alias:
    if ($arg =~ /^\+rfc$p?6797$/i)      { $arg = '+hsts';           } # alias:
    if ($arg =~ /^\+rfc$p?7525$/i)      { $arg = '+rfc_7525';       } # alias:
        # do not match +fingerprints  in next line as it may be in .o-saft.pl
    if ($arg =~ /^\+fingerprint$p?(.{2,})$/)          { $arg = '+fingerprint_' . $1;} # alias:
    if ($arg =~ /^\+fingerprint$p?sha$/i)             { $arg = '+fingerprint_sha1'; } # alais:
    if ($arg =~ /^\+subject$p?altnames?/i)            { $arg = '+altname';          } # alias:
    if ($arg =~ /^\+modulus$p?exponent$p?1$/)         { $arg = '+modulus_exp_1';    } # alias:
    if ($arg =~ /^\+modulus$p?exponent$p?65537$/)     { $arg = '+modulus_exp_65537';} # alias:
    if ($arg =~ /^\+modulus$p?exponent$p?size$/)      { $arg = '+modulus_exp_oldssl'; } # alias:
    if ($arg =~ /^\+pubkey$p?enc(?:ryption)?$/)       { $arg = '+pub_encryption'; } # alias:
    if ($arg =~ /^\+public$p?enc(?:ryption)?$/)       { $arg = '+pub_encryption'; } # alias:
    if ($arg =~ /^\+pubkey$p?enc(?:ryption)?$p?known/){ $arg = '+pub_enc_known';  } # alias:
    if ($arg =~ /^\+public$p?enc(?:ryption)?$p?known/){ $arg = '+pub_enc_known';  } # alias:
    if ($arg =~ /^\+ocsp$p?public$p?hash$/)           { $arg = '+ocsp_public_hash'; }
    if ($arg =~ /^\+ocsp$p?subject$p?hash$/)          { $arg = '+ocsp_subject_hash';}
    if ($arg =~ /^\+sig(key)?$p?enc(?:ryption)?$/)    { $arg = '+sig_encryption'; } # alias:
    if ($arg =~ /^\+sig(key)?$p?enc(?:ryption)?_known/){$arg = '+sig_enc_known';  } # alias:
    if ($arg =~ /^\+server$p?(?:temp)?$p?key$/)       { $arg = '+dh_parameter';   } # alias:
    if ($arg =~ /^\+master$p?secret$/)                { $arg = '+master_secret';  }
    if ($arg =~ /^\+extended$p?master$p?secret$/)     { $arg = '+master_secret';  } # alias:
    if ($arg =~ /^\+reneg/)             { $arg = '+renegotiation';  } # alias:
    if ($arg =~ /^\+resum/)             { $arg = '+resumption';     } # alias:
    if ($arg =~ /^\+reused?$/i)         { $arg = '+resumption';     } # alias:
    if ($arg =~ /^\+commonName$/i)      { $arg = '+cn';             } # alias:
    if ($arg =~ /^\+cert(?:ificate)?$/i){ $arg = '+pem';            } # alias:
    if ($arg =~ /^\+issuer$p?X509$/i)   { $arg = '+issuer';         } # alias:
    if ($arg =~ /^\+subject$p?X509$/i)  { $arg = '+subject';        } # alias:
    if ($arg =~ /^\+sha2sig(?:nature)?$/){$arg = '+sha2signature';  } # alias:
    if ($arg =~ /^\+sni$p?check$/)      { $arg = '+check_sni';      }
    if ($arg =~ /^\+check$p?sni$/)      { $arg = '+check_sni';      }
    if ($arg =~ /^\+ext$p?aia$/i)       { $arg = '+ext_authority';  } # alias: AIA is a common acronym ...
    if ($arg =~ /^\+vulnerabilit(y|ies)/) {$arg= '+vulns';          } # alias:
    if ($arg =~ /^\+hpkp$/i)            { $arg = '+https_pins';     } # alias:
    if ($arg =~ /^\+pkp$p?pins$/i)      { $arg = '+https_pins';     } # alias: +pkp_pins before 19.12.19
    if ($arg =~ /^\+https?${p}body$/i)  { _set_cfg_out('http_body', 1); } # SEE Note:--https_body
    #!#+---------+----------------------+---------------------------+-------------
    #  +---------+----------------------+-----------------------+----------------
    #   command to check     what to do                          what to do next
    #  +---------+----------+-----------------------------------+----------------
    # commands which cannot be combined with others
    if ($arg eq  '+host')   { push(@{$cfg{'do'}}, 'host');                      next; } # special
    if ($arg eq  '+info')   { @{$cfg{'do'}} = (@{$cfg{'cmd-info'}},    'info'); next; }
    if ($arg eq  '+info--v'){ @{$cfg{'do'}} = (@{$cfg{'cmd-info--v'}}, 'info'); next; } # like +info ...
    if ($arg eq  '+quick')  { @{$cfg{'do'}} = (@{$cfg{'cmd-quick'}},  'quick'); next; }
    if ($arg eq  '+check')  { @{$cfg{'do'}} = (@{$cfg{'cmd-check'}},  'check'); next; }
    if ($arg eq  '+vulns')  { @{$cfg{'do'}} = (@{$cfg{'cmd-vulns'}},  'vulns'); next; }
    if ($arg eq '+check_sni'){@{$cfg{'do'}} =  @{$cfg{'cmd-sni--v'}};           next; }
    if ($arg eq '+protocols'){@{$cfg{'do'}} = (@{$cfg{'cmd-prots'}});           next; }
#    if ($arg =~ /^\+next$p?prot(?:ocol)s$/) { @{$cfg{'do'}}= (@{$cfg{'cmd-prots'}}); next; }
    if ($arg =~ /^\+(.*)/)  {   # all  other commands
        my $val = $1;
        _y_ARG("command+ $val");
        next if ($val =~ m/^\+\s*$/);   # ignore empty commands; for CGI mode
        next if ($val =~ m/^\s*$/);     # ignore empty arguments; for CGI mode
        if ($val =~ m/^exec$/i) {       # +exec is special
            $cfg{'exec'} = 1;
            next;
        }
        $val = lc($val);                # be greedy to allow +BEAST, +CRIME, etc.
        push(@{$cfg{'done'}->{'arg_cmds'}}, $val);
        if ($val eq 'sizes')    { push(@{$cfg{'do'}}, @{$cfg{'cmd-sizes'}});   next; }
        if ($val eq 'hsts')     { push(@{$cfg{'do'}}, @{$cfg{'cmd-hsts'}});    next; }
        if ($val eq 'http')     { push(@{$cfg{'do'}}, @{$cfg{'cmd-http'}});    next; }
        if ($val eq 'pfs')      { push(@{$cfg{'do'}}, @{$cfg{'cmd-pfs'}});     next; }
        if ($val eq 'sni')      { push(@{$cfg{'do'}}, @{$cfg{'cmd-sni'}});     next; }
        if ($val eq 'ev')       { push(@{$cfg{'do'}}, @{$cfg{'cmd-ev'}});      next; }
        if ($val eq 'bsi')      { push(@{$cfg{'do'}}, @{$cfg{'cmd-bsi'}});     next; }
        if ($val eq 'beast')    { push(@{$cfg{'do'}}, @{$cfg{'cmd-beast'}});   next; }
        if ($val eq 'crime')    { push(@{$cfg{'do'}}, @{$cfg{'cmd-crime'}});   next; }
        if ($val eq 'drown')    { push(@{$cfg{'do'}}, @{$cfg{'cmd-drown'}});   next; }
        if ($val eq 'freak')    { push(@{$cfg{'do'}}, @{$cfg{'cmd-freak'}});   next; }
        if ($val eq 'lucky13')  { push(@{$cfg{'do'}}, @{$cfg{'cmd-lucky13'}}); next; }
        if ($val eq 'robot')    { push(@{$cfg{'do'}}, @{$cfg{'cmd-robot'}});   next; }
        if ($val eq 'sweet32')  { push(@{$cfg{'do'}}, @{$cfg{'cmd-sweet32'}}); next; }
        if ($val =~ /tr$p?02102/){push(@{$cfg{'do'}}, qw(tr_02102+ tr_02102-));next; }
        if ($val =~ /tr$p?03116/){push(@{$cfg{'do'}}, qw(tr_03116+ tr_03116-));next; }
        if (_is_member($val, \@{$cfg{'commands_usr'}}) == 1) {
            _y_ARG("cmdsusr= $val");
                                  push(@{$cfg{'do'}}, @{$cfg{"cmd-$val"}});    next; }
        if (_is_member($val, \@{$cfg{'commands_notyet'}}) > 0) {
            _warn("044: command not yet implemented '$val' may be ignored");
        }
        if (_is_member($val, \@{$cfg{'commands'}}) == 1) {
            _y_ARG("command= $val");
            push(@{$cfg{'do'}}, lc($val));      # lc() as only lower case keys are allowed since 14.10.13
        } else {
            _warn("049: command '$val' unknown; command ignored");
            _hint($cfg{'hints'}->{'cipher'}) if ($val =~ m/^cipher(?:all|raw)/);
        }
        next;
    }
    #} +---------+----------+------------------------------------+----------------

    if ($arg =~ /(?:ciphers|s_client|version)/) {  # handle openssl commands special
        _warn("041: host-like argument '$arg'; treated as command '+$arg'");
        _hint("please use '+$arg' instead");
        push(@{$cfg{'do'}}, $arg);
        next;
    }

    _y_ARG("host?    $arg");
    if ($typ eq 'HOST')     {   # host argument is the only one parsed here
        if ($arg !~ m/^[a-zA-Z0-9.-]+/){
            # TODO: lazy check for valid hostname, needs to be improved
            _warn("042: invalid host argument '$arg'; ignored");
            next;   # can safely reloop here, as we are at end of while
        }
        #    use previously defined port || default port
        my $default_port = ($cfg{'port'} || $target_defaults[0]->[3]);
        my ($prot, $host, $port, $auth, $path) = _get_target($default_port, $arg);
        if (($host =~ m/^\s*$/) or ($port =~ m/^\s*$/)){
            _warn("043: invalid port argument '$arg'; ignored");
            # TODO: occours i.e with --port=' ' but not with --host=' '
        } else {
            my $idx   = $#{$cfg{'targets'}}; $idx++; # next one
            my $proxy = 0; # TODO: target parameter for proxy not yet supported
            _y_ARG("host=    $host:$port,  auth=$auth,  path=$path");
            _yeast("host: $host:$port") if ($cfg{'trace'} > 0);
            # if perlish programming
            # push(@{$cfg{'targets'}}, [$idx, $prot, $host, $port, $auth, $proxy, $path, $arg]);
            # elsif people expecting object-oriented programming
            osaft::set_target_orig( $idx, $arg);
            osaft::set_target_nr(   $idx, $idx);
            osaft::set_target_prot( $idx, $prot);
            osaft::set_target_host( $idx, $host);
            osaft::set_target_port( $idx, $port);
            osaft::set_target_auth( $idx, $auth);
            osaft::set_target_proxy($idx, $proxy);
            osaft::set_target_path( $idx, $path);
            osaft::set_target_start($idx, 0);
            osaft::set_target_open( $idx, 0);
            osaft::set_target_stop( $idx, 0);
            osaft::set_target_error($idx, 0);
            # endif
        }
    } else {
        _y_ARG("ignore=  $typ $arg");   # should never happen
    }

} # while options and arguments

# exit if ($#{$cfg{'do'}} < 0); # no exit here, as we want some --v output

#| prepare %cfg according options
#| -------------------------------------

local $\ = "\n";

# TODO: use cfg{'targets'} for proxy
if ($cfg{'proxyhost'} ne "" && 0 == $cfg{'proxyport'}) {
    my $q = "'";
    printusage_exit("$q--proxyhost=$cfg{'proxyhost'}$q requires also '--proxyport=NN'");
}
$verbose = $cfg{'verbose'};
$legacy  = $cfg{'legacy'};
if (_is_cfg_do('cipher') and (0 == $#{$cfg{'do'}})) {
    # +cipher does not need DNS and HTTP, may improve perfromance
    # HTTP may also cause errors i.e. for STARTTLS
    $cfg{'use'}->{'https'}  = 0;
    $cfg{'use'}->{'http'}   = 0;
    $cfg{'use'}->{'dns'}    = 0;
    _hint($cfg{'hints'}->{'cipher'});
}

if (_is_cfg_do('list')) {
    # our own command to list ciphers: uses header and TAB as separator
    _set_cfg_out('header', 1)  if ((grep{/--no.?header/} @argv) <= 0);
    $text{'separator'}  = "\t" if ((grep{/--(?:tab|sep(?:arator)?)/} @argv) <= 0); # tab if not set
}
if (_is_cfg_do('pfs'))  { push(@{$cfg{'do'}}, 'cipher_pfsall') if (not _is_cfg_do('cipher_pfsall')); }

if (_is_cfg_do('version') or (_is_cfg_use('mx')))             { $cfg{'need_netdns'}    = 1; }
if (_is_cfg_do('version') or (_is_cfg_do('sts_expired')) > 0) { $cfg{'need_timelocal'} = 1; }

$cfg{'connect_delay'}   =~ s/[^0-9]//g; # simple check for valid values

if (_is_cfg_out('http_body')) { # SEE Note:ignore-out, SEE Note:--https_body
    @{$cfg{'ignore-out'}} = grep{not /https_body/} @{$cfg{'ignore-out'}};
    @{$cfg{'out'}->{'ignore'}} = grep{not /https_body/} @{$cfg{'out'}->{'ignore'}};
}

# SEE Note:Testing, sort
# _dbx "unsorted: @{$cfg{'do'}}";
@{$cfg{'do'}} = sort(@{$cfg{'do'}}) if (0 < _is_argv('(?:--no.?rc)'));
# _dbx "  sorted: @{$cfg{'do'}}";
# $cfg{'do'}} should not contain duplicate commands; SEE Note:Duplicate Commands

if (2 == @{$cfg{'targets'}}) {
    # Exactly one host defined, check if --port was also given after --host .
    # Assuming that  "--port 123 host"  was meant instead  "host --port 123".
    # Latest given port can be found in  $cfg{'port'}. If it differs from the
    # port stored in the list @{$cfg{'targets'}}, redefine port for the host.
    # NOTE: the documentation always recommends to use --port first.
    my $host = osaft::get_target_host(1);
    my $port = osaft::get_target_port(1);
    if (defined $cfg{'port'}) {
        _warn("045: '--port' used with single host argument; using '$host:$cfg{'port'}'");
        osaft::set_target_port(1, $cfg{'port'});
    }
}

# set environment
# NOTE:  openssl  has no option to specify the path to its  configuration
# directoy.  However, some sub command (like req) do have -config option.
# Nevertheless the environment variable is used to specify the path, this
# is independent of the sub command and any platform.
# We set the environment variable only, if  --openssl-cnf  was used which
# then overwrites an already set environment variable.
# This behaviour also honors that  all command-line options are  the last
# resort for all configurations.
# As we do not use  req  or  ca  sub commands (11/2015),  this setting is
# just to avoid noicy warnings from openssl.
$ENV{'OPENSSL_CONF'} = $cfg{'openssl_cnf'}  if (defined $cfg{'openssl_cnf'});  ## no critic qw(Variables::RequireLocalizedPunctuationVars
$ENV{'OPENSSL_FIPS'} = $cfg{'openssl_fips'} if (defined $cfg{'openssl_fips'}); ## no critic qw(Variables::RequireLocalizedPunctuationVars

_yeast_args();          # all arguments parsed; print with --traceARG
_yeast_EXIT("exit=ARGS  - options and arguments done");
_vprintme();

#_init_openssldir();    # called later for performance reasons

usr_pre_exec();

#| call with other libraries
#| -------------------------------------
_y_ARG("exec? $cfg{'exec'}");
# NOTE: this must be the very first action/command
if (0 == $cfg{'exec'})  {
    # As all shared libraries used by Perl modules are already loaded when this
    # program executes, PATH and LD_LIBRARY_PATH need to be set before the tool
    # is called. Hence call myself with proper set environment variables again.
    # NOTE: --exe points to the directoy with the openssl executable
    # while --lib points to the directoy with the libraries
    # Sometimes, when building new libraries or openssl,  the libraries and the
    # executable are located in the same directoy, therefore the directoy given
    # with  --lib will be added to the PATH environment variable too, it should
    # not harm.
    if (($#{$cmd{'path'}} + $#{$cmd{'libs'}}) > -2) { # any of these is used
        _y_CMD("exec command " . join(" ", @{$cfg{'do'}}));
        #ENV{OPENSSL} no need to set again if already done when called
        my $chr = ($ENV{PATH} =~ m/;/) ? ";" : ":"; # set separator character (lazy)
        my $lib = $ENV{$cmd{envlibvar}};            # save existing LD_LIBRARY_PATH
        local $\ = "\n";
        $ENV{PATH} = join($chr, @{$cmd{'path'}}, $ENV{PATH})  if ($#{$cmd{'path'}} >= 0); ## no critic qw(Variables::RequireLocalizedPunctuationVars)
        $ENV{PATH} = join($chr, @{$cmd{'libs'}}, $ENV{PATH})  if ($#{$cmd{'libs'}} >= 0); ## no critic qw(Variables::RequireLocalizedPunctuationVars)
        $ENV{$cmd{envlibvar}}  = join($chr, @{$cmd{'libs'}})  if ($#{$cmd{'libs'}} >= 0); ## no critic qw(Variables::RequireLocalizedPunctuationVars
        $ENV{$cmd{envlibvar}} .= $chr . $lib if ($lib);
        if ($verbose > 0) {
            _yeast("exec: envlibvar=$cmd{envlibvar}");
            _yeast("exec: $cmd{envlibvar}=" . ($ENV{$cmd{envlibvar}} || "")); # ENV may not exist
            _yeast("exec: PATH=$ENV{PATH}");
        }
        _yeast("exec: $0 +exec " . join(" ", @ARGV));
        _yeast("################################################") if (_is_cfg_out('traceARG') or _is_cfg_out('traceCMD'));
        exec $0, '+exec', @ARGV;
    }
}

#| openssl and Net::SSLeay is picky about path names
#| -------------------------------------
foreach my $key (qw(ca_file ca_path ca_crl)) {
    next if not defined $cfg{$key};
    _warn("053: option with spaces '$key'='$cfg{$key}'; may cause connection problems")
        if ($cfg{$key} =~ m/\s/);
}

#| set openssl-specific path for executable and CAs
#| -------------------------------------
_init_openssl();    # if (0 < _need_openssl());

if (0 < $info) {        # +info does not do anything with ciphers
    # main purpose is to avoid missing "*PN" warnings in following _checks_*()
    $cmd{'extciphers'}      = 0;
    $cfg{'use'}->{'alpn'}   = 0;
    $cfg{'use'}->{'npn'}    = 0;
}

#| set proper cipher command depending on --ciphermode option (default: intern)
#| -------------------------------------
# SEE Note:+cipher
if ((0 < _need_cipher()) or (0 < _need_default())) {
    foreach my $mode (@{$cfg{'ciphermodes'}}) {
        if ($mode eq $cfg{'ciphermode'}) {
            # add: cipher_intern, cipher_openssl, cipher_ssleay, cipher_dump
            my $do = 'cipher_' . $mode;
            push(@{$cfg{'do'}}, $do) if (not _is_cfg_do($do)); # only if not yet set
            # TODO: funktioniert nicht sauber
            #$cfg{'legacy'} = 'owasp' if ($do eq 'cipher_intern'); # new default
            #$legacy = $cfg{'legacy'};
        }
    }
    # $cfg{'need_netinfo'} = 0 if ("intern" eq $cfg{'ciphermode'});
    # TODO: need_netinfo disabled until all functionaluty provided by NET::SSLhello
}

_yeast_TIME("inc{");

#| import common and private modules
#| -------------------------------------
_load_modules() if (0 == $::osaft_standalone);

_yeast_TIME("inc}");
_yeast_TIME("mod{");
_y_CMD("check $cfg{'me'} internals ...");

my $do_checks = _is_cfg_do('cipher_openssl') + _is_cfg_do('cipher_ssleay');

#| check for required module versions
#| -------------------------------------
_check_modules()    if (0 < $do_checks);
    # --ciphermode=intern does not need these checks
    # check done after loading our own modules because they may require
    # other common Perl modules too; we may have detailed warnings before

#| check for required functionality
#| -------------------------------------
_check_functions()  if (0 < $do_checks + _is_cfg_do('cipher') + _need_checkprot());
    # more detailed checks on version numbers with proper warning messages

#| check for proper openssl support
#| -------------------------------------
_check_openssl()    if (0 < $do_checks);

#_dbx "do: @{$cfg{'do'}}";
#_dbx "need-default: @{$cfg{'need-default'}}";
#_dbx "_check_ssl_methods(): " . _need_cipher() . " : " . _need_default() . " : ver? "._is_cfg_do('version');

#| check for supported SSL versions
#| -------------------------------------
_check_ssl_methods() if (0 < _need_cipher() + _need_default() + _is_cfg_do('version'));
    # initialise $cfg{'version'} and all $cfg{ssl}
    # function is oversized for --ciphermode=intern but does the work

_yeast_TIME("mod}");
_yeast_TIME("ini{");

#| set additional defaults if missing
#| -------------------------------------
_set_cfg_out('header', 1) if(0 => $verbose);# verbose uses headers
_set_cfg_out('header', 1) if(0 => grep{/\+(check|info|quick|cipher)$/} @argv); # see --header
_set_cfg_out('header', 0) if(0 => grep{/--no.?header/} @argv);    # command-line option overwrites defaults above
#cfg{'sni_name'}    = $host;    # see below: loop targets
$sniname            = $cfg{'sni_name'}; # safe setting; may be undef
if (not _is_cfg_use('http')) {          # was explicitly set with --no-http 'cause default is 1
    # STS makes no sence without http
    _warn("064: STS $text{'na_http'}") if(0 => (grep{/hsts/} @{$cfg{'do'}})); # check for any hsts*
}
$quick = 1 if ($cfg{'legacy'} eq 'testsslserver');
if (1 == $quick) {
    _set_cfg_out('enabled', 1);
    $cfg{'label'}   = 'short';
}
$text{'separator'}  = "\t"    if ($cfg{'legacy'} eq "quick");

#| set defaults for Net::SSLinfo
#| -------------------------------------
{
    #$IO::Socket::SSL::DEBUG         = $cfg{'trace'} if ($cfg{'trace'} > 0);
    no warnings qw(once); ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
        # avoid: Name "Net::SSLinfo::trace" used only once: possible typo at ...
    if (1 > $cfg{'traceME'}) {
        $Net::SSLinfo::trace        = $cfg{'trace'} if (0 < $cfg{'trace'});
    }
    $Net::SSLinfo::verbose          = $cfg{'verbose'};
    $Net::SSLinfo::linux_debug      = $cfg{'linux_debug'};
    $Net::SSLinfo::use_openssl      = $cmd{'extopenssl'};
    $Net::SSLinfo::use_sclient      = $cmd{'extsclient'};
    $Net::SSLinfo::openssl          = $cmd{'openssl'};
    $Net::SSLinfo::use_SNI          = $cfg{'use'}->{'sni'};
    $Net::SSLinfo::use_alpn         = $cfg{'use'}->{'alpn'};
    $Net::SSLinfo::use_npn          = $cfg{'use'}->{'npn'};
    $Net::SSLinfo::protos_alpn      = (join(",", @{$cfg{'protos_alpn'}}));
    $Net::SSLinfo::protos_npn       = (join(",", @{$cfg{'protos_npn'}}));
    $Net::SSLinfo::use_extdebug     = $cfg{'use'}->{'extdebug'};
    $Net::SSLinfo::use_reconnect    = $cfg{'use'}->{'reconnect'};
    $Net::SSLinfo::socket_reuse     = $cfg{'socket_reuse'};
    $Net::SSLinfo::slowly           = $cfg{'slowly'};
    $Net::SSLinfo::sclient_opt      = $cfg{'sclient_opt'};
    $Net::SSLinfo::timeout_sec      = $cfg{'timeout'};
    $Net::SSLinfo::no_compression   = $cfg{'use'}->{'no_comp'};
    $Net::SSLinfo::no_cert          = ((_is_cfg_use('cert')) ? 0 : 1);
    $Net::SSLinfo::no_cert_txt      = $cfg{'no_cert_txt'};
    $Net::SSLinfo::ignore_case      = $cfg{'ignorecase'};
    $Net::SSLinfo::ca_crl           = $cfg{'ca_crl'};
    $Net::SSLinfo::ca_file          = $cfg{'ca_file'};
    $Net::SSLinfo::ca_path          = $cfg{'ca_path'};
    $Net::SSLinfo::ca_depth         = $cfg{'ca_depth'};
    $Net::SSLinfo::ignore_handshake = $cfg{'sslerror'}->{'ignore_handshake'};
    $Net::SSLinfo::starttls         = $cfg{'starttls'};
    $Net::SSLinfo::proxyhost        = $cfg{'proxyhost'};
    $Net::SSLinfo::proxyport        = $cfg{'proxyport'};
    $Net::SSLinfo::proxypass        = $cfg{'proxypass'};
    $Net::SSLinfo::proxyuser        = $cfg{'proxyuser'};
    $Net::SSLinfo::file_sclient     = $cfg{'data'}->{'file_sclient'};
    $Net::SSLinfo::file_pem         = $cfg{'data'}->{'file_pem'};
    $Net::SSLinfo::method           = "";
    # following are just defaults, will be redefined for each target below
    $Net::SSLinfo::sni_name         = $cfg{'sni_name'}; # NOTE: may be undef
    $Net::SSLinfo::use_http         = $cfg{'use'}->{'http'};
    $Net::SSLinfo::use_https        = $cfg{'use'}->{'https'};
    $Net::SSLinfo::target_url       = "/";
    $Net::SSLinfo::user_agent       = $cfg{'use'}->{'user_agent'};
}
if ('cipher' eq join("", @{$cfg{'do'}})) {
    $Net::SSLinfo::use_http         = 0; # if only +cipher given don't use http 'cause it may cause erros
}

#| set defaults for Net::SSLhello
#| -------------------------------------
if (defined $Net::SSLhello::VERSION) {
    no warnings qw(once); ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
        # avoid: Name "Net::SSLinfo::trace" used only once: possible typo at ...
    if (1 > $cfg{'traceME'}) {
        $Net::SSLhello::trace       = $cfg{'trace'};
    }
    $Net::SSLhello::traceTIME       = $cfg{'out'}->{'traceTIME'};
    $Net::SSLhello::experimental    = $cfg{'use'}->{'experimental'};
    $Net::SSLhello::usemx           = $cfg{'use'}->{'mx'};
    $Net::SSLhello::usesni          = $cfg{'use'}->{'sni'};
    $Net::SSLhello::sni_name        = $cfg{'sni_name'};
    $Net::SSLhello::connect_delay   = $cfg{'connect_delay'};
    $Net::SSLhello::starttls        = (($cfg{'starttls'} eq "") ? 0 : 1);
    $Net::SSLhello::starttlsType    = $cfg{'starttls'};
    $Net::SSLhello::starttlsDelay   = $cfg{'starttls_delay'};
    $Net::SSLhello::slowServerDelay = $cfg{'slow_server_delay'};
    $Net::SSLhello::timeout         = $cfg{'sslhello'}->{'timeout'};
    $Net::SSLhello::retry           = $cfg{'sslhello'}->{'retry'};
    $Net::SSLhello::max_ciphers     = $cfg{'sslhello'}->{'maxciphers'};
    $Net::SSLhello::use_signature_alg = $cfg{'sslhello'}->{'usesignaturealg'};
    $Net::SSLhello::usereneg        = $cfg{'sslhello'}->{'usereneg'};
    $Net::SSLhello::useecc          = $cfg{'sslhello'}->{'useecc'};
    $Net::SSLhello::useecpoint      = $cfg{'sslhello'}->{'useecpoint'};
    $Net::SSLhello::double_reneg    = $cfg{'sslhello'}->{'double_reneg'};
    $Net::SSLhello::noDataEqNoCipher= $cfg{'sslhello'}->{'nodatanocipher'};
    $Net::SSLhello::proxyhost       = $cfg{'proxyhost'};
    $Net::SSLhello::proxyport       = $cfg{'proxyport'};
    $Net::SSLhello::cipherrange     = $cfg{'cipherrange'};  # not really necessary, see below
    $Net::SSLhello::ciphercurves    = (join(":", @{$cfg{'ciphercurves'}}));
    $Net::SSLhello::protos_alpn     = (join(",", @{$cfg{'protos_alpn'}}));
    $Net::SSLhello::protos_npn      = (join(",", @{$cfg{'protos_npn'}}));
    # TODO: need to unify variables
    @Net::SSLhello::starttlsPhaseArray  = @{$cfg{'starttls_phase'}};
    # add 'starttls_error' array elements according Net::SSLhello's internal
    # representation
    push(@Net::SSLhello::starttlsPhaseArray, @{$cfg{'starttls_error'}}[1..3]);
}
$cfg{'trace'} = 1 if (0 < $cfg{'traceME'});
$cfg{'trace'} = 0 if (0 > $cfg{'traceME'});

if ($cfg{'label'} eq 'short') {     # reconfigure texts
    foreach my $key (keys %data)   { $data{$key}  ->{'txt'} = $shorttexts{$key}; }
    foreach my $key (keys %checks) { $checks{$key}->{'txt'} = $shorttexts{$key}; }
}

_initchecks_val();  # initialise default values in %checks again depending on given options

_yeast_TIME("ini}");

#| first all commands which do not make a connection
#| -------------------------------------
_y_CMD("no connection commands ...");
_trace(" --test= $test");
# all --test-cipher* are special (need other data like %cfg or alike)
$test =~ s/^(?:[+]|--)(test.*)/--$1/;   # SEE Note:--test-*
if ($test =~ m/testciphers?list/)   { _yeast_test($test);   exit 0; }
if ($test =~ m/testciphers?regex/)  { test_cipher_regex();  exit 0; }
if ($test =~ m/^--testcipher/)      { OSaft::Ciphers::show($test); exit 0; }
if ($test !~ m/^\s*$/)              { _yeast_test($test);   exit 0; }
# interanl information commands
if (_is_cfg_do('list'))             { printciphers();       exit 0; }
if (_is_cfg_do('ciphers'))          { printciphers();       exit 0; }
if (_is_cfg_do('version'))          { printversion();       exit 0; }
if (_is_cfg_do('libversion'))       { printopenssl();       exit 0; }
if (_is_cfg_do('quit'))             { printquit();          exit 0; }

if (($cfg{'trace'} + $cfg{'verbose'}) >  0) {   # +info command is special with --v
    @{$cfg{'do'}} = @{$cfg{'cmd-info--v'}} if (@{$cfg{'do'}} eq @{$cfg{'cmd-info'}});
}
_y_CMD("dbx init ...");
_yeast_init();  # call in printquit() also!

if (0 > $#{$cfg{'do'}}) {
    _yeast_exit();
    printusage_exit("no command given");
}

_y_ARG("commands=@{$cfg{'do'}}");

usr_pre_cipher();

#| get list of ciphers available for tests
#| -------------------------------------
if (_is_cfg_do('cipher_openssl') or _is_cfg_do('cipher_ssleay')) {
    if ((_need_cipher() > 0) or (_need_default() > 0)) {
        _yeast_TIME("get{");
        _y_CMD("get cipher list ...");
        @{$cfg{'ciphers'}} = _get_cipherlist_openssl();
        _yeast_TIME("get}");
    } # _need_cipher or _need_default
}

#| SEE Note:Duplicate Commands
#| -------------------------------------
# my %unique = map{$_, 42} @{$cfg{'do'}};   # perlish way cannot be used,
# @{$cfg{'do'}} = keys %unique;             # because sequence is user-defined
@{$cfg{'do'}} = do { my %seen; grep { !$seen{$_}++ } @{$cfg{'do'}} };

_yeast_EXIT("exit=MAIN  - start");
_yeast_ciphers_list();
usr_pre_main();

#| do the work for all targets
#| -------------------------------------

# defensive, user-friendly programming
  # could do these checks earlier (after setting defaults), but we want
  # to keep all checks together for better maintenace
printusage_exit("no target hosts given") if ($#{$cfg{'targets'}} <= 0); # does not make any sense
if (_is_cfg_do('cipher_openssl') or _is_cfg_do('cipher_ssleay')) {
    if ($#{$cfg{'done'}->{'arg_cmds'}} > 0) {
        printusage_exit("additional commands in conjunction with '+cipher' are not supported; '+" . join(" +", @{$cfg{'done'}->{'arg_cmds'}}) ."'");
    }
}
if ((0 < $info)  and ($#{$cfg{'done'}->{'arg_cmds'}} >= 0)) {
    # +info does not allow additional commands
    # see printchecks() call below
    _warn("047: additional commands in conjunction with '+info' are not supported; '+" . join(" +", @{$cfg{'done'}->{'arg_cmds'}}) . "' ignored");
}
if ((0 < $check) and ($#{$cfg{'done'}->{'arg_cmds'}} >= 0)) {
    # +check does not allow additional commands of type "info"
    foreach my $key (@{$cfg{'done'}->{'arg_cmds'}}) {
        if (_is_member( $key, \@{$cfg{'cmd-info'}})) {
            _warn("048: additional commands in conjunction with '+check' are not supported; +'$key' ignored");
        }
    }
}

#| perform commands for all hosts
#| -------------------------------------

usr_pre_host();

my $fail = 0;
# check if output disabled for given/used commands, SEE Note:ignore-out
foreach my $cmd (@{$cfg{'ignore-out'}}) {
    $fail++ if (_is_cfg_do($cmd));
}
if ($fail > 0) {
    _warn("066: $fail data and check outputs are disbaled due to use of '--no-out':");
    if (0 < $cfg{'verbose'}) {
        _warn("067:  disabled:  +" . join(" +", @{$cfg{'ignore-out'}}));
        _warn("068:  given:  +"    . join(" +", @{$cfg{'do'}}));
    } else {
        _hint("use '--v' for more information");
    }
    _hint("do not use '--ignore-out=*' or '--no-out=*'");
        # It's not simple to identify the given command, as $cfg{'do'} may
        # contain a list of commands. So the hint is a bit vage.
        # _dbx "@{$cfg{'done'}->{'arg_cmds'}}"
} else {
    # print warnings and hints if necessary
    foreach my $cmd (@{$cfg{'do'}}) {
        if (_is_member($cmd, \@{$cfg{'commands_hint'}})) {
            _hint("+$cmd : please see '$cfg{'me'} --help=CHECKS' for more information");
        }
    }
}

_y_CMD("hosts ...");
_yeast_TIME("hosts{");

# run the appropriate SSL tests for each host (ugly code down here):
$sniname  = $cfg{'sni_name'};           # safe value;  NOTE: may be undef!
my $idx   = 0;
foreach my $target (@{$cfg{'targets'}}) { # loop targets (hosts)
    next if (0 == @{$target}[0]);       # first entry contains default settings
    $idx++;
    $host = osaft::get_target_host($idx);
    $port = osaft::get_target_port($idx);
    $cfg{'port'}    = $port;
    $cfg{'host'}    = $host;
    next if _yeast_NEXT("exit=HOST0 - host $host:$port");
    _y_CMD("host " . ($host||"") . ":$port {");
    _trace(" host   = $host {\n");
    # SNI must be set foreach host, but it's always the same name!
    if (_is_cfg_use('sni')) {
        if (defined $sniname) {
            if ($host ne $cfg{'sni_name'}) {
                _warn("069: hostname not equal SNI name; checks are done with '$host'");
            }
            $Net::SSLinfo::sni_name = $cfg{'sni_name'};
            $Net::SSLhello::sni_name= $cfg{'sni_name'};
        } else {
            $cfg{'sni_name'}        = $host;
            $Net::SSLinfo::sni_name = $host;
            $Net::SSLhello::sni_name= $host;
        }
    }
    $Net::SSLinfo::use_https    = $cfg{'use'}->{'https'}; # reset
    $Net::SSLinfo::use_http     = $cfg{'use'}->{'http'};  # reset
    $Net::SSLinfo::target_url   = osaft::get_target_path($idx);
    $Net::SSLinfo::target_url   =~ s:^\s*$:/:;      # set to / if empty
    _resetchecks();
    print_header(_get_text('out_target', "$host:$port"), "", "", $cfg{'out'}->{'header'});

    _yeast_TIME("DNS{");

    # prepare DNS stuff
    #  gethostbyname() and gethostbyaddr() set $? on error, needs to be reset!
    my $rhost = "";
    $fail = "";     # reusing variable
    if ("" ne $cfg{'proxyhost'}) {
        # if a proxy is used, DNS might not work at all, or be done by the
        # proxy (which even may return other results than the local client)
        # so we set corresponding values to a warning
        $fail = _get_text('disabled', "--proxyhost=$cfg{'proxyhost'}");
        $cfg{'rhost'}   = $fail;
        $cfg{'DNS'}     = $fail;
        $cfg{'IP'}      = $fail;
        $cfg{'ip'}      = $fail;
    } else {
        $fail  = '<<gethostbyaddr() failed>>';
        $cfg{'ip'}      = gethostbyname($host); # primary IP as identified by given hostname
        if (not defined $cfg{'ip'}) {
            _warn("201: Can't get IP for host '$host'; host ignored");
            _y_CMD("host}");
            next;   # otherwise all following fails
        }
        # gethostbyaddr() is strange: returns $?==0 but an error message in $!
        # hence just checking $? is not reliable, we do it additionally.
        # If gethostbyaddr()  fails we use Perl's  `or'  to assign our default
        # text.  This may happen when there are problems with the local name
        # resolution.
        # When gethostbyaddr() fails, the connection to the target most likely
        # fails also, which produces more Perl warnings later.
        _y_CMD("test IP ...");
        $cfg{'IP'}          = join(".", unpack("W4", $cfg{'ip'}));
        if (_is_cfg_use('dns')) {   # following settings only with --dns
            _y_CMD("test DNS (disable with --no-dns) ...");
           _yeast_TIME("test DNS{");
           local $? = 0; local $! = undef;
           ($cfg{'rhost'}   = gethostbyaddr($cfg{'ip'}, AF_INET)) or $cfg{'rhost'} = $fail;
            $cfg{'rhost'}   = $fail if ($? != 0);
            my ($fqdn, $aliases, $addrtype, $length, @ips) = gethostbyname($host);
            my $i = 0;
            #dbx printf "@ips = %s\n", join(" - ", @ips);
            foreach my $ip (@ips) {
                local $? = 0; local $! = undef;
                # TODO: $rhost  = gethostbyaddr($ipv6, AF_INET6));
               ($rhost  = gethostbyaddr($ip, AF_INET)) or $rhost = $fail;
                $rhost  = $fail if ($? != 0);
                $cfg{'DNS'} .= join(".", unpack("W4", $cfg{'ip'})) . " " . $rhost . "; ";
                #dbx printf "[%s] = %s\t%s\n", $i, join(".",unpack("W4",$ip)), $rhost;
            }
            if ($cfg{'rhost'} =~ m/gethostbyaddr/) {
                _warn("202: Can't do DNS reverse lookup: for '$host': $fail; ignored");
                _hint("use '--no-dns' to disable this check");
            }
           _yeast_TIME("test DNS}");
        }
    }
    # print DNS stuff
    if (_is_cfg_do('host') or (($info + $check + $cmdsni) > 0)) {
        _y_CMD("+info || +check || +sni*");
        if ($legacy =~ /(compact|full|owasp|simple)/) {
            print_ruler();
            print_line($legacy, $host, $port, 'host_name', $text{'host_name'}, $host);
            print_line($legacy, $host, $port, 'host_IP',   $text{'host_IP'}, $cfg{'IP'});
            if (_is_cfg_use('dns')) {
                print_line($legacy, $host, $port, 'host_rhost', $text{'host_rhost'}, $cfg{'rhost'});
                print_line($legacy, $host, $port, 'host_DNS',   $text{'host_DNS'},   $cfg{'DNS'});
            }
            print_ruler();
        }
    }

    _yeast_TIME("DNS}");
    next if _yeast_NEXT("exit=HOST1 - host DNS");

    # Quick check if the target is available
    _y_CMD("test connect ...");
    _yeast_TIME("test connect{");# SEE Note:Connection Test
    my $connect_ssl = 1;
    _trace("sni_name= " . ($cfg{'sni_name'} || $STR{UNDEF}));
    if (not _can_connect($host, $port, $cfg{'sni_name'}, $cfg{'timeout'}, $connect_ssl)) {
        next if ($cfg{'sslerror'}->{'ignore_no_conn'} <= 0);
    }
    $connect_ssl = 0;
    if (not _can_connect($host, 80   , $cfg{'sni_name'}, $cfg{'timeout'}, $connect_ssl)) {
        $Net::SSLinfo::use_http = 0;
        _warn("325: HTTP disabled, using '--no-http'");
    }
    _yeast_TIME("test connect}");

    if (_is_cfg_do('cipher_dh')) {
        if (0 >= $cmd{'extopenssl'}) {   # TODO: as long as openssl necessary
            _warn("408: OpenSSL disabled using '--no-openssl', can't check DH parameters; target ignored");
            next;
        }
    }

    if (_is_cfg_do('cipher_intern') or _is_cfg_do('cipher_dump')) { # implies _need_cipher()
        _y_CMD("+cipher");
        _yeast_TIME("ciphermode=intern{");
        Net::SSLhello::printParameters() if ($cfg{'trace'} > 1);
        _warn("209: No SSL versions for '+cipher' available") if ($#{$cfg{'version'}} < 0);
            # above warning is most likely a programming error herein
        $cipher_results = {};           # new list for every host (array of arrays)
        $cipher_results = ciphers_scan_raw($host, $port);   # print ciphers also
        $checks{'cnt_totals'}->{val} = scalar %$cipher_results; # FIXME: this is the number of enabled ciphers!
        foreach my $ssl (@{$cfg{'version'}}) {  # all requested protocol versions
            $checks{'cnt_totals'}->{val} += osaft::get_ciphers_range($ssl, $cfg{'cipherrange'});
        }
        # SEE Note:+cipherall
        my $total   = $checks{'cnt_totals'}->{val};
        checkciphers($host, $port, $cipher_results);# necessary to compute 'out_summary'
        printciphersummary($legacy, $host, $port, $total) if (_is_cfg_do('cipher'));
        _yeast_TIME("ciphermode=intern}");
        next if (_is_cfg_do('cipher') and (0 == $quick));
    } # ciphermode=intern
    next if _yeast_NEXT("exit=HOST2 - host ciphermode=intern");

    if (_is_cfg_do('fallback_protocol')) {
        _y_CMD("protocol fallback support ...");
        # following similar to ciphers_scan_prot();
        my ($version, $supported, $dh);
        if (0 == $cmd{'extciphers'}) {
            ($version, $supported)      = _usesocket( '', $host, $port, '');
        } else { # force openssl
            ($version, $supported, $dh) = _useopenssl('', $host, $port, '');
        }
        $prot{'fallback'}->{val} = $version;
        _trace("fallback: $version $supported");
    }

    if ((_need_default() > 0) or ($check > 0)) {
        # SEE Note:+cipherall
        _y_CMD("get default ...");
        _yeast_TIME("need_default{");
        $cfg{'done'}->{'ssl_failed'} = 0;   # SEE Note:--ssl-error
        foreach my $ssl (@{$cfg{'version'}}) {  # all requested protocol versions
            next if not defined $prot{$ssl}->{opt};
            my $anf = time();
            # no need to check for "valid" $ssl (like DTLSfamily), done by _get_default()
            $prot{$ssl}->{'cipher_strong'}  = _get_default($ssl, $host, $port, 'strong');
            $prot{$ssl}->{'cipher_weak'}    = _get_default($ssl, $host, $port, 'weak');
            $prot{$ssl}->{'default'}        = _get_default($ssl, $host, $port, 'default');
            # FIXME: there are 3 connections above, but only one is counted
            last if (_is_ssl_error($anf, time(), "$ssl: abort getting preferred cipher") > 0);
            my $cipher  = $prot{$ssl}->{'cipher_strong'};
            $prot{$ssl}->{'cipher_pfs'}     = $cipher if ("" ne _is_ssl_pfs($ssl, $cipher));
            ##if (_is_cfg_do('cipher_selected') and ($#{$cfg{'do'}} == 0)) {
            ##    # +cipher_selected command given, but no other commands; ready
            ##    print_cipherpreferred($legacy, $ssl, $host, $port); # need to check if $ssl available first
            ##    next HOSTS; # TODO: foreach-loop for targets misses label
            ##}
        }
        checkpreferred($host, $port);
        _yeast_TIME("need_default}");
    }
    next if _yeast_NEXT("exit=HOST3 - host ciphers start");

    if (_is_cfg_do('cipher_default') and (0 < $#{$cfg{'do'}})) {
        # don't print if not a single command, because +check or +cipher do it
        # in printptotocols() anyway
        printcipherpreferred($legacy, $host, $port);
        goto CLOSE_SSL; # next HOSTS
    }

    if (_is_cfg_do('cipher_openssl') or _is_cfg_do('cipher_ssleay')) {  # implies _need_cipher()
        _yeast_TIME("need_cipher{");
        _y_CMD("  need_cipher ...");
        _y_CMD("  use socket ...")  if (0 == $cmd{'extciphers'});
        _y_CMD("  use openssl ...") if (1 == $cmd{'extciphers'});
        $cipher_results = {};           # new list for every host
        $cipher_results = ciphers_scan($host, $port);
        $checks{'cnt_totals'}->{val} = scalar %$cipher_results;
        checkciphers($host, $port, $cipher_results); # necessary to compute 'out_summary'
        _yeast_TIME("need_cipher}");
     }
    next if _yeast_NEXT("exit=HOST4 - host get ciphers");

    # check ciphers manually (required for +check also)
    if ((0 < $check or _is_cfg_do('cipher')) and (_is_cfg_do('cipher_openssl') or _is_cfg_do('cipher_ssleay'))) {
        _y_CMD("+cipher");
        _yeast_TIME("ciphermode=ssleay{");
        _trace(" ciphers= @{$cfg{'ciphers'}}");
        # TODO: for legacy==testsslserver we need a summary line like:
        #      Supported versions: SSLv3 TLSv1.0
        my $_printtitle = 0;    # count title lines; 0 = no ciphers checked
        foreach my $ssl (@{$cfg{'version'}}) {
            $_printtitle++;
            if (($legacy ne "sslscan") or ($_printtitle <= 1)) {
                # format of sslscan not yet supported correctly
                my $header = $cfg{'out'}->{'header'};
                if (_is_cfg_out('header') or (scalar @{$cfg{'version'}}) > 1) {
                    # need a header when more than one protocol is checked
                    $header = 1;
                }
                print_title($legacy, $ssl, $host, $port, $header);
            }
            # TODO: need to simplify above conditions
            printciphercheck($legacy, $ssl, $host, $port,
                ($legacy eq "sslscan")?($_printtitle):0, $cipher_results);
        }
        if ($legacy eq 'sslscan') {
            my $ssl = ${$cfg{'version'}}[4];
            print_cipherpreferred($legacy, $ssl, $host, $port);
            # TODO: there is only one $data{'cipher_selected'}
            #foreach my $ssl (@{$cfg{'version'}}) {
            #    print_cipherpreferred($legacy, $ssl, $host, $port);
            #}
        }
        if ($_printtitle > 0) { # if we checked for ciphers
            # SEE Note:+cipherall
            printciphersummary($legacy, $host, $port, scalar %$cipher_results);
        }
        _yeast_TIME("ciphermode=ssleay}");
    } # cipher
    next if _yeast_NEXT("exit=HOST5 - host ciphers end");

    goto CLOSE_SSL if (_is_cfg_do('cipher') and ($quick == 0));

    usr_pre_info();
    _yeast_TIME("SNI{");
    _get_data0($host, $port);   # uses Net::SSLinfo::do_ssl_open() and ::do_ssl_close()
    _yeast_TIME("SNI}");

    usr_pre_open();

    # TODO dirty hack, check with dh256.tlsfun.de
    # checking for DH parameters does not need a default connection
    if (_is_cfg_do('cipher_dh')) {
        _y_CMD("+cipher-dh");
        _yeast_TIME("cipher-dh{");
        printciphers_dh($legacy, $host, $port);
        _yeast_TIME("cipher-dh}");
        goto CLOSE_SSL;
    }

    # SEE Note:Connection Test
    if (0 >= $cfg{'sslerror'}->{'ignore_no_conn'}) {
        # use Net::SSLinfo::do_ssl_open() instead of IO::Socket::INET->new()
        # to check the connection (hostname and port)
        # this is the first call to Net::SSLinfo::do_ssl_open()
        # NOTE: the previous test (see can_connect above) should be sufficient
        _y_CMD("test connection  (disable with  --ignore-no-conn) ...");
        _yeast_TIME("test connection{");
        if (not defined Net::SSLinfo::do_ssl_open(
                            $host, $port,
                            (join(" ", @{$cfg{'version'}})),
                             join(" ", @{$cfg{'ciphers'}}))
           ) {
            my @errtxt = Net::SSLinfo::errors($host, $port);
            if (0 < $#errtxt) {
                _v_print(join("\n".$STR{ERROR}, @errtxt));
                _warn("205: Can't make a connection to '$host:$port'; target ignored");
                _hint("use '--v' to show more information");
                _hint("use '--socket-reuse' it may help in some cases");
                _hint("use '--ignore-no-conn' to disable this check");
                _hint("do not use '--no-ignore-handshake'") if ($cfg{'sslerror'}->{'ignore_handshake'} <= 0);
                _yeast_TIME("  test connection} failed");
                goto CLOSE_SSL;
            }
        }
        _yeast_TIME("  connection open.");
        my @errtxt = Net::SSLinfo::errors($host, $port);
        if (0 < (grep{/\*\*ERROR/} @errtxt)) {
            _warn("207: Errors occoured when using '$cmd{'openssl'}', some results may be wrong; errors ignored");
            _hint("use '--v' to show more information");
            # do not print @errtxt because of multiple lines not in standard format
        }
        _yeast_TIME("test connection}");
    }

    usr_pre_cmds();
    _yeast_TIME("prepare{");

    if (_is_cfg_do('dump')) {
        _y_CMD("+dump");
        if (1 < $cfg{'trace'}) {   # requires: --v --trace --trace
            _trace(' ############################################################ %SSLinfo');
            print Net::SSLinfo::datadump();
        }
        printdump($legacy, $host, $port);
    }

    usr_pre_data();

    # following sequence important!
    # if conditions are just to improve performance
    # Net::SSLinfo::do_ssl_open() will be call here if --ignore_no_conn was given
    _y_CMD("get checks ...");
    if (_need_checkalpn() > 0) {
        _y_CMD("  need_pn ...");
        checkalpn( $host, $port);   _yeast_TIME("  checkalpn.");
    }
        checkdates($host, $port);   _yeast_TIME("  checkdates.");
    if (_need_checkhttp() > 0) {
        checkhttp( $host, $port);   _yeast_TIME("  checkhttp.");
    }
        checksni(  $host, $port);   _yeast_TIME("  checksni.");
        checksizes($host, $port);   _yeast_TIME("  checksizes.");
    if ($info == 0) {   # not for +info
        checkdv(   $host, $port);   _yeast_TIME("  checkdv.");
    }
    if (_need_checkprot() > 0) {
        checkprot( $host, $port);   _yeast_TIME("  checkprot.");
    }
    if (_need_checkdest() > 0) {
        checkdest( $host, $port);   _yeast_TIME("  checkdest.");
    }
    if (_need_checkbleed() > 0) {
        _y_CMD("  need_checkbleed ...");
        checkbleed($host, $port);   _yeast_TIME("  checkbleed.");
    }
    if (_need_checkssl() > 0) {
        _y_CMD("  need_checkssl ...");
        checkssl(  $host, $port);   _yeast_TIME("  checkssl.");
    }
    if (_is_cfg_do('sstp')) {   # only check if needed
        checksstp( $host, $port);   _yeast_TIME("  checksstp.");
    }

    _yeast_TIME("prepare}");
    next if _yeast_NEXT("exit=HOST6 - host prepare");
    usr_pre_print();

    if (0 < $check) {
        _y_CMD("+check");
        _warn("208: No openssl, some checks are missing") if (($^O =~ m/MSWin32/) and ($cmd{'extopenssl'} == 0));
    }

    # for debugging only
    if (_is_cfg_do('s_client')) {
        _y_CMD("+s_client"); print "#{\n", Net::SSLinfo::s_client($host, $port), "\n#}";
    }
    _y_CMD("do=".join(" ",@{$cfg{'do'}}));

    # print all required data and checks
    # NOTE: if key (aka given command) exists in %checks and %data it will be printed for both
    _yeast_TIME("info{");
    printdata(  $legacy, $host, $port) if (1 > $check); # not for +check
    _yeast_TIME("info}");
    _yeast_TIME("checks{");
    printchecks($legacy, $host, $port) if (1 > $info); # not for +info
    _yeast_TIME("checks}");

    if (_is_cfg_out('score')) { # no output for +info also
        _y_CMD("scores");
        _yeast_TIME("score{");
        printscores($legacy, $host, $port);
        _yeast_TIME("score}");
    }

    CLOSE_SSL:
    _y_CMD("host " . ($host||"") . ":$port }");
    {
      no warnings qw(once); ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
      if (defined $Net::SSLinfo::socket) { # check to avoid: WARNING undefined Net::SSLinfo::socket
        Net::SSLinfo::do_ssl_close($host, $port);
      }
    }
    _trace(" host   = $host }\n");
    $cfg{'done'}->{'hosts'}++;

    usr_pre_next();
    next if _yeast_NEXT("exit=HOST8 - host end");
    _yeast_EXIT("exit=HOST9 - perform host end");

} # foreach host

_yeast_TIME("hosts}");

usr_pre_exit();
_yeast_exit();
_yeast_EXIT("exit=END   - end");# for symetric reason, rather useless here

$cfg{'use'}->{'exitcode'} += $cfg{'out'}->{'exitcode'}; # --exitcode-v
exit 0 if (not _is_cfg_use('exitcode'));

my $status = check_exitcode();
if (0 < $status) {
    # print EXIT message unless switched off with --exitcode-quiet
    print "# EXIT $status" if (not _isc_fg_out('exitcode_quiet'));
}
exit $status;

# no  __END__   here, because it causes problems in generated gen_standalone.sh
# no  __DATA__  here, because ...

# public user documentation, please see  OSaft/Doc/*.txt  and  OSaft/Doc/Data.pm

# following annotations are avalable by using:  perldoc o-saft.pl

=pod

=encoding utf8


=head1 Documentation

This is the documentation for development!

For user documentation please use:

    o-saft.pl --help
    o-saft.pl --help=HELP

=head3 Documentation General

Documentation distinguishes between:

=over

=item L<Public User Documentation>

=item L<Internal Developer Documentation>

=item L<Internal Code Documentation>

=item L<Internal Makefile Documentation>

=back

=head3 Public User Documentation

All public user documentation is available in plain text format. It can be
accessed programmatically with the  --help  option and various variants of
it. All plain texts are designed for human readability and simple editing,
see:

    ./OSaft/Doc/*.txt

For details on documentation texts (format, syntax, etc.) from files, see:

    ./OSaft/Doc/Data.pm
    ./o-saft-man.pm

=head3 Internal Developer Documentation

Documentation for development such as tracing, debugging, testing and make
can be found in:

    OSaft/Doc/devel.txt
    o-saft.pl --help=developer

=head3 Internal Code Documentation

All comments/documentation/explanation of code details is written close to
the corresponding code lines.  Note that these comments describe *why* the
code is written in some way  (means the logic of the code), and not *what*
the code does (which is most likely obvious).
Some special syntax for comment lines are used, see  "Comments" section in

    OSaft/Doc/coding.txt
    o-saft.pl --help=Program.Code

Additional documentation in POD format  is avaialble at end of many files,
see for examples:

    perldoc o-saft.pl
    perldoc o-saft-man.pm

These comments are called  "Annotations"  and referred to using  a special
syntax, see following chapter  L<Annotations, Internal Notes> .
These Annotations are used  for descriptions needed at  multiple places in
the code or even multiple files.


=head3 Internal Makefile Documentation

Documentation of the make system is mainly done in POD format in:

    perldoc t/Makefile.pod

It contains the general documentation as well as the Annotations used from
within the other Makefile*.

=head3 Terminology

General notes about terms and words used in all documentations,  no matter
if user or development documentation.

=over

=item  Perl

Is used when the programming language in general is meant.

=item  perl

Is used when the program perl (or perl.exe) is meant.

=item  Perl::Critic

Is used when the functionality of the  Perl::Critic module, or any program
using it (such as perlcritic), is meant.

=item  perlcritic

Is used when the program  perlcritic  is meant.

=item  Makefile

Is used when  a particular file is meant (usually the file itself in which
the term is used).  The term Makefile* is used when any of our  Makefile.*
is means.

=item  makefile(s)

Is used when files to be used as  input for make in general are meant.

=item variable, macro

In documentations for makefiles, for example GNU Make, the terms macro and
variable are used interchangeable.  In our documentation the term variable
is preferred.

=item target

Is used in O-Saft's documentation for the host target to be tested. And it
is also used in makefiles where it means the recipe to be executed.

=item arguments

Is used for arguments to the tools, like o-saft.pl, and is meant as option
or command for this tool, please see also  COMMANDS  and  OPTIONS  in

    o-saft.pl  --help

=back


=head1 Testing (Development)

See  L<Documentation>  above and  L<Note:--test-*>  below and

    o-saft.pl  --help=testing


=head1 Annotations, Internal Notes

The annotations from here on describe behaviours, observations, and alike,
which lead to special program logic.  The intention is to have one central
place where to do the documentation.
Up to now --2023-- this is an internal documentation only. It is available
for the developer also with:

    perldoc o-saft.pl

It is written in POD format, because some tools analysing the code want to
"see" comments and documentation. We feed them. For more information about
that, please see "voodoo" in o-saft-man.pm .

=head3 Annotation Syntax

Each single annotation is headed using POD's =head2 syntax.  All following
text is supposed to be read by humans!

It then will be referenced in the code with the "SEE <Annotation>" syntax,
where  "<Annotation>"  is the text right of the  =head2  keyword.

I.g. no other markup is used, except POD'S =head3 and  L <..> markup.

All following texts from here on are Annotations.


=head2 Note:Documentation

=head3 Since VERSION 18.12.18

Switching to CGI mode if the script is named *.cgi is no longer supported,
this script should be called by a proper wrapper, i.e o-saft.cgi .
The functionality was silently removed, no warning or error is printed.

=head3 Since VERSION 18.01.18

All public user documentation is now in plain text files which use charset
UTF-8, see  ./OSaft/Doc/*.txt . Previous files ./OSaft/Doc/*.pm  have been
replaced by  ./OSaft/Doc/Data.pm and the afore mentioned plain text files.
Reading plain text from external files instead of  Perl's DATA also avoids
sophisticated computation of the correct file and DATA handle, for example
when  ./OSaft/Doc/*.pm  is imported in  Perl's BEGIN section,  please also
SEE L<Perl:BEGIN> below.

=head3 Since VERSION 17.07.17

All documentation from variables, i.e.  %man_text, moved to separate files
in  ./OSaft/Doc/*. This simplified editing texts as they are  simple ASCII
format in the  __DATA__ section of each file. The overhead compared to the
%man_text  variable is just the Perl module file with its  POD texts.  The
disadvantage is, that it's more complicated to import the data in a stand-
alone script, see  contrib/gen_standalone.sh .

=head3 Since VERSION 17.06.17

All user documentation is now in  o-saft-man.pl, which uses a mix of texts
defined in Perl variables,  i.e. %man_text.  The public user documentation
is defined in the  __DATA__  section (mainly all the documentation).

=head3 Since VERSION 16.06.16

Reading of o-saft-README  disabled because most people asked how to remove
it, which is described in o-saft-README itself. People won't read :-(

=head3 Until VERSION 14.11.12

The documentation was initially written in Perl's doc format: perldoc POD.
The advantage  of POD is the  well formatted output on  various platforms,
but results in more difficult efforts for extracting information from it.
In particular following problems occoured with POD:

    - perldoc is not available on all platforms by default
    - POD is picky when text lines start with a whitespace
    - programmatically extracting data requires additional substitutes
    - POD is slow

See following table  how changing POD to plain ASCII (VERSION 14.11.14 vs.
14.12.14) results (for equal number of source code lines or kBytes):

      Description              POD ASCII           %    File
    -------------------------+----+-------------+------+----------
    * reduced doc. text:      3110  2656 lines     85%  o-saft.pl
    * reduced doc. text:      86.9  85.5 kBytes    98%  o-saft.pl
    * reduced source code:     122    21 lines     17%  o-saft.pl
    * reduced source code:     4.4   1.0 kBytes    23%  o-saft.pl
    * improved performance:    2.7  0.02 seconds 0.75%  o-saft.pl
    -------------------------+----+-------------+------+----------


=head2 Perl:perlcritic

perlcritic  is used for general code quality. Our code isn't accademically
perfect, nor is perlcritic. Hence perlcritic's pragmas are used to disable
some checks as needed. This is done in general in perlcritic's config file

    t/.perlcriticrc

and selectively in the code using the pragma:

    ## no critic ...

All disabled checks are documented, in  t/.perlcriticrc  or as pragma.

Following pragmas are used in various files:

* InputOutput::ProhibitBacktickOperators)

    This check seems to be a perosnal opinion of perlcritic's author,  see
    descriptions like   "... but I find that they make a lot of noise" and
    "... I think its better to use ..." .
    Using IPC::Open3 here is simply over-engineered.

* Documentation::RequirePodSections

    Our POD in *pm is fine, perlcritic (severity 2) is too pedantic here.

* Variables::ProhibitPackageVars

    perlcritic  complains to not declare  (global) package variables.  The
    purpose of some modules is to do that.


=head2 Perl:BEGIN perlcritic

perlcritic  cannot handle  BEGIN{}  sections semantically correct. If this
section is defined before the  `use strict;'  statement, it complains with
the error 'TestingAndDebugging::ProhibitNoStrict'.

Therefore any  BEGIN{}  section is defined after  `use strict;',  ugly but
avoids clumsy  `## no critic'  pragmas.


=head2 Perl:import include

Perl recommends to import modules using the  `use' or `require' statement.
Both methods have the disadvantage that this scripts fails  if a requested
module is missing.  The script fails immediately at startup if modules are
loaded with `use', or at runtime if loaded with `require'.

One goal is to be able to run on  ancient or incomplete configured systems
too. Hence we try to load all modules with our own function  _load_file(),
which uses `require' to load the module at runtime. This way it's possible
that  some functionality is disabled selectively, if loading of the module
fails for various reasons (i.e. wrong version).

Perl's `use autouse' is also not possible, as to much functions need to be
declared for that pragma then.
Unfortunately some common Perl modules resist to be loaded with `require'.
They are still imported using  use  .


=head2 Perl:EXPORT

Perl modules may export their sombols using `EXPORT' or `EXPORT_OK'.
TODO


=head2 Perl:Undefined subroutine

Perl requires that subroutines are defined before first use, obviously. As
we have some subroutines which should be used in the main script, and also
in our modules, another separate module would be necessary to achieve this.
This module then needs to be imported ('use' or 'require') in all scripts.

In practice, only a small number of these subroutines  are required in our
modules.  Hence we avoid building a special purpose module.  Unfortunately
this may result in Perl errors like:

    Undefined subroutine &main::_warn called at ...

when the module is called as standalone script.

Following approach is used:

  - subroutines are defined where (mainly) needed
  - modules use Perl's named subroutines like following, example: _warn():

    *_warn = sub { print($STR{WARN}, @_); } if not defined &_warn;

This ensures, that the definition is used only, if it doesn't exists. This
also avoids use of Perl's eval(). The disadvantage is, that the subroutine
does not have exacly the same functionality as the original definition.
TODO: in each named subroutin:  return if (grep{/(?:--no.?warn)/} @ARGV);

Also SEE L<Perl:BEGIN>.


=head2 Perl:@INC

Perl includes modules with the `use' or `require' statement. Therefore the
@INC  array is used which contains  a predefined list of directories where
to search for the files to be included. Following disadvantages are known:

  - the list of directories depends on the system (OS and distribution)
  - this list must be known before any Perl command is executed
  - it's tricky to use private directories
  - using "-I . lib/" in shebang line will pre- and append to @INC

Therefore  @INC  needs to be adapted properly in Perl's  BEGIN  scope (see
next annotation also). The added directories are:

  - $_path          # user-friendly: add path of the called script also
  - lib  $_path/lib # we support some local lib directories
  - $ENV{PWD}       # calling directory, some kind of fallback
  - /bin"           # special installation on portable media

Note that  $ENV{PWD}  may be undefined, it will obviously not used then.
Note that  /  works here even for Windoze.

Some logic is used to prepend these directories to @INC,  avoiding useless
paths. Keep in mind that any script may be called in following context:

  - /path/to/OSaft/Doc/Data.pm  # full path
  - OSaft/Doc/Data.pm           # local path
  - ./Data.pm                   # local path
  - ../OSaft/Doc/Data.pm        # relative path
  - Data.pm                     # by $PATH

Two of the above exmples need special settings:

  - Data.pm                     # the path matches the script name
  - /path/to/OSaft/Doc/Data.pm  # the path matches ^/


=head2 Perl:BEGIN

Loading `require'd  files and modules  as well as parsing the command-line
in Perl's  BEGIN section  increases performance and lowers the memory foot
print for some commands (see o-saft-man.pm also).
Unfortunately Perl's BEGIN has following limits and restrictions:

  - constants can be defined before and used herein
  - sub can be defined herein and used later
  - variables can not be defined herein and used later
  - some file handles (like <DATA>) are not yet available
  - strict sequence of definitions and usage (even for variables in subs)

Perl subs used in the  BEGIN section must be defined there also, or before
the BEGIN section (which is a crazy behaviour of Perl).
To make the program work as needed,  the limitations  force us to use some
dirty code hacks and split the flow of processing into  different parts of
the source.

Also SEE L<Perl:BEGIN perlcritic>.
Also SEE L<Perl:constant>.
Also SEE L<Perl:Undefined subroutine>.


=head2 Perl:constant

Perl has no "real" concept and implementation  of constants.  Using Perl's
pragma constant  declares in fact subroutines. Beside others, this has the
disadvantage,  that such constants cannot be use in strings,  they are not
interpolated there.

Our texts are rather variables than real constants, because it is possible
to overwrite them (beside some exceptions). Therefore it's more consequent
to use variables anywhere.

Perl's constants have the advantage that they are replaced at compile time
and therefore the code may result in better performance. That's not really
relevant for the tool's intended purpose.

Unfortunately using Perl's  Readonly instead of constant  is not possible,
because constants are used in the  BEGIN  section also.  Constants  can be
used there but not Readonly variables.

A hash is used for our texts. This has the advantage, that many values can
be defined without the need to care about every value everywhere. This has
the disadvantage,  that runtime errors like  "Undefined variable ..."  may
occour.

Instead of using  constant , the corrsponding  sub  are defined verbatim.


Also SEE L<Perl:BEGIN perlcritic>.


=head2 Perl:binmode()

Perl uses various layers for I/O operations. It's called  I/O layers -also
known as discipline. Layers to be used are defined globally with binmode()
or individually in each open() call. All the glory details can be found in
Perl's documentation (man or perldoc) for: PerlIO, binmode, open.

The tool here roughly destingushes two types of I/O:

    1. writing texts to the user using STDOUT and STDERR channels,
       note that it never reads, except from command-line, hence no STDIN;
    2. writing and reading to network sockets, which is done underneath.

We assume that the  I/O socket (2. above)  is handled properly by the used
modules. This leaves STDOUT and STDERR (1. above) to be set properly like:

    binmode(STDOUT, ":unix:utf8");
    binmode(STDERR, ":unix:utf8");

As most --nearly all-- data on STDOUT and STDERR is supposed to be read by
humans, only these channels are handled explicitly.  The idea is, that all
texts consist of printable characters only, probably in various languages.
Hence UTF-8 is used as default character set.  The channels are configured
to expect UTF-8 characters.
Perl destingushes between ':utf8' and ':encoding(UTF-8)' layer,  where the
':utf8' does not check for valid encodings. ':utf8' is sufficient here, as
we only want to ensure UTF-8 on output.
The I/O layers need to be set in the main script only, all modules inherit
the settings from there. However, modules need to use the proper binmode()
call itself, if they are called from command-line.

Unfortunately  Perl::Critic  complains that  ':encoding(UTF-8)'  should be
used, InputOutput::RequireEncodingWithUTF8Layer  must be disabled there.

Note that we use STDOUT and STDERR  and not the pseudo layer ':std' or the
-S flag/option, because they also contain STDIN.


=head2 Perl:map()

To replace data in each item of an arrays,  Perl provides various methods,
examples:

    @arr = map {$_ =~ s/old/new/g; $_; } @arr;  # 0. very bad
    @arr = map {      s/old/new/g; $_; } @arr;  # 1. bad
           map {      s/old/new/g;     } @arr;  # 2. better
                      s/old/new/     for @arr;  # 3. best

we prefer the perlish one (3. above).  Because it does not copy the array,
it is the most performant solution also.
Unfortunately  Perl::Critic complains about postfix controls with
ControlStructures::ProhibitPostfixControls  which seems to be misleading.
If there are multiple substitutions to be done, it is better to use a loop
like (which then keeps Perl::Critic happy too):

    while (@arr) {
        s/old/new/;
        s/alt/neu/;
    }


=head2 Perl:warn _warn

I.g. Perl's warn() is not used, but our private  _warn(). Using the option
--no-warning  _warn() can suppress messages. However, some warnings should
never be suppressed, hence  warn()  is used in rare cases.
Each warning should have a unique number, SEE L<Note:Message Numbers>.
See also  CONCEPTS  (if it exists in our help texts).


=head2 Note:Message Numbers

Each warning has a unique number. The numbers are grouped as follows:

    0xx     startup check, options, arguments
    1xx     check (runtime) functionality
    2xx     loop targets (hosts)
    3xx     connect functions
    4xx     cipher check functions
    5xx     inernal check functions
    6xx     check functions
    8xx     print functions

Check for used numbers with:

    egrep '(die|_warn| warn )' o-saft.pl | sed -e 's/^ *//' | sort

A proper test for the message should be done in t/Makefile.warnings, where
we have:

    make warnings-info


=head2 Note:Data Structures

To make (programmer's) life simple,  complex data structures are avoided.
Global variables are used (mostly defined in osaft.pm). This should be ok,
as there are no plans to run this tool in threaded mode.
Please see OSaft/Doc/coding.txt also.

Here's an overview of the used global variables:
Data structures with (mainly) static data:

    %cmd            - configuration for external commands (like openssl)
    %text           - configuration for message texts
    %ciphers        - definition of our cipher suites
    %shorttexts     - short texts (labels) for %data and %checks
    %prot_txt       - labels for %prot

Data structures with runtime data:

    %cfg            - configuration for commands and options herein
    %data           - labels and correspondig value (from Net::SSLinfo)
    %checks         - collected and checked certificate data
                      collected and checked target (connection) data
                      collected and checked connection data
                      collected and checked length and count data
    %info           - like %data, but for data which could not be retrieved
                      from Net::SSLinfo like HTTP vs. HTTPS checks
    %prot           - collected data per protocol (from Net::SSLinfo)
    @cipher_results - collected results as:  [SSL, cipher, "yes|no"]

NOTE: all keys in %data and %checks must be unique 'cause of %shorttexts.
NOTE: all keys in %checks  must be in lower case letters,  because generic
conversion of +commands to keys. The keys related to protocol, i.e. SSLv3,
TLSv11, etc. are mixed case.

Note according perlish programming style:

    references to $arr->{'val') are most often simplified as $arr->{val) ,
    same applies to 'txt' and 'typ'.

=head3 Initialisation

Most data structures are statically initalised. Some, mainly %checks, will
be initilised programmatically. The values in  %checks  must be initilised
also before the check result will be assigned. This default initialisation
could be:

    yes     - (empty string)
    no      - (any string)
    undef   - fixed string

Each method has its pros and cons. This has been changed, see below.

=head3 Initialisation since VERSION 19.12.26

All values in %check are set to  "<<undef>", which means neither 'yes' nor
'no'. The advantage is that missing checks are reported as:

    no (<<undef>>)

and hence are easily identified. This also allows to use different default
strings, for example disabled or missing checks, for example:

    no (<<N/A as STS not set>>)

The disadvantage is that all checks must assign the value  'yes'  or 'no'.

The default initialisation is done after processing all arguments from the
command-line and the RC-FILE.

=head3 Initialisation before VERSION 19.12.26

All values in %check were set to  ""  which means 'yes'. The advantage was
a very simple default assignment and only failed checks are assigned.  The
disadvantage was that missing checks, due to programming errors,  were re-
ported as 'yes'.

=head3 Shortened variable names

Some varaible names are abrevated,  instead of using full blown "speaking"
names. The main reason is to avoid overlong coding lines. Some examples:

    cn                  - common_name
    ext_authorityid     - ext_authorityid_key_id
    ext_certtype        - ext_netscape_certtyp
    ext_cps_notice      - ext_cps_user_notice
    ext_crl             - ext_crl_distribution_point
    master_secret       - extended_master_secret
    psk_hint            - psk_identity_hint


=head2 Note:Testing, sort

When values are assigned to arrays, or values are pushed on arrays, Perl's
final order in the array is random.
This results in  different orders  of the values when the array values are
printed,  means that the order changes for each program call.  Such random
orders in output makes internal testing difficult.
Hence, arrays are sorted (after defining them) when they are used. It is a
small perfomance penulty in production because the 'sort' is only required
while testing. Using a pragma like in C would be nice ...

Unfortunately there are arrays preset with a special order, these must not
be sorted. These are most likely the settings read from RC-FILE. For that,
sorting is not done for data read from RC-FILE. The --no-rc option is used
to check if the RC-FILE was read.

The data to be sorted is for example:

    @cfg{do}
    @cfg{commands}
    @cfg{commands_*}


=head2 Note:ARGV

Command-line arguments are read after some other internal initialisations.
Unfortunately sometimes options need to be checked before argument parsing
is completed. Therfore following is needed: '(grep{/--trace)/} @ARGV)'.
These check are implemented as simple functions and return grep's result.


=head2 Note:SSL protocol versions

The phrases 'SSL protocol versions', 'SSL protocols' or simply 'protocols'
are used through out the comments in the sources equal for  SSLv2,  SSLv3,
TLSv1 etc..


=head2 Note:ALPN, NPN

Traditionally first known as NPN, the  "protocol negotiation",  is used in
in the two flaviours NPN and ALPN. The internal variable names are adapted
to these acronyms and use "alpn" and "npn" in their names.  For historical
reason, the list of the protocol names was stored in "cfg{'next_protos'}",
which reflects the openssl option (-nextprotoneg),  and the function names
used in some Perl modules.
As newer versions of openssl uses the option  -alpn,  and some other tools
also use  -alpn  and/or  -npn  as option, the internal variable names have
been adapted to this naming scheme after version 17.04.17.
The primary variable names containing ALPN or NPN protocol names are now:

    protos_next     - internal list of all protocol names
    protos_alpn     - used with/for ALPN options
    protos_npn      - used with/for  NPN options
    cipher_alpns    - used with/for ALPN options for +cipher command only
    cipher_npns     - used with/for  NPN options for +cipher command only

I.g. these are arrays. But as the common syntax for most other tools is to
use a comma-separated list of names, the value in "cfg{'protos_next'}"  is
stored as a string.  Using a string instead of an array also simplifies to
pass the value to functions.

Note that openssl uses a comma-separated list for ALPN and NPN, but uses a
colon-separated list for ecliptic curves and also for ciphers.  Confusing.
Hence we allow both separators for all lists on command-line.

See also Note:OpenSSL Version


=head2 Note:alias

The code for parsing options and arguments uses some special syntax:

* following comment at end of the line:

    # alias: any other text

is used for aliases of commands or options. These lines are extracted by

   --help=alias


=head2 Note:anon-out

Some texts in output, mainly in warning or verbose messages,  may disclose
internal information. This may happen if the tool is executed in CGI mode.
To avoid such information disclosure,  a pattern is used to match texts to
be anonymised in output.
The use, hence definition, of this pattern is intended in CGI mode and can
there be done in the RC-FILE. Therefore it is also necessary that the tool
has an corresponding command-line option:  --anon-output .
The pattern is stored in  %cfg.  The correspondig string for anonymisation
(replacement) is defined in %text.

Note that the corresponding variable names (in %cfg and %text) should also
be part of the pattern to avoid its disclosure with --v or --trace option.

Known (9/2020) variables and texts with potential information disclosure:

    ENV{PWD}
    $me
    cfg{me}
    cfg{RC-ARGV}
    cfg{RC-FILE}
    cfg{regex}->{anon_output}
    cmd{openssl}


=head2 Note:ignore-out

The option  --ignore-out  (same as  --no-cmd) adds commands to the list of
commands  @cfg{out}->{ignore}.   The purpose is that values of the  listed
commands should not be printed in output. This is used mainly for commands
where theoutput will be noisy (like some +bsi* commands).
All data collections and checks are still done, just output of results are
omitted. Technically these commands are not removed from cfg{do}, but just
skipped in printdata() and printchecks(),  which makes implementation much
easier.


=head2 Note:--https_body

+https_body  prints the HTTP response body of the target. This may be very
noisy and is disabled by default. The option  --https_body  can be used to
force printing the HTTP data. The option removes  'https_body'  from array
cfg{out}->{ignore}.  For convenience and lacy users, some variants of this
options are allowed.


=head2 Note:warning-no-duplicates

Due to the program logic, for example nested looping (targets, protocols,
ciphers), the same message may be printed multiple times (in each loop).
As the duplicate warning doesn't give additional information to the user,
the duplicates are ignored by default. The option  --warnings_dups can be
used to enable printing of all messages.

As the tool traditionally supports complementary options for enabling and
disabling a functionality,  there is  --no-warnings_no_dups  respectively
--warnings_dups  too.
Note that using both options  --no-warnings --no-warnings_no_dups  is not
supported, means that no messages are printed.  This behaviour may change
in future.

Technically the list (array)  "cfg{'warnings_no_dups'}"  contains message
numbers not to be printed multiple times. This list is set empty when the
option  --warnings_dups  is given.

Some messages contain variable values,  therefore the printed text of the
message sligtly differs for several messages. Such messages should not be
subject to the "don't print duplicates" mechanism, in practice: don't add
their message number to  "cfg{'warnings_no_dups'}".
The array  "cfg{'warnings_printed'}"  is used internally and contains the
numbers of messages already printed.

SEE L<Note:Message Numbers> also.

To get a list of message numbers, use:

    make warnings-info


=head2 Note:OpenSSL Version

About OpenSSL's version numbers see openssl/opensslv.h . Examples:

  0x01000000 => openssl-0.9x.x
  0x1000000f => openssl-1.0.0
  0x10001000 => openssl-1.0.1
  0x10002000 => openssl-1.0.2
  0x102031af => 1.2.3z


=head2 Note:OpenSSL CApath

_init_openssldir() gets the configured directory for the certificate files
from the openssl executable. It is expected that openssl returns something
like:  OPENSSLDIR: "/usr/local/openssl"

Some versions of openssl on Windows may return "/usr/local/ssl", or alike,
which is most likely wrong.  The existence of the returned directory  will
be checked,  this produces a  **WARNING  and unsets the ca_path.  However,
the used Perl modules (i.e. Net::SSLeay)  may be compiled with a different
OpenSSL, and hence use their (compiled-in) private path to the certs.

Note that the returned OPENSSLDIR is a base-directory where the cert files
are found in the certs/ sub-directory. This 'certs/' is hardcoded herein.


=head2 Note:OpenSSL s_client

Net::SSLinfo::s_client_check() is used to check for openssl capabilities.
Each capability can be queried with  Net::SSLinfo::s_client_opt_get().
Even  Net::SSLinfo::s_client_*()  will check capabilities, no proper error
messages could be printed there. Hence checks are done herein first, which
disables unavailable functionality and avoids warnings. Results (supported
or not capability) are stored  in $cfg{'openssl'} .

Some options for s_client are implemented, see Net::SSLinfo.pm , or use:
    Net/SSLinfo.pm --test-sclient

Example of (1.0.2d) openssl s_client --help

 unknown option --help
 usage: s_client args

 -host host     - use -connect instead
 -port port     - use -connect instead
 -connect host:port - who to connect to (default is localhost:4433)
 -proxy host:port - use HTTP proxy to connect
 -verify_host host - check peer certificate matches "host"
 -verify_email email - check peer certificate matches "email"
 -verify_ip ipaddr - check peer certificate matches "ipaddr"
 -verify arg   - turn on peer certificate verification
 -verify_return_error - return verification errors
 -cert arg     - certificate file to use, PEM format assumed
 -certform arg - certificate format (PEM or DER) PEM default
 -key arg      - Private key file to use, in cert file if
                 not specified but cert file is.
 -keyform arg  - key format (PEM or DER) PEM default
 -pass arg     - private key file pass phrase source
 -CApath arg   - PEM format directory of CA's
 -CAfile arg   - PEM format file of CA's
 -no_alt_chains - only ever use the first certificate chain found
 -reconnect    - Drop and re-make the connection with the same Session-ID
 -pause        - sleep(1) after each read(2) and write(2) system call
 -prexit       - print session information even on connection failure
 -showcerts    - show all certificates in the chain
 -debug        - extra output
 -msg          - Show protocol messages
 -nbio_test    - more ssl protocol testing
 -state        - print the 'ssl' states
 -nbio         - Run with non-blocking IO
 -crlf         - convert LF from terminal into CRLF
 -quiet        - no s_client output
 -ign_eof      - ignore input eof (default when -quiet)
 -no_ign_eof   - don't ignore input eof
 -psk_identity arg - PSK identity
 -psk arg      - PSK in hex (without 0x)
 -jpake arg    - JPAKE secret to use
 -srpuser user     - SRP authentification for 'user'
 -srppass arg      - password for 'user'
 -srp_lateuser     - SRP username into second ClientHello message
 -srp_moregroups   - Tolerate other than the known g N values.
 -srp_strength int - minimal length in bits for N (default 1024).
 -ssl2         - just use SSLv2
 -ssl3         - just use SSLv3
 -tls1_2       - just use TLSv1.2
 -tls1_1       - just use TLSv1.1
 -tls1         - just use TLSv1
 -dtls1        - just use DTLSv1
 -fallback_scsv - send TLS_FALLBACK_SCSV
 -mtu          - set the link layer MTU
 -no_tls1_2/-no_tls1_1/-no_tls1/-no_ssl3/-no_ssl2 - turn off that protocol
 -bugs         - Switch on all SSL implementation bug workarounds
 -serverpref   - Use server's cipher preferences (only SSLv2)
 -cipher       - preferred cipher to use, use the 'openssl ciphers'
                 command to see what is available
 -starttls prot - use the STARTTLS command before starting TLS
                 for those protocols that support it, where
                 'prot' defines which one to assume.  Currently,
                 only "smtp", "pop3", "imap", "ftp", "xmpp"
                 "telnet" and "ldap" are supported.
                 are supported.
 -xmpphost host - When used with "-starttls xmpp" specifies the virtual host.
 -engine id    - Initialise and use the specified engine
 -rand file:file:...
 -sess_out arg - file to write SSL session to
 -sess_in arg  - file to read SSL session from
 -servername host  - Set TLS extension servername in ClientHello
 -tlsextdebug      - hex dump of all TLS extensions received
 -status           - request certificate status from server
 -no_ticket        - disable use of RFC4507bis session tickets
 -serverinfo types - send empty ClientHello extensions (comma-separated numbers)
 -curves arg       - Elliptic curves to advertise (colon-separated list)
 -sigalgs arg      - Signature algorithms to support (colon-separated list)
 -client_sigalgs arg - Signature algorithms to support for client
                       certificate authentication (colon-separated list)
 -nextprotoneg arg - enable NPN extension, considering named protocols supported (comma-separated list)
 -alpn arg         - enable ALPN extension, considering named protocols supported (comma-separated list)
 -legacy_renegotiation - enable use of legacy renegotiation (dangerous)
 -use_srtp profiles - Offer SRTP key management with a colon-separated profile list
 -keymatexport label   - Export keying material using label
 -keymatexportlen len  - Export len bytes of keying material (default 20)
 -no_tlsext        - Don't send any TLS extensions (breaks servername, NPN and ALPN among others)

Example of (1.l.0l) openssl s_client --help

 Usage: s_client [options]
 Valid options are:
 -help                      Display this summary
 -host val                  Use -connect instead
 -port +int                 Use -connect instead
 -connect val               TCP/IP where to connect (default is :4433)
 -proxy val                 Connect to via specified proxy to the real server
 -unix val                  Connect over the specified Unix-domain socket
 -4                         Use IPv4 only
 -6                         Use IPv6 only
 -verify +int               Turn on peer certificate verification
 -cert infile               Certificate file to use, PEM format assumed
 -certform PEM|DER          Certificate format (PEM or DER) PEM default
 -key val                   Private key file to use, if not in -cert file
 -keyform PEM|DER|ENGINE    Key format (PEM, DER or engine) PEM default
 -pass val                  Private key file pass phrase source
 -CApath dir                PEM format directory of CA's
 -CAfile infile             PEM format file of CA's
 -no-CAfile                 Do not load the default certificates file
 -no-CApath                 Do not load certificates from the default certificates directory
 -dane_tlsa_domain val      DANE TLSA base domain
 -dane_tlsa_rrdata val      DANE TLSA rrdata presentation form
 -dane_ee_no_namechecks     Disable name checks when matching DANE-EE(3) TLSA records
 -reconnect                 Drop and re-make the connection with the same Session-ID
 -showcerts                 Show all certificates sent by the server
 -debug                     Extra output
 -msg                       Show protocol messages
 -msgfile outfile           File to send output of -msg or -trace, instead of stdout
 -nbio_test                 More ssl protocol testing
 -state                     Print the ssl states
 -crlf                      Convert LF from terminal into CRLF
 -quiet                     No s_client output
 -ign_eof                   Ignore input eof (default when -quiet)
 -no_ign_eof                Don't ignore input eof
 -starttls val              Use the appropriate STARTTLS command before starting TLS
 -xmpphost val              Host to use with "-starttls xmpp[-server]"
 -rand val                  Load the file(s) into the random number generator
 -sess_out outfile          File to write SSL session to
 -sess_in infile            File to read SSL session from
 -use_srtp val              Offer SRTP key management with a colon-separated profile list
 -keymatexport val          Export keying material using label
 -keymatexportlen +int      Export len bytes of keying material (default 20)
 -fallback_scsv             Send the fallback SCSV
 -name val                  Hostname to use for "-starttls smtp"
 -CRL infile                CRL file to use
 -crl_download              Download CRL from distribution points
 -CRLform PEM|DER           CRL format (PEM or DER) PEM is default
 -verify_return_error       Close connection on verification error
 -verify_quiet              Restrict verify output to errors
 -brief                     Restrict output to brief summary of connection parameters
 -prexit                    Print session information when the program exits
 -security_debug            Enable security debug messages
 -security_debug_verbose    Output more security debug output
 -cert_chain infile         Certificate chain file (in PEM format)
 -chainCApath dir           Use dir as certificate store path to build CA certificate chain
 -verifyCApath dir          Use dir as certificate store path to verify CA certificate
 -build_chain               Build certificate chain
 -chainCAfile infile        CA file for certificate chain (PEM format)
 -verifyCAfile infile       CA file for certificate verification (PEM format)
 -nocommands                Do not use interactive command letters
 -servername val            Set TLS extension servername in ClientHello
 -tlsextdebug               Hex dump of all TLS extensions received
 -status                    Request certificate status from server
 -serverinfo val            types  Send empty ClientHello extensions (comma-separated numbers)
 -alpn val                  Enable ALPN extension, considering named protocols supported (comma-separated list)
 -async                     Support asynchronous operation
 -ssl_config val            Use specified configuration file
 -split_send_frag int       Size used to split data for encrypt pipelines
 -max_pipelines int         Maximum number of encrypt/decrypt pipelines to be used
 -read_buf int              Default read buffer size to be used for connections
 -no_ssl3                   Just disable SSLv3
 -no_tls1                   Just disable TLSv1
 -no_tls1_1                 Just disable TLSv1.1
 -no_tls1_2                 Just disable TLSv1.2
 -bugs                      Turn on SSL bug compatibility
 -no_comp                   Disable SSL/TLS compression (default)
 -comp                      Use SSL/TLS-level compression
 -no_ticket                 Disable use of TLS session tickets
 -serverpref                Use server's cipher preferences
 -legacy_renegotiation      Enable use of legacy renegotiation (dangerous)
 -no_renegotiation          Disable all renegotiation.
 -legacy_server_connect     Allow initial connection to servers that don't support RI
 -no_resumption_on_reneg    Disallow session resumption on renegotiation
 -no_legacy_server_connect  Disallow initial connection to servers that don't support RI
 -strict                    Enforce strict certificate checks as per TLS standard
 -sigalgs val               Signature algorithms to support (colon-separated list)
 -client_sigalgs val        Signature algorithms to support for client certificate authentication (colon-separated list)
 -curves val                Elliptic curves to advertise (colon-separated list)
 -named_curve val           Elliptic curve used for ECDHE (server-side only)
 -cipher val                Specify cipher list to be used
 -min_protocol val          Specify the minimum protocol version to be used
 -max_protocol val          Specify the maximum protocol version to be used
 -debug_broken_protocol     Perform all sorts of protocol violations for testing purposes
 -policy val                adds policy to the acceptable policy set
 -purpose val               certificate chain purpose
 -verify_name val           verification policy name
 -verify_depth int          chain depth limit
 -auth_level int            chain authentication security level
 -attime intmax             verification epoch time
 -verify_hostname val       expected peer hostname
 -verify_email val          expected peer email
 -verify_ip val             expected peer IP address
 -ignore_critical           permit unhandled critical extensions
 -issuer_checks             (deprecated)
 -crl_check                 check leaf certificate revocation
 -crl_check_all             check full chain revocation
 -policy_check              perform rfc5280 policy checks
 -explicit_policy           set policy variable require-explicit-policy
 -inhibit_any               set policy variable inhibit-any-policy
 -inhibit_map               set policy variable inhibit-policy-mapping
 -x509_strict               disable certificate compatibility work-arounds
 -extended_crl              enable extended CRL features
 -use_deltas                use delta CRLs
 -policy_print              print policy processing diagnostics
 -check_ss_sig              check root CA self-signatures
 -trusted_first             search trust store first (default)
 -suiteB_128_only           Suite B 128-bit-only mode
 -suiteB_128                Suite B 128-bit mode allowing 192-bit algorithms
 -suiteB_192                Suite B 192-bit-only mode
 -partial_chain             accept chains anchored by intermediate trust-store CAs
 -no_alt_chains             (deprecated)
 -no_check_time             ignore certificate validity time
 -allow_proxy_certs         allow the use of proxy certificates
 -xkey infile               key for Extended certificates
 -xcert infile              cert for Extended certificates
 -xchain infile             chain for Extended certificates
 -xchain_build              build certificate chain for the extended certificates
 -xcertform PEM|DER         format of Extended certificate (PEM or DER) PEM default
 -xkeyform PEM|DER          format of Extended certificate's key (PEM or DER) PEM default
 -tls1                      Just use TLSv1
 -tls1_1                    Just use TLSv1.1
 -tls1_2                    Just use TLSv1.2
 -dtls                      Use any version of DTLS
 -timeout                   Enable send/receive timeout on DTLS connections
 -mtu +int                  Set the link layer MTU
 -dtls1                     Just use DTLSv1
 -dtls1_2                   Just use DTLSv1.2
 -nbio                      Use non-blocking IO
 -psk_identity val          PSK identity
 -psk val                   PSK in hex (without 0x)
 -srpuser val               SRP authentication for 'user'
 -srppass val               Password for 'user'
 -srp_lateuser              SRP username into second ClientHello message
 -srp_moregroups            Tolerate other than the known g N values.
 -srp_strength +int         Minimal length in bits for N
 -nextprotoneg val          Enable NPN extension, considering named protocols supported (comma-separated list)
 -engine val                Use engine, possibly a hardware device
 -ssl_client_engine val     Specify engine to be used for client certificate operations
 -ct                        Request and parse SCTs (also enables OCSP stapling)
 -noct                      Do not request or parse SCTs (default)
 -ctlogfile infile          CT log list CONF file


=head2 Note:Selected Protocol

'sslversion' returns protocol as used in our data structure (like TLSv12)

example (output from openssl):

    New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES128-GCM-SHA256

example Net::SSLeay:

    Net::SSLeay::version(..)

example (output from openssl):
'session_protocol' retruns string used by openssl (like TLSv1.2)

    Protocol  : TLSv1.2

'fallback_protocol'

    Note: output from openssl:      TLSv1.2
    Note: output from Net::SSLeay:  TLSv1_2


=head2 Note:Selected Cipher

SEE L<Note:term default cipher>.

'cipher_selected' returns the cipher as used in our data structure (like
 DHE-DES-CBC), this is the one selected if the client provided a list
example (output from openssl):

example Net::SSLeay:
        Net::SSLeay::get_cipher(..)


=head2 Note:Cipher and Protocol

Cipher suites names are not unique per SSL/TLS protocol and can be used in
multiple protocols, for example SSLv3 and TLSv11. When ciphers are checked
with  +cipher  or  +check , its not possible to map the reported cipher to
the propper SSL/TLS protocol, unless the  --header option was used.

As the the checks for cipher suites are done per protocol, the result will
be pretended with a header line indicating the current SSL/TLS protocol.

This additional header line is only printed for our own formats. If output
format for other tools is requested by using  --legacy=* , these tools are
responsible themself to print proper results.


=head2 Note:Connection Test

To avoid long timeouts, a quick connection check to the target is done. At
least the connection to the SSL port must succeed.  If not, all checks are
skipped. If just the connection to port 80 fails, just the HTTP checks are
disabled. Also SEE L<Note:--ssl-error>.

The initial connection check just opens the port and does nothing. This is
done because  some methods, i.e.  Net::SSLeay::get_http(),  do not support
timeout settings, which then results in "hanging" connections.


=head2 Note:--ssl-error

The option  --ssl-error  in conjunction with error counts  --ssl-error-max
and --ssl-error-total controls wether to try to connect to the target even
if there are errors or timeouts. I.g. the used API IO::Socket:SSL, openssl
returns an error in $!. Unfortunately the error may be different according
the used version.  Hence the check herein  does not use the returned error
but relies on the time passed during the connection.  The assumtion (based
on experience) is, that successful or rejected connection take less than a
second, even on slow connections.  If the connection cannot be established
(because not supported or blocked), we run into a timeout, which is always
more than 0, at least 1 second (see --timeout=SEC option).

Timeout cannot be set less than  one second.  Also measuring the times and
their difference is in seconds.  A more accurate time measurement requires
the  Time::Local  module, which we try to avoid. Measuring within a second
is sufficent for these checks.

More descriptions are in the section  LIMITATIONS  of the man page, see

    "Connection Problems"  there.


=head2 Note:%prot

Using SSL/TLS protocols can either be done using %prot or $cfg{'versions'}
in contrast to "keys %prot"  $cfg{'versions'} is sorted according protocol
like: SSLv2 SSLv3 TLSv1 ...


=head2 Note:--exitcode

Ideas and discussions see also: https://github.com/OWASP/O-Saft/issues/52
By default  --exitcode  counts all settings considered weak or insecure.
This behaviour can be controlled with the  --exitcode-no-*  options.
The reasons and calculations of the returned status are printed withh  --v
or the special  --trace-exit  option.
By default, the "EXIT status" messages is printed, which can be suppressed
with  --exitcode-quiet .
NOTE: option named  --trace-exit  and not  --exitcode-v so that it matches
all checks according --trace* .


=head2 Note:heartbleed

http://heartbleed.com/
http://possible.lv/tools/hb/
http://filippo.io/Heartbleed/
https://github.com/proactiveRISK/Heartbleed
https://www.cloudflarechallenge.com/heartbleed
See also "--ignore-no-reply" description in o-saft-man.pm.

Apache cannot disable heartbeat, see:
??

nginx cannot disable heartbeat, see:
https://www.nginx.com/blog/nginx-and-the-heartbleed-vulnerability/


=head2 Note:ticketbleed

TBD


=head2 Note:CGI mode

Using the general concept of pipes which returns all results on STDOUT, it
is possible that the tool operates as CGI script in a web server. However,
some additional checks are necessary then to avoid misuse.

* Disabled functionality in CGI mode:

    * early verbose messages are not printed
    * debug and trace is not allowed (disabled)
    * configuration cannot be read from files

* Following checks must be done by the caller:

    * rejecting invalid target names
    * some dangerous options (i.e. --lib, --exe, etc.  see o-saft.cgi)
    * checking parameters (options) for dangerous characters

* The caller is also responsible to print proper HTTP headers.

Following special options are available for CGI mode:

    * --cgi         - must be passed to  o-saft.cgi  as first parameter
    * --cgi-exec    - must be set by caller only (i.g. o-saft.cgi)
    * --cgi-trace   - print HTTP header (for debugging only)

The option  --cgi-trace is for debugging when used from command-line only.

It is recommended that this script is called by  o-saft.cgi  in CGI mode.


=head2 Note:Option in CGI mode

In CGI mode all options are passed with a trailing  =  even those which do
not have an argument (value). This means that options cannot be ignored in
general, because they may occour at least in CGI mode, i.e.  --cmd=  .
The trailing  =  can always be removed, empty values are not possible.


=head2 Note:Stand-alone

A stand-alone script is a single script,  which executes without any other
module to be included (read) at run-time.
Most modules --means modules in Perl context and syntax-- are already read
using a private function  _load_file(),  which uses Perl's require instead
of use. This way the modules are loaded at  run-time (require)  and not at
compile-time (use).
Unfortunately there exist modules, which must be loaded with Perl's use.
When generating a stand-alone executable script, the complete file of each
module is simply copied into the main script file (o-saft.pl usually).  In
that case, the corresponding use statement must be removed. Modules loaded
with  _load_file()  read the files only if the variable  $osaft_standalone
does not exist.
Please refer to the  INSTALLATION  section,  in particular the sub-section
Stand-alone Executable  there, for more details on generating  stand-alone
scripts.
Generating a stand-alone script is done by contrib/gen_standalone.sh .


=head2 Note:root-CA

Some texts from: http://www.zytrax.com/tech/survival/ssl.html
The term Certificate Authority is defined as being an entity which signs
certificates in which the following are true:

   * the issuer and subject fields are the same,
   * the KeyUsage field has keyCertSign set,
   * and/or the basicConstraints field has the cA attribute set TRUE.

Typically, in chained certificates the root CA certificate is the topmost
in the chain but RFC 4210 defines a 'root CA' to be any issuer for which
the end-entity, for example, the browser has a certificate which was obtained
by a trusted out-of-band process. Since final authority for issuing any
certificate rest with this CA the terms and conditions of any intermediate
certificate may be modified by this entity.


Subordinate Authority:
May be marked as CAs (the extension BasicContraints will be present and cA
will be set True).


Intermediate Authority (a.k.a. Intermediate CA):
Imprecise term occasionally used to define an entity which creates an
intermediate certificate and could thus encompass an RA or a subordinate CA.


Cross certificates (a.k.a. Chain or Bridge certificate):
A cross-certificate is one in which the subject and the issuer are not the
same but in both cases they are CAs (BasicConstraints extension is present and has cA set True).


Intermediate certificates (a.k.a. Chain certificates):
Imprecise term applied to any certificate which is not signed by a root CA.
The term chain in this context is meaningless (but sounds complicated and
expensive) and simply indicates that the certificate forms part of a chain.


Qualified certificates: Defined in RFC 3739
the term Qualified certificates relates to personal certificates (rather than
server certificates) and references the European Directive on Electronic Signature (1999/93/EC)
see check02102() above


Multi-host certificates (a.k.a wildcard certificates)

EV Certificates (a.k.a. Extended Certificates): Extended Validation (EV)
certificates are distinguished by the presence of the CertificatePolicies
extension containing a registered OID in the policyIdentifier field.  See
checkev() above:

    RFC 3280
     4.2.1.10  Basic Constraints
       X509v3 Basic Constraints:
           cA:FALSE
           pathLenConstraint  INTEGER (0..MAX) OPTIONAL )
    RFC 4158


=head2 Note:term default cipher

Technically SSL/TLS does not know about a "default cipher".  Starting with
TLSv1, a "preferred selected cipher" is provided.  The server then selects
a cipher which is common between its own list of ciphers and the list send
by the client. The more correct term therfore is "preferred" or "selected"
cipher.
Many documents still use the term "default".  Some code exists, which also
uses "default" as part of variable or function names.


=head2 Note:Duplicate Commands

If a command is given multiple times, in any order,  it should be executed
only once.  The normalisation is done  right before commands are executed,
because multiple commands may occour in many places.

The normalisation must preserve the sequence of the commands, which can be
defined by the user. The first occourance of a command is used, all others
are ignored.


=head2 Note:+cipherall

SEE L<Note:term default cipher>.

In October 2017 (VERSION 17.09.17), the +cipherall command is no longer an
alias for +cipherraw. It is now using the the same technique as +cipherraw
to detect the targets ciphers, but prints the results like the traditional
+cipher command.
This has some impacts on computing other checks, like the default selected
cipher, the strongest and weakest selected cipher.

One problem is, that  +cipher  itself cannot detect the default cipher, so
it uses the underlaying SSL library's methods to do it, see _get_default()
which also computes the strongest and weakest selected cipher.
When using +cipherraw another method to detect these ciphers must be used;
this is not yet implemented completely.
The problem should finally be solved when  +cipher and +cipherraw  use the
same data structure for the results. Then the program flow should be like:

    ciphers_scan()
    checkciphers()
    printciphers()
    printciphersummary()


=head2 Note:+cipher

Starting with VERSION 19.11.19, only the command  +cipher  is supported.
When using any of the old commands, a hint will be written.

With this version the output format for cipher results was also changed.
It now prints the "Security" A, B, C (and  -?- if unknown) as specified by
OWASP. The column "supported" will not be printed,  because only supported
ciphers are listed now. This makes the options  --enabled  and  --disabled
also obsolete.

Note that the description in L<Note:+cipherall> uses the commands names as
used in VESRIONs before 19.11.19.

More information, which is also important for users,  can be found in user
documentation  OSaft/Doc/help.txt  section "Version 19.11.19 and later".

Internally, the commands  cipher_intern, cipher_openssl, cipher_ssleay and
cipher_dump are used; the command cipher still remains in $cfg{do}.

SEE L<Note:Cipher and Protocol>.


=head2 Note:--enabled --disabled

The options  --enabled  and  --disabled  are traditionally  implemented as
toggle for the functionality to print enabled or disabled ciphers only.
Therefore the default is to print both types. When either option is given,
the opposite one is deactivated.

The options  --noenabled  and  --nodisabled  are just for convenience, but
do not toggle the opposite one.


=head2 Note:--test-*

The options  --test-*  are used for testing, showing internal information.
Actually these are commands, hence the form  +test-*  is also supported.
All these commands do not perform any checks on the specified targets, but
exit right before the checks start. It is the same behaviour as the  +quit
command.

Until VERSION 19.12.21, only the options  --test-*  where supported. Using
these options exited the program. This behaviour resulted in incomplete or
misleading information.


=head2 Note:hints

The output may contain  !!Hint  messages, see  --help=output  for details.

The texts used for hint messages can be hardcoded in %cfg, set dynamically
in %cfg in the code, or set using command-line options at startup.
The hash %{$cfg{'hints'}} contains all these texts.

There're at least following types (places of definition) of hints:

    * permanent hints   -- defined in %{$cfg{'hints'}} directly
    * dynamic hints     -- defined at command line with option --cfg_hint=
    * hints for new or experimental code    -- defined in the code itself

A definition for a hint may look like:

    $cfg{hints}->{KEY} = 'new text';

KEY can be any string. If KEY (without leading +) is a known valid command
the message is printed automatically with the commands output (see below).
The text may contain formatting characters like \t and \n.

To set new hints dynamicly, following option can be used:

    $0 --cfg_hint=KEY="some text\nin 2 lines"

All predefined (hardcoded) hints can be listed with:

    $0 --help=hint

Note that dynamicly defined hints with  --cfg_hint=KEY=  are also shown if
the option was given before  --help=hint , example:

    $0 --cfg_hint=my-hint="given on command-line" --help=hint

Automatic printing works as follows:

    print_check() and print_data()  will automatically print hint texts if
    defined for the corresponding command.

They can be printed immediately (without being specified in  $cfg{hints} :

    printhint('your-key'),

It is not recommended to use:

    print $STR[HINT}, "my text";


=head2 Note:tty

The general concept is to use postprocessors for any output processing and
formatting.  This concept becomes clumsy  when the tool is used on devices
with limited capabilities (like tablets or smartphones).

The format of the output is described in the  RESULT  section of the docu-
mentation. Beside the results we also have the documentation itself, which
is intended to be read by humans.
I.g. all output may be passed to well known  formatting tools like  nroff,
troff, etc.  but this may clutter some texts  which are well formatted for
human readability.
The documentation is also preformatted for a screen width of 80 characters
(when troff or alike is not in use).

This means that following situations have to be handled:

    * output of results
    * output of documentation
    * output of preformatted documentation

To get a better human readable documentation on small devices, options can
be used to force formatting of some output depending on the screen width.
These options are mainly (for details please see  OPTIONS  section):

    --format-tty   --tty
    --format-width=NN
    --format-ident=NN
    --format-arrow=CHR

By default, the format settings are not used.  The settings are grouped in
the  %cfg{tty}  structure.

All special formatting according the tty is done in o-saft-man.pl (because
only documentation is effected). The function  _man_squeeze()  is used for
that. It tries to optimize the ouput for the device. Text preformatted for
better readability will be respected.

As the approach is genereric, the final result may not be perfect.
Following restrictions, oddities exist:

    * splitting is done on length of the text not on word bounderies, some
      words may be split in the middle
    * additional empty lines may occour
    * dashed lines (used for headings) are mainly not adapted (split)

To clearly mark the special formatting,  an additional  "return" character
is inserted where text was split.

If the (human) user decided to use  --tty , the output is  most likely not
subject to further postprocessing,  hence each leading TAB can be replaced
by 8 spaces too.

Hopefully this generated result is more comfortable to read  than the text
provided by the default behaviour. Simply use the  --tty  option.


=cut
