#!/usr/bin/perl -w
# Filename : checkAllCiphers.pl
#!#############################################################################
#!#                    Copyright (c) Torsten Gigler 
#!#             This script is part of the OWASP-Project 'o-saft'
#!#                  It's a simple wrapper the SSLhello.
#!#----------------------------------------------------------------------------
#!#       THIS Software is in ALPHA state, please give us feed back via
#!#              https://lists.owasp.org/mailman/listinfo/o-saft
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
#!# "Program Code" at the end of this file if you want to improve the program.

use strict;
use warnings;
use Carp;                                                       #replaces warn and die
use OSaft::error_handler qw (:sslhello_contants);               # use internal error_handler, get all constants used for SSLHELLO, for subs the      full names will be used (includung OSaft::error_handler-><sub>)$

use osaft;

BEGIN {
    my $_path = $0; $_path =~ s#[/\\][^/\\]*$##;
    unshift(@INC, $_path, "/bin" ); # /bin for special installation on portable media
}

my $VERSION = "17.07.15";
my  $me     = $0; $me     =~ s#.*(?:/|\\)##;
my  $mepath = $0; $mepath =~ s#/[^/\\]*$##;
    $mepath = "./" if ($mepath eq $me);
my  $mename = "checkAllCiphers";
    $mename = "O-Saft " if ($me !~ /checkAllCiphers/);

sub printhelp {
    print << "EoT";
NAME
    $me - simple wrapper for Net::SSLhello to test for all ciphers

SYNOPSIS
    $me [OPTIONS] hostname[:port] | mx-domain-name[:port]

OPTIONS
    --help      nice option
    --host=HOST add HOST to list of hosts to be checked
    -h=HOST     dito.
    --port=PORT use PORT for following hosts (default is 443)
    -p=PORT     dito.
    --proxy=PROXYHOST:PROXYPORT
                make connection through proxy on PROXYHOST:PROXYPORT
    --proxyhost=PROXYHOST
                make connection through proxy on PROXYHOST
    --proxyport=PROXYPORT
                make connection through proxy on PROXYHOST:PROXYPORT
    --proxyuser=PROXYUSER (not yet implemented)
                user to authenticate at PROXYHOST
    --proxypass=PROXYPASS (not yet implemented)
                passowrd to authenticate at PROXYUSER
    --mx        make a MX-Record DNS lookup for the mx-domain-name
                (makes sense together with --STARTTLS=SMTP)
    --SSL       test for this SSL version
                SSL is any of: sslv2, sslv3, tlsv1, tlsv11, tlsv12, tlsv13, dtlsv09, dtlsv1, (dtlsv11), dtlsv12, dtlsv13
                (e.g. --dtlsv12; default: sslv2, sslv3, tlsv1, tlsv11, tlsv12, tlsv13)
                Remark: All DTLS-Protocols are experimental (see --experimental), DTLSv09 (=OpenSSL pre 0.9.8f),
                        DTLSv11 has never been released
    --no-SSL    do not test for this SSL version
                SSL see --SSL  option
    --no-tcp    do not test any SSL versions using TCP, like sslv2, ... tlsv13
    --no-udp    do not test any SSL versions using UDP, like dtlsv09, ... dtlsv13
    --legacy=L  use format L in printed results
                available formarts: compact, simple, full
    --sni       test with 'Server Name Indication (SNI)' mode if supported by the protocol (default)
    --no-sni    do not test with SNI mode
    --toggle-sni
                test with and witout SNI mode (equivalent to --sni-toggle)
    --sniname=SNINAME
                if SNINAME is set, this Name is used in the Server Name Indication (SNI) Extension
                (instead of the hostname)
    --connect-delay=SEC
                Additional delay in seconds after each connect for a cipher check.
                This is useful when connecting to servers which have IPS in place,
                or are slow in accepting new connections or requests
    --ssl-retry=CNT
                number of retries for connects, if timed-out
    --ssl-timeout=SEC
                timeout in seconds for connects
    --cipherrange=RANGE, --range=RANGE
                RANGE is any of rfc, long, huge, safe, full, SSLv2, shifted (rfc, shifted by 64 bytes to the right)
                (see o-saft.pl --help)
    --ssl-maxciphers=CNT
                maximal number of ciphers sent in a sslhello (default is 64)
    --ssl-nodataeqnocipher
                some servers do not answer if none of the ciphers is supported
                This handling is by default on. Use '--no-ssl-nodataeqnocipher' to switch it off
    --ssl-use-ecc
                use supported elliptic curves. Default on.
    --ssl-use-ec-point
                use TLS 'ec_point_formats' extension. Default on.
    --ssl-usereneg
                use secure renegotion
    --ssl-doubel-reneg
                use renegotion SSL Extension also for SCSV (double send)
    --slow-server-delay=SEC
                additional delay n secs after a server s connected via a proxy or before starting STARTTLS.
                This is useful for testing connections via slow proxy chains or slow servers before sending the STARTTLS sequence
    --starttls  Use STARTTLS to start a TLS connection via SMTP
    --starttls=STARTTLS_TYPE
                Use STARTTLS to start TLS.
                STARTTLS_TYPE is any of SMTP (SMTP_2), ACAP, IMAP (IMAP_2), IRC, POP3, FTPS, LDAP, RDP (RDP_SSL), XMPP, CUSTOM
                (Notes: * SMTP_2 and IMAP_2 are second ways to use SMTP/IMAP, like RDP_SSL for RDP
                        * SMTP: use '--mx' for checking a mail-domain instead of a host)
                Please give us feedback (especially for FTPS, LDAP, RDP, CUSTOM)
                The STARTTLS_TYPEs 'ACAP', 'IRC' and 'CUSTOM' need the '--experimental' option, and please take care!
                You can use the STARTTLS_TYPE 'CUSTOM' to customize your own STARTTLS sequence including error handling, see '--starttls_phase1..5' and --starttls_error1..3
    --starttls_delay=SEC
                seconds to pause before sending a packet, to slow down the starttls-requests (default = 0).
                This may prevent a blockade of requests due to too much/too fast connections.
                (Info: In this case there is an automatic suspension and retry with a longer delay)
    --starttls_phase1..5="VALUE" (VALUE might be an expression or a string)
                Customize the internal state machine to manage STARTTLS, you can use up to 5 phases:
                 --starttls_phase1: set expression for 'receive data (RX)', e.g. ".?(?:^|\\n)220\\s"
                 --starttls_phase2: set string for 'send data (TX)',        e.g. "EHLO o-saft.localhost\\r\\n"
                 --starttls_phase3: set expression for RX,                  e.g. ".?(?:^|\\n)250\\s"
                 --starttls_phase4: set string for TX,                      e.g. "STARTTLS\\r\\n"
                 --starttls_phase5: set expression for RX,                  e.g. ".?(?:^|\\n)220\\s"
                For the TX phases 2 and 4 solely the escape sequences '\\r', '\\n', '\\t', '\\e', '\\x<00-ff>' and '\\' are supported, e.g. "\\r\\n", "\\x0d\\x0a"
                It is recommended to use at least TX and RX (last RX to get data that does not belong to the handshake of SSL/TLS itself), furthermore you should use '--trace=3' when you start customizing.
                Please share your results with us (o-saft (at) lists.owasp.org or via github).
                needs also '--starttls=CUSTOM', see above
                optional use of '--starttls_error1..3' to handle errors
    --starttls_error1..3="EXPRESSION" (or '--starttls_err1..3="EXPRESSION")
                Optional error handling for customized STARTTLS used in the RX phases (1, 3 and 5)
                 --starttls_error1: set expression for 'temporary unreachable (too many connections)', e.g. ".?(?:^|\\n)(?:421|450)\\s"
                 --starttls_error2: set expression for 'this SSL/TLS-Protocol is not supported',       e.g. ".?(?:^|\\n)4[57]4\\s"
                 --starttls_error3: set exptession for 'fatal Error/STARTTLS not supported',           e.g. ".*?(?:^|\\n)(?:451|50[023]|554)\\s"
                needs also '--starttls=CUSTOM' and '--starttls_phase1..3', see above
    --experimental
                to use experimental functions
    --trace     
                Print debugging messages
    --trace=<VALUE>
                Print more debugging messages (VALUE=1..4)
    --trace-time
                prints additional timestamps in trace output for benchmarking and debugging

DESCRIPTION
    This is just a very simple wrapper for the Net::SSLhello module to test
    a target for all available ciphers. It is a shortcut for
    o-saft.pl +cipherall YOUR-HOST

INSTALLATION
    checkAllCiphers.pl requires following Perl modules:
                IO::Socket::INET     (preferred >= 1.31)
                Net::DNS             (if option '--mx' is used)

                Module Net::SSLhello is part of O-Saft and should be
                installed in ./Net .
                All dependencies for these modules must also be installed.

EoT
return;
} # printhelp

##no critic qw(Modules::RequireBarewordIncludes)
# Modul name includes a hyphen -> '' and .pm are necessary
if (! eval {require 'o-saft-dbx.pm';} ) {
    # o-saft-dbx may not be installed, try to find in program's directory
    push(@INC, $mepath);
    require("o-saft-dbx.pm");
}
##use critic

if (! eval {require Net::SSLhello;} ) {
    # Net::SSLhello may not be installed, try to find in program's directory
    push(@INC, $mepath);
    require Net::SSLhello;
}

my $arg = "";
my @argv = grep {/--trace.?arg/} @ARGV;# preserve --tracearg option
push(@argv, @ARGV);
#dbx# _dbx "ARG: " . join(" ", @argv);

# read file with source for trace and verbose, if any
# -------------------------------------
my @dbx = grep {/--(?:trace|v$|yeast)/} @argv;  # option can be in .rc-file, hence @argv
if ($#dbx >= 0) {
    $arg =  "./o-saft-dbx.pm";
    $arg =  $dbx[0] if ($dbx[0] =~ m#/#);
    $arg =~ s#[^=]+=##; # --trace=./myfile.pl
    if (! -e $arg) {
        carp "**WARNING: '$arg' not found";
        $arg = join("/", $mepath, $arg);    # try to find it in installation directory
        croak  "**ERROR: '$!' '$arg'; exit" unless (-e $arg);
        # no need to continue if required file does not exist
        # Note: if $mepath or $0 is a symbolic link, above checks fail
        #       we don't fix that! Workaround: install file in ./
    }
    push(@{$dbx{file}}, $arg);
    printf("=== reading trace file ===\n") if(grep {/(:?--no.?header)/i} @ARGV <= 0);
    require $arg;   # `our' variables are available there
}

# initialize defaults
my $ssl;            # temporary variable used in main
my $host    = "";   # the host currently processed in main
my $port    = 443;  # the port currently used in main
   # above host, port, legacy and verbose are just shortcuts for corresponding
   # values in $cfg{}, used for better human readability

my %text = (
    'separator' => ":", # separator character between label and value
);

# set some default cfg values different to osaft
$cfg{'legacy'}                  = "compact";                    # used for sub printCipherStringArray
$cfg{'sslhello'}{'maxciphers'}  = 64;                           # configurations for TCP SSL protocol$: number of ciphers sent in SSL3/TLS Client-Hello

# scan options and arguments
# -------------------------------------
while ($#argv >= 0) {
    $arg = shift @argv;
    push(@{$dbx{argv}}, $arg) if (($arg !~ m/^--cfg_/) && ($arg =~ m/^[+-]/));
    push(@{$dbx{cfg}},  $arg) if  ($arg =~ m/^--cfg_/);    # both aprox. match are sufficient for debugging
    if ($arg !~ /(?:[+]|--)(?:cmd|host|port|exe|lib|cipher|format|legacy|timeout|url)=/) {
        $arg =~ s/=+$//;                    # remove trailing = (for CGI mode)
    }
    # Simple check for option; only options with syntax  --KEY=VALUE allowed.
    # Following checks use exact matches with 'eq' or regex matches with '=~'

    #{ options
    #!# You may read the lines as table with colums like:
    #!#--------+------------------------+-------------------------
    #!#           argument to check       value to be set
    #!#--------+------------------------+-------------------------
    if ($arg =~ /^--http$/i)                            { $cfg{'usehttp'}++;     next; } # must be before --h
    if ($arg =~ /^--no[_-]?http$/i)                     { $cfg{'usehttp'}   = 0; next; }
    if ($arg =~ /^--h(?:elp)?(?:=(.*))?$/i)             { printhelp(); exit 0;         } # allow --h --help --h=*
    if ($arg =~ /^\+help=?(.*)$/i)                      { printhelp(); exit 0;         } # allow +help +help=*
    if ($arg =~ /^--v(erbose)?$/i)                      { $cfg{'verbose'}++;     next; }
    if ($arg =~ /^--n$/i)                               { $cfg{'try'}       = 1; next; }
    if ($arg =~ /^--connect[_-]?delay=(\d+)$/i)         { $cfg{'connect_delay'}=$1; next;}
    if ($arg =~ /^--trace$/i)                           { $cfg{'trace'}++;       next; }
    if ($arg =~ /^--trace(--|[_-]?arg)$/i)              { $cfg{'traceARG'}++;    next; } # special internal tracing
    if ($arg =~ /^--trace([_-]?cmd)$/i)                 { $cfg{'traceCMD'}++;    next; } # ..
    if ($arg =~ /^--trace(@|[_-]?key)$/i)               { $cfg{'traceKEY'}++;    next; } # ..
    if ($arg =~ /^--trace=(\d+)$/i)                     { $cfg{'trace'}    = $1; next; }
    if ($arg =~ /^--trace([_-]?time)$/i)                { $cfg{'traceTIME'}++;   $cfg{'trace'} = $cfg{'trace'}||1; next; } # Timestamp on; trace on if it was off
    if ($arg =~ /^--?p(?:ort)?=(\d+)$/i)                { $cfg{'port'}     = $1; next; }
    if ($arg =~ /^--?h(?:ost)?=(.+)$/i)                 { push(@{$cfg{'hosts'}}, $1 . ":" . ($cfg{'port'}||443)); next; }     
    # proxy options
    if ($arg =~ /^--proxy=(.+?)\:(\d+)$/i)              { $cfg{'proxyhost'}= $1;
                                                          $cfg{'proxyport'}= $2; next; }
    if ($arg =~ /^--proxyhost=(.+)$/i)                  { $cfg{'proxyhost'}= $1; next; }
    if ($arg =~ /^--proxyport=(.+)$/i)                  { $cfg{'proxyport'}= $1; next; }
    if ($arg =~ /^--proxyuser=(.+)$/i)                  { $cfg{'proxyuser'}= $1; next; }
    if ($arg =~ /^--proxypass=(.+)$/i)                  { $cfg{'proxypass'}= $1; next; }
    if ($arg =~ /^--proxyauth=(.+)$/i)                  { $cfg{'proxyauth'}= $1; next; }
    if ($arg =~ /^--slow[_-]?server[_-]?delay=(\d+)$/i) {$cfg{'slowServerDelay'}=$1; next; }
    if ($arg =~ /^--starttls$/i)                        { $cfg{'starttls'}  = 1; $cfg{'starttlsType'}='SMTP'; next; }  # starttls, starttlsType=SMTP(=0)
    if ($arg =~ /^--starttls=(\w+)$/i)                  { $cfg{'starttls'}  = 1; $cfg{'starttlsType'}=uc($1); next;} # starttls, starttlsType=Typ (EXPERIMENTAL!!) ##Early Alpha!! 2xIMAP to test!
                                                        # 9 Types defined: SMTP, IMAP, IMAP2, POP3, FTPS, LDAP, RDP, XMPP, CUSTOM
    if ($arg =~ /^--starttls[_-]?phase(\d)=(.+)$/i){ $cfg{'starttls_phase'}[$1] = $2 if (($1 >0) && ($1<=5)); next; } # starttl, CUSTOM starttls-sequence 
    if ($arg =~ /^--starttls[_-]?err(?:or)?(\d)=(.+)$/i){ $cfg{'starttls_error'}[($1)] = $2 if (($1 >0) && ($1<=3)); next; } # starttls, error-handling for CUSTOMized starttls
    if ($arg =~ /^--starttls[_-]?delay=(\d+)$/i)        {$cfg{'starttlsDelay'}=$1; next;}
    # option
    if ($arg =~ /^--sni$/i)                             { $cfg{'usesni'}    = 1; next; }
    if ($arg =~ /^--no[_-]?sni$/i)                      { $cfg{'usesni'}    = 0; next; } 
    if ($arg =~ /^--toggle[_-]?sni$/i)                  { $cfg{'usesni'}    = 2; next; } # test with and without SNI
    if ($arg =~ /^--sni[_-]?toggle$/i)                  { $cfg{'usesni'}    = 2; next; } # test with and without SNI
    if ($arg =~ /^--sni[_-]?name$/i)                    { $cfg{'sni_name'}  = ""; $cfg{'use_sni_name'} = 1; next; } # sniname=""
    if ($arg =~ /^--sni[_-]?name=(.*)$/i)               { $cfg{'sni_name'}  = $1; $cfg{'use_sni_name'} = 1; next; } # sniname=SNINAME 
    if ($arg =~ /^--no[_-]?sni[_-]?name$/i)             { $cfg{'use_sni_name'} = 0; $cfg{'sni_name'} = "1"; next; } # go back to hostname; ##FIX: reset 'sni_name'="1" until o-saft migrated to get 'use_sni_name', too
    if ($arg =~ /^--header$/i)                          { $cfg{'out_header'}= 1; next; }
    if ($arg =~ /^--no[_-]?header$/i)                   { $cfg{'out_header'}= 0; push(@ARGV, "--no-header"); next; } # push() is ugly hack to preserve option even from rc-file
    if ($arg =~ /^--?sslv?2$/i)                         { $cfg{'SSLv2'}     = 1; next; } # allow case insensitive
    if ($arg =~ /^--?sslv?3$/i)                         { $cfg{'SSLv3'}     = 1; next; } # ..
    if ($arg =~ /^--?tlsv?1$/i)                         { $cfg{'TLSv1'}     = 1; next; } # ..
    if ($arg =~ /^--?tlsv?1[-_.]?1$/i)                  { $cfg{'TLSv11'}    = 1; next; } # allow ._- separator
    if ($arg =~ /^--?tlsv?1[-_.]?2$/i)                  { $cfg{'TLSv12'}    = 1; next; } # ..
    if ($arg =~ /^--?dtlsv?0[-_.]?9$/i)                 { $cfg{'DTLSv09'}   = 1; next; } # .. OpenSSL pre 0.9.8f
    if ($arg =~ /^--?dtlsv?1[-_.]?0?$/i)                { $cfg{'DTLSv1'}    = 1; next; } # ..
    if ($arg =~ /^--?dtlsv?1[-_.]?1$/i)                 { $cfg{'DTLSv11'}   = 1; next; } # ..
    if ($arg =~ /^--?dtlsv?1[-_.]?2$/i)                 { $cfg{'DTLSv12'}   = 1; next; } # ..
    if ($arg =~ /^--?dtlsv?1[-_.]?3$/i)                 { $cfg{'DTLSv13'}   = 1; next; } # ..
    if ($arg =~ /^--no[_-]?sslv?2$/i)                   { $cfg{'SSLv2'}     = 0; next; } # allow _- separator
    if ($arg =~ /^--no[_-]?sslv?3$/i)                   { $cfg{'SSLv3'}     = 0; next; } # ..
    if ($arg =~ /^--no[_-]?tlsv?1$/i)                   { $cfg{'TLSv1'}     = 0; next; } # ..
    if ($arg =~ /^--no[_-]?tlsv?11$/i)                  { $cfg{'TLSv11'}    = 0; next; } # ..
    if ($arg =~ /^--no[_-]?tlsv?12$/i)                  { $cfg{'TLSv12'}    = 0; next; } # ..
    if ($arg =~ /^--no[_-]?tlsv?13$/i)                  { $cfg{'TLSv13'}    = 0; next; } # ..
    if ($arg =~ /^--no[_-]?dtlsv?09$/i)                 { $cfg{'DTLSv09'}   = 0; next; } # .. OpenSSL pre 0.9.8f
    if ($arg =~ /^--no[_-]?dtlsv?10?$/i)                { $cfg{'DTLSv1'}    = 0; next; } # ..
    if ($arg =~ /^--no[_-]?dtlsv?11$/i)                 { $cfg{'DTLSv11'}   = 0; next; } # ..
    if ($arg =~ /^--no[_-]?dtlsv?12$/i)                 { $cfg{'DTLSv12'}   = 0; next; } # ..
    if ($arg =~ /^--no[_-]?dtlsv?13$/i)                 { $cfg{'DTLSv13'}   = 0; next; } # ..
    if ($arg =~ /^--no[_-]?tcp$/i)                      { $cfg{'SSLv2'}     = 0;
                                                          $cfg{'SSLv3'}     = 0;
                                                          $cfg{'TLSv1'}     = 0;
                                                          $cfg{'TLSv11'}    = 0;
                                                          $cfg{'TLSv12'}    = 0;
                                                          $cfg{'TLSv13'}    = 0; next; } # ..$
    if ($arg =~ /^--no[_-]?udp$/i)                      { $cfg{'DTLSv09'}   = 0;         # OpenSSL pre 0.9.8f
                                                          $cfg{'DTLSv1'}    = 0;
                                                          $cfg{'DTLSv11'}   = 0;
                                                          $cfg{'DTLSv12'}   = 0;
                                                          $cfg{'DTLSv13'}   = 0; next; } # ..$
    if ($arg =~ /^--nullsslv?2$/i)                      { $cfg{'nullssl2'}  = 1; next; } # ..
    if ($arg =~ /^--no[_-]?dns$/i)                      { $cfg{'usedns'}    = 0; next; }
    if ($arg =~ /^--dns$/i)                             { $cfg{'usedns'}    = 1; next; }
    if ($arg =~ /^--no[_-]?(?:dns[_-]?)?mx$/i)          { $cfg{'usemx'}     = 0; next; }
    if ($arg =~ /^--(?:dns[_-]?)?mx$/i)                 { local $@="";        # this command needs an additional Perl Module
                                                          eval {
                                                            require Net::DNS;
                                                            $cfg{'usemx'}= 1; # no error
                                                            1;
                                                          } or do {           # error handling
                                                            carp ("$me: Perl Module 'NET::DNS' is not installed, opition '$arg' ignored: $@");
                                                          };                     next; }
    if ($arg =~ /^--enabled$/i)                         { $cfg{'enabled'}   = 1; next; }
    if ($arg =~ /^--disabled$/i)                        { $cfg{'disabled'}  = 1; next; }
    if ($arg =~ /^--printavailable$/i)                  { $cfg{'enabled'}   = 1; next; } # ssldiagnos
    if ($arg =~ /^--showhost$/i)                        { $cfg{'showhost'}  = 1; next; }
    if ($arg =~ /^--no[_-]failed$/i)                    { $cfg{'enabled'}   = 0; next; } # sslscan
    if ($arg =~ /^--range=(.*)/i)                       { $cfg{'cipherrange'}=$1;next; }
    if ($arg =~ /^--cipherrange=(.*)$/i)                { $cfg{'cipherrange'}=$1;next; }
    if ($arg =~ /^--legacy=(.*)$/i)                     { $cfg{'legacy'}     =$1;next; }
    if ($arg =~ /^--tab$/i)                             { $text{'separator'}="\t";next;} # TAB character
    if ($arg =~ /^--no[_-]?ssl[_-]?useecc$/i)           { $cfg{'sslhello'}->{'useecc'}           = 0; next; } # alias ...
    if ($arg =~ /^--ssl[_-]?nouseecc$/i)                { $cfg{'sslhello'}->{'useecc'}           = 0; next; }
    if ($arg =~ /^--ssl[_-]?useecc$/i)                  { $cfg{'sslhello'}->{'useecc'}           = 1; next; }
    if ($arg =~ /^--no[_-]?ssl[_-]?useecpoint$/i)       { $cfg{'sslhello'}->{'useecpoint'}       = 0; next; } # alias ...
    if ($arg =~ /^--ssl[_-]?nouseecpoint$/i)            { $cfg{'sslhello'}->{'useecpoint'}       = 0; next; }
    if ($arg =~ /^--ssl[_-]?useecpoint$/i)              { $cfg{'sslhello'}->{'useecpoint'}       = 1; next; }
    if ($arg =~ /^--ssl[_-]?retry=(\d+)$/i)             { $cfg{'sslhello'}->{'retry'}            =$1; next; }
    if ($arg =~ /^--ssl[_-]?timeout=(\d+)$/i)           { $cfg{'sslhello'}->{'timeout'}          =$1; next; }
    if ($arg =~ /^--ssl[_-]?maxciphers=(\d+)$/i)        { $cfg{'sslhello'}->{'maxciphers'}       =$1; next; }
    if ($arg =~ /^--ssl[_-]?usereneg=(\d+)$/i)          { $cfg{'sslhello'}->{'usereneg'}         =$1; next; }
    if ($arg =~ /^--no[_-]?ssl[_-]?usereneg$/i)         { $cfg{'sslhello'}->{'usereneg'}         = 0; next; } # alias ...
    if ($arg =~ /^--ssl[_-]?no[_-]?usereneg$/i)         { $cfg{'sslhello'}->{'usereneg'}         = 0; next; }
    if ($arg =~ /^--ssl[_-]?use[_-]?reneg$/i)           { $cfg{'sslhello'}->{'usereneg'}         = 1; next; }
    if ($arg =~ /^--ssl[_-]?double[_-]?reneg$/i)        { $cfg{'sslhello'}->{'double_reneg'}     = 1; next; }
    if ($arg =~ /^--no[_-]?ssl[_-]?doublereneg$/i)      { $cfg{'sslhello'}->{'double_reneg'}     = 0; next; } # alias ...
    if ($arg =~ /^--ssl[_-]?no[_-]?doublereneg$/i)      { $cfg{'sslhello'}->{'double_reneg'}     = 0; next; }
    if ($arg =~ /^--no[_-]?nodata(?:eq)?nocipher$/i)    { $cfg{'sslhello'}->{'nodatanocipher'}   = 0; next; } # alias ...
    if ($arg =~ /^--no[_-]?ssl[_-]?nodata(?:eq)?nocipher$/i){ $cfg{'sslhello'}->{'nodatanocipher'} = 0; next; }
    if ($arg =~ /^--ssl[_-]?nodataneqnocipher$/i)       { $cfg{'sslhello'}->{'nodatanocipher'}   = 0; next; } # alias ...
    if ($arg =~ /^--nodataneqnocipher$/i)               { $cfg{'sslhello'}->{'nodatanocipher'}   = 0; next; } # alias
    if ($arg =~ /^--ssl[_-]?nodata(?:eq)?nocipher$/i)   { $cfg{'sslhello'}->{'nodatanocipher'}   = 1; next; }
    if ($arg =~ /^--nodata(?:eq)?nocipher$/i)           { $cfg{'sslhello'}->{'nodatanocipher'}   = 1; next; } # alias
    if ($arg =~ /^--?experimental$/i)                   { $cfg{'experimental'}                   = 1; next; }
    #} +---------+----------------------+-------------------------

    if ($arg =~ /^[+-]/) {
        carp "**WARNING: unknown command or option '$arg' ignored. Try '$me --help' to get more information!";
        next;
    }
    push(@{$cfg{'hosts'}}, $arg . ":" . ($cfg{'port'}||443));
} # while

# set defaults for Net::SSLhello
# -------------------------------------
{
    no warnings qw(once); # avoid: Name "Net::SSLhello::trace" used only once: possible typo at ...
    $Net::SSLhello::trace           = $cfg{'trace'} if ($cfg{'trace'} > 0);
    $Net::SSLhello::traceTIME       = $cfg{'traceTIME'};
    $Net::SSLhello::usesni          = $cfg{'usesni'};
    $Net::SSLhello::use_sni_name    = $cfg{'use_sni_name'};
    $Net::SSLhello::sni_name        = $cfg{'sni_name'};
    $Net::SSLhello::connect_delay   = $cfg{'connect_delay'};
    $Net::SSLhello::starttls        = $cfg{'starttls'};
    $Net::SSLhello::starttlsType    = $cfg{'starttlsType'}; 
    @Net::SSLhello::starttlsPhaseArray  = @{$cfg{'starttls_phase'}};
    # add 'starttls_error' array elements according Net::SSLhello's internal
    # representation
    push(@Net::SSLhello::starttlsPhaseArray, @{$cfg{'starttls_error'}}[1..3]);
    if ($cfg{'trace'} > 3) {
        for my $i (1..5) {
            _trace ("  \$cfg{'starttls_phase'}[$i]=$cfg{'starttls_phase'}[$i]\n") if (defined($cfg{'starttls_phase'}[$i]));
        }
        for my $i (1..3) {
            _trace ("  \$cfg{'starttls_error'}[$i]=$cfg{'starttls_error'}[$i]\n") if (defined($cfg{'starttls_error'}[$i]));
        }
    }
    $Net::SSLhello::starttlsDelay       = $cfg{'starttlsDelay'}; #reset to original value for each host (same as some lines later to prevent 'used only once' warning) 
    $Net::SSLhello::slowServerDelay     = $cfg{'slowServerDelay'}; 
    $Net::SSLhello::timeout         = $cfg{'sslhello'}->{'timeout'};
    $Net::SSLhello::retry           = $cfg{'sslhello'}->{'retry'};
    $Net::SSLhello::usereneg        = $cfg{'sslhello'}->{'usereneg'};
    $Net::SSLhello::useecc          = $cfg{'sslhello'}->{'useecc'};
    $Net::SSLhello::useecpoint      = $cfg{'sslhello'}->{'useecpoint'};
    $Net::SSLhello::double_reneg    = $cfg{'sslhello'}->{'double_reneg'};
    $Net::SSLhello::proxyhost       = $cfg{'proxyhost'};
    $Net::SSLhello::proxyport       = $cfg{'proxyport'};
    $Net::SSLhello::max_ciphers     = $cfg{'sslhello'}->{'maxciphers'};
    $Net::SSLhello::cipherrange     = $cfg{'cipherrange'};
    $Net::SSLhello::experimental    = $cfg{'experimental'};
    $Net::SSLhello::noDataEqNoCipher    = $cfg{'sslhello'}->{'nodatanocipher'};
}

print "##############################################################################\n";
print "# '$me' (part of OWASP project 'O-Saft'),\n";
print "#     Version (yy.mm.dd):           $VERSION\n";
print "# using (internal) modules:\n";
print "#     O-Saft::";
Net::SSLhello::version();
print "#     O-Saft::";
OSaft::error_handler::version();
print "##############################################################################\n\n";

#reset error_handler and set basic information for this sub$
OSaft::error_handler->reset_err( {module => $me, sub => '', print => ($cfg{'trace'} > 0), trace => $cfg{'trace'}} );

Net::SSLhello::printParameters() if ($cfg{'trace'} > 1);

my $protocols;
print "Protocols to check:\n";
# check ssl protocols
foreach my $ssl (@{$cfg{'versions'}}) {
    if ( ($ssl =~ /DTLS/) && ($cfg{$ssl} == 1) && ($cfg{'experimental'} !=1 ) ) { # DTLS support is experimental
        $protocols .= ", " if ($protocols);
        $protocols .= "$ssl";
        next;
    }
    next if ($cfg{$ssl} != 1); #  = 0 or undefined
    print "$ssl\n"; 
    push(@{$cfg{'version'}}, $ssl);
}
print "Use of Protocol(s) '$protocols' is experimental, please use the option '--experimental' and take care.\n" if ($protocols);
print "\n";

if ($cfg{'usemx'}) { # get mx-records
    _trace2 (" \$cfg{'usemx'} = $cfg{'usemx'}\n");
    print "\n# get MX-Records:\n";
    @{$cfg{'mx_domains'}} = @{$cfg{'hosts'}}; #we have got mx domains no hosts, yet
    $cfg{'hosts'} = [];

    foreach my $mx_domain (@{$cfg{'mx_domains'}}) {  # loop domains
        if ($mx_domain =~ m#.*?:\d+#) { 
            ($mx_domain, $port) = split(":", $mx_domain); 
        }
        _trace3 (" get MX-Records for '$mx_domain'\n");
        my $dns = Net::DNS::Resolver->new;
        my $mx = $dns->query($mx_domain, 'MX');
        my $sep =", ";

        if (defined ($mx) && defined($mx->answer)) {
            foreach my $mxRecord ($mx->answer) {
                _trace3 (" => ". $mxRecord->exchange. ' ('. $mxRecord->preference. ")\n");
                push(@{$cfg{'hosts'}}, $mxRecord->exchange . ":" . ($port||25));
                printf "%16s%s%5s%s%-6s%s%32s%-6s%s%-4s%s\n",
                    $mx_domain, $sep,           # %16s%s
                    ($port||25), $sep,          # %5s%s
                    "MX", $sep,                 # %-6s%s
                    $mxRecord->exchange, $sep,  # %32s%s
                    "Prio", $sep,               # %-6s%s
                    $mxRecord->preference, $sep;# %-4s%s
            }
        } else {
            printf "%16s%s%5s%s%-6s%s%32s%-6s%s%-4s%s\n",
                $mx_domain, $sep,   # %16s%s
                ($port||25), $sep,  # %5s%s
                "MX", $sep,         # %-6s%s
                "", $sep,           # %32s%s
                "Prio", $sep,       # %-6s%s
                "", $sep;           # %-4s%s
        }
    }
    print "------------------------------------------------------------------------------\n";
}

foreach my $host (@{$cfg{'hosts'}}) {  # loop hosts
    #reset error_handler and set basic information for this sub$
    OSaft::error_handler->reset_err( {module => $me, sub => '', print => ($cfg{'trace'} > 0), trace => $cfg{'trace'}} );

    if ($host =~ m#.*?:\d+#) { 
       ($host, $port) = split(":", $host);
        $cfg{'port'}  = $port;  #
        $cfg{'host'}  = $host;
    }
    _trace("host{ " . ($host||"") . ":" . $port . "\n");
    $cfg{'host'} = $host;
    $Net::SSLhello::starttlsDelay = $cfg{'starttlsDelay'}; #reset to original value for each host 
    foreach my $ssl (@{$cfg{'version'}}) {
        my @accepted = (); # List of all Ciphers that are supported by the server with the tested Protocol
        my @testing  = ();
        my $range = $cfg{'cipherrange'};                        # use specified range of constants
           $range = 'SSLv2_long' if ($ssl eq 'SSLv2');          # but SSLv2 needs its own list: SSLV2+SSLV3-Ciphers

        #reset error_handler and set basic information for this sub$
        OSaft::error_handler->reset_err( {module => $me, sub => '', print => ($cfg{'trace'} > 0), trace => $cfg{'trace'}} );

        ## no critic qw(BuiltinFunctions::ProhibitStringyEval)
        #  NOTE: this eval must not use the block form because the value needs to be evaluated
        push(@testing, sprintf("0x%08X",$_)) foreach (eval($cfg{'cipherranges'}->{$range}));
        ## use critic
        if ($Net::SSLhello::usesni) { # usesni (--sni: 1 or --togglesni: 2) is set 
            if ( ($Net::SSLhello::usesni > 1) || ($ssl eq 'SSLv2') || ($ssl eq 'SSLv3') ) { # toggle SNI (2): test first without sni, old protocols: test solely without SNI
                $Net::SSLhello::usesni = 0;
                @accepted = Net::SSLhello::checkSSLciphers ($host, $port, $ssl, @testing);
                if ((OSaft::error_handler->get_err_type()) <= (OERR_SSLHELLO_RETRY_HOST)) { # severe error
                    _trace ("**WARNING: checkAllCiphers (1.1): -> Abort '$host:$port' caused by ".OSaft::error_handler->get_err_str."\n");
                    carp   ("**WARNING: checkAllCiphers (1.1): -> Abort '$host:$port'");
                    last;
                }
                _trace(" $ssl: tested ciphers: " . scalar(@testing) . ", accepted: " . (scalar(@accepted) - (scalar(@accepted) >= 2  && ($accepted[0] eq $accepted[1]) )) . "\n");  # delete 1 when the first 2 ciphers are identical (this indicates an Order by the Server)
                _v_print(" $ssl: tested ciphers: " . scalar(@testing) . ", accepted: " . (scalar(@accepted) - (scalar(@accepted) >= 2  && ($accepted[0] eq $accepted[1]) )) );  # delete 1 when the first 2 ciphers are identical (this indicates an Order by the Server)
                _trace("accepted ciphers: @accepted\n");
                Net::SSLhello::printCipherStringArray ($cfg{'legacy'}, $host, $port, $ssl, 0, @accepted);
                $Net::SSLhello::usesni=$cfg{'usesni'}; # restore
            }
            next if ($ssl eq 'SSLv2');# SSLv2 has no SNI
            next if ($ssl eq 'SSLv3');# SSLv3 has originally no SNI
#            next if ($ssl eq 'DTLSv09');# DTLSv09 has originally no SNI(??)
        }
        @accepted = Net::SSLhello::checkSSLciphers ($host, $port, $ssl, @testing);
        if ((OSaft::error_handler->get_err_type()) <= (OERR_SSLHELLO_RETRY_HOST)) { # severe error
            _trace ("**WARNING: checkAllCiphers (1.2): -> Abort '$host:$port' caused by ".OSaft::error_handler->get_err_str."\n");
            carp   ("**WARNING: checkAllCiphers (1.2): -> Abort '$host:$port'");
            last;
        }
        _trace(" $ssl: tested ciphers: " . scalar(@testing) . ", accepted: " . (scalar(@accepted) - (scalar(@accepted) >= 2  && ($accepted[0] eq $accepted[1]) )) . "\n");  # delete 1 when the first 2 ciphers are identical (this indicates an Order by the Server)
        _v_print(" $ssl: tested ciphers: " . scalar(@testing) . ", accepted: " . (scalar(@accepted) - (scalar(@accepted) >= 2  && ($accepted[0] eq $accepted[1]) )) );  # delete 1 when the first 2 ciphers are identical (this indicates an Order by the Server)
        _trace("accepted ciphers: @accepted\n");
        Net::SSLhello::printCipherStringArray ($cfg{'legacy'}, $host, $port, $ssl, $Net::SSLhello::usesni, @accepted);
    }
    _trace("host}" . "\n");
}

exit;
