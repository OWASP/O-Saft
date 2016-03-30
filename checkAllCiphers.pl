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

my $VERSION = "2016-03-26";
our $me     = $0; $me     =~ s#.*(?:/|\\)##;
our $mepath = $0; $mepath =~ s#/[^/\\]*$##;
    $mepath = "./" if ($mepath eq $me);
our $mename = "checkAllCiphers";
    $mename = "O-Saft " if ($me !~ /checkAllCiphers/);

sub printhelp() {
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
    --proxypass=PROXYPASS (not yet implemented)S
                passowrd to authenticate at PROXYUSER
    --mx        make a MX-Record DNS lookup for the mx-domain-name
                (makes sense together with --STARTTLS=SMTP)
    --SSL       test for this SSL version
                SSL is any of: sslv2, sslv3, tlsv1, tlsv11, tlsv12, tlsv13, dtlsv09, dtlsv1, (dtlsv11), dtlsv12, dtlsv13
                (e.g. --dtlsv12; default: sslv2, sslv3, tlsv1, tlsv11, tlsv12, tlsv13)A
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
                You can use the STARTTLS_TYPE 'CUSTOM' to customize your own STARTTLS sequence including error handling, see '--starttls_phase[NUMBER]' and --starttls_error[NUMBER]
    --starttls_delay=SEC
                seconds to pause before sending a packet, to slow down the starttls-requests (default = 0).
                This may prevent a blockade of requests due to too much/too fast connections.
                (Info: In this case there is an automatic suspension and retry with a longer delay)
    --starttls_phase[NUMBER from 1..5]="VALUE" (VALUE might be an expression or a string)
                Customize the internal state machine to manage STARTTLS, you can use up to 5 phases:
                 1: set expression for 'receive data (RX)', e.g. ".?(?:^|\\n)220\\s"
                 2: set string for 'send data (TX)',        e.g. "EHLO o-saft.localhost\\r\\n"
                 3: set expression for RX,                  e.g. ".?(?:^|\\n)250\\s"
                 4: set string for TX,                      e.g. "STARTTLS\\r\\n"
                 5: set expression for RX,                  e.g. ".?(?:^|\\n)220\\s"
                For the TX phases 2 and 4 solely the escape sequences '\\r', '\\n', '\\t' and '\\x<00-ff>' are supported, e.g. "\\r\\n", "\\x0d\\x0a"
                It is recommended to use at least TX and RX (last RX to get data that does not belong to the handshake of SSL/TLS itself), furthermore you should use '--trace=3' when you start customizing.
                Please share your results with us (o-saft (at) lists.owasp.org or via github).
                needs also '--starttls=CUSTOM', see above
                optional use of '--starttls_error[NUMBER]' to handle errors
    --starttls_error[NUMBER from 1..3]="EXPRESSION" (or '--starttls_err[NUMBER from 1..3]="EXPRESSION")
                Optional error handling for customized STARTTLS used in the RX phases (1, 3 and 5)
                 1: set expression for 'temporary unreachable (too many connections)', e.g. ".?(?:^|\\n)(?:421|450)\\s"
                 2: set expression for 'this SSL/TLS-Protocol is not supported',       e.g. ".?(?:^|\\n)4[57]4\\s"
                 3: set exptession for 'fatal Error/STARTTLS not supported',           e.g. ".*?(?:^|\\n)(?:451|50[023]|554)\\s"
                needs also '--starttls=CUSTOM' and '--starttls_phase[NUMBER]', see above
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
} # printhelp

if (! eval("require 'o-saft-dbx.pm';")) {
    # o-saft-dbx.pm may not be installed, try to find in program's directory
    push(@INC, $mepath);
    require("o-saft-dbx.pm");
}

if (! eval("require Net::SSLhello;")) {
    # Net::SSLhello may not be installed, try to find in program's directory
    push(@INC, $mepath);
    require Net::SSLhello;
}

my $arg = "";
# array to collect data fordebugging, they are global!
our @dbxarg;    # normal options and arguments
our @dbxcfg;    # config options and arguments
our @dbxexe;    # executable, library, environment
our @dbxfile;   # read files

my @argv = grep(/--trace.?arg/, @ARGV);# preserve --tracearg option
push(@argv, @ARGV);
#dbx# _dbx "ARG: " . join(" ", @argv);

# read file with source for trace and verbose, if any
# -------------------------------------
my @dbx = grep(/--(?:trace|v$|yeast)/, @argv);  # option can be in .rc-file, hence @argv
if ($#dbx >= 0) {
    $arg =  "./o-saft-dbx.pm";
    $arg =  $dbx[0] if ($dbx[0] =~ m#/#);
    $arg =~ s#[^=]+=##; # --trace=./myfile.pl
    if (! -e $arg) {
        warn "**WARNING: '$arg' not found";
        $arg = join("/", $mepath, $arg);    # try to find it in installation directory
        die  "**ERROR: '$!' '$arg'; exit" unless (-e $arg);
        # no need to continue if required file does not exist
        # Note: if $mepath or $0 is a symbolic link, above checks fail
        #       we don't fix that! Workaround: install file in ./
    }
    push(@dbxfile, $arg);
    printf("=== reading trace file ===\n") if(grep(/(:?--no.?header)/i, @ARGV) <= 0);
    require $arg;   # `our' variables are available there
}

# initialize defaults
my ($key,$sec,$ssl);# some temporary variables used in main
my $host    = "";   # the host currently processed in main
my $port    = 443;  # the port currently used in main
   # above host, port, legacy and verbose are just shortcuts for corresponding
   # values in $cfg{}, used for better human readability

our %cfg = ( # from o-saft (only relevant parts)
   # config. key        default   description
   #------------------+---------+----------------------------------------------
    'try'           => 0,       # 1: do not execute openssl, just show
    'exec'          => 0,       # 1: if +exec command used
    'experimental'  => 0,       # 1: if experimental functions should be used
    'trace'         => 0,       # 1: trace yeast, 2=trace Net::SSLeay and Net::SSLhello also
    'traceARG'      => 0,       # 1: trace yeast's argument processing
    'traceCMD'      => 0,       # 1: trace command processing
    'traceKEY'      => 0,       # 1: (trace) print yeast's internal variable names
    'traceTIME'     => 0,       # 1: (trace) print additional time for benchmarking
    'verbose'       => 0,       # used for --v
    'proxyhost'     => "",      # FQDN or IP of proxy to be used
    'proxyport'     => 0,       # port for proxy
    'proxyauth'     => "",      # authentication string used for proxy
    'proxyuser'     => "",      # username for proxy authentication (Basic or Digest Auth)
    'proxypass'     => "",      # password for proxy authentication (Basic or Digest Auth)
    'enabled'       => 0,       # 1: only print enabled ciphers
    'disabled'      => 0,       # 1: only print disabled ciphers
    'nolocal'       => 0,
    'usedns'        => 1,       # 1: make DNS reverse lookup
    'usemx'         => 0,       # 1: make MX-Record DNS lookup
    'usehttp'       => 1,       # 1: make HTTP request
    'forcesni'      => 0,       # 1: do not check if SNI seems to be supported by Net::SSLeay
    'usesni'        => 1,       # 0: do not make connection in SNI mode, 1: use SNI extension (if protocol >= tlsv1), 2: toggle-sni (check without and with SNI)
    'use_sni_name'  => 0,       # 0: use hostname (default), 1: use sni_name for SNI mode connections
    'sni_name'      => "1",     # name to be used for SNI mode connection; hostname if usesni=1; temp/tbd: Default is "1" until migration of o-saft.pl to additionally set 'use_sni_name'=1 will be done
    'version'       => [],      # contains the versions to be checked
    'versions'      => [qw(SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 TLSv13 DTLSv09 DTLSv1 DTLSv11 DTLSv12 DTLSv13)], #added TLSv13
    'SSLv2'         => 1,       # 1: check this SSL version
    'SSLv3'         => 1,       # 1:   "
    'TLSv1'         => 1,       # 1:   "
    'TLSv11'        => 1,       # 1:   "
    'TLSv12'        => 1,       # 1:   "
    'TLSv13'        => 1,       # 1:   " # added
    'DTLSv09'       => 0,       # 1:   "TBD: different to o-saft, change it there TBD!!
    'DTLSv1'        => 0,       # 1:   "TBD: different to o-saft, change it there TBD
    'DTLSv11'       => 0,       # 1:   "
    'DTLSv12'       => 0,       # 1:   "
    'DTLSv13'       => 0,       # 1:   "
    'nullssl2'      => 0,       # 1: complain if SSLv2 enabled but no ciphers accepted
    'cipherrange'   => 'rfc',   # the range to be used from 'cipherranges'
    'cipherranges'  => {        # constants for ciphers (NOTE: written as hex)
                                # Technical (perl) note for definition of these ranges:
                                # Each range is defined as a string like  key=>"2..5, c..f"
                                # instead of an array like  key=>[2..5, c..f]  which would
                                # result in  key=>[2 3 4 5 c d e f].
                                # This expansion of the range is done at compile time  and
                                # so will consume a huge amount of memory at runtime.
                                # Using a string instead of the expanded array reduces the
                                # memory footprint,  but requires use of  eval()  when the
                                # range is needed:  eval($cfg{cipherranges}->{rfc})
                                # Each string must be syntax for perl's range definition.
        'yeast'     => "",      # internal list, computed later ...
                                # push(@all, @{$_}[0]) foreach (values %cipher_names);
        'rfc'       =>          # constants for ciphers defined in various RFCs
                       "0x03000000 .. 0x030000FF, 0x0300C000 .. 0x0300C0FF,
                        0x0300CC00 .. 0x0300CCFF, 0x0300FE00 .. 0x0300FFFF,
                       ",
        'shifted'   =>          # constants for ciphers defined in various RFCs shifted with an offset of 64 (=0x40) Bytes
                       "0x03000100 .. 0x0300013F, 0x03000000 .. 0x030000FF, 0x0300C000 .. 0x0300C0FF,
                        0x0300CC00 .. 0x0300CCFF, 0x0300FE00 .. 0x0300FFFF,
                       ",
        'long'      =>          # more lazy list of constants for cipher
                       "0x03000000 .. 0x030000FF, 0x0300C000 .. 0x0300FFFF,
                       ",
        'full'      =>          # full range of constants for cipher
                       "0x03000000 .. 0x0300FFFF,
                       ",
        'SSLv2'     =>          # constants for ciphers according RFC for SSLv2
                       "0x02010080,   0x02020080, 0x02030080, 0x02040080, 0x02050080,
                        0x02060040,   0x02060140, 0x020700C0, 0x020701C0,
                        0x02FF0810,   0x02FF0800, 0x02FFFFFF,             # obsolete SSLv2 Ciphers
                        0x03000000 .. 0x0300002C, 0x030000FF,             # old SSLv3 Cuiphers
                        0x0300FEE0,   0x0300FEE1, 0x0300FEFE, 0x0300FEFF, # obsolete FIPS Ciphers
                       ",
        'SSLv2_long'=>          # more lazy list of constants for ciphers for SSLv2
                       "0x02010080,   0x02020080, 0x02030080, 0x02040080, 0x02050080,
                        0x02060040,   0x02060140, 0x020700C0, 0x020701C0,
                        0x02FF0810,   0x02FF0800, 0x02FFFFFF,             # obsolete SSLv2 Ciphers
                        0x03000000 .. 0x0300002F, 0x030000FF,             # old SSLv3 Cuiphers 
                        0x0300FEE0,   0x0300FEE1, 0x0300FEFE, 0x0300FEFF, # obsolete FIPS Ciphers
                       ",
    }, # cipherranges

    'out_header'       => 0,    # print header lines in output
    'mx_domains'       => [],   # list of mx-domains:port to be processed
    'hosts'            => [],   # list of hosts:port to be processed
    'host'             => "",   # currently scanned host
    'ip'               => "",   # currently scanned host's IP
    'IP'               => "",   # currently scanned host's IP (human readable, doted octed)
    'rhost'            => "",   # currently scanned host's reverse resolved name
    'DNS'              => "",   # currently scanned host's other IPs and names (DNS aliases)
    'port'             => 443,  # port for currently used connections
    'timeout'          => 2,    # default timeout in seconds for connections
                                # NOTE that some servers do not connect SSL within this time
                                #      this may result in ciphers marked as  "not supported"
                                #      it's recommended to set timeout to 3 or higher, which
                                #      results in a performance bottleneck, obviously
    'slowServerDelay'  => 0,    # time to wait in seconds after a connection via proxy or before starting the STARTTLS sequence
    'starttlsDelay'    => 0,    # STARTTLS: time to wait in seconds (to slow down the requests)
    'starttlsPhaseArray' => [], # STARTTLS: Array for CUSTOMized starttls sequences including error handling)
    #} +---------+----------------------+-------------------------
    'sslhello' => {    # configurations for TCP SSL protocol
        'timeout'      => 2,    # timeout to receive ssl-answer
        'retry'        => 2,    # number of retry when timeout
        'maxciphers'   => 64,   # number of ciphers sent in SSL3/TLS Client-Hello
        'usereneg'     => 0,    # 0: do not send reneg_info Extension
        'useecc'       => 1,    # 1: use supported elliptic curves
        'useecpoint'   => 1,    # 1: use ec_point_formats extension
        'double_reneg' => 0,    # 0: do not send reneg_info Extension if the cipher_spec already includes SCSV (be polite according RFC5746)
                                #    "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" {0x00, 0xFF}
        'noDataEqNoCipher'=> 1, # 1: no Data is Equal to no (supported) Cipher in ServerHellos
    },
    'legacy'        => "compact", # FIXME: simple
    'legacys'       => [qw(cnark sslaudit sslcipher ssldiagnos sslscan
                        ssltest ssltest-g sslyze testsslserver tchsslcheck
                        simple full compact quick)],
    'showhost'      => 0,       # 1: prefix printed line with hostname
   #------------------+---------+----------------------------------------------
    'openssl_option_map' => {   # map our internal option to openssl option
        'SSLv2'     => "-ssl2",
        'SSLv3'     => "-ssl3",
        'TLSv1'     => "-tls1",
        'TLSv11'    => "-tls1_1",
        'TLSv12'    => "-tls1_2",
        'TLSv13'    => "-tls1_3",
        'DTLSv1'    => "-dtls1",
        'DTLSv11'   => "-dtls1_1",
        'DTLSv12'   => "-dtls1_2",
        'DTLSv13'   => "-dtls1_3",
     },
    'openssl_version_map' => {  # map our internal option to openssl version (hex value)
        'SSLv2'     => 0x0002,
        'SSLv3'     => 0x0300,
        'TLSv1'     => 0x0301,
        'TLSv11'    => 0x0302,
        'TLSv12'    => 0x0303,
        'TLSv13'    => 0x0304,
        'DTLSv1'    => 0xFEFF,
        'DTLSv11'   => 0xFEFE,
        'DTLSv12'   => 0xFEFD,
        'DTLSv13'   => 0xFEFC,
        'SCSV'      => 0x03FF,
     },
);

my %text = (
    'separator' => ":", # separator character between label and value
);

# scan options and arguments
# -------------------------------------
while ($#argv >= 0) {
    $arg = shift @argv;
    push(@dbxarg, $arg) if (($arg !~ m/^--cfg_/) && ($arg =~ m/^[+-]/));
    push(@dbxcfg, $arg) if  ($arg =~ m/^--cfg_/);    # both aprox. match are sufficient for debugging
    if ($arg !~ /([+]|--)(cmd|host|port|exe|lib|cipher|format|legacy|timeout|url)=/) {
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
    if ($arg =~ /^--h(?:elp)?(?:=(.*))?$/i)             { printhelp(); exit 0;   next; } # allow --h --help --h=*
    if ($arg =~ /^\+help=?(.*)$/i)                      { printhelp(); exit 0;   next; } # allow +help +help=*
    if ($arg =~ /^--v(erbose)?$/i)                      { $cfg{'verbose'}++;     next; }
    if ($arg =~ /^--n$/i)                               { $cfg{'try'}       = 1; next; }
    if ($arg =~ /^--trace$/i)                           { $cfg{'trace'}++;       next; }
    if ($arg =~ /^--trace(--|[_-]?arg)$/i)              { $cfg{'traceARG'}++;    next; } # special internal tracing
    if ($arg =~ /^--trace([_-]?cmd)$/i)                 { $cfg{'traceCMD'}++;    next; } # ..
    if ($arg =~ /^--trace(@|[_-]?key)$/i)               { $cfg{'traceKEY'}++;    next; } # ..
    if ($arg =~ /^--trace=(\d+)$/i)                     { $cfg{'trace'}    = $1; next; }
    if ($arg =~ /^--trace([_-]?time)$/i)                { $cfg{'traceTIME'}++;   next; } # Timestamp on
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
    if ($arg =~ /^--starttls[_-]?phase\[(\d)\]=(.+)$/i){ $cfg{'starttlsPhaseArray'}[$1] = $2 if (($1 >0) && ($1<=5)); next; } # starttl, CUSTOM starttls-sequence 
    if ($arg =~ /^--starttls[_-]?err(?:or)?\[(\d)\]=(.+)$/i){ $cfg{'starttlsPhaseArray'}[($1+5)] = $2 if (($1 >0) && ($1<=3)); next; } # starttls, error-handling for CUSTOMized starttls
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
    if ($arg =~ /^--(?:dns[_-]?)?mx$/i)                 { eval {require Net::DNS;}; # this command needs an additional Perl Module
                                                          unless ($@) { $cfg{'usemx'}= 1; # no error
                                                                      } else { warn ("$me: Perl Module 'NET::DNS' is not installed, opition '$arg' ignored: $@");
                                                                      }         next; }
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
    if ($arg =~ /^--no[_-]?nodata(?:eq)?nocipher$/i)    { $cfg{'sslhello'}->{'noDataEqNoCipher'} = 0; next; } # alias ...
    if ($arg =~ /^--no[_-]?ssl[_-]?nodata(?:eq)?nocipher$/i){ $cfg{'sslhello'}->{'noDataEqNoCipher'} = 0; next; }
    if ($arg =~ /^--ssl[_-]?nodataneqnocipher$/i)       { $cfg{'sslhello'}->{'noDataEqNoCipher'} = 0; next; } # alias ...
    if ($arg =~ /^--nodataneqnocipher$/i)               { $cfg{'sslhello'}->{'noDataEqNoCipher'} = 0; next; } # alias
    if ($arg =~ /^--ssl[_-]?nodata(?:eq)?nocipher$/i)   { $cfg{'sslhello'}->{'noDataEqNoCipher'} = 1; next; }
    if ($arg =~ /^--nodata(?:eq)?nocipher$/i)           { $cfg{'sslhello'}->{'noDataEqNoCipher'} = 1; next; } # alias
    if ($arg =~ /^--?experimental$/i)                   { $cfg{'experimental'}                   = 1; next; }
    #} +---------+----------------------+-------------------------

    if ($arg =~ /^[+-]/) {
        warn "**WARNING: unknown command or option '$arg' ignored. Try '$me --help' to get more information!";
        next;
    }
    push(@{$cfg{'hosts'}}, $arg . ":" . ($cfg{'port'}||443));
} # while

# set defaults for Net::SSLhello
# -------------------------------------
{
    no warnings qw(once); # avoid: Name "Net::SSLhello::trace" used only once: possible typo at ...
    $Net::SSLhello::trace           = $cfg{'trace'} if ($cfg{'trace'} > 0);
    $Net::SSLhello::usesni          = $cfg{'usesni'};
    $Net::SSLhello::use_sni_name    = $cfg{'use_sni_name'};
    $Net::SSLhello::sni_name        = $cfg{'sni_name'};
    $Net::SSLhello::starttls        = $cfg{'starttls'};
    $Net::SSLhello::starttlsType    = $cfg{'starttlsType'}; 
    @Net::SSLhello::starttlsPhaseArray  = @{$cfg{'starttlsPhaseArray'}};
    if ($cfg{'trace'} > 3) {
        for my $i (1..8) {
            _trace ("  \$cfg{'starttlsPhaseArray'}[$i]=$cfg{'starttlsPhaseArray'}[$i]\n") if (defined($cfg{'starttlsPhaseArray'}[$i]));
            _trace ("  starttlsPhaseArray[$i]=$Net::SSLhello::starttlsPhaseArray[$i]\n")  if (defined($Net::SSLhello::starttlsPhaseArray[$i]));
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
    $Net::SSLhello::noDataEqNoCipher    = $cfg{'sslhello'}->{'noDataEqNoCipher'};
}

print "##############################################################################\n";
print "# '$me' (part of OWASP project 'O-Saft'), Version: $VERSION\n";
print "#                          ";
Net::SSLhello::version();
print "##############################################################################\n\n";

$@="";
print "Protocols to check:\n";
# check ssl protocols
foreach $ssl (@{$cfg{'versions'}}) {
    if ( ($ssl =~ /DTLS/) && ($cfg{$ssl} == 1) && ($cfg{'experimental'} !=1 ) ) { # DTLS support is experimental
        $@ .= ", " if ($@);
        $@ .= "$ssl";
        next;
    }
    next if ($cfg{$ssl} != 1); #  = 0 or undefined
    print "$ssl\n"; 
    push(@{$cfg{'version'}}, $ssl);
}
print "Use of Protocol(s) '$@' is experimental, please use the option '--experimental' and take care.\n" if ($@);
$@="";
print "\n";

if ($cfg{'usemx'}) { # get mx-records
    _trace2 (" \$cfg{'usemx'} = $cfg{'usemx'}\n");
    print "\n# get MX-Records:\n";
    @{$cfg{'mx_domains'}} = @{$cfg{'hosts'}}; #we have got mx domains no hosts, yet
    $cfg{'hosts'} = [];

    my $mx_domain;

    foreach $mx_domain (@{$cfg{'mx_domains'}}) {  # loop domains
        if ($mx_domain =~ m#.*?:\d+#) { 
            ($mx_domain, $port) = split(":", $mx_domain); 
        }
        _trace3 (" get MX-Records for '$mx_domain'\n");
        my $dns = new Net::DNS::Resolver;
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

foreach $host (@{$cfg{'hosts'}}) {  # loop hosts
    if ($host =~ m#.*?:\d+#) { 
       ($host, $port) = split(":", $host);
        $cfg{'port'}  = $port;  #
        $cfg{'host'}  = $host;
    }
    _trace("host{ " . ($host||"") . ":" . $port . "\n");
    $? = 0;
    $cfg{'host'} = $host;
    $Net::SSLhello::starttlsDelay = $cfg{'starttlsDelay'}; #reset to original value for each host 
    foreach $ssl (@{$cfg{'version'}}) {
        my @accepted = (); # List of all Ciphers that are supported by the server with the tested Protocol
        my @testing  = ();
        my $range = $cfg{'cipherrange'};            # use specified range of constants
           $range = 'SSLv2' if ($ssl eq 'SSLv2');   # but SSLv2 needs its own list: SSLV2+SSLV3-Ciphers
        push(@testing, sprintf("0x%08X",$_)) foreach (eval($cfg{'cipherranges'}->{$range}));
        if ($Net::SSLhello::usesni) { # usesni (--sni: 1 or --togglesni: 2) is set 
            if ( ($Net::SSLhello::usesni > 1) || ($ssl eq 'SSLv2') || ($ssl eq 'SSLv3') ) { # toggle SNI (2): test first without sni, old protocols: test solely without SNI
                $Net::SSLhello::usesni = 0;
                @accepted = Net::SSLhello::checkSSLciphers ($host, $port, $ssl, @testing);
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
        _trace(" $ssl: tested ciphers: " . scalar(@testing) . ", accepted: " . (scalar(@accepted) - (scalar(@accepted) >= 2  && ($accepted[0] eq $accepted[1]) )) . "\n");  # delete 1 when the first 2 ciphers are identical (this indicates an Order by the Server)
        _v_print(" $ssl: tested ciphers: " . scalar(@testing) . ", accepted: " . (scalar(@accepted) - (scalar(@accepted) >= 2  && ($accepted[0] eq $accepted[1]) )) );  # delete 1 when the first 2 ciphers are identical (this indicates an Order by the Server)
        _trace("accepted ciphers: @accepted\n");
        Net::SSLhello::printCipherStringArray ($cfg{'legacy'}, $host, $port, $ssl, $Net::SSLhello::usesni, @accepted);
    }
    _trace("host}" . "\n");
}

exit;
