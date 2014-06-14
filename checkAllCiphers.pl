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

my $VERSION = "2014-06-14";
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
    $me [OPTIONS] hostname

OPTIONS
    --help      nice option
    --host=HOST add HOST to list of hosts to be checked
    -h=HOST     dito.
    --port=PORT use PORT for following hosts
    -h=PORT     dito.
    --SSL       test for this SSL version
                SSL is any of: sslv2, sslv3, tlsv1, tlsv11, tlsv12, tlsv13
    --no-SSL    do not test for this SSL version
                SSL see --SSL  option
    --legacy=L  use format L in printed results
                available formarts: compact, simple, full
    --sni       test in SNI mode also (default)
    --no-sni    do not test in SNI mode
    --ssl-retry=CNT
                number of retries for connects, if timed-out
    --ssl-timeout=SEC
                timeout in seconds for connects
    --ssl-usereneg
                use secure renegotion
    --ssl-doubel-reneg
                use renegotion SSL Extension also for SCSV (double send)
    --proxyhost=PROXYHOST
                make connection through proxy on PROXYHOST
    --proxyport=PROXYPORT
                make connection through proxy on PROXYHOST:PROXYPORT
    --proxyuser=PROXYUSER
                user to authenticate at PROXYHOST
    --proxypass=PROXYPASS
                passowrd to authenticate at PROXYUSER

DESCRIPTION
    This is just a very simple wrapper for the Net::SSLhello module to test
    a target for all available ciphers. It is a shortcut for
	o-saft.pl +cipherraw YOUR-HOST

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
    'trace'         => 0,       # 1: trace yeast, 2=trace Net::SSLeay and Net::SSLhello also
    'traceARG'      => 0,       # 1: trace yeast's argument processing
    'traceCMD'      => 0,       # 1: trace command processing
    'traceKEY'      => 0,       # 1: (trace) print yeast's internal variable names
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
    'usehttp'       => 1,       # 1: make HTTP request
    'forcesni'      => 0,       # 1: do not check if SNI seems to be supported by Net::SSLeay
    'usesni'        => 1,       # 0: do not make connection in SNI mode;
    'version'       => [],      # contains the versions to be checked
    'versions'      => [qw(SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 TLSv13 DTLSv1)], #added TLSv13
    'SSLv2'         => 1,       # 1: check this SSL version
    'SSLv3'         => 1,       # 1:   "
    'TLSv1'         => 1,       # 1:   "
    'TLSv11'        => 1,       # 1:   "
    'TLSv12'        => 1,       # 1:   "
    'TLSv13'        => 1,       # 1:   " # added
    'DTLSv9'        => 0,       # 1:   "
    'DTLSv1'        => 1,       # 1:   "
    'nullssl2'      => 0,       # 1: complain if SSLv2 enabled but no ciphers accepted
    'cipherrange'   => 'rfc',   # the range to be used from 'cipherranges'
    'cipherranges'  => {        # constants for ciphers (Note: written as hex)
        'yeast'     => [],      # internal list, computed later ...
                                # push(@all, @{$_}[0]) foreach (values %cipher_names);
        'rfc'       => [        # constants for ciphers defined in various RFCs
                        0x03000000 .. 0x030000FF, 0x0300C000 .. 0x0300C0FF,
                        0x0300CC00 .. 0x0300CCFF, 0x0300FE00 .. 0x0300FFFF,
                       ],
        'long'      => [        # more lazy list of constants for cipher
                        0x03000000 .. 0x030000FF, 0x0300C000 .. 0x0300FFFF,
                       ],
        'full'      => [        # full range of constants for cipher
                        0x03000000 .. 0x0300FFFF,
                       ],
        'SSLv2'     => [        # constants for ciphers according RFC for SSLv2
                        0x02000000,   0x02010080, 0x02020080, 0x02030080, 0x02040080,
                        0x02050080,   0x02060040, 0x02060140, 0x020700C0, 0x020701C0,
                        0x02FF0810,   0x02FF0800, 0x02FFFFFF,
                        0x03000001,   0x03000002, 0x03000007 .. 0x0300002C,
                        0x030000FF,
                       ],
        'SSLv2_long'=> [        # more lazy list of constants for ciphers for SSLv2
                        0x02000000,   0x02010080, 0x02020080, 0x02030080, 0x02040080,
                        0x02050080,   0x02060040, 0x02060140, 0x020700C0, 0x020701C0,
                        0x02FF0810,   0x02FF0800, 0x02FFFFFF,
                        0x03000000 .. 0x0300002F, 0x030000FF,
                       ],
    }, # cipherranges

    'out_header'    => 0,       # print header lines in output
    'hosts'         => [],      # list of hosts:port to be processed
    'host'          => "",      # currently scanned host
    'ip'            => "",      # currently scanned host's IP
    'IP'            => "",      # currently scanned host's IP (human readable, doted octed)
    'rhost'         => "",      # currently scanned host's reverse resolved name
    'DNS'           => "",      # currently scanned host's other IPs and names (DNS aliases)
    'port'          => 443,     # port for currently used connections
    'timeout'       => 2,       # default timeout in seconds for connections
                                # NOTE that some servers do not connect SSL within this time
                                #      this may result in ciphers marked as  "not supported"
                                #      it's recommended to set timeout to 3 or higher, which
                                #      results in a performance bottleneck, obviously
    'sslhello' => {    # configurations for TCP SSL protocol
        'timeout'   => 2,       # timeout to receive ssl-answer
        'retry'     => 3,       # number of retry when timeout
        'usereneg'  => 0,       # 0: do not send reneg_info Extension
        'double_reneg'  => 0,   # 0: do not send reneg_info Extension if the cipher_spec already includes SCSV (be polite according RFC5746)
                                #    "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" {0x00, 0xFF}
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
     },
    'openssl_version_map' => {  # map our internal option to openssl version (hex value)
        'SSLv2'     => 0x0002,
        'SSLv3'     => 0x0300,
        'TLSv1'     => 0x0301,
        'TLSv11'    => 0x0302,
        'TLSv12'    => 0x0303,
        'TLSv13'    => 0x0304,
        'DTLSv1'    => 0xFEFF,
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
    if ($arg eq   '--http')             { $cfg{'usehttp'}++;     } # must be before --h
    if ($arg =~ /^--no[_-]?http$/)      { $cfg{'usehttp'}   = 0; }
    if ($arg =~ /^--h(?:elp)?(?:=(.*))?$/)  { printhelp(); exit 0; } # allow --h --help --h=*
    if ($arg =~ /^\+help=?(.*)$/)           { printhelp(); exit 0; } # allow +help +help=*
    if ($arg =~ /^--v(erbose)?$/)       { $cfg{'verbose'}++;     }
    if ($arg eq  '--n')                 { $cfg{'try'}       = 1; }
    if ($arg eq  '--trace')             { $cfg{'trace'}++;       }
    if ($arg =~ /^--trace(--|[_-]?arg)/){ $cfg{'traceARG'}++;    } # special internal tracing
    if ($arg =~ /^--trace([_-]?cmd)/)   { $cfg{'traceCMD'}++;    } # ..
    if ($arg =~ /^--trace(@|[_-]?key)/) { $cfg{'traceKEY'}++;    } # ..
    if ($arg =~ /^--trace=(.*)/)        { $cfg{'trace'}    = $1; }
    if ($arg =~ /^--?p(?:ort)?=(.*)/)   { $cfg{'port'}     = $1; }
    if ($arg =~ /^--?h(?:ost)?=(.*)/)   { push(@{$cfg{'hosts'}}, $1 . ":" . ($cfg{'port'}||443)); }     
    # proxy optionms
    if ($arg =~  '--proxyhost=(.*)')    { $cfg{'proxyhost'}= $1; }
    if ($arg =~  '--proxyport=(.*)')    { $cfg{'proxyport'}= $1; }
    if ($arg =~  '--proxyuser=(.*)')    { $cfg{'proxyuser'}= $1; }
    if ($arg =~  '--proxypass=(.*)')    { $cfg{'proxypass'}= $1; }
    if ($arg =~  '--proxyauth=(.*)')    { $cfg{'proxyauth'}= $1; }
    if ($arg =~ /^--?starttls$/i)       { $cfg{'starttls'}  = 1; } # starttls
    # options
    if ($arg eq  '--sni')               { $cfg{'usesni'}    = 1; }
    if ($arg =~ /^--no[_-]?sni/)        { $cfg{'usesni'}    = 0; }
    if ($arg eq  '--header')            { $cfg{'out_header'}= 1; }
    if ($arg =~ /^--no[_-]?header$/)    { $cfg{'out_header'}= 0; push(@ARGV, "--no-header"); next; } # push() is ugly hack to preserve option even from rc-file
    if ($arg =~ /^--?sslv?2$/i)         { $cfg{'SSLv2'}     = 1; } # allow case insensitive
    if ($arg =~ /^--?sslv?3$/i)         { $cfg{'SSLv3'}     = 1; } # ..
    if ($arg =~ /^--?tlsv?1$/i)         { $cfg{'TLSv1'}     = 1; } # ..
    if ($arg =~ /^--?tlsv?1[-_.]?1$/i)  { $cfg{'TLSv11'}    = 1; } # allow ._- separator
    if ($arg =~ /^--?tlsv?1[-_.]?2$/i)  { $cfg{'TLSv12'}    = 1; } # ..
    if ($arg =~ /^--dtlsv?0[-_.]?9$/i)  { $cfg{'DTLSv9'}    = 1; } # ..
    if ($arg =~ /^--dtlsv?1[-_.]?0?$/i) { $cfg{'DTLSv1'}    = 1; } # ..
    if ($arg =~ /^--no[_-]?sslv?2$/i)   { $cfg{'SSLv2'}     = 0; } # allow _- separator
    if ($arg =~ /^--no[_-]?sslv?3$/i)   { $cfg{'SSLv3'}     = 0; } # ..
    if ($arg =~ /^--no[_-]?tlsv?1$/i)   { $cfg{'TLSv1'}     = 0; } # ..
    if ($arg =~ /^--no[_-]?tlsv?11$/i)  { $cfg{'TLSv11'}    = 0; } # ..
    if ($arg =~ /^--no[_-]?tlsv?12$/i)  { $cfg{'TLSv12'}    = 0; } # ..
    if ($arg =~ /^--no[_-]?tlsv?13$/i)  { $cfg{'TLSv13'}    = 0; } # ..
    if ($arg =~ /^--no[_-]?dtlsv?09$/i) { $cfg{'DTLSv9'}    = 0; } # ..
    if ($arg =~ /^--no[_-]?dtlsv?10?$/i){ $cfg{'DTLSv1'}    = 0; } # ..
    if ($arg =~ /^--nullsslv?2$/i)      { $cfg{'nullssl2'}  = 1; } # ..
    if ($arg =~ /^--no[_-]?dns/)        { $cfg{'usedns'}    = 0; }
    if ($arg eq  '--dns')               { $cfg{'usedns'}    = 1; }
    if ($arg eq  '--enabled')           { $cfg{'enabled'}   = 1; }
    if ($arg eq  '--disabled')          { $cfg{'disabled'}  = 1; }
    if ($arg eq  '-printavailable')     { $cfg{'enabled'}   = 1; } # ssldiagnos
    if ($arg eq  '--showhost')          { $cfg{'showhost'}  = 1; }
    if ($arg =~ /^--?no[_-]failed$/)    { $cfg{'enabled'}   = 0; } # sslscan
    if ($arg =~ /^--range=(.*)/)        { $cfg{'cipherrange'}=$1;}
    if ($arg =~ /^--cipherrange=(.*)/)  { $cfg{'cipherrange'}=$1;}
    if ($arg =~ /^--legacy=(.*)/)       { $cfg{'legacy'}   = $1; }
    if ($arg =~ /^--tab$/)          { $text{'separator'} = "\t"; } # TAB character
    if ($arg =~ /^--ssl[_-]?retry=(.*)/){ $cfg{'sslhello'}->{'retry'}=$1;}
    if ($arg =~ /^--ssl[_-]?timeout=(.*)/)  {$cfg{'sslhello'}->{'timeout'}=$1;}
    if ($arg =~ /^--ssl[_-]?usereneg=(.*)/) {$cfg{'sslhello'}->{'usereneg'}=$1;}
    if ($arg =~ /^--ssl[_-]?double[_-]?reneg/)  {$cfg{'sslhello'}->{'double_reneg'}=1;}
    #} +---------+----------------------+-------------------------

    next if ($arg =~ /^[+-]/); # quick&dirty
    push(@{$cfg{'hosts'}}, $arg . ":" . ($cfg{'port'}||443));     

} # while

# set defaults for Net::SSLhello
# -------------------------------------
{
    no warnings qw(once); # avoid: Name "Net::SSLhello::trace" used only once: possible typo at ...
    $Net::SSLhello::trace       = $cfg{'trace'} if ($cfg{'trace'} > 0);
    $Net::SSLhello::usesni      = $cfg{'usesni'};
    $Net::SSLhello::starttls    = 0;
    $Net::SSLhello::timeout     = $cfg{'sslhello'}->{'timeout'};
    $Net::SSLhello::retry       = $cfg{'sslhello'}->{'retry'};
    $Net::SSLhello::usereneg    = $cfg{'sslhello'}->{'usereneg'};
    $Net::SSLhello::double_reneg= $cfg{'sslhello'}->{'double_reneg'};
    $Net::SSLhello::proxyhost   = $cfg{'proxyhost'};
    $Net::SSLhello::proxyport   = $cfg{'proxyport'};
}

# check ssl protocols
foreach $ssl (@{$cfg{'versions'}}) {
    next if ($ssl eq 'DTLSv1'); # not yet supported
    next if ($cfg{$ssl} == 0);
    push(@{$cfg{'version'}}, $ssl);
}

print "##############################################################################\n";
print "# '$me' (part of OWASP project 'O-Saft'), Version: $VERSION\n";
print "#                          ";
Net::SSLhello::version();
print "##############################################################################\n";

foreach $host (@{$cfg{'hosts'}}) {  # loop hosts
    if ($host =~ m#.*?:\d+#) { 
       ($host, $port) = split(":", $host);
        $cfg{'port'}  = $port;  #
        $cfg{'host'}  = $host;
    }
    _trace("host{ " . ($host||"") . ":" . $port . "\n");
    $? = 0;
    $cfg{'host'} = $host;
    foreach $ssl (@{$cfg{'version'}}) {
        my @accepted = (); # List of all Ciphers that are supported by the server with the tested Protocol
        my @testing  = ();
        my $range = $cfg{'cipherrange'};            # use specified range of constants
           $range = 'SSLv2' if ($ssl eq 'SSLv2');   # but SSLv2 needs its own list: SSLV2+SSLV3-Ciphers
        push(@testing, sprintf("0x%08X",$_)) foreach (@{$cfg{'cipherranges'}->{$range}});
        if ($Net::SSLhello::usesni==1) { # always test without SNI
            $Net::SSLhello::usesni=0;
            @accepted = Net::SSLhello::checkSSLciphers ($host, $port, $ssl, @testing);
            _trace(" $ssl: tested ciphers: " . scalar(@testing) . ", accepted: " . scalar(@accepted) . "\n");
            _trace("accepted ciphers: @accepted\n");
            Net::SSLhello::printCipherStringArray ($cfg{'legacy'}, $host, $port, $ssl, 0, @accepted);
            $Net::SSLhello::usesni=1; # restore
        }
        next if ($Net::SSLhello::usesni==0);
        next if ($ssl eq 'SSLv2');# SSLv2 has no SNI
        next if ($ssl eq 'SSLv3');# SSLv3 has originally no SNI
            @accepted = Net::SSLhello::checkSSLciphers ($host, $port, $ssl, @testing);
            _trace(" $ssl: tested ciphers: " . scalar(@testing) . ", accepted: " . scalar(@accepted) . "\n");
            _trace("accepted ciphers: @accepted\n");
            Net::SSLhello::printCipherStringArray ($cfg{'legacy'}, $host, $port, $ssl, 1, @accepted);
    }
    _trace("host}" . "\n");
}

exit;
