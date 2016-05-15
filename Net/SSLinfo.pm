#! /usr/bin/perl
## PACKAGE {

#!#############################################################################
#!#             Copyright (c) Achim Hoffmann, sic[!]sec GmbH
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

package Net::SSLinfo;

use strict;
use warnings;
use constant {
    SSLINFO_VERSION => '16.04.05',
    SSLINFO         => 'Net::SSLinfo',
    SSLINFO_ERR     => '#Net::SSLinfo::errors:',
    SSLINFO_HASH    => '<<openssl>>',
    SSLINFO_SID     => '@(#) Net::SSLinfo.pm 1.134 16/05/15 22:35:12',
};

######################################################## public documentation #
# Documentaion starts here, so  POD-style inline documentation  can be used for
# functions also which will be extracted automatically by POD tools. All public
# functions will be prefixed with a POD description.
#
# Dragons with perldoc:
#   =head2
#       Needs at least one space between ( and ) , otherwise formatting will be
#       wrong.
#   C<$something>
#       Does not print  "$something"  but simply  $something  unless  $somthing
#       contains = or * character, i.e. $some=thing. Hence we use I<$something>
#       instead.

# NOTE: This module should not use any  print(), warn() or die() calls to avoid
#       unexpected behaviours in the calling program. Only exception is print()
#       when used in trace mode ($trace > 0).
# FIXME: there're still some warn (3/2015)

=pod

=encoding utf8

=head1 NAME

Net::SSLinfo -- perl extension for SSL certificates

=head1 SYNOPSIS

    # on command line:
    Net::SSLinfo.pm            # print help
    Net::SSLinfo.pm your.tld   # print data from your.tld

    # from within perl scripts:
    use Net::SSLinfo;
    print join("\n",
        PEM("www.example.com",443),
        dates(),
        selected()
        ciphers()
        );
    do_ssl_close("www.example.com",443);

=head1 DESCRIPTION

This module is an extension to L<Net::SSLeay(3pm)> to provide information
according a SSL connection to a specific server.

The purpose is to give as much as possible information to the user (caller)
according the specified server aka hostname without struggling with the
internals of SSL as needed by Net::SSLeay.

=head1 RETURN VALUES

All methods return a string on success, empty string otherwise.

No output is written on STDOUT or STDERR. Errors need to be retrived using
I<Net::SSLinfo::errors()> method.

=head1 DEBUGGING

Simple tracing can be activated with I<$Net::SSLinfo:trace=1>.

I<$Net::SSLinfo:trace=2> or I<$Net::SSLinfo:trace=3> will be passed to
I<$Net::SSLeay::trace>.
I<$Net::SSLeay::linux_debug=1> will be set if trace > 2.

Debugging of low level SSL can be enabled by setting I<$Net::SSLeay::trace>,
see L<Net::SSLeay> for details.

In trace messages empty or undefined strings are written as "<<undefined>>".

=over

=item $Net::SSLeay::linux_debug

Passed to Net::SSLeay; default: 0

=item $Net::SSLinfo::slowly

Passed to Net::SSLeay; default: 0

=back

=head1 VARIABLES

Following variables are supported:

=over

=item $Net::SSLinfo::ca_crl

URL where to find CRL file; default: ''

=item $Net::SSLinfo::ca_file

File in PEM format file with all CAs;   default: ''

Value will not be used at all is set C<undef>.

=item $Net::SSLinfo::ca_path

Directory with PEM files for all CAs;   default: ''

Value will not be used at all is set C<undef>.

=item $Net::SSLinfo::ca_depth

Depth of peer certificate verification; default: 9

Value will not be used at all if set C<undef>.

=item $Net::SSLinfo::proxyhost

FQDN or IP of proxy to be used; default: ''.

=item $Net::SSLinfo::proxyport

Port for proxy; default: ''.

=item $Net::SSLinfo::proxypass

Username for proxy authentication (Basic or Digest Auth); default: ''.

=item $Net::SSLinfo::proxyuser

Password for proxy authentication (Basic or Digest Auth); default: ''.

=item $Net::SSLinfo::proxyauth

Authentication string used for proxy; default: ''.

=item $Net::SSLinfo::socket

Socket to be used for connection.  This must be a file descriptor and
it's assumed to be an AF_INET or AF_INET6 TCP STREAM type connection.
Note: the calling application is responsible for closing the socket.

=item $Net::SSLinfo::starttls

Use STARTTLS if not empty.

=item $Net::SSLinfo::openssl

Path for openssl executable to be used; default: openssl

=item $Net::SSLinfo::timeout

Path for timeout executable to be used; default: timeout

=item $Net::SSLinfo::use_openssl

More informations according the  SSL connection and  the certificate,
additional to that of Net::SSLeay, can be retrived using the  openssl
executable. If set to "1" openssl will be used also; default: 1

If disabled, the values returned will be: #

=item $Net::SSLinfo::use_sclient

Some informations according the  SSL connection and the certificate,
can only be retrived using  "openssl s_client ...".   Unfortunatelly
the use may result in a  performance penulty  on some systems and so
it can be disabled with "0"; default: 1

If disabled, the values returned will be: #

=item $Net::SSLinfo::use_SNI

The specified string will be used as hostname for SNI.  If set to "1", the
given hostname will be used for SNI.  This is needed if there are multiple
SSL hostnames on the same IP address. If empty string  or set to  "0", the
hostname from  PeerAddr  will be used.  The latter will fail if only an IP
was given.
If set to "0" no SNI will be used. This can be used to check if the target
supports SNI; default: 1

=item $Net::SSLinfo::use_http

If set to "1", make a simple  HTTP request on the open  SSL connection and
parse the response for additional SSL/TLS related information (for example
Strict-Transport-Security header); default: 1

=item $Net::SSLinfo::no_cert

The target may allow connections using SSL protocol,  but does not provide
a certificate. In this case all calls to functions to get details from the
certificate fail (most likely with "segmentation fault" or alike).
Due to the behaviour of the used low level ssl libraries,  there is no way
to detect this failure automatically. If the calling programm terminates
abnormally with an error, then setting this value can help.

If set to "0", collect data from target's certificate; this is default.
If set to "1", don't collect data from target's certificate  and return an
empty string.
If set to "2", don't collect data from target's certificate and return the 
string defined in  "$Net::SSLinfo::no_cert_txt".

=item $Net::SSLinfo::no_cert_txt

String to be used if "$Net::SSLinfo::no_cert" is set.
Default is (same as openssl): "unable to load certificate"

=back

=head1 EXAMPLES

See SYNOPSIS above.

=head1 LIMITATIONS

=head2 Collected data with openssl

Some data is collected using an external openssl executable. The output of
this executable is used to find proper information. Hence some data may be
missing or detected wrong due to different output formats of openssl.
If in doubt use "$Net::SSLinfo::use_openssl = 0" to disable openssl usage.

=head2 Threads

This module is not thread-save as it only supports one internal object for
socket handles. However, it will work if all threads use the same hostname.

=head1 KNOWN PROBLEMS

=head2 Certificate Verification

The verification of the target's certificate chain relies on the installed
root CAs. As this tool uses  Net::SSLeay  which usually relies on  openssl
and its libraries, the (default) settings in these libraries are effective
for our certificate chain verification.

I.g. the root CAs can be provided in a single combined PEM format file, or
in a directory containing one file per CA with a proper link which name is
the CA's hash value. Therfor the library uses the  CAPFILE  and/or  CAPATH
environment variable. The tools, like openssl, have options to pass proper
values for the file and path.

We provide these settings in the variables:  I<$Net::SSLinfo::ca_file>,
I<$Net::SSLinfo::ca_path>,  I<$Net::SSLinfo::ca_depth> .

Please see  B<VARIABLES>  for details.

Unfortunately the  default settings  for the libraries and tools differ on
various platforms, so there is  no simple way to check if the verification
was successful as expected.

In particular the behaviour is unpredictable if the  environment variables 
are set and our internal variables (see above) too. Hence, we recommend to
either ensure that  no environment variables are in use,  or our variables
are set  C<undef>.

=head2 Errors

Net::SSLeay::X509_get_subject_name()   from version 1.49 sometimes crashes
with segmentation fault.

Error message like:
  panic: sv_setpvn called with negative strlen at Net/SSLinfo.pm line 552,
     <DATA> line 1384.

Reason most likely Net::SSLeay Version (version<1.49) which doesn't define
C<Net::SSLeay::X509_NAME_get_text_by_NID()>.

=head1 METHODS

All methods are simple getters to retrieve information from `SSL objects'.
The general usage is:

=over

=item # 1. very first call with hostname and port

    my $value = method('hostname', 8443);

=item # 2. very first call with hostname only, port defaults to 443

    my $value = method('hostname');

=item # 3. continous call, hostname and port not necessary

    my $value = method();

=back

Methods named C<do_*> open and close the TCP connections. They are called
automatically by the getters (see above) if at least a C<hostname> parameter
is given. It's obvious, that for these  C<do_*>  methods the  C<hostname>
parameter is mandatory.

All following descriptions omit the  C<hostname, port> parameter as they all
follow the rules describend above.

=cut

############################################################## initialization #

use Exporter qw(import);
use base qw(Exporter);
our $VERSION   = SSLINFO_VERSION;
our @EXPORT_OK = qw(
        net_sslinfo_done
        test_ssleay
        datadump
        do_ssl_open
        do_ssl_close
        do_openssl
        set_cipher_list
        options
        errors
        PEM
        pem
        text
        fingerprint
        fingerprint_hash
        fingerprint_text
        fingerprint_type
        fingerprint_sha1
        fingerprint_md5
        cert_type
        email
        serial
        serial_int
        serial_hex
        modulus
        modulus_len
        modulus_exponent
        subject_hash
        issuer_hash
        aux
        pubkey
        pubkey_algorithm
        pubkey_value
        signame
        sigdump
        sigkey_len
        sigkey_value
        extensions
        tlsextdebug
        tlsextensions
        heartbeat
        trustout
        ocsp_uri
        ocspid
        before
        after
        dates
        issuer
        subject
        default
        selected
        cipher_list
        cipher_local
        ciphers
        cn
        commonname
        altname
        authority
        owner
        certificate
        SSLversion
        version
        keysize
        keyusage
        https_protocols
        https_svc
        https_status
        https_server
        https_alerts
        https_location
        https_refresh
        https_pins
        http_protocols
        http_svc
        http_status
        http_location
        http_refresh
        http_sts
        hsts
        hsts_maxage
        hsts_subdom
        verify_hostname
        verify_altname
        verify_alias
        verify
        error_verify
        error_depth
        chain
        chain_verify
        compression
        expansion
        protocols
        alpn
        no_alpn
        next_protocol
        krb5
        psk_hint
        psk_identity
        srp
        master_key
        session_id
        session_lifetime
        session_ticket
        session_ticket_hint
        session_timeout
        session_protocol
        renegotiation
        resumption
        dh_parameter
        selfsigned
        s_client
        error
);
    # insert above in vi with:
    # :r !sed -ne 's/^sub \([a-zA-Z][^ (]*\).*/\t\t\1/p' %

our $HAVE_XS = eval { 
        local $SIG{'__DIE__'} = 'DEFAULT';
        eval {
            require XSLoader;
            XSLoader::load('Net::SSLinfo', $VERSION);
            1;
        } or do {
            require DynaLoader;
            bootstrap Net::SSLinfo $VERSION;
            1;
        };

    } ? 1 : 0;

use Socket;
use Net::SSLeay;
BEGIN {
    Net::SSLeay::load_error_strings();
    Net::SSLeay::SSLeay_add_ssl_algorithms();   # Important!
    Net::SSLeay::randomize();
    Net::SSLeay::initialize();
}
$Net::SSLinfo::timeout     = 'timeout'; # timeout executable
$Net::SSLinfo::openssl     = 'openssl'; # openssl executable
$Net::SSLinfo::use_openssl = 1; # 1 use installed openssl executable
$Net::SSLinfo::use_sclient = 1; # 1 use openssl s_client ...
$Net::SSLinfo::use_extdebug= 1; # 0 do not use openssl with -tlsextdebug option
$Net::SSLinfo::use_nextprot= 1; # 0 do not use openssl with -nextprotoneg option
$Net::SSLinfo::use_reconnect=1; # 0 do not use openssl with -reconnect option
$Net::SSLinfo::sclient_opt =""; # option for openssl s_client command
$Net::SSLinfo::use_SNI     = 1; # 1 use SNI to connect to target; 0: do not use SNI; string: use this as hostname for SNI
$Net::SSLinfo::use_http    = 1; # 1 make HTTP request and retrive additional data
$Net::SSLinfo::no_cert     = 0; # 0 collect data from target's certificate
                                # 1 don't collect data from target's certificate
                                #   return empty string
                                # 2 don't collect data from target's certificate
                                #   return string $Net::SSLinfo::no_cert_txt
$Net::SSLinfo::no_cert_txt = 'unable to load certificate'; # same as openssl 1.0.x
$Net::SSLinfo::protocols   = 'h2,h2-15,h2-14,spdy/4a4,spdy/4a2,spdy/3.1,spdy/3,spdy/2,spdy/1,http/2.0,http/1.1';
                                # next protocols not yet configurable
                                # protocols may have prefix `exp' which should not be checked by server
$Net::SSLinfo::ignore_case = 1; # 1 match hostname, CN case insensitive
$Net::SSLinfo::timeout_sec = 3; # time in seconds for timeout executable
$Net::SSLinfo::starttls    = "";# use STARTTLS if not empty
$Net::SSLinfo::proxyhost   = "";# FQDN or IP of proxy to be used
$Net::SSLinfo::proxyport   = "";# port for proxy
$Net::SSLinfo::proxypass   = "";# username for proxy authentication (Basic or Digest Auth)
$Net::SSLinfo::proxyuser   = "";# password for proxy authentication (Basic or Digest Auth)
$Net::SSLinfo::proxyauth   = "";# authentication string used for proxy
$Net::SSLinfo::socket   = undef;# socket to be used for connection
$Net::SSLinfo::ca_crl   = undef;# URL where to find CRL file
$Net::SSLinfo::ca_file  = undef;# PEM format file with CAs
$Net::SSLinfo::ca_path  = undef;# path to directory with PEM files for CAs
$Net::SSLinfo::ca_depth = undef;# depth of peer certificate verification verification
                                # 0=verification is off, returns always "Verify return code: 0 (ok)"
                                # 9=complete verification (max. value, openssl's default)
                                # undef= not used, means system default is used
$Net::SSLinfo::trace       = 0; # 1=simple debugging Net::SSLinfo
                                # 2=trace     including $Net::SSLeay::trace=2
                                # 3=dump data including $Net::SSLeay::trace=3
$Net::SSLinfo::linux_debug = 0; # passed to Net::SSLeay::linux_debug
$Net::SSLinfo::slowly      = 0; # passed to Net::SSLeay::slowly

$Net::SSLeay::slowly = 0;

# avoid perl warning "... used only once: possible typo ..."
my $dumm_1   = $Net::SSLinfo::linux_debug;
my $dumm_2   = $Net::SSLinfo::proxyport;
my $dumm_3   = $Net::SSLinfo::proxypass;
my $dumm_4   = $Net::SSLinfo::proxyuser;
my $dumm_5   = $Net::SSLinfo::proxyauth;
my $trace    = $Net::SSLinfo::trace;

# forward declarations
sub do_ssl_open($$$@);
sub do_ssl_close($$);
sub do_openssl($$$$);

sub _settrace {
    $trace = $Net::SSLinfo::trace;          # set global variable
    $Net::SSLeay::trace = $trace    if ($trace > 1);
        # must set $Net::SSLeay::trace here again as $Net::SSLinfo::trace
        # might unset when Net::SSLinfo called initially;
    $Net::SSLeay::linux_debug = 1   if ($trace > 2);
        # Net::SSLeay 1.72 uses linux_debug with trace>2 only
    $Net::SSLeay::slowly = $Net::SSLinfo::slowly;
    return;
}

sub _trace($) { my $txt = shift; local $\ = "\n"; print '#' . SSLINFO . '::' . $txt if ($trace > 0); return; }

# define some shortcuts to avoid $Net::SSLinfo::*
my $_echo    = "";              # dangerous if aliased or wrong one found
my $_timeout = undef;
my $_openssl = undef;

sub _setcmd() {
    #? check for external commands and initialize if necessary
    return if (defined $_timeout);  # lazy check
    `$Net::SSLinfo::timeout --version 2>&1` and $_timeout = "$Net::SSLinfo::timeout $Net::SSLinfo::timeout_sec"; # without leading \, lazy
    `$Net::SSLinfo::openssl version   2>&1` and $_openssl = $Net::SSLinfo::openssl;
    $_timeout = "" if (!defined $_timeout);  # Mac OS X does not have timeout by default; can work without ...
    $_openssl = "" if (!defined $_openssl);  # shit happens ...
    #dbx# print "#_setcmd using: " . `which openssl`;
    if ($^O !~ m/MSWin32/) {
        # Windows is too stupid for secure program calls
        $_timeout = '\\' .  $_timeout if (($_timeout ne '') and ($_timeout !~ /\//));
        $_openssl = '\\' .  $_openssl if (($_openssl ne '') and ($_openssl !~ /\//));
        $_echo    = '\\' .  $_echo;
    }
    return;
} # _setcmd

sub _traceSSL() {
    # print bitmasks of available SSL constants
    my $_op_sub;
    _settrace();
    foreach my $op (qw(OP_NO_SSLv2 OP_NO_SSLv3 OP_NO_TLSv1 OP_NO_TLSv1_1 OP_NO_TLSv1_2 OP_NO_TLSv1_3 OP_NO_DTLSv1)) {
        $_op_sub = \&{"Net::SSLeay::$op"};
        # cannot use _trace() 'cause we want our own formatting
        printf("#%s SSL version bitmask: %15s ", SSLINFO, $op);
        if (defined &{"Net::SSLeay::$op"}) {
            printf("0x%010x\n", &$_op_sub()); # &$_op_sub() same as &{"Net::SSLeay::$op"}() here
        } else {
            printf("<<undef>>\n");
        }
    }
    return;
}

##################################################### internal data structure #

my %_SSLmap = ( # map libssl's constants to speaking names
    # SSL and openssl is a pain, for setting protocols it needs a bitmask
    # and SSL itself returns a hex constant, which is different
    #                 /----- returned by Net::SSLeay::version($ssl)
    # key             v      bitmask used in Net::SSLeay::CTX_set_options()
    #-------------+---------+---------------------------------------------
    'SSLv2'     => [0x0002,  Net::SSLeay::OP_NO_SSLv2()  ], # 0x01000000
    'SSLv3'     => [0x0300,  Net::SSLeay::OP_NO_SSLv3()  ], # 0x02000000
    'TLSv1'     => [0x0301,  undef],                        # 0x04000000
    'TLSv11'    => [0x0302,  undef],                        # 0x08000000
    'TLSv12'    => [0x0303,  undef],                        # 0x10000000
    'TLSv13'    => [0x0304,  undef],                        # 0x10000000
    'TLS1FF'    => [0x03FF,  undef],                        # 
    'DTLSfamily'=> [0xFE00,  undef],                        #
    'DTLSv09'   => [0x0100,  undef],                        # 0xFEFF in some openssl versions
    'DTLSv1'    => [0xFEFF,  undef],                        # ??
    'DTLSv11'   => [0xFEFE,  undef],                        # ??
    'DTLSv12'   => [0xFEFD,  undef],                        # ??
    'DTLSv13'   => [0xFEFF,  undef],                        # ??
);
# unfortunately not all openssl and/or Net::SSLeay versions have all constants,
# hence we need to assign some values dynamically (to avoid perl errors)
# NOTE: existance cannot be checked with:  defined &Net::SSLeay::OP_NO_TLSv1
$_SSLmap{'TLSv1'}  [1] = Net::SSLeay::OP_NO_TLSv1()    if (eval {Net::SSLeay::OP_NO_TLSv1()});
$_SSLmap{'TLSv11'} [1] = Net::SSLeay::OP_NO_TLSv1_1()  if (eval {Net::SSLeay::OP_NO_TLSv1_1()});
$_SSLmap{'TLSv12'} [1] = Net::SSLeay::OP_NO_TLSv1_2()  if (eval {Net::SSLeay::OP_NO_TLSv1_2()});
$_SSLmap{'TLSv13'} [1] = Net::SSLeay::OP_NO_TLSv1_3()  if (eval {Net::SSLeay::OP_NO_TLSv1_3()});
$_SSLmap{'DTLSv1'} [1] = Net::SSLeay::OP_NO_DTLSv1()   if (eval {Net::SSLeay::OP_NO_DTLSv1()});
#$_SSLmap{'DTLSv11'}[1] = Net::SSLeay::OP_NO_DTLSv1_1() if (eval {Net::SSLeay::OP_NO_DTLSv1_1()});
#$_SSLmap{'DTLSv12'}[1] = Net::SSLeay::OP_NO_DTLSv1_2() if (eval {Net::SSLeay::OP_NO_DTLSv1_2()});
#$_SSLmap{'DTLSv13'}[1] = Net::SSLeay::OP_NO_DTLSv1_3() if (eval {Net::SSLeay::OP_NO_DTLSv1_3()});
    # NOTE: we use the bitmask provided by the system
    # NOTE: all checks are done now, we don't need to fiddle around that later
    #       we just need to check for undef then
# TODO: %_SSLmap should be inherited from $cfg{openssl_version_map} or vice versa
my %_SSLhex = map { $_SSLmap{$_}[0] => $_ } keys %_SSLmap;  # reverse map

my %_SSLinfo= ( # our internal data structure
    'key'       => 'value',     # description
    #-------------+-------------+---------------------------------------------
    'host'      => '',          # hostname (FQDN) or IP as given by user
    'addr'      => undef,       # raw INET IP for hostname (FQDN)
    'ip'        => '',          # human readable IP for hostname (FQDN)
    'port'      => 443,         # port as given by user (default 443)
    'ssl'       => undef,       # handle for Net::SSLeay
    'ctx'       => undef,       # handle for Net::SSLeay::CTX_new()
    '_options'  => '',          # option bitmask used for connection
    'errors'    => [],          # stack for errors, if any
    'cipherlist'=> 'ALL:NULL:eNULL:aNULL:LOW', # we want to test really all ciphers available
    'verify_cnt'=> 0,           # Net::SSLeay::set_verify() call counter
    # now store the data we get from above handles
    'SSLversion'=> '',          # Net::SSLeay::version(); used protocol version
    'version'   => '',          # certificate version
    'error_verify'  => '',      # error string of certificate chain check
    'error_depth'   => '',      # integer value of depth where certificate chain check failed
    'keysize'   => '',
    'keyusage'  => '',
    'altname'   => '',
    'cn'        => '',
    'subject'   => '',
    'issuer'    => '',
    'before'    => '',
    'after'     => '',
    'PEM'       => '',
    'text'      => '',
    'cert_type' => '',          # X509 certificate type  EXPERIMENTAL
    'ciphers'           => [],  # list of ciphers offered by local SSL implementation
    # all following are available when calling  openssl only
    's_client'          => "",  # data we get from `openssl s_client -connect ...'
    'ciphers_openssl'   => "",  # list of ciphers returned by openssl executable
    'subject_hash'      => "",  #
    'issuer_hash'       => "",  #
    'aux'               => "",  #
    'pubkey'            => "",  # certificates public key
    'pubkey_algorithm'  => "",  # certificates public key algorithm
    'pubkey_value'      => "",  # certificates public key value (same as modulus)
    'signame'           => "",  #
    'sigdump'           => "",  # algorithm and value of signature key
    'sigkey_len'        => "",  # bit length  of signature key
    'sigkey_value'      => "",  # value       of signature key
    'extensions'        => "",  #
    'tlsextdebug'       => "",  # TLS extension visible with "openssl -tlsextdebug .."
    'tlsextensions'     => "",  # TLS extension visible with "openssl -tlsextdebug .."
    'email'             => "",  # the email address(es)
    'heartbeat'         => "",  # heartbeat supported
    'serial'            => "",  # the serial number, string as provided by openssl: int (hex)
    'serial_hex'        => "",  # the serial number as Integer
    'serial_int'        => "",  # the serial number as hex
    'modulus'           => "",  # the modulus of the public key
    'modulus_len'       => "",  # bit length  of the public key
    'modulus_exponent'  => "",  # exponent    of the public key
    'fingerprint_text'  => "",  # the fingerprint text
    'fingerprint_type'  => "",  # just the fingerprint hash algorithm
    'fingerprint_hash'  => "",  # the fingerprint hash value
    'fingerprint_sha1'  => "",  # SHA1 fingerprint (if available)
    'fingerprint_md5'   => "",  # MD5  fingerprint (if available)
    'selected'          => "",  # cipher selected for session by server
    # all following need output from "openssl s_client ..."
    'verify'            => "",  # certificate chain verification
    'chain'             => "",  # certificate's CA chain
    'chain_verify'      => "",  # certificate's CA chain verifacion trace
    'dh_parameter'      => "",  # DH Parameter (starting with openssl 1.0.2a)
    'renegotiation'     => "",  # renegotiation supported
    'resumption'        => "",  # resumption supported
    'selfsigned'        => "",  # self-signed certificate
    'compression'       => "",  # compression supported
    'expansion'         => "",  # expansion supported
    'protocols'         => "",  # Protocols advertised by server
    'alpn'              => "",  # ALPN protocol
    'no_alpn'           => "",  # No ALPN negotiated
    'next_protocol'     => "",  # Next protocol
    'krb5'              => "",  # Krb Principal
    'psk_hint'          => "",  # PSK identity hint
    'psk_identity'      => "",  # PSK identity
    'srp'               => "",  # SRP username
    'master_key'        => "",  # Master-Key
    'session_id'        => "",  # Session-ID
    'session_lifetime'  => "",  # TLS session ticket lifetime hint
    'session_ticket'    => "",  # TLS session ticket
    'session_timeout'   => "",  # SSL-Session Timeout
    'session_protocol'  => "",  # SSL-Session Protocol
    # following from HTTP(S) request
    'https_protocols'   => "",  # HTTPS Alternate-Protocol header
    'https_svc'         => "",  # HTTPS Alt-Svc header
    'https_status'      => "",  # HTTPS response (aka status) line
    'https_server'      => "",  # HTTPS Server header
    'https_alerts'      => "",  # HTTPS Alerts send by server
    'https_location'    => "",  # HTTPS Location header send by server
    'https_refresh'     => "",  # HTTPS Refresh header send by server
    'https_pins'        => "",  # HTTPS Public Key Pins header
    'http_protocols'    => "",  # HTTP Alternate-Protocol header
    'http_svc'          => "",  # HTTP Alt-Svc header
    'http_status'       => "",  # HTTP response (aka status) line
    'http_location'     => "",  # HTTP Location header send by server
    'http_refresh'      => "",  # HTTP Refresh header send by server
    'http_sts'          => "",  # HTTP Strict-Transport-Security header send by server (whish is very bad)
    'https_sts'         => "",  # complete STS header
    'hsts_maxage'       => "",  # max-age attribute of STS header
    'hsts_subdom'       => "",  # includeSubDomains attribute of STS header
); # %_SSLinfo

sub _SSLinfo_reset() {  # reset %_SSLinfo, for internal use only
    #? reset internal data structure
    foreach my $key (keys %_SSLinfo) {
        $_SSLinfo{$key}     = "";
    }
    # some are special
    $_SSLinfo{'key'}        = 'value';
    $_SSLinfo{'ctx'}        = undef;
    $_SSLinfo{'ssl'}        = undef;
    $_SSLinfo{'addr'}       = undef;
    $_SSLinfo{'port'}       = 443;
    $_SSLinfo{'errors'}     = [];
    $_SSLinfo{'ciphers'}    = [];
    $_SSLinfo{'cipherlist'} = 'ALL:NULL:eNULL:aNULL:LOW';
    $_SSLinfo{'verify_cnt'} = 0;
    $_SSLinfo{'ciphers_openssl'} = "";
    return;
} # _SSLinfo_reset

sub test_ssleay() {
    # availability and information about Net::SSLeay
    my $line = "#------------+-------------------+------------";
    my $data = "# Net::SSLeay{ function           1=available
$line
#            ::SSLv2_method     = " . ((defined &Net::SSLeay::SSLv2_method)     ? 1 : 0) . "
#            ::SSLv3_method     = " . ((defined &Net::SSLeay::SSLv3_method)     ? 1 : 0) . "
#            ::SSLv23_method    = " . ((defined &Net::SSLeay::SSLv23_method)    ? 1 : 0) . "
#            ::TLSv1_method     = " . ((defined &Net::SSLeay::TLSv1_method)     ? 1 : 0) . "
#            ::TLSv1_1_method   = " . ((defined &Net::SSLeay::TLSv1_1_method)   ? 1 : 0) . "
#            ::TLSv1_2_method   = " . ((defined &Net::SSLeay::TLSv1_2_method)   ? 1 : 0) . "
#{ following missing in Net::SSLeay (up to 1.72):
#            ::TLSv1_3_method   = " . ((defined &Net::SSLeay::TLSv1_3_method)   ? 1 : 0) . "
#            ::DTLSv1_method    = " . ((defined &Net::SSLeay::DTLSv1_method)    ? 1 : 0) . "
#            ::DTLSv1_2_method  = " . ((defined &Net::SSLeay::DTLSv1_2_method)  ? 1 : 0) . "
#            ::DTLS_method      = " . ((defined &Net::SSLeay::DTLS_method)      ? 1 : 0) . "
#}
#            ::CTX_new_with_method = " . ((defined &Net::SSLeay::CTX_new_with_method) ? 1 : 0) . "
#            ::CTX_new          = " . ((defined &Net::SSLeay::CTX_new)          ? 1 : 0) . "
#            ::CTX_v2_new       = " . ((defined &Net::SSLeay::CTX_v2_new)       ? 1 : 0) . "
#            ::CTX_v3_new       = " . ((defined &Net::SSLeay::CTX_v3_new)       ? 1 : 0) . "
#            ::CTX_v23_new      = " . ((defined &Net::SSLeay::CTX_v23_new)      ? 1 : 0) . "
#            ::CTX_tlsv1_new    = " . ((defined &Net::SSLeay::CTX_tlsv1_new)    ? 1 : 0) . "
#            ::CTX_tlsv1_0_new  = " . ((defined &Net::SSLeay::CTX_tlsv1_0_new)  ? 1 : 0) . "
#            ::CTX_tlsv1_1_new  = " . ((defined &Net::SSLeay::CTX_tlsv1_1_new)  ? 1 : 0) . "
#            ::CTX_tlsv1_2_new  = " . ((defined &Net::SSLeay::CTX_tlsv1_2_new)  ? 1 : 0) . "
#            ::CTX_tlsv1_3_new  = " . ((defined &Net::SSLeay::CTX_tlsv1_3_new)  ? 1 : 0) . "
#            ::CTX_get_options  = " . ((defined &Net::SSLeay::CTX_get_options)  ? 1 : 0) . "
#            ::CTX_dtlsv1_new   = " . ((defined &Net::SSLeay::CTX_dtlsv1_new)   ? 1 : 0) . "
#            ::CTX_dtlsv1_2_new = " . ((defined &Net::SSLeay::CTX_dtlsv1_2_new) ? 1 : 0) . "
$line
# Net::SSLeay} function
# Net::SSLeay{ constant           hex value
$line
#            ::OP_NO_SSLv2      = " . ((defined &Net::SSLeay::OP_NO_SSLv2)    ? sprintf('0x%08x', Net::SSLeay::OP_NO_SSLv2())    : "<<undef>>") . "
#            ::OP_NO_SSLv3      = " . ((defined &Net::SSLeay::OP_NO_SSLv3)    ? sprintf('0x%08x', Net::SSLeay::OP_NO_SSLv3())    : "<<undef>>") . "
#            ::OP_NO_TLSv1      = " . ((defined &Net::SSLeay::OP_NO_TLSv1)    ? sprintf('0x%08x', Net::SSLeay::OP_NO_TLSv1())    : "<<undef>>") . "
#            ::OP_NO_TLSv1_1    = " . ((defined &Net::SSLeay::OP_NO_TLSv1_1)  ? sprintf('0x%08x', Net::SSLeay::OP_NO_TLSv1_1())  : "<<undef>>") . "
#            ::OP_NO_TLSv1_2    = " . ((defined &Net::SSLeay::OP_NO_TLSv1_2)  ? sprintf('0x%08x', Net::SSLeay::OP_NO_TLSv1_2())  : "<<undef>>") . "
#            ::OP_NO_TLSv1_3    = " . ((defined &Net::SSLeay::OP_NO_TLSv1_3)  ? sprintf('0x%08x', Net::SSLeay::OP_NO_TLSv1_3())  : "<<undef>>") . "
#            ::OP_NO_DTLSv09    = " . ((defined &Net::SSLeay::OP_NO_DTLSv09)  ? sprintf('0x%08x', Net::SSLeay::OP_NO_DTLSv09())  : "<<undef>>") . "
#            ::OP_NO_DTLSv1     = " . ((defined &Net::SSLeay::OP_NO_DTLSv1)   ? sprintf('0x%08x', Net::SSLeay::OP_NO_DTLSv1())   : "<<undef>>") . "
#            ::OP_NO_DTLSv1_1   = " . ((defined &Net::SSLeay::OP_NO_DTLSv1_1) ? sprintf('0x%08x', Net::SSLeay::OP_NO_DTLSv1_1()) : "<<undef>>") . "
#            ::OP_NO_DTLSv1_2   = " . ((defined &Net::SSLeay::OP_NO_DTLSv1_2) ? sprintf('0x%08x', Net::SSLeay::OP_NO_DTLSv1_2()) : "<<undef>>") . "
#            ::OP_NO_DTLSv1_3   = " . ((defined &Net::SSLeay::OP_NO_DTLSv1_3) ? sprintf('0x%08x', Net::SSLeay::OP_NO_DTLSv1_3()) : "<<undef>>") . "
$line
# Net::SSLeay} constant
# Net::SSLeay{ call
#      experimental ...
# Net::SSLeay::CTX_new {
#            ::CTX_get_options(CTX)= " . sprintf('0x%08x', Net::SSLeay::CTX_get_options(Net::SSLeay::CTX_new())) . "
# Net::SSLeay::CTX_new }
# Net::SSLeay::CTX_v3_new {
#            ::CTX_get_options(CTX)= " . sprintf('0x%08x', Net::SSLeay::CTX_get_options(Net::SSLeay::CTX_v3_new())) . "
# Net::SSLeay::CTX_v3_new }
# Net::SSLeay::CTX_v23_new {
#            ::CTX_get_options(CTX)= " . sprintf('0x%08x', Net::SSLeay::CTX_get_options(Net::SSLeay::CTX_v23_new())) . "
#            ::CTX_get_timeout(CTX)= " . Net::SSLeay::CTX_get_timeout(Net::SSLeay::CTX_v23_new()) . "
#            ::CTX_get_verify_mode(CTX) = " . sprintf('0x%08x', Net::SSLeay::CTX_get_verify_mode(Net::SSLeay::CTX_v23_new())) . "
#            ::CTX_get_verify_depth(CTX)= " . Net::SSLeay::CTX_get_verify_depth(Net::SSLeay::CTX_v23_new()) . "
# Net::SSLeay::CTX_v23_new }
# Net::SSLeay} call\n";

    return $data;
} # test_ssleay


sub _dump($$$) {
    my $key = shift;
    my $txt = shift;
    my $val = shift;
    return sprintf("#{ %-12s:%s%s #}\n", $key, $txt, ($val || "<<undefined>>"));
} # _dump
    # my ($label, $separator, $value) = @_;
sub datadump() {
    #? return internal data structure
    my $data = '';
    if ($Net::SSLinfo::use_sclient > 1) {
        $data .= _dump('s_client', " ", $_SSLinfo{'s_client'});
    } else {
        $data .= _dump('s_client', " ", "#### please set 'Net::SSLinfo::use_sclient > 1' to dump s_client data also ###");
    }
    $data .= _dump('PEM',     " ", $_SSLinfo{'PEM'});
    $data .= _dump('text',    " ", $_SSLinfo{'text'});
    $data .= _dump('ciphers', " ", join(" ", @{$_SSLinfo{'ciphers'}}));
    foreach my $key (keys %_SSLinfo) {
        next if ($key =~ m/ciphers|errors|PEM|text|fingerprint_|s_client/); # handled special
        $data .= _dump($key, " ", $_SSLinfo{$key});
    }
    foreach my $key (keys %_SSLinfo) {
        next if ($key !~ m/fingerprint_/);
        $data .= _dump($key, " ", $_SSLinfo{$key});
    }
    $data .= _dump('errors',  "\n", join("\n ** ", @{$_SSLinfo{'errors'}}));
    return $data;
} # datadump

########################################################## internal functions #

sub _SSLinfo_get($$$) {
    # get specified value from %_SSLinfo, first parameter 'key' is mandatory
    my ($key, $host, $port) = @_;
    _settrace();
    _trace("_SSLinfo_get('$key'," . ($host||'') . "," . ($port||'') . ")");
    if ($key eq 'ciphers_openssl') {
        _trace("_SSLinfo_get($key): WARNING: function obsolete, please use cipher_local()");
        return "";
    }
    if ($key eq 'errors') { # always there, no need to connect target
        #src = Net::SSLeay::ERR_peek_error;      # just returns number
        #src = Net::SSLeay::ERR_peek_last_error; # should work since openssl 0.9.7
        return wantarray ? @{$_SSLinfo{$key}} : join("\n", @{$_SSLinfo{$key}});
    }
    return '' if !defined do_ssl_open($host, $port, '');
    if ($key eq 'ciphers') { # special handling
        return wantarray ? @{$_SSLinfo{$key}} : join(' ', @{$_SSLinfo{$key}});
        return wantarray ? @{$_SSLinfo{$key}} : join(':', @{$_SSLinfo{$key}}); # if we want `openssl ciphers' format
    }
    if ($key eq 'dates') {
        return ( $_SSLinfo{'before'}, $_SSLinfo{'after'});
    }
    _trace("_SSLinfo_get '$key'=" . ($_SSLinfo{$key} || ""));
    return (grep{/^$key$/} keys %_SSLinfo) ? $_SSLinfo{$key} : '';
} # _SSLinfo_get

#
# general internal functions
#

sub _check_host($) {
    #? convert hostname to IP and store in $_SSLinfo{'host'}, returns 1 on success
    my $host = shift;
    _trace("_check_host($host)");
    $host  = $_SSLinfo{'host'} unless defined $host;
    my $ip = undef;
    if($ip = gethostbyname($host)) {
        $_SSLinfo{'host'} = $host;
        $_SSLinfo{'addr'} = $ip;
        $_SSLinfo{'ip'}   = join('.', unpack('W4', $ip));
    }
    _trace("_check_host $_SSLinfo{'host'} $_SSLinfo{'ip'} .");
    return (defined $ip) ? 1 : undef;
}

sub _check_port($) {
    #? convert port name to number and store in $_SSLinfo{'port'}, returns 1 on success
    my $port = shift;
    _trace("_check_port($port)");
    $port  = $_SSLinfo{'port'} unless defined $port;
    $port  = getservbyname($port, 'tcp') unless $port =~ /^\d+$/;
    $_SSLinfo{'port'} = $port if (defined $port);
    _trace("_check_port $port .");
    return (defined $port) ? 1 : undef;
}

sub _ssleay_get($$) {
    #? get specified value from SSLeay certificate
        # wrapper to get data provided by certificate
        # note that all these function may produce "segmentation fault" or alike if
        # the target does not have/use a certificate but allows connection with SSL
    my ($key, $x509) = @_;
    _settrace();
    _trace("_ssleay_get('$key', x509)");
    if ($Net::SSLinfo::no_cert != 0) {
            _trace("_ssleay_get 'use_cert' $Net::SSLinfo::no_cert .");
        return $Net::SSLinfo::no_cert_txt if ($Net::SSLinfo::no_cert == 2);
        return '';
    }

    return Net::SSLeay::X509_get_version(        $x509) + 1     if ($key eq 'version');
    return Net::SSLeay::X509_get_fingerprint(    $x509,  'md5') if ($key eq 'md5');
    return Net::SSLeay::X509_get_fingerprint(    $x509, 'sha1') if ($key eq 'sha1');
    return Net::SSLeay::X509_NAME_oneline(        Net::SSLeay::X509_get_subject_name($x509)) if($key eq 'subject');
    return Net::SSLeay::X509_NAME_oneline(        Net::SSLeay::X509_get_issuer_name( $x509)) if($key eq 'issuer');
    return Net::SSLeay::P_ASN1_UTCTIME_put2string(Net::SSLeay::X509_get_notBefore(   $x509)) if($key eq 'before');
    return Net::SSLeay::P_ASN1_UTCTIME_put2string(Net::SSLeay::X509_get_notAfter(    $x509)) if($key eq 'after');
    return Net::SSLeay::P_ASN1_INTEGER_get_hex(Net::SSLeay::X509_get_serialNumber(   $x509)) if($key eq 'serial_hex');
    return Net::SSLeay::X509_NAME_get_text_by_NID(Net::SSLeay::X509_get_subject_name($x509), &Net::SSLeay::NID_commonName) if($key eq 'cn');
    return Net::SSLeay::X509_NAME_get_text_by_NID(Net::SSLeay::X509_get_subject_name($x509), &Net::SSLeay::NID_certificate_policies) if ($key eq 'policies');

    my $ret = "";
    if ($key =~ 'serial') {
# TODO: dead code as Net::SSLeay::X509_get_serialNumber() does not really return an integer
        $ret = Net::SSLeay::P_ASN1_INTEGER_get_hex(Net::SSLeay::X509_get_serialNumber(   $x509));
        return $ret if($key eq 'serial_hex');
        my $int = hex($ret);
        return $int if($key eq 'serial_int');
        return "$int (0x$ret)"; # if($key eq 'serial');
    }

    if ($key eq 'altname') {
        my @altnames = Net::SSLeay::X509_get_subjectAltNames($x509); # returns array of (type, string)
        _trace("_ssleay_get: Altname: " . join(" ", @altnames));
        while (@altnames) {             # construct string like openssl
            my ($type, $name) = splice(@altnames, 0, 2);
            # TODO: replace ugly code by %_SSLtypemap
            $type = 'DNS'           if ($type eq '2');
            $type = 'URI'           if ($type eq '6');
            $type = 'X400'          if ($type eq '3');
            $type = 'DIRNAME'       if ($type eq '4');
            $type = 'EDIPARTY'      if ($type eq '5');
            $type = 'IPADD'         if ($type eq '7');
            $type = 'RID'           if ($type eq '8');
            $type = 'email'         if ($type eq '1');
            $name = '<<undefined>>' if(($type eq '0') && ($name!~/^/));
            $type = 'othername'     if ($type eq '0');
            # all other types are used as is, so we see what's missing
            $ret .= ' ' . join(':', $type, $name);
        }
    }
    _trace("_ssleay_get: $ret.");  # or warn "**WARNING: wrong key '$key' given; ignored";
    return $ret;
} # _ssleay_get

sub _header_get($$) {
    #? get value for specified header from given HTTP response; empty if not exists
    my $head    = shift;   # header to search for
    my $response= shift; # response where to serach
    my $value   = '';
    _trace("__header_get('$head', <<response>>)");
    if ($response =~ m/[\r\n]$head\s*:/i) {
        $value  =  $response;
        $value  =~ s/.*?[\r\n]$head\s*:\s*([^\r\n]*).*$/$1/ims;
    }
    return $value;
} # _header_get

sub _openssl_MS($$$$) {
    #? wrapper to call external openssl executable on windows
    my $mode = shift;   # must be openssl command
    my $host = shift;   # '' if not used
    my $port = shift;   # '' if not used
    my $text = shift;   # text to be piped to openssl
    my $data ='';
    return '' if ($^O !~ m/MSWin32/);

    _trace("_openssl_MS($mode, $host, $port)");
    if ($_openssl eq '') {
        _trace("_openssl_MS($mode): WARNING: no openssl");
        return SSLINFO_HASH;
    }
    $host .= ':' if ($port ne '');
    $text = '""' if (!defined $text);
    chomp $text;
    $text = '""' if ($text !~ /[\r\n]/);
        # $data = `echo '$text' | $_openssl $mode ... 2>&1`;
        # windows hangs even with empty STDIN, hence we use cmd.exe always
    # convert multiple lines to an echo for each line
    $text =~ s/\n/\n echo /g;
    $text = "(echo $text)"; # it's a subshell now with multiple echo commands
    my $err = '';
    my $src = 'open';
    my $tmp = '.\\_yeast.bat'; # do not use $ENV{'TMP'} as it can be empty or unset
    _trace("_openssl_MS $mode $host$port: cmd.exe /D /C /S $tmp") if ($trace > 1);
    TRY: {
        my $fh;
        open($fh, '>', $tmp)                or {$err = $!} and last;
        print $fh "$text | $_openssl $mode $host$port 2>&1";
        close($fh);
        #dbx# print `cat $tmp`;
        $src = 'cmd.exe';
        ($data =  `cmd.exe /D /S /C $tmp`) or {$err = $!} and last;
        $src = 'unlink';
        unlink  $tmp                       or {$err = $!} and last;
         $data =~ s#^[^)]*[^\r\n]*.##s;          # remove cmd.exe's output
         $data =~ s#WARN.*?openssl.cnf[\r\n]##;  # remove WARNINGs
        _trace("_openssl_MS $mode $host$port : $data #") if ($trace > 1);
    }
    if ($err ne '') {
        $text = "_openssl_MS() failed calling $src: $err";
        _trace($text) if ($trace > 1);
        push(@{$_SSLinfo{'errors'}}, $text);
        return '';
    }
    return $data;
} # _openssl_MS

sub _openssl_x509($$) {
    #? call external openssl executable to retrive more data from PEM
    my $pem  = shift;
    my $mode = shift;   # must be one of openssl x509's options
    my $data = '';
    _trace("_openssl_x509($mode,...).");
    _setcmd();
    if ($_openssl eq '') {
        _trace("_openssl_x509($mode): WARNING: no openssl");
        return SSLINFO_HASH;
    }

    #if ($mode =~ m/^-(text|email|modulus|serial|fingerprint|subject_hash|trustout)$/) {
    #   # supported by openssl's x509 (0.9.8 and higher)
    #}
    if ($mode =~ m/^-?(version|pubkey|signame|sigdump|aux|extensions)$/) {
        # openssl works the other way around:
        #   define as -certopt what should *not* be printed
        # hence we use a list with all those no_* options and remove that one
        # which should be printed
        my $m =  'no_' . $mode;
        $mode =  '-text -certopt no_header,no_version,no_serial,no_signame,no_validity,no_subject,no_issuer,no_pubkey,no_sigdump,no_aux,no_extensions,ext_default,ext_dump';
            # ca_default   not used as it's already in $_SSLinfo{'text'}
        $mode =~ s/$m//;
        $mode =~ s/,,/,/;  # need to remove , also, otherwise we get everything
    }
    $mode = 'x509 -noout ' . $mode;
    _trace("_openssl_x509(openssl $mode).") if ($trace > 1);
    if ($^O !~ m/MSWin32/) {
        $data = `echo '$pem' | $_openssl $mode 2>&1`;
    } else { # it's sooooo simple, except on Windows :-(
        $data = _openssl_MS($mode, '', '', $pem);
    }
    chomp $data;
    $data =~ s/\s*$//;  # be sure ...
    $data =~ s/\s*Version:\s*//i if (($mode =~ m/ -text /) && ($mode !~ m/version,/)); # ugly test for version
    #dbx# print "#3 $data \n#3";
    return $data;
} # _openssl_x509

############################################################ public functions #

=pod

=head2 do_ssl_open($host,$port,$sslversions[,$cipherlist])

Opens new SSL connection with Net::SSLeay.

I<$sslversions> is space-separated list of SSL versions to be used. Following
strings are allowed for versions: C<SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 DTLSv1>.
If I<$sslversions> is empty, the system's default settings of versions are used.
If I<$cipherlist> is missing or empty, default C<ALL:NULL:eNULL:aNULL:LOW> will be used.

Returns array with $ssl object and $ctx object.

This method is called automatically by all other functions, hence no need to
call it directly.
=cut

# from openssl/x509_vfy.h
sub _X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT () { return 18; }
sub _FLAGS_ALLOW_SELFSIGNED () { return 0x00000001; }

sub do_ssl_open($$$@) {
    my ($host, $port, $sslversions, $cipher) = @_;
    $cipher = "" if (!defined $cipher); # cipher parameter is optional
    _settrace();
    _trace("do_ssl_open(" . ($host||'') . "," . ($port||'') . "," . ($sslversions||'') . "," . ($cipher||'') . ")");
    goto finished if (defined $_SSLinfo{'ssl'});
    _traceSSL() if ($trace > 0);
    #_SSLinfo_reset(); # <== does not work yet as it clears everything

    if ($cipher =~ m/^\s*$/) {
        $cipher = $_SSLinfo{'cipherlist'};
    } else {
        $_SSLinfo{'cipherlist'} = $cipher;
    }
    _trace("do_ssl_open cipherlist: $_SSLinfo{'cipherlist'}");
    my $src;         # function where something failed
    my $err = "";    # error string, if any, from sub-system $src
    my $ctx = undef;
    my $ssl = undef;
    my $cafile  = "";
    my $capath  = "";
    my $socket  = *FH;  # if we need it ...
    my $dum     = *FH;  # keep perl's -w quiet
       $dum     = undef;

    TRY: {
        #1. open TCP connection
        if (!defined $Net::SSLinfo::socket) {   # no filehandle, open our own one
            unless (($Net::SSLinfo::starttls) || ($Net::SSLinfo::proxyhost)) { # $Net::SSLinfo::proxyport was already checked in main
                #1a. no proxy and not starttls
                $src = "_check_host($host)"; if (!defined _check_host($host)) { last; }
                $src = "_check_port($port)"; if (!defined _check_port($port)) { last; }
                $src = 'socket()';
                        socket( $socket, &AF_INET, &SOCK_STREAM, 0) or {$err = $!} and last;
                $src = 'connect()';
                $dum=()=connect($socket, sockaddr_in($_SSLinfo{'port'}, $_SSLinfo{'addr'})) or {$err = $!} and last;
            } else {
                #1b. starttls or via proxy
                require Net::SSLhello;      # ok here, as perl handles multiple includes proper
                Net::SSLhello::version() if ($trace > 1); # TODO: already done in _yeast_init()
                $src = "Net::SSLhello::openTcpSSLconnection()";
                # open TCP connection via proxy and do STARTTLS if requested
                # NOTE that $host cannot be checked here because the proxy does
                # DNS and also has the routes to the host
                ($socket = Net::SSLhello::openTcpSSLconnection($host, $port)) or {$err = $!} and last;
            }
            ## no critic qw(InputOutput::ProhibitOneArgSelect)
            select($socket); local $| = 1; select(STDOUT);  # Eliminate STDIO buffering
            ## use critic
            $Net::SSLinfo::socket = $socket;
        } else {
            $socket = $Net::SSLinfo::socket;
        }

        #2. prepare SSL's context object
        ($ctx = Net::SSLeay::CTX_v23_new()) or {$src = 'Net::SSLeay::CTX_v23_new()'} and last;
            # CTX_v23_new() returns an object, errors are on error stack
            # we use CTX_v23_new() 'cause of CTX_new() sets SSL_OP_NO_SSLv2

        #2a. set certificate verification options
        Net::SSLeay::CTX_set_verify($ctx, &Net::SSLeay::VERIFY_NONE, \&_check_peer);
            # we're in client mode where only  VERYFY_NONE  or  VERYFY_PEER  is
            # used; as we want to get all informations,  even if something went
            # wrong, we use VERIFY_NONE so we can proceed collecting data
            # possible values:
            #  0 = SSL_VERIFY_NONE
            #  1 = SSL_VERIFY_PEER
            #  2 = SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            #  4 = SSL_VERIFY_CLIENT_ONCE
        $src = "Net::SSLeay::CTX_load_verify_locations()";
        $cafile = $Net::SSLinfo::ca_file || "";
        if ($cafile !~ m#^(?:[a-zA-Z0-9_,.\\/()-])*$#) {
            $err = "invalid characters for " . '$Net::SSLinfo::ca_file; not used';
            last;
        }
        $capath = $Net::SSLinfo::ca_path || "";
        if ($capath !~ m#^(?:[a-zA-Z0-9_,.\\/()-]*)$#) {
            $err = "invalid characters for " . '$Net::SSLinfo::ca_path; not used';
            last;
        }
        if (($capath . $cafile) ne "") { # CTX_load_verify_locations() fails if both are empty
            Net::SSLeay::CTX_load_verify_locations($ctx, $cafile, $capath) or do {$err = $!} and last;
            # CTX_load_verify_locations()  sets SSLeay's error stack,  which is
            # roughly the same as $!
        }
        $dum = $Net::SSLinfo::ca_crl;   # TODO: keep perl's -w quiet until used
        $src = "Net::SSLeay::CTX_set_verify_depth()";
        if (defined $Net::SSLinfo::ca_depth) {
            if ($Net::SSLinfo::ca_depth !~ m/^[0-9]$/) {
                $err = "invalid value '$Net::SSLinfo::ca_depth' for " . '$Net::SSLinfo::ca_depth; not used';
                last;
            }
            Net::SSLeay::CTX_set_verify_depth($ctx, $Net::SSLinfo::ca_depth);
        }
        # TODO: certificate CRL
        # just code example, not yet tested
        #
        # enable Net::SSLeay CRL checking:
        #   &Net::SSLeay::X509_STORE_set_flags
        #       (&Net::SSLeay::CTX_get_cert_store($ssl),
        #        &Net::SSLeay::X509_V_FLAG_CRL_CHECK);

        #2b. set protocol options
        $ssl = (defined &Net::SSLeay::SSLv23_method) ? 1:0;
        if (defined &Net::SSLeay::SSLv23_method) {
            $src = "Net::SSLeay::CTX_set_ssl_version(SSLv23_method)";   # set default SSL protocol
            Net::SSLeay::CTX_set_ssl_version($ctx, Net::SSLeay::SSLv23_method()) or do {$err = $!} and last;
            # allow all protocols for backward compatibility; user specific
            # restrictions are done later with  CTX_set_options()
        } else {
            $src = "Net::SSLeay::SSLv23_method()";
            push(@{$_SSLinfo{'errors'}}, "do_ssl_open() WARNING '$src' not available, using system default");
            # if we don't have  SSLv23_method(), we better use the system's
            # default behaviour, because anything else  would stick  on the
            # specified protocol version, like SSLv3_method()
        }
        $src = 'Net::SSLeay::CTX_set_options()';       # now limit as specified by user
                Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL); # can not fail according description!
            # disable not specified SSL versions
        foreach  my $ssl (keys %_SSLmap) {
            # $sslversions  passes the version which should be supported,  but
            # openssl and hence Net::SSLeay, configures what  should *not*  be
            # supported, so we skip all versions found in  $sslversions
            next if ($sslversions =~ m/^\s*$/); # no version given, leave default
            next if (grep{/^$ssl$/} split(" ", $sslversions));
            if (defined $_SSLmap{$ssl}[1]) {        # if there is a bitmask, disable this version
                _trace("do_ssl_open: OP_NO_$ssl");  # NOTE: constant name *not* as in ssl.h
                Net::SSLeay::CTX_set_options($ctx, $_SSLmap{$ssl}[1]) if(defined $_SSLmap{$ssl}[1]);
            }
        }
        $ssl = undef;

# TODO:      Net::SSLeay::CTX_set_options($ctx, (Net::SSLeay::OP_CIPHER_SERVER_PREFERENCE));
# TODO:      Net::SSLeay::CTX_set_options($ctx, (Net::SSLeay::OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION));
# TODO: Client-Cert see smtp_tls_cert.pl
# TODO: proxy settings work in HTTP mode only
##Net::SSLeay::set_proxy('some.tld', 84, 'z00', 'pass');
##print "#ERR: $!";

        #3. prepare SSL object
        $src = 'Net::SSLeay::new()';
        ($ssl=  Net::SSLeay::new($ctx))                        or {$err = $!} and last;
        $src = 'Net::SSLeay::set_fd()';
                Net::SSLeay::set_fd($ssl, fileno($socket))     or {$err = $!} and last;
        $src = 'Net::SSLeay::set_cipher_list(' . $cipher .')';
                Net::SSLeay::set_cipher_list($ssl, $cipher)    or {$err = $!} and last;
        $Net::SSLinfo::use_SNI =~ s/\s//g;  # ensure no spaces
        if ($Net::SSLinfo::use_SNI !~ m/^0?$/) {    # no SNI if 0 or empty string
            _trace("do_ssl_open: SNI");
            my $name = $Net::SSLinfo::use_SNI;
               $name = $host if ($Net::SSLinfo::use_SNI =~ m/^1$/); # old style, Net::SSLinfo < 1.85
            if (1.45 <= $Net::SSLeay::VERSION) {
                $src = 'Net::SSLeay::set_tlsext_host_name()';
                Net::SSLeay::set_tlsext_host_name($ssl, $name) or {$err = $!} and last;
            } else {
                # quick&dirty instead of:
                #  use constant SSL_CTRL_SET_TLSEXT_HOSTNAME => 55
                #  use constant TLSEXT_NAMETYPE_host_name    => 0
                $src = 'Net::SSLeay::ctrl()';
                Net::SSLeay::ctrl($ssl, 55, 0, $name)          or {$err = $!} and last;
                # TODO: ctrl() sometimes fails but does not return errors, reason yet unknown
            }
        }

        #4. connect SSL
        local $SIG{PIPE} = 'IGNORE';        # Avoid "Broken Pipe"
        my $ret;
        $src = 'Net::SSLeay::connect() ';
        $ret =  Net::SSLeay::connect($ssl); # may call _check_peer() ..
        if ($ret <= 0) {
            $src .= " failed start"     if ($ret <  0); # i.e. no matching protocol
            $src .= " failed handshake" if ($ret == 0);
            $err  = $!;
            last;
        }
        #$Net::SSLeay::ssl_version = 2;  # Insist on SSLv2
        #  or =3  or =10  seems not to work, reason unknown, hence CTX_set_options() above

        #5. SSL established, let's get informations
        # TODO: starting from here implement error checks
        $src ='Net::SSLeay::get_peer_certificate()';
        my $x509= Net::SSLeay::get_peer_certificate($ssl);

        #5a. get internal data
        $_SSLinfo{'ctx'}        = $ctx;
        $_SSLinfo{'ssl'}        = $ssl;
        $_SSLinfo{'x509'}       = $x509;
        $_SSLinfo{'_options'}  .= sprintf("0x%016x", Net::SSLeay::CTX_get_options($ctx));
        $_SSLinfo{'SSLversion'} = $_SSLhex{Net::SSLeay::version($ssl)};
            # TODO: Net::SSLeay's documentation also has:
            #    get_version($ssl); get_cipher_version($ssl);
            # but they are not implemented (up to 1.49)

        #5b. store actually used ciphers for this connection
        my $i   = 0;
        my $c   = '';
        push(@{$_SSLinfo{'ciphers'}}, $c) while ($c = Net::SSLeay::get_cipher_list($ssl, $i++));
        $_SSLinfo{'selected'}   = Net::SSLeay::get_cipher($ssl);
            # same as above:      Net::SSLeay::CIPHER_get_name(Net::SSLeay::get_current_cipher($ssl));

        #5c. store certificate informations
        $_SSLinfo{'certificate'}= Net::SSLeay::dump_peer_certificate($ssl);  # same as issuer + subject
        #$_SSLinfo{'master_key'} = Net::SSLeay::SESSION_get_master_key($ssl); # TODO: returns binary, hence see below
        $_SSLinfo{'PEM'}        = Net::SSLeay::PEM_get_string_X509($x509) || "";
            # 'PEM' set empty for example when $Net::SSLinfo::no_cert is in use
            # this inhibits warnings inside perl (see  NO Certificate  below)
        $_SSLinfo{'version'}    = _ssleay_get('version', $x509);
        $_SSLinfo{'subject'}    = _ssleay_get('subject', $x509);
        $_SSLinfo{'issuer'}     = _ssleay_get('issuer',  $x509);
        $_SSLinfo{'before'}     = _ssleay_get('before',  $x509);
        $_SSLinfo{'after'}      = _ssleay_get('after',   $x509);
        $_SSLinfo{'policies'}   = _ssleay_get('policies',$x509);
        if (1.33 <= $Net::SSLeay::VERSION) {# condition stolen from IO::Socket::SSL,
            $_SSLinfo{'altname'}= _ssleay_get('altname', $x509);
        } else {
            warn "**WARNING: Net::SSLeay >= 1.33 required for getting subjectAltNames";
        }
        if (1.30 <= $Net::SSLeay::VERSION) {# condition stolen from IO::Socket::SSL
            $_SSLinfo{'cn'}     = _ssleay_get('cn', $x509);
            $_SSLinfo{'cn'}     =~ s{\0$}{};# work around Bug in Net::SSLeay <1.33 (from IO::Socket::SSL)
        } else {
            warn "**WARNING: Net::SSLeay >= 1.30 required for getting commonName";
        }
        if (1.45 <= $Net::SSLeay::VERSION) {
            $_SSLinfo{'fingerprint_md5'} = _ssleay_get('md5',  $x509);
            $_SSLinfo{'fingerprint_sha1'}= _ssleay_get('sha1', $x509);
        } else {
            warn "**WARNING: Net::SSLeay >= 1.45 required for getting fingerprint_md5";
        }
        if (1.46 <= $Net::SSLeay::VERSION) {# see man Net::SSLeay
            #$_SSLinfo{'pubkey_value'}   = Net::SSLeay::X509_get_pubkey($x509);
                # TODO: returns a structure, needs to be unpacked
            $_SSLinfo{'error_verify'}   = Net::SSLeay::X509_verify_cert_error_string(Net::SSLeay::get_verify_result($ssl));
            $_SSLinfo{'error_depth'}    = Net::SSLeay::X509_STORE_CTX_get_error_depth($x509);
            $_SSLinfo{'serial_hex'}     = _ssleay_get('serial_hex', $x509);
            $_SSLinfo{'cert_type'}      = sprintf("0x%x  <<experimental>>", Net::SSLeay::X509_certificate_type($x509));
            $_SSLinfo{'subject_hash'}   = sprintf("%x", Net::SSLeay::X509_subject_name_hash($x509));
            $_SSLinfo{'issuer_hash'}    = sprintf("%x", Net::SSLeay::X509_issuer_name_hash($x509));
                # previous two values are integers, need to be converted to
                # hex, we omit a leading 0x so they can be used elswhere
        } else {
            warn "**WARNING: Net::SSLeay >= 1.46 required for getting some certificate checks";
        }
        $_SSLinfo{'commonName'} = $_SSLinfo{'cn'};
        $_SSLinfo{'authority'}  = $_SSLinfo{'issuer'};
        $_SSLinfo{'owner'}      = $_SSLinfo{'subject'};
            # used by IO::Socket::SSL, allow for compatibility and lazy user
            #   owner commonName cn subject issuer authority subjectAltNames
            #   alias: owner == subject, issuer == authority, commonName == cn

        # TODO: certificate chain depth, OCSP
        # see: http://search.cpan.org/~mikem/Net-SSLeay-1.68/lib/Net/SSLeay.pod#Certificate_verification_and_Online_Status_Revocation_Protocol_%28OCSP%29

        #5d. get data related to HTTP(S)
        if ($Net::SSLinfo::use_http > 0) {
            _trace("do_ssl_open HTTPS {");
            #dbx# $host .= 'x'; # TODO: <== some servers behave strange if a wrong hostname is passed
            my $response = "";
            my $request  = "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n";
            $src = 'Net::SSLeay::write()';
# $t1 = time();
#           ($ctx = Net::SSLeay::CTX_v23_new()) or {$src = 'Net::SSLeay::CTX_v23_new()'} and last;
            Net::SSLeay::write($ssl, $request) or {$err = $!} and last;
            $src = 'Net::SSLeay::read()';
            $response = Net::SSLeay::read($ssl) || "<<GET failed>>";
# TODO: Net::SSLeay::read() fails sometimes, i.e. for fancyssl.hboeck.de
# 03/2015: even using ssl_write_all() and ssl_read_all() does not help
# TODO: reason unknown, happens probably if server requires SNI
# $t2 = time(); set error = "<<timeout: Net::SSLeay::read()>>";
            $_SSLinfo{'https_status'}   =  $response;
            $_SSLinfo{'https_status'}   =~ s/[\r\n].*$//ms; # get very first line
            $_SSLinfo{'https_server'}   =  _header_get('Server',   $response);
            $_SSLinfo{'https_location'} =  _header_get('Location', $response);
            $_SSLinfo{'https_refresh'}  =  _header_get('Refresh',  $response);
            $_SSLinfo{'https_pins'}     =  _header_get('Public-Key-Pins', $response);
            $_SSLinfo{'https_protocols'}=  _header_get('Alternate-Protocol', $response);
            $_SSLinfo{'https_svc'}      =  _header_get('Alt-Svc',  $response);
            $_SSLinfo{'https_sts'}      =  _header_get('Strict-Transport-Security', $response);
            $_SSLinfo{'hsts_maxage'}    =  $_SSLinfo{'https_sts'};
            $_SSLinfo{'hsts_maxage'}    =~ s/.*?max-age=([^;" ]*).*/$1/i;
            $_SSLinfo{'hsts_subdom'}    = 'includeSubDomains' if ($_SSLinfo{'https_sts'} =~ m/includeSubDomains/i);
# TODO:     $_SSLinfo{'hsts_alerts'}    =~ s/.*?((?:alert|error|warning)[^\r\n]*).*/$1/i;
# TODO: HTTP header:
#    X-Firefox-Spdy: 3.1
            _trace("\n$response \n# do_ssl_open HTTPS }");
            _trace("do_ssl_open HTTP {");   # HTTP uses its own connection ...
            my %headers;
            $src = 'Net::SSLeay::get_http()';
            ($response, $_SSLinfo{'http_status'}, %headers) = Net::SSLeay::get_http($host, 80, '/',
                 Net::SSLeay::make_headers('Connection' => 'close', 'Host' => $host)
            );
                # Net::SSLeay 1.58 (and before)
                # Net::SSLeay::get_http() may return:
                # Read error: Connection reset by peer (,199725) at blib/lib/Net/SSLeay.pm (autosplit into blib/lib/auto/Net/SSLeay/tcp_read_all.al) line 535.
                # Read error: Die Verbindung wurde vom Kommunikationspartner zurückgesetzt (,199725) at blib/lib/Net/SSLeay.pm (autosplit into blib/lib/auto/Net/SSLeay/tcp_read_all.al) line 535.
                #
                # Unfortunately in this case  Net::SSLeay::ERR_get_error is 0
                # and  Net::SSLeay::print_errs()  returns nothing even the error
		# is present as string (according current locale) in $!.
                # It still may return a response and a status, hence there is
                # need to handle it special as the check for the status below
                # already does the work.
		# The error is printed by Net/SSLeay, and cannot be omitted.
                #
                # Following error ocours (Net::SSLeay 1.58) when _http() failed:
                # Use of uninitialized value $headers in split at blib/lib/Net/SSLeay.pm (autosplit into blib/lib/auto/Net/SSLeay/do_httpx2.al) line 1291.

# $t3 = time(); set error = "<<timeout: Net::SSLeay::get_http()>>";
            if ($_SSLinfo{'http_status'} =~ m:^HTTP/... ([1234][0-9][0-9]|500) :) {
                # TODO: not tested if following grep() catches multiple occourances
                $_SSLinfo{'http_location'}  =  $headers{(grep{/^Location$/i} keys %headers)[0] || ""};
                $_SSLinfo{'http_refresh'}   =  $headers{(grep{/^Refresh$/i}  keys %headers)[0] || ""};
                $_SSLinfo{'http_sts'}       =  $headers{(grep{/^Strict-Transport-Security$/i} keys %headers)[0] || ""};
                $_SSLinfo{'http_svc'}       =  $headers{(grep{/^Alt-Svc$/i} keys %headers)[0]  || ""};
                $_SSLinfo{'http_protocols'} =  $headers{(grep{/^Alternate-Protocol/i} keys %headers)[0] || ""};
                # TODO: http_protocols somtimes fails, reason unknown (03/2015)
            } else { # any status code > 500
                #no print "**WARNING: http:// connection refused; consider using --no-http"; # no print here!
                push(@{$_SSLinfo{'errors'}}, "do_ssl_open() WARNING $src: " . $_SSLinfo{'http_status'});
                if ($_SSLinfo{'http_status'} =~ m:^HTTP/... (50[12345]) :) {
                    # If we get status 50x, there is most likely a (local)
                    # proxy which is not able to connect to the target.
                    # This could either be 'cause the target refuses the
                    # connection (status 503 and 504) or 'cause the proxy
                    # itself has a problem.
                    # HTTP headers and response may contain more hints.
                    push(@{$_SSLinfo{'errors'}}, "do_ssl_open() WARNING $src: check HTTP gateway");
                #} else { Net::SSLeay::get_http() most likely returns status 900
                }
                $response = ""; # avoid uninitialized value later
            }
            _trace("\n$response \n# do_ssl_open HTTP }");
        }

        if ($Net::SSLinfo::use_openssl == 0) {
            # calling external openssl is a performance penulty
            # it would be better to manually parse $_SSLinfo{'text'} but that
            # needs to be adapted to changes of openssl's output then
            _trace("do_ssl_open() without openssl done.");
            goto finished;
        }

        #5e. get data from openssl, if required
        # NOTE: all following are only available when openssl is used
        #       those alredy set before will be overwritten

        # NO Certificate {
        # We get following data using openssl executable.
        # There is no need  to check  $Net::SSLinfo::no_cert  as openssl is
        # clever enough to return following strings if the cert is missing:
        #         unable to load certificate
        # If we use  'if (defined $_SSLinfo{'PEM'}) '  instead of an empty
        # $_SSLinfo{'PEM'}  (see initial setting above),  then  all values
        # would contain an empty string instead of the the openssl warning:
        #         unable to load certificate
        my $fingerprint                 = _openssl_x509($_SSLinfo{'PEM'}, '-fingerprint');
        chomp $fingerprint;
        $_SSLinfo{'fingerprint_text'}   = $fingerprint;
        $_SSLinfo{'fingerprint'}        = $fingerprint; #alias
       ($_SSLinfo{'fingerprint_type'},  $_SSLinfo{'fingerprint_hash'}) = split(/=/, $fingerprint);
        $_SSLinfo{'fingerprint_type'}   =~ s/(^[^\s]*).*/$1/;
        $_SSLinfo{'fingerprint_hash'}   = "" if (!defined $_SSLinfo{'fingerprint_hash'});
        $_SSLinfo{'subject_hash'}       = _openssl_x509($_SSLinfo{'PEM'}, '-subject_hash');
        $_SSLinfo{'issuer_hash'}        = _openssl_x509($_SSLinfo{'PEM'}, '-issuer_hash');
        $_SSLinfo{'version'}            = _openssl_x509($_SSLinfo{'PEM'}, 'version');
        $_SSLinfo{'text'}               = _openssl_x509($_SSLinfo{'PEM'}, '-text');
        $_SSLinfo{'modulus'}            = _openssl_x509($_SSLinfo{'PEM'}, '-modulus');
       #$_SSLinfo{'serial'}             = _openssl_x509($_SSLinfo{'PEM'}, '-serial');
        $_SSLinfo{'email'}              = _openssl_x509($_SSLinfo{'PEM'}, '-email');
        $_SSLinfo{'trustout'}           = _openssl_x509($_SSLinfo{'PEM'}, '-trustout');
        $_SSLinfo{'ocsp_uri'}           = _openssl_x509($_SSLinfo{'PEM'}, '-ocsp_uri');
        $_SSLinfo{'ocspid'}             = _openssl_x509($_SSLinfo{'PEM'}, '-ocspid');
        $_SSLinfo{'aux'}                = _openssl_x509($_SSLinfo{'PEM'}, 'aux');
        $_SSLinfo{'pubkey'}             = _openssl_x509($_SSLinfo{'PEM'}, 'pubkey');
        $_SSLinfo{'extensions'}         = _openssl_x509($_SSLinfo{'PEM'}, 'extensions');
        $_SSLinfo{'signame'}            = _openssl_x509($_SSLinfo{'PEM'}, 'signame');
        $_SSLinfo{'sigdump'}            = _openssl_x509($_SSLinfo{'PEM'}, 'sigdump');
       ($_SSLinfo{'sigkey_value'}       =  $_SSLinfo{'sigdump'}) =~ s/.*?\n//ms;
       ($_SSLinfo{'pubkey_algorithm'}   =  $_SSLinfo{'pubkey'})  =~ s/^.*?Algorithm: ([^\r\n]*).*/$1/si;
       ($_SSLinfo{'pubkey_value'}       =  $_SSLinfo{'pubkey'})  =~ s/^.*?Modulus ?([^\r\n]*)//si;
            # damn Windows: some versions behave like *NIX and return:
            #                Modulus (2048 bit):
            # but some versions return:
            #                Modulus:
            # which makes the regex dirty: space followed by question mark
        $_SSLinfo{'pubkey_value'}       =~ s/^.*?pub:([^\r\n]*)//si;
            # public key with EC use  "pub:" instead of "Modulus:"
        $_SSLinfo{'pubkey_value'}       =~ s/(Exponent|ASN1 OID).*//si;
            # public key with EC use  "ASN1 OID:" instead of "Exponent:"
        $_SSLinfo{'modulus_exponent'}   =  $_SSLinfo{'pubkey'};
        $_SSLinfo{'modulus_exponent'}   =~ s/^.*?(?:Exponent|ASN1 OID): (.*)$/$1/si;
        $_SSLinfo{'modulus'}            =~ s/^[^=]*=//i;
        $_SSLinfo{'serial'}             =~ s/^[^=]*=//i;
        $_SSLinfo{'signame'}            =~ s/^[^:]*: //i;
        $_SSLinfo{'modulus_len'}        =  4 * length($_SSLinfo{'modulus'});
            # Note: modulus is hex value where 2 characters are 8 bit
        $_SSLinfo{'sigkey_len'}         =  $_SSLinfo{'sigkey_value'};
        $_SSLinfo{'sigkey_len'}         =~ s/[\s\n]//g;
        $_SSLinfo{'sigkey_len'}         =~ s/[:]//g;
        $_SSLinfo{'sigkey_len'}         =  4 * length($_SSLinfo{'sigkey_len'});
        chomp $_SSLinfo{'fingerprint_hash'};
        chomp $_SSLinfo{'modulus'};
        chomp $_SSLinfo{'pubkey'};
        chomp $_SSLinfo{'serial'};
        chomp $_SSLinfo{'signame'};
        # NO Certificate }

        $_SSLinfo{'s_client'}       = do_openssl('s_client', $host, $port, '');

            # from s_client: (if openssl supports -nextprotoneg)
            #    Protocols advertised by server: spdy/4a4, spdy/3.1, spdy/3, http/1.1

            # from s_client: (openssl > 1.0.1)
            #    Peer signing digest: SHA512
            #    Server Temp Key: DH, 2048 bits
            #    Server Temp Key: ECDH, P-256, 256 bits

            # from s_client:
            #  SSL-Session:
            #    Protocol  : TLSv1
            #    Cipher    : ECDHE-RSA-RC4-SHA
            #    Session-ID: 322193A0D243EDD1C07BA0B2E68D1044CDB06AF0306B67836558276E8E70655C
            #    Session-ID-ctx: 
            #    Master-Key: EAC0900291A1E5B73242C3C1F5DDCD4BAA7D9F8F4BC6E640562654B51E024143E5403716F9BF74672AF3703283456403
            #    Key-Arg   : None
            #    Krb5 Principal: None
            #    PSK identity: None
            #    PSK identity hint: None
            #    SRP username: None
            #    Timeout   : 300 (sec)
            #    Compression: zlib compression
            #    Expansion: zlib compression
            #    TLS session ticket lifetime hint: 100800 (seconds)
            #    TLS session ticket:
            #    0000 - 00 82 87 03 7b 42 7f b5-a2 fc 9a 95 9c 95 2c f3   ....{B........,.
            #    0010 - 69 91 54 a9 5b 7a 32 1c-08 b1 6e 3c 8c b7 b8 1f   i.T.[z2...n<....
            #    0020 - e4 89 63 3e 3c 0c aa bd-96 70 30 b2 cd 1e 2d c0   ..c><....p0...-.
            #    0030 - e7 fe 10 cd d4 82 e9 8f-d8 ee 91 16 02 42 7b 93   .............B{.
            #    0040 - fc 93 82 c4 d3 fd 0a f3-c6 3d 77 ab 1d 25 4f 5a   .........=w..%OZ
            #    0050 - fc 44 9a 21 3e cb 18 e9-a4 44 1b 30 7c 98 4d 04   .D.!>....D.0|.M.
            #    0060 - bb 12 3e 67 c8 9a ad 99-b4 50 32 81 1e 54 70 2d   ..>g.....P2..Tp-
            #    0070 - 06 08 82 30 9a 94 82 6f-e2 fa c7 e8 5a 19 af dc   ...0...o....Z...
            #    0080 - 70 45 71 f9 d1 e6 a8 d7-3c c2 c6 b8 e1 d5 4f dd   pEq.....<.....O.
            #    0090 - 52 12 f3 90 0c 51 c5 81-6c 9e 69 b6 bd 0c e6 e6   R....Q..l.i.....
            #    00a0 - 4c d4 72 33                                       L.r3
            #
            #    Start Time: 1435254245
        my %match_map = (
            # %_SSLinfo key       string to match in s_client output
            #-------------------+-----------------------------------
            'session_id'       => "Session-ID:",
            'master_key'       => "Master-Key:",
            'krb5'             => "Krb5 Principal:",
            'psk_identity'     => "PSK identity:",
            'psk_hint'         => "PSK identity hint:",
            'srp'              => "SRP username:",
            'compression'      => "Compression:",
            'expansion'        => "Expansion:",
            'alpn'             => "ALPN protocol:",
            'no_alpn'          => "No ALPN negotiated", # has no value, see below
            'next_protocol'    => "Next protocol:",
            'protocols'        => "Protocols advertised by server:",
            'session_protocol' => "Protocol\\s+:",      # \s must be meta
            'session_timeout'  => "Timeout\\s+:",       # \s must be meta
            'session_lifetime' => "TLS session ticket lifetime hint:",
            #'session_ticket'   => "TLS session ticket:",
                # this is a multiline value, must be handled special, see below
            #'renegotiation'    => "Renegotiation",
                # Renegotiation comes with different values, see below
            'dh_parameter'     => "Server Temp Key:",
        );
        my $d    = "";
        my $data = $_SSLinfo{'text'};
        # from text:
        #        Serial Number: 11598581680733355983 (0xa0f670963276ffcf)
        $d = $data; $d =~ s/.*?Serial Number:\s*(.*?)\n.*/$1/si;
        $_SSLinfo{'serial'}             = $d;
        $d =~ s/\s.*$//;
        $_SSLinfo{'serial_int'}         = $d;
            # getting integer value from text representation 'cause
            # Net::SSLeay does not have a proper function
            # and converting the retrived hex value to an int with
            # hex($hex)  returns an error without module bigint
        if ($d =~ m/[0-9a-f]:/i) {
            # some certs return  09:f5:fd:2e:a5:2a:85:48:db:be:5d:a0:5d:b6
            # or similar, then we try to convert to integer manually
            $d =~ s/://g;
            my $b = 8;  # the usual size in 64-bit systems
            if (length($d) > 8) {   # check if we are on 32-bit system
                # on 32-bit systems perl may handle large numbers correctly
                # if compiled properly, can be checked with $Config{ivsize}
                # so we need the value which requires loading the module
                #
                # cannot use eval with block form here, needs to be quoted
                ## no critic qw(BuiltinFunctions::ProhibitStringyEval)
                if (eval('use Configx; $b = $Config{ivsize};')) {
                    # use $Config{ivsize}
                } else {
                    $err = "use Config";
                    push(@{$_SSLinfo{'errors'}}, "do_ssl_open() failed calling $src: $err");
                    $_SSLinfo{'serial_int'} = "<<$err failed>>";
                }
                ## use critic
            }
            if ((length($d) > $b)   # larger than integer of this architecture
              ||(length($d) > 16))  # to large at all
            {  # ugly check if we need bigint
                if (eval {require Math::BigInt;}) {
                    $_SSLinfo{'serial_int'} = Math::BigInt->from_hex($d);
                } else {
                    $err = "Math::BigInt->from_hex($d)";
                    push(@{$_SSLinfo{'errors'}}, "do_ssl_open() failed calling $src: $err");
                    $_SSLinfo{'serial_int'} = "<<$err failed>>";
                }
            } else {
                $_SSLinfo{'serial_int'} = hex($d);
            }
        }

        $data = $_SSLinfo{'s_client'};
            # Note: as openssl s_client is called with -resume, the retrived
            # data may contain output of s_client up to 5 times
            # it's not ensured that all 5 data sets are identical, hence
            # we need to check them all -at least the last one-
            # Unfortunately all following checks use all 5 data sets.
        foreach my $key (keys %match_map) {
            my $regex = $match_map{$key};
            $d = $data;
            $d =~ s/.*?$regex\s*([^\n]*)\n.*/$1/si;
            if ($data =~ m/$regex/) {
                $_SSLinfo{$key} = $d if ($data =~ m/$regex/);
                $_SSLinfo{$key} = $regex if ($key eq 'no_alpn');
                    # no_alpn: single line, has no value: No ALPN negotiated
            }
        }

        $d = $data; $d =~ s/.*?TLS session ticket:\s*[\n\r]+(.*?)\n\n.*/$1_/si;
        if ($data =~ m/TLS session ticket:/) {
            $d =~ s/\s*[0-9a-f]{4}\s*-\s*/_/gi;   # replace leading numbering with marker
            $d =~ s/^_//g;         # remove useless marker
            $d =~ s/   .{16}//g;   # remove traling characters
            $d =~ s/[^0-9a-f]//gi; # remove all none hex characters
            $_SSLinfo{'session_ticket'} = $d;
        }

            # from s_client:
            #   Secure Renegotiation IS supported
            #   Secure Renegotiation IS NOT supported
            # TODO: pedantically we also need to check if "RENEGOTIATING" is
            #       there, as just the information "IS supported" does not
            #       mean that it works
        $d = $data; $d =~ s/.*?((?:Secure\s*)?Renegotiation[^\n]*)\n.*/$1/si; $_SSLinfo{'renegotiation'}  = $d;

            # from s_client:
            #    Reused, TLSv1/SSLv3, Cipher is RC4-SHA
            #    Session-ID: F4AD8F441FDEBDCE445D4BD676EE592F6A0CEDA86F08860DF824F8D29049564F
            #    Start Time: 1387270456
            # we do a simple check: just grep for "Reused" in s_client
            # in details it should check if all "Reused" strings are
            # identical *and* the "Session-ID" is the same for all
            # if more than 2 "New" are detected, we assume no resumption
            # finally "Reused" must be part of s_client data
            # should also check "Start Time"
        $d = $data;
        my $cnt =()= $d =~ m/(New|Reused),/g;
        if ($cnt < 3) {
            _trace("do_ssl_open: slow target server; resumption not detected; try to increase \$Net::SSLinfo::timeout_sec");
        } else {
            $cnt =()= $d =~ m/New,/g;
            _trace("do_ssl_open: checking resumption: found $cnt `New' ");
            if ($cnt > 2) { # too much "New" reconnects, assume no resumption
                $cnt =()= $d =~ m/Reused,/g;
                _trace("do_ssl_open: checking resumption: found $cnt `Reused' ");
                $_SSLinfo{'resumption'} = 'no';
            } else {
                $d =~ s/.*?(Reused,[^\n]*).*/$1/si;
                $_SSLinfo{'resumption'} = $d if ($d =~ m/Reused,/);
            }
        }

            # from s_client (different openssl return different strings):
            #       verify error:num=10:certificate has expired
            #       verify error:num=18:self signed certificate
            #       verify error:num=20:unable to get local issuer certificate
            #       verify error:num=21:unable to verify the first certificate
            #       verify error:num=27:certificate not trusted
            #       Verify return code: 10 (certificate has expired)
            #       Verify return code: 19 (self signed certificate in certificate chain)
            #       Verify return code: 20 (unable to get local issuer certificate)
            #       Verify return code: 21 (unable to verify the first certificate)
        $d = $data; $d =~ s/.*?Verify (?:error|return code):\s*((?:num=)?[\d]*[^\n]*).*/$1/si;
        $_SSLinfo{'verify'}         = $d;
        # TODO: $_SSLinfo{'verify_host'}= $ssl->verify_hostname($host, 'http');  # returns 0 or 1
        # scheme can be: ldap, pop3, imap, acap, nntp http, smtp

        $d =~ s/.*?(self signed.*)/$1/si;
        $_SSLinfo{'selfsigned'}     = $d;
            # beside regex above, which relies on strings returned from s_client
            # we can compare subject_hash and issuer_hash, which are eqal when
            # self-digned
        
            # from s_client:
            # $_SSLinfo{'s_client'} grep
            #       Certificate chain
        $d = $data; $d =~ s/.*?Certificate chain[\r\n]+(.*?)[\r\n]+---[\r\n]+.*/$1/si;
        $_SSLinfo{'chain'}          = $d;
        
            # from s_client:
            # $_SSLinfo{'s_client'} grep
            #       depth=  ... ---
        $d = $data; $d =~ s/.*?(depth=-?[0-9]+.*?)[\r\n]+---[\r\n]+.*/$1/si;
        $_SSLinfo{'chain_verify'}   = $d;

            # from s_client -tlsextdebug -nextprotoneg
            # TLS server extension "renegotiation info" (id=65281), len=1
            # TLS server extension "session ticket" (id=35), len=0
            # TLS server extension "heartbeat" (id=15), len=1
            # TLS server extension "EC point formats" (id=11), len=4
            # TLS server extension "next protocol" (id=13172), len=25
            # TLS server extension "session ticket" (id=35), len=0
        foreach my $line (split(/[\r\n]+/, $data)) {
            next if ($line !~ m/TLS server extension/i);
            $d = $line;
            $d =~ s/TLS server extension\s*"([^"]*)"/$1/i;
                # remove prefix text, but leave id= and len= for caller
            my $rex =  $d;  # $d may contain regex meta characters, like ()
               $rex =~ s#([(/*)])#\\$1#g;
            next if ((grep{/$rex/} split(/\n/, $_SSLinfo{'tlsextensions'})) > 0);
            $_SSLinfo{'tlsextdebug'}   .= "\n" . $line;
            $_SSLinfo{'tlsextensions'} .= "\n" . $d;
            $_SSLinfo{'heartbeat'}= $d if ($d =~ m/heartbeat/);
            # following already done, see above, hence with --trace only
            _trace("-tlsextdebug  $d") if ($d =~ m/session ticket/);
            _trace("-tlsextdebug  $d") if ($d =~ m/renegotiation info/);
        }
        $_SSLinfo{'tlsextensions'} =~ s/\([^)]*\),?\s+//g;  # remove additional informations
        $_SSLinfo{'tlsextensions'} =~ s/\s+len=\d+//g;      # ...

        _trace("do_ssl_open() with openssl done.");
        print Net::SSLinfo::datadump() if ($trace > 0);
        goto finished;
    } # TRY

    #6. error handling
    push(@{$_SSLinfo{'errors'}}, "do_ssl_open() failed calling $src: $err");
    if ($trace > 1) {
        Net::SSLeay::print_errs(SSLINFO_ERR);
        print SSLINFO_ERR . $_ foreach @{$_SSLinfo{'errors'}};
    }
    _trace("do_ssl_open() failed.");
    return;

    finished:
    _trace("do_ssl_open() done.");
    return wantarray ? ($_SSLinfo{'ssl'}, $_SSLinfo{'ctx'}) : $_SSLinfo{'ssl'};
} # do_ssl_open

=pod

=head2 do_ssl_close( )

Close L<Net::SSLeay> connection and free allocated objects.
=cut

sub do_ssl_close($$) {
    #? close TCP connection for SSL
    my ($host, $port) = @_;
    _trace("do_ssl_close($host,$port)");
    Net::SSLeay::free($_SSLinfo{'ssl'})     if (defined $_SSLinfo{'ssl'}); # or warn "**WARNING: Net::SSLeay::free(): $!";
    Net::SSLeay::CTX_free($_SSLinfo{'ctx'}) if (defined $_SSLinfo{'ctx'}); # or warn "**WARNING: Net::SSLeay::CTX_free(): $!";
    _SSLinfo_reset();
    if (defined $Net::SSLinfo::socket) {
        close($Net::SSLinfo::socket);
        $Net::SSLinfo::socket = undef;
    } else {
        warn "**WARNING: undefined Net::SSLinfo::socket; connection cannot be closed";
        # this is most likely a programming error, or usage of an old caller
    }
    return;
} # do_ssl_close

=pod

=head2 do_openssl($command,$host,$port,$data)

Wrapper for call of external L<openssl(1)> executable. Handles special
behaviours on some platforms.

If I<$command> equals C<s_client> it will add C<-reconnect -connect> to the
openssl call. All other values of I<$command> will be used verbatim.
Note that the SSL version must be part (added) as proper openssl option
to C<$command> as this option cannot preceed the command in openssl..

Examples for I<$command>:

    ciphers -sslv3

    s_client -tlsv1_1 -connect

The value of I<$data>, if set, is piped to openssl.

Returns retrieved data or '<<openssl>>' if openssl or s_client missing.
=cut

sub do_openssl($$$$) {
    #? call external openssl executable to retrive more data
    my $mode = shift;   # must be openssl command
    my $host = shift;
    my $port = shift || "";  # may be empty for some calls
    my $pipe = shift || "";  # piped data is optional
    my $data = "";
    my $capath = $Net::SSLinfo::ca_path || "";
    my $cafile = $Net::SSLinfo::ca_file || "";
    _trace("do_openssl($mode,$host,$port...).");
    _setcmd();
    if ($_openssl eq '') {
        _trace("do_openssl($mode): WARNING: no openssl");
        return SSLINFO_HASH;
    }
    if ($mode =~ m/^-?(s_client)$/) {
        if ($Net::SSLinfo::use_sclient == 0) {
            _trace("do_openssl($mode): WARNING: no openssl s_client") if ($trace > 1);
            return SSLINFO_HASH;
        }
        # pass -nextprotoneg option to validate 'protocols' support later
        # pass -reconnect option to validate 'resumption' support later
        # pass -tlsextdebug option to validate 'heartbeat' support later
        # NOTE that openssl 1.x or later is required for -nextprotoneg
        $mode  = 's_client' . $Net::SSLinfo::sclient_opt;
# FIXME: { following fixes general verify, but not self signed
#        $mode .= ' -CApath ' . $capath if ($capath ne "");
#        $mode .= ' -CAfile ' . $cafile if ($cafile ne "");
# }
        $mode .= ' -nextprotoneg ' . $Net::SSLinfo::protocols if ($Net::SSLinfo::use_nextprot == 1);
        $mode .= ' -reconnect'   if ($Net::SSLinfo::use_reconnect == 1);
        $mode .= ' -tlsextdebug' if ($Net::SSLinfo::use_extdebug  == 1);
        $mode .= ' -connect';
    }
    $host = $port = "" if ($mode =~ m/^-?(ciphers)/);
    _trace("echo '' | $_timeout $_openssl $mode $host:$port 2>&1") ;
    if ($^O !~ m/MSWin32/) {
        $host .= ':' if ($port ne '');
        $data = `echo $pipe | $_timeout $_openssl $mode $host$port 2>&1`;
        if ($data =~ m/(\nusage:|unknown option)/s) { 
            _trace("do_openssl($mode): WARNING: openssl does not support -nextprotoneg option");
            $mode =  's_client -reconnect -connect';
            $data = `echo $pipe | $_timeout $_openssl $mode $host$port 2>&1`;
        }
    } else {
        $data = _openssl_MS($mode, $host, $port, '');
        if ($data =~ m/(\nusage:|unknown option)/s) { # we like performance penulties ...
            _trace("do_openssl($mode): WARNING: openssl does not support -nextprotoneg option");
            $data = _openssl_MS($mode, $host, $port, '');
        }
    }
    if ($mode =~ m/^-?(ciphers)/) { # check for errors in getting cipher list
        if ($data =~ m/^\s*(?:Error|openssl)(?: |:)/i) {
            push(@{$_SSLinfo{'errors'}}, "do_openssl($mode) failed: $data");
            $data =  "";
        }
    }
    chomp $data;
    $data =~ s/\s*$//;  # be sure ...
    return $data;
} # do_openssl

# From here on, we use a pod sections for multiple functions, then the
# corresponding function definitions follow that section. This is done
# to make the code more readable for humans.

=pod

=head2 set_cipher_list($ssl,$cipherlist)

Set cipher list for connection.

Returns empty string on success, errors otherwise.
=cut

sub set_cipher_list($$) {
    my $ssl    = shift;
    my $cipher = shift;
    Net::SSLeay::set_cipher_list($ssl, $cipher) or return SSLINFO . '::set_cipher_list(' . $cipher . ')';
    $_SSLinfo{'cipherlist'} = $cipher;
    return '';
}

=pod

=head2 errors( )

Get list of errors, intenal ones but most likely from I<$Net::SSLeay::*> calls.

=head2 s_client( )

Dump data retrived from "openssl s_client ..." call. For debugging only.

=head2 options( )

Return hex value bitmask of (openssl) options used to establish connection.
Useful for debugging and trouble shooting.

=head2 PEM( ), pem( )

Get certificate in PEM format.

=head2 text( )

Get certificate in human readable format.

=head2 before( )

Get date before certificate is valid.

=head2 after( )

Get date after certificate is valid.

=head2 dates( )

Get dates when certificate is valid.

=head2 issuer( )

Get issuer of certificate.

=head2 subject( )
 
Get subject of certificate.

=head2 selected( )

Get cipher selected by server for current session. Returns ciphers string.

=head2 cipher_list($pattern)

Get cipher list offered by local SSL implementation. Returns space-separated list of ciphers.
Returns array if used in array context, a single string otherwise.

Requires successful connection to target.

=head2 ciphers($pattern)

Returns List of ciphers provided for current connection to target.

=head2 cipher_local($pattern)

Get cipher list offered by local openssl implementation. Returns colon-separated list of ciphers.

Does not require connection to any target.

=cut

sub cipher_list {
    my $pattern = shift || $_SSLinfo{'cipherlist'}; # use default if unset
    my ($ctx, $ssl, $cipher);
    my $priority = 0;
    my @list;
    _trace("cipher_list($pattern)");
    TRY: { # defensive programming with simple error checks
        # just getting local ciphers does not need sophisticated error handling
        ($ctx = Net::SSLeay::CTX_new()) or last;
        ($ssl=  Net::SSLeay::new($ctx)) or last;
        Net::SSLeay::set_cipher_list($ssl, $pattern) or last;
            # second parameter must not be empty; default see above
        push(@list, $cipher) while ($cipher = Net::SSLeay::get_cipher_list($ssl, $priority++));
    } # TRY
    Net::SSLeay::free($ssl)     if (defined $ssl);
    Net::SSLeay::CTX_free($ctx) if (defined $ctx);
    return (wantarray) ? @list : join(' ', @list);
} # cipher_list

sub cipher_local {
    my $pattern = shift || $_SSLinfo{'cipherlist'}; # use default if unset
    my $list;
    _trace("cipher_local($pattern)");
    _setcmd();
    _trace("_SSLinfo_get: openssl ciphers $pattern") if ($trace > 1);
    $list = do_openssl("ciphers $pattern", '', '', '');
    chomp  $list;
    return (wantarray) ? split(/[:\s]+/, $list) : $list;
} # cipher_local

## no critic qw(Subroutines::RequireArgUnpacking)
sub ciphers {
    return cipher_list( @_) if ($Net::SSLinfo::use_openssl == 0);
    return cipher_local(@_);
} # ciphers

# "critic Subroutines::RequireArgUnpacking" disabled from hereon for a couple
# of subs because using explicit variable declarations in each sub would make
# (human) reading more difficult; it is also ensured that the called function
# _SSLinfo_get()  does not modify the parameters.

=pod

All following functions have  $host and $port  parameter and return
information according the the connection, certificate for this connection.

=head2 cn( ), commonname( )

Get common name (CN) from certificate.

=head2 altname( )

Get alternate name (subjectAltNames) from certificate.

=head2 authority( )

Get authority (issuer) from certificate.

=head2 owner( )

Get owner (subject) from certificate.

=head2 certificate( )

Get certificate (subject, issuer) from certificate.

=head2 SSLversion( )

Get SSL protocol version used by connection.

=head2 version( )

Get version from certificate.
=cut

# TODO: not yet implemented
#=head2 keysize( )
#
#Get certificate private key size.
#
#=head2 keyusage( )
#
#Get certificate X509v3 Extended Key Usage (Version 3 and TLS only?)

=pod

=head2 test_ssleay( )

Test availability and print information about Net::SSLeay:
Example: C<perl -MNet::SSLinfo -le 'print Net::SSLinfo::test_ssleay();'>

=head2 datadump( )

Print all available (by Net::SSLinfo) data.

Due to huge amount of data, the value for s_client is usually omitted.
Please set I<$Net::SSLinfo::use_sclient gt 1> to print this data also.

=head2 (details)

All following require that I<$Net::SSLinfo::use_openssl=1;> being set.

=head2 compression( )

Get target's compression support.

=head2 exapansion( )

Get target's exapansion support.

=head2 protocols( )

Get protocols advertised by server,

=head2 alpn( )

Get target's selected protocol (ALPN).

=head2 no_alpn( )

Get target's not negotiated message (ALPN).

=head2 next_protocol( )

Get target's next protocol message (ALPN).

=head2 krb5

Get target's Krb5 Principal.

=head2 psk_identity

Get target's PSK identity.

=head2 psk_hint

Get target's PSK identity hint.

=head2 srp

Get target's SRP username.

=head2 master_key

Get target's Master-Key.

=head2 session_protocol

Get target's announced SSL protocols.

=head2 session_ticket

Get target's TLS session ticket.

=head2 session_ticket_hint, session_lifetime

Get target's TLS session ticket lifetime hint.

=head2 session_timeout

Get target's SSL session timeout.

=head2 dh_parameter( )

Get targets DH parameter.

=head2 fingerprint_hash( )

Get certificate fingerprint hash value.

=head2 fingerprint_md5( )

Get  MD5 fingerprint if available (Net::SSLeay >= 1.49)

=head2 fingerprint_sha1( )

Get SHA1 fingerprint if available (Net::SSLeay >= 1.49)

=head2 fingerprint_type( )

Get certificate fingerprint hash algorithm.

=head2 fingerprint_text( )

Get certificate fingerprint, which is the hash algorthm followed by the hash
value. This is usually the same as I<fingerprint_type()=fingerprint_hash()>.

=head2 fingerprint( )

Alias for I<fingerprint_text()>.

=head2 email( )

Get certificate email address(es).

=head2 serial_hex( )

Get certificate serial number as hex value.

=head2 serial_int( )

Get certificate serial number as integer value.

=head2 serial( )

Get certificate serial number as integer and hex value.

=head2 modulus( )

Get certificate modulus of the public key.

=head2 modulus_exponent( )

Get certificate modulus' exponent of the public key.

=head2 modulus_len( )

Get certificate modulus (bit) length of the public key.

=head2 pubkey( )

Get certificate's public key.

=head2 pubkey_algorithm( )

Get certificate's public key algorithm.

=head2 pubkey_value( )

Get certificate's public key value.
Same as I<modulus()>  but may be different format.

=head2 renegotiation( )

Get certificate's renegotiation support.

=head2 resumption( )

Get certificate's resumption support.
Some target servers respond with  `New' and `Reused'  connections in
unexpected sequence. If `Reused' is found and less than 3 `New' then
resumption is assumed. 

If resumption is not detected, increasing the timeout with i.e.
I<$Net::SSLinfo::timeout_sec = 5>  may return different results.

=head2 sigkey_len( )

Get certificate signature key (bit).

=head2 sigkey_value( )

Get certificate signature value (hexdump).

=head2 subject_hash( ), issuer_hash( )

Get certificate subject/issuer hash value (in hex).

=head2 verify( )

Get result of certificate chain verification.

=head2 error_verify( )

Get error string of certificate chain verification, if any.

=head2 error_depth( )

Get depth where certificate chain verification failed.

=head2 chain( )

Get certificate's CA chain.

=head2 chain_verify( )

Get certificate's CA chain verification trace (for debugging only).

=head2 selfsigned( )

If certificate is self signed.

=head2 https_alerts( )

Get HTTPS alerts send by server.

=head2 https_protocols( )

Get HTTPS Alterenate-Protocol header.

=head2 https_svc( )

Get HTTPS Alt-Svc header.

=head2 https_status( )

Get HTTPS response (aka status) line.

=head2 https_server( )

Get HTTPS Server header.

=head2 https_location( )

Get HTTPS Location header.

=head2 https_refresh( )

Get HTTPS Refresh header.

=head2 http_protocols( )

Get HTTP Alterenate-Protocol header.

=head2 http_svc( )

Get HTTP Alt-Svc header.

=head2 http_status( )

Get HTTP response (aka status) line.

=head2 http_location( )

Get HTTP Location header.

=head2 http_refresh( )

Get HTTP Refresh header.

=head2 http_sts( )

Get HTTP Strict-Transport-Security header, if any.

=head2 hsts( )

Get complete STS header.

=head2 hsts_maxage( )

Get max-age attribute of STS header.

=head2 hsts_subdom( )

Get includeSubDomains attribute of STS header.

=head2 https_pins( )

Get pins attribute of STS header.

=cut

sub errors          { return _SSLinfo_get('errors',           $_[0], $_[1]); }
sub s_client        { return _SSLinfo_get('s_client',         $_[0], $_[1]); }
sub options         { return _SSLinfo_get('_options',         $_[0], $_[1]); }
sub PEM             { return _SSLinfo_get('PEM',              $_[0], $_[1]); }
sub pem             { return _SSLinfo_get('PEM',              $_[0], $_[1]); } # alias for PEM
sub text            { return _SSLinfo_get('text',             $_[0], $_[1]); }
sub before          { return _SSLinfo_get('before',           $_[0], $_[1]); }
sub after           { return _SSLinfo_get('after',            $_[0], $_[1]); }
sub dates           { return _SSLinfo_get('dates',            $_[0], $_[1]); }
sub issuer          { return _SSLinfo_get('issuer',           $_[0], $_[1]); }
sub subject         { return _SSLinfo_get('subject',          $_[0], $_[1]); }
#sub default         { return _SSLinfo_get('selected',         $_[0], $_[1]); } # alias; used in VERSION < 14.11.14
sub selected        { return _SSLinfo_get('selected',         $_[0], $_[1]); }
sub cn              { return _SSLinfo_get('cn',               $_[0], $_[1]); }
sub commonname      { return _SSLinfo_get('cn',               $_[0], $_[1]); } # alias for cn
sub altname         { return _SSLinfo_get('altname',          $_[0], $_[1]); }
sub authority       { return _SSLinfo_get('authority',        $_[0], $_[1]); }
sub owner           { return _SSLinfo_get('owner',            $_[0], $_[1]); } # alias for subject
sub certificate     { return _SSLinfo_get('certificate',      $_[0], $_[1]); }
sub SSLversion      { return _SSLinfo_get('SSLversion',       $_[0], $_[1]); }
sub version         { return _SSLinfo_get('version',          $_[0], $_[1]); }
sub keysize         { return _SSLinfo_get('keysize',          $_[0], $_[1]); } # NOT IMPLEMENTED
sub keyusage        { return _SSLinfo_get('keyusage',         $_[0], $_[1]); } # NOT IMPLEMENTED
sub email           { return _SSLinfo_get('email',            $_[0], $_[1]); }
sub modulus         { return _SSLinfo_get('modulus',          $_[0], $_[1]); }
sub serial_hex      { return _SSLinfo_get('serial_hex',       $_[0], $_[1]); }
sub serial_int      { return _SSLinfo_get('serial_int',       $_[0], $_[1]); }
sub serial          { return _SSLinfo_get('serial',           $_[0], $_[1]); }
sub aux             { return _SSLinfo_get('aux',              $_[0], $_[1]); }
sub extensions      { return _SSLinfo_get('extensions',       $_[0], $_[1]); }
sub tlsextdebug     { return _SSLinfo_get('tlsextdebug',      $_[0], $_[1]); }
sub tlsextensions   { return _SSLinfo_get('tlsextensions',    $_[0], $_[1]); }
sub heartbeat       { return _SSLinfo_get('heartbeat',        $_[0], $_[1]); }
sub trustout        { return _SSLinfo_get('trustout',         $_[0], $_[1]); }
sub ocsp_uri        { return _SSLinfo_get('ocsp_uri',         $_[0], $_[1]); }
sub ocspid          { return _SSLinfo_get('ocspid',           $_[0], $_[1]); }
sub pubkey          { return _SSLinfo_get('pubkey',           $_[0], $_[1]); }
sub signame         { return _SSLinfo_get('signame',          $_[0], $_[1]); }
sub sigdump         { return _SSLinfo_get('sigdump',          $_[0], $_[1]); }
sub sigkey_value    { return _SSLinfo_get('sigkey_value',     $_[0], $_[1]); }
sub sigkey_len      { return _SSLinfo_get('sigkey_len',       $_[0], $_[1]); }
sub subject_hash    { return _SSLinfo_get('subject_hash',     $_[0], $_[1]); }
sub issuer_hash     { return _SSLinfo_get('issuer_hash',      $_[0], $_[1]); }
sub verify          { return _SSLinfo_get('verify',           $_[0], $_[1]); }
sub error_verify    { return _SSLinfo_get('error_verify',     $_[0], $_[1]); }
sub error_depth     { return _SSLinfo_get('error_depth',      $_[0], $_[1]); }
sub chain           { return _SSLinfo_get('chain',            $_[0], $_[1]); }
sub chain_verify    { return _SSLinfo_get('chain_verify',     $_[0], $_[1]); }
sub compression     { return _SSLinfo_get('compression',      $_[0], $_[1]); }
sub expansion       { return _SSLinfo_get('expansion',        $_[0], $_[1]); }
sub protocols       { return _SSLinfo_get('protocols',        $_[0], $_[1]); }
sub alpn            { return _SSLinfo_get('alpn',             $_[0], $_[1]); }
sub no_alpn         { return _SSLinfo_get('no_alpn',          $_[0], $_[1]); }
sub next_protocol   { return _SSLinfo_get('next_protocol',    $_[0], $_[1]); }
sub krb5            { return _SSLinfo_get('krb5',             $_[0], $_[1]); }
sub psk_hint        { return _SSLinfo_get('psk_hint',         $_[0], $_[1]); }
sub psk_identity    { return _SSLinfo_get('psk_identity',     $_[0], $_[1]); }
sub srp             { return _SSLinfo_get('srp',              $_[0], $_[1]); }
sub master_key      { return _SSLinfo_get('master_key',       $_[0], $_[1]); }
sub session_id      { return _SSLinfo_get('session_id',       $_[0], $_[1]); }
sub session_ticket  { return _SSLinfo_get('session_ticket',   $_[0], $_[1]); }
sub session_lifetime{ return _SSLinfo_get('session_lifetime', $_[0], $_[1]); }
sub session_ticket_hint{return _SSLinfo_get('session_lifetime',$_[0],$_[1]); } # alias
sub session_timeout { return _SSLinfo_get('session_timeout',  $_[0], $_[1]); }
sub session_protocol{ return _SSLinfo_get('session_protocol', $_[0], $_[1]); }
sub fingerprint_hash{ return _SSLinfo_get('fingerprint_hash', $_[0], $_[1]); }
sub fingerprint_text{ return _SSLinfo_get('fingerprint_text', $_[0], $_[1]); }
sub fingerprint_type{ return _SSLinfo_get('fingerprint_type', $_[0], $_[1]); }
sub fingerprint_sha1{ return _SSLinfo_get('fingerprint_sha1', $_[0], $_[1]); }
sub fingerprint_md5 { return _SSLinfo_get('fingerprint_md5' , $_[0], $_[1]); }
sub fingerprint     { return _SSLinfo_get('fingerprint',      $_[0], $_[1]); } # alias for fingerprint_text
sub cert_type       { return _SSLinfo_get('cert_type',        $_[0], $_[1]); }
sub modulus_len     { return _SSLinfo_get('modulus_len',      $_[0], $_[1]); }
sub modulus_exponent{ return _SSLinfo_get('modulus_exponent', $_[0], $_[1]); }
sub pubkey_algorithm{ return _SSLinfo_get('pubkey_algorithm', $_[0], $_[1]); }
sub pubkey_value    { return _SSLinfo_get('pubkey_value',     $_[0], $_[1]); }
sub renegotiation   { return _SSLinfo_get('renegotiation',    $_[0], $_[1]); }
sub resumption      { return _SSLinfo_get('resumption',       $_[0], $_[1]); }
sub dh_parameter    { return _SSLinfo_get('dh_parameter',     $_[0], $_[1]); }
sub selfsigned      { return _SSLinfo_get('selfsigned',       $_[0], $_[1]); }
sub https_protocols { return _SSLinfo_get('https_protocols',  $_[0], $_[1]); }
sub https_svc       { return _SSLinfo_get('https_svc',        $_[0], $_[1]); }
sub https_status    { return _SSLinfo_get('https_status',     $_[0], $_[1]); }
sub https_server    { return _SSLinfo_get('https_server',     $_[0], $_[1]); }
sub https_alerts    { return _SSLinfo_get('https_alerts',     $_[0], $_[1]); }
sub https_location  { return _SSLinfo_get('https_location',   $_[0], $_[1]); }
sub https_refresh   { return _SSLinfo_get('https_refresh',    $_[0], $_[1]); }
sub https_pins      { return _SSLinfo_get('https_pins',       $_[0], $_[1]); }
sub http_protocols  { return _SSLinfo_get('http_protocols',   $_[0], $_[1]); }
sub http_svc        { return _SSLinfo_get('http_svc',         $_[0], $_[1]); }
sub http_status     { return _SSLinfo_get('http_status',      $_[0], $_[1]); }
sub http_location   { return _SSLinfo_get('http_location',    $_[0], $_[1]); }
sub http_refresh    { return _SSLinfo_get('http_refresh',     $_[0], $_[1]); }
sub http_sts        { return _SSLinfo_get('http_sts',         $_[0], $_[1]); }
sub https_sts       { return _SSLinfo_get('https_sts',        $_[0], $_[1]); }
sub hsts_maxage     { return _SSLinfo_get('hsts_maxage',      $_[0], $_[1]); }
sub hsts_subdom     { return _SSLinfo_get('hsts_subdom',      $_[0], $_[1]); }

=pod

=head2 verify_hostname( )

Verify if given hostname matches common name (CN) in certificate.
=cut

############ TODO:  do_ssl_open  vorbereiten fuer verify_*
sub verify_hostname {
    my ($host, $port) = @_;
    return if !defined do_ssl_open($host, $port, '');
    return $Net::SSLinfo::no_cert_txt if ($Net::SSLinfo::no_cert != 0);
    my $cname = $_SSLinfo{'cn'};
    my $match = '';
    if ($Net::SSLinfo::ignore_case == 1) {
        $host = lc($host);
        $cname= lc($cname);
    }
    $match = ($host eq $cname) ? 'matches' : 'does not match';
    return sprintf("Given hostname '%s' %s CN '%s' in certificate", $host, $match, $cname);
}

=head2 verify_altname( ), verify_alias( )

Verify if given hostname matches alternate name (subjectAltNames) in certificate.
=cut

sub verify_altname($$) {
    my ($host, $port) = @_;
    return if !defined do_ssl_open($host, $port, '');
    return $Net::SSLinfo::no_cert_txt if ($Net::SSLinfo::no_cert != 0);
    _trace("verify_altname($host)");
    my $match = 'does not match';
    my $cname = $_SSLinfo{'altname'};
    return "No alternate name defined in certificate" if ($cname eq '');
    _trace("verify_altname: $cname");
    foreach my $alt (split(' ', $cname)) {
        my ($type, $name) = split(/:/, $alt);
# TODO: implement IP and URI
#dbx print "# ($type, $name)";
        push(@{$_SSLinfo{'errors'}}, "verify_altname() $type not supported in SNA") if ($type !~ m/DNS/i);
        my $rex = $name;
        if ($Net::SSLinfo::ignore_case == 1) {
            $host = lc($host);
            $rex  = lc($rex);
        }
        $rex =~ s/[.]/\\./g;
        if ($name =~ m/[*]/) {
            $rex =~ s/(\*)/.*?/;
        }
        _trace("verify_altname: $host =~ $rex ");
        if ($host =~ /^$rex$/) {
            $match = 'matches';
            $cname = $alt;   # only show matching name
            last;
        }
    }
    _trace("verify_altname() done.");
    return sprintf("Given hostname '%s' %s alternate name '%s' in certificate", $host, $match, $cname);
}

sub verify_alias { verify_altname($_[0], $_[1]); return; }

sub _check_peer() {
    # TBD
    my ($ok, $x509_store_ctx) = @_;
    _trace("_check_peer($ok, $x509_store_ctx)");
    $_SSLinfo{'verify_cnt'} += 1;
    return $ok;
}
sub _check_client_cert() {print "##check_client_cert\n"; return; }
#$my $err = Net::SSLeay::set_verify ($ssl, Net::SSLeay::VERIFY_CLIENT_ONCE, \&_check_client_cert );

sub _check_crl($$) {
    # TBD
    my $ssl = shift;
    _trace("_check_crl()");
    return;
}

sub error($) {
    # TBD
    #return Net::SSLeay::ERR_get_error;
}

=pod

=head1 DEENDENCIES

L<Net::SSLeay(3pm)>
L<Math::BigInt(3pm)>  (required if necessary only)

=head1 SEE ALSO

L<Net::SSLeay(1)>

=head1 AUTHOR

08-aug-12 Achim Hoffmann

=cut

sub net_sslinfo_done() {};      # dummy to check successful include
## PACKAGE }

unless (defined caller) {       # print myself or open connection
    printf("# %s %s\n", __PACKAGE__, $VERSION);
    if ($#ARGV >= 0) {
        local $\="\n";
        do_ssl_open( shift, 443, '');
        print Net::SSLinfo::datadump();
        exit 0;
    }
    if (eval{require POD::Perldoc;}) {
        # pod2usage( -verbose => 1 );
        exit( Pod::Perldoc->run(args=>[$0]) );
    }
    if (qx(perldoc -V)) {
        # may return:  You need to install the perl-doc package to use this program.
        #exec "perldoc $0"; # scary ...
        printf("# no POD::Perldoc installed, please try:\n  perldoc $0\n");
        exit 0;
    }
}

1;
