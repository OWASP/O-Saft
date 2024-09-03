#! /usr/bin/perl -CADSio
## PACKAGE {

#!#############################################################################
#!#             Copyright (c) 2024, Achim Hoffmann
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
#!# the original  source or any  software  utilising a GPL  component, such  as
#!# this, is also licensed under the same GPL license.
#!#############################################################################

package SSLinfo;
use strict;
use warnings;

## no critic qw(ErrorHandling::RequireCarping)
#  

## no critic qw(Subroutines::ProhibitExcessComplexity)
#  it's the nature of some checks to be complex
#  a max_mccabe = 40 would be nice, but cannot be set per file

## no critic qw(Subroutines::ProhibitSubroutinePrototypes)
#  NOTE: See t/.perlcriticrc

## no critic qw(RegularExpressions::RequireExtendedFormatting)
#  because we use /x as needed for human readability

## no critic qw(Variables::ProhibitPackageVars)
#  using package variables are considered ok in this package, check in future again

#_____________________________________________________________________________
#___________________________________________________ package initialisation __|

my  $SID_sslinfo    =  "@(#) SSLinfo.pm 3.29 24/09/04 00:18:49";
our $VERSION        =  "24.06.24";  # official verion number of this file

BEGIN {
    # SEE Perl:@INC
    my $_path = $0; $_path =~ s#[/\\][^/\\]*$##;
    my $_pwd  = $ENV{PWD} || ".";   # . as fallback if $ENV{PWD} not defined
    unshift(@INC, $_path)   if (1 > (grep{/^$_path$/} @INC));
    unshift(@INC, $_pwd)    if (1 > (grep{/^$_pwd$/}  @INC));
    unshift(@INC, "lib")    if (1 > (grep{/^lib$/}    @INC));
    unshift(@INC, ".")      if (1 > (grep{/^\.$/}     @INC));
}

use OText       qw(%STR);
use Socket;
use Net::SSLeay;

my %SSLINFO = (
    'ME'        => 'SSLinfo',
    'ERROR'     => '#SSLinfo::errors:',
    'OPENSSL'   => '<<openssl>>',
    'UNDEF'     => '<<undefined>>',
    'NO_PEM'    => '<<N/A (no PEM)>>',
);

my $_protos = 'http/1.1,h2c,h2c-14,spdy/1,npn-spdy/2,spdy/2,spdy/3,spdy/3.1,spdy/4a2,spdy/4a4,h2-14,h2-15,http/2.0,h2';
    # NOTE: most weak protocol first, cause we check for vulnerabilities
    # next protocols not yet configurable
    # h2c*  - HTTP 2 Cleartext
    # protocols may have prefix `exp' which should not be checked by server
    # grpc-exp not yet supported (which has -exp suffix, strange ...)
$SSLinfo::timeout       = 'timeout'; # timeout executable
$SSLinfo::openssl       = 'openssl'; # openssl executable
$SSLinfo::use_openssl   = 1; # 1 use installed openssl executable
$SSLinfo::use_sclient   = 1; # 1 use openssl s_client ...
$SSLinfo::use_extdebug  = 1; # 0 do not use openssl with -tlsextdebug option
$SSLinfo::use_nextprot  = 1; # 0 do not use openssl with -nextprotoneg option
$SSLinfo::use_reconnect = 1; # 0 do not use openssl with -reconnect option
$SSLinfo::sclient_opt   = '';# option for openssl s_client command
$SSLinfo::file_sclient  = '';# file to read "open s_client" data from
$SSLinfo::sni_name      = '';# use this as hostname for SNI
$SSLinfo::use_SNI       = 1; # 1 use SNI to connect to target; 0: do not use SNI; string: use this as hostname for SNI
$SSLinfo::use_https     = 1; # 1 make HTTPS request and retrive additional data
$SSLinfo::use_http      = 1; # 1 make HTTP  request and retrive additional data
$SSLinfo::use_alpn      = 1; # 1 to set ALPN option using $SSLinfo::protos_alpn
$SSLinfo::use_npn       = 1; # 1 to set NPN option using $SSLinfo::protos_npn
$SSLinfo::protos_alpn   = $_protos;
$SSLinfo::protos_npn    = $_protos;
$SSLinfo::no_cert       = 0; # 0 collect data from target's certificate
                             # 1 don't collect data from target's certificate
                             #   return empty string
                             # 2 don't collect data from target's certificate
                             #   return string $SSLinfo::no_cert_txt
$SSLinfo::no_cert_txt   = 'unable to load certificate'; # same as openssl 1.0.x
$SSLinfo::ignore_case   = 1; # 1 match hostname, CN case insensitive
$SSLinfo::target_url    = '/'; # URL to use when connecting with get_http(s)
$SSLinfo::ignore_handshake = 0; # 1 treat "failed handshake" as error
$SSLinfo::timeout_sec   = 3; # time in seconds for timeout executable
$SSLinfo::starttls      = '';# use STARTTLS if not empty
$SSLinfo::proxyhost     = '';# FQDN or IP of proxy to be used
$SSLinfo::proxyport     = '';# port for proxy
$SSLinfo::proxypass     = '';# username for proxy authentication (Basic or Digest Auth)
$SSLinfo::proxyuser     = '';# password for proxy authentication (Basic or Digest Auth)
$SSLinfo::proxyauth     = '';# authentication string used for proxy
$SSLinfo::method        = '';# used Net::SSLeay::*_method
$SSLinfo::socket_reuse  = 1; # 0: close and reopen socket for each connection
$SSLinfo::no_compression= 0; # 1: use OP_NO_COMPRESSION for connetion in Net::SSLeay
$SSLinfo::socket     = undef;# socket to be used for connection
$SSLinfo::ca_crl     = undef;# URL where to find CRL file
$SSLinfo::ca_file    = undef;# PEM format file with CAs
$SSLinfo::ca_path    = undef;# path to directory with PEM files for CAs
$SSLinfo::ca_depth   = undef;# depth of peer certificate verification verification
                             # 0=verification is off, returns always "Verify return code: 0 (ok)"
                             # 9=complete verification (max. value, openssl's default)
                             # undef= not used, means system default is used
$SSLinfo::trace         = 0; # 1=simple debugging SSLinfo
                             # 2=trace     including $Net::SSLeay::trace=2
                             # 3=dump data including $Net::SSLeay::trace=3
$SSLinfo::prefix_trace  = "#$SSLINFO{'ME'}::";  # prefix string used in trace messages
$SSLinfo::prefix_verbose= "#$SSLINFO{'ME'}::";  # prefix string used in trace messages
$SSLinfo::user_agent    = '-'; # User-Agent for HTTP requests
$SSLinfo::verbose       = 0; # 1: print some verbose messages
$SSLinfo::linux_debug   = 0; # passed to Net::SSLeay::linux_debug
$SSLinfo::slowly        = 0; # passed to Net::SSLeay::slowly

# avoid Perl warning "... used only once: possible typo ..."
my $dumm_1  = $SSLinfo::linux_debug;
my $dumm_2  = $SSLinfo::proxyport;
my $dumm_3  = $SSLinfo::proxypass;
my $dumm_4  = $SSLinfo::proxyuser;
my $dumm_5  = $SSLinfo::proxyauth;
my $dumm_6  = $SSLinfo::ca_crl;
my $dumm_7  = $SSLinfo::use_nextprot;

BEGIN {
    Net::SSLeay::load_error_strings();
    Net::SSLeay::SSLeay_add_ssl_algorithms();   # Important!
    Net::SSLeay::randomize();
    if (1.45 > $Net::SSLeay::VERSION) {
        warn("**WARNING: 081: ancient Net::SSLeay $Net::SSLeay::VERSION < 1.49; cannot use ::initialize"); ## no critic qw(ErrorHandling::RequireCarping)
    } else {
        Net::SSLeay::initialize();
    }
    # define trace functions, required if called in stand-alone mode
    # SEE Perl:Undefined subroutine
    if (not exists &_trace) {   # lazy check
        sub __trace { my @txt=@_; printf("$SSLinfo::prefix_trace %s\n", "@txt"); return; }
        sub _trace  { my @txt=@_; __trace(@txt) if (0  < $SSLinfo::trace); return; }
        sub _trace1 { my @txt=@_; __trace(@txt) if (1 == $SSLinfo::trace); return; }
        sub _trace2 { my @txt=@_; __trace(@txt) if (1  < $SSLinfo::trace); return; }
    }
    if (not exists &OCfg::warn) {
        sub OCfg::warn   { my @txt=@_; printf("%s%s\n", ($STR{'WARN'}||"**wARNING: "), "@txt"); return; }
    }
    if (not exists &_dbx) {
        sub _dbx    { my @txt=@_; printf("%s%s\n", ($STR{'DBX'} ||"#dbx# "), "@txt"); return; }
    }
}

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

# Documentaion starts here, so  POD-style inline documentation  can be used for
# functions also which will be extracted automatically by POD tools. All public
# functions will be prefixed with a POD description.  POD =head3 should be used
# for function descriptions.
#
# Dragons with perldoc:
#   =head2, =head3
#       Needs at least one space between ( and ) , otherwise formatting will be
#       wrong.
#   C<$something>
#       Does not print  "$something"  but simply  $something  unless  $somthing
#       contains = or * character, i.e. $some=thing. Hence we use I<$something>
#       instead.

# This module  should not use any  print(), warn() or die()  calls to avoid any
# unexpected behaviours in the calling program. Exception are:
#       warn()  when used to inform about ancient modules
#       print() when used in trace mode (0 < $trace).

=pod

=encoding utf8

=head1 NAME

SSLinfo -- Perl module to retrieve SSL connection and certificate data

=head1 SYNOPSIS

    # on command-line:
    SSLinfo.pm                  # print help
    SSLinfo.pm --help           # print help
    SSLinfo.pm +VERSION         # print version string
    SSLinfo.pm version          # print internal version string
    SSLinfo.pm +test-sclient    # print available options for 'openssl s_client'
    SSLinfo.pm +test-sslmap     # print constants for SSL protocols
    SSLinfo.pm +test-openssl    # print information about openssl capabilities
    SSLinfo.pm +test-ssleay     # print information about Net::SSLeay capabilities
    SSLinfo.pm +test-methods    # print available methods in Net::SSLeay
    SSLinfo.pm unknown-host     # print empty data structure
    SSLinfo.pm your.tld         # print data from your.tld

    # from within perl scripts:
    use SSLinfo;
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
I<SSLinfo::errors()> method.

=head1 DEBUGGING

Simple tracing can be activated with  I<$SSLinfo::trace=1>.  If set to "2"
or greater, more data will be printed, for example the complete request and
response data as well as data which covers more than one line.

I<$SSLinfo::trace=2> or I<$SSLinfo::trace=3> will be passed to
I<$Net::SSLeay::trace>.
I<$Net::SSLeay::linux_debug=1> will be set if trace > 2.

Debugging of low level SSL can be enabled by setting I<$Net::SSLeay::trace>,
see L<Net::SSLeay> for details.
Note that Net::SSLeay may print on STDERR with I<$Net::SSLeay::trace> set.

In trace messages empty or undefined strings are written as "<<undefined>>".

I<$SSLinfo::prefix_trace> contains the string used as prefix for each message 
printed with --trace

I<$SSLinfo::prefix_verbose> contains the string used as prefix for each
message printed with --v

=over

=item $SSLeay::linux_debug

Passed to SSLeay; default: 0

=item $SSLinfo::slowly

Passed to SSLeay; default: 0

=back

=head1 VARIABLES

Following variables are supported:

=over

=item $SSLinfo::ca_crl

URL where to find CRL file; default: ''

=item $SSLinfo::ca_file

File in PEM format file with all CAs;   default: ''

Value will not be used at all is set C<undef>.

=item $SSLinfo::ca_path

Directory with PEM files for all CAs;   default: ''

Value will not be used at all is set C<undef>.

=item $SSLinfo::ca_depth

Depth of peer certificate verification; default: 9

Value will not be used at all if set C<undef>.

=item $SSLinfo::no_compression

Set SSL/TLS option to use compression; default: 1

=item $SSLinfo::ignore_handshake

If set to "1" connection attempts returning "faild handshake" will be
treated as errorM default: 0.

=item $SSLinfo::proxyhost

FQDN or IP of proxy to be used; default: ''.

=item $SSLinfo::proxyport

Port for proxy; default: ''.

=item $SSLinfo::proxypass

Username for proxy authentication (Basic or Digest Auth); default: ''.

=item $SSLinfo::proxyuser

Password for proxy authentication (Basic or Digest Auth); default: ''.

=item $SSLinfo::proxyauth

Authentication string used for proxy; default: ''.

=item SSLinfo::target_url

URL to be used when makeing HTTP/HTTPS connection (to get HTTP data).

=item $SSLinfo::socket

Socket to be used for connection.  This must be a file descriptor and
it's assumed to be an AF_INET or AF_INET6 TCP STREAM type connection.
Note: the calling application is responsible for closing the socket.

=item $SSLinfo::socket_reuse

If set to "1" sockets will be reused if a SSL connection fails and is
opened again. The socket will be closed and reopend if set to "0".

Background: some servers complain with an TLS Alert  if such a socket
will be reused. In such cases the default "1" should be set to "0".

=item $SSLinfo::starttls

Use STARTTLS if not empty.

=item $SSLinfo::openssl

Path for openssl executable to be used; default: openssl

=item $SSLinfo::timeout

Path for timeout executable to be used; default: timeout

=item $SSLinfo::use_openssl

More information  according the  SSL connection and  the certificate,
additional to that of Net::SSLeay, can be retrived using the  openssl
executable. If set to "1" openssl will be used also; default: 1

If disabled, the values returned will be: #

=item $SSLinfo::use_sclient

Some information  according the  SSL connection and the certificate,
can only be retrived using   "openssl s_client ...".   Unfortunately
the use may result in a  performance penulty  on some systems and so
it can be disabled with "0"; default: 1

If disabled, the values returned will be: #

=item $SSLinfo::use_SNI

If set to "1", "$SSLinfo::sni_name"  will be used as SNI when opening the
connection. If set to "0", no SNI will be used.
SNI is needed if there are multiple SSL hostnames on the same IP address.
This can be used to check if the target supports SNI; default: 1

=item $SSLinfo::sni_name

The specified string will be used as hostname for SNI.  It will be used if
$SSLinfo::use_SNI is set to "1".
supports SNI; default: ""

=item $SSLinfo::use_http

If set to "1", make a simple  HTTP request on the open  SSL connection and
parse the response for additional SSL/TLS related information (for example
Strict-Transport-Security header); default: 1

=item $SSLinfo::use_https

If set to "1", make a simple  HTTPS  request on the open  SSL connection.

=item $SSLinfo::use_alpn

If set to "1",  protocols from  "$SSLinfo::protos_alpn"  are used for
the ALPN option to open the SSL connection.

=item $SSLinfo::use_npn

If set to "1",  protocols from  "$SSLinfo::protos_npn"  are  used for
the NPN option to open the SSL connection.

=item $SSLinfo::protos_alpn

List of protocols to be used for ALPN option when opening a SSL connection.
Used if  "$SSLinfo::use_alpn" is set.

=item $SSLinfo::protos_npn

List of protocols to be used for NPN option when opening a SSL connection.
Used if  "$SSLinfo::use_npn" is set.

=item $SSLinfo::no_cert

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
string defined in  "$SSLinfo::no_cert_txt".

=item $SSLinfo::no_cert_txt

String to be used if "$SSLinfo::no_cert" is set.
Default is (same as openssl): "unable to load certificate"

=item $SSLinfo::method

Will be set to the Net::SSLeay::*_method used to in do_ssl_open().

=item $SSLinfo::file_sclient

Use content of this file instead opening connection with openssl.
Used for debugging.  Note: there are no checks if the content of this file
matches the other parameters, in particular the host and port.

=item $SSLinfo::verbose

Print some verbose messages. If set > 1 prints call to external openssl.

=item $SSLinfo::user_agent

Text to be used as User-Agent in HTTP requests.

=back

=head1 EXAMPLES

See SYNOPSIS above.

=head1 LIMITATIONS

=head2 Collected data with openssl

Some data is collected using an external openssl executable. The output of
this executable is used to find proper information. Hence some data may be
missing or detected wrong due to different output formats of openssl.
If in doubt use "$SSLinfo::use_openssl = 0" to disable openssl usage.

Port 443 is used when calling:
    SSLinfo.pm your.tld

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
the CA's hash value. Therefore the library uses the  CAPFILE and/or CAPATH
environment variable. The tools, like openssl, have options to pass proper
values for the file and path.

We provide these settings in the variables:
    I<$SSLinfo::ca_file>,  I<$SSLinfo::ca_path>,  I<$SSLinfo::ca_depth> .

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

=begin HACKER_INFO

Internal documentation only.

=head1 General Program Flow

=over

=item _ssleay_socket()

    socket()
    connect()
    select()

=item _ssleay_ctx_new()

    Net::SSLeay::CTX_tlsv1_2_new()
    Net::SSLeay::CTX_set_ssl_version()
    Net::SSLeay::CTX_set_options()
    Net::SSLeay::CTX_set_timeout()

=item _ssleay_ctx_ca()

    Net::SSLeay::CTX_set_verify()
    Net::SSLeay::CTX_load_verify_locations()
    Net::SSLeay::CTX_set_verify_depth()

=item _ssleay_ssl_new()

    Net::SSLeay::new()
    Net::SSLeay::set_tlsext_host_name()
    Net::SSLeay::ctrl()

=item _ssleay_ssl_np()
    Net::SSLeay::CTX_set_alpn_protos()
    Net::SSLeay::CTX_set_next_proto_select_cb()

=item do_ssl_new()

    _ssleay_socket()
    _ssleay_ctx_new()
    _ssleay_ctx_ca()
    _ssleay_ssl_new()
    _ssleay_ssl_np()
    Net::SSLeay::connect()

=item do_ssl_open()

    do_ssl_new()
    _ssleay_cert_get()
    Net::SSLeay::*()  # getter
    $_SSLinfo{'*'}    # getter
    Net::SSLeay::write() && Net::SSLeay::ssl_read_all  # HTTPS
    _header_get()   # getter
    Net::SSLeay::get_http()
    $headers        # getter
    _openssl_x509() # getter using openssl
    do_openssl()

=item do_ssl_free()

    close(socket)
    Net::SSLeay::free()
    Net::SSLeay::CTX_free()

=item do_ssl_close()

    do_ssl_free()
    _SSLinfo_reset()

=back

=head1 General Usage

=over

=item Open TCP connection and collect data

    do_ssl_open(host,port)
    #... check some stuff
    do_ssl_close()

=item Open TCP connection

    do_ssl_new(host,port,ssl-version,cipher))
    #... check some stuff
    do_ssl_free()

=back

=end HACKER_INFO

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

#_____________________________________________________________________________
#________________________________________________ public (export) variables __|

use Exporter qw(import);
use base     qw(Exporter);
our @EXPORT = qw(
        net_sslinfo_done
        ssleay_methods
        test_methods
        test_openssl
        test_sclient
        test_sslmap
        test_ssleay
        datadump
        s_client_check
        s_client_get_optionlist
        s_client_opt_get
        do_ssl_new
        do_ssl_free
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
        fingerprint_sha2
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
        ocsp_response
        ocsp_response_data
        ocsp_response_status
        ocsp_cert_status
        ocsp_next_update
        ocsp_this_update
        before
        after
        dates
        issuer
        subject
        default
        selected
        cipher_list
        cipher_openssl
        cipher_local
        ciphers
        cn
        commonname
        altname
        subjectaltnames
        authority
        owner
        certificate
        SSLversion
        version
        keysize
        keyusage
        https_protocols
        https_svc
        https_body
        https_status
        https_server
        https_alerts
        https_location
        https_refresh
        https_pins
        https_content_enc
        https_transfer_enc
        http_protocols
        http_svc
        http_status
        http_location
        http_refresh
        http_sts
        hsts
        hsts_httpequiv
        hsts_maxage
        hsts_subdom
        hsts_preload
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
        extended_master_secret
        master_secret
        next_protocols
        alpn
        no_alpn
        next_protocol
        krb5
        master_key
        psk_hint
        psk_identity
        public_key_len
        session_id
        session_id_ctx
        session_startdate
        session_starttime
        session_lifetime
        session_ticket
        session_ticket_hint
        session_timeout
        session_protocol
        srp
        renegotiation
        resumption
        dh_parameter
        selfsigned
        s_client
        error
        CTX_method
);
    # insert above in vi with:
    # :r !sed -ne 's/^sub \([a-zA-Z][^ (]*\).*/\t\t\1/p' %

our $HAVE_XS = eval {
    local $SIG{'__DIE__'} = 'DEFAULT';
    eval {
        require XSLoader;
        XSLoader::load('SSLinfo', $VERSION);
        1;
    } or do {
        require DynaLoader;
        bootstrap SSLinfo $VERSION;
        1;
    };
} ? 1 : 0;

#_____________________________________________________________________________
#___________________________________________________________ initialisation __|

# define some shortcuts to avoid $SSLinfo::*
my $trace    = $SSLinfo::trace;
my $_echo    = '';              # dangerous if aliased or wrong one found
my $_timeout = undef;
my $_openssl = undef;

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

# forward declarations
sub do_ssl_open($$$@);
sub do_ssl_close($$);
sub do_openssl($$$$);

sub _vprint     { my $txt=shift; printf("$SSLinfo::prefix_verbose $txt\n") if (0 < $SSLinfo::verbose); return; }
sub _vprint2    { my $txt=shift; printf("$SSLinfo::prefix_verbose $txt\n") if (1 < $SSLinfo::verbose); return; }

sub _traceset   {
    $trace = $SSLinfo::trace;       # set global variable
    $Net::SSLeay::trace = $trace    if (1 < $trace);
        # must set $Net::SSLeay::trace here again as $SSLinfo::trace
        # might unset when SSLinfo called initially;
    $Net::SSLeay::linux_debug = 1   if (2 < $trace);
        # Net::SSLeay 1.72 uses linux_debug with trace > 2 only
    $Net::SSLeay::slowly = $SSLinfo::slowly;
    return;
}

sub _trace_value_or_text {
    # return given $val if --trace > 1; text otherwise
    my $val = shift || "undef";
    return (1 < $trace) ? $val : "<<use --trace=2 to print pointer>>";
} # _trace_value_or_text

sub _setcommand {
    #? check for external command $command; returns command or empty string
    my $command = shift;
    return '' if not $command;
    my $cmd;
    my $opt = "version";
       $opt = "--version" if ($command =~ m/timeout$/);
    _trace("_setcommand($command) $opt 2>&1");
    $cmd = qx("$command" $opt 2>&1);  ## no critic qw(InputOutput::ProhibitBacktickOperators)
        #  qx() is safe here as checked before
    if (defined $cmd) {
        # chomp() and _trace() here only to avoid "Use of uninitialized value $cmd ..."
        chomp $cmd;
        _trace2("_setcommand: #{ $cmd #}");
        $cmd = "$command";
        if ($cmd =~ m#timeout$#) {
            # some timout implementations require -t option, i.e. BusyBox v1.26.2
            # hence we check if it works with -t and add it to $cmd
            $cmd = "$cmd -t " if (qx("$cmd" -t 2 pwd 2>&1) !~ m/timeout/);  ## no critic qw(InputOutput::ProhibitBacktickOperators)
        }
    } else {
        _trace("_setcommand: $command = ''");
        $cmd = '';  # i.e. Mac OS X does not have timeout by default; can work without ...
    }
    if ($^O !~ m/MSWin32/) {
        # Windows is too stupid for secure program calls
        $cmd = '\\' .  $cmd if (($cmd ne '') and ($cmd !~ /\//));
    }
    _trace("_setcommand cmd=$cmd");
    return $cmd;
} # _setcommand

sub _setcmd     {
    #? check for external commands and initialise if necessary
    # set global variabales $_openssl and $_timeout
    return if (defined $_timeout);  # lazy check
    $_openssl   = _setcommand($SSLinfo::openssl);
    $_timeout   = _setcommand($SSLinfo::timeout);
    $_timeout  .= " $SSLinfo::timeout_sec"  if (defined $_timeout);
    _trace("#_setcmd: _openssl=$_openssl ; _timeout=$_timeout");
    if ($^O !~ m/MSWin32/) {
        # Windows is too stupid for secure program calls
        $_echo  = '\\' .  $_echo;
    }
    return;
} # _setcmd

sub _traceSSLbitmasks   {
    # print bitmasks of available SSL constants
    my $txt  = shift; # prefix string as in _trace()
    my $mask = shift;
    return if (0 >= $trace);
    _traceset();
    ## no critic (TestingAndDebugging::ProhibitProlongedStrictureOverride)
    #  NOTE: perlcritic is too pedantic
    foreach my $op (sort qw(
            OP_ALL
            OP_MICROSOFT_SESS_ID_BUG
            OP_NETSCAPE_CHALLENGE_BUG
            OP_LEGACY_SERVER_CONNECT
            OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
            OP_TLSEXT_PADDING
            OP_MICROSOFT_BIG_SSLV3_BUFFER
            OP_SAFARI_ECDHE_ECDSA_BUG
            OP_SSLEAY_080_CLIENT_DH_BUG
            OP_TLS_D5_BUG
            OP_TLS_BLOCK_PADDING_BUG
            OP_DONT_INSERT_EMPTY_FRAGMENTS
            OP_NO_QUERY_MTU
            OP_COOKIE_EXCHANGE
            OP_NO_TICKET
            OP_CISCO_ANYCONNECT
            OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
            OP_NO_COMPRESSION
            OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
            OP_SINGLE_ECDH_USE
            OP_SINGLE_DH_USE
            OP_CIPHER_SERVER_PREFERENCE
            OP_TLS_ROLLBACK_BUG 
            OP_NO_SSLv2
            OP_NO_SSLv3
            OP_NO_TLSv1
            OP_NO_TLSv1_1
            OP_NO_TLSv1_2
            OP_NO_TLSv1_3
            OP_NO_SSL_MASK
            OP_NETSCAPE_CA_DN_BUG
            OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
            OP_CRYPTOPRO_TLSEXT_BUG
            OP_SSLREF2_REUSE_CERT_TYPE_BUG
            OP_MSIE_SSLV2_RSA_PADDING
            OP_EPHEMERAL_RSA
            OP_PKCS1_CHECK_1
            OP_PKCS1_CHECK_2
            OP_ALLOW_NO_DHE_KEX
            OP_NON_EXPORT_FIRST
            OP_NO_CLIENT_RENEGOTIATION
            OP_NO_ENCRYPT_THEN_MAC
            OP_NO_RENEGOTIATION
            OP_PRIORITIZE_CHACHA
            )) {
        no strict;  ## no critic (TestingAndDebugging::ProhibitNoStrict)
            # necessary as we use {"Net::SSLeay::$op"}
        ## my $_op_sub = \&{"Net::SSLeay::$op"}; # will not catch all values and errors; hence eval() below
        my $bit;
        my $opt;
        my $_ok = eval { $opt = &{"Net::SSLeay::$op"}; };
        if (defined $_ok) {
            $bit = (($mask & $opt)>0) || 0;
            $bit = sprintf("0x%08x %s", $opt, $bit);
        } else {
            $bit = sprintf("<<$@>>");   # error string from Net::SSLeay instead <<undef>>
                # error may contain for example:
                #   Can't locate auto/Net/SSLeay/OP_NO_TLSv1.al in @INC (@INC contains: ...
        }
        _trace(sprintf("%s: %-30s %s", $txt, $op, $bit));
    }
    return;
} # _traceSSLbitmasks

#_____________________________________________________________________________
#__________________________________________________ internal data structure __|

sub _ssleay_value_get   {
    #? retrun value of $type (option, timeout, verify_mode, verify_depth, OP) for specified function as formated string
    #  returns <<undef>> if specified function does not exist
    #  $func is i.e.: Net::SSLeay::CTX_v3_new, Net::SSLeay::CTX_v23_new
    my $type= shift;
    my $func= shift;
    my $val = "<<undef>>";
       $val =    undef  if ('OP_or_undef' eq $type);
    _traceset();
    _trace("_ssleay_value_get('$type', '$func')");
    if (defined &$func) {
       $val = sprintf('0x%08x', Net::SSLeay::CTX_get_options(&$func())) if ('options' eq $type);
       $val =                   Net::SSLeay::CTX_get_timeout(&$func())  if ('timeout' eq $type);
       $val = sprintf('0x%08x', Net::SSLeay::CTX_get_verify_mode( &$func())) if ('verify_mode'  eq $type);
       $val =                   Net::SSLeay::CTX_get_verify_depth(&$func())  if ('verify_depth' eq $type);
       $val = sprintf('0x%08x', &$func())   if ('OP' eq $type);
       $val = sprintf('0x%08x', &$func())   if ('OP_or_undef' eq $type);
    }
    _trace("_ssleay_value_get ret=" . ($val || "undef"));
    return $val;
} # _ssleay_value_get

my %_OpenSSL_opt = (    # openssl capabilities
    # openssl has various capabilities which can be used with options.
    # Depending on the version of openssl, these options are available or not.
    # The data structure contains the important options, each as key where its
    # value is  1  if the option is available at openssl.
    # Currently only options for openssl's  s_client  command are supported.
    # This data structure is for one openssl command. More than one command is
    # not expected, not useful, hence it is thread save.
    # NOTE:  some options are present in different spellings because different
    #        openssl version use different spellings, grrr.
    'done'          => 0, # set to 1 if initialised
    'data'          => '',# contains output from "openssl s_client -help"
    #--------------+------------
    # key (=option) supported=1
    #--------------+------------
    '-CAfile'       => 0,
    '-CApath'       => 0,
    '-alpn'         => 0,
    '-npn'          => 0, # same as -nextprotoneg
    '-nextprotoneg' => 0,
    '-reconnect'    => 0,
    '-fallback_scsv'=> 0,
    '-comp'         => 0,
    '-no_comp'      => 0,
    '-no_ticket'    => 0,
    '-no_tlsext'    => 0,
    '-serverinfo'   => 0,
    '-servername'   => 0,
    '-serverpref'   => 0,
    '-showcerts'    => 0,
    '-curves'       => 0,
    '-debug'        => 0,
    '-bugs'         => 0,
    '-key'          => 0,
    '-msg'          => 0,
    '-nbio'         => 0,
    '-psk'          => 0,
    '-psk_identity' => 0,
    '-pause'        => 0,
    '-prexit'       => 0,
    '-proxy'        => 0,
    '-quiet'        => 0,
    '-sigalgs'      => 0,
    '-state'        => 0,
    '-status'       => 0,
    '-strict'       => 0,
    '-nbio_test'    => 0,
    '-tlsextdebug'  => 0,
    '-client_sigalgs'           => 0,
    '-record_padding'           => 0,
    '-no_renegotiation'         => 0,
    '-legacyrenegotiation'      => 0,
    '-legacy_renegotiation'     => 0,
    '-legacy_server_connect'    => 0,
    '-no_legacy_server_connect' => 0,
    #--------------+------------
    # openssl > 1.x disabled various protocols, hence check if available
    #--------------+------------  
    '-ssl2'         => 0,
    '-ssl3'         => 0,
    '-tls1'         => 0,
    '-tls1_1'       => 0,
    '-tls1_2'       => 0,
    '-tls1_3'       => 0,
    '-dtls'         => 0,
    '-dtls1'        => 0,   # do we need -dtls1_0 also?
    '-dtls1_1'      => 0,   # 12/2023: not supported by OpenSSL 3.0.11
    '-dtls1_2'      => 0,
    '-dtls1_3'      => 0,   # 12/2023: not supported by OpenSSL 3.0.11
    '-no_ssl2'      => 0,
    '-no_ssl3'      => 0,
    '-no_tls1'      => 0,
    '-no_tls1_1'    => 0,
    '-no_tls1_2'    => 0,
    '-no_tls1_3'    => 0,
    #--------------+------------
    # options in server mode
    #--------------+------------
    #'-anti_replay'  => 0,
    #'-no_anti_replay'           => 0,
    #'-dhparam'      => 0,
    #'-prioritize_chacha'        => 0,
    #'-no_resumption_on_reneg'   => 0,
);

my %_SSLmap = ( # map libssl's constants to speaking names
    # SSL and openssl is a pain, for setting protocols it needs a bitmask
    # and SSL itself returns a hex constant, which is different
    #                 /----- returned by Net::SSLeay::version($ssl)
    #                 |      bitmask used in Net::SSLeay::CTX_set_options()
    # key             v      v          example bitmask
    #-------------+---------+---------------------------------------------
    'SSLv2'     => [0x0002,  undef],  # 0x01000000
    'SSLv3'     => [0x0300,  undef],  # 0x02000000
    'TLSv1'     => [0x0301,  undef],  # 0x04000000
    'TLSv11'    => [0x0302,  undef],  # 0x08000000
    'TLSv12'    => [0x0303,  undef],  # 0x10000000
    'TLSv13'    => [0x0304,  undef],  # 0x10000000
    'TLS1FF'    => [0x03FF,  undef],  #
    'DTLSfamily'=> [0xFE00,  undef],  #
    'DTLSv09'   => [0x0100,  undef],  # 0xFEFF in some openssl versions
    'DTLSv1'    => [0xFEFF,  undef],  # ??
    'DTLSv11'   => [0xFEFE,  undef],  # ??
    'DTLSv12'   => [0xFEFD,  undef],  # ??
    'DTLSv13'   => [0xFEFF,  undef],  # ??
);
# unfortunately not all openssl and/or Net::SSLeay versions have all constants,
# hence we need to assign values dynamically (to avoid perl errors)
$_SSLmap{'SSLv2'}  [1] = _ssleay_value_get('OP_or_undef', *Net::SSLeay::OP_NO_SSLv2);
$_SSLmap{'SSLv3'}  [1] = _ssleay_value_get('OP_or_undef', *Net::SSLeay::OP_NO_SSLv3);
$_SSLmap{'TLSv1'}  [1] = _ssleay_value_get('OP_or_undef', *Net::SSLeay::OP_NO_TLSv1);
$_SSLmap{'TLSv11'} [1] = _ssleay_value_get('OP_or_undef', *Net::SSLeay::OP_NO_TLSv1_1);
$_SSLmap{'TLSv12'} [1] = _ssleay_value_get('OP_or_undef', *Net::SSLeay::OP_NO_TLSv1_2);
$_SSLmap{'TLSv13'} [1] = _ssleay_value_get('OP_or_undef', *Net::SSLeay::OP_NO_TLSv1_3);
$_SSLmap{'DTLSv1'} [1] = _ssleay_value_get('OP_or_undef', *Net::SSLeay::OP_NO_DTLSv1);
$_SSLmap{'DTLSv11'}[1] = _ssleay_value_get('OP_or_undef', *Net::SSLeay::OP_NO_DTLSv1_1);
$_SSLmap{'DTLSv12'}[1] = _ssleay_value_get('OP_or_undef', *Net::SSLeay::OP_NO_DTLSv1_2);
$_SSLmap{'DTLSv13'}[1] = _ssleay_value_get('OP_or_undef', *Net::SSLeay::OP_NO_DTLSv1_3);
    # NOTE: we use the bitmask provided by the system
    # NOTE: all checks are done now, we don't need to fiddle around that later
    #       we just need to check for undef then
# TODO: %_SSLmap should be inherited from $cfg{openssl_version_map} or vice versa
my %_SSLhex = map { $_SSLmap{$_}[0] => $_ } keys %_SSLmap;  # reverse map

sub _SSLversion_get { return $_SSLmap{$_[0]}[0]; }  ## no critic qw(Subroutines::RequireArgUnpacking Subroutines::ProhibitUnusedPrivateSubroutines)
sub _SSLbitmask_get { return $_SSLmap{$_[0]}[1]; }  ## no critic qw(Subroutines::RequireArgUnpacking)
                                # for 'no critic' above, see comment far below

my %_SSLtemp= ( # temporary internal data structure when establishing a connection
    # 'key'     => 'value',     # description
    #-------------+-------------+---------------------------------------------
    'addr'      => undef,       # raw INET IP for hostname (FQDN)
    'socket'    => undef,       # socket handle of new connection
    'ctx'       => undef,       # handle for Net::SSLeay::CTX_new()
    'ssl'       => undef,       # handle for Net::SSLeay
    'method'    => '',          # used Net::SSLeay::*_method
    'errors'    => [],          # stack for errors, if any
    'PEM_text'  => '',          # temp. storage oF PEM to avoid multiple openssl calls
    #-------------+-------------+---------------------------------------------
); # %_SSLtemp

sub _SSLtemp_reset  {
    #? reset internal data structure%_SSLtemp ; for internal use only
    foreach my $key (keys %_SSLtemp) { $_SSLtemp{$key} = undef; }
    $_SSLtemp{'method'}     = '';
    $_SSLtemp{'errors'}     = [];
    $_SSLtemp{'PEM_text'}   = '';
    return;
} # _SSLtemp_reset

my %_SSLinfo= ( # our internal data structure
    'key'       => 'value',     # description
    #-------------+-------------+---------------------------------------------
    'host'      => '',          # hostname (FQDN) or IP as given by user
    'addr'      => undef,       # raw INET IP for hostname (FQDN)
    'ip'        => '',          # human readable IP for hostname (FQDN)
    'port'      => 443,         # port as given by user (default 443)
    'ctx'       => undef,       # handle for Net::SSLeay::CTX_new()
    'ssl'       => undef,       # handle for Net::SSLeay
    '_options'  => '',          # option bitmask used for connection
    'errors'    => [],          # stack for errors, if any
    'cipherlist'=> 'ALL:NULL:eNULL:aNULL:LOW:EXP', # we want to test really all ciphers available
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
    'ocsp_response'     => "",  # selected data from OCSP Response Data
    'ocsp_response_data'=> "",  # complete OCSP Response with "openssl -tlsextdebug -status .."
    'ocsp_response_status'=>"", # OCSP Response Data: Response Status
    'ocsp_cert_status'  => "",  # OCSP Response Data: Cert Status
    'ocsp_next_update'  => "",  # OCSP Response Data: Next Update
    'ocsp_this_update'  => "",  # OCSP Response Data: This Update
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
    'fingerprint_sha2'  => "",  # SHA2 fingerprint (if available)
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
    'next_protocols'    => "",  # Protocols advertised by server
    'alpn'              => "",  # ALPN protocol
    'no_alpn'           => "",  # No ALPN negotiated
    'next_protocol'     => "",  # Next protocol
    'krb5'              => "",  # Krb Principal
    'psk_hint'          => "",  # PSK identity hint
    'psk_identity'      => "",  # PSK identity
    'srp'               => "",  # SRP username
    'master_key'        => "",  # Master-Key
    'master_secret'     => "",  # Extended master secret
    'public_key_len'    => "",  # Server public key
    'session_id'        => "",  # Session-ID
    'session_id_ctx'    => "",  # Session-ID-ctx
    'session_startdate' => "",  # TLS session start time (human readable)
    'session_starttime' => "",  # TLS session start time (seconds EPOCH)
    'session_lifetime'  => "",  # TLS session ticket lifetime hint
    'session_ticket'    => "",  # TLS session ticket
    'session_timeout'   => "",  # SSL-Session Timeout
    'session_protocol'  => "",  # SSL-Session Protocol
    # following from HTTP(S) request
    'https_protocols'   => "",  # HTTPS Alternate-Protocol header
    'https_svc'         => "",  # HTTPS Alt-Svc, X-Firefox-Spdy header
    'https_body'        => "",  # HTTPS response (HTML body)
    'https_status'      => "",  # HTTPS response (aka status) line
    'https_server'      => "",  # HTTPS Server header
    'https_alerts'      => "",  # HTTPS Alerts send by server
    'https_location'    => "",  # HTTPS Location header send by server
    'https_refresh'     => "",  # HTTPS Refresh header send by server
    'https_pins'        => "",  # HTTPS Public Key Pins header
    'https_content_enc' => "",  # HTTPS Content-Encoding header
    'https_transfer_enc'=> "",  # HTTPS Transfer-Encoding header
    'http_protocols'    => "",  # HTTP Alternate-Protocol header
    'http_svc'          => "",  # HTTP Alt-Svc, X-Firefox-Spdy header
    'http_status'       => "",  # HTTP response (aka status) line
    'http_location'     => "",  # HTTP Location header send by server
    'http_refresh'      => "",  # HTTP Refresh header send by server
    'http_sts'          => "",  # HTTP Strict-Transport-Security header send by server (whish is very bad)
    'https_sts'         => "",  # complete STS header
    'hsts_httpequiv'    => "",  # http-equiv meta tag in HTTP body
    'hsts_maxage'       => "",  # max-age attribute of STS header
    'hsts_subdom'       => "",  # includeSubDomains attribute of STS header
    'hsts_preload'      => "",  # preload attribute of STS header
    #-------------+-------------+---------------------------------------------
); # %_SSLinfo

#  $_SSLinfo_random # SEE Make:OSAFT_MAKE (in Makefile.pod)
my $_SSLinfo_random = qr/ctx|master_key|session_(?:startdate|starttime|ticket)|ssl|x509/; ## no critic qw(RegularExpressions::ProhibitComplexRegexes)
my $_SSLinfo_random_text = $STR{MAKEVAL};

sub _SSLinfo_reset  {
    #? reset internal data structure%_SSLinfo ; for internal use only
    foreach my $key (keys %_SSLinfo) { $_SSLinfo{$key} = ''; }
    # some are special
    $_SSLinfo{'key'}        = 'value';
    $_SSLinfo{'ctx'}        = undef;
    $_SSLinfo{'ssl'}        = undef;
    $_SSLinfo{'addr'}       = undef;
    $_SSLinfo{'port'}       = 443;
    $_SSLinfo{'errors'}     = [];
    $_SSLinfo{'ciphers'}    = [];
    $_SSLinfo{'cipherlist'} = 'ALL:NULL:eNULL:aNULL:LOW:EXP';
    $_SSLinfo{'verify_cnt'} = 0;
    $_SSLinfo{'ciphers_openssl'} = '';
    return;
} # _SSLinfo_reset

sub _SSLinfo_print  {
    #? print some data in $_SSLinfo (for --verbose)
    foreach my $key (sort qw(
            subject_hash
            issuer_hash
            aux
            ocsp_response
            ocsp_response_data
            ocsp_response_status
            ocsp_cert_status
            ocsp_next_update
            ocsp_this_update
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
            email
            heartbeat
            serial
            serial_hex
            serial_int
            modulus
            modulus_len
            modulus_exponent
            fingerprint_text
            fingerprint_type
            fingerprint_hash
            fingerprint_sha2
            fingerprint_sha1
            fingerprint_md5
            selected
            verify
            chain
            chain_verify
            dh_parameter
            renegotiation
            resumption
            selfsigned
            compression
            expansion
            next_protocols
            alpn
            no_alpn
            next_protocol
            krb5
            psk_hint
            psk_identity
            srp
            master_secret
            master_key
            public_key_len
            session_id
            session_id_ctx
            session_startdate
            session_starttime
            session_lifetime
            session_ticket
            session_timeout
            session_protocol
            ))
            # not yet:
            #  cert_type
            #  ciphers
            #  s_client
            #  ciphers_openssl
            # not HTTP(S)
    {
        next if (not defined $_SSLinfo{$key});
        _trace("$key=$_SSLinfo{$key}"); 
    }
    return;
} # _SSLinfo_print

#_____________________________________________________________________________
#______________________________________________________ public test methods __|

sub ssleay_methods  {
            # not yet
            #  cert_type
            #  ciphers
            #  s_client
            #  ciphers_openssl
    #? returns list of available Net::SSLeay::*_method; most important first
# TODO:  check for mismatch Net::SSLeay::*_method and Net::SSLeay::CTX_*_new
    my @list;
    # following sequence is important: most modern methods first; DTLS not yet important
    push(@list, 'TLSv1_3_method'  ) if (defined &Net::SSLeay::TLSv1_3_method);  # Net::SSLeay > 1.72
    push(@list, 'TLSv1_2_method'  ) if (defined &Net::SSLeay::TLSv1_2_method);
    push(@list, 'TLSv1_1_method'  ) if (defined &Net::SSLeay::TLSv1_1_method);
    push(@list, 'TLSv1_method'    ) if (defined &Net::SSLeay::TLSv1_method);
    push(@list, 'SSLv23_method'   ) if (defined &Net::SSLeay::SSLv23_method);
    push(@list, 'SSLv3_method'    ) if (defined &Net::SSLeay::SSLv3_method);
    push(@list, 'SSLv2_method'    ) if (defined &Net::SSLeay::SSLv2_method);
    push(@list, 'DTLSv1_3_method' ) if (defined &Net::SSLeay::DTLSv1_3_method); # Net::SSLeay > 1.72
    push(@list, 'DTLSv1_2_method' ) if (defined &Net::SSLeay::DTLSv1_2_method); # Net::SSLeay > 1.72
    push(@list, 'DTLSv1_1_method' ) if (defined &Net::SSLeay::DTLSv1_1_method); # Net::SSLeay > 1.72
    push(@list, 'DTLSv1_method'   ) if (defined &Net::SSLeay::DTLSv1_method);   # Net::SSLeay > 1.72
    push(@list, 'DTLS_method'     ) if (defined &Net::SSLeay::DTLS_method);     # Net::SSLeay > 1.72
    push(@list, 'CTX_tlsv1_3_new' ) if (defined &Net::SSLeay::CTX_tlsv1_3_new);
    push(@list, 'CTX_tlsv1_2_new' ) if (defined &Net::SSLeay::CTX_tlsv1_2_new);
    push(@list, 'CTX_tlsv1_1_new' ) if (defined &Net::SSLeay::CTX_tlsv1_1_new);
    push(@list, 'CTX_tlsv1_0_new' ) if (defined &Net::SSLeay::CTX_tlsv1_0_new);
    push(@list, 'CTX_tlsv1_new'   ) if (defined &Net::SSLeay::CTX_tlsv1_new);
    push(@list, 'CTX_v23_new'     ) if (defined &Net::SSLeay::CTX_v23_new);
    push(@list, 'CTX_v3_new'      ) if (defined &Net::SSLeay::CTX_v3_new);
    push(@list, 'CTX_v2_new'      ) if (defined &Net::SSLeay::CTX_v2_new);
    push(@list, 'CTX_new_with_method')  if (defined &Net::SSLeay::CTX_new_with_method);
    push(@list, 'CTX_new'         ) if (defined &Net::SSLeay::CTX_new);
    push(@list, 'CTX_dtlsv1_3_new') if (defined &Net::SSLeay::CTX_dtlsv1_3_new);
    push(@list, 'CTX_dtlsv1_2_new') if (defined &Net::SSLeay::CTX_dtlsv1_2_new);
    push(@list, 'CTX_dtlsv1_new'  ) if (defined &Net::SSLeay::CTX_dtlsv1_new);
    push(@list, 'CTX_get_options' ) if (defined &Net::SSLeay::CTX_get_options);
    push(@list, 'CTX_set_options' ) if (defined &Net::SSLeay::CTX_set_options);
    push(@list, 'CTX_set_timeout' ) if (defined &Net::SSLeay::CTX_set_timeout);
    push(@list, 'CTX_set_alpn_protos')  if (defined &Net::SSLeay::CTX_set_alpn_protos); # Net::SSLeay > 1.72 ??
    push(@list, 'CTX_set_next_proto_select_cb') if (defined &Net::SSLeay::CTX_set_next_proto_select_cb);
    return @list;
} # ssleay_methods

sub test_openssl    {
    #? return internal data structure %_OpenSSL_opt (openssl options)
    # also prints openssl executable which returned capabilities/options
    s_client_check();
    my $line  = "=-----------------------+----------------";
    my $data  = "= using $SSLinfo::openssl\n";
       $data .= "$line\n= _OpenSSL_opt          | 1=available\n$line\n";
    foreach my $_opt (sort keys %_OpenSSL_opt) {
        if ('data' eq $_opt) {  # huge internal data from from openssl call
            if (0 >= $SSLinfo::verbose) {
                $_OpenSSL_opt{$_opt} = '<<use  --v  or  --trace to see openssl usage>>';
            }
        }
        $data  .= sprintf("%23s\t= %s\n", $_opt, $_OpenSSL_opt{$_opt});
    }
    $data .= "$line";
    return $data;
} # test_openssl

sub test_methods    {
    #? return openssl s_client availabilities (options for s_client)
    return join(" ", sort(ssleay_methods()));
} # test_methods

sub test_sclient    {
    #? return openssl s_client availabilities (options for s_client)
    return join(" ", sort(s_client_get_optionlist()) );
} # test_sclient

sub test_sslmap     {
    #? return internal data structure %_SSLmap
    my $line = "=-----------------------+--------+-------------";
    my $data = "$line\n= _SSLmap    key        | SSLeay  bitmask\n$line\n";
    foreach my $_ssl (sort keys %_SSLmap) {
        my $mask = "<<undef>>";
           $mask = $_SSLmap{$_ssl}[1] if defined $_SSLmap{$_ssl}[1];
        $data  .= sprintf("%23s\t= 0x%04X  %s\n", $_ssl, $_SSLmap{$_ssl}[0], $mask);
    }
    $data .= "$line";
    return $data;
} # test_sslmap

sub test_ssleay     {
    #? return availability and information about Net::SSLeay
    ## no critic qw(ValuesAndExpressions::ProhibitImplicitNewlines)
    #  a here document is not possible here, or at least more cumbersome,
    #  because Perl code is used inside
    my @list = ssleay_methods();
    my $line = "=------------+------------------+-------------";
    my $data = "$line
= Net::SSLeay{ function         | 1=available
$line
             ::SSLv2_method     = " . ((grep{/^SSLv2_method$/}     @list) ? 1 : 0) . "
             ::SSLv3_method     = " . ((grep{/^SSLv3_method$/}     @list) ? 1 : 0) . "
             ::SSLv23_method    = " . ((grep{/^SSLv23_method$/}    @list) ? 1 : 0) . "
             ::TLSv1_method     = " . ((grep{/^TLSv1_method$/}     @list) ? 1 : 0) . "
             ::TLSv1_1_method   = " . ((grep{/^TLSv1_1_method$/}   @list) ? 1 : 0) . "
             ::TLSv1_2_method   = " . ((grep{/^TLSv1_2_method$/}   @list) ? 1 : 0) . "
#{ following missing in Net::SSLeay (up to 1.72):
             ::TLSv1_3_method   = " . ((grep{/^TLSv1_3_method$/}   @list) ? 1 : 0) . "
             ::DTLSv1_method    = " . ((grep{/^DTLSv1_method$/}    @list) ? 1 : 0) . "
             ::DTLSv1_2_method  = " . ((grep{/^DTLSv1_2_method$/}  @list) ? 1 : 0) . "
             ::DTLS_method      = " . ((grep{/^DTLS_method$/}      @list) ? 1 : 0) . "
#}
             ::CTX_new_with_method  = " . ((grep{/^CTX_new_with_method$/} @list) ? 1 : 0) . "
             ::CTX_new          = " . ((grep{/^CTX_new$/}          @list) ? 1 : 0) . "
             ::CTX_v2_new       = " . ((grep{/^CTX_v2_new$/}       @list) ? 1 : 0) . "
             ::CTX_v3_new       = " . ((grep{/^CTX_v3_new$/}       @list) ? 1 : 0) . "
             ::CTX_v23_new      = " . ((grep{/^CTX_v23_new$/}      @list) ? 1 : 0) . "
             ::CTX_tlsv1_new    = " . ((grep{/^CTX_tlsv1_new$/}    @list) ? 1 : 0) . "
             ::CTX_tlsv1_0_new  = " . ((grep{/^CTX_tlsv1_0_new$/}  @list) ? 1 : 0) . "
             ::CTX_tlsv1_1_new  = " . ((grep{/^CTX_tlsv1_1_new$/}  @list) ? 1 : 0) . "
             ::CTX_tlsv1_2_new  = " . ((grep{/^CTX_tlsv1_2_new$/}  @list) ? 1 : 0) . "
             ::CTX_tlsv1_3_new  = " . ((grep{/^CTX_tlsv1_3_new$/}  @list) ? 1 : 0) . "
             ::CTX_dtlsv1_new   = " . ((grep{/^CTX_dtlsv1_new$/}   @list) ? 1 : 0) . "
             ::CTX_dtlsv1_2_new = " . ((grep{/^CTX_dtlsv1_2_new$/} @list) ? 1 : 0) . "
             ::CTX_dtlsv1_3_new = " . ((grep{/^CTX_dtlsv1_3_new$/} @list) ? 1 : 0) . "
             ::CTX_get_options  = " . ((grep{/^CTX_get_options$/}  @list) ? 1 : 0) . "
             ::CTX_set_options  = " . ((grep{/^CTX_set_options$/}  @list) ? 1 : 0) . "
             ::CTX_set_timeout  = " . ((grep{/^CTX_set_timeout$/}  @list) ? 1 : 0) . "
             ::CTX_set_alpn_protos  = " . ((grep{/^CTX_set_alpn_protos$/}  @list) ? 1 : 0) . "
             ::CTX_set_next_proto_select_cb = " . ((grep{/^CTX_set_next_proto_select_cb$/}  @list) ? 1 : 0) . "
$line
= Net::SSLeay} function\n";
    no warnings 'once'; ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
        # NOTE: perl's strict is picky for OP_NO_DTLS* below
    $data .= "= Net::SSLeay{ constant           hex value
$line
             ::OP_NO_SSLv2      = " . _ssleay_value_get('OP', *Net::SSLeay::OP_NO_SSLv2) . "
             ::OP_NO_SSLv3      = " . _ssleay_value_get('OP', *Net::SSLeay::OP_NO_SSLv3) . "
             ::OP_NO_TLSv1      = " . _ssleay_value_get('OP', *Net::SSLeay::OP_NO_TLSv1) . "
             ::OP_NO_TLSv1_1    = " . _ssleay_value_get('OP', *Net::SSLeay::OP_NO_TLSv1_1)  . "
             ::OP_NO_TLSv1_2    = " . _ssleay_value_get('OP', *Net::SSLeay::OP_NO_TLSv1_2)  . "
             ::OP_NO_TLSv1_3    = " . _ssleay_value_get('OP', *Net::SSLeay::OP_NO_TLSv1_3)  . "
             ::OP_NO_DTLSv09    = " . _ssleay_value_get('OP', *Net::SSLeay::OP_NO_DTLSv09)  . "
             ::OP_NO_DTLSv1     = " . _ssleay_value_get('OP', *Net::SSLeay::OP_NO_DTLSv1)   . "
             ::OP_NO_DTLSv1_1   = " . _ssleay_value_get('OP', *Net::SSLeay::OP_NO_DTLSv1_1) . "
             ::OP_NO_DTLSv1_2   = " . _ssleay_value_get('OP', *Net::SSLeay::OP_NO_DTLSv1_2) . "
             ::OP_NO_DTLSv1_3   = " . _ssleay_value_get('OP', *Net::SSLeay::OP_NO_DTLSv1_3) . "
$line
= Net::SSLeay} constant\n";
    $data .= "= Net::SSLeay{ call
$line
#      experimental ...
  Net::SSLeay::CTX_new {
             ::CTX_get_options(CTX)= " . _ssleay_value_get('options', *Net::SSLeay::CTX_new) . "
  Net::SSLeay::CTX_new }
  Net::SSLeay::CTX_v3_new {
             ::CTX_get_options(CTX)= " . _ssleay_value_get('options', *Net::SSLeay::CTX_v3_new)  . "
  Net::SSLeay::CTX_v3_new }
  Net::SSLeay::CTX_v23_new {
             ::CTX_get_options(CTX)= " . _ssleay_value_get('options', *Net::SSLeay::CTX_v23_new) . "
             ::CTX_get_timeout(CTX)= " . _ssleay_value_get('timeout', *Net::SSLeay::CTX_v23_new) . "
             ::CTX_get_verify_mode(CTX) = " . _ssleay_value_get('verify_mode',  *Net::SSLeay::CTX_v23_new) . "
             ::CTX_get_verify_depth(CTX)= " . _ssleay_value_get('verify_depth', *Net::SSLeay::CTX_v23_new) . "
  Net::SSLeay::CTX_v23_new }
  Net::SSLeay::CTX_tlsv1_2_new {
             ::CTX_get_options(CTX)= " . _ssleay_value_get('options', *Net::SSLeay::CTX_tlsv1_2_new) . "
             ::CTX_get_timeout(CTX)= " . _ssleay_value_get('timeout', *Net::SSLeay::CTX_tlsv1_2_new) . "
             ::CTX_get_verify_mode(CTX) = " . _ssleay_value_get('verify_mode',  *Net::SSLeay::CTX_tlsv1_2_new) . "
             ::CTX_get_verify_depth(CTX)= " . _ssleay_value_get('verify_depth', *Net::SSLeay::CTX_tlsv1_2_new) . "
  Net::SSLeay::CTX_tlsv1_2_new }
$line
= Net::SSLeay} call\n";

    return $data;
} # test_ssleay

sub _dump           {
    my $key = shift;
    my $txt = shift;
    my $val = shift;
    return sprintf("#{ %-12s=%s%s #}\n", $key, $txt, ($val || "<<undefined>>"));
} # _dump

sub datadump        {
    #? return internal data structure
    my $prefix  = shift;    # get prefix as parameter
    my $data    = $prefix;
       $data   .= " datadump #{\n";
    if ($SSLinfo::use_sclient > 1) {
       $data   .= _dump('s_client', " ", $_SSLinfo{'s_client'});
    } else {
       $data   .= _dump('s_client', " ", "#### please set 'SSLinfo::use_sclient > 1' to dump s_client data also ###");
    }
    $data .= _dump('PEM',     " ", $_SSLinfo{'PEM'});
    $data .= _dump('text',    " ", $_SSLinfo{'text'});
    $data .= _dump('ciphers', " ", join(' ', @{$_SSLinfo{'ciphers'}}));
    $data .= _dump('addr',    " ", join('.', unpack('W4', $_SSLinfo{'addr'}||"")));  # pretty print IP
    foreach my $key (sort keys %_SSLinfo) { # SEE Note:Testing, sort
        next if ($key =~ m/addr|ciphers|errors|PEM|text|fingerprint_|s_client/); # handled special
        if ($key =~ m/$_SSLinfo_random/) {  # handled special
            if (defined $ENV{'OSAFT_MAKE'}) {
                # SEE Make:OSAFT_MAKE (in Makefile.pod)
                # ugly hack here, but simplifies testing with make; however, this code is for debugging only
                $data .= _dump($key, " ", $_SSLinfo_random_text);
                next;
            }
        }
        $data .= _dump($key, " ", $_SSLinfo{$key});
    }
    foreach my $key (sort keys %_SSLinfo) { # SEE Note:Testing, sort
        next if ($key !~ m/fingerprint_/);
        $data .= _dump($key, " ", $_SSLinfo{$key});
    }
    $data .= _dump('errors',  "\n", join("\n ** ", @{$_SSLinfo{'errors'}}));
    $data .= "$SSLinfo::prefix_trace$prefix datadump #}"; # quick&dirty global prefix_trace
    return $data;
} # datadump

#_____________________________________________________________________________
#______________________________________________ internal SSL helper methods __|

### _OpenSSL_opt_get()  defined later to avoid forward declaration

sub _SSLinfo_get    {
    # get specified value from %_SSLinfo, first parameter 'key' is mandatory
    # uses trace=2 to avoid superfluous output
    my ($key, $host, $port) = @_;
    _traceset();
    _trace2("_SSLinfo_get('$key'," . ($host||'') . "," . ($port||'') . ")");
    if ($key eq 'ciphers_openssl') {
        _trace("_SSLinfo_get($key): WARNING: function obsolete, please use cipher_openssl()");
        return '';
    }
    if ($key eq 'errors') { # always there, no need to connect target
        #src = Net::SSLeay::ERR_peek_error;      # just returns number
        #src = Net::SSLeay::ERR_peek_last_error; # should work since openssl 0.9.7
        return wantarray ? @{$_SSLinfo{$key}} : join("\n", @{$_SSLinfo{$key}});
    }
    if (not defined $_SSLinfo{'ssl'}) {
        # if-condition only to avoid multiple calls, improves performance and produces less trace output
        return '' if not defined do_ssl_open($host, $port, '');
    }
    if ($key eq 'ciphers') { # special handling
        return wantarray ? @{$_SSLinfo{$key}} : join(' ', @{$_SSLinfo{$key}});
        return wantarray ? @{$_SSLinfo{$key}} : join(':', @{$_SSLinfo{$key}}); # if we want `openssl ciphers' format
    }
    if ($key eq 'dates') {
       _trace2("_SSLinfo_get 'dates'=" . $_SSLinfo{'before'} . " " . $_SSLinfo{'after'});
        return ( $_SSLinfo{'before'}, $_SSLinfo{'after'});
    }
    if (0 < $trace) {
        my $value = $_SSLinfo{$key} || '';
           $value = "<<use --trace=2 to print data>>" if ($value =~ m/[\r\n]/);
        _trace2("_SSLinfo_get '$key'=$value");
    }
    return (grep{/^$key$/} keys %_SSLinfo) ? $_SSLinfo{$key} : '';
} # _SSLinfo_get

#
# general internal functions
#

sub _check_host     {
    #? convert hostname to IP and store in $_SSLinfo{'host'}, returns 1 on success
    my $host = shift;
    _trace("_check_host(" . ($host||'') . ")");
    $host  = $_SSLinfo{'host'} unless defined $host;
    my $ip = undef;
    if($ip = gethostbyname($host)) {    # check result of assignment!
        $_SSLinfo{'host'} = $host;
        $_SSLinfo{'addr'} = $ip;
        $_SSLinfo{'ip'}   = join('.', unpack('W4', $ip));
    } else {
        push(@{$_SSLinfo{'errors'}}, "_check_host: $!");
    }
    _trace("_check_host $_SSLinfo{'host'} $_SSLinfo{'ip'}");
    #dbx# _trace("_check_host =" . ((defined $ip) ? 1 : undef));
    return (defined $ip) ? 1 : undef;
} # _check_host

sub _check_port     {
    #? convert port name to number and store in $_SSLinfo{'port'}, returns 1 on success
    my $port = shift;
    _trace("_check_port(" . ($port||'') . ")");
    $port  = $_SSLinfo{'port'} unless defined $port;
    $port  = getservbyname($port, 'tcp') unless $port =~ /^\d+$/;
    push(@{$_SSLinfo{'errors'}}, "_check_port: $!") if ($! !~ m/^\s*$/);
    $_SSLinfo{'port'} = $port if (defined $port);
    #dbx# _trace("_check_port =$port");
    return (defined $port) ? 1 : undef;
} # _check_port

sub _check_peer     {
    # TBD
    my ($ok, $x509_store_ctx) = @_;
    _trace("_check_peer($ok, " . _trace_value_or_text($x509_store_ctx) . ")");
    $_SSLinfo{'verify_cnt'} += 1;
    return $ok;
} # _check_peer

sub _check_crl      { ## no critic qw(Subroutines::ProhibitUnusedPrivateSubroutines)
    # TBD
    my $ssl = shift;
    _trace("_check_crl()");
    return;
} # _check_crl

sub _check_client_cert {print "##check_client_cert\n"; return; } ## no critic qw(Subroutines::ProhibitUnusedPrivateSubroutines)
#$my $err = Net::SSLeay::set_verify ($ssl, Net::SSLeay::VERIFY_CLIENT_ONCE, \&_check_client_cert );

sub _ssleay_cert_get    {
    #? get specified value from SSLeay certificate
        # wrapper to get data provided by certificate
        # note that all these function may produce "segmentation fault" or alike if
        # the target does not have/use a certificate but allows connection with SSL
    my ($key, $x509) = @_;
    _traceset();
    _trace("_ssleay_cert_get('$key', x509)");
    if (0 != $SSLinfo::no_cert) {
        _trace("_ssleay_cert_get 'use_cert' $SSLinfo::no_cert .");
        return $SSLinfo::no_cert_txt if (2 == $SSLinfo::no_cert);
        return '';
    }

    if (not $x509) {
        # ugly check to avoid "Segmentation fault" if $x509 is 0 or undef
        return $SSLinfo::no_cert_txt if ($key =~ m/^(PEM|version|md5|sha1|sha2|subject|issuer|before|after|serial_hex|cn|policies|error_depth|cert_type|serial|altname)/); ## no critic qw(RegularExpressions::ProhibitComplexRegexes)
    }

    return Net::SSLeay::PEM_get_string_X509(     $x509) || ''   if ($key eq 'PEM');
    return Net::SSLeay::X509_get_version(        $x509) + 1     if ($key eq 'version');
    return Net::SSLeay::X509_get_fingerprint(    $x509,  'md5') if ($key eq 'md5');
    return Net::SSLeay::X509_get_fingerprint(    $x509, 'sha1') if ($key eq 'sha1');
    return Net::SSLeay::X509_get_fingerprint(  $x509, 'sha256') if ($key eq 'sha2');
    return Net::SSLeay::X509_NAME_oneline(        Net::SSLeay::X509_get_subject_name($x509)) if ($key eq 'subject');
    return Net::SSLeay::X509_NAME_oneline(        Net::SSLeay::X509_get_issuer_name( $x509)) if ($key eq 'issuer');
    return Net::SSLeay::P_ASN1_UTCTIME_put2string(Net::SSLeay::X509_get_notBefore(   $x509)) if ($key eq 'before');
    return Net::SSLeay::P_ASN1_UTCTIME_put2string(Net::SSLeay::X509_get_notAfter(    $x509)) if ($key eq 'after');
    return Net::SSLeay::P_ASN1_INTEGER_get_hex(Net::SSLeay::X509_get_serialNumber(   $x509)) if ($key eq 'serial_hex');
    return Net::SSLeay::X509_NAME_get_text_by_NID(
                    Net::SSLeay::X509_get_subject_name($x509), &Net::SSLeay::NID_commonName) if ($key eq 'cn');
    return Net::SSLeay::X509_NAME_get_text_by_NID(
                    Net::SSLeay::X509_get_subject_name($x509), &Net::SSLeay::NID_certificate_policies) if ($key eq 'policies');
    return Net::SSLeay::X509_STORE_CTX_get_error_depth($x509)   if ($key eq 'error_depth');
    return Net::SSLeay::X509_certificate_type(         $x509)   if ($key eq 'cert_type');
    return Net::SSLeay::X509_subject_name_hash(        $x509)   if ($key eq 'subject_hash');
    return Net::SSLeay::X509_issuer_name_hash(         $x509)   if ($key eq 'issuer_hash');

    my $ret = '';
    if ($key =~ 'serial') {
#dbx# print "#SERIAL# $key #\n";
# TODO: dead code as Net::SSLeay::X509_get_serialNumber() does not really return an integer
        $ret = Net::SSLeay::P_ASN1_INTEGER_get_hex(Net::SSLeay::X509_get_serialNumber(   $x509));
        return $ret if($key eq 'serial_hex');
        my $int = hex($ret);
        return $int if($key eq 'serial_int');
        return "$int (0x$ret)"; # if($key eq 'serial');
    }

    if ($key eq 'altname') {
        my @altnames = Net::SSLeay::X509_get_subjectAltNames($x509); # returns array of (type, string)
        _trace2("_ssleay_cert_get: Altname: " . join(' ', @altnames));
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
            $name = join('.', unpack('W4', $name)) if ($type eq 'IPADD');
            # all other types are used as is, so we see what's missing
            $ret .= ' ' . join(':', $type, $name);
        }
    }
    _trace("_ssleay_cert_get '$key'=$ret");  # or warn "$STR{WARN} wrong key '$key' given; ignored";
    return $ret;
} # _ssleay_cert_get

sub _ssleay_socket  {
    #? craete TLS socket or use given socket
    # side-effects: uses $SSLinfo::starttls, $SSLinfo::proxyhost  ::proxyport
    my $host    = shift;
    my $port    = shift;
    my $socket  = shift;
    my $src     = '';   # function (name) where something failed
    my $err     = '';
    my $dum     = '';
    _traceset();
    _trace("_ssleay_socket(" . ($host||'') . "," . ($port||'') . ") {");
    goto FIN if (defined $socket);
    $socket  = undef;
    local $! = undef;   # avoid using cached error messages

    TRY: {
        unless (($SSLinfo::starttls) || ($SSLinfo::proxyhost)) {
               # $SSLinfo::proxyport was already checked in main
            #1a. no proxy and not starttls
            # $host and $port may be undefined, hence the ugly setting of $src
            # to avoid Perl's "Use of uninitialized value $host in concatenation ... "
            # _check_host() and _check_port() woll work poper with undef values
            $src = '_check_host(' . ($host||'') . ')'; if (not defined _check_host($host)) { $err = $!; last; }
            $src = '_check_port(' . ($port||'') . ')'; if (not defined _check_port($port)) { $err = $!; last; }
            $src = 'socket()';
                    socket( $socket, Socket::AF_INET, Socket::SOCK_STREAM, 0) or do {$err = $!} and last;
            $src = 'connect()';
            $dum=()=connect($socket, Socket::sockaddr_in($_SSLinfo{'port'}, $_SSLinfo{'addr'})) or do {$err = $!} and last;
        } else {
            #1b. starttls or via proxy
            require SSLhello;   # ok here, as perl handles multiple includes proper
            SSLhello::version() if (1 < $trace);
            $src = 'SSLhello::openTcpSSLconnection()';
            # open TCP connection via proxy and do STARTTLS if requested
            # NOTE that $host cannot be checked here because the proxy does
            # DNS and also has the routes to the host
            ($socket = SSLhello::openTcpSSLconnection($host, $port)) or do {$err = $!} and last;
        }
        ## no critic qw(InputOutput::ProhibitOneArgSelect)
        select($socket); local $| = 1; select(STDOUT);  # Eliminate STDIO buffering
        ## use critic
        goto FIN;
    }; # TRY
    push(@{$_SSLinfo{'errors'}}, "_ssleay_socket() failed calling $src: $err");
    FIN:
    _trace("_ssleay_socket()\t= " . _trace_value_or_text($socket) . " }");
    return $socket;
} # _ssleay_socket

sub _ssleay_ctx_new {
    #? get SSLeay CTX object; returns ctx object or undef
    my $method  = shift;# CTX method to be used for creating object
    my $ctx     = undef;# CTX object to be created
    my $src     = '';   # function (name) where something failed
    my $err     = '';
    my $old     = '';
    _traceset();
    _trace("_ssleay_ctx_new($method) {");
    $src = "Net::SSLeay::$method";
    _trace2(" _ssleay_ctx_new: $src");
    local $! = undef;   # avoid using cached error messages

    TRY: {
        # no proper generic way to replace following ugly SWITCH code, however: it's save
        # calling function already checked for CTX_*  and  *_method, but we do
        # not have the information (aka result from ssleay_methods()) here, so
        # we need to check for existance of  *_method  again
        # CTX_* (i.e. CTX_v23_new) returns an object, errors are on error stack
        # last gets out of TRY block
        $_   = $method; # { # SWITCH
        /CTX_tlsv1_3_new/  && do {
            #2.1. prepare SSL's context object
            ($ctx = Net::SSLeay::CTX_tlsv1_3_new()) or last;# create object
            #2.2. set default protocol version
            if (defined &Net::SSLeay::TLSv1_3_method) {
                $src = 'Net::SSLeay::CTX_set_ssl_version(TLSv1_3_method)';
                Net::SSLeay::CTX_set_ssl_version($ctx, Net::SSLeay::TLSv1_3_method()) or do {$err = $!} and last;
                # allow all versions for backward compatibility; user specific
                # restrictions are done later with  CTX_set_options()
                $src = '';  # push error on error stack at end of SWITCH
            } else {
                $src = 'Net::SSLeay::TLSv1_3_method()';
            }
        };
        /CTX_tlsv1_2_new/  && do {
            ($ctx = Net::SSLeay::CTX_tlsv1_2_new()) or last;
            if (defined &Net::SSLeay::TLSv1_2_method) {
                $src = 'Net::SSLeay::CTX_set_ssl_version(TLSv1_2_method)';
                Net::SSLeay::CTX_set_ssl_version($ctx, Net::SSLeay::TLSv1_2_method()) or do {$err = $!} and last;
                $src = '';
            } else {
                $src = 'Net::SSLeay::TLSv1_2_method()';
            }
            # default timeout is 7200
        };
        /CTX_tlsv1_1_new/  && do {
            ($ctx = Net::SSLeay::CTX_tlsv1_1_new()) or last;
            if (defined &Net::SSLeay::TLSv1_1_method) {
                $src = 'Net::SSLeay::CTX_set_ssl_version(TLSv1_1_method)';
                Net::SSLeay::CTX_set_ssl_version($ctx, Net::SSLeay::TLSv1_1_method()) or do {$err = $!} and last;
                $src = '';
            } else {
                $src = 'Net::SSLeay::TLSv1_1_method()';
            }
        };
        /CTX_tlsv1_new/    && do {
            ($ctx = Net::SSLeay::CTX_tlsv1_new()) or last;
            if (defined &Net::SSLeay::TLSv1_method) {
                $src = 'Net::SSLeay::CTX_set_ssl_version(TLSv1_method)';
                Net::SSLeay::CTX_set_ssl_version($ctx, Net::SSLeay::TLSv1_method())   or do {$err = $!} and last;
                $src = '';
            } else {
                $src = 'Net::SSLeay::TLSv1_2_method()';
            }
        };
        /CTX_v23_new/      && do {
            # we use CTX_v23_new() 'cause of CTX_new() sets SSL_OP_NO_SSLv2
            ($ctx = Net::SSLeay::CTX_v23_new()) or last;
            if (defined &Net::SSLeay::SSLv23_method) {
                $src = 'Net::SSLeay::CTX_set_ssl_version(SSLv23_method)';
                Net::SSLeay::CTX_set_ssl_version($ctx, Net::SSLeay::SSLv23_method())  or do {$err = $!} and last;
                $src = '';
            } else {
                $src = 'Net::SSLeay::SSLv23_method()';
            }
            # default timeout is 300
        };
        /CTX_v3_new/       && do {
            ($ctx = Net::SSLeay::CTX_v3_new()) or last;
            if (defined &Net::SSLeay::SSLv3_method) {
                $src = 'Net::SSLeay::CTX_set_ssl_version(SSLv3_method)';
                Net::SSLeay::CTX_set_ssl_version($ctx, Net::SSLeay::SSLv3_method())   or do {$err = $!} and last;
                $src = '';
            } else {
                $src = 'Net::SSLeay::SSLv3_method()';
            }
        };
        /CTX_v2_new/       && do {
            ($ctx = Net::SSLeay::CTX_v2_new()) or last;
            if (defined &Net::SSLeay::SSLv2_method) {
                $src = 'Net::SSLeay::CTX_set_ssl_version(SSLv2_method)';
                Net::SSLeay::CTX_set_ssl_version($ctx, Net::SSLeay::SSLv2_method())   or do {$err = $!} and last;
                $src = '';
            } else {
                $src = 'Net::SSLeay::SSLv2_method()';
            }
        };
        /CTX_dtlsv1_3_new/ && do {
        };
        /CTX_dtlsv1_2_new/ && do {
        };
        /CTX_dtlsv1_1_new/ && do {
        };
        /CTX_dtlsv1_new/   && do {
        };
        #} # SWITCH
        goto FIN if not $ctx; # no matching method, ready
        $_SSLinfo{'CTX_method'} = $method;  # for debugging only
        if ('' ne $src) {
            # setting protocol options failed (see SWITCH above)
            push(@{$_SSLinfo{'errors'}}, "_ssleay_ctx_new() WARNING '$src' not available, using system default for '$method'");
            # if we don't have proper  *_method(), we better use the system's
            # default behaviour, because anything else  would stick  on the
            # specified protocol version, like SSLv3_method()
        }
        #2.3. set protocol options
        my  $options  = &Net::SSLeay::OP_ALL;
            # sets all options, even those for all protocol versions (which are removed later)
        if (0 < $SSLinfo::no_compression) {
            $options |= &Net::SSLeay::OP_NO_COMPRESSION;
            # default:  OP_ALL does not contain OP_NO_COMPRESSION
            # this is ok as we want to detect if targets support compression,
            # disabling compression must be requested with special option
        }
            #test# # quick$dirty disable SSL_OP_TLSEXT_PADDING 0x00000010L (see ssl.h)
            #test# $options ^= 0x00000010;
            # OP_CIPHER_SERVER_PREFERENCE, OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
            # should also be set now
        $src = 'Net::SSLeay::CTX_set_options()';
            #   Net::SSLeay::CTX_set_options(); # can not fail according description!
                Net::SSLeay::CTX_set_options($ctx, 0); # reset options
                Net::SSLeay::CTX_set_options($ctx, $options);
        $src = 'Net::SSLeay::CTX_set_timeout()';
        ($old = Net::SSLeay::CTX_set_timeout($ctx, $SSLinfo::timeout_sec)) or do {$err = $!; } and last;
        _trace(" CTX_get_session_cache_mode(CTX)= " . sprintf('0x%08x', Net::SSLeay::CTX_get_session_cache_mode($ctx)));
        _trace(" CTX_get_timeout(CTX)= $old -> " . Net::SSLeay::CTX_get_timeout($ctx));
        _trace(" CTX_get_options(CTX)= " . sprintf('0x%08x', Net::SSLeay::CTX_get_options($ctx)));
        _traceSSLbitmasks( " CTX options", Net::SSLeay::CTX_get_options($ctx));
        goto FIN;
    } # TRY
    # reach here if ::CTX_* failed
    push(@{$_SSLinfo{'errors'}}, "_ssleay_ctx_new() failed calling $src: $err");
    FIN:
    return $ctx;
} # _ssleay_ctx_new

sub _ssleay_ctx_ca  {
    #? set certificate verify options (client mode); returns 0 on failure
    #  uses settings from $SSLinfo::ca*
    my $ctx     = shift;
    my $ssl     = undef;
    my $ret     = 0;
    my $src     = '';   # function (name) where something failed
    my $err     = '';
    my $cafile  = '';
    my $capath  = '';
    _traceset();
    _trace("_ssleay_ctx_ca(" . _trace_value_or_text($ctx) . ") {");
    TRY: {
        Net::SSLeay::CTX_set_verify($ctx, &Net::SSLeay::VERIFY_NONE, \&_check_peer);
            # we're in client mode where only  VERYFY_NONE  or  VERYFY_PEER  is
            # used; as we want to get all information,  even if something  went
            # wrong, we use VERIFY_NONE so we can proceed collecting data
            # possible values:
            #  0 = SSL_VERIFY_NONE
            #  1 = SSL_VERIFY_PEER
            #  2 = SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            #  4 = SSL_VERIFY_CLIENT_ONCE
# TODO: SSL_OCSP_NO_STAPLE
        $src = 'Net::SSLeay::CTX_load_verify_locations()';
        $cafile = $SSLinfo::ca_file || '';
        if ($cafile !~ m#^(?:[a-zA-Z0-9_,.\\/()-])*$#) {
            $err = "invalid characters for " . '$SSLinfo::ca_file; not used';
            last;
        }
        $capath = $SSLinfo::ca_path || '';
        if ($capath !~ m#^(?:[a-zA-Z0-9_,.\\/()-]*)$#) {
            $err = "invalid characters for " . '$SSLinfo::ca_path; not used';
            last;
        }
        if (($capath . $cafile) ne '') { # CTX_load_verify_locations() fails if both are empty
            Net::SSLeay::CTX_load_verify_locations($ctx, $cafile, $capath) or do {$err = $!} and last;
            # CTX_load_verify_locations()  sets SSLeay's error stack,  which is
            # roughly the same as $!
        }
        $src = 'Net::SSLeay::CTX_set_verify_depth()';
        if (defined $SSLinfo::ca_depth) {
            if ($SSLinfo::ca_depth !~ m/^[0-9]$/) {
                $err = "invalid value '$SSLinfo::ca_depth' for " . '$SSLinfo::ca_depth; not used';
                last;
            }
            Net::SSLeay::CTX_set_verify_depth($ctx, $SSLinfo::ca_depth);
        }
        # TODO: certificate CRL
        # just code example, not yet tested
        #
        # enable Net::SSLeay CRL checking:
        #   &Net::SSLeay::X509_STORE_set_flags
        #       (&Net::SSLeay::CTX_get_cert_store($ssl),
        #        &Net::SSLeay::X509_V_FLAG_CRL_CHECK);
        $ret = 1; # success
        goto FIN;
    } # TRY
    push(@{$_SSLinfo{'errors'}}, "_ssleay_ctx_ca() failed calling $src: $err");
    FIN:
    _trace("_ssleay_ctx_ca()\t= $ret }");
    return $ret;
} # _ssleay_ctx_ca

sub _ssleay_ssl_new {
    #? create new SSL object; return SSL object or undef
    #  uses $SSLinfo::use_SNI
    my $ctx     = shift;
    my $host    = shift;
    my $socket  = shift;
    my $cipher  = shift;
    my $ssl     = undef;
    my $src     = '';   # function (name) where something failed
    my $err     = '';
    _traceset();
    _trace("_ssleay_ssl_new(" . _trace_value_or_text($ctx) . ") {");
    TRY: {
        #3. prepare SSL object
        $src = 'Net::SSLeay::new()';
        ($ssl=  Net::SSLeay::new($ctx))                        or do {$err = $!} and last;
        $src = 'Net::SSLeay::set_fd()';
                Net::SSLeay::set_fd($ssl, fileno($socket))     or do {$err = $!} and last;
        $src = "Net::SSLeay::set_cipher_list($cipher)";
                Net::SSLeay::set_cipher_list($ssl, $cipher)    or do {$err = $!} and last;
        if (0 < $SSLinfo::use_SNI) {
            my $sni  = $SSLinfo::sni_name;
            _trace(" use SNI");
            if (1.45 <= $Net::SSLeay::VERSION) {
                # set_tlsext_host_name() vanished somewhen after 1.88
                $src = 'Net::SSLeay::set_tlsext_host_name()';
                my $e = Net::SSLeay::set_tlsext_host_name($ssl, $sni);
                if ((0 == $e) and ($0 !~ /SSLinfo.pm$/)) { $err = $!; last; }
                    # TODO: openssl > 2.0: sets error "No such file or directory",
                    #       but seems to work, probably because API missing
                    # fails since (1.88 < $Net::SSLeay::VERSION) when called as:
                    #       Net/SSLinfo.pm localhost
                    # reason unknown; hence exit for Net/SSLinfo.pm itself disabled
            } else {
                # quick&dirty instead of:
                #  use constant SSL_CTRL_SET_TLSEXT_HOSTNAME => 55
                #  use constant TLSEXT_NAMETYPE_host_name    => 0
                $src = 'Net::SSLeay::ctrl()';
                Net::SSLeay::ctrl($ssl, 55, 0, $sni)           or do {$err = $!} and last;
                # TODO: ctrl() sometimes fails but does not return errors, reason yet unknown
            }
        }
        goto FIN;
    } # TRY
    push(@{$_SSLinfo{'errors'}}, "_ssleay_ssl_new() failed calling $src: $err");
    FIN:
    _trace("_ssleay_ssl_new()\t= " . _trace_value_or_text($ssl) . " }");
    return $ssl;
} # _ssleay_ssl_new

sub _ssleay_ssl_np  {
    #? sets CTX for ALPN and/or NPN if possible
    # returns -1 on success, otherwise array with errors
    # Note: check if functionality is available should be done before,
    #       for defensive programming, it's done here again
    # Note  that parameters are different: ALPN array ref. vs. NPN array
    my $ctx         = shift;
    my $protos_alpn = shift;
    my $protos_npn  = shift;
    my @protos_alpn = split(/,/, $protos_alpn); # Net::SSLeay wants a list
    my @protos_npn  = split(/,/, $protos_npn);
    _trace("_ssleay_ssl_np(ctx, $protos_alpn, $protos_npn)");
    my $src;
    my @err;
    # functions return 0 on success, hence: && do{} to catch errors
    # ALPN (Net-SSLeay > 1.55, openssl >= 1.0.2)
    if ($protos_alpn !~ m/^\s*$/) {
        if (exists &Net::SSLeay::CTX_set_alpn_protos) {
            $src = 'Net::SSLeay::CTX_set_alpn_protos()';
            Net::SSLeay::CTX_set_alpn_protos($ctx, [@protos_alpn]) && do {
                push(@err, "_ssleay_ssl_np(),alpn failed calling $src: $!");
            };
        }
    }
    # NPN  (Net-SSLeay > 1.45, openssl >= 1.0.1)
    if ($protos_npn !~ m/^\s*$/) {
        if (exists &Net::SSLeay::CTX_set_next_proto_select_cb) {
            $src = 'Net::SSLeay::CTX_set_next_proto_select_cb()';
            Net::SSLeay::CTX_set_next_proto_select_cb($ctx, @protos_npn) && do {
                push(@err, "_ssleay_ssl_np(),npn  failed calling $src: $!");
            };
        }
    }
    _trace("_ssleay_ssl_np()\t= $#err }");
    return @err;
} # _ssleay_ssl_np

sub _header_get     {
    #? get value for specified header from given HTTP response; empty if not exists
    my $head    = shift;   # header to search for
    my $response= shift; # response where to serach
    my $value   = '';
    _trace2("__header_get('$head', <<response>>)");
    if ($response =~ m/[\r\n]$head\s*:/i) {
        $value  =  $response;
        $value  =~ s/.*?[\r\n]$head\s*:\s*([^\r\n]*).*$/$1/ims;
    }
    return $value;
} # _header_get

sub _openssl_MS     {
    #? wrapper to call external openssl executable on windows
    my $mode = shift;   # must be openssl command
    my $host = shift;   # '' if not used
    my $port = shift;   # '' if not used
    my $text = shift;   # text to be piped to openssl
    my $data = '';
    return '' if ($^O !~ m/MSWin32/);

    _trace("_openssl_MS($mode, $host, $port)");
    if ('' eq $_openssl) {
        _trace("_openssl_MS($mode): WARNING: no openssl");
        return $SSLINFO{'OPENSSL'};
    }
    $host .= ':' if ($port ne '');
    $text = '""' if (not defined $text);
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
    _trace2("_openssl_MS $mode $host$port: cmd.exe /D /C /S $tmp");
    TRY: {
        my $fh;
        open($fh, '>', $tmp)                or do {$err = $!} and last;
        print $fh "$text | $_openssl $mode $host$port 2>&1";
        close($fh);
        #dbx# print `cat $tmp`;
        $src = 'cmd.exe';
        ($data = qx(cmd.exe /D /S /C $tmp)) or do {$err = $!} and last; ## no critic qw(InputOutput::ProhibitBacktickOperators)
            # qx() is safe here because `$tmp' is hardcoded here
        $src = 'unlink';
        unlink  $tmp                        or do {$err = $!} and last;
         $data =~ s#^[^)]*[^\r\n]*.##s;          # remove cmd.exe's output
         $data =~ s#WARN.*?openssl.cnf[\r\n]##;  # remove WARNINGs
        _trace2("_openssl_MS $mode $host$port : $data #");
    }
    if ('' ne $err) {
        $text = "_openssl_MS() failed calling $src: $err";
        _trace2($text);
        push(@{$_SSLinfo{'errors'}}, $text);
        return '';
    }
    return $data;
} # _openssl_MS

sub _openssl_x509   {
    #? call external openssl executable to retrive more data from PEM
    my $pem  = shift;
    my $mode = shift;   # must be one of openssl x509's options
    my $data = '';
    _trace2("_openssl_x509($mode,...) {");
    _setcmd();
    if ($_openssl eq '') {
        _trace2("_openssl_x509($mode): WARNING: no openssl");
        return $SSLINFO{'OPENSSL'};
    }
    if ('' eq $pem) {
        # if PEM is empty, openssl may return an error like:
        # unable to load certificate
        # 140593914181264:error:0906D06C:PEM routines:PEM_read_bio:no start line:pem_lib.c:701:Expecting: TRUSTED CERTIFICATE
        _trace2("_openssl_x509($mode): WARNING: no PEM");
        return $SSLinfo::no_cert_txt;
    }

######## 4/2021
# TODO: external openssl is called for every $mode to extract some data from
#       the given $pem.  In practice openssl "simply extracts" the requested
#       information $mode from the textual representation of $pem.
# idea: convert $pem once to text ($mode==-text), then all other data can be
#       extracted from that text; results in one external openssl call.
# currently 4/2021 openssl is call ca. 13 times
# see more comments labeled 14apr21
########

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
    if ($mode =~ m/^-?ocsp/) {
        $mode = "x509 $mode";
        # openssl x509 -ocspid returns data only without noout, probably a bug
    } else {
        $mode = "x509 -noout $mode";
    }
    if (2 < $trace) {
        _trace("_openssl_x509: openssl $mode < '$pem'");
    } else {
        _trace("_openssl_x509: openssl $mode");
    }
    if ($^O !~ m/MSWin32/) {
        $data = qx(echo '$pem' | $_openssl $mode 2>&1); ## no critic qw(InputOutput::ProhibitBacktickOperators)
            # qx() is safe here because `$_openssl' checked in _setcommand()
    } else { # it's sooooo simple, except on Windows :-(
        $data = _openssl_MS($mode, '', '', $pem);
    }
    chomp $data;
    $data =~ s/\n?-----BEGIN.*$//s if ( $mode =~ m/ -ocsp/); # see above
    $data =~ s/\s*$//;  # be sure ...
    $data =~ s/\s*Version:\s*//i if (($mode =~ m/ -text /) && ($mode !~ m/version,/)); # ugly test for version
    #_dbx# print "#3 $data \n#3";
    _trace2("_openssl_x509()\t= $data }");
    return $data;
} # _openssl_x509

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

=pod

=head3 s_client_check()

Check if specified openssl executable is available and check capabilities of
"s_client"  command..
Returns  undef  if openssl is not available.

=head3 s_client_get_optionlist

Get list of options for openssl s_client command. Returns array.

=head3 s_client_opt_get($option)

Returns 1 if specified option is available for openssl s_client.

=cut

sub s_client_check  {
    #? store capabilities of "openssl s_client" command in %_OpenSSL_opt
    return 1 if (0 < $_OpenSSL_opt{'done'});
    _traceset();
    _trace("s_client_check()");
    _setcmd();
    if ('' eq $_openssl) {
        _trace("s_client_check(): WARNING: no openssl");
        return undef; ## no critic qw(Subroutines::ProhibitExplicitReturnUndef)
    }

    # check with "openssl s_client --help" where --help most likely is unknown
    # and hence forces the usage message which will be analysed
    # Note: following checks asume that the  returned usage properly describes
    #       openssl's capabilities
    # Partial example of output:
    # unknown option --help
    # usage: s_client args
    #
    #  -host host     - use -connect instead
    #  -port port     - use -connect instead
    #  -connect host:port - who to connect to (default is localhost:4433)
    #  -proxy host:port - use HTTP proxy to connect
    #...
    #  -CApath arg   - PEM format directory of CA's
    #  -CAfile arg   - PEM format file of CA's
    #  -reconnect    - Drop and re-make the connection with the same Session-ID
    #  -pause        - sleep(1) after each read(2) and write(2) system call
    #  -debug        - extra output
    #  -msg          - Show protocol messages
    #  -nbio_test    - more ssl protocol testing
    #  -psk_identity arg - PSK identity
    #  -psk arg      - PSK in hex (without 0x)
    #  -fallback_scsv - send TLS_FALLBACK_SCSV
    #  -bugs         - Switch on all SSL implementation bug workarounds
    #...
    #  -servername host  - Set TLS extension servername in ClientHello
    #  -tlsextdebug      - hex dump of all TLS extensions received
    #  -status           - request certificate status from server
    #  -no_ticket        - disable use of RFC4507bis session tickets
    #  -serverinfo types - send empty ClientHello extensions
    #  -curves arg       - Elliptic curves to advertise
    #  -sigalgs arg      - Signature algorithms to support
    #  -nextprotoneg arg - enable NPN extension
    #  -alpn arg         - enable ALPN extension
    #  -legacy_renegotiation - enable use of legacy renegotiation
    #  -no_tlsext        - Don't send any TLS extensions
    #
    if ($^O =~ m/MSWin32/) {
        $_OpenSSL_opt{'data'} = _openssl_MS('s_client -help', '', '', '');  # no host:port
    } else {
        $_OpenSSL_opt{'data'} = qx($_openssl s_client -help 2>&1);  ## no critic qw(InputOutput::ProhibitBacktickOperators)
            # qx() is safe here because `$_openssl' checked in _setcommand()
    }
    #_trace("data{ $_OpenSSL_opt{'data'} }";

    # store data very simple: set value to 1 if option appears in output
    foreach my $key (sort keys %_OpenSSL_opt) {
        next if ($key !~ m/^-/);    # ensure that only options are set
        $_OpenSSL_opt{$key} = grep{/^ *$key\s/} split("\n", $_OpenSSL_opt{'data'}); # returns 1 or 0
    }
    $_OpenSSL_opt{'-npn'} = $_OpenSSL_opt{'-nextprotoneg'}; # -npn is an alias
    $_OpenSSL_opt{'done'} = 1;
    _trace("s_client_check()\t= 1");
    return 1;
} # s_client_check

sub _OpenSSL_opt_get{
    #? get specified value from %_OpenSSL_opt, parameter 'key' is mandatory
    my $key = shift;
    _traceset();
    if (0 <= $_OpenSSL_opt{'done'}) {
        # initialise %_OpenSSL_opt
        if (not defined s_client_check()) {
            _trace("_OpenSSL_opt_get('$key') undef");
            return $SSLINFO{'OPENSSL'};
        }
    }
    _trace("_OpenSSL_opt_get('$key')\t= " . ($_OpenSSL_opt{$key} || 0));
    return (grep{/^$key$/} keys %_OpenSSL_opt) ? $_OpenSSL_opt{$key} : '';
} # _OpenSSL_opt_get

sub s_client_get_optionlist { return (grep{/^-/} keys %_OpenSSL_opt); }

sub s_client_opt_get{ return _OpenSSL_opt_get(shift); }

=pod

=head3 do_ssl_free($ctx,$ssl,$socket)

Destroy and free L<Net::SSLeay> allocated objects.
=cut

sub do_ssl_free     {
    #? free SSL objects of NET::SSLeay TCP connection
    my ($ctx, $ssl, $socket) = @_;
    close($socket)              if (defined $socket);
    Net::SSLeay::free($ssl)     if (defined $ssl); # or warn "$STR{WARN} Net::SSLeay::free(): $!";
    Net::SSLeay::CTX_free($ctx) if (defined $ctx); # or warn "$STR{WARN} Net::SSLeay::CTX_free(): $!";
    return;
} # do_ssl_free

=pod

=head3 do_ssl_new($host,$port,$sslversions[,$cipherlist,$alpns,$npns,$socket])

Establish new SSL connection using L<Net::SSLeay>.

Returns array with $ssl object, $ctx object, $socket and CTX $method.
Errors, if any, are stored in $_SSLtemp{'errors'}.

This method is thread safe according the limitations described in L<Net::SSLeay>.
Use L<do_ssl_free($ctx,$ssl,$socket)> to free allocated objects.
=cut

sub do_ssl_new      {   ## no critic qw(Subroutines::ProhibitManyArgs)
    my ($host, $port, $sslversions, $cipher, $protos_alpn, $protos_npn, $socket) = @_;
    my $ctx     = undef;
    my $ssl     = undef;
    my $method  = undef;
    my $src;            # function (name) where something failed
    my $err     = '';   # error string, if any, from sub-system $src
    my $tmp_sock= undef;# newly opened socket,
                        # Note: $socket is only used to check if it is defined
    my $dum     = undef;
    $cipher     = '' if (not defined $cipher);      # cipher parameter is optional
    $protos_alpn= '' if (not defined $protos_alpn); # -"-
    $protos_npn = '' if (not defined $protos_npn);  # -"-
    _traceset();
    _trace("do_ssl_new(" . ($host||'') . ',' . ($port||'') . ',' . ($sslversions||'') . ','
                       . ($cipher||'') . ',' . ($protos_alpn||'') . ',socket) {');
    _SSLtemp_reset();   # assumes that handles there are already freed

    TRY: {

        # TRY_PROTOCOL: {
        # Open TCP connection and innitilise SSL connection.
        # This nitialisation is done with Net::SSLeay's CTX_*_new and *_method
        # methods (i.e. CTX_tlsv1_2_new and TLSv1_2_method).
        # Remember the concepts: work with ancient (perl, openssl) installations
        # Hence we try all known methods, starting with the most modern first.
        # The list of methods and its sequence is provided by  ssleay_methods.
        # We loop over this list of methods (aka protocols) until a valid  CTX
        # object will be returned.
        # NOTE: _ssleay_ctx_new() gets $ctx_new but also needs *_method, which
        #       is not passed as argument.  Hence  _ssleay_ctx_new()  needs to
        #       check for it again, ugly ... may change in future ...
        #
        # Some servers (godaddy.com 11/2016) behave strange if the socket will
        # be reused. In particular they respond with an TLS Alert, complaining
        # that the protocol is not allowed (alert message 70).
        # * Until Version 17.03.17
        #   The socket (if it exists) will be closed and then reopend.
        # FIXME: 11/2016:  not tested if the $SSLinfo::socket is provided
        #        by the caller
        # * Version 17.04.17
        #   Socket opened only if it is undef; the caller is responsibel for a
        #   proper $socket value.

        my @list = ssleay_methods();
        foreach my $ctx_new (@list) {
            next if ($ctx_new !~ m/^CTX_/);
            next if ($ctx_new =~ m/CTX_new$/);  # CTX_new
            next if ($ctx_new =~ m/_method$/);  # i.e. CTX_new_with_method
            next if ($ctx_new =~ m/_options$/); # i.e. CTX_get_options
            next if ($ctx_new =~ m/_timeout$/); # i.e. CTX_set_timeout
            $method = $ctx_new;
            _trace("do_ssl_new: $method ...");
            $src = $ctx_new;

            #0. first reset Net::SSLeay objects if they exist
            do_ssl_free($ctx, $ssl, $tmp_sock);
            $ctx        = undef;
            $ssl        = undef;
            $tmp_sock   = undef;

            #1a. open TCP connection; no way to continue if it fails
            ($tmp_sock = _ssleay_socket($host, $port, $tmp_sock)) or do {$src = '_ssleay_socket()'} and last TRY;
            # TODO: need to pass ::starttls, ::proxyhost and ::proxyport

            #1b. get SSL's context object
            ($ctx = _ssleay_ctx_new($ctx_new))  or do {$src = '_ssleay_ctx_new()'} and next;

            #1c. disable not specified SSL versions, limit as specified by user
            foreach my $_ssl (sort keys %_SSLmap) {
                # $sslversions  passes the version which should be supported,  but
                # openssl and hence Net::SSLeay, configures what  should *not*  be
                # supported, so we skip all versions found in  $sslversions
                next if ($sslversions =~ m/^\s*$/); # no version given, leave default
                next if (grep{/^$_ssl$/} split(/ /, $sslversions));
                my $bitmask = _SSLbitmask_get($_ssl);
                if (defined $bitmask) {        # if there is a bitmask, disable this version
                    _trace("do_ssl_new: OP_NO_$_ssl");  # NOTE: constant name *not* as in ssl.h
                    if (1.85 <= $Net::SSLeay::VERSION) {
                        # either perl after 5.32 (here 5.36) complains with:
                        #   Argument "0x04000000" isn't numeric in subroutine entry at ...
                        # or the API of Net::SSLeay::CTX_set_options() after 1.85 changed,
                        # so that the bitmask must be passed as integer
                        Net::SSLeay::CTX_set_options($ctx, hex($bitmask));
                    } else {
                        Net::SSLeay::CTX_set_options($ctx, $bitmask); # 10nov23: 1.85 and older
                    }
                }
                #$Net::SSLeay::ssl_version = 2;  # Insist on SSLv2
                #  or =3  or =10  seems not to work, reason unknown, hence CTX_set_options() above
            }
# TODO: Client-Cert see smtp_tls_cert.pl
# TODO: proxy settings work in HTTP mode only
##Net::SSLeay::set_proxy('some.tld', 84, 'z00', 'pass');
##print "#ERR= $!";

            #1d. set certificate verification options
            ($dum = _ssleay_ctx_ca($ctx))       or do {$src = '_ssleay_ctx_ca()' } and next;

            #1e. set ALPN and NPN option
            my @err = _ssleay_ssl_np($ctx, $protos_alpn, $protos_npn);
            if (0 < $#err) {     # somthing failed, just collect errors
                push(@{$_SSLtemp{'errors'}}, @err);
            }

            #1f. prepare SSL object
            ($ssl = _ssleay_ssl_new($ctx, $host, $tmp_sock, $cipher)) or do {$src = '_ssleay_ssl_new()'} and next;

            #1g. connect SSL
            local $SIG{PIPE} = 'IGNORE';        # Avoid "Broken Pipe"
            my $ret;
            $src = 'Net::SSLeay::connect() ';
            $ret =  Net::SSLeay::connect($ssl); # may call _check_peer() ..
            if (0 > $ret) {
                $src .= " failed start with $ctx_new()"; # i.e. no matching protocol
                $err  = $!;
                push(@{$_SSLtemp{'errors'}}, "do_ssl_new() $src: $err");
                next;
            }
            # following check only if requested; fails to often
            if ($SSLinfo::ignore_handshake <= 0){
              if (0 == $ret) {
                $src .= " failed handshake with $ctx_new()";
                $err  = $!;
                push(@{$_SSLtemp{'errors'}}, "do_ssl_new() $src: $err");
                next;
              }
            }
            $src = '';
            last;
        } # TRY_PROTOCOL }
        if ('' eq $src) {
            # avoid printing empty line, hence "if -1 < $#"
            _trace2(join("\n" . $SSLINFO{'ERROR'} . ' ', '', @{$_SSLtemp{'errors'}})) if (-1 < $#{$_SSLtemp{'errors'}});
            _trace2(" errors reseted.");
            @{$_SSLtemp{'errors'}} = ();        # messages no longer needed
            goto FIN;
        } else {
            # connection failed (see TRY_PROTOCOL above)
            push(@{$_SSLtemp{'errors'}}, "do_ssl_new() connection failed in '$src': $err");
            $src = " failed to connect";
            last;
        }
        #goto FIN if (not $ctx); # TODO: not yet properly tested 11/2016
        _trace("do_ssl_new: $method");

    } # TRY

    # error handling
    close($tmp_sock) if (defined $tmp_sock);
    push(@{$_SSLtemp{'errors'}}, "do_ssl_new() failed calling $src: $err");
    if (1 < $trace) {
        Net::SSLeay::print_errs($SSLINFO{'ERROR'});
        printf("%s%s\n", $SSLINFO{'ERROR'}, $_) foreach @{$_SSLtemp{'errors'}};
    }
    _trace("do_ssl_new() failed }");
    return;

    FIN:
    _trace("do_ssl_new() done }");
    return wantarray ? ($ssl, $ctx, $tmp_sock, $method) : $ssl;
} # do_ssl_new

=pod

=head3 do_ssl_open($host,$port,$sslversions[,$cipherlist])

Opens new SSL connection with Net::SSLeay and stores collected data.

I<$sslversions> is space-separated list of SSL versions to be used. Following
strings are allowed for versions: C<SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 DTLSv1>.
If I<$sslversions> is empty, the system's default settings of versions are used.
If I<$cipherlist> is missing or empty, default C<ALL:NULL:eNULL:aNULL:LOW:EXP>
will be used.

Returns array with $ssl object and $ctx object.

This method is called automatically by all other functions, hence no need to
call it directly.

Use L<do_ssl_close($host,$port)> to free allocated objects.

This method tries to use the most modern methods provided by Net::SSLeay to
establish the connections, i.e. CTX_tlsv1_2_new or CTX_v23_new. If a method
is not available,  the next one will be used.  The sequence of used methods
is hardcoded with most modern first. The current sequence can be seen with:

C<perl -I lib -MSSLinfo -le 'print join"\n",SSLinfo::ssleay_methods();'>

=cut

# from openssl/x509_vfy.h
sub _X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT () { return 18; } ## no critic qw(Subroutines::ProhibitUnusedPrivateSubroutines)
sub _FLAGS_ALLOW_SELFSIGNED () { return 0x00000001; }         ## no critic qw(Subroutines::ProhibitUnusedPrivateSubroutines)
    # "no critic" because these subs may be used by Net::SSLeay

sub do_ssl_open($$$@) {
    my ($host, $port, $sslversions, $cipher) = @_;
    $cipher = '' if (not defined $cipher);  # cipher parameter is optional
    #$port   = _check_port($port);
        # TODO: port may be empty for some calls; results in "... uninitialised
        #       value $port ..."; need to check if call can provide a port
        #       mainly happens if called with --ignore-no-connect
    _traceset();
    _trace("do_ssl_open(" . ($host||'') . "," . ($port||'') . "," . ($sslversions||'') . "," . ($cipher||'') . ") {");
    goto FIN if (defined $_SSLinfo{'ssl'});
    #_traceSSLbitmasks("do_ssl_open SSL version bitmask", &Net::SSLeay::OP_ALL);
    # TODO: no real value for _traceSSLbitmasks() 

    $SSLinfo::target_url =~ s:^\s*$:/:;# set to / if empty
    _vprint("do_ssl_open " . ($host||'') . ":" . ($port||'') . $SSLinfo::target_url );
    #_SSLinfo_reset(); # <== does not work yet as it clears everything
    if ($cipher =~ m/^\s*$/) {
        $cipher = $_SSLinfo{'cipherlist'};
    } else {
        $_SSLinfo{'cipherlist'} = $cipher;
    }
    _trace("do_ssl_open cipherlist: $_SSLinfo{'cipherlist'}");
    my $ctx     = undef;
    my $ssl     = undef;
    my $socket  = undef;
    my $method  = undef;
    my $src;            # function (name) where something failed
    my $err     = '';   # error string, if any, from sub-system $src

    # initialise %_OpenSSL_opt
    $src = 's_client_check';
    if (0 < $SSLinfo::use_openssl) {
        if (not defined s_client_check()) {
            push(@{$_SSLinfo{'errors'}}, "do_ssl_open() WARNING $src: undefined");
       }
    }

    {
      no warnings;  ## no critic (TestingAndDebugging::ProhibitNoWarnings)
      if (defined $SSLinfo::next_protos) { # < 1.182
        warn("$STR{WARN} 090: SSLinfo::next_protos no longer supported, please use SSLinfo::protos_alpn instead");
      }
    }

    TRY: {

        #0. first reset SSLinfo objects if they exist
        # note that $ctx and $ssl is still local and not in %_SSLinfo
        Net::SSLeay::free($ssl)     if (defined $ssl);
        Net::SSLeay::CTX_free($ctx) if (defined $ctx);
        if (1 > $SSLinfo::socket_reuse) {
            close($SSLinfo::socket) if (defined $SSLinfo::socket);
            $SSLinfo::socket = undef;
        }

        #1. open TCP connection; no way to continue if it fails
        $src = 'SSinfo::do_ssl_new()';
        ($ssl, $ctx, $socket, $method) = do_ssl_new($host, $port, $sslversions,
               $cipher, $SSLinfo::protos_alpn, $SSLinfo::protos_npn,
               $SSLinfo::socket);
        if (not defined $ssl) { $err = 'undef $ssl'; last; }
        if (not defined $ctx) { $err = 'undef $ctx'; last; }
        $_SSLinfo{'ctx'}      = $ctx;
        $_SSLinfo{'ssl'}      = $ssl;
        $_SSLinfo{'method'}   = $method;
        $SSLinfo::method      = $method;
        $SSLinfo::socket      = $socket;
        push(@{$_SSLinfo{'errors'}}, @{$_SSLtemp{'errors'}});
        _trace("do_ssl_open: $SSLinfo::method");

        # from here on mainly IO::Socket::SSL is used from within Net::SSLeay
        # using Net::SSLeay::trace is most likely same as IO::Socket::SSL::DEBUG
        #dbx# $Net::SSLeay::trace     = 2;
        #dbx# $IO::Socket::SSL::DEBUG = 1;
        #dbx# Net::SSLeay::print_errs();

        #5. SSL established, let's get information
        # TODO: starting from here implement error checks
        $src = 'Net::SSLeay::get_peer_certificate()';
        my $x509= Net::SSLeay::get_peer_certificate($ssl);
            # $x509 may be undef or 0; this may cause "Segmentation fault"s in
            # some Net::SSLeay::X509_* methods; hence we always use _ssleay_cert_get

        #5a. get internal data
        # Some values may be overwritten below (see %match_map below).
        $_SSLinfo{'x509'}       = $x509;
        $_SSLinfo{'_options'}  .= sprintf("0x%016x", Net::SSLeay::CTX_get_options($ctx)) if $ctx;
        $_SSLinfo{'SSLversion'} = $_SSLhex{Net::SSLeay::version($ssl)};
            # TODO: Net::SSLeay's documentation also has:
            #    get_version($ssl); get_cipher_version($ssl);
            # but they are not implemented (up to 1.49)
        $_SSLinfo{'session_protocol'}   = $_SSLinfo{'SSLversion'};
        $_SSLinfo{'session_starttime'}  = Net::SSLeay::SESSION_get_time($ssl);
        $_SSLinfo{'session_timeout'}    = Net::SSLeay::SESSION_get_timeout($ssl);

        #5b. store actually used ciphers for this connection
        my $i   = 0;
        my $c   = '';
        push(@{$_SSLinfo{'ciphers'}}, $c) while ($c = Net::SSLeay::get_cipher_list($ssl, $i++));
        $_SSLinfo{'selected'}   = Net::SSLeay::get_cipher($ssl);
            # same as above:      Net::SSLeay::CIPHER_get_name(Net::SSLeay::get_current_cipher($ssl));

        #5c. store certificate information
        $_SSLinfo{'certificate'}= Net::SSLeay::dump_peer_certificate($ssl);  # same as issuer + subject
        #$_SSLinfo{'master_key'} = Net::SSLeay::SESSION_get_master_key($ssl); # TODO: returns binary, hence see below
        $_SSLinfo{'PEM'}        = _ssleay_cert_get('PEM',     $x509);
            # 'PEM' set empty for example when $SSLinfo::no_cert is in use
            # this inhibits warnings inside perl (see  NO Certificate  below)
        $_SSLinfo{'subject'}    = _ssleay_cert_get('subject', $x509);
        $_SSLinfo{'issuer'}     = _ssleay_cert_get('issuer',  $x509);
        $_SSLinfo{'before'}     = _ssleay_cert_get('before',  $x509);
        $_SSLinfo{'after'}      = _ssleay_cert_get('after',   $x509);
        $_SSLinfo{'policies'}   = _ssleay_cert_get('policies',$x509);
        if (1.45 <= $Net::SSLeay::VERSION) {
            $_SSLinfo{'version'}= _ssleay_cert_get('version', $x509);
        } else {
            warn("$STR{WARN} 651: Net::SSLeay >= 1.45 required for getting version");
        }
        if (1.33 <= $Net::SSLeay::VERSION) {# condition stolen from IO::Socket::SSL,
            $_SSLinfo{'altname'}= _ssleay_cert_get('altname', $x509);
        } else {
            warn("$STR{WARN} 652: Net::SSLeay >= 1.33 required for getting subjectAltNames");
        }
        if (1.30 <= $Net::SSLeay::VERSION) {# condition stolen from IO::Socket::SSL
            $_SSLinfo{'cn'}     = _ssleay_cert_get('cn', $x509);
            $_SSLinfo{'cn'}     =~ s{\0$}{};# work around Bug in Net::SSLeay <1.33 (from IO::Socket::SSL)
        } else {
            warn("$STR{WARN} 653: Net::SSLeay >= 1.30 required for getting commonName");
        }
        if (1.45 <= $Net::SSLeay::VERSION) {
            $_SSLinfo{'fingerprint_md5'} = _ssleay_cert_get('md5',  $x509);
            $_SSLinfo{'fingerprint_sha1'}= _ssleay_cert_get('sha1', $x509);
            $_SSLinfo{'fingerprint_sha2'}= _ssleay_cert_get('sha2', $x509);
        } else {
            warn("$STR{WARN} 654: Net::SSLeay >= 1.45 required for getting fingerprint_md5");
        }
        if (1.46 <= $Net::SSLeay::VERSION) {# see man Net::SSLeay
            #$_SSLinfo{'pubkey_value'}   = Net::SSLeay::X509_get_pubkey($x509);
                # TODO: returns a structure, needs to be unpacked
            $_SSLinfo{'error_verify'}   = Net::SSLeay::X509_verify_cert_error_string(Net::SSLeay::get_verify_result($ssl));
            $_SSLinfo{'error_depth'}    = _ssleay_cert_get('error_depth', $x509);
            $_SSLinfo{'serial_hex'}     = _ssleay_cert_get('serial_hex',  $x509);
            $_SSLinfo{'cert_type'}      = sprintf("0x%x  <<experimental>>", _ssleay_cert_get('cert_type', $x509) || 0);
            $_SSLinfo{'subject_hash'}   = sprintf("%x", _ssleay_cert_get('subject_hash', $x509) || 0);
            $_SSLinfo{'issuer_hash'}    = sprintf("%x", _ssleay_cert_get('issuer_hash',  $x509) || 0);
                # previous two values are integers, need to be converted to
                # hex, we omit a leading 0x so they can be used elswhere
        } else {
            warn("$STR{WARN} 655: Net::SSLeay >= 1.46 required for getting some certificate checks");
        }
        $_SSLinfo{'commonName'} = $_SSLinfo{'cn'};
        $_SSLinfo{'authority'}  = $_SSLinfo{'issuer'};
        $_SSLinfo{'owner'}      = $_SSLinfo{'subject'};
            # used by IO::Socket::SSL, allow for compatibility and lazy user
            #   owner commonName cn subject issuer authority subjectAltNames
            #   alias: owner == subject, issuer == authority, commonName == cn

        # TODO: certificate chain depth, OCSP
        # see: http://search.cpan.org/~mikem/Net-SSLeay-1.68/lib/Net/SSLeay.pod#Certificate_verification_and_Online_Status_Revocation_Protocol_%28OCSP%29

        #5d. get OSCP related data
# TODO: related constants
#        TLSEXT_STATUSTYPE_ocsp V_OCSP_CERTSTATUS_GOOD V_OCSP_CERTSTATUS_REVOKED
#        V_OCSP_CERTSTATUS_UNKNOWN
# TODO: check if supported
#        if (not exists &Net::SSLeay::OCSP_cert2ids) { $cfg{'ssleay'}->{'can_ocsp'} = 0 }
#        # same as IO::Socket::SSL::can_ocsp() IO::Socket::SSL::can_ocsp_staple()
# TODO:
         # see:https://mojolicious.org/perldoc/Net/SSLeay (same as)
         #     https://metacpan.org/pod/release/MIKEM/Net-SSLeay-1.81/lib/Net/SSLeay.pod
         # # Extract OCSP_RESPONSE.
         # my $resp = eval { Net::SSLeay::d2i_OCSP_RESPONSE($content) };

         # # Check status of response.
         # my $status = Net::SSLeay::OCSP_response_status($resp);
         # if ($status != Net::SSLeay::OCSP_RESPONSE_STATUS_SUCCESSFUL())
         # die "OCSP response failed: " .  Net::SSLeay::OCSP_response_status_str($status);

         # # set TLS extension before doing SSL_connect
         # Net::SSLeay::set_tlsext_status_type($ssl, Net::SSLeay::TLSEXT_STATUSTYPE_ocsp());

        #5e. get data related to HTTP(S)
        if (0 < $SSLinfo::use_https) {
            _trace("do_ssl_open HTTPS {");
            #dbx# $host .= 'x'; # TODO: <== some servers behave strange if a wrong hostname is passed
            my $ua = "User-Agent: Mozilla/5.0 (quark rv:52.0) Gecko/20100101 Firefox/52.0";
            my $response = '';
            my $request  = "GET $SSLinfo::target_url HTTP/1.1\r\n";
               $request .= "Host:$host\r\nConnection:close\r\n";
               $request .= "Accept-Encoding:gzip,deflate\r\n";
               $request .= "User-Agent:$SSLinfo::user_agent\r\n\r\n";
               # Accept-Encoding to get response header Content-Encoding
# $t1 = time();
#           ($ctx = Net::SSLeay::CTX_v23_new()) or do {$src = 'Net::SSLeay::CTX_v23_new()'} and last;
            # FIXME: need to find proper method instead hardcoded CTX_v23_new(); see _ssleay_ctx_new
            #dbx# $Net::SSLeay::trace     = 2;
            $src = 'Net::SSLeay::write()';
            Net::SSLeay::write($ssl, $request) or {$err = $!} and last;
            $src = 'Net::SSLeay::ssl_read_all()';
            # use ::ssl_read_all() instead of ::read() to get HTTP body also
            $response = Net::SSLeay::ssl_read_all($ssl) || "<<GET failed>>";
            _trace("do_ssl_open: request $host:$port");
            if (1 == $trace) {
                _trace("do_ssl_open: request  #{<<use --trace=2 to print data>>#}");
                _trace("do_ssl_open: response #{\n$response #}") if ($response =~ m/<<GET failed/); # always
                _trace("do_ssl_open: response #{<<use --trace=2 to print data>>#}");
            } else {
                # matches $trace==0 too; that's ok as handled correctly in _trace()
                _trace2("do_ssl_open: request  #{\n$request");  _trace2("do_ssl_open request #}");
                _trace2("do_ssl_open: response #{\n$response"); _trace2("do_ssl_open response #}");
            }
            if ($response =~ /handshake_failed/) {  # may get: http2_handshake_failed
                $response = "<<HTTP handshake failed>>";
                # no last; # as it will break checks outside
            }
            if ($response =~ /bad client magic byte string/) {  # http2_handshake_failed
                # dirty hack with goto
                #$SSLinfo::protos_alpn = "";
                #goto TRY;
                $response =  "<<Received bad client magic byte string>>";
            }
# TODO: Net::SSLeay::read() fails sometimes, i.e. for fancyssl.hboeck.de
# 03/2015: even using ssl_write_all() and ssl_read_all() does not help
# TODO: reason unknown, happens probably if server requires SNI
# $t2 = time(); set error = "<<timeout: Net::SSLeay::read()>>";
            $_SSLinfo{'https_body'}     =  $response;
            $_SSLinfo{'https_body'}     =~ s/.*?\r\n\r\n(.*)/$1/ms;
            $_SSLinfo{'https_location'} =  _header_get('Location', $response);
                # if a new Location is send for HTTPS, we should not follow
            $_SSLinfo{'https_status'}   =  $response;
            $_SSLinfo{'https_status'}   =~ s/[\r\n].*$//ms; # get very first line
            $_SSLinfo{'https_server'}   =  _header_get('Server',   $response);
            $_SSLinfo{'https_refresh'}  =  _header_get('Refresh',  $response);
            $_SSLinfo{'https_pins'}     =  _header_get('Public-Key-Pins',    $response);
            $_SSLinfo{'https_protocols'}=  _header_get('Alternate-Protocol', $response);
            $_SSLinfo{'https_svc'}      =  _header_get('Alt-Svc',  $response);
            $_SSLinfo{'https_svc'}      .= _header_get('X-Firefox-Spdy',     $response);
            $_SSLinfo{'https_svc'}      .= _header_get('Spdy',     $response);
            $_SSLinfo{'https_sts'}      =  _header_get('Strict-Transport-Security', $response);
            $_SSLinfo{'https_content_enc'}  = _header_get('Content-Encoding', $response);
            $_SSLinfo{'https_transfer_enc'} = _header_get('Transfer-Encoding',$response);
            $_SSLinfo{'hsts_httpequiv'} =  $_SSLinfo{'https_body'};
            $_SSLinfo{'hsts_httpequiv'} =~ s/.*?(http-equiv=["']?Strict-Transport-Security[^>]*).*/$1/ims;
            $_SSLinfo{'hsts_httpequiv'} = '' if ($_SSLinfo{'hsts_httpequiv'} eq $_SSLinfo{'https_body'});
            $_SSLinfo{'hsts_maxage'}    =  $_SSLinfo{'https_sts'};
            $_SSLinfo{'hsts_maxage'}    =~ s/.*?max-age=([^;" ]*).*/$1/i;
            $_SSLinfo{'hsts_subdom'}    = 'includeSubDomains' if ($_SSLinfo{'https_sts'} =~ m/includeSubDomains/i);
            $_SSLinfo{'hsts_preload'}   = 'preload' if ($_SSLinfo{'https_sts'} =~ m/preload/i);
# TODO:     $_SSLinfo{'hsts_alerts'}    =~ s/.*?((?:alert|error|warning)[^\r\n]*).*/$1/i;
# TODO: HTTP header:
#    X-Firefox-Spdy: 3.1
#    X-Firefox-Spdy: h2             (seen at policy.mta-sts.google.com 9/2016)
#           X-Firefox-Spdy  most likely returned only for proper User-Agent
            _trace("do_ssl_open HTTPS }");
        }
        if (0 < $SSLinfo::use_http) {
            _trace("do_ssl_open HTTP {");   # HTTP uses its own connection ...
            my %headers;
            my $response = '';
            my $request  = '';
            _trace("do_ssl_open ::use_http: $SSLinfo::use_http");
            # TODO: add 'Authorization:'=>'Basic ZGVtbzpkZW1v',
            # NOTE: Net::SSLeay always sets  Accept:*/*
            $src = 'Net::SSLeay::get_http()';
            ($response, $_SSLinfo{'http_status'}, %headers) =
                Net::SSLeay::get_http($host, 80, $SSLinfo::target_url,
                  Net::SSLeay::make_headers(
                        'Host'       => $host,
                        'User-Agent' => $SSLinfo::user_agent,
                        'Connection' => 'close',
                  )
                );
            # NOTE that get_http() returns all keys in %headers capitalised
            my $headers = "";   # for trace only
            foreach my $h (sort(keys %headers)) { $headers .= "$h: $headers{$h}\n"; }
            _trace("do_ssl_open: request $host:$port");
            if (1 == $trace) {
                _trace("do_ssl_open: request  #{<<use --trace=2 to print data>>#}");
                _trace("do_ssl_open: response #{\n$response #}") if ($response =~ m/<<GET failed/); # always
                _trace("do_ssl_open: response #{<<use --trace=2 to print data>>#}");
            } else {
                # matches $trace==0 too; that's ok as handled correctly in _trace()
                _trace2("do_ssl_open: request  #{\n$request");  _trace2("do_ssl_open request #}");
                _trace2("do_ssl_open: response #{\n$response"); _trace2("do_ssl_open response #}");
            }
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
                # Use of uninitialised value $headers in split at blib/lib/Net/SSLeay.pm (autosplit into blib/lib/auto/Net/SSLeay/do_httpx2.al) line 1291.

# $t3 = time(); set error = "<<timeout: Net::SSLeay::get_http()>>";
            if ($_SSLinfo{'http_status'} =~ m:^HTTP/... ([1234][0-9][0-9]|500) :) {
                # TODO: not tested if following grep() catches multiple occurrences
                $_SSLinfo{'http_location'}  =  $headers{(grep{/^Location$/i} keys %headers)[0] || ''};
                $_SSLinfo{'http_refresh'}   =  $headers{(grep{/^Refresh$/i}  keys %headers)[0] || ''};
                $_SSLinfo{'http_sts'}       =  $headers{(grep{/^Strict-Transport-Security$/i} keys %headers)[0] || ''};
                $_SSLinfo{'http_svc'}       =  $headers{(grep{/^Alt-Svc$/i}  keys %headers)[0] || ''} || '';
                $_SSLinfo{'http_svc'}      .=  $headers{(grep{/^X-Firefox-Spdy$/i}    keys %headers)[0] || ''} || '';
                $_SSLinfo{'http_protocols'} =  $headers{(grep{/^Alternate-Protocol/i} keys %headers)[0] || ''};
                # TODO: http_protocols somtimes fails, reason unknown (03/2015)
            } else { # any status code > 500
                #no print "$STR{WARN} http:// connection refused; consider using --no-http"; # no print here!
                push(@{$_SSLinfo{'errors'}}, "do_ssl_open WARNING $src: " . $_SSLinfo{'http_status'});
                if ($_SSLinfo{'http_status'} =~ m:^HTTP/... (50[12345]) :) {
                    # If we get status 50x, there is most likely a (local)
                    # proxy which is not able to connect to the target.
                    # This could either be 'cause the target refuses the
                    # connection (status 503 and 504) or 'cause the proxy
                    # itself has a problem.
                    # HTTP headers and response may contain more hints.
                    push(@{$_SSLinfo{'errors'}}, "do_ssl_open WARNING $src: check HTTP gateway");
                #} else { Net::SSLeay::get_http() most likely returns status 900
                }
                $response = ''; # avoid uninitialised value later
            }
            _trace("do_ssl_open HTTP }");
        }

        if (0 == $SSLinfo::use_openssl) {
            # calling external openssl is a performance penulty
            # it would be better to manually parse $_SSLinfo{'text'} but that
            # needs to be adapted to changes of openssl's output then
            _trace2("do_ssl_open without openssl");
            goto finished;
        }

        #5f. get data from openssl, if required
        # NOTE: all following are only available when openssl is used
        #       those alredy set before will be overwritten

        # NO Certificate {
        # We get following data using openssl executable.
        # No need  to check  $SSLinfo::no_cert  as openssl is clever enough to
        # return following strings if the cert is missing:
        #         unable to load certificate
        # If we use  'if (defined $_SSLinfo{'PEM'}) '  instead of an empty
        # $_SSLinfo{'PEM'}  (see initial setting above), then all values would
        # contain an empty string instead of the the openssl warning:
        #         unable to load certificate
# 14apr21 my $cert = Net::SSLeay::get_peer_certificate($ssl);
# 14apr21 my $id = eval { Net::SSLeay::OCSP_cert2ids($ssl,$cert) };
# 14apr21 my $id = Net::SSLeay::OCSP_cert2ids($ssl,$cert) ;
# 14apr21 print "#### ID $id ";
# 14apr21 print "#### PEM=$_SSLinfo{'PEM'} ";
        my $fingerprint                 = _openssl_x509($_SSLinfo{'PEM'}, '-fingerprint');
        chomp $fingerprint;
        $_SSLinfo{'fingerprint_text'}   = $fingerprint;
        $_SSLinfo{'fingerprint'}        = $fingerprint; #alias
       ($_SSLinfo{'fingerprint_type'},  $_SSLinfo{'fingerprint_hash'}) = split(/=/, $fingerprint);
        $_SSLinfo{'fingerprint_type'}   = $SSLinfo::no_cert_txt if (not defined $_SSLinfo{'fingerprint_type'});
        $_SSLinfo{'fingerprint_hash'}   = $SSLinfo::no_cert_txt if (not defined $_SSLinfo{'fingerprint_hash'});
        $_SSLinfo{'fingerprint_type'}   =~ s/\s+.*$//;
        $_SSLinfo{'fingerprint_type'}   =~ s/(^[^\s]*).*/$1/ if (m/^[^\s]*/);  # TODO: ugly check
        $_SSLinfo{'subject_hash'}       = _openssl_x509($_SSLinfo{'PEM'}, '-subject_hash');
        $_SSLinfo{'issuer_hash'}        = _openssl_x509($_SSLinfo{'PEM'}, '-issuer_hash');
        $_SSLinfo{'version'}            = _openssl_x509($_SSLinfo{'PEM'}, 'version');
        $_SSLinfo{'text'}               = _openssl_x509($_SSLinfo{'PEM'}, '-text');
        $_SSLinfo{'modulus'}            = _openssl_x509($_SSLinfo{'PEM'}, '-modulus');
       #$_SSLinfo{'serial'}             = _openssl_x509($_SSLinfo{'PEM'}, '-serial'); # done below
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
        $_SSLinfo{'signame'}            =~ s/^[^:]*: //i;
        $_SSLinfo{'modulus_len'}        =  4 * length($_SSLinfo{'modulus'});
            # Note: modulus is hex value where 2 characters are 8 bit
        if ($_SSLinfo{'sigkey_value'} ne $SSLinfo::no_cert_txt) {
            $_SSLinfo{'sigkey_len'}     =  $_SSLinfo{'sigkey_value'};
            $_SSLinfo{'sigkey_len'}     =~ s/[\s\n]//g;
            $_SSLinfo{'sigkey_len'}     =~ s/[:]//g;
            $_SSLinfo{'sigkey_len'}     =  4 * length($_SSLinfo{'sigkey_len'});
        }
        chomp $_SSLinfo{'fingerprint_hash'};
        chomp $_SSLinfo{'modulus'};
        chomp $_SSLinfo{'pubkey'};
        chomp $_SSLinfo{'signame'};
        # NO Certificate }

        $_SSLinfo{'s_client'}       = do_openssl('s_client', $host, $port, '');
            # this should be the first call to openssl herein
        my  $eee = $_SSLinfo{'s_client'};
        if ($eee =~ m/.*(?:\*\*ERROR)/) {   # pass errors to caller
            $eee =~ s/.*(\*\*ERROR[^\n]*).*/$1/s;
            push(@{$_SSLinfo{'errors'}}, "do_ssl_open WARNING openssl: $eee");
        } else {
            $eee =  '';
        }
        # FIXME: lazy and incomplete approach to pass errors

            # from s_client: (if openssl supports -nextprotoneg)
            #    Protocols advertised by server: spdy/4a4, spdy/3.1, spdy/3, http/1.1

            # from s_client: (openssl > 1.0.1)
            #    Peer signing digest: SHA512
            #    Server Temp Key: DH, 2048 bits
            #    Server Temp Key: ECDH, P-256, 256 bits

            # from s_client (openssl 1.1.x and newer):
            #  Server public key is 2048 bit

            # from s_client:
            #  SSL-Session:
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
            #    0030 - e7 fe 10 cd d4 82 e9 8f-d8 ee 91 16 02 42 7b 93   .............B}.
            #    0040 - fc 93 82 c4 d3 fd 0a f3-c6 3d 77 ab 1d 25 4f 5a   .........=w..%OZ
            #    0050 - fc 44 9a 21 3e cb 18 e9-a4 44 1b 30 7c 98 4d 04   .D.!>....D.0|.M.
            #    0060 - bb 12 3e 67 c8 9a ad 99-b4 50 32 81 1e 54 70 2d   ..>g.....P2..Tp-
            #    0070 - 06 08 82 30 9a 94 82 6f-e2 fa c7 e8 5a 19 af dc   ...0...o....Z...
            #    0080 - 70 45 71 f9 d1 e6 a8 d7-3c c2 c6 b8 e1 d5 4f dd   pEq.....<.....O.
            #    0090 - 52 12 f3 90 0c 51 c5 81-6c 9e 69 b6 bd 0c e6 e6   R....Q..l.i.....
            #    00a0 - 4c d4 72 33                                       L.r3
            #
            #    Start Time: 1435254245
            #    Extended master secret: yes
        my %match_map = (
            # %_SSLinfo key       string to match in s_client output
            #-------------------+-----------------------------------
            'session_id'       => "Session-ID:",
            'session_id_ctx'   => "Session-ID-ctx:",
            'master_key'       => "Master-Key:",
            'master_secret'    => "Extended master secret:",
            'krb5'             => "Krb5 Principal:",
            'psk_identity'     => "PSK identity:",
            'psk_hint'         => "PSK identity hint:",
            'srp'              => "SRP username:",
            'compression'      => "Compression:",
            'expansion'        => "Expansion:",
            'alpn'             => "ALPN protocol:",
            'no_alpn'          => "No ALPN negotiated", # has no value, see below
            'next_protocol'    => "Next protocol:",
            'next_protocols'   => "Protocols advertised by server:",
            'session_protocol' => "Protocol\\s+:",      # \s must be meta
            'session_timeout'  => "Timeout\\s+:",       # \s must be meta
            'session_lifetime' => "TLS session ticket lifetime hint:",
            'session_starttime'=> "Start Time:",
            #'session_ticket'   => "TLS session ticket:",
                # this is a multiline value, must be handled special, see below
            #'renegotiation'    => "Renegotiation",
                # Renegotiation comes with different values, see below
            'dh_parameter'     => "Server Temp Key:",
            #'ocsp_response_data' => "OCSP response:",
                # this is a multiline value, must be handled special, see below
            #'public_key_len'   => "Server public key",
                # this line has no  :  hence must be handled special, see below
        );
        my $d    = '';
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
            if (8 < length($d)) {   # check if we are on 32-bit system
                # on 32-bit systems perl may handle large numbers correctly
                # if compiled properly, can be checked with $Config{ivsize}
                # so we need the value which requires loading the module
                #
                # cannot use eval with block form here, needs to be quoted
                ## no critic qw(BuiltinFunctions::ProhibitStringyEval)
                if (eval('use Config; $b = $Config{ivsize};')) {
                    # use $Config{ivsize}
                } else {
                    $err = "use Config";
                    push(@{$_SSLinfo{'errors'}}, "do_ssl_open Cfg failed calling $src: $err");
                    $_SSLinfo{'serial_int'} = "<<$err failed>>";
                }
                ## use critic
            }
            if (($b < length($d))   # larger than integer of this architecture
              ||(16 < length($d)))  # to large at all
            {  # ugly check if we need bigint
                if (eval {require Math::BigInt;}) {
                    $_SSLinfo{'serial_int'} = Math::BigInt->from_hex($d);
                } else {
                    $err = "Math::BigInt->from_hex($d)";
                    push(@{$_SSLinfo{'errors'}}, "do_ssl_open Big failed calling $src: $err");
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
#print "####\n $data \n####";
        foreach my $key (sort keys %match_map) {
            my $regex = $match_map{$key};
            $d = $data;
            $d =~ s/.*?$regex[ \t]*([^\n\r]*)\n.*/$1/si;
#print("do_ssl_open: match key:   $key\t= $regex");
            _trace2("do_ssl_open: match key:   $key\t= $regex");
            if ($data =~ m/$regex/) {
                $_SSLinfo{$key} = $d;
                $_SSLinfo{$key} = $regex if ($key eq 'no_alpn');
                    # no_alpn: single line, has no value: No ALPN negotiated
#print("do_ssl_open: match value: $key\t= $_SSLinfo{$key}");
                _trace2("do_ssl_open: match value: $key\t= $_SSLinfo{$key}");
            }
        }
            # from s_client:
            # ....
            #     Start Time: 1544899903
            #     Timeout   : 300 (sec)
            #     Verify return code: 0 (ok)
            # ---
        my $key = 'session_starttime';
        $_SSLinfo{'session_startdate'} = scalar localtime($_SSLinfo{$key});
            # add human readable time

            # from s_client:
            #  OCSP response: no response sent
            # or:
            #  OCSP response:
            #  ======================================
            #  OCSP Response Data:
            #      OCSP Response Status: successful (0x0)
            #      Response Type: Basic OCSP Response
            #      Version: 1 (0x0)
            #      Responder Id: 1C6C1E3B17EDF8DAB15CEBCDBC2D315868862497
            #      Produced At: Jul  7 16:34:44 2018 GMT
            #      Responses:
            #      Certificate ID:
            #        Hash Algorithm: sha1
            #        Issuer Name Hash: 881A4A74FEFF4652F354BB510FD3A4EEEFE0A1C8
            #        Issuer Key Hash: 919E3B446C3D579C42772A34D74FD1CC4A972CDA
            #        Serial Number: 2000036E72ADED906765595FAE000000036E72
            #      Cert Status: good
            #      This Update: Jul  7 16:34:44 2018 GMT
            #      Next Update: Jul 11 16:34:44 2018 GMT
            #          Response Single Extensions:
            #              OCSP Archive Cutoff:
            #                  Jul  7 16:34:44 2017 GMT
            #
            #      Signature Algorithm: sha256WithRSAEncryption
            #      ....
            # (following Signature and Certificate date not shown and skipped)
            # TODO: extract single values 'ocsp_response_*' from above output,
            #       can be done with %match_map
        $d = $data;
        $d =~ s/.*?OCSP response:\s*([a-zA-Z0-9,. -]+)[\n\r].*/$1/si;
        if ($d =~ m/^\s*$/) {   # probably complete OCSP Response Data:
            $d = $data;
            $d =~ s/.*?OCSP response:\s*[\n\r]+(.*?)[\n\r][\n\r].*/$1/si;
            $d =~ s/^[\n\r]*//;
            if ($d =~ m/OCSP Response Status:\s*([^\n\r]+)[\n\r]/i) {
                $_SSLinfo{'ocsp_response_status'}  = $1;
            }
            if ($d =~ m/Cert Status:\s*([^\n\r]+)[\n\r]/i) {
                $_SSLinfo{'ocsp_cert_status'}  = $1;
            }
            if ($d =~ m/This Update:\s*([^\n\r]+)[\n\r]/i) {
                $_SSLinfo{'ocsp_this_update'}  = $1;
            }
            if ($d =~ m/Next Update:\s*([^\n\r]+)[\n\r]/i) {
                $_SSLinfo{'ocsp_next_update'}  = $1;
            }
            $_SSLinfo{'ocsp_response'}  = 
                  "Response Status: " . $_SSLinfo{'ocsp_response_status'}
                . "; Cert Status: "   . $_SSLinfo{'ocsp_cert_status'}
                . "; This Update: "   . $_SSLinfo{'ocsp_this_update'}
                . "; Next Update: "   . $_SSLinfo{'ocsp_next_update'};
            # TODO: no extract more important values
        } else {                # probably only  OCSP response:
            $_SSLinfo{'ocsp_response'}  = $d;
        }
        $_SSLinfo{'ocsp_response_data'} = $d; # complete string, both cases above

        $d = $data; $d =~ s/.*?Server public key is *([^\n\r]*)[\n\r].*/$1/si;
        $_SSLinfo{'public_key_len'} = $d if ($data =~ m/Server public key is /);

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
            _trace2("do_ssl_open: slow target server; resumption not detected; try to increase \$SSLinfo::timeout_sec");
        } else {
            $cnt =()= $d =~ m/New,/g;
            _trace2("do_ssl_open: checking resumption: found $cnt `New' ");
            if ($cnt > 2) { # too much "New" reconnects, assume no resumption
                $cnt =()= $d =~ m/Reused,/g;
                _trace2("do_ssl_open: checking resumption: found $cnt `Reused' ");
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
            #
            # s_client returns at end:
            #       Verify return code: 0 (ok)
            # or just one of following, even if more than one applies:
            #       Verify return code: 10 (certificate has expired)
            #       Verify return code: 19 (self signed certificate in certificate chain)
            #       Verify return code: 20 (unable to get local issuer certificate)
            #       Verify return code: 21 (unable to verify the first certificate)
            #
            # following matches any line, but return first only:
            # TODO: need more extensive tests with different servers and openssl versions
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

        #dbx# print "TLS: $data\n";
            # from s_client -tlsextdebug -nextprotoneg
            # TLS server extension "server name" (id=0), len=0
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
            _trace("do_ssl_open: -tlsextdebug  $d") if ($d =~ m/session ticket/);
            _trace("do_ssl_open: -tlsextdebug  $d") if ($d =~ m/renegotiation info/);
        }
        $_SSLinfo{'tlsextensions'} =~ s/\([^)]*\),?\s+//g;  # remove additional information
        $_SSLinfo{'tlsextensions'} =~ s/\s+len=\d+//g;      # ...

        _trace1("do_ssl_open <<use --trace=2 to print data collected from openssl>>");
        _trace2(SSLinfo::datadump("do_ssl_open"));
        goto finished;
    } # TRY

    #6. error handling
    push(@{$_SSLinfo{'errors'}}, "do_ssl_open TRY failed calling $src: $err");
    if (1 < $trace) {
        Net::SSLeay::print_errs($SSLINFO{'ERROR'});
        printf("%s%s\n", $SSLINFO{'ERROR'}, $_) foreach @{$_SSLtemp{'errors'}};
    }
    _trace("do_ssl_open ()failed }");
    return;

    finished:
    _SSLinfo_print();   # --verbose only
    FIN:
    _trace("do_ssl_open() done }");
    return wantarray ? ($_SSLinfo{'ssl'}, $_SSLinfo{'ctx'}) : $_SSLinfo{'ssl'};
} # do_ssl_open

=pod

=head3 do_ssl_close( )

Close L<Net::SSLeay> connection and free allocated objects.
=cut

sub do_ssl_close($$)  {
    #? close TCP connection for SSL
    my ($host, $port) = @_;
    _trace("do_ssl_close($host,$port)");
    do_ssl_free($_SSLinfo{'ctx'}, $_SSLinfo{'ssl'}, $SSLinfo::socket);
    _SSLinfo_reset();
    $SSLinfo::socket = undef;
    $SSLinfo::method = '';
    return;
} # do_ssl_close

=pod

=head3 do_openssl($command,$host,$port,$data)

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
Returns '<<undefined>>' if PEM missing.
=cut

sub do_openssl($$$$)  {
    #? call external openssl executable to retrive more data
    #  should not be used to check ciphers because of timeout of 1 second for
    #  each call due to compatibility with openssl 3.x
    my $mode = shift;   # must be openssl command
    my $host = shift;
    my $port = shift || '';  # may be empty for some calls
    my $pipe = shift || '';  # piped data is optional
    my $data = '';
    my $capath = $SSLinfo::ca_path || '';
    my $cafile = $SSLinfo::ca_file || '';
    _trace("do_openssl($mode,$host,$port...).");
    _setcmd();
#printf("#dbx# %s -> %s -> %s : %s : %s #\n", (caller(5))[3], (caller(3))[3], (caller(0))[3], $mode, $pipe);
    _vprint("do_openssl $mode");
    if ('' eq $_openssl) {
        _trace("do_openssl($mode): WARNING: no openssl");
        return $SSLINFO{'OPENSSL'};
    }
    if ($mode =~ m/^-?s_client$/) {
        if ($SSLinfo::file_sclient !~ m/^\s*$/) {
            if (open(my $fh, '<:encoding(UTF-8)', $SSLinfo::file_sclient)) {
                undef $/;   # get anything
                $data = <$fh>;
                close($fh);
                return $data;
            }
            _trace("do_openssl($mode): WARNING: cannot open $SSLinfo::file_sclient");
            return $SSLINFO{'OPENSSL'};
        }
        if (0 == $SSLinfo::use_sclient) {
            _trace2("do_openssl($mode): WARNING: no openssl s_client");
            return $SSLINFO{'OPENSSL'};
        }
# TODO: Optionen hier entfernen, muss im Caller gemacht werden
        # pass -alpn option to validate 'protocols' support later
        # pass -nextprotoneg option to validate 'protocols' support later
        # pass -reconnect option to validate 'resumption' support later
        # pass -tlsextdebug option to validate 'heartbeat' support later
        # pass -status option to get 'ocsp_response_data' support later
        # NOTE that openssl 1.x or later is required for -nextprotoneg
        # NOTE that openssl 1.0.2 or later is required for -alpn
        $mode  = 's_client' . $SSLinfo::sclient_opt;
# FIXME: { following fixes general verify, but not self signed
        $mode .= ' -CApath ' . $capath if ('' ne $capath);
        $mode .= ' -CAfile ' . $cafile if ('' ne $cafile);
# }
        $mode .= ' -reconnect'   if (1 == $SSLinfo::use_reconnect);
        $mode .= ' -tlsextdebug' if (1 == $SSLinfo::use_extdebug);
        $mode .= ' -status';
    }
    if (($mode =~ m/^-?s_client$/)
    ||  ($mode =~ m/^-?s_client.*?-cipher/)) {
        $mode .= ' -alpn '         . $SSLinfo::protos_alpn if (1 == $SSLinfo::use_alpn);
        if ($mode !~ m/-tls1_3/) { # TODO: check chould be for openssl 3.x only
            $mode .= ' -nextprotoneg ' . $SSLinfo::protos_npn  if (1 == $SSLinfo::use_npn);
            # openssl 3.0.11 does not like -nextprotoneg with -tls1_3
        }
    }
    if ($mode =~ m/^-?s_client/) {
        $mode .= ' -connect'     if  ($mode !~ m/-connect/);
    }
    $host = $port = '' if ($mode =~ m/^-?(ciphers)/);   # TODO: may be scary
    _trace("do_openssl($mode): echo '' | $_timeout $_openssl $mode $host:$port 2>&1"); 
    _vprint2("$_timeout $_openssl $mode $host:$port");
        # TODO: both, _trace and _vprint, may produce useless trailing : 
    if ($^O !~ m/MSWin32/) {
        $host .= ':' if ($port ne '');
        $pipe  = 'HEAD / HTTP/1.1' if ($pipe =~ m/^$/);
        $pipe .= "\r\nUser-Agent:$SSLinfo::user_agent\r\n\r";
            # sending an empty string or simply one without \r results in
            # a line in access.log like: "\n" 400 750 "-" "-"
            # to avoid this, \r is appended to the string always
        #dbx# print "echo $pipe | $_timeout $_openssl $mode $host$port 2>&1";
        $data  = qx((echo "$pipe"; sleep 1 ) | $_timeout $_openssl $mode $host$port 2>&1); ## no critic qw(InputOutput::ProhibitBacktickOperators)
            # system() or qx() should be safe because $_openssl and $timeout
            # are already checked in _setcommand()
            # 31aug24: openssl 3.x behaves different, if STDIN is closed too
            #          early some output is missing, hence the "sleep 1
        if ($data =~ m/(\nusage:|unknown option)/s) {
            #$data =~ s/((?:usage:|unknown option)[^\r\n]*).*/$1/g;
            my $u1 = $data; $u1 =~ s/.*?(unknown option[^\r\n]*).*/$1/s;
            my $u2 = $data; $u2 =~ s/.*?\n(usage:[^\r\n]*).*/$1/s;
            $data = "**ERROR: $u1\n**ERROR: $u2\n"; # pass basic error string to caller
            _trace("do_openssl($mode): WARNING: openssl does not support -nextprotoneg option");
            push(@{$_SSLinfo{'errors'}}, "do_openssl($mode) failed: $data");
            # try to do it again with mostly safe options
            $mode =  's_client';
            $mode .= ' -CApath ' . $capath if ('' ne $capath);
            $mode .= ' -CAfile ' . $cafile if ('' ne $cafile);
            $mode .= ' -reconnect'   if (1 == $SSLinfo::use_reconnect);
            $mode .= ' -connect';
            $data .= qx((echo "$pipe"; sleep 1 ) | $_timeout $_openssl $mode $host$port 2>&1); ## no critic qw(InputOutput::ProhibitBacktickOperators)
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
            $data =  '';
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

=head3 set_cipher_list($ssl,$cipherlist)

Set cipher list for connection. List is colon-separated list of ciphers.

Returns empty string on success, errors otherwise.
=cut

sub set_cipher_list {
    my $ssl    = shift;
    my $cipher = shift;
    Net::SSLeay::set_cipher_list($ssl, $cipher) or return $SSLINFO{'ME'} . '::set_cipher_list(' . $cipher . ')';
    $_SSLinfo{'cipherlist'} = $cipher;
    return '';
}

=pod

=head3 errors( )

Get list of errors, intenal ones but most likely from I<$Net::SSLeay::*> calls.

=head3 s_client( )

Dump data retrived from "openssl s_client ..." call. For debugging only.

=head3 options( )

Return hex value bitmask of (openssl) options used to establish connection.
Useful for debugging and trouble shooting.

=head3 PEM( ), pem( )

Get certificate in PEM format.

=head3 text( )

Get certificate in human readable format.

=head3 before( )

Get date before certificate is valid.

=head3 after( )

Get date after certificate is valid.

=head3 dates( )

Get dates when certificate is valid.

=head3 issuer( )

Get issuer of certificate.

=head3 subject( )

Get subject of certificate.

=head3 selected( )

Get cipher selected by server for current session. Returns ciphers string.

=head3 cipher_list($pattern)

Get cipher list offered by local SSL implementation (i.g. Net::SSLeay).
Returns space-separated list of ciphers.
Returns array if used in array context, a single string otherwise.

Requires successful connection to target.

=head3 cipher_openssl($pattern)

Get cipher list offered by local openssl implementation. Returns colon-separated list of ciphers.

Does not require connection to any target.

=head3 ciphers($pattern)

Returns List of ciphers provided for current connection to target.
Calls cipher_list() or cipher_openssl() depending on SSLinfo::use_openssl.

=cut

sub cipher_list     {
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

sub cipher_openssl  {
    my $pattern = shift || $_SSLinfo{'cipherlist'}; # use default if unset
    my $list;
    _trace("cipher_openssl($pattern)");
    _setcmd();
    _trace2("cipher_openssl: openssl ciphers $pattern");
    $list = do_openssl("ciphers $pattern", '', '', '');
    chomp  $list;
    return (wantarray) ? split(/[:\s]+/, $list) : $list;
} # cipher_openssl

## no critic qw(Subroutines::RequireArgUnpacking)
# "critic Subroutines::RequireArgUnpacking" disabled from hereon for a couple
# of subs because using explicit variable declarations in each sub would make
# (human) reading more difficult; it is also ensured that the called function
# _SSLinfo_get()  does not modify the parameters.

sub cipher_local    {
    warn("$STR{WARN} 451: function obsolete, please use cipher_openssl()");
    return cipher_openssl(@_);
} # cipher_local

sub ciphers         {
    return cipher_list(   @_) if ($SSLinfo::use_openssl == 0);
    return cipher_openssl(@_);
} # ciphers

=pod

All following functions have  $host and $port  parameter and return
information according the the connection, certificate for this connection.

=head3 cn( ), commonname( )

Get common name (CN) from certificate.

=head3 altname( )

Get alternate name (subjectAltNames) from certificate.

=head3 authority( )

Get authority (issuer) from certificate.

=head3 owner( )

Get owner (subject) from certificate.

=head3 certificate( )

Get certificate (subject, issuer) from certificate.

=head3 SSLversion( )

Get SSL protocol version used by connection.

=head3 version( )

Get version from certificate.
=cut

# TODO: not yet implemented
#=head3 keysize( )
#
#Get certificate private key size.
#
#=head3 keyusage( )
#
#Get certificate X509v3 Extended Key Usage (Version 3 and TLS only?)

=pod

=head3 ssleay_methods( )

Return list of available methods:  Net::SSLeay::*_method and
Net::SSLeay::CTX_*_new . Most important (newest) method first.

=head3 test_ssleay( )

Test availability and print information about Net::SSLeay:
Example: C<perl -I lib -MSSLinfo -le 'print SSLinfo::test_ssleay();'>

=head3 datadump( )

Print all available (by SSLinfo) data.

Due to huge amount of data, the value for s_client is usually omitted.
Please set I<$SSLinfo::use_sclient gt 1> to print this data also.

=head3 (details)

All following require that I<$SSLinfo::use_openssl=1;> being set.

=head3 compression( )

Get target's compression support.

=head3 exapansion( )

Get target's exapansion support.

=head3 next_protocols( )

Get (NPN) protocols advertised by server,

=head3 alpn( )

Get target's selected protocol (ALPN).

=head3 no_alpn( )

Get target's not negotiated message (ALPN).

=head3 next_protocol( )

Get target's next protocol message (ALPN).

=head3 krb5

Get target's Krb5 Principal.

=head3 psk_identity

Get target's PSK identity.

=head3 psk_hint

Get target's PSK identity hint.

=head3 srp

Get target's SRP username.

=head3 master_key

Get target's Master-Key.

=head3 master_secret

Get target's support for Extended master secret.

=head3 extended_master_secret

Same as master_secret .

=head3 public_key_len

Get target's Server public key length.

=head3 session_id

Get target's TLS Session-ID.

=head3 session_id_ctx

Get target's TLS Session-ID-ctx.

=head3 session_protocol

Get target's announced SSL protocols.

=head3 session_startdate

Get target's TLS Start Time (human readable format))

=head3 session_starttime

Get target's TLS Start Time (seconds since EPOCH)

=head3 session_ticket

Get target's TLS session ticket.

=head3 session_ticket_hint, session_lifetime

Get target's TLS session ticket lifetime hint.

=head3 session_timeout

Get target's SSL session timeout.

=head3 dh_parameter( )

Get targets DH parameter.

=head3 fingerprint_hash( )

Get certificate fingerprint hash value.

=head3 fingerprint_md5( )

Get  MD5 fingerprint if available (Net::SSLeay >= 1.49)

=head3 fingerprint_sha1( )

Get SHA1 fingerprint if available (Net::SSLeay >= 1.49)

=head3 fingerprint_sha2( )

Get SHA2 fingerprint if available (Net::SSLeay >= 1.49)

=head3 fingerprint_type( )

Get certificate fingerprint hash algorithm.

=head3 fingerprint_text( )

Get certificate fingerprint, which is the hash algorthm followed by the hash
value. This is usually the same as I<fingerprint_type()=fingerprint_hash()>.

=head3 fingerprint( )

Alias for I<fingerprint_text()>.

=head3 email( )

Get certificate email address(es).

=head3 serial_hex( )

Get certificate serial number as hex value.

=head3 serial_int( )

Get certificate serial number as integer value.

=head3 serial( )

Get certificate serial number as integer and hex value.

=head3 modulus( )

Get certificate modulus of the public key.

=head3 modulus_exponent( )

Get certificate modulus' exponent of the public key.

=head3 modulus_len( )

Get certificate modulus (bit) length of the public key.

=head3 ocsp_response( )

Get OCSP Response (compact list with values from ocsp_response_data()).

=head3 ocsp_response_data( )

Get complete OCSP Response Data.

=head3 ocsp_response_status( )

Get OCSP Response Status value.

=head3 ocsp_cert_status( )

Get OCSP Response Cert Status value.

=head3 ocsp_next_update( )

Get OCSP Response Next Update date.

=head3 ocsp_this_update( )

Get OCSP Response This Update date.

=head3 pubkey( )

Get certificate's public key.

=head3 pubkey_algorithm( )

Get certificate's public key algorithm.

=head3 pubkey_value( )

Get certificate's public key value.
Same as I<modulus()>  but may be different format.

=head3 renegotiation( )

Get certificate's renegotiation support.

=head3 resumption( )

Get certificate's resumption support.
Some target servers respond with  `New' and `Reused'  connections in
unexpected sequence. If `Reused' is found and less than 3 `New' then
resumption is assumed.

If resumption is not detected, increasing the timeout with i.e.
I<$SSLinfo::timeout_sec = 5>  may return different results.

=head3 sigkey_len( )

Get certificate signature key (bit).

=head3 sigkey_value( )

Get certificate signature value (hexdump).

=head3 subject_hash( ), issuer_hash( )

Get certificate subject/issuer hash value (in hex).

=head3 verify( )

Get result of certificate chain verification.

=head3 error_verify( )

Get error string of certificate chain verification, if any.

=head3 error_depth( )

Get depth where certificate chain verification failed.

=head3 chain( )

Get certificate's CA chain.

=head3 chain_verify( )

Get certificate's CA chain verification trace (for debugging only).

=head3 selfsigned( )

If certificate is self signed.

=head3 https_alerts( )

Get HTTPS alerts send by server.

=head3 https_protocols( )

Get HTTPS Alterenate-Protocol header.

=head3 https_svc( )

Get HTTPS Alt-Svc and X-Firefox-Spdy header.

=head3 https_body( )

Get HTTPS response (body)

=head3 https_status( )

Get HTTPS response (aka status) line.

=head3 https_server( )

Get HTTPS Server header.

=head3 https_location( )

Get HTTPS Location header.

=head3 https_refresh( )

Get HTTPS Refresh header.

=head3 https_content_enc( )

Get HTTPS Content-Encoding header.

=head3 https_transfer_enc( )

Get HTTPS Transfer-Encoding header.

=head3 http_protocols( )

Get HTTP Alterenate-Protocol header.

=head3 http_svc( )

Get HTTP Alt-Svc and X-Firefox-Spdy header.

=head3 http_status( )

Get HTTP response (aka status) line.

=head3 http_location( )

Get HTTP Location header.

=head3 http_refresh( )

Get HTTP Refresh header.

=head3 http_sts( )

Get HTTP Strict-Transport-Security header, if any.

=head3 hsts_httpequiv( )

Get hhtp-equiv=Strict-Transport-Security attribute from HTML body, if any.

=head3 hsts( )

Get complete STS header.

=head3 hsts_maxage( )

Get max-age attribute of STS header.

=head3 hsts_subdom( )

Get includeSubDomains attribute of STS header.

=head3 hsts_preload( )

Get preload attribute of STS header.

=head3 https_pins( )

Get pins attribute of STS header.

=head3 CTX_method( )

Get used Net::SSLeay::CTX_*_new) method. Useful for debugging only.

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
sub subjectaltnames { return _SSLinfo_get('altname',          $_[0], $_[1]); } # alias for altname
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
sub ocsp_response   { return _SSLinfo_get('ocsp_response',    $_[0], $_[1]); }
sub ocsp_response_data   { return _SSLinfo_get('ocsp_response_data',   $_[0], $_[1]); }
sub ocsp_response_status { return _SSLinfo_get('ocsp_response_status', $_[0], $_[1]); }
sub ocsp_cert_status{ return _SSLinfo_get('ocsp_cert_status', $_[0], $_[1]); }
sub ocsp_next_update{ return _SSLinfo_get('ocsp_next_update', $_[0], $_[1]); }
sub ocsp_this_update{ return _SSLinfo_get('ocsp_this_update', $_[0], $_[1]); }
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
sub next_protocols  { return _SSLinfo_get('next_protocols',   $_[0], $_[1]); }
sub protocols       { return _SSLinfo_get('next_protocols',   $_[0], $_[1]); } # alias for backward compatibility (< 1.169)
sub alpn            { return _SSLinfo_get('alpn',             $_[0], $_[1]); }
sub no_alpn         { return _SSLinfo_get('no_alpn',          $_[0], $_[1]); }
sub next_protocol   { return _SSLinfo_get('next_protocol',    $_[0], $_[1]); }
sub krb5            { return _SSLinfo_get('krb5',             $_[0], $_[1]); }
sub psk_hint        { return _SSLinfo_get('psk_hint',         $_[0], $_[1]); }
sub psk_identity    { return _SSLinfo_get('psk_identity',     $_[0], $_[1]); }
sub srp             { return _SSLinfo_get('srp',              $_[0], $_[1]); }
sub master_key      { return _SSLinfo_get('master_key',       $_[0], $_[1]); }
sub master_secret   { return _SSLinfo_get('master_secret',    $_[0], $_[1]); }
sub extended_master_secret  { return _SSLinfo_get('master_secret', $_[0], $_[1]); } # alias
sub public_key_len  { return _SSLinfo_get('public_key_len',   $_[0], $_[1]); }
sub session_id      { return _SSLinfo_get('session_id',       $_[0], $_[1]); }
sub session_id_ctx  { return _SSLinfo_get('session_id_ctx',   $_[0], $_[1]); }
sub session_startdate{return _SSLinfo_get('session_startdate',$_[0], $_[1]); }
sub session_starttime{return _SSLinfo_get('session_starttime',$_[0], $_[1]); }
sub session_lifetime{ return _SSLinfo_get('session_lifetime', $_[0], $_[1]); }
sub session_ticket_hint{return _SSLinfo_get('session_lifetime',$_[0],$_[1]); } # alias
sub session_ticket  { return _SSLinfo_get('session_ticket',   $_[0], $_[1]); }
sub session_timeout { return _SSLinfo_get('session_timeout',  $_[0], $_[1]); }
sub session_protocol{ return _SSLinfo_get('session_protocol', $_[0], $_[1]); }
sub fingerprint_hash{ return _SSLinfo_get('fingerprint_hash', $_[0], $_[1]); }
sub fingerprint_text{ return _SSLinfo_get('fingerprint_text', $_[0], $_[1]); }
sub fingerprint_type{ return _SSLinfo_get('fingerprint_type', $_[0], $_[1]); }
sub fingerprint_sha2{ return _SSLinfo_get('fingerprint_sha2', $_[0], $_[1]); }
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
sub https_body      { return _SSLinfo_get('https_body',       $_[0], $_[1]); }
sub https_svc       { return _SSLinfo_get('https_svc',        $_[0], $_[1]); }
sub https_status    { return _SSLinfo_get('https_status',     $_[0], $_[1]); }
sub https_server    { return _SSLinfo_get('https_server',     $_[0], $_[1]); }
sub https_alerts    { return _SSLinfo_get('https_alerts',     $_[0], $_[1]); }
sub https_location  { return _SSLinfo_get('https_location',   $_[0], $_[1]); }
sub https_refresh   { return _SSLinfo_get('https_refresh',    $_[0], $_[1]); }
sub https_pins      { return _SSLinfo_get('https_pins',       $_[0], $_[1]); }
sub https_content_enc   { return _SSLinfo_get('https_content_enc',  $_[0], $_[1]); }
sub https_transfer_enc  { return _SSLinfo_get('https_transfer_enc', $_[0], $_[1]); }
sub http_protocols  { return _SSLinfo_get('http_protocols',   $_[0], $_[1]); }
sub http_svc        { return _SSLinfo_get('http_svc',         $_[0], $_[1]); }
sub http_status     { return _SSLinfo_get('http_status',      $_[0], $_[1]); }
sub http_location   { return _SSLinfo_get('http_location',    $_[0], $_[1]); }
sub http_refresh    { return _SSLinfo_get('http_refresh',     $_[0], $_[1]); }
sub http_sts        { return _SSLinfo_get('http_sts',         $_[0], $_[1]); }
sub https_sts       { return _SSLinfo_get('https_sts',        $_[0], $_[1]); }
sub hsts_httpequiv  { return _SSLinfo_get('hsts_httpequiv',   $_[0], $_[1]); }
sub hsts_maxage     { return _SSLinfo_get('hsts_maxage',      $_[0], $_[1]); }
sub hsts_subdom     { return _SSLinfo_get('hsts_subdom',      $_[0], $_[1]); }
sub hsts_preload    { return _SSLinfo_get('hsts_preload',     $_[0], $_[1]); }
sub CTX_method      { return _SSLinfo_get('CTX_method',       $_[0], $_[1]); }

=pod

=head3 verify_hostname( )

Verify if given hostname matches common name (CN) in certificate.
=cut

############ TODO:  do_ssl_open  vorbereiten fuer verify_*
sub verify_hostname {
    my ($host, $port) = @_;
    return if (not defined do_ssl_open($host, $port, ''));
    return $SSLinfo::no_cert_txt if (0 != $SSLinfo::no_cert);
    my $cname = $_SSLinfo{'cn'};
    my $match = '';
    if (1 == $SSLinfo::ignore_case) {
        $host = lc($host);
        $cname= lc($cname);
    }
    $match = ($host eq $cname) ? 'matches' : 'does not match';
    return sprintf("Given hostname '%s' %s CN '%s' in certificate", $host, $match, $cname);
} # verify_hostname

=head3 verify_altname( ), verify_alias( )

Verify if given hostname matches alternate name (subjectAltNames) in certificate.
=cut

sub verify_altname  {
    my ($host, $port) = @_;
    return if (not defined do_ssl_open($host, $port, ''));
    return $SSLinfo::no_cert_txt if (0 != $SSLinfo::no_cert);
    _trace("verify_altname($host)");
    my $match = 'does not match';
    my $cname = $_SSLinfo{'altname'};
    return "No alternate name defined in certificate" if ('' eq $cname);
    _trace("verify_altname: $cname");
    foreach my $alt (split(/ /, $cname)) {
        # list of strings like: DNS:some.tld DNS:other.tld email:who@some.tld
        # $alt may contain  (  or  {  , see escape $rex below
        next if ($alt =~ m/^\s*$/);
        my ($type, $name) = split(/:/, $alt);
#dbx# print "#ALT# $alt: ($type, $name)";
# TODO: implement IP and URI; see also o-saft.pl: _checkwildcards()
        push(@{$_SSLinfo{'errors'}}, "verify_altname() $type not supported in SNA") if ($type !~ m/DNS/i);
        my $rex = $name;
        if (1 == $SSLinfo::ignore_case) {
            $host = lc($host);
            $rex  = lc($rex);
        }
        $rex =~ s/[.]/\\./g;        # escape meta characters
        $rex =~ s/([({[])/\\$1/g;   # escape meta characters
        if ($name =~ m/[*]/) {
            $rex =~ s/(\*)/[^.]*/;
        }
        _trace("verify_altname: $host =~ $rex ");
        if ($host  =~ /^$rex$/) {
            $match =  'matches';
            $cname =  $alt;   # only show matching name
            $cname =~ s/^[a-zA-Z0-9]+://;   # remove leading type, i.e. DNS:
            last;
        # else
            # $cname still contains type like DNS:
        }
    }
    _trace("verify_altname() done.");
    return sprintf("Given hostname '%s' %s alternate name '%s' in certificate", $host, $match, $cname);
} # verify_altname

sub verify_alias    { return verify_altname($_[0], $_[1]); }

sub error           {
    # TBD
    #return Net::SSLeay::ERR_get_error;
} # error

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

sub _main           {
    #? print own documentation or special required one
    ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    #  see t/.perlcriticrc for detailed description of "no critic"
    my @argv = @_;
    push(@argv, "--help") if (0 > $#argv);
    my %usage = (
      '# commands to show internal data' => {
          'sclient' => "show available options for 'openssl s_client'",
          'ssleay'  => 'show information about Net::SSLeay capabilities',
          'sslmap'  => 'show constants for SSL protocols',
          'openssl' => 'show information about openssl capabilities',
          'methods' => 'show available methods in Net::SSLeay',
          'unknown-host' => 'show empty data structure',
          'your.tld' => 'show data from your.tld',
      },
      "## some commands can also be used as '+test-CMD'" => {},
    );
    local $\="\n";  # wegen eigenen test_*()
    # got arguments, do something special; any -option or +command exits
    while (my $arg = shift @argv) {
        if ($arg =~ m/^--?h(?:elp)?$/)          { local $\; undef $\; OText::print_pod($0, __PACKAGE__, $SID_sslinfo); exit 0; }
        if ($arg eq '--usage')  { local $\; undef $\; OText::usage_show("", \%usage); exit 0; }
        # ----------------------------- options
        if ($arg =~ m/^--(?:v|trace.?)/i)       { $SSLinfo::verbose++;  next; }
        # ----------------------------- commands
        if ($arg =~ m/^(test.*)/)               { $arg = "+$1"; }   # + may be omitted
        if ($arg =~ m/^(?:--|,)(test.*)/)       { $arg = "+$1"; }   # alias: +test*
        if ($arg =~ m/^version$/)               { print "$SID_sslinfo"; next; }
        if ($arg =~ m/^[+-]?VERSION/i)          { print "$VERSION";     next; }
        if ($arg =~ m/^(?:\+test)?.?ssleay/)    { print test_ssleay();  next; }
        if ($arg =~ m/^(?:\+test)?.?sslmap/)    { print test_sslmap();  next; }
        if ($arg =~ m/^(?:\+test)?.?s_?client/) { print test_sclient(); next; }
        if ($arg =~ m/^(?:\+test)?.?methods/)   { print test_methods(); next; }
        if ($arg =~ m/^(?:\+test)?.?openssl/)   { print test_openssl(); next; }
        if ($arg =~ m/^[+-]/)                   { next; }   # silently ignore unknown options
        # treat remaining args as hostname to test
        do_ssl_open( $arg, 443, '');
        print SSLinfo::datadump("main");
    }
    exit 0;
} # _main

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=head1 DEPENDENCIES

L<Net::SSLeay(3pm)>
L<Math::BigInt(3pm)>  (required if necessary only)

=head1 SEE ALSO

L<Net::SSLeay(1)>

=head1 AUTHOR

08-aug-12 Achim Hoffmann

=cut

sub net_sslinfo_done {};        # dummy to check successful include
## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main(@ARGV) if (not defined caller);

1;
