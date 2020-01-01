#!/usr/bin/perl -w
## PACKAGE {
# Filename : SSLhello.pm
#!#############################################################################
#!#                    Copyright (c) Torsten Gigler
#!#             This module is part of the OWASP-Project 'o-saft'
#!# It simulates the SSLhello packets to check SSL parameters like the ciphers
#!#         indepenantly from any SSL library like Openssl or gnutls.
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

# TODO: check if SNI-extension is supported by the server, if 'usesni' is set

## no critic qw(Subroutines::ProhibitSubroutinePrototypes)
#  NOTE:  Contrary to  Perl::Critic  we consider prototypes as useful, even if
#         the compile-time checks of Perl are not perfect,  Perl may give some
#         hints.

## no critic qw(Variables::ProhibitPackageVars)
#  NOTE:  we have a couple of global variables, but do not want to write them
#         in all CAPS (as it would be required by Perl::Critic)

## no critic qw(Subroutines::ProhibitExcessComplexity ControlStructures::ProhibitDeepNests Subroutines::ProhibitManyArgs)
#  yes, parts of this is is complex

## no critic qw(RegularExpressions::RequireExtendedFormatting)
#  because we use /x as needed for human readability

package Net::SSLhello;

BEGIN {
    # section required only when called as: Net/SSLhello.pm or ./SSLhello.pm
    my $_me   = $0; $_me   =~ s#.*[/\\]##;
    if ("SSLhello.pm" eq $_me) {
        my $_path = $0; $_path =~ s#[/\\][^/\\]*$##;
        unshift(@INC, ".", "./lib", $ENV{PWD}, "/bin");
        if ($_path !~ m#^[.]/*$#) { # . already added
            unshift(@INC, "$_path", "$_path/lib") if ($_me ne $_path);
        }
        unshift(@INC, "../") if ($0 =~ m#^(?:[.]/)?SSLhello.pm#); # call in Net/
    }
}

use strict;
use warnings;
use constant {  ## no critic qw(ValuesAndExpressions::ProhibitConstantPragma)
    SSLHELLO_VERSION=> '19.11.19',
    SSLHELLO        => 'O-Saft::Net::SSLhello',
#   SSLHELLO_SID    => '@(#) SSLhello.pm 1.34 20/01/01 17:46:47',
};
use Socket; ## TBD will be deleted soon TBD ###
use IO::Socket::INET;
#require IO::Select if ($main::cfg{'trace'} > 1);
use Carp;
use OSaft::error_handler qw (:sslhello_contants);
    # use internal error_handler, get all constants used for SSLHELLO, for subs
    # the full names will be used (includung OSaft::error_handler-><sub>)

######################################################## public documentation #

=pod

=head1 NAME

Net::SSLhello - Perl extension for SSL to simulate SSLhello packets to check
SSL parameters (especially ciphers).
Connections via proxy and using STARTTLS (SMTP, IMAP, POP3, FTPS, LDAP, RDP,
XMPP and experimental: ACAP) are supported.

=head1 SYNOPSIS

use Net::SSLhello;

=head1 DESCRIPTION

SSLhello.pm is a Perl Module that is part of the OWASP-Project 'o-saft'.
It checks some basic SSL/TLS configuration of a server, like ciphers and extensions (planned) of the SSL/TLS protocol. These checks work independantly from any SSL library like openSSL or gnutls. It does this by simulating the first packets of a SSL/TLS connection. It sends a ClientHello message and analyzes the ServerHello packet that is answered by the server. It gives you a wide range of options for this, so you can even check ciphers that are not yet defined, reserved or obsole, by their 2-octett-values (see http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4).

As it simulates only the first part of the SSL/TLS handshake, it is really fast! Another advantage of this is that it can even analyze SSL/TLS ciphers of servers that verify client certificates without any need to provide one (this is normally done later in the SSL/TLS handshake).

Export Functions:
$socket = openTcpSSLconnection ($host; $port); # Open a TCP/IP connection to a host on a port (via proxy) and doing STARTTLS if requested
@accepted = Net::SSLhello::checkSSLciphers ($host, $port, $ssl, @testing); # Check a list if ciphers (@testing), output: @accepted ciphers (if the first 2 ciphers are equal the server has an order)
Net::SSLhello::printCipherStringArray ($cfg{'legacy'}, $host, $port, $ssl, $sni, @accepted); # print the list of ciphers (@accepted ciphers)

=head1 METHODS

=cut


#our %main::cfg;    # provided by caller
our $dtlsEpoch = 0; # for DTLS only (globally)
our %_SSLhello;     # our internal data structure
our $my_error = ""; # global store for error message

use Exporter qw(import);
use base qw(Exporter);
our $VERSION    = SSLHELLO_VERSION;
our @EXPORT_OK  = qw(
        net_sslhello_done
        checkSSLciphers
        compileClientHello
        compileSSL2CipherArray
        compileTLSCipherArray
        hexCodedCipher
        hexCodedSSL2Cipher
        hexCodedString
        hexCodedTLSCipher
        openTcpSSLconnection
        parseServerHello
        parseServerKeyExchange
        parseSSL2_ServerHello
        parseTLS_Extension
        parseTLS_ServerHello
        printCipherStringArray
        printParameters
        printSSL2CipherList
        printTLSCipherList
        version
);

our $HAVE_XS = eval {
        local $SIG{'__DIE__'} = 'DEFAULT';
        eval {
            require XSLoader;
            XSLoader::load('Net::SSLhello', $VERSION);
            1;
        } or do {
            require DynaLoader;
            bootstrap Net::SSLhello $VERSION;
            1;
        };

    } ? 1 : 0;

# All Main Parameters, Constants, Lists and Functions that are used by o-saft andSSLhello
use osaft; # TBD add "raw";

use constant {  ## no critic qw(ValuesAndExpressions::ProhibitConstantPragma)
    _MY_SSL3_MAX_CIPHERS                => 64, # Max nr of ciphers sent in a SSL3/TLS Client-Hello to test if they are supported by the server, e.g. 32, 48, 64, 128, ...
    _MY_PRINT_CIPHERS_PER_LINE          =>  8, # Nr of ciphers printed in a trace
    _PROXY_CONNECT_MESSAGE1             => "CONNECT ",
    _PROXY_CONNECT_MESSAGE2             => " HTTP/1.1\n\n",
    _MAX_SEGMENT_COUNT_TO_RESET_RETRY_COUNT => 16, # Max number og TCP-Segments that can reset the retry counter to '0' for next read
    _SLEEP_B4_2ND_READ                  => 0.5, # Sleep before second read (STARTTLS and proxy) [in sec.x]
    _DTLS_SLEEP_AFTER_FOUND_A_CIPHER    => 0.75, # DTLS-Protocol: Sleep after found a cipher to segregate the following request [in sec.x]
    _DTLS_SLEEP_AFTER_NO_CIPHERS_FOUND  => 0.05  # DTLS-Protocol: Sleep after not found a cipher to segregate the following request [in sec.x]
};

#our $LONG_PACKET = 1940; # try to get a 2nd or 3rd segment for long packets
#
#
#defaults for global parameters
$Net::SSLhello::trace               = 0;# 1=simple debugging Net::SSLhello
$Net::SSLhello::traceTIME           = 0;# 1=trace prints timestamp
$Net::SSLhello::usesni              = 1;# 0=do not use SNI extension, 1=use SNI extension (protocol >=tlsv1), 2(or 3): toggle sni (run twice per protocol without and with sni)
$Net::SSLhello::use_sni_name        = 0;# 0=use hostname (default), 1: use sni_name for SNI mode connections
$Net::SSLhello::sni_name            = "1";# name to be used for SNI mode connection is use_sni_name=1; ###FIX: "1": quickfix until migration of o-saft.pl is compleated (tbd)
$Net::SSLhello::force_TLS_extensions= 0;# prevent to not to use TLS extensions in SSLv3
$Net::SSLhello::timeout             = 2;# time in seconds
$Net::SSLhello::retry               = 3;# number of retry when timeout occurs
$Net::SSLhello::connect_delay       = 0;# time to wait in seconds for starting next cipher check
$Net::SSLhello::usereneg            = 0;# secure renegotiation
$Net::SSLhello::use_signature_alg   = 1;# signature_algorithm: 0 (off), 1 (auto on if >=TLSv1.2, >=DTLS1.2), 2: always on
$Net::SSLhello::useecc              = 1;# use 'Supported Elliptic' Curves Extension
$Net::SSLhello::useecpoint          = 1;# use 'ec_point_formats' extension
$Net::SSLhello::starttls            = 0;# 1= do STARTTLS
$Net::SSLhello::starttlsType        = "SMTP";# default: SMTP
@Net::SSLhello::starttlsPhaseArray  = [];# STARTTLS: customized phases (1-5) and error handling (6-8)
$Net::SSLhello::starttlsDelay       = 0;# STARTTLS: time to wait in seconds (to slow down the requests)
$Net::SSLhello::slowServerDelay     = 0;# proxy and STARTTLS: time to wait in seconds (for slow proxies and STARTTLS servers)
$Net::SSLhello::double_reneg        = 0;# 0=Protection against double renegotiation info is active
$Net::SSLhello::proxyhost           = "";#
$Net::SSLhello::proxyport           = "";#
$Net::SSLhello::experimental        = 0;# 0: experimental functions are protected (=not active)
$Net::SSLhello::max_ciphers         = _MY_SSL3_MAX_CIPHERS; # max nr of ciphers sent in a SSL3/TLS Client-Hello to test if they are supported by the server
$Net::SSLhello::max_sslHelloLen     = 16388; # according RFC: 16383+5 bytes; max len of sslHello messages (some implementations had issues with packets longer than 256 bytes)
$Net::SSLhello::noDataEqNoCipher    = 1; # 1= for some TLS intolerant servers 'NoData or timeout equals to no cipher' supported -> Do NOT abort to test next ciphers

my %RECORD_TYPE = ( # RFC 5246
    'change_cipher_spec'    => 20,
    'alert'                 => 21,
    'handshake'             => 22,
    'application_data'      => 23,
    'heartbeat'             => 24,
    '255'                   => 255,
    '<<undefined>>'         => -1       # added for internal use
);

my %HANDSHAKE_TYPE = ( # RFC 5246
    'hello_request'         => 0,
    'client_hello'          => 1,
    'server_hello'          => 2,
    'hello_verify_request'  => 3, # rfc4347 DTLS
    'certificate'           => 11,
    'server_key_exchange'   => 12,
    'certificate_request'   => 13,
    'server_hello_done'     => 14,
    'certificate_verify'    => 15,
    'client_key_exchange'   => 16,
    'finished'              => 20,
    '255'                   => 255,
    '<<undefined>>'         => -1,      # added for internal use
    '<<fragmented_message>>'=> -99      # added for internal use
);

my %PROTOCOL_VERSION = (
    'SSLv2'      => 0x0002,
    'SSLv3'      => 0x0300,
    'TLSv1'      => 0x0301, # TLS1.0 = SSL3.1
    'TLSv11'     => 0x0302, # TLS1.1
    'TLSv12'     => 0x0303, # TLS1.2
    'TLSv13'     => 0x0304, # TLS1.3, not YET specified
    'TLSv1.FF'   => 0x03FF, # Last possible Version of TLS1.x (NOT specified)
    'DTLSv09'    => 0x0100, # DTLS, OpenSSL pre 0.9.8f, not finally standardized (udp)
    'DTLSfamily' => 0xFE00, # DTLS1.FF, no defined PROTOCOL, for internal usea only (udp)
    'DTLSv1'     => 0xFEFF, # DTLS1.0 (udp)
    'DTLSv11'    => 0xFEFE, # DTLS1.1: has NEVER been used (udp)
    'DTLSv12'    => 0xFEFD, # DTLS1.2 (udp)
    'DTLSv13'    => 0xFEFC, # DTLS1.3, not YET specified (udp)
    'SCSV'       => 0x03FF  # adapted to o-saft.pl, was TLS1.FF # FIXME: TLS1.FF was better ;-) TBD: change it at o-saft.pl and delete it here
);

# http://www.iana.org/assignments/tls-parameters/tls-parameters-6.csv
# Value,Description,DTLS-OK,Reference
my %TLS_AlertDescription = (
     0 => [qw(close_notify  Y  [RFC5246])],
    10 => [qw(unexpected_message  Y  [RFC5246])],
    20 => [qw(bad_record_mac  Y  [RFC5246])],
    21 => [qw(decryption_failed  Y  [RFC5246])],
    22 => [qw(record_overflow  Y  [RFC5246])],
    30 => [qw(decompression_failure  Y  [RFC5246])],
    40 => [qw(handshake_failure  Y  [RFC5246])],
    41 => [qw(no_certificate_RESERVED  Y  [RFC5246])],
    42 => [qw(bad_certificate  Y  [RFC5246])],
    43 => [qw(unsupported_certificate  Y  [RFC5246])],
    44 => [qw(certificate_revoked  Y  [RFC5246])],
    45 => [qw(certificate_expired  Y  [RFC5246])],
    46 => [qw(certificate_unknown  Y  [RFC5246])],
    47 => [qw(illegal_parameter  Y  [RFC5246])],
    48 => [qw(unknown_ca  Y  [RFC5246])],
    49 => [qw(access_denied  Y  [RFC5246])],
    50 => [qw(decode_error  Y  [RFC5246])],
    51 => [qw(decrypt_error  Y  [RFC5246])],
    60 => [qw(export_restriction_RESERVED  Y  [RFC5246])],
    70 => [qw(protocol_version  Y  [RFC5246])],
    71 => [qw(insufficient_security  Y  [RFC5246])],
    80 => [qw(internal_error  Y  [RFC5246])],
    86 => [qw(inappropriate_fallback  Y  [RFC5246_update-Draft-2014-05-31])], ### added according 'https://datatracker.ietf.org/doc/draft-bmoeller-tls-downgrade-scsv/?include_text=1'
    90 => [qw(user_canceled  Y  [RFC5246])],
    100 => [qw(no_renegotiation  Y  [RFC5246])],
    110 => [qw(unsupported_extension  Y  [RFC5246])],
    111 => [qw(certificate_unobtainable  Y  [RFC6066])],
    112 => [qw(unrecognized_name  Y  [RFC6066])],
    113 => [qw(bad_certificate_status_response  Y  [RFC6066])],
    114 => [qw(bad_certificate_hash_value  Y  [RFC6066])],
    115 => [qw(unknown_psk_identity  Y  [RFC4279])],
);

my %ECCURVE_TYPE = ( # RFC 4492
    'explicit_prime'        => 1,
    'explicit_char2'        => 2,
    'named_curve'           => 3,
    'reserved_248'          => 248,
    'reserved_249'          => 249,
    'reserved_250'          => 250,
    'reserved_251'          => 251,
    'reserved_252'          => 252,
    'reserved_253'          => 253,
    'reserved_254'          => 254,
    'reserved_255'          => 255,
);

#http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-10
#Value =>   Description bits(added) DTLS-OK Reference
my %ECC_NAMED_CURVE = (
     0 => [qw(Unassigned_0        0 N [IANA])],
     1 => [qw(sect163k1         163 Y [RFC4492])],
     2 => [qw(sect163r1         163 Y [RFC4492])],
     3 => [qw(sect163r2         163 Y [RFC4492])],
     4 => [qw(sect193r1         193 Y [RFC4492])],
     5 => [qw(sect193r2         193 Y [RFC4492])],
     6 => [qw(sect233k1         233 Y [RFC4492])],
     7 => [qw(sect233r1         233 Y [RFC4492])],
     8 => [qw(sect239k1         239 Y [RFC4492])],
     9 => [qw(sect283k1         283 Y [RFC4492])],
    10 => [qw(sect283r1         283 Y [RFC4492])],
    11 => [qw(sect409k1         409 Y [RFC4492])],
    12 => [qw(sect409r1         409 Y [RFC4492])],
    13 => [qw(sect571k1         571 Y [RFC4492])],
    14 => [qw(sect571r1         571 Y [RFC4492])],
    15 => [qw(secp160k1         160 Y [RFC4492])],
    16 => [qw(secp160r1         160 Y [RFC4492])],
    17 => [qw(secp160r2         160 Y [RFC4492])],
    18 => [qw(secp192k1         192 Y [RFC4492])],
    19 => [qw(secp192r1         192 Y [RFC4492])],
    20 => [qw(secp224k1         224 Y [RFC4492])],
    21 => [qw(secp224r1         224 Y [RFC4492])],
    22 => [qw(secp256k1         256 Y [RFC4492])],
    23 => [qw(secp256r1         256 Y [RFC4492])],
    24 => [qw(secp384r1         384 Y [RFC4492])],
    25 => [qw(secp521r1         521 Y [RFC4492])],
    26 => [qw(brainpoolP256r1   256 Y [RFC7027])],
    27 => [qw(brainpoolP384r1   384 Y [RFC7027])],
    28 => [qw(brainpoolP512r1   512 Y [RFC7027])],
    29 => [qw(ecdh_x25519       255 Y [draft-ietf-tls-tls][draft-ietf-tls-rfc4492bis])], #TEMPORARY-registered_2016-02-29,_expires 2017-03-01,
    30 => [qw(ecdh_x448         448 Y [draft-ietf-tls-tls][draft-ietf-tls-rfc4492bis])], #TEMPORARY-registered_2016-02-29,_expires 2017-03-01,
    31 => [qw(eddsa_ed25519     255 Y [https://tools.ietf.org/html/draft-ietf-tls-tls13-11])], # Signature curves, vanished in  https://tools.ietf.org/html/draft-ietf-tls-tls13-12
    32 => [qw(eddsa_ed448       448 Y [https://tools.ietf.org/html/draft-ietf-tls-tls13-11])], # Signature curves, vanished in  https://tools.ietf.org/html/draft-ietf-tls-tls13-12
   256 => [qw(ffdhe2048        2048 Y [RFC-ietf-tls-negotiated-ff-dhe-10])],
   257 => [qw(ffdhe3072        3072 Y [RFC-ietf-tls-negotiated-ff-dhe-10])],
   258 => [qw(ffdhe4096        4096 Y [RFC-ietf-tls-negotiated-ff-dhe-10])],
   259 => [qw(ffdhe6144        6144 Y [RFC-ietf-tls-negotiated-ff-dhe-10])],
   260 => [qw(ffdhe8192        8192 Y [RFC-ietf-tls-negotiated-ff-dhe-10])],
 65281 => [qw(arbitrary_explicit_prime_curves -variable- Y [RFC4492])],
 65282 => [qw(arbitrary_explicit_char2_curves -variable- Y [RFC4492])],
);

##################################################################################
# List of Functions
##################################################################################
sub checkSSLciphers ($$$@);
sub printCipherStringArray ($$$$$@);
sub _timedOut;
sub _error;

# TODO: import/export of the trace-function from o-saft-dbx.pm;
# this is a workaround to get trace running using parameter '$main::cfg{'trace'}'
## forward declarations
#sub _trace  {};
#sub _trace1 {};
#sub _trace2 {};
#sub _trace3 {};
## Print Errors; Debugging
#sub _error    { local $\ = "\n"; print ">>>Net::SSLhello>>> ERROR: " . join(" ", @_); }
#sub _trace_   { _trace (@_); }
#sub _trace1_  { _trace1(@_); }
#sub _trace2_  { _trace2(@_); }
#sub _trace3_  { _trace3(@_); }
#sub _trace4($){ print "# Net::SSLhello::" . join(" ", @_) if ($Net::SSLhello::trace >3); }
#sub _trace4_  { _trace4(@_); }

sub _y_ts      { if ($main::cfg{'traceTIME'} <= 0)  { return ""; }            return sprintf("[%02s:%02s:%02s] ", (localtime)[2,1,0]) }

sub _trace($)  { my @messages = @_; local $\ = ""; print "#" . _y_ts() . SSLHELLO . "::" . $messages[0]                 if ($main::cfg{'trace'} > 0); return }
sub _trace0($) { my @messages = @_; local $\ = ""; print "#" . _y_ts() . SSLHELLO . "::"                                if ($main::cfg{'trace'} > 0); return }
sub _trace1($) { my @messages = @_; local $\ = ""; print "# " . _y_ts() . SSLHELLO . "::" . join(" ", @messages)        if ($main::cfg{'trace'} > 1); return }
sub _trace2($) { my @messages = @_; local $\ = ""; print "# --> " . _y_ts() . SSLHELLO . "::" . join(" ", @messages)    if ($main::cfg{'trace'} > 2); return }
sub _trace3($) { my @messages = @_; local $\ = ""; print "# --> " . _y_ts() . SSLHELLO . "::" . join(" ", @messages)    if ($main::cfg{'trace'} ==3); return }
sub _trace4($) { my @messages = @_; local $\ = ""; print "#   ---> " . _y_ts() . SSLHELLO . "::" . join(" ", @messages) if ($main::cfg{'trace'} > 3); return }
sub _trace_($) { my @messages = @_; local $\ = ""; print " " . join(" ", @messages)                                     if ($main::cfg{'trace'} > 0); return }
sub _trace1_($){ my @messages = @_; local $\ = ""; print " " . join(" ", @messages)                                     if ($main::cfg{'trace'} > 1); return }
sub _trace2_($){ my @messages = @_; local $\ = ""; print join(" ", @messages)                                           if ($main::cfg{'trace'} > 2); return }
sub _trace3_($){ my @messages = @_; local $\ = ""; print join(" ", @messages)                                           if ($main::cfg{'trace'} ==3); return }
sub _trace4_($){ my @messages = @_; local $\ = ""; print join(" ", @messages)                                           if ($main::cfg{'trace'} > 3); return }

sub _carp   {
    #? print warning message if wanted
    # don't print if --no-warning given
    my @txt = @_;
    return if ((grep{/(:?--no.?warn)/ix} @main::ARGV) > 0);
    local $\ = "\n"; carp(STR_WARN, join(" ", @txt));
    return;
}

sub _hint   {
    #? print hint message if wanted
    # don't print if --no-hint given
    my @txt = @_;
    return if ((grep{/(:?--no.?hint)/ix} @main::ARGV) > 0);
    local $\ = "\n"; print(STR_HINT, join(" ", @txt));
    return;
}

#if (! eval("require o-saft-dbx.pm;")) {
#        # o-saft-dbx.pm may not be installed, try to find in program's directory
#        push(@INC, $main::mepath);
#        require "o-saft-dbx.pm";
#}
### end trace functions

###################################################################################

my $CHALLENGE = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20o-saft\xbb\xcc\xdd\xee\xff"; # 16-32 bytes,

##################################################################################
# sslv2
##################################################################################
#http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html
##################################################################################
# Information: not all parameters are used within SSLhello.pm

#C.1 Protocol Version Codes
my $SSL_CLIENT_VERSION            = 0x0002;
my $SSL_SERVER_VERSION            = 0x0002;

#C.2 Protocol Message Codes
#The following values define the message codes that are used by version 2 of the SSL Handshake Protocol.

# SSL2_PROTOCOL_MESSAGE_CODES
my $SSL_MT_ERROR                = 0;
my $SSL_MT_CLIENT_HELLO         = 1;
my $SSL_MT_CLIENT_MASTER_KEY    = 2;
my $SSL_MT_CLIENT_FINISHED      = 3;
my $SSL_MT_SERVER_HELLO         = 4;
my $SSL_MT_SERVER_VERIFY        = 5;
my $SSL_MT_SERVER_FINISHED      = 6;
my $SSL_MT_REQUEST_CERTIFICATE  = 7;
my $SSL_MT_CLIENT_CERTIFICATE   = 8;

#C.3 Error Message Codes
#The following values define the error codes used by the ERROR message.
my $SSL_PE_NO_CIPHER            = 0x0001;
my $SSL_PE_NO_CERTIFICATE       = 0x0002;
my $SSL_PE_BAD_CERTIFICATE      = 0x0004;
my $SSL_PE_UNSUPPORTED_CERTIFICATE_TYPE = 0x0006;

#C.5 Certificate Type Codes
#The following values define the certificate type codes used in the SERVER-HELLO and CLIENT-CERTIFICATE messages.
my $SSL_CT_X509_CERTIFICATE     = 0x01;

#C.6 Authentication Type Codes
#The following values define the authentication type codes used in the REQUEST-CERTIFICATE message.
my $SSL_AT_MD5_WITH_RSA_ENCRYPTION  = 0x01;

#C.7 Upper/Lower Bounds
#The following values define upper/lower bounds for various protocol parameters.
my $SSL_MAX_MASTER_KEY_LENGTH_IN_BITS   = 256;
my $SSL_MAX_SESSION_ID_LENGTH_IN_BYTES  = 16;
my $SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES = 64;
my $SSL_MAX_RECORD_LENGTH_2_BYTE_HEADER = 32767;
my $SSL_MAX_RECORD_LENGTH_3_BYTE_HEADER = 16383;

#C.8 Recommendations
#Because protocols have to be implemented to be of value, we recommend the following values for various operational parameters. This is only a recommendation, and not a strict requirement for conformance to the protocol.

#################################################################
my %cipherHexHash = (
#!#----------------------------------------+-------------+--------------------+
#!# Protocol: SSL2 (uppercase!)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
  '0x020700C0'=> [qw(DES_192_EDE3_CBC_WITH_MD5                DES-CBC3-MD5)],
  '0x020701C0'=> [qw(DES_192_EDE3_CBC_WITH_SHA                DES-CBC3-SHA)],
  '0x02060040'=> [qw(DES_64_CBC_WITH_MD5                      DES-CBC-MD5)],
  '0x02060140'=> [qw(DES_64_CBC_WITH_SHA                      DES-CBC-SHA)],
  '0x02FF0800'=> [qw(DES_64_CFB64_WITH_MD5_1                  DES-CFB-M1)],
  '0x02050080'=> [qw(IDEA_128_CBC_WITH_MD5                    IDEA-CBC-MD5)],
  '0x02FF0810'=> [qw(NULL                                     NULL)],
  '0x02000000'=> [qw(NULL_WITH_MD5                            NULL-MD5)],
  '0x02040080'=> [qw(RC2_128_CBC_EXPORT40_WITH_MD5            EXP-RC2-CBC-MD5)],
  '0x02030080'=> [qw(RC2_128_CBC_WITH_MD5                     RC2-CBC-MD5)],
  '0x02020080'=> [qw(RC4_128_EXPORT40_WITH_MD5                EXP-RC4-MD5)],
  '0x02010080'=> [qw(RC4_128_WITH_MD5                         RC4-MD5)],
  '0x02080080'=> [qw(RC4_64_WITH_MD5                          RC4-64-MD5)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol: SSL3 (invented)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
  '0x0300001B'=> [qw(ADH_WITH_DES_192_CBC3_SHA                ADH-DES-CBC3-SHA)],
  '0x03000019'=> [qw(ADH_WITH_DES_40_CBC_SHA                  EXP-ADH-DES-CBC-SHA)],
  '0x0300001A'=> [qw(ADH_WITH_DES_64_CBC_SHA                  ADH-DES-CBC-SHA)],
  '0x03000018'=> [qw(ADH_WITH_RC4_128_MD5                     ADH-RC4-MD5)],
  '0x03000017'=> [qw(ADH_WITH_RC4_40_MD5                      EXP-ADH-RC4-MD5)],
  '0x0300000D'=> [qw(DH_DSS_WITH_DES_192_CBC3_SHA             DH-DSS-DES-CBC3-SHA)],
  '0x0300000B'=> [qw(DH_DSS_WITH_DES_40_CBC_SHA               EXP-DH-DSS-DES-CBC-SHA)],
  '0x0300000C'=> [qw(DH_DSS_WITH_DES_64_CBC_SHA               DH-DSS-DES-CBC-SHA)],
  '0x03000010'=> [qw(DH_RSA_WITH_DES_192_CBC3_SHA             DH-RSA-DES-CBC3-SHA)],
  '0x0300000E'=> [qw(DH_RSA_WITH_DES_40_CBC_SHA               EXP-DH-RSA-DES-CBC-SHA)],
  '0x0300000F'=> [qw(DH_RSA_WITH_DES_64_CBC_SHA               DH-RSA-DES-CBC-SHA)],
  '0x03000013'=> [qw(EDH_DSS_WITH_DES_192_CBC3_SHA            EDH-DSS-DES-CBC3-SHA)],
  '0x03000011'=> [qw(EDH_DSS_WITH_DES_40_CBC_SHA              EXP-EDH-DSS-DES-CBC-SHA)],
  '0x03000012'=> [qw(EDH_DSS_WITH_DES_64_CBC_SHA              EDH-DSS-DES-CBC-SHA)],
  '0x03000016'=> [qw(EDH_RSA_WITH_DES_192_CBC3_SHA            EDH-RSA-DES-CBC3-SHA)],
  '0x03000014'=> [qw(EDH_RSA_WITH_DES_40_CBC_SHA              EXP-EDH-RSA-DES-CBC-SHA)],
  '0x03000015'=> [qw(EDH_RSA_WITH_DES_64_CBC_SHA              EDH-RSA-DES-CBC-SHA)],
  '0x0300001D'=> [qw(FZA_DMS_FZA_SHA                          FZA-FZA-CBC-SHA)],
  '0x0300001C'=> [qw(FZA_DMS_NULL_SHA                         FZA-NULL-SHA)],
  '0x0300001E'=> [qw(FZA_DMS_RC4_SHA                          FZA-RC4-SHA)],
  '0x03000023'=> [qw(KRB5_WITH_DES_192_CBC3_MD5               KRB5-DES-CBC3-MD5)],
  '0x0300001F'=> [qw(KRB5_WITH_DES_192_CBC3_SHA               KRB5-DES-CBC3-SHA)],
  '0x03000029'=> [qw(KRB5_WITH_DES_40_CBC_MD5                 EXP-KRB5-DES-CBC-MD5)],
  '0x03000026'=> [qw(KRB5_WITH_DES_40_CBC_SHA                 EXP-KRB5-DES-CBC-SHA)],
  '0x03000022'=> [qw(KRB5_WITH_DES_64_CBC_MD5                 KRB5-DES-CBC-MD5)],
  '0x0300001E'=> [qw(KRB5_WITH_DES_64_CBC_SHA                 KRB5-DES-CBC-SHA)],
  '0x03000025'=> [qw(KRB5_WITH_IDEA_128_CBC_MD5               KRB5-IDEA-CBC-MD5)],
  '0x03000021'=> [qw(KRB5_WITH_IDEA_128_CBC_SHA               KRB5-IDEA-CBC-SHA)],
  '0x0300002A'=> [qw(KRB5_WITH_RC2_40_CBC_MD5                 EXP-KRB5-RC2-CBC-MD5)],
  '0x03000027'=> [qw(KRB5_WITH_RC2_40_CBC_SHA                 EXP-KRB5-RC2-CBC-SHA)],
  '0x03000024'=> [qw(KRB5_WITH_RC4_128_MD5                    KRB5-RC4-MD5)],
  '0x03000020'=> [qw(KRB5_WITH_RC4_128_SHA                    KRB5-RC4-SHA)],
  '0x0300002B'=> [qw(KRB5_WITH_RC4_40_MD5                     EXP-KRB5-RC4-MD5)],
  '0x03000028'=> [qw(KRB5_WITH_RC4_40_SHA                     EXP-KRB5-RC4-SHA)],
  '0x0300000A'=> [qw(RSA_WITH_DES_192_CBC3_SHA                DES-CBC3-SHA)],
  '0x03000008'=> [qw(RSA_WITH_DES_40_CBC_SHA                  EXP-DES-CBC-SHA)],
  '0x03000009'=> [qw(RSA_WITH_DES_64_CBC_SHA                  DES-CBC-SHA)],
  '0x03000007'=> [qw(RSA_WITH_IDEA_128_SHA                    IDEA-CBC-SHA)],
  '0x03000000'=> [qw(NULL_WITH_NULL_NULL                      NULL-NULL)],
  '0x03000001'=> [qw(RSA_WITH_NULL_MD5                        NULL-MD5)],
  '0x03000002'=> [qw(RSA_WITH_NULL_SHA                        NULL-SHA)],
  '0x03000006'=> [qw(RSA_WITH_RC2_40_MD5                      EXP-RC2-CBC-MD5)],
  '0x03000004'=> [qw(RSA_WITH_RC4_128_MD5                     RC4-MD5)],
  '0x03000005'=> [qw(RSA_WITH_RC4_128_SHA                     RC4-SHA)],
  '0x03000003'=> [qw(RSA_WITH_RC4_40_MD5                      EXP-RC4-MD5)],
  '0x030000FF'=> [qw(EMPTY_RENEGOTIATION_INFO_SCSV            SCSV-RENEG)], #activated 'Signaling Cipher Suite Value'
  '0x03005600'=> [qw(FALLBACK_SCSV_DRAFT                      SCSV-FALLBACK-DRAFT)], ### added according 'https://datatracker.ietf.org/doc/draft-bmoeller-tls-downgrade-scsv/?include_text=1'

#!#----------------------------------------+-------------+--------------------+
#!# Protocol:  TLS 1.0 (invented)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
  '0x030000A6'=> [qw(ADH_WITH_AES_128_GCM_SHA256              ADH-AES128-GCM-SHA256)],
  '0x03000034'=> [qw(ADH_WITH_AES_128_SHA                     ADH-AES128-SHA)],
  '0x0300006C'=> [qw(ADH_WITH_AES_128_SHA256                  ADH-AES128-SHA256)],
  '0x030000A7'=> [qw(ADH_WITH_AES_256_GCM_SHA384              ADH-AES256-GCM-SHA384)],
  '0x0300003A'=> [qw(ADH_WITH_AES_256_SHA                     ADH-AES256-SHA)],
  '0x0300006D'=> [qw(ADH_WITH_AES_256_SHA256                  ADH-AES256-SHA256)],
  '0x03000046'=> [qw(ADH_WITH_CAMELLIA_128_CBC_SHA            ADH-CAMELLIA128-SHA)],
  '0x03000089'=> [qw(ADH_WITH_CAMELLIA_256_CBC_SHA            ADH-CAMELLIA256-SHA)],
  '0x0300009B'=> [qw(ADH_WITH_SEED_SHA                        ADH-SEED-SHA)],
  '0x03000063'=> [qw(DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA      EXP1024-DHE-DSS-DES-CBC-SHA)],
  '0x03000065'=> [qw(DHE_DSS_EXPORT1024_WITH_RC4_56_SHA       EXP1024-DHE-DSS-RC4-SHA)],
  '0x030000A2'=> [qw(DHE_DSS_WITH_AES_128_GCM_SHA256          DHE-DSS-AES128-GCM-SHA256)],
  '0x03000032'=> [qw(DHE_DSS_WITH_AES_128_SHA                 DHE-DSS-AES128-SHA)],
  '0x03000040'=> [qw(DHE_DSS_WITH_AES_128_SHA256              DHE-DSS-AES128-SHA256)],
  '0x030000A3'=> [qw(DHE_DSS_WITH_AES_256_GCM_SHA384          DHE-DSS-AES256-GCM-SHA384)],
  '0x03000038'=> [qw(DHE_DSS_WITH_AES_256_SHA                 DHE-DSS-AES256-SHA)],
  '0x0300006A'=> [qw(DHE_DSS_WITH_AES_256_SHA256              DHE-DSS-AES256-SHA256)],
  '0x03000044'=> [qw(DHE_DSS_WITH_CAMELLIA_128_CBC_SHA        DHE-DSS-CAMELLIA128-SHA)],
  '0x03000087'=> [qw(DHE_DSS_WITH_CAMELLIA_256_CBC_SHA        DHE-DSS-CAMELLIA256-SHA)],
  '0x03000066'=> [qw(DHE_DSS_WITH_RC4_128_SHA                 DHE-DSS-RC4-SHA)],
  '0x03000099'=> [qw(DHE_DSS_WITH_SEED_SHA                    DHE-DSS-SEED-SHA)],
  '0x0300009E'=> [qw(DHE_RSA_WITH_AES_128_GCM_SHA256          DHE-RSA-AES128-GCM-SHA256)],
  '0x03000033'=> [qw(DHE_RSA_WITH_AES_128_SHA                 DHE-RSA-AES128-SHA)],
  '0x03000067'=> [qw(DHE_RSA_WITH_AES_128_SHA256              DHE-RSA-AES128-SHA256)],
  '0x0300009F'=> [qw(DHE_RSA_WITH_AES_256_GCM_SHA384          DHE-RSA-AES256-GCM-SHA384)],
  '0x03000039'=> [qw(DHE_RSA_WITH_AES_256_SHA                 DHE-RSA-AES256-SHA)],
  '0x0300006B'=> [qw(DHE_RSA_WITH_AES_256_SHA256              DHE-RSA-AES256-SHA256)],
  '0x03000045'=> [qw(DHE_RSA_WITH_CAMELLIA_128_CBC_SHA        DHE-RSA-CAMELLIA128-SHA)],
  '0x03000088'=> [qw(DHE_RSA_WITH_CAMELLIA_256_CBC_SHA        DHE-RSA-CAMELLIA256-SHA)],
  '0x0300009A'=> [qw(DHE_RSA_WITH_SEED_SHA                    DHE-RSA-SEED-SHA)],
  '0x030000A4'=> [qw(DH_DSS_WITH_AES_128_GCM_SHA256           DH-DSS-AES128-GCM-SHA256)],
  '0x03000030'=> [qw(DH_DSS_WITH_AES_128_SHA                  DH-DSS-AES128-SHA)],
  '0x0300003E'=> [qw(DH_DSS_WITH_AES_128_SHA256               DH-DSS-AES128-SHA256)],
  '0x030000A5'=> [qw(DH_DSS_WITH_AES_256_GCM_SHA384           DH-DSS-AES256-GCM-SHA384)],
  '0x03000036'=> [qw(DH_DSS_WITH_AES_256_SHA                  DH-DSS-AES256-SHA)],
  '0x03000068'=> [qw(DH_DSS_WITH_AES_256_SHA256               DH-DSS-AES256-SHA256)],
  '0x03000042'=> [qw(DH_DSS_WITH_CAMELLIA_128_CBC_SHA         DH-DSS-CAMELLIA128-SHA)],
  '0x03000085'=> [qw(DH_DSS_WITH_CAMELLIA_256_CBC_SHA         DH-DSS-CAMELLIA256-SHA)],
  '0x03000097'=> [qw(DH_DSS_WITH_SEED_SHA                     DH-DSS-SEED-SHA)],
  '0x030000A0'=> [qw(DH_RSA_WITH_AES_128_GCM_SHA256           DH-RSA-AES128-GCM-SHA256)],
  '0x03000031'=> [qw(DH_RSA_WITH_AES_128_SHA                  DH-RSA-AES128-SHA)],
  '0x0300003F'=> [qw(DH_RSA_WITH_AES_128_SHA256               DH-RSA-AES128-SHA256)],
  '0x030000A1'=> [qw(DH_RSA_WITH_AES_256_GCM_SHA384           DH-RSA-AES256-GCM-SHA384)],
  '0x03000037'=> [qw(DH_RSA_WITH_AES_256_SHA                  DH-RSA-AES256-SHA)],
  '0x03000069'=> [qw(DH_RSA_WITH_AES_256_SHA256               DH-RSA-AES256-SHA256)],
  '0x03000043'=> [qw(DH_RSA_WITH_CAMELLIA_128_CBC_SHA         DH-RSA-CAMELLIA128-SHA)],
  '0x03000086'=> [qw(DH_RSA_WITH_CAMELLIA_256_CBC_SHA         DH-RSA-CAMELLIA256-SHA)],
  '0x03000098'=> [qw(DH_RSA_WITH_SEED_SHA                     DH-RSA-SEED-SHA)],
  '0x0300C009'=> [qw(ECDHE_ECDSA_WITH_AES_128_CBC_SHA         ECDHE-ECDSA-AES128-SHA)],
  '0x0300C02B'=> [qw(ECDHE_ECDSA_WITH_AES_128_GCM_SHA256      ECDHE-ECDSA-AES128-GCM-SHA256)],
  '0x0300C023'=> [qw(ECDHE_ECDSA_WITH_AES_128_SHA256          ECDHE-ECDSA-AES128-SHA256)],
  '0x0300C00A'=> [qw(ECDHE_ECDSA_WITH_AES_256_CBC_SHA         ECDHE-ECDSA-AES256-SHA)],
  '0x0300C02C'=> [qw(ECDHE_ECDSA_WITH_AES_256_GCM_SHA384      ECDHE-ECDSA-AES256-GCM-SHA384)],
  '0x0300C024'=> [qw(ECDHE_ECDSA_WITH_AES_256_SHA384          ECDHE-ECDSA-AES256-SHA384)],
  '0x0300C008'=> [qw(ECDHE_ECDSA_WITH_DES_192_CBC3_SHA        ECDHE-ECDSA-DES-CBC3-SHA)],
  '0x0300C006'=> [qw(ECDHE_ECDSA_WITH_NULL_SHA                ECDHE-ECDSA-NULL-SHA)],
  '0x0300C007'=> [qw(ECDHE_ECDSA_WITH_RC4_128_SHA             ECDHE-ECDSA-RC4-SHA)],
  '0x0300C013'=> [qw(ECDHE_RSA_WITH_AES_128_CBC_SHA           ECDHE-RSA-AES128-SHA)],
  '0x0300C02F'=> [qw(ECDHE_RSA_WITH_AES_128_GCM_SHA256        ECDHE-RSA-AES128-GCM-SHA256)],
  '0x0300C027'=> [qw(ECDHE_RSA_WITH_AES_128_SHA256            ECDHE-RSA-AES128-SHA256)],
  '0x0300C014'=> [qw(ECDHE_RSA_WITH_AES_256_CBC_SHA           ECDHE-RSA-AES256-SHA)],
  '0x0300C030'=> [qw(ECDHE_RSA_WITH_AES_256_GCM_SHA384        ECDHE-RSA-AES256-GCM-SHA384)],
  '0x0300C028'=> [qw(ECDHE_RSA_WITH_AES_256_SHA384            ECDHE-RSA-AES256-SHA384)],
  '0x0300C012'=> [qw(ECDHE_RSA_WITH_DES_192_CBC3_SHA          ECDHE-RSA-DES-CBC3-SHA)],
  '0x0300C010'=> [qw(ECDHE_RSA_WITH_NULL_SHA                  ECDHE-RSA-NULL-SHA)],
  '0x0300C011'=> [qw(ECDHE_RSA_WITH_RC4_128_SHA               ECDHE-RSA-RC4-SHA)],
  '0x0300C004'=> [qw(ECDH_ECDSA_WITH_AES_128_CBC_SHA          ECDH-ECDSA-AES128-SHA)],
  '0x0300C02D'=> [qw(ECDH_ECDSA_WITH_AES_128_GCM_SHA256       ECDH-ECDSA-AES128-GCM-SHA256)],
  '0x0300C025'=> [qw(ECDH_ECDSA_WITH_AES_128_SHA256           ECDH-ECDSA-AES128-SHA256)],
  '0x0300C005'=> [qw(ECDH_ECDSA_WITH_AES_256_CBC_SHA          ECDH-ECDSA-AES256-SHA)],
  '0x0300C02E'=> [qw(ECDH_ECDSA_WITH_AES_256_GCM_SHA384       ECDH-ECDSA-AES256-GCM-SHA384)],
  '0x0300C026'=> [qw(ECDH_ECDSA_WITH_AES_256_SHA384           ECDH-ECDSA-AES256-SHA384)],
  '0x0300C003'=> [qw(ECDH_ECDSA_WITH_DES_192_CBC3_SHA         ECDH-ECDSA-DES-CBC3-SHA)],
  '0x0300C001'=> [qw(ECDH_ECDSA_WITH_NULL_SHA                 ECDH-ECDSA-NULL-SHA)],
  '0x0300C002'=> [qw(ECDH_ECDSA_WITH_RC4_128_SHA              ECDH-ECDSA-RC4-SHA)],
  '0x0300C00E'=> [qw(ECDH_RSA_WITH_AES_128_CBC_SHA            ECDH-RSA-AES128-SHA)],
  '0x0300C031'=> [qw(ECDH_RSA_WITH_AES_128_GCM_SHA256         ECDH-RSA-AES128-GCM-SHA256)],
  '0x0300C029'=> [qw(ECDH_RSA_WITH_AES_128_SHA256             ECDH-RSA-AES128-SHA256)],
  '0x0300C00F'=> [qw(ECDH_RSA_WITH_AES_256_CBC_SHA            ECDH-RSA-AES256-SHA)],
  '0x0300C032'=> [qw(ECDH_RSA_WITH_AES_256_GCM_SHA384         ECDH-RSA-AES256-GCM-SHA384)],
  '0x0300C02A'=> [qw(ECDH_RSA_WITH_AES_256_SHA384             ECDH-RSA-AES256-SHA384)],
  '0x0300C00D'=> [qw(ECDH_RSA_WITH_DES_192_CBC3_SHA           ECDH-RSA-DES-CBC3-SHA)],
  '0x0300C00B'=> [qw(ECDH_RSA_WITH_NULL_SHA                   ECDH-RSA-NULL-SHA)],
  '0x0300C00C'=> [qw(ECDH_RSA_WITH_RC4_128_SHA                ECDH-RSA-RC4-SHA)],
  '0x0300C018'=> [qw(ECDH_anon_WITH_AES_128_CBC_SHA           AECDH-AES128-SHA)],
  '0x0300C019'=> [qw(ECDH_anon_WITH_AES_256_CBC_SHA           AECDH-AES256-SHA)],
  '0x0300C017'=> [qw(ECDH_anon_WITH_DES_192_CBC3_SHA          AECDH-DES-CBC3-SHA)],
  '0x0300C015'=> [qw(ECDH_anon_WITH_NULL_SHA                  AECDH-NULL-SHA)],
  '0x0300C016'=> [qw(ECDH_anon_WITH_RC4_128_SHA               AECDH-RC4-SHA)],
  '0x0300008B'=> [qw(PSK_WITH_3DES_EDE_CBC_SHA                PSK-3DES-EDE-CBC-SHA)],
  '0x0300008C'=> [qw(PSK_WITH_AES_128_CBC_SHA                 PSK-AES128-CBC-SHA)],
  '0x0300008D'=> [qw(PSK_WITH_AES_256_CBC_SHA                 PSK-AES256-CBC-SHA)],
  '0x0300008A'=> [qw(PSK_WITH_RC4_128_SHA                     PSK-RC4-SHA)],
  '0x03000062'=> [qw(RSA_EXPORT1024_WITH_DES_CBC_SHA          EXP1024-DES-CBC-SHA)],
  '0x03000061'=> [qw(RSA_EXPORT1024_WITH_RC2_CBC_56_MD5       EXP1024-RC2-CBC-MD5)],
  '0x03000060'=> [qw(RSA_EXPORT1024_WITH_RC4_56_MD5           EXP1024-RC4-MD5)],
  '0x03000064'=> [qw(RSA_EXPORT1024_WITH_RC4_56_SHA           EXP1024-RC4-SHA)],
  '0x0300009C'=> [qw(RSA_WITH_AES_128_GCM_SHA256              AES128-GCM-SHA256)],
  '0x0300002F'=> [qw(RSA_WITH_AES_128_SHA                     AES128-SHA)],
  '0x0300003C'=> [qw(RSA_WITH_AES_128_SHA256                  AES128-SHA256)],
  '0x0300009D'=> [qw(RSA_WITH_AES_256_GCM_SHA384              AES256-GCM-SHA384)],
  '0x03000035'=> [qw(RSA_WITH_AES_256_SHA                     AES256-SHA)],
  '0x0300003D'=> [qw(RSA_WITH_AES_256_SHA256                  AES256-SHA256)],
  '0x03000041'=> [qw(RSA_WITH_CAMELLIA_128_CBC_SHA            CAMELLIA128-SHA)],
  '0x03000084'=> [qw(RSA_WITH_CAMELLIA_256_CBC_SHA            CAMELLIA256-SHA)],
  '0x0300003B'=> [qw(RSA_WITH_NULL_SHA256                     NULL-SHA256)],
  '0x03000096'=> [qw(RSA_WITH_SEED_SHA                        SEED-SHA)],
  '0x0300C01C'=> [qw(SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA        SRP-DSS-3DES-EDE-CBC-SHA)],
  '0x0300C01F'=> [qw(SRP_SHA_DSS_WITH_AES_128_CBC_SHA         SRP-DSS-AES-128-CBC-SHA)],
  '0x0300C022'=> [qw(SRP_SHA_DSS_WITH_AES_256_CBC_SHA         SRP-DSS-AES-256-CBC-SHA)],
  '0x0300C01B'=> [qw(SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA        SRP-RSA-3DES-EDE-CBC-SHA)],
  '0x0300C01E'=> [qw(SRP_SHA_RSA_WITH_AES_128_CBC_SHA         SRP-RSA-AES-128-CBC-SHA)],
  '0x0300C021'=> [qw(SRP_SHA_RSA_WITH_AES_256_CBC_SHA         SRP-RSA-AES-256-CBC-SHA)],
  '0x0300C01A'=> [qw(SRP_SHA_WITH_3DES_EDE_CBC_SHA            SRP-3DES-EDE-CBC-SHA)],
  '0x0300C01D'=> [qw(SRP_SHA_WITH_AES_128_CBC_SHA             SRP-AES-128-CBC-SHA)],
  '0x0300C020'=> [qw(SRP_SHA_WITH_AES_256_CBC_SHA             SRP-AES-256-CBC-SHA)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol:  http://tools.ietf.org/html/draft-chudov-cryptopro-cptls-04
#!# added manually 20140209:  GOST 28147-89 Cipher Suites for Transport Layer Security (TLS)
#!#                   draft-chudov-cryptopro-cptls-04 (2008-12-08)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
  '0x03000080'=> [qw(GOSTR341094_WITH_28147_CNT_IMIT      GOSTR341094-28147-CNT-IMIT)],
  '0x03000081'=> [qw(GOSTR341001_WITH_28147_CNT_IMIT      GOSTR341001-28147-CNT-IMIT)],
  '0x03000082'=> [qw(GOSTR341094_WITH_NULL_GOSTR3411      GOSTR341094-NULL-GOSTR3411)],
  '0x03000083'=> [qw(GOSTR341001_WITH_NULL_GOSTR3411      GOSTR341001-NULL-GOSTR3411)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol:  http://tools.ietf.org/html/draft-mavrogiannopoulos-chacha-tls-01
#!# added manually 20140209: ChaCha Stream Cipher for Transport Layer Security
#!# 20160330: renamed Ciphers 0x0300CC12 .. 0x0300CC19 as hex-numbers changed
#!#           in version 05 of the draft: __OLD, __OLD
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
  '0x0300CC12'=> [qw(RSA_WITH_CHACHA20_POLY1305__OLD         RSA-CHACHA20-POLY1305__OLD)],
  '0x0300CC13'=> [qw(ECDHE_RSA_WITH_CHACHA20_POLY1305__OLD   ECDHE-RSA-CHACHA20-POLY1305__OLD)],
  '0x0300CC14'=> [qw(ECDHE_ECDSA_WITH_CHACHA20_POLY1305__OLD ECDHE-ECDSA-CHACHA20-POLY1305__OLD)],

  '0x0300CC15'=> [qw(DHE_RSA_WITH_CHACHA20_POLY1305__OLD     DHE-RSA-CHACHA20-POLY1305__OLD)],
  '0x0300CC16'=> [qw(DHE_PSK_WITH_CHACHA20_POLY1305__OLD     DHE-PSK-CHACHA20-POLY1305__OLD)],

  '0x0300CC17'=> [qw(PSK_WITH_CHACHA20_POLY1305__OLD         PSK-CHACHA20-POLY1305__OLD)],
  '0x0300CC18'=> [qw(ECDHE_PSK_WITH_CHACHA20_POLY1305__OLD   ECDHE-PSK-CHACHA20-POLY1305__OLD)],
  '0x0300CC19'=> [qw(RSA_PSK_WITH_CHACHA20_POLY1305__OLD     RSA-PSK-CHACHA20-POLY1305__OLD)],

  '0x0300CC20'=> [qw(RSA_WITH_CHACHA20_SHA              RSA-CHACHA20-SHA)],
  '0x0300CC21'=> [qw(ECDHE_RSA_WITH_CHACHA20_SHA        ECDHE-RSA-CHACHA20-SHA)],
  '0x0300CC22'=> [qw(ECDHE_ECDSA_WITH_CHACHA20_SHA      ECDHE-ECDSA-CHACHA20-SHA)],

  '0x0300CC23'=> [qw(DHE_RSA_WITH_CHACHA20_SHA          DHE-RSA-CHACHA20-SHA)],
  '0x0300CC24'=> [qw(DHE_PSK_WITH_CHACHA20_SHA          DHE-PSK-CHACHA20-SHA)],

  '0x0300CC25'=> [qw(PSK_WITH_CHACHA20_SHA              PSK-CHACHA20-SHA)],
  '0x0300CC26'=> [qw(ECDHE_PSK_WITH_CHACHA20_SHA        ECDHE-PSK-CHACHA20-SHA)],
  '0x0300CC27'=> [qw(RSA_PSK_WITH_CHACHA20_SHA          RSA-PSK-CHACHA20-SHA)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol:  http://tools.ietf.org/html/draft-mavrogiannopoulos-chacha-tls-05
#!# added manually 20160330: NEW ChaCha Stream Cipher for Transport Layer Security
#!# ATTENTION: the same Ciphers existed before using 0x0300CC12 .. 0x0300CC19
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
  '0x0300CCA0'=> [qw(RSA_WITH_CHACHA20_POLY1305         RSA-CHACHA20-POLY1305)],
  '0x0300CCA1'=> [qw(ECDHE_RSA_WITH_CHACHA20_POLY1305   ECDHE-RSA-CHACHA20-POLY1305)],
  '0x0300CCA2'=> [qw(ECDHE_ECDSA_WITH_CHACHA20_POLY1305 ECDHE-ECDSA-CHACHA20-POLY1305)],

  '0x0300CCA3'=> [qw(DHE_RSA_WITH_CHACHA20_POLY1305     DHE-RSA-CHACHA20-POLY1305)],
  '0x0300CCA4'=> [qw(DHE_PSK_WITH_CHACHA20_POLY1305     DHE-PSK-CHACHA20-POLY1305)],

  '0x0300CCA5'=> [qw(PSK_WITH_CHACHA20_POLY1305         PSK-CHACHA20-POLY1305)],
  '0x0300CCA6'=> [qw(ECDHE_PSK_WITH_CHACHA20_POLY1305   ECDHE-PSK-CHACHA20-POLY1305)],
  '0x0300CCA7'=> [qw(RSA_PSK_WITH_CHACHA20_POLY1305     RSA-PSK-CHACHA20-POLY1305)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol: https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305-04
#!# added manually 20160331:
#!#           ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+

# CipherSuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = {0xTBD, 0xTBD} {0xCC, 0xA8}
# CipherSuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = {0xTBD, 0xTBD} {0xCC, 0xA9}
# CipherSuite TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     = {0xTBD, 0xTBD} {0xCC, 0xAA}

# CipherSuite TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         = {0xTBD, 0xTBD} {0xCC, 0xAB}
# CipherSuite TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   = {0xTBD, 0xTBD} {0xCC, 0xAC}
# CipherSuite TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     = {0xTBD, 0xTBD} {0xCC, 0xAD}
# CipherSuite TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256     = {0xTBD, 0xTBD} {0xCC, 0xAE}
  '0x0300CCA8'=> [qw(ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   ECDHE-RSA-CHACHA20-POLY1305-SHA256)],
  '0x0300CCA9'=> [qw(ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 ECDHE-ECDSA-CHACHA20-POLY1305-SHA256)],
  '0x0300CCAA'=> [qw(DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     DHE-RSA-CHACHA20-POLY1305-SHA256)],

  '0x0300CCAB'=> [qw(PSK_WITH_CHACHA20_POLY1305_SHA256         PSK-CHACHA20-POLY1305-SHA256)],
  '0x0300CCAC'=> [qw(ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   ECDHE-PSK-CHACHA20-POLY1305-SHA256)],
  '0x0300CCAD'=> [qw(DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     DHE-PSK-CHACHA20-POLY1305-SHA256)],
  '0x0300CCAE'=> [qw(RSA_PSK_WITH_CHACHA20_POLY1305_SHA256     RSA-PSK-CHACHA20-POLY1305-SHA256)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol:  http://tools.ietf.org/html/rfc5932
#!# added manually 20140630:  Camellia Cipher Suites for TLS
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
# CipherSuite TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256      = { 0x00,0xBA };
# CipherSuite TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256   = { 0x00,0xBB };
# CipherSuite TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256   = { 0x00,0xBC };
# CipherSuite TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256  = { 0x00,0xBD };
# CipherSuite TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256  = { 0x00,0xBE };
# CipherSuite TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256  = { 0x00,0xBF };
  '0x030000BA'=> [qw(RSA_WITH_CAMELLIA_128_CBC_SHA256     RSA-CAMELLIA128-SHA256)],
  '0x030000BB'=> [qw(DH_DSS_WITH_CAMELLIA_128_CBC_SHA256  DH-DSS-CAMELLIA128-SHA256)],
  '0x030000BC'=> [qw(DH_RSA_WITH_CAMELLIA_128_CBC_SHA256  DH-RSA-CAMELLIA128-SHA256)],
  '0x030000BD'=> [qw(DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 DHE-DSS-CAMELLIA128-SHA256)],
  '0x030000BE'=> [qw(DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 DHE-RSA-CAMELLIA128-SHA256)],
  '0x030000BF'=> [qw(ADH_WITH_CAMELLIA_128_CBC_SHA256     ADH-CAMELLIA128-SHA256)],


# CipherSuite TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256      = { 0x00,0xC0 };
# CipherSuite TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256   = { 0x00,0xC1 };
# CipherSuite TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256   = { 0x00,0xC2 };
# CipherSuite TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256  = { 0x00,0xC3 };
# CipherSuite TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256  = { 0x00,0xC4 };
# CipherSuite TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256  = { 0x00,0xC5 };
  '0x030000C0'=> [qw(RSA_WITH_CAMELLIA_256_CBC_SHA256     RSA-CAMELLIA256-SHA256)],
  '0x030000C1'=> [qw(DH_DSS_WITH_CAMELLIA_256_CBC_SHA256  DH-DSS-CAMELLIA256-SHA256)],
  '0x030000C2'=> [qw(DH_RSA_WITH_CAMELLIA_256_CBC_SHA256  DH-RSA-CAMELLIA256-SHA256)],
  '0x030000C3'=> [qw(DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 DHE-DSS-CAMELLIA256-SHA256)],
  '0x030000C4'=> [qw(DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 DHE-RSA-CAMELLIA256-SHA256)],
  '0x030000C5'=> [qw(ADH_WITH_CAMELLIA_256_CBC_SHA256     ADH-CAMELLIA256-SHA256)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol:  http://tools.ietf.org/html/rfcrfc6367
#!# added manually 20140701:  Camellia Cipher Suites for TLS
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
# CipherSuite TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = {0xC0,0x72};
# CipherSuite TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = {0xC0,0x73};
# CipherSuite TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  = {0xC0,0x74};
# CipherSuite TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  = {0xC0,0x75};
# CipherSuite TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   = {0xC0,0x76};
# CipherSuite TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384   = {0xC0,0x77};
# CipherSuite TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256    = {0xC0,0x78};
# CipherSuite TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384    = {0xC0,0x79};
  '0x0300C072'=> [qw(ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256   ECDHE-ECDSA-CAMELLIA128-SHA256)],
  '0x0300C073'=> [qw(ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384   ECDHE-ECDSA-CAMELLIA256-SHA384)],
  '0x0300C074'=> [qw(ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256    ECDH-ECDSA-CAMELLIA128-SHA256)],
  '0x0300C075'=> [qw(ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384    ECDH-ECDSA-CAMELLIA256-SHA384)],
  '0x0300C076'=> [qw(ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256     ECDHE-RSA-CAMELLIA128-SHA256)],
  '0x0300C077'=> [qw(ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384     ECDHE-RSA-CAMELLIA256-SHA384)],
  '0x0300C078'=> [qw(ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256      ECDH-RSA-CAMELLIA128-SHA256)],
  '0x0300C079'=> [qw(ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384      ECDH-RSA-CAMELLIA256-SHA384)],

# CipherSuite TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256          = {0xC0,0x7A};
# CipherSuite TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384          = {0xC0,0x7B};
# CipherSuite TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256      = {0xC0,0x7C};
# CipherSuite TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384      = {0xC0,0x7D};
# CipherSuite TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256       = {0xC0,0x7E};
# CipherSuite TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384       = {0xC0,0x7F};
  '0x0300C07A'=> [qw(RSA_WITH_CAMELLIA_128_GCM_SHA256           RSA-CAMELLIA128-GCM-SHA256)],
  '0x0300C07B'=> [qw(RSA_WITH_CAMELLIA_256_GCM_SHA384           RSA-CAMELLIA256-GCM-SHA384)],
  '0x0300C07C'=> [qw(DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256       DHE-RSA-CAMELLIA128-GCM-SHA256)],
  '0x0300C07D'=> [qw(DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384       DHE-RSA-CAMELLIA256-GCM-SHA384)],
  '0x0300C07E'=> [qw(DH_RSA_WITH_CAMELLIA_128_GCM_SHA256        DH-RSA-CAMELLIA128-GCM-SHA256)],
  '0x0300C07F'=> [qw(DH_RSA_WITH_CAMELLIA_256_GCM_SHA384        DH-RSA-CAMELLIA256-GCM-SHA384)],

# CipherSuite TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256      = {0xC0,0x80};
# CipherSuite TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384      = {0xC0,0x81};
# CipherSuite TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256       = {0xC0,0x82};
# CipherSuite TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384       = {0xC0,0x83};
# CipherSuite TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256      = {0xC0,0x84};
# CipherSuite TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384      = {0xC0,0x85};
  '0x0300C080'=> [qw(DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256       DHE-DSS-CAMELLIA128-GCM-SHA256)],
  '0x0300C081'=> [qw(DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384       DHE-DSS-CAMELLIA256-GCM-SHA384)],
  '0x0300C082'=> [qw(DH_DSS_WITH_CAMELLIA_128_GCM_SHA256        DH-DSS-CAMELLIA128-GCM-SHA256)],
  '0x0300C083'=> [qw(DH_DSS_WITH_CAMELLIA_256_GCM_SHA384        DH-DSS-CAMELLIA256-GCM-SHA384)],
  '0x0300C084'=> [qw(ADH_DSS_WITH_CAMELLIA_128_GCM_SHA256       ADH-DSS-CAMELLIA128-GCM-SHA256)],
  '0x0300C085'=> [qw(ADH_DSS_WITH_CAMELLIA_256_GCM_SHA384       ADH-DSS-CAMELLIA256-GCM-SHA384)],

# CipherSuite TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256  = {0xC0,0x86};
# CipherSuite TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384  = {0xC0,0x87};
# CipherSuite TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256   = {0xC0,0x88};
# CipherSuite TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384   = {0xC0,0x89};
# CipherSuite TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256    = {0xC0,0x8A};
# CipherSuite TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384    = {0xC0,0x8B};
# CipherSuite TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256     = {0xC0,0x8C};
# CipherSuite TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384     = {0xC0,0x8D};
  '0x0300C086'=> [qw(ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256   ECDHE-ECDSA-CAMELLIA128-GCM-SHA256)],
  '0x0300C087'=> [qw(ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384   ECDHE-ECDSA-CAMELLIA256-GCM-SHA384)],
  '0x0300C088'=> [qw(ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256    ECDH-ECDSA-CAMELLIA128-GCM-SHA256)],
  '0x0300C089'=> [qw(ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384    ECDH-ECDSA-CAMELLIA256-GCM-SHA384)],
  '0x0300C08A'=> [qw(ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256     ECDHE-RSA-CAMELLIA128-GCM-SHA256)],
  '0x0300C08B'=> [qw(ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384     ECDHE-RSA-CAMELLIA256-GCM-SHA384)],
  '0x0300C08C'=> [qw(ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256      ECDH-RSA-CAMELLIA128-GCM-SHA256)],
  '0x0300C08D'=> [qw(ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384      ECDH-RSA-CAMELLIA256-GCM-SHA384)],

# CipherSuite TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256        = {0xC0,0x8E}; ##BUG in RFC6376##
# CipherSuite TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384        = {0xC0,0x8F};
# CipherSuite TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256    = {0xC0,0x90};
# CipherSuite TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384    = {0xC0,0x91};
# CipherSuite TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256    = {0xC0,0x92};
# CipherSuite TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384    = {0xC0,0x93};
  '0x0300C08E'=> [qw(PSK_WITH_CAMELLIA_128_GCM_SHA256           PSK-CAMELLIA128-GCM-SHA256)],
  '0x0300C08F'=> [qw(PSK_WITH_CAMELLIA_256_GCM_SHA384           PSK-CAMELLIA256-GCM-SHA384)],
  '0x0300C090'=> [qw(DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256       DHE-PSK-CAMELLIA128-GCM-SHA256)],
  '0x0300C091'=> [qw(DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384       DHE-PSK-CAMELLIA256-GCM-SHA384)],
  '0x0300C092'=> [qw(RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256       RSA-PSK-CAMELLIA128-GCM-SHA256)],
  '0x0300C093'=> [qw(RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384       RSA-PSK-CAMELLIA256-GCM-SHA384)],

# CipherSuite TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256        = {0xC0,0x94};
# CipherSuite TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384        = {0xC0,0x95};
# CipherSuite TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256    = {0xC0,0x96};
# CipherSuite TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384    = {0xC0,0x97};
# CipherSuite TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256    = {0xC0,0x98};
# CipherSuite TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384    = {0xC0,0x99};
  '0x0300C094'=> [qw(PSK_WITH_CAMELLIA_128_CBC_SHA256           PSK-CAMELLIA128-SHA256)],
  '0x0300C095'=> [qw(PSK_WITH_CAMELLIA_256_CBC_SHA384           PSK-CAMELLIA256-SHA384)],
  '0x0300C096'=> [qw(DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256       DHE-PSK-CAMELLIA128-SHA256)],
  '0x0300C097'=> [qw(DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384       DHE-PSK-CAMELLIA256-SHA384)],
  '0x0300C098'=> [qw(RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256       RSA-PSK-CAMELLIA128-SHA256)],
  '0x0300C099'=> [qw(RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384       RSA-PSK-CAMELLIA256-SHA384)],

# CipherSuite TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256  = {0xC0,0x9A};
# CipherSuite TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384  = {0xC0,0x9B};
  '0x0300C09A'=> [qw(ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256     ECDHE-PSK-CAMELLIA128-SHA256)],
  '0x0300C09B'=> [qw(ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384     ECDHE-PSK-CAMELLIA256-SHA384)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol:  http://tools.ietf.org/html/rfc6655
#!# added manually 20140705:  AES-CCM cipher suites for TLS
#!# precompiled using
#!# cat rfc6655.txt | grep 'CipherSuite TLS_' | sed -e "s#.*CipherSuite TLS_\(.*\)\s*\=\s*{0x\(.*\),0x\(.*\)[})]#  \'0x0300\2\3\'=> [qw(\1 \1)]\,#"
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
  '0x0300C09C'=> [qw(RSA_WITH_AES_128_CCM        RSA-AES128-CCM)],
  '0x0300C09D'=> [qw(RSA_WITH_AES_256_CCM        RSA-AES256-CCM)],
  '0x0300C09E'=> [qw(DHE_RSA_WITH_AES_128_CCM    DHE-RSA-AES128_CCM)],
  '0x0300C09F'=> [qw(DHE_RSA_WITH_AES_256_CCM    DHE-RSA-AES256_CCM)],
  '0x0300C0A0'=> [qw(RSA_WITH_AES_128_CCM_8      RSA-AES128-CCM8)],
  '0x0300C0A1'=> [qw(RSA_WITH_AES_256_CCM_8      RSA-AES256-CCM8)],
  '0x0300C0A2'=> [qw(DHE_RSA_WITH_AES_128_CCM_8  DHE-RSA-AES128_CCM8)],
  '0x0300C0A3'=> [qw(DHE_RSA_WITH_AES_256_CCM_8  DHE-RSA-AES256_CCM8)],
  '0x0300C0A4'=> [qw(PSK_WITH_AES_128_CCM        PSK-WITH-AES128_CCM)],
  '0x0300C0A5'=> [qw(PSK_WITH_AES_256_CCM        PSK-WITH-AES256_CCM)],
  '0x0300C0A6'=> [qw(DHE_PSK_WITH_AES_128_CCM    DHE-PSK-AES128_CCM)],
  '0x0300C0A7'=> [qw(DHE_PSK_WITH_AES_256_CCM    DHE-PSK-AES256_CCM)],
  '0x0300C0A8'=> [qw(PSK_WITH_AES_128_CCM_8      PSK-AES128-CCM8)],
  '0x0300C0A9'=> [qw(PSK_WITH_AES_256_CCM_8      PSK-AES256-CCM8)],
  '0x0300C0AA'=> [qw(PSK_DHE_WITH_AES_128_CCM_8  PSK-DHE-AES128-CCM8)],
  '0x0300C0AB'=> [qw(PSK_DHE_WITH_AES_256_CCM_8  PSK-DHE-AES256-CCM8)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol: http://www-archive.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
#!# added manually 20141011:
#!# Netscape: FIPS SSL CipherSuite Numbers (OBSOLETE)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
  '0x0300FEE0'=> [qw(RSA_FIPS_WITH_3DES_EDE_CBC_SHA      RSA-FIPS-3DES-EDE-SHA)],
  '0x0300FEE1'=> [qw(RSA_FIPS_WITH_DES_CBC_SHA           RSA-FIPS-DES-CBC-SHA)],
  '0x0300FEFE'=> [qw(RSA_FIPS_WITH_DES_CBC_SHA           RSA-FIPS-DES-CBC-SHA)],
  '0x0300FEFF'=> [qw(RSA_FIPS_WITH_3DES_EDE_CBC_SHA      RSA-FIPS-3DES-EDE-SHA)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol: some  PSK and CCM ciphers (from o-saft.pl, nane1 <-> name2)
#!# added manually 20141012
#!#
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
   '0x0300002C' => [qw(PSK_WITH_NULL_SHA                 PSK-SHA)],
   '0x0300002D' => [qw(DHE_PSK_WITH_NULL_SHA             DHE-PSK-SHA)],
   '0x0300002E' => [qw(RSA_PSK_WITH_NULL_SHA             RSA-PSK-SHA)],
   '0x0300008E' => [qw(DHE_PSK_WITH_RC4_128_SHA          DHE-PSK-RC4-SHA)],
   '0x0300008F' => [qw(DHE_PSK_WITH_3DES_EDE_CBC_SHA     DHE-PSK-3DES-SHA)],
   '0x03000090' => [qw(DHE_PSK_WITH_AES_128_CBC_SHA      DHE-PSK-AES128-SHA)],
   '0x03000091' => [qw(DHE_PSK_WITH_AES_256_CBC_SHA      DHE-PSK-AES256-SHA)],
   '0x03000092' => [qw(RSA_PSK_WITH_RC4_128_SHA          RSA-PSK-RC4-SHA)],
   '0x03000093' => [qw(RSA_PSK_WITH_3DES_EDE_CBC_SHA     RSA-PSK-3DES-SHA)],
   '0x03000094' => [qw(RSA_PSK_WITH_AES_128_CBC_SHA      RSA-PSK-AES128-SHA)],
   '0x03000095' => [qw(RSA_PSK_WITH_AES_256_CBC_SHA      RSA-PSK-AES256-SHA)],

   '0x030000AA' => [qw(DHE_PSK_WITH_AES_128_GCM_SHA256   DHE-PSK-AES128-GCM-SHA256)],
   '0x030000AB' => [qw(DHE_PSK_WITH_AES_256_GCM_SHA384   DHE-PSK-AES256-GCM-SHA384)],
   '0x030000AC' => [qw(RSA_PSK_WITH_AES_128_GCM_SHA256   RSA-PSK-AES128-GCM-SHA256)],
   '0x030000AD' => [qw(RSA_PSK_WITH_AES_256_GCM_SHA384   RSA-PSK-AES256-GCM-SHA384)],
   '0x030000AE' => [qw(PSK_WITH_AES_128_CBC_SHA256       PSK-AES128-SHA256)],
   '0x030000AF' => [qw(PSK_WITH_AES_256_CBC_SHA384       PSK-AES256-SHA384)],
   '0x030000B0' => [qw(PSK_WITH_NULL_SHA256              PSK-SHA256)],
   '0x030000B1' => [qw(PSK_WITH_NULL_SHA384              PSK-SHA384)],
   '0x030000B2' => [qw(DHE_PSK_WITH_AES_256_CBC_SHA256   DHE-PSK-AES128-SHA256)],
   '0x030000B3' => [qw(DHE_PSK_WITH_AES_256_CBC_SHA384   DHE-PSK-AES256-SHA384)],
   '0x030000B4' => [qw(DHE_PSK_WITH_NULL_SHA256          DHE-PSK-SHA256)],
   '0x030000B5' => [qw(DHE_PSK_WITH_NULL_SHA384          DHE-PSK-SHA384)],
   '0x030000B6' => [qw(RSA_PSK_WITH_AES_256_CBC_SHA256   RSA-PSK-AES128-SHA256)],
   '0x030000B7' => [qw(RSA_PSK_WITH_AES_256_CBC_SHA384   RSA-PSK-AES256-SHA384)],
   '0x030000B8' => [qw(RSA_PSK_WITH_NULL_SHA256          RSA-PSK-SHA256)],
   '0x030000B9' => [qw(RSA_PSK_WITH_NULL_SHA384          RSA-PSK-SHA384)],

   '0x0300C0AC' => [qw(ECDHE_ECDSA_WITH_AES_128_CCM      ECDHE-RSA-AES128-CCM)],
   '0x0300C0AD' => [qw(ECDHE_ECDSA_WITH_AES_256_CCM      ECDHE-RSA-AES256-CCM)],
   '0x0300C0AE' => [qw(ECDHE_ECDSA_WITH_AES_128_CCM_8    ECDHE-RSA-AES128-CCM-8)],
   '0x0300C0AF' => [qw(ECDHE_ECDSA_WITH_AES_256_CCM_8    ECDHE-RSA-AES256-CCM-8)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol: some PSK ciphers
#!# added manually 20141012
#!#
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
# RFC 5487: http://tools.ietf.org/html/rfc5487
# CipherSuite TLS_PSK_WITH_AES_128_GCM_SHA256        = {0x00,0xA8};
# CipherSuite TLS_PSK_WITH_AES_256_GCM_SHA384        = {0x00,0xA9};
   '0x030000A8' => [qw(PSK_WITH_AES_128_GCM_SHA256       PSK-AES128-GCM-SHA256)],
   '0x030000A9' => [qw(PSK_WITH_AES_256_GCM_SHA384       PSK-AES256-GCM-SHA384)],

# RFC 5489: http://tools.ietf.org/html/rfc5489
# CipherSuite TLS_ECDHE_PSK_WITH_RC4_128_SHA          = {0xC0,0x33};
# CipherSuite TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA     = {0xC0,0x34};
# CipherSuite TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA      = {0xC0,0x35};
# CipherSuite TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA      = {0xC0,0x36};
# CipherSuite TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256   = {0xC0,0x37};
# CipherSuite TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384   = {0xC0,0x38};
# CipherSuite TLS_ECDHE_PSK_WITH_NULL_SHA             = {0xC0,0x39};
# CipherSuite TLS_ECDHE_PSK_WITH_NULL_SHA256          = {0xC0,0x3A};
# CipherSuite TLS_ECDHE_PSK_WITH_NULL_SHA384          = {0xC0,0x3B};
   '0x0300C033' => [qw(ECDHE_PSK_WITH_RC4_128_SHA          ECDHE-PSK-RC4-SHA)],
   '0x0300C034' => [qw(ECDHE_PSK_WITH_3DES_EDE_CBC_SHA     ECDHE-PSK-3DES-SHA)],
   '0x0300C035' => [qw(ECDHE_PSK_WITH_AES_128_CBC_SHA      ECDHE-PSK-AES128-SHA)],
   '0x0300C036' => [qw(ECDHE_PSK_WITH_AES_256_CBC_SHA      ECDHE-PSK-AES256-SHA)],
   '0x0300C037' => [qw(ECDHE_PSK_WITH_AES_128_CBC_SHA256   ECDHE-PSK-AES128-SHA256)],
   '0x0300C038' => [qw(ECDHE_PSK_WITH_AES_256_CBC_SHA384   ECDHE-PSK-AES256-SHA384)],
   '0x0300C039' => [qw(ECDHE_PSK_WITH_NULL_SHA             ECDHE-PSK-SHA)],
   '0x0300C03A' => [qw(ECDHE_PSK_WITH_NULL_SHA256          ECDHE-PSK-SHA256)],
   '0x0300C03B' => [qw(ECDHE_PSK_WITH_NULL_SHA384          ECDHE-PSK-SHA384)],

# RFC 6209 (To be done)
# CipherSuite TLS_RSA_WITH_ARIA_128_CBC_SHA256         = { 0xC0,0x3C };
# CipherSuite TLS_RSA_WITH_ARIA_256_CBC_SHA384         = { 0xC0,0x3D };
# CipherSuite TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256      = { 0xC0,0x3E };
# CipherSuite TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384      = { 0xC0,0x3F };
# CipherSuite TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256      = { 0xC0,0x40 };
# CipherSuite TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384      = { 0xC0,0x41 };
# CipherSuite TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256     = { 0xC0,0x42 };
# CipherSuite TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384     = { 0xC0,0x43 };
# CipherSuite TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256     = { 0xC0,0x44 };
   '0x0300C03C'=>[qw(RSA_WITH_ARIA_128_CBC_SHA256          RSA-ARIA128-SHA256)],
   '0x0300C03D'=>[qw(RSA_WITH_ARIA_256_CBC_SHA384          RSA-ARIA256-SHA384)],
   '0x0300C03E'=>[qw(DH_DSS_WITH_ARIA_128_CBC_SHA256       DH-DSS-ARIA128-SHA256)],
   '0x0300C03F'=>[qw(DH_DSS_WITH_ARIA_256_CBC_SHA384       DH-DSS-ARIA256-SHA384)],
   '0x0300C040'=>[qw(DH_RSA_WITH_ARIA_128_CBC_SHA256       DH-RSA-ARIA128-SHA256)],
   '0x0300C041'=>[qw(DH_RSA_WITH_ARIA_256_CBC_SHA384       DH-RSA-ARIA256-SHA384)],
   '0x0300C042'=>[qw(DHE_DSS_WITH_ARIA_128_CBC_SHA256      DHE-DSS-ARIA128-SHA256)],
   '0x0300C043'=>[qw(DHE_DSS_WITH_ARIA_256_CBC_SHA384      DHE-DSS-ARIA256-SHA384)],
   '0x0300C044'=>[qw(DHE_RSA_WITH_ARIA_128_CBC_SHA256      DHE-RSA-ARIA128-SHA256)],

# CipherSuite TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384     = { 0xC0,0x45 };
# CipherSuite TLS_DH_anon_WITH_ARIA_128_CBC_SHA256     = { 0xC0,0x46 };
# CipherSuite TLS_DH_anon_WITH_ARIA_256_CBC_SHA384     = { 0xC0,0x47 };
   '0x0300C045'=>[qw(DHE_RSA_WITH_ARIA_256_CBC_SHA384      DHE-RSA-ARIA256-SHA384)],
   '0x0300C046'=>[qw(DH_anon_WITH_ARIA_128_CBC_SHA256      ADH-ARIA128-SHA256)],
   '0x0300C047'=>[qw(DH_anon_WITH_ARIA_256_CBC_SHA384      ADH-ARIA256-SHA384)],

# CipherSuite TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = { 0xC0,0x48 };
# CipherSuite TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = { 0xC0,0x49 };
# CipherSuite TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256  = { 0xC0,0x4A };
# CipherSuite TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384  = { 0xC0,0x4B };
# CipherSuite TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256   = { 0xC0,0x4C };
# CipherSuite TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384   = { 0xC0,0x4D };
# CipherSuite TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256    = { 0xC0,0x4E };
# CipherSuite TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384    = { 0xC0,0x4F };
   '0x0300C048'=>[qw(ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256  ECDHE-ECDSA-ARIA128-SHA256)],
   '0x0300C049'=>[qw(ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384  ECDHE-ECDSA-ARIA256-SHA384)],
   '0x0300C04A'=>[qw(ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256   ECDH-ECDSA-ARIA128-SHA256)],
   '0x0300C04B'=>[qw(ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384   ECDH-ECDSA-ARIA256-SHA384)],
   '0x0300C04C'=>[qw(ECDHE_RSA_WITH_ARIA_128_CBC_SHA256    ECDHE-RSA-ARIA128-SHA256)],
   '0x0300C04D'=>[qw(ECDHE_RSA_WITH_ARIA_256_CBC_SHA384    ECDHE-RSA-ARIA256-SHA384)],
   '0x0300C04E'=>[qw(ECDH_RSA_WITH_ARIA_128_CBC_SHA256     ECDH-RSA-ARIA128-SHA256)],
   '0x0300C04F'=>[qw(ECDH_RSA_WITH_ARIA_256_CBC_SHA384     ECDH-RSA-ARIA256-SHA384)],

# CipherSuite TLS_RSA_WITH_ARIA_128_GCM_SHA256         = { 0xC0,0x50 };
# CipherSuite TLS_RSA_WITH_ARIA_256_GCM_SHA384         = { 0xC0,0x51 };
# CipherSuite TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256     = { 0xC0,0x52 };
# CipherSuite TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384     = { 0xC0,0x53 };
# CipherSuite TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256      = { 0xC0,0x54 };
# CipherSuite TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384      = { 0xC0,0x55 };
# CipherSuite TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256     = { 0xC0,0x56 };
# CipherSuite TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384     = { 0xC0,0x57 };
# CipherSuite TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256      = { 0xC0,0x58 };
# CipherSuite TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384      = { 0xC0,0x59 };
# CipherSuite TLS_DH_anon_WITH_ARIA_128_GCM_SHA256     = { 0xC0,0x5A };
# CipherSuite TLS_DH_anon_WITH_ARIA_256_GCM_SHA384     = { 0xC0,0x5B };
   '0x0300C050'=>[qw(RSA_WITH_ARIA_128_GCM_SHA256          RSA-ARIA128-GCM-SHA256)],
   '0x0300C051'=>[qw(RSA_WITH_ARIA_256_GCM_SHA384          RSA-ARIA256-GCM-SHA384)],
   '0x0300C052'=>[qw(DHE_RSA_WITH_ARIA_128_GCM_SHA256      DHE-RSA-ARIA128-GCM-SHA256)],
   '0x0300C053'=>[qw(DHE_RSA_WITH_ARIA_256_GCM_SHA384      DHE-RSA-ARIA256-GCM-SHA384)],
   '0x0300C054'=>[qw(DH_RSA_WITH_ARIA_128_GCM_SHA256       DH-RSA-ARIA128-GCM-SHA256)],
   '0x0300C055'=>[qw(DH_RSA_WITH_ARIA_256_GCM_SHA384       DH-RSA-ARIA256-GCM-SHA384)],
   '0x0300C056'=>[qw(DHE_DSS_WITH_ARIA_128_GCM_SHA256      DHE-DSS-ARIA128-GCM-SHA256)],
   '0x0300C057'=>[qw(DHE_DSS_WITH_ARIA_256_GCM_SHA384      DHE-DSS-ARIA256-GCM-SHA384)],
   '0x0300C058'=>[qw(DH_DSS_WITH_ARIA_128_GCM_SHA256       DH-DSS-ARIA128-GCM-SHA256)],
   '0x0300C059'=>[qw(DH_DSS_WITH_ARIA_256_GCM_SHA384       DH-DSS-ARIA256-GCM-SHA384)],
   '0x0300C05A'=>[qw(DH_anon_WITH_ARIA_128_GCM_SHA256      ADH-ARIA128-GCM-SHA256)],
   '0x0300C05B'=>[qw(DH_anon_WITH_ARIA_256_GCM_SHA384      ADH-ARIA256-GCM-SHA384)],

# CipherSuite TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = { 0xC0,0x5C };
# CipherSuite TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = { 0xC0,0x5D };
# CipherSuite TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256  = { 0xC0,0x5E };
# CipherSuite TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384  = { 0xC0,0x5F };
# CipherSuite TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256   = { 0xC0,0x60 };
# CipherSuite TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384   = { 0xC0,0x61 };
# CipherSuite TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256    = { 0xC0,0x62 };
# CipherSuite TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384    = { 0xC0,0x63 };
   '0x0300C05C'=>[qw(ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256  ECDHE-ECDSA-ARIA128-GCM-SHA256)],
   '0x0300C05D'=>[qw(ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384  ECDHE-ECDSA-ARIA256-GCM-SHA384)],
   '0x0300C05E'=>[qw(ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256   ECDH-ECDSA-ARIA128-GCM-SHA256)],
   '0x0300C05F'=>[qw(ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384   ECDH-ECDSA-ARIA256-GCM-SHA384)],
   '0x0300C060'=>[qw(ECDHE_RSA_WITH_ARIA_128_GCM_SHA256    ECDHE-RSA-ARIA128-GCM-SHA256)],
   '0x0300C061'=>[qw(ECDHE_RSA_WITH_ARIA_256_GCM_SHA384    ECDHE-RSA-ARIA256-GCM-SHA384)],
   '0x0300C062'=>[qw(ECDH_RSA_WITH_ARIA_128_GCM_SHA256     ECDH-RSA-ARIA128-GCM-SHA256)],
   '0x0300C063'=>[qw(ECDH_RSA_WITH_ARIA_256_GCM_SHA384     ECDH-RSA-ARIA256-GCM-SHA384)],

# CipherSuite TLS_PSK_WITH_ARIA_128_CBC_SHA256         = { 0xC0,0x64 };
# CipherSuite TLS_PSK_WITH_ARIA_256_CBC_SHA384         = { 0xC0,0x65 };
# CipherSuite TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256     = { 0xC0,0x66 };
# CipherSuite TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384     = { 0xC0,0x67 };
# CipherSuite TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256     = { 0xC0,0x68 };
# CipherSuite TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384     = { 0xC0,0x69 };
# CipherSuite TLS_PSK_WITH_ARIA_128_GCM_SHA256         = { 0xC0,0x6A };
# CipherSuite TLS_PSK_WITH_ARIA_256_GCM_SHA384         = { 0xC0,0x6B };
# CipherSuite TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256     = { 0xC0,0x6C };
# CipherSuite TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384     = { 0xC0,0x6D };
# CipherSuite TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256     = { 0xC0,0x6E };
# CipherSuite TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384     = { 0xC0,0x6F };
# CipherSuite TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256   = { 0xC0,0x70 };
# CipherSuite TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384   = { 0xC0,0x71 };
   '0x0300C064'=>[qw(PSK_WITH_ARIA_128_CBC_SHA256          PSK-ARIA128-SHA-56)],
   '0x0300C065'=>[qw(PSK_WITH_ARIA_256_CBC_SHA384          PSK-ARIA256-SHA384)],
   '0x0300C066'=>[qw(DHE_PSK_WITH_ARIA_128_CBC_SHA256      DHE-PSK-ARIA128-SHA256)],
   '0x0300C067'=>[qw(DHE_PSK_WITH_ARIA_256_CBC_SHA384      DHE-PSK-ARIA256-SHA384)],
   '0x0300C068'=>[qw(RSA_PSK_WITH_ARIA_128_CBC_SHA256      RSA-PSK-ARIA128-SHA256)],
   '0x0300C069'=>[qw(RSA_PSK_WITH_ARIA_256_CBC_SHA384      RSA-PSK-ARIA256-SHA384)],
   '0x0300C06A'=>[qw(PSK_WITH_ARIA_128_GCM_SHA256          PSK-ARIA128-GCM-SHA256)],
   '0x0300C06B'=>[qw(PSK_WITH_ARIA_256_GCM_SHA384          PSK-ARIA256-GCM-SHA384)],
   '0x0300C06C'=>[qw(DHE_PSK_WITH_ARIA_128_GCM_SHA256      DHE-PSK-ARIA128-GCM-SHA256)],
   '0x0300C06D'=>[qw(DHE_PSK_WITH_ARIA_256_GCM_SHA384      DHE-PSK-ARIA256-GCM-SHA384)],
   '0x0300C06E'=>[qw(RSA_PSK_WITH_ARIA_128_GCM_SHA256      RSA-PSK-ARIA128-GCM-SHA256)],
   '0x0300C06F'=>[qw(RSA_PSK_WITH_ARIA_256_GCM_SHA384      RSA-PSK-ARIA256-GCM-SHA384)],
   '0x0300C070'=>[qw(ECDHE_PSK_WITH_ARIA_128_CBC_SHA256    ECDHE-PSK-ARIA128-SHA256)],
   '0x0300C071'=>[qw(ECDHE_PSK_WITH_ARIA_256_CBC_SHA384    ECDHE-PSK-ARIA256-SHA384)],

#!#----------------------------------------+-------------+--------------------+
); # cipherHexHash

#################################################################

# TLS_PROTOCOL_MESSAGE_CODES
my $TLS_CLIENT_HELLO    = 1;
my $TLS_SERVER_HELLO    = 2;

my %SSL2_CIPHER_STRINGS = (
  '0x020700C0'=> [qw(DES_192_EDE3_CBC_WITH_MD5                DES-CBC3-MD5       SSL_CK_DES_192_EDE3_CBC_WITH_MD5)],
  '0x020701C0'=> [qw(DES_192_EDE3_CBC_WITH_SHA                DES-CBC3-SHA)],
  '0x02060040'=> [qw(DES_64_CBC_WITH_MD5                      DES-CBC-MD5        SSL_CK_DES_64_CBC_WITH_MD5)],
  '0x02060140'=> [qw(DES_64_CBC_WITH_SHA                      DES-CBC-SHA)],
  '0x02FF0800'=> [qw(DES_64_CFB64_WITH_MD5_1                  DES-CFB-M1)],
  '0x02050080'=> [qw(IDEA_128_CBC_WITH_MD5                    IDEA-CBC-MD5       SSL_CK_IDEA_128_CBC_WITH_MD5)],
  '0x02FF0810'=> [qw(NULL                                     NULL)],
  '0x02000000'=> [qw(NULL_WITH_MD5                            NULL-MD5)],
  '0x02040080'=> [qw(RC2_128_CBC_EXPORT40_WITH_MD5            EXP-RC2-CBC-MD5    SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5)],
  '0x02030080'=> [qw(RC2_128_CBC_WITH_MD5                     RC2-CBC-MD5        SSL_CK_RC2_128_CBC_WITH_MD5)],
  '0x02020080'=> [qw(RC4_128_EXPORT40_WITH_MD5                EXP-RC4-MD5        SSL_CK_RC4_128_EXPORT40_WITH_MD5)],
  '0x02010080'=> [qw(RC4_128_WITH_MD5                         RC4-MD5            SSL_CK_RC4_128_WITH_MD5)],
  '0x02FFFFFF'=> [qw(SSL2_UNFFINED_CIPHER_0x02FFFFFF          SSL2_UNFFINED_CIPHER_0x02FFFFFF             SSL2_UNFFINED_CIPHER_0x02FFFFFF)],
#!#----------------------------------------+-------------+--------------------+
#!# Protocol: SSL3 (invented)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
  '0x0300001B'=> [qw(ADH_WITH_DES_192_CBC_SHA                 ADH-DES-CBC3-SHA)],
  '0x03000019'=> [qw(ADH_WITH_DES_40_CBC_SHA                  EXP-ADH-DES-CBC-SHA)],
  '0x0300001A'=> [qw(ADH_WITH_DES_64_CBC_SHA                  ADH-DES-CBC-SHA)],
  '0x03000018'=> [qw(ADH_WITH_RC4_128_MD5                     ADH-RC4-MD5)],
  '0x03000017'=> [qw(ADH_WITH_RC4_40_MD5                      EXP-ADH-RC4-MD5)],
  '0x0300000D'=> [qw(DH_DSS_WITH_DES_192_CBC3_SHA             DH-DSS-DES-CBC3-SHA)],
  '0x0300000B'=> [qw(DH_DSS_WITH_DES_40_CBC_SHA               EXP-DH-DSS-DES-CBC-SHA)],
  '0x0300000C'=> [qw(DH_DSS_WITH_DES_64_CBC_SHA               DH-DSS-DES-CBC-SHA)],
  '0x03000010'=> [qw(DH_RSA_WITH_DES_192_CBC3_SHA             DH-RSA-DES-CBC3-SHA)],
  '0x0300000E'=> [qw(DH_RSA_WITH_DES_40_CBC_SHA               EXP-DH-RSA-DES-CBC-SHA)],
  '0x0300000F'=> [qw(DH_RSA_WITH_DES_64_CBC_SHA               DH-RSA-DES-CBC-SHA)],
  '0x03000013'=> [qw(EDH_DSS_WITH_DES_192_CBC3_SHA            EDH-DSS-DES-CBC3-SHA)],
  '0x03000011'=> [qw(EDH_DSS_WITH_DES_40_CBC_SHA              EXP-EDH-DSS-DES-CBC-SHA)],
  '0x03000012'=> [qw(EDH_DSS_WITH_DES_64_CBC_SHA              EDH-DSS-DES-CBC-SHA)],
  '0x03000016'=> [qw(EDH_RSA_WITH_DES_192_CBC3_SHA            EDH-RSA-DES-CBC3-SHA)],
  '0x03000014'=> [qw(EDH_RSA_WITH_DES_40_CBC_SHA              EXP-EDH-RSA-DES-CBC-SHA)],
  '0x03000015'=> [qw(EDH_RSA_WITH_DES_64_CBC_SHA              EDH-RSA-DES-CBC-SHA)],
  '0x0300001D'=> [qw(FZA_DMS_FZA_SHA                          FZA-FZA-CBC-SHA)],
  '0x0300001C'=> [qw(FZA_DMS_NULL_SHA                         FZA-NULL-SHA)],
#  '0x0300001E'=> [qw(FZA_DMS_RC4_SHA                          FZA-RC4-SHA)], #doppelt => prüfen
  '0x03000023'=> [qw(KRB5_WITH_DES_192_CBC3_MD5               KRB5-DES-CBC3-MD5)],
  '0x0300001F'=> [qw(KRB5_WITH_DES_192_CBC3_SHA               KRB5-DES-CBC3-SHA)],
  '0x03000029'=> [qw(KRB5_WITH_DES_40_CBC_MD5                 EXP-KRB5-DES-CBC-MD5)],
  '0x03000026'=> [qw(KRB5_WITH_DES_40_CBC_SHA                 EXP-KRB5-DES-CBC-SHA)],
  '0x03000022'=> [qw(KRB5_WITH_DES_64_CBC_MD5                 KRB5-DES-CBC-MD5)],
  '0x0300001E'=> [qw(KRB5_WITH_DES_64_CBC_SHA                 KRB5-DES-CBC-SHA)],
  '0x03000025'=> [qw(KRB5_WITH_IDEA_128_CBC_MD5               KRB5-IDEA-CBC-MD5)],
  '0x03000021'=> [qw(KRB5_WITH_IDEA_128_CBC_SHA               KRB5-IDEA-CBC-SHA)],
  '0x0300002A'=> [qw(KRB5_WITH_RC2_40_CBC_MD5                 EXP-KRB5-RC2-CBC-MD5)],
  '0x03000027'=> [qw(KRB5_WITH_RC2_40_CBC_SHA                 EXP-KRB5-RC2-CBC-SHA)],
  '0x03000024'=> [qw(KRB5_WITH_RC4_128_MD5                    KRB5-RC4-MD5)],
  '0x03000020'=> [qw(KRB5_WITH_RC4_128_SHA                    KRB5-RC4-SHA)],
  '0x0300002B'=> [qw(KRB5_WITH_RC4_40_MD5                     EXP-KRB5-RC4-MD5)],
  '0x03000028'=> [qw(KRB5_WITH_RC4_40_SHA                     EXP-KRB5-RC4-SHA)],
  '0x0300000A'=> [qw(RSA_WITH_DES_192_CBC3_SHA                DES-CBC3-SHA)],
  '0x03000008'=> [qw(RSA_WITH_DES_40_CBC_SHA                  EXP-DES-CBC-SHA)],
  '0x03000009'=> [qw(RSA_WITH_DES_64_CBC_SHA                  DES-CBC-SHA)],
  '0x03000007'=> [qw(RSA_WITH_IDEA_128_SHA                    IDEA-CBC-SHA)],
  '0x03000000'=> [qw(NULL_WITH_NULL_NULL                      NULL-NULL)],
  '0x03000001'=> [qw(RSA_WITH_NULL_MD5                        NULL-MD5)],
  '0x03000002'=> [qw(RSA_WITH_NULL_SHA                        NULL-SHA)],
  '0x030000FF'=> [qw(EMPTY_RENEGOTIATION_INFO_SCSV            SCSV-RENEG)],
);


#############################################################################################
############################################################################################
sub version { # version of SSLhello
    #? prints the official version number of SSLhello (yy-mm-dd)

    local $\ = ""; # no auto '\n' at the end of the line
    print "NET::SSLhello        ($VERSION)\n";
    return;
}

sub printParameters {
    #? prints the global parameters
    #
    local $\ = ""; # no auto '\n' at the end of the line
    print ("#O-Saft::Net::SSLhello::Parameters:\n");
    print ("#SSLHello:                 retry=$Net::SSLhello::retry\n")              if (defined($Net::SSLhello::retry));
    print ("#SSLHello:               timeout=$Net::SSLhello::timeout\n")            if (defined($Net::SSLhello::timeout));
    print ("#SSLHello:         connect_delay=$Net::SSLhello::connect_delay\n")      if (defined($Net::SSLhello::connect_delay));
    print ("#SSLHello:                 trace=$Net::SSLhello::trace\n")              if (defined($Net::SSLhello::trace));
    print ("#SSLHello:             traceTIME=$Net::SSLhello::traceTIME\n")          if (defined($Net::SSLhello::traceTIME));
    print ("#SSLHello:              usereneg=$Net::SSLhello::usereneg\n")           if (defined($Net::SSLhello::usereneg));
    print ("#SSLHello:          double_reneg=$Net::SSLhello::double_reneg\n")       if (defined($Net::SSLhello::double_reneg));
    print ("#SSLHello:                usesni=$Net::SSLhello::usesni\n")             if (defined($Net::SSLhello::usesni));
    print ("#SSLHello:          use_sni_name=$Net::SSLhello::use_sni_name\n")       if (defined($Net::SSLhello::use_sni_name));
    print ("#SSLHello:              sni_name=$Net::SSLhello::sni_name\n")           if (defined($Net::SSLhello::sni_name));
    print ("#SSLHello:     use_signature_alg=$Net::SSLhello::use_signature_alg\n")  if (defined($Net::SSLhello::use_signature_alg));
    print ("#SSLHello:                useecc=$Net::SSLhello::useecc\n")             if (defined($Net::SSLhello::useecc));
    print ("#SSLHello:            useecpoint=$Net::SSLhello::useecpoint\n")         if (defined($Net::SSLhello::useecpoint));
    print ("#SSLHello:              starttls=$Net::SSLhello::starttls\n")           if (defined($Net::SSLhello::starttls));
    print ("#SSLHello:          starttlsType=$Net::SSLhello::starttlsType\n")       if (defined($Net::SSLhello::starttlsType));
    for my $i (1..5) {
        print ("#SSLHello: starttlsPhaseArray[$i]=$Net::SSLhello::starttlsPhaseArray[$i]\n")   if (defined($Net::SSLhello::starttlsPhaseArray[$i]));
    }
    for my $i (6..8) {
        print ("#SSLHello: starttlsErrorArray[".($i-5)."]=$Net::SSLhello::starttlsPhaseArray[$i] = starttlsPhaseArray[$i] (internally)\n")   if (defined($Net::SSLhello::starttlsPhaseArray[$i]));
    }
    print ("#SSLHello:         starttlsDelay=$Net::SSLhello::starttlsDelay\n")      if (defined($Net::SSLhello::starttlsDelay));
    print ("#SSLHello:       slowServerDelay=$Net::SSLhello::slowServerDelay\n")    if (defined($Net::SSLhello::slowServerDelay));
    print ("#SSLHello:          experimental=$Net::SSLhello::experimental\n")       if (defined($Net::SSLhello::experimental));
    print ("#SSLHello:             proxyhost=$Net::SSLhello::proxyhost\n")          if (defined($Net::SSLhello::proxyhost));
    print ("#SSLHello:             proxyport=$Net::SSLhello::proxyport\n")          if (defined($Net::SSLhello::proxyport));
    print ("#SSLHello:           max_ciphers=$Net::SSLhello::max_ciphers\n")        if (defined($Net::SSLhello::max_ciphers));
    print ("#SSLHello:       max_sslHelloLen=$Net::SSLhello::max_sslHelloLen\n")    if (defined($Net::SSLhello::max_sslHelloLen));
    print ("#------------------------------------------------------------------------------------------\n");
    return;
}

### --------------------------------------------------------------------------------------------------------- ###
### compile packets functions
### ---------------------------------------------------------------------------------------------------------
### Aufruf mit printCipherStringArray ($cfg{'legacy'}, $host, $port, "TLS1.2 0x0303", $cfg{'usesni'}, @acceptedCipherArray);
sub printCipherStringArray ($$$$$@) {
    #? <<description missing>> # FIXME:
    # @cipherArray: string representation of the cipher octetts, fe.g. 0x0300000A
    # The first two ciphers are identical, if the server has a preferred order
    #

    my($legacy, $host, $port, $ssl, $usesni, @cipherArray) = @_;
#    my $legacy    = shift; #$_[0]
#    my $host    = shift; #$_[1]
#    my $port    = shift; #$_[2]
#    my $ssl        = shift; #$_[3]
#    my $usesni    = shift; #$_[4]
#    my (@cipherArray) = @{$_[5]};

    my $arrayLen = @cipherArray;
    my $cipherOrder = ""; # cipher suites in server-preferred order or not
    my $sni     = "";
    my $sep     = ", ";
    my $protocol = $PROTOCOL_VERSION{$ssl}; # 0x0002, 0x3000, 0x0301, 0x0302
    local $\    = ""; # no auto '\n' at the end of the line

    _trace4 ("printCipherStringArray: {\n");

    if ($usesni) {
        $sni = "SNI"; #tbd: check in serverHello if SNI is supported by the server
        $Net::SSLhello::use_sni_name = 1 if ( ($Net::SSLhello::use_sni_name == 0) && ($Net::SSLhello::sni_name) && ($Net::SSLhello::sni_name ne "1") ); ###FIX: quickfix until migration of o-saft.pl is compleated (tbd)
        $sni .= " ($Net::SSLhello::sni_name)" if ( ($Net::SSLhello::use_sni_name) && ($Net::SSLhello::sni_name) );
    } else {
        $sni = "no SNI";
    }

    my $firstEle = 0;
    if ($arrayLen > 1) { # 2 or more ciphers
        if ( ($cipherArray[0] eq $cipherArray[1]) ) { # cipher suites in server-preferred order
            if ($legacy eq 'compact') { $cipherOrder = "Server Order"; } else { print "# cipher suites in server-preferred order:\n"; }
            $firstEle = 1;
        } else {
            if ($legacy eq 'compact') { $cipherOrder = "No Order"; } else { print "# server has NO preferred order for cipher suites\n"; }
        }
    } elsif ($arrayLen == 0) { # no cipher for this protocol
        if ($legacy eq 'compact') { # csv-style, protocol without cipher
            printf "%s%s%s%s%-6s (0x%04X)%s%6s%s%-12s%s%10s%s\n",
                $host, $sep,            # %s%s
                $port, $sep,            # %s%s
                $ssl,                   # %-6s (
                $protocol, $sep,        # 0x%04X)%s
                $sni, $sep,             # %6s%s%
                "", $sep,               # %-12s%s
                "", $sep;               # %10s%s
        }
    }

    foreach my $protocolCipher (@cipherArray[$firstEle .. $#cipherArray]) { # array may have the first element twice to signal a server-preferred order
        if ($legacy eq 'compact') { # csv-style
            printf "%s%s%s%s%-6s (0x%04X)%s%6s%s%-12s%s%10s%s",
                $host, $sep,            # %s%s
                $port, $sep,            # %s%s
                $ssl,                   # %-6s (
                $protocol, $sep,        # 0x%04X)%s
                $sni, $sep,             # %6s%s%
                $cipherOrder, $sep,     # %-12s%s
                $protocolCipher, $sep;  # %10s%s
            if ( (defined ($cipherHexHash {$protocolCipher}) ) && ($#{$cipherHexHash {$protocolCipher}}>0) ) { # definiert, max index >0
                printf "%-28s%s%-34s",
                    $cipherHexHash {$protocolCipher}[1], $sep,  # %-28s%s
                    $cipherHexHash {$protocolCipher}[0];        # %-34s
                if (defined ($_SSLhello {$protocolCipher."\|ServerKey"})) { #length of dh_param
                    printf "%s%s\n",
                        $sep, "(".$_SSLhello {$protocolCipher."\|ServerKey"}.")"; # %s%s
                } else {
                    print "\n";
                }
            } else { # no RFC-Defined cipher
                printf "%-28s%s%-34s\n",
                    "NO-RFC-".$protocolCipher, $sep,            # %-28s%s
                    "NO-RFC-".$protocolCipher;                  # %-34ss
            }
        } else { # human readable output
               if ( (defined ($cipherHexHash {$protocolCipher}) ) && ($#{$cipherHexHash {$protocolCipher}}>0) ) { # definiert, max index >0
                    printf "# Cipher-String: >%s<, %-32s, %s",$protocolCipher, $cipherHexHash {$protocolCipher}[1], $cipherHexHash {$protocolCipher}[0];
               if (defined ($_SSLhello {$protocolCipher."\|ServerKey"})) { #length of dh_param
                    print  ", (".$_SSLhello {$protocolCipher."\|ServerKey"}.")";
               }
            } else {
                print  "# Cipher-String: >".$protocolCipher."<, NO-RFC-".$protocolCipher;
            }
            print "\n";
        }
    } # foreach my $protocolCipher ...
    if ($legacy eq 'compact') { # csv-style
        print "\n";
    }
    _trace4 ("printCipherStringArray: }\n\n");
    return;
} # printCipherStringArray


sub checkSSLciphers ($$$@) {
    #? simulate SSL handshake to check any ciphers by the HEX value
    #? @cipher_str_array: string representation of the cipher octet, e.g. >=SSLv3: 0x0300000Aa, SSLv2: 0x02800102
    #? if the first 2 ciphers are identical the array is sorted by priority of the server
    #
    my($host, $port, $ssl, @cipher_str_array) = @_;
#    my $host  = shift || "localhost"; # hostname
#    my $port  = shift || 443;
#    my $ssl   = shift || ""; # SSLv2
#    my (@cipher_str_array) = @_ || ();
    my $cipher_spec     = "";               # raw data with all hex values, SSLv2: 3 bytes, SSLv3 and later: 2 bytes
    my $acceptedCipher  = "";
    my @cipherSpecArray = ();               # temporary Array for all ciphers to be tested in the next _doCheckSSLciphers
    my @acceptedCipherArray = ();           # all ciphers accepted by the server
    my @acceptedCipherSortedArray = ();     # all ciphers accepted by the server with server order
    my $arrayLen = 0;
    my $i = 0;
    my $protocol = $PROTOCOL_VERSION{$ssl}; # 0x0002, 0x3000, 0x0301, 0x0302
    my $maxCiphers = $Net::SSLhello::max_ciphers;
    local $\ = ""; # no auto '\n' at the end of the line
    printParameters () if ($Net::SSLhello::trace >= 4);              # additional trace information
    
    OSaft::error_handler->reset_err( {module => (SSLHELLO), sub => 'checkSSLciphers', print => ($Net::SSLhello::trace > 0), trace => $Net::SSLhello::trace} );

    if ($Net::SSLhello::trace > 0) {
        _trace("checkSSLciphers ($host, $port, $ssl, Cipher-Strings:");
        foreach my $cipher_str (@cipher_str_array) {                         # $cipher_str: human readable in internal repesentation ('0x0300xxxx' or '0x02yyyyyy')
            _trace_ ("\n  ")  if (($i++) %_MY_PRINT_CIPHERS_PER_LINE == 0);  #  print up to '_MY_PRINT_CIPHERS_PER_LINE' ciphers per line
            _trace_ (" >$cipher_str<");
        }
        _trace_(") {\n");
    }

    if ($protocol == $PROTOCOL_VERSION{'SSLv2'}) { #SSL2
        _trace4_ ("\n");
        foreach my $cipher_str (@cipher_str_array) {
            _trace4 ("checkSSLciphers: Cipher-String: >$cipher_str< -> ");
            ($cipher_str) =~ s/(?:0x03|0x02|0x)?\s?([a-fA-F0-9]{2})\s?/chr(hex $1)/egx; ## Str2hex
            _trace4_ (" >". hexCodedCipher($cipher_str)."<\n");

            $cipher_spec .= $cipher_str; # collect cipher specs
        }
        _trace4_ ("\n");
        $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_spec);
        if ($Net::SSLhello::trace > 0) { #about: _trace
            $i = 0;
            my $anzahl = int length ($acceptedCipher) / 3;
            _trace(" checkSSLciphers: Accepted ". $anzahl ." Ciphers:\n");
            foreach my $cipher_str (compileSSL2CipherArray ($acceptedCipher) ) {
                _trace_ ("\n         ") if (($i++) %_MY_PRINT_CIPHERS_PER_LINE == 0); #  print up to '_MY_PRINT_CIPHERS_PER_LINE' ciphers per line
                _trace_ (" >" . $cipher_str . "<");
            }
            _trace_("\n");
            _trace(" checkSSLciphers: }\n\n");
        }
        return (compileSSL2CipherArray ($acceptedCipher));
    } else { # SSL3, TLS, DTLS .... check by the cipher
        $cipher_spec = ""; # collect cipher specs
        _trace4_ ("\n");
        foreach my $cipher_str (@cipher_str_array) {
            _trace4 ("checkSSLciphers: Cipher-String: >$cipher_str< -> ");
            if ($cipher_str !~ /0x02/x) { # No SSL2 cipher
                ($cipher_str) =~ s/(?:0x0[3-9a-fA-F]00|0x)?\s?([a-fA-F0-9]{2})\s?/chr(hex $1)/egx; ## Str2hex
                _trace4_ ("  >". hexCodedCipher($cipher_str)."<");
            } else {
                _trace4_ ("  SSL2-Cipher suppressed\n");
                next; # nothing to do for this cipher
            }
            _trace4_ ("\n");

            push (@cipherSpecArray, $cipher_str); # add cipher to next test
            $arrayLen = @cipherSpecArray;
            if ( $arrayLen >= $maxCiphers) { # test up to ... ciphers ($Net::SSLhello::max_ciphers = _MY_SSL3_MAX_CIPHERS) with 1 doCheckSSLciphers (=> Client Hello)
                $my_error = ""; # reset error message
                # reset error_handler and set basic information for this sub
                OSaft::error_handler->reset_err( {module => (SSLHELLO), sub => 'checkSSLciphers', print => ($Net::SSLhello::trace > 0), trace => $Net::SSLhello::trace} );
                $cipher_spec = join ("",@cipherSpecArray); # all ciphers to test in this round

                if ($Net::SSLhello::trace > 1) { # print ciphers that are tested this round:
                    $i = 0;
                    if ($Net::SSLhello::starttls) {
                        _trace1 ("checkSSLciphers ($host, $port (STARTTLS), $ssl): Checking ". scalar(@cipherSpecArray)." Ciphers, this round (1):");
                    } else {
                        _trace1 ("checkSSLciphers ($host, $port, $ssl): Checking ". scalar(@cipherSpecArray)." Ciphers, this round (1):");
                    }
                    _trace4_ ("\n");
                    foreach my $cipher_str (compileTLSCipherArray (join ("",@cipherSpecArray)) ) {
                        _trace_ ("\n  ") if (($i++) %_MY_PRINT_CIPHERS_PER_LINE == 0); #  print up to '_MY_PRINT_CIPHERS_PER_LINE' ciphers per line
                        _trace_ (" >" . $cipher_str . "<");
                    }
                    _trace2_ ("\n");
                }
                $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_spec, $dtlsEpoch); # test ciphers and collect accepted ciphers, $dtlsEpoch is only used in DTLS
                _trace2_ ("       ");
                if ($acceptedCipher) { # received an accepted cipher
                    _trace1_ ("=> found >0x0300".hexCodedCipher($acceptedCipher)."<\n");
                    if (grep { $_ eq $acceptedCipher } @cipherSpecArray) { #accepted cipher that was in the checklist
                        @cipherSpecArray = grep { $_ ne $acceptedCipher } @cipherSpecArray;    # delete accepted cipher from ToDo-Array '@cipherSpecArray'
                    } else { # cipher was *NOT* in the checklist
                        carp ("**WARNING: Server replied (again) with cipher '0x".hexCodedCipher($acceptedCipher)."' that has not been requested this time (1): ('0x".hexCodedCipher($cipherSpecArray[0])." ... 0x".hexCodedCipher($cipherSpecArray[-1])."'.");
                        @cipherSpecArray = (); # => Empty @cipherSpecArray
                     }
                    push (@acceptedCipherArray, $acceptedCipher); # add the cipher to the list of accepted ciphers
                } else { # no ciphers accepted
                    _trace1_ ("=> no Cipher found\n");
                if ( ((OSaft::error_handler->get_err_type()) <= (OERR_SSLHELLO_RETRY_HOST))
                     || ($my_error =~ /Fatal Exit/)
                     || ($my_error =~ /make a connection/ )
                     || ($my_error =~ /create a socket/) ) {
                        #### Fatal Errors -> Useless to check more protocols

                        _trace ("checkSSLciphers (1.1): '$my_error'\n") if ($my_error);
                        _trace ("**WARNING: checkSSLciphers => Exit loop (1.1): -> Abort '$host:$port' caused by ".OSaft::error_handler->get_err_str."\n");
                        @cipherSpecArray =(); # server did not accept any cipher => nothing to do for these ciphers => empty @cipherSpecArray
                        last;
                    } elsif ( ((OSaft::error_handler->get_err_type()) <= (OERR_SSLHELLO_RETRY_PROTOCOL))
                      || ($my_error =~ /answer ignored/)
                      || ($my_error =~ /protocol_version.*?not supported/)
                      || ($my_error =~ /check.*?aborted/x) ) { # Just stop, no warning
                        _trace2 ("checkSSLciphers (1.2): '$my_error'\n") if ($my_error);
                        @cipherSpecArray =(); # server did not accept any cipher => nothing to do for these ciphers => empty @cipherSpecArray
                        last;
                    } elsif ( ($my_error =~ /target.*?ignored/x) || ($my_error =~ /protocol.*?ignored/x) ) {   #### Fatal Errors -> Useless to check more ciphers
                        _trace2 ("checkSSLciphers (1.3): \'$my_error\'\n") if ($my_error);
                        carp ("**WARNING: checkSSLciphers => Exit Loop (1.3)");
                        @cipherSpecArray =(); # server did not accept any cipher => nothing to do for these ciphers => empty @cipherSpecArray
                        last;
                    } elsif ( ((OSaft::error_handler->get_err_type()) <= (OERR_SSLHELLO_RETRY_CIPHERS)) || ($my_error =~ /\-> Received NO Data/)) { # some servers 'Respond' by closing the TCP connection => check each cipher individually
                        if ($Net::SSLhello::noDataEqNoCipher == 1) { # ignore error messages for TLS intolerant servers that do not respond if non of the ciphers are supported
                            _trace2 ("checkSSLciphers (1.4): Ignore error messages for TLS intolerant servers that do not respond if non of the ciphers are supported. Ignored: '$my_error'\n");
                            @cipherSpecArray =(); # => empty @cipherSpecArray
                            $my_error = ""; # reset error message
                            next;
                        } else { # noDataEqNoCipher == 0
                            _trace2 ("checkSSLciphers (1.5): \'$my_error\', => Please use the option \'--noDataEqNoCipher\' for servers not answeing if none of the requested ciphers are supported. Retry to test the following cipheres individually:\n");
                            carp ("**WARNING: checkSSLciphers (1.5): \'$my_error\', => Please use the option \'--noDataEqNoCipher\' for servers not answeing if none of the requested ciphers are supported.");
                        }
                    } elsif ( ((OSaft::error_handler->get_err_type()) <= (OERR_SSLHELLO_RETRY_RECORD)) || ($my_error =~ /Error 1: too many requests/)) {   #### Too many connections: Automatic suspension and higher timeout did not help
                        _trace2 ("checkSSLciphers (1.6): \'$my_error\', => Please use the option \'--starttls_delay=SEC\' to slow down\n");
                        carp ("**WARNING: checkSSLciphers (1.6): \'$my_error\', => Please use the option \'--starttls_delay=SEC\' to slow down");
                        next;
                    } elsif ((OSaft::error_handler->is_err) || $my_error) { # Error found
                        unless (OSaft::error_handler->is_err) { # no error set, but no socket obtaied
                            OSaft::error_handler->new( {
                                type    => (OERR_SSLHELLO_ERROR_MESSAGE_IGNORED),
                                id      => '(1.9)',
                                message => "Unexpected Error Messagege ignored: \'$my_error\'",
                                warn    => 1,
                            } );
                        }
                        $my_error = ""; # reset error message
                        #reset error_handler and set basic information for this sub
                        OSaft::error_handler->reset_err( {module => (SSLHELLO), sub => 'checkSSLciphers', print => ($Net::SSLhello::trace > 0), trace => $Net::SSLhello::trace} );
                    } # else: no cipher accepted but no error
                    @cipherSpecArray =(); # => Empty @cipherSpecArray
                } # end: if 'no ciphers accepted'
            } # end: test ciphers
        } # end: foreach my $cipher_str...

        while ( (@cipherSpecArray > 0) && (!OSaft::error_handler->is_err) && (!$my_error) ) { # there are still ciphers to test in this last round
            $cipher_spec = join ("",@cipherSpecArray); # all ciphers to test in this round;
            if ($Net::SSLhello::trace > 1) { #print ciphers that are tested this round:
                $i = 0;
                _trace ("checkSSLciphers ($host, $port, $ssl): Checking ". scalar(@cipherSpecArray)." Ciphers, this round (2):");
                _trace4_ ("\n");
                foreach my $cipher_str (compileTLSCipherArray (join ("",@cipherSpecArray)) ) {
                    _trace_ ("\n  ") if (($i++) %_MY_PRINT_CIPHERS_PER_LINE == 0);  #  print up to '_MY_PRINT_CIPHERS_PER_LINE' ciphers per line
                    _trace_ ( " >" . $cipher_str . "<");
                }
                _trace2_ ("\n");
            }
            $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_spec, $dtlsEpoch); # test ciphers and collect Accepted ciphers
            _trace2_ ("       ");
            if ($acceptedCipher) { # received an accepted cipher ## TBD: Error handling using `given'/`when' TBD
                _trace1_ ("=> found >0x0300".hexCodedCipher($acceptedCipher)."<\n");
                if (grep { $_ eq $acceptedCipher } @cipherSpecArray) { # accepted cipher that was in the checklist
                    @cipherSpecArray = grep { $_ ne $acceptedCipher } @cipherSpecArray;    # delete accepted cipher from ToDo-Array '@cipherSpecArray'
                } else { # cipher was *NOT* in the checklist
                    carp ("**WARNING: Server replied (again) with cipher '0x".hexCodedCipher($acceptedCipher)."' that has not been requested this time (2): ('0x".hexCodedCipher($cipherSpecArray[0])." ... 0x".hexCodedCipher($cipherSpecArray[-1])."'.");
                    @cipherSpecArray = (); # => Empty @cipherSpecArray
                }
                push (@acceptedCipherArray, $acceptedCipher); # add the cipher to the list of accepted ciphers
            } else { # no cipher accepted
                _trace1_ ("=> no cipher found\n");
                if ( ($my_error =~ /Fatal Exit/) || ($my_error =~ /make a connection/ ) || ($my_error =~ /create a socket/) ) { #### Fatal Errors -> Useless to check more ciphers
                    _trace2 ("checkSSLciphers (2.1): '$my_error'\n");
                    carp ("**WARNING: checkSSLciphers => Exit Loop (2.1)");
                    @cipherSpecArray =(); # server did not accept any cipher => nothing to do for these ciphers => empty @cipherSpecArray
                    last;
                } elsif ( ($my_error =~ /answer ignored/) || ($my_error =~ /protocol_version.*?not supported/) || ($my_error =~ /check.*?aborted/) ) { # just stop, no warning
                    _trace1 ("**checkSSLciphers => Exit Loop (2.2)");
                    @cipherSpecArray =(); # server did not accepty any cipher => nothing to do for these ciphers => empty @cipherSpecArray
                    last;       # no more ciphers to test
                } elsif ( ($my_error =~ /target.*?ignored/x) || ($my_error =~ /protocol.*?ignored/x) ) {   #### Fatal Errors -> Useless to check more ciphers
                    _trace2 ("checkSSLciphers (2.3): '$my_error'\n");
                    carp ("**WARNING: checkSSLciphers => Exit Loop (2.3)");
                    @cipherSpecArray =(); # server did not accept any cipher => nothing to do for these ciphers => empty @cipherSpecArray
                    last;
                } elsif ( $my_error =~ /\-> Received NO Data/) { # some servers 'Respond' by closing the TCP connection => check each cipher individually
                    if ($Net::SSLhello::noDataEqNoCipher == 1) { # ignore error messages for TLS intolerant servers that do not respond if non of the ciphers are supported
                        _trace1 ("checkSSLciphers (2.4): Ignore Error Messages for TLS intolerant Servers that do not respond if non of the Ciphers are supported. Ignored: '$my_error'\n");
                        @cipherSpecArray =(); # => Empty @cipherSpecArray
                        $my_error = ""; # reset error message
                        next;   # here: eq last
                    } else {    # noDataEqNoCipher == 0
                        _trace2 ("checkSSLciphers (2.5): '$my_error', => Please use the option \'--noDataEqNoCipher\' for Servers not answering if none of the requested Ciphers are supported. Retry to test the following Cipheres individually:\n");
                        carp ("**WARNING: checkSSLciphers (2.5): '$my_error', => Please use the option \'--noDataEqNoCipher\' for Servers not answering if none of the requested Ciphers are supported.");
                    }
                } elsif ($my_error =~ /Error 1: too many requests/) {   #### Too many connections: Automatic suspension and higher timeout did not help
                    _trace2 ("checkSSLciphers (1.6): \'$my_error\', => Please use the option \'--starttls_delay=SEC\' to slow down\n");
                    carp ("**WARNING: checkSSLciphers (1.6): \'$my_error\', => Please use the option \'--starttls_delay=SEC\' to slow down");
                    next;
                } elsif ($my_error) {  # error found
                    _trace2 ("checkSSLciphers (2.6): Unexpected Error Messagege ignored: '$my_error'\n");
                    carp ("checkSSLciphers (2.6): Unexpected Error Messagege ignored: '$my_error'\n");
                    $my_error = ""; # reset error message
                }
                @cipherSpecArray =(); # => Empty @cipherSpecArray
            }
        } # end while ...

        if ($Net::SSLhello::trace > 0) {    # about: _trace
            $i = 0;
            _trace(" checkSSLciphers ($host, $port, $ssl): Accepted ". scalar(@acceptedCipherArray)." Ciphers (unsorted):");
            foreach my $cipher_str (compileTLSCipherArray (join ("",@acceptedCipherArray)) ) {
                _trace_ ("\n  ") if (($i++) %_MY_PRINT_CIPHERS_PER_LINE == 0); #  print up to '_MY_PRINT_CIPHERS_PER_LINE' ciphers per line
                _trace_ (" >" . $cipher_str . "<");
            }
            _trace_("\n");
        }

        # >>>>> Check priority of ciphers <<<<<
        ####################################################################################################################
        ######      Derzeit wird der 1. Cipher doppelt in die Liste eingetragen, wenn der Server die Prio vorgibt      #####
        ####################################################################################################################
        my $cipher_str = join ("",@acceptedCipherArray);
        printTLSCipherList ($cipher_str) if ($Net::SSLhello::trace > 3); # abt: _trace4

        while ($cipher_str) { # found some cipher => Check priority
            _trace2 ("checkSSLciphers: Check Cipher Prioity for Cipher-Spec >". hexCodedString($cipher_str)."<\n");
            $my_error = ""; # reset error message
            $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_str, $dtlsEpoch, 1); # collect accepted ciphers by priority
            _trace2_ ("#                                  -->". hexCodedCipher($acceptedCipher)."<\n");
            if ($my_error) {
                _trace2 ("checkSSLciphers (3): '$my_error'\n");
                # list untested ciphers
                $i = 0;
                my $str = ""; #output string with list of ciphers
                foreach my $cipher_str (compileTLSCipherArray (join ("",@acceptedCipherArray)) ) {
                    if (($i++) != 0) { # not 1st element
                        $str .= "\n  " if ($i %_MY_PRINT_CIPHERS_PER_LINE == 0); # 'print' up to '_MY_PRINT_CIPHERS_PER_LINE' ciphers per line
                        $str .= " ";
                    }
                    $str .= ">" . $cipher_str . "<";
                }
                # End: list untested ciphers
                if ( ($my_error =~ /Fatal Exit/) || ($my_error =~ /make a connection/ ) || ($my_error =~ /create a socket/) || ($my_error =~ /target.*?ignored/x) || ($my_error =~ /protocol.*?ignored/x) ) {
                    _trace1 ("checkSSLciphers (3.1): => Unexpected Loss of Connection while checking the priority of the ciphers \'$str\' -> Exit Loop. Reason: '$my_error'\n");
                    carp ("**WARNING: checkSSLciphers (3.1): => Unexpected Loss of Connection while checking the priority of the ciphers \'$str\' -> Exit Loop. Reason: '$my_error'");
                    $my_error = ""; # reset error message
                    last;
                } elsif ( ($my_error =~ /answer ignored/) || ($my_error =~ /protocol_version.*?not supported/) || ($my_error =~ /check.*?aborted/x) ) { # Just stop, no warning
                    _trace1 ("checkSSLciphers (3.2): => Unexpected Lack of Data or unexpected Answer while checking the priority of the ciphers \'$str\' -> Exit Loop. Reason: '$my_error'\n");
                    carp ("**WARNING: checkSSLciphers (3.2): => Unexpected Lack of Data or unexpected Answer while checking the priority of the ciphers \'$str\' -     > Exit Loop. Reason: '$my_error'");
                    _hint("The server may have an IPS in place. To slow down the test, consider adding the option '--connect-delay=SEC'.");
                    $my_error = ""; # reset error message
                    last;
                }
            }
            if ($acceptedCipher) { # received an accepted cipher
                push (@acceptedCipherSortedArray, $acceptedCipher); # add found cipher to sorted List
                $arrayLen = @acceptedCipherSortedArray;
                if ( $arrayLen == 1) { # 1st cipher
                    if ($acceptedCipher eq ($acceptedCipherArray[0])) { # is equal to 1st cipher of requested cipher_spec
                        _trace3    ("#   Got back 1st cipher of unsorted List => Check again with this Cipher >".hexCodedTLSCipher($acceptedCipher)."< at the end of the List\n");
                        shift (@acceptedCipherArray); # delete first cipher in this array
                        $cipher_str = join ("",@acceptedCipherArray).$acceptedCipher; # test again with the first cipher as the last
                        _trace3 ("Check Cipher Prioity for Cipher-S(2) > ". hexCodedCipher($cipher_str)."< ");
                        _trace4 ("\n");
                        $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_str, $dtlsEpoch, 1); # if server uses a priority List we get the same cipher again!
                        _trace3_ ("#                                  -->". hexCodedCipher($acceptedCipher)."<\n");
                        _trace4_ ("#                                 --->". hexCodedCipher($acceptedCipher)."<\n");
                        if ($acceptedCipher) { # received an accepted cipher ### TBD: if ($acceptedCipher eq ($acceptedCipherArray[0]) => no order => return (@acceptedCipherSortedArray[0].$acceptedCipherArray)
                            push (@acceptedCipherSortedArray, $acceptedCipher);
                        }
                    } else { # 1st element is nOT equal of 1st checked cipher => sorted => NOW: add cipher again to mark it as sorted list
                        push (@acceptedCipherSortedArray, $acceptedCipher); # add found cipher again to sorted List
                    }
                } # not the first cipher

                if ( (grep { $_ eq $acceptedCipher } @acceptedCipherArray) || (($arrayLen == 1) && ($acceptedCipher eq $acceptedCipherSortedArray[1])) ) { # accepted cipher was in the checklist
                    @acceptedCipherArray = grep { $_ ne $acceptedCipher } @acceptedCipherArray;    # delete accepted cipher in ToDo-Array '@acceptedCipherArray'
                } else { # cipher was *NOT* in the checklist
                    carp ("**WARNING: checkSSLciphers: Server replied (again) with cipher '0x".hexCodedCipher($acceptedCipher)."' that has not been requested this time (3): ('0x".hexCodedCipher($acceptedCipherArray[0])." ... 0x".hexCodedCipher($acceptedCipherArray[-1])."'. Untested Ciphers:");
                    # list untested ciphers
                    $i = 0;
                    my $str = ""; # output string with list of ciphers
                    foreach my $cipher_str (compileTLSCipherArray (join ("",@acceptedCipherArray)) ) {
                        if (($i++) != 0) { # not 1st element
                            $str .= "\n  " if ($i %_MY_PRINT_CIPHERS_PER_LINE == 0); # 'print' up to '_MY_PRINT_CIPHERS_PER_LINE' ciphers per line
                            $str .= " ";
                        }
                        $str .= ">" . $cipher_str . "<";
                    }
                    # End: list untested ciphers
                    @acceptedCipherArray = (); # => Empty @cipherSpecArray
                } # End cipher was *NOT* in the ckecklist

                $cipher_str = join ("",@acceptedCipherArray); # check prio for next ciphers
            } else { # nothing received => lost connection
                _trace2 ("checkSSLciphers (6): '$my_error'\n");
                # list untested ciphers
                $i = 0;
                my $str = ""; # output string with list of ciphers
                foreach my $cipher_str (compileTLSCipherArray (join ("",@acceptedCipherArray)) ) {
                    if (($i++) != 0) { # not 1st element
                        $str .= "\n  " if ($i %_MY_PRINT_CIPHERS_PER_LINE == 0); # 'print' up to '_MY_PRINT_CIPHERS_PER_LINE' ciphers per line
                        $str .= " ";
                    }
                    $str .= ">" . $cipher_str . "<";
                }
                # End: list untested ciphers
                if (  ($my_error =~ /Fatal Exit/) || ($my_error =~ /make a connection/ ) || ($my_error =~ /create a socket/) || ($my_error =~ /target.*?ignored/x) || ($my_error =~ /protocol.*?ignored/x) ) {
                    _trace1 ("checkSSLciphers (6.1): => Unexpected Loss of Connection while checking the priority of the ciphers \'$str\' -> Exit Loop. Reason: '$my_error'\n");
                    carp ("**WARNING: checkSSLciphers (6.1): => Unexpected Loss of Connection while checking the priority of the ciphers \'$str\' -> Exit Loop. Reason: '$my_error'");
                    $my_error = ""; # reset error message
                    last;
                } elsif ($my_error =~ /Error 1: too many requests/) {   #### Too many connections: Automatic suspension and higher timeout did not help
                    _trace2 ("checkSSLciphers (1.6): \'$my_error\', => Please use the option \'--starttls_delay=SEC\' to slow down\n");
                    carp ("**WARNING: checkSSLciphers (1.6): \'$my_error\', => Please use the option \'--starttls_delay=SEC\' to slow down");
                    next;
                } elsif ($my_error) { #any other Error like: #} elsif ( ( $my_error =~ /\-> Received NO Data/) || ($my_error =~ /answer ignored/) || ($my_error =~ /protocol_version.*?not supported/) || ($my_error =~ /check.*?aborted/) ) {
                    _trace1 ("checkSSLciphers (6.2): => Unexpected Lack of Data or unexpected Answer while checking the priority of the ciphers \'$str\' -> Exit Loop. Reason: ''\n");
                    carp ("**WARNING: checkSSLciphers (6.2): => Unexpected Lack of Data or unexpected Answer while checking the priority of the ciphers \'$str\' -> Exit Loop. Reason: '$my_error'");
                    _hint("The server may have an IPS in place. To slow down the test, consider adding the option '--connect-delay=SEC'.");
                    $my_error = ""; # reset error message
                    last;
                }
            }
        } # end while-Loop
    ###      _trace4 ("#   Accepted (sorted) Ciphers [cipher1 = cipher 2 => sorted by Server]:\n");
    ### TBD: _trace4: print all ciphers?!!
        _trace(" checkSSLciphers: }\n\n");
        return (compileTLSCipherArray (join ("",@acceptedCipherSortedArray)));
    }
} # checkSSLciphers


sub openTcpSSLconnection ($$) {
    #? open a TCP connection to a server and port and send STARTTLS if requested
    #? this SSL connection could be made via a http proxy
    my $host            = shift || ""; # hostname
    my $port            = shift || "";
    my $socket;
    my $connect2ip;
    my $alarmTimeout    = $Net::SSLhello::timeout +1; # 1 sec more than normal timeout as a time line of second protection
    my $proxyConnect    = "";
    my $clientHello     = "";
    my $input           = "";
    my $input2          = "";
    my $retryCnt        = 0;
    my $sleepSecs       =  $Net::SSLhello::starttlsDelay   || 0;
    my $slowServerDelay =  $Net::SSLhello::slowServerDelay || 0;
    my $suspendSecs     = 0;
    my $firstMessage    = "";
    my $secondMessage   = "";
    my $starttlsType=0; # SMTP
#   15 Types defined: 0:SMTP, 1:SMTP_2, 2:IMAP, 3:IMAP_CAPACITY, 4:IMAP_2, 5:POP3, 6:POP3_CAPACITY, 7:FTPS, 8:LDAP, 9:RDP, 10:RDP_SSL, 11:XMPP, 12:ACAP, 13:IRC, 14:IRC_CAPACITY
#
#   ##TBD new subs openTcpSSLconnectionViaProxy, openTcpSSLconnectionUsingStarttls
#
#    local $my_error = "" if (!defined($my_error));

    my @starttls_matrix =
        ( ["SMTP",
            ".*?(?:^|\\n)220\\s",                       # Phase1: receive '220 smtp.server.com Simple Mail Transfer Service Ready'
            "EHLO o-saft.localhost\r\n",                # Phase2: send    'EHLO o-saft.localhost\r\n'
            ".*?(?:^|\\n)250\\s",                       # Phase3: receive '250 smtp.server.com Hello o-saft.localhost'
            "STARTTLS\r\n",                             # Phase4: send    'STARTTLS'
            ".*?(?:^|\\n)220\\s",                       # Phase5: receive '220'
            ".*?(?:^|\\n)(?:421|450)\\s",               # Error1: temporary unreachable (too many connections); 450 Traffic is being throttled (connects per ip limit: ...), +454?
            ".*?(?:^|\\n)4[57]4\\s",                    # Error2: This SSL/TLS-Protocol is not supported 454 or 474
            ".*?(?:^|\\n)(?:451|50[023]|554)\\s",       # Error3: fatal Error/STARTTLS not supported: '500 Syntax error, command unrecognized', '502 Command not implemented', '503 TLS is not allowed',  554 PTR lookup failure ...
          ],
          ["SMTP_2",                                    # for servers that do *NOT* respond compliantly to RFC 821, or are too slow to get the last line:
                                                        # 'three-digit code' <SPACE> one line of text <CRLF> (at least the last line needs a Space after the numer, according to the RFC)
            ".*?(?:^|\\n)220",                          # Phase1: receive '220-smtp.server.com Simple Mail Transfer Service Ready' or '220 smtp.server.com ....'
            "EHLO o-saft.localhost\r\n",                # Phase2: send    'EHLO o-saft.localhost\r\n'
            ".*?(?:^|\\n)250",                          # Phase3: receive '250-smtp.server.com Hello o-saft.localhost'
            "STARTTLS\r\n",                             # Phase4: send    'STARTTLS'
            ".*?(?:^|\\n)220",                          # Phase5: receive '220-'
            ".*?(?:^|\\n)(?:421|450)",                  # Error1: temporary unreachable (too many connections); 450-Traffic is being throttled (connects per ip limit: ...), +454?
            ".*?(?:^|\\n)4[57]4",                       # Error2: This SSL/TLS-Protocol is not supported 454-or 474-
            ".*?(?:^|\\n)(?:451|50[023]|554)",          # Error3: fatal Error/STARTTLS not supported: '500-Syntax error, command unrecognized', '502-Command not implemented', '503-TLS is not allowed',  554-PTR lookup failure ...
          ],
          ["IMAP",                                      # according RFC2595; found good hints at 'https://github.com/iSECPartners/sslyze/blob/master/utils/SSLyzeSSLConnection.py'
            ".*?(?:^|\\n)\\*\\s*OK.*?IMAP(?:\\s|\\d)",  # Phase1: receive '* OK IMAP'
            "",                                         # Phase2: send    -unused-
            "",                                         # Phase2: receive -unused-
            "a001 STARTTLS\r\n",                        # Phase4: send    'STARTTLS'
            ".*?(?:^|\\n)(?:\\*|a001)\\s*OK\\s",        # Phase5: receive 'OK completed'
            "",                                         # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: This SSL/TLS-Protocol is not supported
            ".*?(?:^|\\n)(?:\\*|a00\\d)\\s*(?:BAD|NO)\\s.*?(?:invalid.+?command|unrecognized.+?command|TLS.*?(?:isn\\'t|not)|\\s+no\\s+.*?(?:SSL|TLS)|authoriz)", # Error3: fatal Error/STARTTLS not supported
          ],
          ["IMAP_CAPACITY",                             # according RFC2595; found good hints at 'https://github.com/iSECPartners/sslyze/blob/master/utils/SSLyzeSSLConnection.py'
            ".*?(?:^|\\n)\\*\\s*OK.*?IMAP(?:\\s|\\d)",  # Phase1: receive '* OK IMAP'
            "a001 CAPABILITY\r\n",                      # Phase2: send    view CAPABILITY (optional)
            ".*?(?:^|\\n)\\*\\s*CAPABILITY",            # Phase3: receive CAPABILITY-List should include STARTTLS
            "a002 STARTTLS\r\n",                        # Phase4: send    'STARTTLS'
            ".*?(?:^|\\n)(?:\\*|a002)\\s*OK\\s",        # Phase5: receive 'OK completed'
            "",                                         # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: This SSL/TLS-Protocol is not supported
            ".*?(?:^|\\n)(?:\\*|a00\\d)\\s*(?:BAD|NO)\\s.*?(?:invalid.+?command|unrecognized.+?command|TLS.*?(?:isn\\'t|not)|\\s+no\\s+.*?(?:SSL|TLS)|authoriz)", # Error3: fatal Error/STARTTLS not supported
          ],
          ["IMAP_2",                                    # found good hints at 'https://github.com/iSECPartners/sslyze/blob/master/utils/SSLyzeSSLConnection.py'
            ".*?(?:^|\\n)\\*\\sOK.*?IMAP(?:\\s|\\d)",   # Phase1: receive '* OK IMAP'
            "",                                         # Phase2: send    -unused-
            "",                                         # Phase3: receive -unused-
            ". STARTTLS\r\n",                           # Phase4: send    'STARTTLS'
            ".*?(?:^|\\n). OK\\s",                      # Phase5: receive '. OK completed'
            "",                                         # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: This SSL/TLS-Protocol is not supported
             ".*?(?:^|\\n)(?:\\*|a00\\d)\\s*(?:BAD|NO)\\s.*?(?:invalid.+?command|unrecognized.+?command|TLS.*?(?:isn\\'t|not)|\\s+no\\s+.*?(?:SSL|TLS)|authoriz)", # Error3: fatal Error/STARTTLS not supported
          ],
          ["POP3",                                      # according RFC2595; found good hints at 'https://github.com/iSECPartners/sslyze/blob/master/utils/SSLyzeSSLConnection.py'
            ".*?(?:^|\\n)\\+\\s*OK(?:\\s+|.*?ready|\\r|\\n)",   # Phase1: receive '+ OK...ready.'
            "",                                                 # Phase2: send    -unused-
            "",                                                 # Phase3: receive -unused-
            "STLS\r\n",                                         # Phase4: send    'STLS' (-> STARTTLS)'
            ".*?(?:^|\\n)\\+\\s*OK",                            # Phase5: receive '+OK Begin TLS'
            "",                                                 # Error1: temporary unreachable (too many connections);
            "",                                                 # Error2: This SSL/TLS-Protocol is not supported
            ".*?(?:^|\\n)\\-\\s*ERR.*?(?:invalid command|TLS.*?(?:isn\\'t|not)|\\s+no\\s+.*?(?:SSL|TLS)|authoriz)", # Error3: fatal Error/STARTTLS not supported: '-ERR TLS support isn't enabled'
          ],
          ["POP3_CAPACITY",                             # according RFC2595; found good hints at 'https://github.com/iSECPartners/sslyze/blob/master/utils/SSLyzeSSLConnection.py'
            ".*?(?:^|\\n)\\+\\s*OK(?:\\s+|.*?ready|\\r|\\n)",   # Phase1: receive '+ OK...ready.'
            "CAPA\r\n",                                         # Phase2: send view CAPABILITY (optional)
            ".*?(?:^|\\n)\\+\\s*OK",                            # Phase3: receive List of should include STLS
            "STLS\r\n",                                         # Phase4: send    'STLS' (-> STARTTLS)'
            ".*?(?:^|\\n)\\+\\s*OK",                            # Phase5: receive '+OK Begin TLS'
            "",                                                 # Error1: temporary unreachable (too many connections);
            "",                                                 # Error2: This SSL/TLS-Protocol is not supported
            ".*?(?:^|\\n)\\-\\s*ERR.*?(?:invalid command|TLS.*?(?:isn\\'t|not)|\\s+no\\s+.*?(?:SSL|TLS)|authoriz)", # Error3: fatal Error/STARTTLS not supported: '-ERR TLS support isn't enabled'
          ],
          ["FTPS",                                      # found good hints at 'https://github.com/iSECPartners/sslyze/blob/master/utils/SSLyzeSSLConnection.py'
            ".*?(?:^|\\n)220\\s",                       # Phase1: receive '220 ProFTPD 1.3.2rc4 Server (TJ's FTPS Server) [127.0.0.1]'
            "",                                         # Phase2: send view CAPABILITY (optional)
            "",                                         # Phase3: receive List of should include STLS
            "AUTH TLS\r\n",                             # Phase4: send    'AUTH TLS' (-> STARTTLS)'
            ".*?(?:^|\\n)234\\s+",                      # Phase5: receive '234 AUTH TLS successful'
            "",                                         # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: This SSL/TLS-Protocol is not supported
            "",                                         # Error3: fatal Error/STARTTLS not supported
          ],
          ["LDAP",                                      # found good hints at 'https://github.com/iSECPartners/sslyze/blob/master/utils/SSLyzeSSLConnection.py'$
            "",                                         # Phase1: receive -unused-$
            "",                                         # Phase2: send    -unused-$
            "",                                         # Phase3: receive -unused-$
            "0\x1d\x02\x01\x01w\x18\x80\x161.3.6.1.4.1.1466.20037", # Phase4: send    'STARTTLS'
            "0\\x24\\x02\\x01\\x01\\x78\\x1F\\x0A\\x01\\x00\\x04\\x00\\x04\\x00\\x8A\\x161\\.3\\.6\\.1\\.4\\.1\\.1466\\.20037",  # Phase5: receive 'Start TLS request accepted.'
            "",                                         # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: This SSL/TLS-Protocol is not supported
            "",                                         # Error3: fatal Error/STARTTLS not supported
          ],
          ["RDP",                                       # found good hints at 'https://github.com/iSECPartners/sslyze/blob/master/utils/SSLyzeSSLConnection.py'$
            "",                                         # Phase1: receive -unused-$
            "",                                         # Phase2: send    -unused-$
            "",                                         # Phase3: receive -unused-$
            "\x03\x00\x00\x13\x0E\xE0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x0B\x00\x00\x00", # Phase4: send    'STARTTLS'; http://msdn.microsoft.com/en-us/library/cc240500.aspx
            "\\x03\\x00\\x00\\x13\\x0E\\xD0.....\\x02.\\x08\\x00[\\x01\\x02\\x08]\\x00\\x00\\x00", # Phase5: receive 'Start TLS request accepted' = [PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX] http://msdn.microsoft.com/en-us/library/cc240506.aspx
            "",                                         # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: This SSL/TLS-Protocol is not supported
            "\\x03\\x00\\x00\\x13\\x0E\\xD0.....\\x03.\\x08\\x00[\\x01\\x02\\x08]\\x00\\x00\\x00", # Error3: fatal Error/STARTTLS not supported
          ], #  Typical ErrorMsg if STARTTLS is *not* supported:  ---> O-Saft::Net::SSLhello ::openTcpSSLconnection: ## STARTTLS (Phase 5): ... Received STARTTLS answer: 19 bytes
             #   >0x03 0x00 0x00 0x13 0x0E 0xD0 0x00 0x00 0x12 0x34 0x00 0x03 0x00 0x08 0x00 0x02 0x00 0x00 0x00 <  #### SSL_NOT_ALLOWED_BY_SERVER; http://msdn.microsoft.com/en-us/library/cc240507.aspx
          ["RDP_SSL",                                   # found good hints at 'https://github.com/iSECPartners/sslyze/blob/master/utils/SSLyzeSSLConnection.py'
            "",                                         # Phase1: receive -unused-$
            "",                                         # Phase2: send    -unused-$
            "",                                         # Phase3: receive -unused-$
            "\x03\x00\x00\x13\x0E\xE0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x01\x00\x00\x00", # Phase4: send    'STARTTLS' for latency RDP not supporting HYBRID modes
            "\\x03\\x00\\x00\\x13\\x0E\\xD0.....\\x02.\\x08\\x00[\\x01\\x02\\x08]\\x00\\x00\\x00", # Phase5: receive 'Start TLS request accepted' = [PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX]
            "",                                         # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: This SSL/TLS-Protocol is not supported
            "\\x03\\x00\\x00\\x13\\x0E\\xD0.....\\x03.\\x08\\x00[\\x01\\x02\\x08]\\x00\\x00\\x00", # Error3: fatal Error/STARTTLS not supported
          ],
          ["XMPP",                                      # according rfc3920; found good hints at 'https://github.com/iSECPartners/sslyze/blob/master/utils/SSLyzeSSLConnection.py'$
            "",                                                     # Phase1: receive -unused-$
            "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'".
             " to='".$host."' xml:lang='en' version='1.0'>",        # Phase2: send  Client initiates stream to server (no from to try to avoid to get blocked due to too much connects!)
##             " from='osaft\@im.owasp.org' to='".$host."' xml:lang='en' version='1.0'>", # Phase2: send  Client initiates stream to server
###          " xmlns:tls='http://www.ietf.org/rfc/rfc2595.txt' to='".$host."' xml:lang='en' version='1.0'>", # Phase2: send  Client initiates stream to server
            "<stream:stream.*?>",                                   # Phase3: receive response steam header
            "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",  # Phase4: send    'STARTTLS'$
            "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",   # Phase5: receive 'Start TLS request accepted.'
                                                                    # Errors: text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>You exceeded the number of connections/logins allowed in 60 seconds, good bye.</text>
            "",                                                     # Error1: temporary unreachable (too many connections);
            "",                                                     # Error2: This SSL/TLS-Protocol is not supported
            "",                                                     # Error3: fatal Error/STARTTLS not supported
          ],
          ["ACAP",                                      # according RFC2595; http://www.vocal.com/secure-communication/secure-acap-over-ssltls/
            ".*?(?:^|\\n)\\*\\s*OK.*?ACAP(?:\\s|\\d)",  # Phase1: receive '* OK ACAP'
            "",                                         # Phase2: send    -unused-
            "",                                         # Phase2: receive -unused-
            "a001 STARTTLS\r\n",                        # Phase4: send    'a001 STARTTLS'
            ".*?(?:^|\\n)(?:\\*|a001)\\s*OK\\s",        # Phase5: receive 'a001 OK (Begin TLS Negotiation)'
            "",                                         # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: This SSL/TLS-Protocol is not supported
            "",                                         # Error3: fatal Error/STARTTLS not supported
          ],
          ["IRC",                                               # according https://github.com/ircv3/ircv3-specifications/blob/master/extensions/tls-3.1 and
                                                                #           https://gist.github.com/grawity/f661adc10fb2d7a580ea
            ".*?NOTICE.*?",                                     # Phase1: receive ':<Server> NOTICE AUTH :*** No ident response; username prefixed with ~'
            "",                                                 # Phase2: send    -unused-
            "",                                                 # Phase2: receive -unused-
            "STARTTLS\r\n",                                     # Phase4: send    'STARTTLS'
            ".*?(?:^|\n)\\:.*?\\s670\\s+\\:STARTTLS\\s",        # Phase5: receive ':<Server> 670  :STARTTLS successful, go ahead with TLS handshake'
            ".*?(?:^|\n)ERROR\\s.*?too.*?(?:fast|much|many)",   # Error1: temporary unreachable (too many connections);
            "",                                                 # Error2: this SSL/TLS-Protocol is not supported
            ".*?(?:^|\\n)421\\s",                               # Error3: fatal Error/STARTTLS not supported: '421 ERR_UNKNOWNCOMMAND "<command> :Unknown command"'
          ],
          ["IRC_CAPACITY",                                      # according https://github.com/ircv3/ircv3-specifications/blob/master/extensions/tls-3.1 and
                                                                #           https://gist.github.com/grawity/f661adc10fb2d7a580ea
            ".*?NOTICE.*?",                                     # Phase1: receive ':<Server> NOTICE AUTH :*** No ident response; username prefixed with ~'
            "CAP LS\r\n",                                       # Phase2: send    view CAPABILITY (optional)
            ".*?(?:^|\n)\\:.*?\\sCAP\\s.*?\\:.*tls(?:\\s|$|\r\n)",    # Phase3: receive :<Server> CAP * LS :account-notify away-notify multi-prefix tls us     erhost-in-names
            "STARTTLS\r\n",                                     # Phase4: send    'STARTTLS'
            ".*?(?:^|\n)\\:.*?\\s670\\s+\\:STARTTLS\\s",        # Phase5: receive ':<Server> 670  :STARTTLS successful, go ahead with TLS handshake'
            ".*?(?:^|\n)ERROR\\s.*?too.*?(?:fast|much|many)",   # Error1: temporary unreachable (too many connections);
            "",                                                 # Error2: this SSL/TLS-Protocol is not supported
            ".*?(?:^|\\n)421\\s",                               # Error3: fatal Error/STARTTLS not supported: '421 ERR_UNKNOWNCOMMAND "<command> :Unknown command"'
          ],
          ["CUSTOM",                                            # CUSTOMize your own starttls sequence wit up to 5 phases
            "",                                                 # Phase1: receive <placeholder|-unused->
            "",                                                 # Phase2: send    <placeholder|-unused->
            "",                                                 # Phase2: receive <placeholder|-unused->
            "",                                                 # Phase4: send    <placeholder|-unused-> STARTTLS'
            "",                                                 # Phase5: receive <placeholder|-unused-> OK (Begin TLS Negotiation)'
            "",                                                 # Error1: temporary unreachable (too many connections): <placeholder|-unused->
            "",                                                 # Error2: this SSL/TLS-Protocol is not supported: <placeholder|-unused->
            "",                                                 # Error3: fatal Error/STARTTLS not supported: <placeholder|-unused->
          ],
        );

    my %startTlsTypeHash;
    local $my_error = ""; # reset error message
    OSaft::error_handler->reset_err( {module => (SSLHELLO), sub => 'openTcpSSLconnection', print => ($Net::SSLhello::trace > 0), trace => $Net::SSLhello::trace} );
    if ( ($Net::SSLhello::proxyhost) && ($Net::SSLhello::proxyport) ) { # via proxy
        _trace2 ("openTcpSSLconnection: Try to connect and open a SSL connection to $host:$port via proxy ".$Net::SSLhello::proxyhost.":".$Net::SSLhello::proxyport."\n");
    } else {
        _trace2 ("openTcpSSLconnection: Try to connect and open a SSL connection to $host:$port\n");
    }
    $retryCnt = 0;
    if ($Net::SSLhello::starttls)  {                            # starttls -> find STARTTLS type
        $startTlsTypeHash{$starttls_matrix[$_][0]} = $_ for 0 .. scalar(@starttls_matrix) - 1;
        _trace4 ("openTcpSSLconnection: nr of Elements in starttlsTypeMatrix: ".scalar(@starttls_matrix)."; looking for starttlsType $Net::SSLhello::starttlsType\n");

        if (defined($startTlsTypeHash{uc($Net::SSLhello::starttlsType)})) {
            $starttlsType = $startTlsTypeHash{uc($Net::SSLhello::starttlsType)};
            _trace4 ("openTcpSSLconnection: Index-Nr of StarttlsType $Net::SSLhello::starttlsType is $starttlsType\n");
            if ( grep {/^$starttlsType$/x} ('12', '13', '14','15') ) { # ('12', '13', ...) -> Use of an experimental STARTTLS type
                if  ($Net::SSLhello::experimental >0) {         # experimental function is are  activated
                    _trace_("\n");
                    _trace ("openTcpSSLconnection: WARNING: use of STARTTLS type $starttls_matrix[$starttlsType][0] is experimental! Send us feedback to o-saft (at) lists.owasp.org, please\n");
                } else {                                        # use of experimental functions is not permitted (option is not activated)
                    if ( grep {/^$starttlsType$/x} ('12', '13', '14', '15') ) { # experimental and untested
                        OSaft::error_handler->new( {
                            type    => (OERR_SSLHELLO_ABORT_PROGRAM),
                            id      => 'ckeck starttls type (1)',
                            message => "WARNING: use of STARTTLS type $starttls_matrix[$starttlsType][0] is experimental and *untested*!! Please take care! Please add option '--experimental' to use it. Please send us your feedback to o-saft (at) lists.owasp.org",
                            warn    => 1,
                        } );
                    } else {                                    # tested, but still experimental # experimental but tested
                        OSaft::error_handler->new( {
                            type    => (OERR_SSLHELLO_ABORT_PROGRAM),
                            id      => 'ckeck starttls type (2)',
                            message => "WARNING: use of STARTTLS type $starttls_matrix[$starttlsType][0] is experimental! Please add option '--experimental' to use it. Please send us your feedback to o-saft (at) lists.owasp.org",
                            warn    => 1,
                        } );
                    }
                    exit (1);                                   # stop program
                }
            }
            if ($starttls_matrix[$starttlsType][0] eq 'CUSTOM') { # customize the starttls_matrix
                for my $i (1..8) {
                    if (defined($Net::SSLhello::starttlsPhaseArray[$i])) {
                        _trace4 ("openTcpSSLconnection: Customize starttls_matrix: \$Net::SSLhello::starttlsPhaseArray[$i]= >$Net::SSLhello::starttlsPhaseArray[$i]< = hex: >".unpack("H*",$Net::SSLhello::starttlsPhaseArray[$i])."<\n");
                        if (($i == 2) || ($i == 4)) { #TX Data needs a different handling
                            $starttls_matrix[$starttlsType][$i] = "$Net::SSLhello::starttlsPhaseArray[$i]";
                            #($starttls_matrix[$starttlsType][$i]) =~ s/(\[^xc]|\c.)/chr(ord('$1'))/eg; ## escape2hex does not work
                            ($starttls_matrix[$starttlsType][$i]) =~ s/\\r/chr(13)/egx; ## return character
                            ($starttls_matrix[$starttlsType][$i]) =~ s/\\n/chr(10)/egx; ## new line character
                            ($starttls_matrix[$starttlsType][$i]) =~ s/\\t/chr(9)/egx;  ## tab character
                            ($starttls_matrix[$starttlsType][$i]) =~ s/\\e/chr(27)/egx; ## 'esc' character
                            ($starttls_matrix[$starttlsType][$i]) =~ s/\\x([a-fA-F0-9]{2})/chr(hex $1)/egx; ## Str2hex
                            ($starttls_matrix[$starttlsType][$i]) =~ s/\\\\/\\/gx;      ## escaping the escape character
                        } else { # normal copy
                            $starttls_matrix[$starttlsType][$i] = $Net::SSLhello::starttlsPhaseArray[$i];
                        }
                        _trace2 ("openTcpSSLconnection: Customize \$starttls_matrix[$starttlsType][$i]= >$starttls_matrix[$starttlsType][$i]< = hex: >".unpack("H*",$starttls_matrix[$starttlsType][$i])."<\n");
                    }
                }
            }
        } else {
            $starttlsType=0;
            carp ("openTcpSSLconnection: Undefined StarttlsType, use $starttls_matrix[$starttlsType][0] instead");
        }
    }

    RETRY_TO_OPEN_SSL_CONNECTION: { do { # connect to #server:port (via proxy) and open a ssl connection (use STARTTLS if activated)
        OSaft::error_handler->reset_err( {module => (SSLHELLO), sub => 'openTcpSSLconnection', print => ($Net::SSLhello::trace > 0), trace => $Net::SSLhello::trace} );
        if ( defined($Net::SSLhello::connect_delay) && ($Net::SSLhello::connect_delay > 0) ) {
            _trace_ ("\n");
            _trace  ("openTcpSSLconnection: connect delay $cfg{'connect_delay'} second(s)\n");
            sleep($Net::SSLhello::connect_delay);
            _trace4 ("openTcpSSLconnection: connect delay $cfg{'connect_delay'} second(s) [End]\n");
        }
        alarm (0); # switch off alarm (e.g. for  next retry )
        if ($retryCnt >0) { # retry
            _trace1_ ("\n") if (($retryCnt == 1) && ($main::cfg{'trace'} < 3)); # to catch up '\n' if 1st retry and trace-level is 2 (1 < trace-level < 3)
            if ( ($Net::SSLhello::proxyhost) && ($Net::SSLhello::proxyport) ) { # via proxy
                _trace1 ("openTcpSSLconnection: $retryCnt. Retry to connect and open a SSL connection to $host:$port via proxy ".$Net::SSLhello::proxyhost.":".$Net::SSLhello::proxyport);
                if ($retryCnt > $Net::SSLhello::retry) {
                    _trace1_ (" (this is an additional retry after suspension)");
                }
                _trace1_ ("\n");
            } else {
                _trace1 ("openTcpSSLconnection: $retryCnt. Retry to connect and open a SSL connection to $host:$port\n");
            }
        }
        if ($Net::SSLhello::starttls) {
            _trace ("openTcpSSLconnection: $host:$port: wait $sleepSecs sec(s) to prevent too many connects\n") if ( ($main::cfg{'trace'} >2) || ($sleepSecs > 0) );
            sleep ($sleepSecs);
        }

        { # >> start a block
            local $@ = "";
            eval {
                local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                alarm($alarmTimeout);                               # set Alarm for get-socket and set-socketoptions->timeout(s)
                socket($socket,PF_INET,SOCK_STREAM,(getprotobyname('tcp'))[2]) or croak "Can't create a socket \'$!\' -> target $host:$port ignored ";
                setsockopt($socket, SOL_SOCKET, SO_SNDTIMEO, pack('L!L!', $Net::SSLhello::timeout, 0) ) or croak "Can't set socket Sent-Timeout \'$!\' -> target $host:$port ignored"; #L!L! => compatible to 32 and 64-bit
                setsockopt($socket, SOL_SOCKET, SO_RCVTIMEO, pack('L!L!', $Net::SSLhello::timeout, 0) ) or croak "Can't set socket Receive-Timeout \'$!\' -> target $host:$port ignored";
                alarm (0);      # clear alarm
            } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {          # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                $my_error = $@;                                     # save the error message as soon as possible
                alarm (0);                                          # clear alarm if not done before
                OSaft::error_handler->new( {
                    type    => (OERR_SSLHELLO_RETRY_HOST),
                    id      => 'socket (1)',
                    message => $my_error,
                    warn    => 0,
                } );
                next RETRY_TO_OPEN_SSL_CONNECTION;                  # Error -> next retry
            }};                                                     # End of the section 'or do { if () { ...'. Do NOT forget the;
            alarm (0);                                              # clear alarm if not done before
        } # << end a block

        ######## Connection via a proxy ########
        if ( ($Net::SSLhello::proxyhost) && ($Net::SSLhello::proxyport) ) { # via proxy
            GET_PROXY_IP: { # >> start a block
                $my_error = "";
                $connect2ip = inet_aton($Net::SSLhello::proxyhost);
                if (!defined ($connect2ip) ) {                      # no IP address
                    $my_error = "Can't get the IP address of the proxy $Net::SSLhello::proxyhost:$Net::SSLhello::proxyport -> target $host:$port ignored";
                    carp "$my_error";
                    OSaft::error_handler->new( {
                        type    => (OERR_SSLHELLO_ABORT_HOST),
                        id      => 'get proxy IP',
                        message => $my_error,
                        warn    => 0,
                    } );
                    last RETRY_TO_OPEN_SSL_CONNECTION;              # retry
                }
            } # << end a block

            { # >> start a block
                $my_error = "";
                local $@ = "";
                eval {
                    local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                    alarm($alarmTimeout); # set Alarm for Connect
                    connect($socket, pack_sockaddr_in($Net::SSLhello::proxyport, $connect2ip) ) or croak "Can't make a connection to proxy $Net::SSLhello::proxyhost:$Net::SSLhello::proxyport -> target $host:$port ignored";
                    # TBD will be: TBD
                    # $sock = new IO::Socket::INET(
                    #   Proto     => "tcp",
                    #   PeerAddr => "$Net::SSLhello::proxyhost:$Net::SSLhello::proxyport",
                    #   Blocking  => 1, # Default
                    #   Timeout => $timeout,
                    # ) or die "Can't make a connection to proxy $Net::SSLhello::proxyhost:$Net::SSLhello::proxyport ($@, $!) -> target $host:$port ignored"; # error handling
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = $@;                                    # save the error message as soon as possible
                    alarm (0);                                          # clear alarm if not done before
                    OSaft::error_handler->new( {
                        type    => (OERR_SSLHELLO_RETRY_HOST),
                        id      => 'connection via proxy (1)',
                        message => $my_error,
                        warn    => 0,
                    } );
                    close ($socket) or carp("**WARNING: ". OSaft::error_handler->get_err_str() ."; Can't close socket, too: $!"); #tbd löschen ###
                    #_trace2 ("openTcpSSLconnection: $@ -> Fatal Exit in openTcpSSLconnection");
                    sleep (1);
                    # last; # no retry
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # next retry
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # clear alarm if not done before
            } # << end a block

            { # >> start a block
                $my_error = "";
                local $@ = ""; 
                eval {
                    $proxyConnect=_PROXY_CONNECT_MESSAGE1.$host.":".$port._PROXY_CONNECT_MESSAGE2;
                    _trace4 ("openTcpSSLconnection: ## ProxyConnect-Message: >$proxyConnect<\n");
                    local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                    alarm($alarmTimeout); # set Alarm for Connect
                    defined(send($socket, $proxyConnect, 0)) || croak "Can't make a connection to $host:$port via proxy $Net::SSLhello::proxyhost:$Net::SSLhello::proxyport [".inet_ntoa($connect2ip).":$Net::SSLhello::proxyport] -> target $host:$port ignored";
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = $@;                                 # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    OSaft::error_handler->new( {
                        type    => (OERR_SSLHELLO_RETRY_HOST),
                        id      => 'connection via proxy (2)',
                        message => $my_error,
                        warn    => 0,
                    } );
                    close ($socket) or carp("**WARNING: ". OSaft::error_handler->get_err_str() ."; Can't close socket, too: $!");
                    if (defined($slowServerDelay) && ($slowServerDelay>0)) {
                        _trace2 ("openTcpSSLconnection: via proxy $host:$port: wait $slowServerDelay sec(s) to wait for slow proxies\n");
                        sleep ($slowServerDelay);
                    }
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # retry
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # clear alarm if not done before
            } # << end a block

            { # start a block
                $my_error = "";
                local $@ = "";
                # CONNECT via proxy
                eval {
                    $input = "";
                    _trace2 ("openTcpSSLconnection ## CONNECT via proxy: try to receive the Connected-Message from the proxy $Net::SSLhello::proxyhost:$Net::SSLhello::proxyport, Retry = $retryCnt\n");
                    # select(undef, undef, undef, _SLEEP_B4_2ND_READ) if ($retryCnt > 0); # if retry: sleep some ms
                    osaft::osaft_sleep (_SLEEP_B4_2ND_READ) if ($retryCnt > 0); # if retry: sleep some ms
                    local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                    alarm($alarmTimeout);
                    recv ($socket, $input, 32767, 0);
                    if (length ($input)==0) { # did not receive a Message
                        _trace4 ("openTcpSSLconnection: ... Received Connected-Message from proxy (1a): received NO Data\n");
                        sleep(1) if ($retryCnt > 0);
                        # Sleep for 250 milliseconds
                        osaft::osaft_sleep (_SLEEP_B4_2ND_READ);
                        # select(undef, undef, undef, _SLEEP_B4_2ND_READ);
                        recv ($socket, $input, 32767, 0); # 2nd try
                        #### TBD TBD received NO Data TBD TBD ###
                    }
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = $@;                                 # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    OSaft::error_handler->new( {
                        type    => (OERR_SSLHELLO_RETRY_HOST),
                        id      => 'connection via proxy (3)',
                        message => $my_error,
                        warn    => 0,
                    } );
                    close ($socket) or carp("**WARNING: ". OSaft::error_handler->get_err_str() ."; Can't close socket, too: $!");
                    if (defined($slowServerDelay) && ($slowServerDelay>0)) {
                        _trace2 ("openTcpSSLconnection: via proxy $host:$port: wait $slowServerDelay sec(s) to wait for slow proxies\n");
                        sleep ($slowServerDelay);
                    }
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # retry
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # clear alarm if not done before
            } # << end a block

            if (length ($input) >0) { # got data
                _trace3 ("openTcpSSLconnection: ... Received data via proxy: ".length($input)." bytes\n          >".substr(_chomp_r($input),0,64)."< ...\n");
                _trace4 ("openTcpSSLconnection: ... Received data via proxy: ".length($input)." bytes\n          >"._chomp_r($input)."<\n");
                if ($input =~ /(?:^|\s)200\s/x) { # HTTP/1.0 200 Connection established\r\nProxy-agent: ... \r\n\r\n
                    $my_error = ""; # connection established
                    _trace2 ("openTcpSSLconnection: Connection established to $host:$port via proxy ".$Net::SSLhello::proxyhost.":".$Net::SSLhello::proxyport."\n");
                } else {
                    if ($Net::SSLhello::trace == 0) { # no trace => shorten the output
                        $input =~ /^((?:.+?(?:\r?\n|$)){1,4})/x; # maximal 4 lines
                        $input = _chomp_r($1);
                    }
                    OSaft::error_handler->new( {
                        type    => (OERR_SSLHELLO_RETRY_HOST),
                        id      => 'connection via proxy (4)',
                        message => "Can't make a connection to $host:$port via proxy $Net::SSLhello::proxyhost:$Net::SSLhello::proxyport; target ignored. Proxy error: ".$input, # error message received from the proxy
                        warn    => 0,
                    } );
                    close ($socket) or carp("**WARNING: ". OSaft::error_handler->get_err_str() ."; Can't close socket, too: $!");
                    if (defined($slowServerDelay) && ($slowServerDelay>0)) {
                        _trace2 ("openTcpSSLconnection: via proxy $host:$port: wait $slowServerDelay sec(s) to wait for slow proxies\n");
                        sleep ($slowServerDelay);
                    }
                    next RETRY_TO_OPEN_SSL_CONNECTION;
                }
            }
        } else { #### no proxy ####
            { # >> start a block
                $my_error = "";
                $connect2ip = inet_aton($host);
                if (!defined ($connect2ip) ) {                      # no IP address
                    $my_error = "Can't get the IP address of $host -> target $host:$port ignored in openTcpSSLconnection";
                    #croak "$my_error";
                    carp "$my_error";
                    OSaft::error_handler->new( {
                        type    => (OERR_SSLHELLO_ABORT_HOST),
                        id      => 'get host IP',
                        message => $my_error,
                        warn    => 0,
                    } );
                    last RETRY_TO_OPEN_SSL_CONNECTION;              # retry
                }
            } # << end a block

            { # >> start a block
                $my_error = "";
                local $@ = "";
                eval {
                    local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                    alarm($alarmTimeout);                           # set alarm for connect
                    connect( $socket, pack_sockaddr_in($port, $connect2ip) ) or croak "Can't make a connection to $host:$port [".inet_ntoa($connect2ip).":$port]; -> target ignored ";
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = $@;                                 # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    if (defined ($connect2ip) ) {
                        $my_error .= " -> No connection to $host:$port [".inet_ntoa($connect2ip).":$port]; -> target ignored in openTcpSSLconnection";
                    } else {
                        $my_error .= " -> No connection to $host:$port; -> target ignored in openTcpSSLconnection";
                    }
                    OSaft::error_handler->new( {
                        type    => (OERR_SSLHELLO_RETRY_HOST),
                        id      => 'connect (1)',
                        message => $my_error,
                        warn    => 0,
                    } );
                    close ($socket) or carp("**WARNING: ". OSaft::error_handler->get_err_str() ."; Can't close socket, too: $!");
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # retry
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # clear alarm if not done before
                _trace2 ("openTcpSSLconnection: Connected to server $host:$port\n");
            } # << end a block
        }

        if ( !(OSaft::error_handler->is_err) && ($Net::SSLhello::starttls) )  { # no Error and starttls ###############  Begin STARTTLS Support #############
            _trace2 ("openTcpSSLconnection: try to STARTTLS using the ".$starttls_matrix[$starttlsType][0]." protocol for server $host:$port, Retry = $retryCnt\n");
            # select(undef, undef, undef, _SLEEP_B4_2ND_READ) if ($sleepSecs > 0) || ($retryCnt > 0); # if slowed down or retry: sleep some ms
            if (($slowServerDelay > 0) || ($retryCnt > 0)) { # slow server or retry: sleep some secs
                _trace2 ("openTcpSSLconnection: $host:$port: wait ".($slowServerDelay||1)." sec(s) to cope with slow servers\n");
                sleep ($slowServerDelay||1); # sleep $slowServerDelay secs or min 1 sec
                #select(undef, undef, undef, _SLEEP_B4_2ND_READ) if ($retryCnt > 1); # if retry: sleep some ms
            }
            ### STARTTLS_Phase1 (receive)
            if ($starttls_matrix[$starttlsType][1]) {
                local $@ = "";
                eval {
                    $input = "";
                    _trace2 ("openTcpSSLconnection: ## STARTTLS (Phase 1): try to receive the ".$starttls_matrix[$starttlsType][0]."-Ready-Message from the Server $host:$port\n");
                    #select(undef, undef, undef, _SLEEP_B4_2ND_READ) if ($retryCnt > 0); # if retry: sleep some ms
                    osaft::osaft_sleep (_SLEEP_B4_2ND_READ) if ($retryCnt > 0); # if retry: sleep some ms
                    local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                    alarm($alarmTimeout);
                    recv ($socket, $input, 32767, 0); #|| die "openTcpSSLconnection: STARTTLS (Phase 1aa): Did *NOT* get any ".$starttls_matrix[$starttlsType][0]." Message from $host:$port\n"; # did not receive a Message ## unless seems to work better than if!!
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = "STARTTLS phase #1 failed): $@";    # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # Error -> next retry
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # clear alarm if not done before
                if (length ($input) >0) { # received Data => 220 smtp.server.com Simple Mail Transfer Service Ready?
                    _trace2 ("openTcpSSLconnection: ## STARTTLS (Phase 1):  ... Received ".$starttls_matrix[$starttlsType][0]."-Message (1): ".length($input)." bytes: >"._chomp_r($input)."<\n");
                    if ($input =~ /$starttls_matrix[$starttlsType][1]/) { # e.g. SMTP: 220 smtp.server.com Simple Mail Transfer Service Ready
                        $my_error = "";    # server is ready
                    } else {
                        $input=_chomp_r($input);
                        if ( ($starttls_matrix[$starttlsType][6]) && ($input =~ /$starttls_matrix[$starttlsType][6]/) ) {
                            # did receive a temporary error message
                            if ($retryCnt > $Net::SSLhello::retry) { # already an additional final retry -> restore last error message
                                $my_error = "STARTTLS (Phase 1): Error 1: too many requests: $host:$port \'$input\' -> suspend $suspendSecs second(s) and all subsequent packets will be slowed down by $sleepSecs second(s)";
                                last RETRY_TO_OPEN_SSL_CONNECTION;
                            }
                            $Net::SSLhello::starttlsDelay = $sleepSecs; # adopt global variable 1 step later
                            $sleepSecs += $retryCnt + 2;
                            $suspendSecs= 60 * ($retryCnt +1);
                            $my_error = "STARTTLS (Phase 1): Error 1: too many requests: $host:$port \'$input\' -> suspend $suspendSecs second(s) and all subsequent packets will be slowed down by $sleepSecs second(s)";
                            _trace2  ("openTcpSSLconnection: $my_error\n");
                            carp ("**WARNING: openTcpSSLconnection: ... $my_error"); #if ($retryCnt > 1); # warning if at least 2nd retry
                            close ($socket) or carp("**WARNING: STARTTLS: $my_error; Can't close socket, too: $!");
                            sleep($suspendSecs);
                            _trace4 ("openTcpSSLconnection: STARTTLS (Phase 1): End suspend\n");
                            if ($retryCnt == $Net::SSLhello::retry) { # signal to do an additional retry
                                $retryCnt++;
                                _trace4 ("openTcpSSLconnection: STARTTLS (Phase 1): 1 additional final retry after too many requests => retry number $retryCnt represented by $retryCnt+1\n");
                                redo RETRY_TO_OPEN_SSL_CONNECTION;      # extra retry
                            }
                            next RETRY_TO_OPEN_SSL_CONNECTION;          # next retry
                        } elsif ( ($starttls_matrix[$starttlsType][7]) && ($input =~ /$starttls_matrix[$starttlsType][7]/) ) { # did receive a protocol error message
                            OSaft::error_handler->new( {
                                type    => (OERR_SSLHELLO_ABORT_PROTOCOL),
                                id      => 'STARTTLS (Phase 1): Error 2',
                                message => "unsupported protocol: $host:$port \'$input\'",
                                warn    => 0,
                            } );
                            close ($socket) or carp("**WARNING: ". OSaft::error_handler->get_err_str() ."; Can't close socket, too: $!");
                            last;
                        } elsif ( ($starttls_matrix[$starttlsType][8]) && ($input =~ /$starttls_matrix[$starttlsType][8]/) ) { # did receive a fatal error message
                            $my_error = "STARTTLS (Phase 1): Error 3: Fatal Error: $host:$port \'$input\' -> target $host:$port ignored";
                            _trace2  ("openTcpSSLconnection: $my_error\n");
                            close ($socket) or carp("**WARNING: STARTTLS: $my_error; Can't close socket, too: $!");
                            last RETRY_TO_OPEN_SSL_CONNECTION;
                        } else {
                            if ($Net::SSLhello::trace == 0) {   # no trace => shorten the output
                                $input =~ /^(.+?)(?:\r?\n|$)/;  # maximal 1 line  of error message
                                $input = $1;
                                # if (($startType == x) || () ....) { $input = hexString ($input) } #
                            }
                            $my_error = "STARTTLS (Phase 1): Did *NOT* get a ".$starttls_matrix[$starttlsType][0]." Server Ready Message from $host:$port; target ignored. Server-Error: >"._chomp_r($input)."<"; # error message received from the server
                            _trace2 ("openTcpSSLconnection: $my_error\n");
                            close ($socket) or carp("**WARNING: STARTTLS: $my_error; Can't close socket, too: $!");
                            next RETRY_TO_OPEN_SSL_CONNECTION;   # next retry
                        }
                    }
                } else {
                    $my_error = ("STARTTLS (Phase 1): Did *NOT* get any ".$starttls_matrix[$starttlsType][0]." message from $host:$port -> slow down and try to retry target.");
                    _trace ("openTcpSSLconnection: $my_error\n");
                    $Net::SSLhello::starttlsDelay = $sleepSecs; # adopt global variable 1 step later
                    $sleepSecs += $retryCnt + 2;
                    close ($socket) or carp("**WARNING: openTcpSSLconnection: STARTTLS: $my_error; Can't close socket, too: $!");
                    next RETRY_TO_OPEN_SSL_CONNECTION;
                }
            } else {
                _trace2 ("openTcpSSLconnection: ## STARTTLS (Phase 1): Nothing to do for ".$starttls_matrix[$starttlsType][0]."\n");
            } # end-if $starttls_matrix[$starttlsType][1]

            ### STARTTLS_Phase2 (send) #####
            if ($starttls_matrix[$starttlsType][2]) {
                local $@ = "";
                eval {
                    _trace2 ("openTcpSSLconnection: ## STARTTLS (Phase 2): send $starttls_matrix[$starttlsType][0] Message: >"._chomp_r($starttls_matrix[$starttlsType][2])."<\n");
                    local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                    alarm($alarmTimeout); # set Alarm for Connect
                    defined(send($socket, $starttls_matrix[$starttlsType][2], 0)) || die  "Could *NOT* send $starttls_matrix[$starttlsType][0] message '$starttls_matrix[$starttlsType][2]' to $host:$port; target ignored\n";
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = "STARTTLS phase #2 failed): $@";    # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    _trace2 ("openTcpSSLconnection: $my_error\n");
                    close ($socket) or carp("**WARNING: openTcpSSLconnection: $my_error Can't close socket, too: $!");
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # next retry
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # clear alarm if not done before
                # wait before next read
                # select(undef, undef, undef, _SLEEP_B4_2ND_READ) if ($sleepSecs > 0) || ($retryCnt > 0); # if slowed down or retry: sleep some ms
                osaft::osaft_sleep (_SLEEP_B4_2ND_READ) if ($sleepSecs > 0) || ($retryCnt > 0); # if slowed down or retry: sleep some ms
                # select(undef, undef, undef, _SLEEP_B4_2ND_READ) if ($retryCnt > 1); # if retry: sleep some ms
                osaft::osaft_sleep (_SLEEP_B4_2ND_READ) if ($retryCnt > 1); # if retry: sleep some ms
            ### STARTTLS_Phase1 (receive)
            } else {
                _trace2 ("openTcpSSLconnection: ## STARTTLS (Phase 2): Nothing to do for ".$starttls_matrix[$starttlsType][0]."\n");
            } # end-if $starttls_matrix[$starttlsType][2]

            ### STARTTLS_Phase3: receive (SMTP) Hello Answer
            if ($starttls_matrix[$starttlsType][3]) {
                local $@ = "";
                eval {
                    $input = "";
                    _trace2 ("openTcpSSLconnection: ## STARTTLS (Phase 3): try to receive the $starttls_matrix[$starttlsType][0] Hello Answer from the Server $host:$port\n");
                    osaft::osaft_sleep (_SLEEP_B4_2ND_READ) if ($retryCnt > 0); # if retry: sleep some ms
                    # select(undef, undef, undef, _SLEEP_B4_2ND_READ) if ($retryCnt > 0); # if retry: sleep some ms
                    local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                    alarm($alarmTimeout);
                    recv ($socket, $input, 32767, 0);
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = "STARTTLS phase #3 failed): $@";    # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # Error -> next retry
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # clear alarm if not done before
                if (length ($input) >0) { # received Data => 250-smtp.server.com Hello o-saft.localhost?
                    _trace3 ("openTcpSSLconnection: ## STARTTLS (Phase 3): ... Received  $starttls_matrix[$starttlsType][0]-Hello: ".length($input)." bytes\n      >".substr(_chomp_r($input),0,64)." ...<\n");
                    _trace4 ("openTcpSSLconnection: ## STARTTLS (Phase 3):  ... Received  $starttls_matrix[$starttlsType][0]-Hello: ".length($input)." bytes\n      >"._chomp_r($input)."<\n");
                    if ($input =~ /$starttls_matrix[$starttlsType][3]/) { # e.g. SMTP: 250-smtp.server.com Hello o-saft.localhost
                        $my_error = "";                             # server is ready
                        _trace2 ("openTcpSSLconnection: ## STARTTLS (Phase 3): received a $starttls_matrix[$starttlsType][0] Hello Answer from the Server $host:$port: >"._chomp_r($input)."<\n");
                    } else {
                        $input=_chomp_r($input);
                        if ( ($starttls_matrix[$starttlsType][6]) && ($input =~ /$starttls_matrix[$starttlsType][6]/) ) { # did receive a temporary Error Message
                           if ($retryCnt > $Net::SSLhello::retry) { # already an additional final retry -> restore last error message
                                $my_error = "STARTTLS (Phase 3): Error 1: too many requests: $host:$port \'$input\' -> too many retries ($retryCnt)";
                                last RETRY_TO_OPEN_SSL_CONNECTION;
                            }
                            $Net::SSLhello::starttlsDelay = $sleepSecs; # adopt global variable 1 step later
                            $sleepSecs += $retryCnt + 2;
                            $suspendSecs= 60 * ($retryCnt +1);
                            $my_error = "STARTTLS (Phase 3): Error 1: too many requests: $host:$port \'$input\' -> suspend $suspendSecs second(s) and all subsequent packets will be slowed down by $sleepSecs second(s)";
                            _trace2  ("openTcpSSLconnection: $my_error\n");
                            carp ("**WARNING: openTcpSSLconnection: ... $my_error"); # if ($retryCnt > 1); # warning if at least 2nd retry
                            close ($socket) or carp("**WARNING: STARTTLS: $my_error; Can't close socket, too: $!");
                            sleep($suspendSecs);
                            _trace4 ("openTcpSSLconnection: STARTTLS (Phase 3): End suspend\n");
                            if ($retryCnt == $Net::SSLhello::retry) { # signal to do an additional retry
                                $retryCnt++;
                                _trace4 ("openTcpSSLconnection: STARTTLS (Phase 3): 1 additional final retry after too many requests => retry number $retryCnt represented by $retryCnt+1\n");
                            }
                            next RETRY_TO_OPEN_SSL_CONNECTION;
                        } elsif ( ($starttls_matrix[$starttlsType][7]) && ($input =~ /$starttls_matrix[$starttlsType][7]/) ) {
                            # did receive a protocol error message
                            OSaft::error_handler->new( {
                                type    => (OERR_SSLHELLO_ABORT_PROTOCOL),
                                id      => 'STARTTLS (Phase 3): Error 2',
                                message => "unsupported protocol: $host:$port \'$input\'",
                                warn    => 0,
                            } );
                            close ($socket) or carp("**WARNING: ". OSaft::error_handler->get_err_str() ."; Can't close socket, too: $!");
                            last RETRY_TO_OPEN_SSL_CONNECTION;
                        } elsif ( ($starttls_matrix[$starttlsType][8]) && ($input =~ /$starttls_matrix[$starttlsType][8]/) ) { # did receive a fatal error message
                            $my_error = "STARTTLS (Phase 3): Error 3: Fatal Error: $host:$port \'$input\' -> target $host:$port ignored";
                            _trace2  ("openTcpSSLconnection: $my_error\n");
                            close ($socket) or carp("**WARNING: STARTTLS: $my_error; Can't close socket, too: $!");
                            last RETRY_TO_OPEN_SSL_CONNECTION;
                        } else {
                            if ($Net::SSLhello::trace == 0) {       # no trace => shorten the output
                                $input =~ /^(.+?)(?:\r?\n|$)/x;     # maximal 1 line of error message
                                $input = $1;
                                # if (($startType == x) || () ....) { $input = hexString ($input) } #
                            }
                            $my_error = "STARTTLS (Phase 3): Did *NOT* get a $starttls_matrix[$starttlsType][0] Server Hello Answer from $host:$port; target ignored. Server-Error: >"._chomp_r($input)."<"; # error message received from the SMTP-Server
                            _trace2 ("openTcpSSLconnection: $my_error; try to retry\n");
                            close ($socket) or carp("**WARNING: STARTTLS: $my_error; Can't close socket, too: $!");
                            next RETRY_TO_OPEN_SSL_CONNECTION;
                        }
                    }
                } else { # did receive a message with length = 0 ?!
                    $my_error = ("STARTTLS (Phase 3): Did *NOT* get any answer to".$starttls_matrix[$starttlsType][0]." client message from $host:$port -> slow down and try to retry target.");
                    _trace ("openTcpSSLconnection: $my_error\n");
                    $Net::SSLhello::starttlsDelay = $sleepSecs; # adopt global variable 1 step later
                    $sleepSecs += $retryCnt + 2;
                     close ($socket) or carp("**WARNING: STARTTLS: $my_error; Can't close socket, too: $!");
                     next RETRY_TO_OPEN_SSL_CONNECTION; # next retry
                }
            } else {
                _trace2 ("openTcpSSLconnection: ## STARTTLS (Phase 3): Nothing to do for ".$starttls_matrix[$starttlsType][0]."\n");
            } # end-if $starttls_matrix[$starttlsType][3]

            #### STARTTLS_Phase4: Do STARTTLS
            if ($starttls_matrix[$starttlsType][4]) {
                local $@ = "";
                eval {
                    _trace2 ("openTcpSSLconnection: ## STARTTLS (Phase 4): $starttls_matrix[$starttlsType][0] Do STARTTLS message: >"._chomp_r($starttls_matrix[$starttlsType][4])."<\n");
                    local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                    alarm($Net::SSLhello::timeout); # set Alarm for Connect
                    defined(send($socket, $starttls_matrix[$starttlsType][4], 0)) || die "Could *NOT* send a STARTTLS message to $host:$port; target ignored\n";
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = "STARTTLS phase #4 failed): $@";    # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    _trace2 ("openTcpSSLconnection: $my_error\n");
                    close ($socket) or carp("**WARNING: openTcpSSLconnection: ## $my_error Can't close socket, too: $!");
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # next retry
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the;
                # wait before next read
                osaft::osaft_sleep (_SLEEP_B4_2ND_READ) if ($sleepSecs > 0) || ($retryCnt > 0); # if slowed down or retry: sleep some ms
                # select(undef, undef, undef, _SLEEP_B4_2ND_READ) if ($sleepSecs > 0) || ($retryCnt > 0); # if slowed down or retry: sleep some ms
                osaft::osaft_sleep (_SLEEP_B4_2ND_READ) if ($retryCnt > 1); # if retry: sleep some ms
                # select(undef, undef, undef, _SLEEP_B4_2ND_READ) if ($retryCnt > 1); # if retry: sleep some ms
             } else {
                _trace2 ("openTcpSSLconnection: ## STARTTLS (Phase 4): Nothing to do for ".$starttls_matrix[$starttlsType][0]."\n");
             } # endi-if $starttls_matrix[$starttlsType][4]

            #### STARTTLS_Phase 5: receive STARTTLS answer
            if ($starttls_matrix[$starttlsType][5]) {
                local $@ = "";
                eval {
                    $input = "";
                    _trace2 ("openTcpSSLconnection: ## STARTTLS (Phase 5): Try to receive the $starttls_matrix[$starttlsType][0] STARTTLS answer from the server $host:$port\n");
                    osaft::osaft_sleep (_SLEEP_B4_2ND_READ) if ($retryCnt > 0); # if retry: sleep some ms
                    # select(undef, undef, undef, _SLEEP_B4_2ND_READ) if ($retryCnt > 0); # if retry: sleep some ms
                    local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                    alarm($alarmTimeout);
                    recv ($socket, $input, 32767, 0);
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = "STARTTLS phase #5 failed): $@";    # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # Error -> next retry
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # clear alarm if not done before
                if (length ($input) >0)  { # received Data => 220
                    _trace3 ("openTcpSSLconnection: ## STARTTLS (Phase 5): ... Received STARTTLS-Answer: ".length($input)." bytes\n      >".substr(_chomp_r($input),0,64)." ...<\n");
                    _trace4 ("openTcpSSLconnection: ## STARTTLS (Phase 5): ... Received STARTTLS-Answer: ".length($input)." bytes\n      >"._chomp_r($input)."<\n");
                    if ($input =~ /$starttls_matrix[$starttlsType][5]/) { # e.g. SMTP: 220
                        $my_error = "";     # server is ready to do SSL/TLS
                        _trace2 ("openTcpSSLconnection: ## STARTTLS: Server is ready to do SSL/TLS\n");
                    } else {
                        $input=_chomp_r($input);
                        if ( ($starttls_matrix[$starttlsType][6]) && ($input =~ /$starttls_matrix[$starttlsType][6]/) ) { # did receive a temporary error message
                            if ($retryCnt > $Net::SSLhello::retry) { # already an additional final retry -> restore last error message
                                $my_error = "STARTTLS (Phase 5): Error 1: Too many requests: $host:$port \'$input\' -> suspend $suspendSecs second(s) and all subsequent packets will be slowed down by $sleepSecs second(s)";
                                last RETRY_TO_OPEN_SSL_CONNECTION;
                            }
                            $Net::SSLhello::starttlsDelay = $sleepSecs; # adopt global Variable 1 step later
                            $sleepSecs += $retryCnt + 2;
                            $suspendSecs = 60 * ($retryCnt +1);
                            $my_error = "STARTTLS (Phase 5): Error 1: Too many requests: $host:$port \'$input\' -> suspend $suspendSecs second(s) and all subsequent packets will be slowed down by $sleepSecs second(s)";
                            _trace2  ("openTcpSSLconnection: $my_error\n");
                            carp ("**WARNING: openTcpSSLconnection: ... $my_error"); # if ($retryCnt > 1); # warning if at least 2nd retry
                            close ($socket) or carp("**WARNING: STARTTLS: $my_error; Can't close socket, too: $!");
                            sleep($suspendSecs);
                            _trace4 ("openTcpSSLconnection: STARTTLS (Phase 5): End suspend\n");
                            if ($retryCnt == $Net::SSLhello::retry) { # signal to do an additional retry
                                $retryCnt++;
                                _trace4 ("openTcpSSLconnection: STARTTLS (Phase 5): 1 additional final retry after too many requests => retry number $retryCnt represented by $retryCnt+1\n");
                            }
                            next RETRY_TO_OPEN_SSL_CONNECTION;
                        } elsif ( ($starttls_matrix[$starttlsType][7]) && ($input =~ /$starttls_matrix[$starttlsType][7]/) ) {
                            # did receive a protocol error message
                            OSaft::error_handler->new( {
                                type    => (OERR_SSLHELLO_ABORT_PROTOCOL),
                                id      => 'STARTTLS (Phase 5): Error 2',
                                message => "unsupported protocol: $host:$port \'$input\'",
                                warn    => 0,
                            } );
                            close ($socket) or carp("**WARNING: ". OSaft::error_handler->get_err_str() ."; Can't close socket, too: $!");
                            last RETRY_TO_OPEN_SSL_CONNECTION;
                        } elsif ( ($starttls_matrix[$starttlsType][8]) && ($input =~ /$starttls_matrix[$starttlsType][8]/) ) { # did receive a Fatal Error Message
                            $my_error = "STARTTLS (Phase 5): Error 3: Fatal Error: $host:$port \'$input\' -> target $host:$port ignored";
                            _trace2  ("openTcpSSLconnection: $my_error\n");
                            close ($socket) or carp("**WARNING: STARTTLS: $my_error; Can't close socket, too: $!");
                            last RETRY_TO_OPEN_SSL_CONNECTION;
                        } else {
                            if ($Net::SSLhello::trace == 0) {   # no trace => shorten the output
                                $input =~ /^(.+?)(?:\r?\n|$)/x;  # maximal 1 line  of error message
                                $input = $1;
                                # if (($startType == x) || () ....) { $input = hexString ($input) } #
                            }
                            $my_error = "STARTTLS (Phase 5): Did *NOT* get a server SSL/TLS confirmation from $host:$port (retry: $retryCnt); target ignored. Server-Error: >"._chomp_r($input)."<"; # error message received from the SMTP-Server
                            _trace2 ("openTcpSSLconnection: ## $my_error; try to retry;\n");
                            close ($socket) or carp("**WARNING: STARTTLS: $my_error; Can't close socket, too: $!");
                            next RETRY_TO_OPEN_SSL_CONNECTION;
                        }
                    }
                } else { # did not receive a message
                    $my_error = ("STARTTLS (Phase 5): Did *NOT* get any answer to".$starttls_matrix[$starttlsType][0]." STARTTLS request from $host:$port -> slow down and try to retry target.");
                    _trace ("openTcpSSLconnection: $my_error\n");
                    $Net::SSLhello::starttlsDelay = $sleepSecs; # adopt global variable 1 step later
                    $sleepSecs += $retryCnt + 2;
                    close ($socket) or carp("**WARNING: STARTTLS: $my_error; Can't close socket, too: $!");
                    next RETRY_TO_OPEN_SSL_CONNECTION; # next retry
                }
            } else {
                _trace2 ("openTcpSSLconnection: ## STARTTLS (Phase 5): Nothing to do for ".$starttls_matrix[$starttlsType][0]."\n");
            } # end-if $starttls_matrix[$starttlsType][5]
        } ###############    End STARTTLS Support  ##################
    } while ( ($my_error) && ( ($retryCnt++ < $Net::SSLhello::retry) || ($retryCnt == $Net::SSLhello::retry + 2) ) ); } # 1 Extra retry if $retryCnt++ == $Net::SSLhello::retry +2
    if ($my_error) { #Error
        chomp($my_error);
        carp ("**WARNING: openTcpSSLconnection: $my_error");
        _trace2 ("openTcpSSLconnection: Exit openTcpSSLconnection }\n");
        return (undef);
    }
    alarm (0);   # race condition protection
    _trace2 ("openTcpSSLconnection: Connected to '$host:$port'\n");
    return ($socket);
} # openTcpSSLconnection


sub _doCheckSSLciphers ($$$$;$$) {
    #? simulate SSL handshake to check any ciphers by the HEX value
    #? called by checkSSLciphers to check some ciphers by the call
    #? if $parseAllRecords==0: solely the ServerHello is parsed to get the selected cipher from the server
    #? if $parseAllRecords >0: All other messages are received up to ServerHelloDone:
    #?                         Certificate:         not parsed in detail yet
    #?                         ServerKeyExchange:   optional message, parsed (if DH, ECDH or EXPORT-RSA Ciphers are used)
    #?                         CertificateRequest:  not parsed in detaili yet
    #?                         ServerHelloDone:     parsed (as trigger to end this function)
    #? $cipher_spec: RAW octets according to RFC
    #
    my $host         = shift || ""; # hostname
    my $port         = shift || 443;
    my $protocol     = shift || 0;  # 0x0002, 0x3000, 0x0301, 0x0302, 0x0303, etc
    my $cipher_spec  = shift || "";
    my $dtls_epoch   = shift || 0;  # optional, used in DTLS only
    my $parseAllRecords = shift || 0; # option to read, parse and analyze all received records (-> 1)
    my $socket;
    my $connect2ip;
    my $proxyConnect = "";
    my $clientHello  = "";
    my $input="";
    my $input2=""; ###
    my $pduLen=0;
    my $v2len=0; ###
    my $v2type=0; ###
    my $v3len=0; ###
    my $v3type=0; ###
    my $v3version=0; ###
    my ($recordType, $recordVersion, $recordLen, $recordEpoch, $recordSeqNr) = (0,0,0,0,0);
    my $recordData = "";
    my $acceptedCipher="";
    my $retryCnt = 0;
    my $firstMessage = "";
    my $secondMessage = "";
    my $segmentCnt=0;
    my $dtlsSequence = 0;
    my $dtlsCookieLen = 0;
    my $dtlsCookie = "";
    my $dtlsNewCookieLen = 0;
    my $dtlsNewCookie = "";
    my $alarmTimeout = $Net::SSLhello::timeout +1; # 1 sec more than normal timeout as a time line of second protection
    my $isUdp = 0; # for DTLS
    my $buffer = "";
    my $lastMsgType = $HANDSHAKE_TYPE {'<<undefined>>'}; # undefined message type
    my $lastRecordType = $RECORD_TYPE {'<<undefined>>'}; # undefined record type

    my %rhash = reverse %PROTOCOL_VERSION;
    my $ssl = $rhash{$protocol};
    if (! defined $ssl) {
        $ssl = "--unknown protocol--";
    }

    _trace4 (sprintf ("_doCheckSSLciphers ($host, $port, $ssl: >0x%04X<\n          >",$protocol).hexCodedString ($cipher_spec,"           ") .") {\n");
    local $my_error = ""; # reset error message
    OSaft::error_handler->reset_err( {module => (SSLHELLO), sub => '_doCheckSSLciphers', print => ($Net::SSLhello::trace > 0), trace => $Net::SSLhello::trace} );
    $isUdp = ( (($protocol & 0xFF00) == $PROTOCOL_VERSION{'DTLSfamily'}) || ($protocol == $PROTOCOL_VERSION{'DTLSv09'})  ); # udp for DTLS1.x or DTLSv09 (OpenSSL pre 0.9.8f)

    unless ($isUdp) { # NO UDP = TCP
        #### Open TCP connection (direct or via a proxy) and do STARTTLS if requested
        $socket=openTcpSSLconnection ($host, $port); # open TCP/IP, connect to the server (via proxy if needes) and STARTTLS if nedded
        if ( (!defined ($socket)) || (OSaft::error_handler->is_err()) || ($@) ) { # no SSL connection
            if ((OSaft::error_handler->get_err_type) == OERR_SSLHELLO_RETRY_HOST) { # no more retries
                OSaft::error_handler->new( {
                   type     => (OERR_SSLHELLO_ABORT_HOST),
#                   warn     => 1,
                } );
            }
            unless (OSaft::error_handler->is_err) { # no error set, but no socket obtaied
                OSaft::error_handler->new( {
                    type    => (OERR_SSLHELLO_ABORT_HOST),
                    id      => 'open TCP SSL connection (1)',
                    message => "WARNING: Did not get a valid SSL-socket from function openTcpSSLconnection -> fatal exit of openTcpSSLconnection", # generic error message
#                    warn    => 1,
                } );
            }
            return ("");
        }
    } else { # udp (no proxy nor STARTTLS)
        if ( defined($Net::SSLhello::connect_delay) && ($Net::SSLhello::connect_delay > 0) ) {
            _trace_ ("\n");
            _trace  ("_doCheckSSLciphers (udp): connect delay $cfg{'connect_delay'} second(s)\n");
            sleep($Net::SSLhello::connect_delay);
            _trace4 ("_doCheckSSLciphers (udp): connect delay $cfg{'connect_delay'} second(s) [End]\n");
        }
        { # >> start a block
            $my_error = "";
            $socket = IO::Socket::INET->new (
                Proto    => "udp",
                PeerAddr => "$host:$port",
                Timeout  => $Net::SSLhello::timeout,
                #Blocking  => 1, #Default
            ) or $my_error = " \'$@\', \'$!\'";
            if ( (!defined ($socket)) || ($my_error) ) { # no UDP socket
                OSaft::error_handler->new( {
                    type    => (OERR_SSLHELLO_ABORT_HOST),
                    id      => 'open UDP socket (1)',
                    message => "WARNING: Did not get a valid socket for UDP: $my_error -> fatal exit of _doCheckSSLciphers (udp)",
#                    warn    => 1,
                } );
                return ("");
            }
        } # << end a block
        _trace4 ("_doCheckSSLciphers: ## New UDP socket to >$host:$port<\n");
    } # end udp socket

    $retryCnt = 0;
    $my_error = ""; # reset error message
    RETRY_TO_EXCHANGE_CLIENT_AND_SERVER_HELLO: while ($retryCnt++ < $Net::SSLhello::retry) { # no error and still retries to go
        #### compile ClientHello
        $clientHello = compileClientHello ($protocol, $protocol, $cipher_spec, $host, $dtls_epoch, $dtlsSequence++, $dtlsCookieLen, $dtlsCookie);

        #### send ClientHello
        _trace3 ("_doCheckSSLciphers: sending Client_Hello\n      >".hexCodedString(substr($clientHello,0,64),"        ")." ...< (".length($clientHello)." bytes)\n\n");
        _trace4 ("_doCheckSSLciphers: sending Client_Hello\n          >".hexCodedString ($clientHello,"           ")."< (".length($clientHello)." bytes)\n\n");
        local $@ = "";
        eval {
            local $SIG{ALRM}= "Net::SSLhello::_timedOut";
            alarm($alarmTimeout); # set alarm for connect
            defined(send($socket, $clientHello, 0)) || die "Could *NOT* send ClientHello to $host:$port; $! -> target ignored\n";
            alarm (0);
        } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {              # End of eval section, begin of an error section ('or do'), that works for Windows, too.
            $my_error = "send client hello failed: $@";             # save the error message as soon as possible
            alarm (0);                                              # protection against race conditions
            OSaft::error_handler->new( {
                type    => (OERR_SSLHELLO_ABORT_HOST),
                id      => 'send client hello failed',
                message => $my_error,
                warn    => 0,
            } );
            return ("");
        }};                                                         # End of the section 'or do { if () { ...'. Do NOT forget the;
        alarm (0);                                                  # protection against race conditions

        ###### receive the answer (SSL+TLS: ServerHello, DTLS: Hello Verify Request or ServerHello)
        ###### Errors are reported in local $my_error
        ($input, $recordType, $recordVersion, $recordLen, $recordData, $recordEpoch, $recordSeqNr, $my_error) = _readRecord ($socket, $isUdp, $host, $port, $protocol);
        # error handling
        if ((OSaft::error_handler->get_err_type()) <= (OERR_SSLHELLO_RETRY_PROTOCOL)) {
            if ((OSaft::error_handler->get_err_type()) == (OERR_SSLHELLO_RETRY_HOST)) { # no more retries
                OSaft::error_handler->new( {
                    type     => (OERR_SSLHELLO_ABORT_HOST),         # upgrade error to abort
#                   warn     => 1,
                } );
            }
            _trace ("**WARNING: ".OSaft::error_handler->get_err_str."\n");
            return ("");
        }
        if ( ($my_error) && ((length($input)==0) && ($Net::SSLhello::noDataEqNoCipher==0)) ) {
            _trace2 ("_doCheckSSLciphers: ... Received Data: Got a timeout receiving Data from $host:$port (protocol: $ssl ".sprintf ("(0x%04X)",$protocol).", ".length($input)." bytes): Eval-Message: >$my_error<\n");
            carp ("**WARNING: _doCheckSSLciphers: ... Received Data: Got a timeout receiving Data from $host:$port (protocol: $ssl ".sprintf ("(0x%04X)",$protocol).", ".length($input)." bytes): Eval-Message: >$my_error<\n");
            return ("");
        } elsif (length($input) ==0) { # len == 0 without any timeout
            $my_error= "... Received NO Data from $host:$port (protocol: $ssl ".sprintf ("(0x%04X)",$protocol).") after $Net::SSLhello::retry retries; This may occur if the server responds by closing the TCP connection instead with an Alert. -> Received NO Data";
            _trace2 ("_doCheckSSLciphers: $my_error\n");
            return ("");
        } elsif ($my_error) { # any other error
             _trace2 ("_doCheckSSLciphers: Error-Message: $my_error\n");
            return ("");
        }
        _trace2("_doCheckSSLciphers: Server '$host:$port': (protocol $ssl [".sprintf ("0x%04X", $protocol)."], (record) type $recordType: received a record with ".length($recordData)." bytes payload (recordData) >".hexCodedString (substr($recordData,0,48),"       ")."< ...)     \n");

        if ($recordVersion <= 0) { # got no SSL/TLS/DTLS-PDU
            # Try to read the whole input buffer
            ($input, $my_error) = _readText ($socket, $isUdp, $input, "");

            if ($Net::SSLhello::starttls)  {
                if ($input =~ /(?:^|\s)554(?:\s|-)security.*?$/ix)  { # 554 Security failure; TBD: perhaps more general in the future
                _trace2  ("_doCheckSSLciphers ## STARTTLS: received SMTP Reply Code '554 Security failure': (Is the STARTTLS command issued within an existing TLS session?) -> input ignored and try to Retry\n");
                    # retry to send clientHello
                    $my_error = ""; # reset error message
                    $input = ""; # reset input data
                    $pduLen=0;
                    next; # retry to send and receive a SSL/TLS or DTLS-Packet
                }
            } elsif ($input =~ /(?:^|\s)220(?:\s|-).*?$/x)  { # service might need STARTTLS
                $my_error= "**WARNING: _doCheckSSLciphers: $host:$port looks like an SMTP-Service, probably the option '--starttls' is needed -> target ignored\n";
                carp ($my_error);
                return ("");
            }
            $my_error = "**WARNING: _doCheckSSLciphers: $host:$port dosen't look like a SSL or a SMTP-Service (1) -> Received data ignored -> target ignored\n";
            carp ($my_error);
            _trace_ ("\n") if ($retryCnt <=1);
            _trace ("_doCheckSSLciphers: Ignored data: ".length($input)." bytes\n        >".hexCodedString($input,"        ")."<\n        >"._chomp_r($input)."<\n");
            $input  = "";
            $pduLen = 0;
            return ("");
        }
        if (length($input) >0) {
            _trace2 ("_doCheckSSLciphers: Total data received: ". length($input). " bytes\n");
            ($acceptedCipher, $lastMsgType, $dtlsNewCookieLen, $dtlsNewCookie) = parseHandshakeRecord ($host, $port, $recordType, $recordVersion, $recordLen, $recordData, "", $protocol);
            if ((OSaft::error_handler->get_err_type()) <= (OERR_SSLHELLO_RETRY_PROTOCOL)) {
                if ((OSaft::error_handler->get_err_type()) == (OERR_SSLHELLO_RETRY_HOST)) { # no more retries
                    OSaft::error_handler->new( {
                        type     => (OERR_SSLHELLO_ABORT_HOST),
#                       warn     => 1,
                    } );
                }
                _trace ("**WARNING: ".OSaft::error_handler->get_err_str."\n");
                return ("");
            }

            if ( ($acceptedCipher ne "") && ($parseAllRecords > 0) && ($lastMsgType != $HANDSHAKE_TYPE {'server_hello_done'}) ) {
                _trace2 ("_doCheckSSLciphers: Try to get and parse next records\n");
                while ( (length($input) >0) && ($lastMsgType != $HANDSHAKE_TYPE {'server_hello_done'}) ) {
                    ###### receive next record
                    _trace2 ("_doCheckSSLciphers: receive next record\n");
                    $input = "";
                    ($input, $recordType, $recordVersion, $recordLen, $recordData, $recordEpoch, $recordSeqNr, $my_error) = _readRecord ($socket, $isUdp, $host, $port, $protocol);
                    last if ( (length($input)==0) || ($my_error) );
                    if ( ($lastMsgType == $HANDSHAKE_TYPE {'<<fragmented_message>>'}) && ($recordType == $lastRecordType) ) { # last message was fragmented
                        $recordData = $buffer.$recordData;
                        $recordLen += length($buffer);
                        _trace4 ("_doCheckSSLciphers: recompiled fragmented message -> compiled RecordLen: $recordLen\n");
                    }
                    # parse the next record (no cipher expected...)
                    ($buffer, $lastMsgType, $dtlsNewCookieLen, $dtlsNewCookie) = parseHandshakeRecord ($host, $port, $recordType, $recordVersion, $recordLen, $recordData, $acceptedCipher, $protocol); # get more information received together with the accepted cipher
                    $lastRecordType = $recordType; # only used for fragmented messages
                }
            }

            if ( ($acceptedCipher ne "") || (! $isUdp) ) {
                last;
            }
            if ($my_error ne "") {
                _trace4 ("_doCheckSSLciphers: Exit with Error: '$my_error'\n");
                return ("");
            }
            if ( ($dtlsNewCookieLen > 0) && $isUdp) {
                $dtlsCookieLen = $dtlsNewCookieLen;
                $dtlsCookie = $dtlsNewCookie;
                $dtlsNewCookieLen = 0;
                $dtlsNewCookie = "";
                _trace2 ("_doCheckSSLciphers: received a cookie ($dtlsCookieLen bytes): >".hexCodedString($dtlsCookie,"        ")."<\n");
                $retryCnt--;
            }
            _trace4 ("_doCheckSSLciphers: DTLS: sleep "._DTLS_SLEEP_AFTER_NO_CIPHERS_FOUND." sec(s) after *NO* cipher found\n");
            osaft::osaft_sleep (_DTLS_SLEEP_AFTER_NO_CIPHERS_FOUND); # sleep after NO cipher found
            # select(undef, undef, undef, _DTLS_SLEEP_AFTER_NO_CIPHERS_FOUND); # sleep after NO cipher found
        }
    } # end while (RETRY_TO_EXCHANGE_CLIENT_AND_SERVER_HELLO)

    if ($isUdp) { # reset DTLS connection using an alert record
        local $@ = "";
        eval {
            local $SIG{ALRM}= "Net::SSLhello::_timedOut";
            my $level = 2; #fatal
            my $description = 90; #### selected alert 90: user_canceled [RFC5246]
            alarm($alarmTimeout); # set alarm for connect
            defined(send($socket, compileAlertRecord ($protocol, $host, $level, $description, $dtls_epoch, $dtlsSequence++), 0)) || die "Could *NOT* send an alert record to $host:$port; $! -> Error ignored\n";
            alarm (0);
        } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {              # End of eval section, begin of an error section ('or do'), that works for Windows, too.
            $my_error = "reset DTLS failed: $@";                    # save the error message as soon as possible
            alarm (0);                                              # protection against race conditions
            OSaft::error_handler->new( {
                type    => (OERR_SSLHELLO_RETRY_PROTOCOL),
                id      => 'reset DTLS failed',
                message => $my_error,
                warn    => 0,
            } );
            # carp ("_doCheckSSLciphers: $my_error");
            return ("");
        }};                                                         # End of the section 'or do { if () { ...'. Do NOT forget the;
        alarm (0);                                                  # protection against race conditions
    }

    unless ( close ($socket)  ) {
        carp("**WARNING: _doCheckSSLciphers: Can't close socket: $!");
    }
    if (($isUdp) && (defined ($acceptedCipher) ) && ($acceptedCipher ne "") ) {
        _trace4 ("_doCheckSSLciphers: DTLS: sleep "._DTLS_SLEEP_AFTER_FOUND_A_CIPHER." sec(s) after received cipher >".hexCodedCipher($acceptedCipher)."<\n");
        # select(undef, undef, undef, _DTLS_SLEEP_AFTER_FOUND_A_CIPHER);
        osaft::osaft_sleep ( _DTLS_SLEEP_AFTER_FOUND_A_CIPHER);
    }
    _trace2 ("_doCheckSSLciphers: }\n");
    return ($acceptedCipher);
} # _doCheckSSLciphers


############################################################
sub _readRecord ($$;$$$$) {
    #? receive the answers:
    # Handshake:
    # 1) SSL+TLS: ServerHello, DTLS: Hello Verify Request or ServerHello
    # 2) Certificate
    # 3) Server Key Exchange (kEDH, kEECDH and ADH only)
    # 4) Client Certificate Request (optional)
    # 5) Server Hello Done
    #
    # or Error Messages
    #

    my $socket  = shift || "";
    my $isUdp   = shift || 0;
    my $host    = shift || ""; # for warn- and trace-messages
    my $port    = shift || ""; # for warn- and trace-messages
    my $client_protocol = shift || -1;  # optional

    my $MAXLEN  = 16384; # according RFC 5246: 16384 bytes for the packetData (without the packet header)
    my $pduLen  = 0;     # no PDUlen detected, yet
    my $readLen = ($isUdp) ? $MAXLEN : 7;
        # minimum len is:
        #    all readable octetts for UDP (-> MAXLEN),
        #    7 octetts for TCP (=len of an alert message);
        # remark rk: the minimum record len is 5 bytes, but it is better to
        #            read 7 bytes to get a compete alert message before any
        #            disconnects can occure #### was: $MAXLEN; # read up to MAXLEN Octetts
    my $len = 0;
    my $recordType      = 0;
    my $recordVersion   = 0;
    my $recordEpoch     = 0;
    my $recordSeqNr_null= 0; # (0x0000)
    my $recordSeqNr     = 0;
    my $my_error        = "";
    my $recordLen       = 0;
    my $recordData      = "";
    my $recordHeaderLen = 0;
    my ($rin, $rout);
    my $alarmTimeout    = $Net::SSLhello::timeout +1; # 1 sec more than normal timeout as a time line of second protection$
    my $retryCnt        = 0;
    my $segmentCnt      = 0;
    my $input           = "";
    my $input2          = "";
    my @socketsReady    = ();
    require IO::Select if ($Net::SSLhello::trace > 0);
    my $select; #used for tracing only
    $select = IO::Select->new if ($Net::SSLhello::trace > 0);
    my $success=0;
    $select->add($socket) if ($Net::SSLhello::trace > 0);

    #reset error_handler and set basic information for this sub
    OSaft::error_handler->reset_err( {module => (SSLHELLO), sub => '_readRecord', print => ($Net::SSLhello::trace > 0), trace => $Net::SSLhello::trace} );

    ###### receive the answer (SSL+TLS: ServerHello, DTLS: Hello Verify Request or ServerHello)
    vec($rin = '',fileno($socket),1 ) = 1; # mark SOCKET in $rin
    RETRY_TO_RECEIVE_A_RECORD: while ( ( (length($input) < $pduLen) || ($input eq "") ) && ($retryCnt++ <= $Net::SSLhello::retry) ) {
        if ($isUdp) { # #still use select for udp
            $my_error = "";
            local $@ = "";
            eval { # check this for timeout, protect it against an unexpected exit of the program
                # set alarm and timeout
                local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                alarm($alarmTimeout);
                # opimized with reference to 'https://github.com/noxxi/p5-ssl-tools/blob/master/check-ssl-heartbleed.pl'
                $success = select($rout = $rin,undef,undef,$Net::SSLhello::timeout);
                alarm (0); #clear alarm
            } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {          # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                $my_error = "failed to select data: $@";            # save the error message as soon as possible
                alarm (0);                                          # clear alarm if not done before
                OSaft::error_handler->new( {
                    type    => (OERR_SSLHELLO_RETRY_CIPHERS),
                    id      => '_readRecord (udp): unknown Timeout error (1)',
                    message => $my_error,
                    warn    => 0,
                } );
                carp ("_readRecord (udp): $my_error");
                _trace4 ("_readRecord (udp) from Server '$host:$port' -> LAST: Received (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($input)." bytes (from $pduLen expected) after $retryCnt tries:\n");
                last RETRY_TO_RECEIVE_A_RECORD;
            }};                                                     # End of the section 'or do { if () { ...'. Do NOT forget the;
            alarm (0);                                              # protection against race conditions
            if ( ! $success) { # nor data NEITHER special event => timeout
                OSaft::error_handler->new( {
                    type    => (OERR_SSLHELLO_RETRY_CIPHERS),
                    id      => '_readRecord (udp): Timeout error (1)',
                    message => $my_error,
                    warn    => 0,
                } );
                _trace4 ("_readRecord (udp): Server '$host:$port' -> Timeout (received nor data NEITHER special event) while reading a record with".length($input)." bytes (from $pduLen expected) after $retryCnt tries:\n");
                last RETRY_TO_RECEIVE_A_RECORD; # resend the UDP packet
            }
            if (vec($rout, fileno($socket),1)) { # got data
                local $@ = "";
                eval { # check this for timeout, protect it against an unexpected exit of the program
                    # set alarm and timeout
                    local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                    alarm($alarmTimeout);
                    @socketsReady = $select->can_read(0) if ($Net::SSLhello::trace > 3); ###additional debug (use IO::select needed)
                    _trace4 ("_readRecord (udp): can read (1): (Segement: $segmentCnt, retry: $retryCnt, position: ".length($input)." bytes)\n") if (scalar (@socketsReady));
                    $success = sysread ($socket, $input, $readLen - length($input), length($input)); #if NO success: EOF or other Error while reading Data
                    alarm (0); #clear alarm
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = "failed to read data with sysread: $@";     # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    OSaft::error_handler->new( {
                        type    => (OERR_SSLHELLO_RETRY_CIPHERS),
                        id      => '_readRecord (udp): unknown Timeout error (2)',
                        message => $my_error,
                        warn    => 0,
                    } );
                    carp ("_readRecord (udp): $my_error");
                    _trace4 ("_readRecord (udp) -> LAST: Received (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($input)." bytes (from $pduLen expected) after $retryCnt tries:\n");
                    last RETRY_TO_RECEIVE_A_RECORD;                 # resend the UDP packet
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # protection against race conditions
                @socketsReady = $select->can_read(0) if ($Net::SSLhello::trace > 3); ###additional debug (use IO::select needed)
                _trace4 ("_readRecord (udp) can read (2): (Segement: $segmentCnt, retry: $retryCnt, position: ".length($input)." bytes)\n") if (scalar (@socketsReady));
                if (! $success ) { # EOF or other Error while reading Data
                    if (length ($input) == 0) { # Disconnected, no Data
                        $my_error = "Server '$host:$port': received EOF (Disconnect), no Data\n";
                        OSaft::error_handler->new( {
                            type    => (OERR_SSLHELLO_RETRY_CIPHERS),
                            id      => '_readRecord (udp): no Data',
                            message => $my_error,
                            warn    => 0,
                        } );
                        _trace4 ("_readRecord (udp) : $my_error\n");
                        last RETRY_TO_RECEIVE_A_RECORD;
                    } else {
                        $my_error = "Server '$host:$port': No data (EOF) after ".length($input)." of expected $pduLen bytes: '$!' -> Retry to read\n";
                        OSaft::error_handler->new( {
                            type    => (OERR_SSLHELLO_RETRY_CIPHERS),
                            id      => '_readRecord (udp): EOF',
                            message => $my_error,
                            warn    => 0,
                        } );
                        _trace1 ("_readRecord (udp): $my_error\n");
                        @socketsReady = $select->can_read(0) if ($Net::SSLhello::trace > 1); ###additional debug (use IO::select needed)
                        _trace1 ("_readRecord (udp): can read (3): (Segement: $segmentCnt, retry: $retryCnt, position: ".length($input)." bytes)\n") if (scalar (@socketsReady));
                        #select (undef, undef, undef, _SLEEP_B4_2ND_READ);
                        osaft::osaft_sleep (_SLEEP_B4_2ND_READ);
                        next RETRY_TO_RECEIVE_A_RECORD;
                    }
                }
            } else {# got NO data
                $my_error = "Server '$host:$port': No data in _readRecord after reading $len of $pduLen expected bytes; $!";
                OSaft::error_handler->new( {
                    type    => (OERR_SSLHELLO_RETRY_CIPHERS),
                    id      => '_readRecord (udp): Received (no more) data',
                    message => $my_error,
                    warn    => 0,
                } );
                _trace1 ("_readRecord (udp): ... Received data: $my_error\n");
                _trace4 ("_readRecord (udp) :-> LAST: Received (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($input)." bytes (from $pduLen expected) after $retryCnt tries:\n");
                last RETRY_TO_RECEIVE_A_RECORD;
            } ###  End got Data
        } else { # TCP
            local $@ = "";
            eval { # check this for timeout, protect it against an unexpected exit of the program
                # set alarm and timeout
                local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                alarm($alarmTimeout);
                _trace4 ("_readRecord (tcp): try to recv (1): (Segement: $segmentCnt, retry: $retryCnt, position: ".length($input)." bytes)\n");
                $success = recv ($socket, $input2, $readLen - length($input), 0); #if NO success: $success undefined
                alarm (0); #clear alarm
            } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {          # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                $my_error = "failed to receive data (recv) $@";     # save the error message as soon as possible
                alarm (0);                                          # clear alarm if not done before
                OSaft::error_handler->new( {
                    type    => (OERR_SSLHELLO_RETRY_CIPHERS),
                    id      => '_readRecord (tcp): recv: unknown Timeout error',
                    message => $my_error,
                    warn    => 0,
                } );
                carp ("_readRecord (tcp): $my_error");
                _trace4 ("_readRecord (tcp): recv -> LAST: Received (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($input)." bytes (from $pduLen expected) after $retryCnt tries:\n");
                last RETRY_TO_RECEIVE_A_RECORD;
            }};                                                     # End of the section 'or do { if () { ...'. Do NOT forget the;
            alarm (0);                                              # protection against race conditions
            $input  .= $input2;                                     # append new input
            $success = length ($input2);                            # same usage as sysread
            _trace4 ("_readRecord (tcp): recv: (Segement: $segmentCnt, retry: $retryCnt, position: ".length($input)." bytes)\n");
        } # End TCP
        $len = length($input);
        if ($success) { # got new data
            if ($pduLen == 0) { # no PduLen decoded, yet
                _trace4 ("_readRecord (tcp): Server '$host:$port': ... Received first $len bytes to detect PduLen\n");
                if ( (! $isUdp) && ($len >= 5) ) { # try to get the pduLen of the SSL/TLS Pdu (=protocol aware length detection)
                    # Check PDUlen; parse the first 5 bytes to check the len of the PDU (SSL3/TLS)
                    ($recordType,       #C (record_type)
                     $recordVersion,    #n (record_version)
                     $recordLen,        #n (record_len)
                    ) = unpack("C n n", $input); # assuming to parse a SSLv3/TLS record, will be redone if it is SSLv2

                   if ( ($recordType < 0x80) && (($recordVersion & 0xFF00) == $PROTOCOL_VERSION{'SSLv3'} || $recordVersion == 0x0000) ) {
                        #SSLv3/TLS (no SSLv2 or 'dummy-Version 0x0000' if recoord version is not supported by the server)

                        _trace2_ (sprintf (
                         "# -->    => SSL3/TLS record type: >%02X<):\n".
                         "# -->    record_version:  >%04X<\n".
                         "# -->    record_len:      >%04X<\n",
                           $recordType,
                           $recordVersion,
                           $recordLen,
                        )); # if ($serverHello{'record_type'} == $RECORD_TYPE {'handshake'});
                        $recordHeaderLen = 5; # record data starts at position 6
                        _trace2 ("_readRecord (tcp): Server '$host:$port': ... Received data: Expected SSLv3/TLS-PDU-Len:");
                    } else { # Check for SSLv2 (parse the Inpit again)
                        ($recordLen,    # n (V2Len > 0x8000)
                         $recordType,   # C = 0
                        ) = unpack("n C", $input);
                        if ( ($recordLen > 0x8000) && (($recordType == $SSL_MT_SERVER_HELLO) || ($recordType == $SSL_MT_ERROR)) ) { # SSLv2 check
                            $recordLen     -= 0x8000;
                            $recordHeaderLen = 2; # Message Data starts at position 3
                            $pduLen         = $recordLen + $recordHeaderLen;
                            $recordVersion  = $PROTOCOL_VERSION{'SSLv2'}; # added the implicitely detected protocol
                            _trace2 ("_readRecord (tcp): Server '$host:$port': ... Received data: Expected SSLv2-PDU-Len:");
                        } else { ### no SSL/TLS/DTLS PDU => Last
                            $my_error = "no known SSL/TLS PDU type";
                            $recordType     = 0;
                            $recordVersion  = 0;
                            $recordLen      = 0;
                            _trace1 ("_readRecord (tcp): $my_error\n");
                            _trace4 ("_readRecord (tcp): -> LAST: received (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($input)." bytes (from $pduLen expected) after $retryCnt tries:\n");
                            last RETRY_TO_RECEIVE_A_RECORD;
                        }
                    }

                } elsif ( ($isUdp) && ($len >= 13) )  { # try to get the pduLen of the DTLS Pdu (=protocol aware length detection)
                    # check PDUlen; parse the first 13 bytes to check the len of the PDU (DTLS)
                    _trace2 ("_readRecord (udp): Server '$host:$port': Protocol: DTLS\n");
                    ($recordType,         # C
                     $recordVersion,      # n
                     $recordEpoch,        # n
                     $recordSeqNr_null,   # n (0x0000)
                     $recordSeqNr,        # N
                     $recordLen,          # n
                    ) = unpack ("C n n n N n", $input);

                    _trace2_ (sprintf (
                     "# -->    => DTLS record type: Handshake  (%02X):\n". ### only for handshake records that we analyze, yet
                     "# -->    record_version:    >%04X<\n".
                     "# -->    record_epoch:      >%04X<\n".        # n
                     "# -->    record_seqNr_null: >%04X<\n".        # n (0x0000)
                     "# -->    record_seqNr:  >%08X<\n".            # N
                     "# -->    record_len:        >%04X<\n",
                       $recordType,
                       $recordVersion,
                       $recordEpoch,                # n
                       $recordSeqNr_null,           # n (0x0000)
                       $recordSeqNr,                # N
                       $recordLen,                  # n
                    ));
                    if ( ($recordType < 0x80) && ( (($recordVersion & 0xFF00) == $PROTOCOL_VERSION{'DTLSfamily'}) # DTLS
                                                 || ($recordVersion == $PROTOCOL_VERSION{'DTLSv09'}) ) ) { # DTLS, or DTLSv09 (OpenSSL pre 0.9.8f)
                        $recordHeaderLen = 13; # record data starts at position 14
                        _trace2 ("_readRecord (udp): Server '$host:$port': ... Received data: Expected DTLS-PDU-Len:");
                    } else {
                        # isUdp is set, but no DTLS-Record recognized
                        $my_error = "Server '$host:$port': no known DTLS PDU type -> unknown protocol";
                        _trace1 ("_readRecord (udp): $my_error\n");
                        _trace1 ("_readRecord (udp): -> LAST: Received (record) type $recordType, -version: ".sprintf ("(0x%04X)", $recordVersion)." with ".length($input)." bytes (from $recordLen expected) after $retryCnt tries: reset all the mentioned parameters to 0\n");
                        $recordType     = 0;
                        $recordVersion  = 0;
                        $recordLen      = 0;
                        $pduLen         = 0;
                        $recordHeaderLen = 0;
                        last RETRY_TO_RECEIVE_A_RECORD;
                    }
                } # end: if DTLS

                $pduLen = $recordLen + $recordHeaderLen; # check PDUlen = len + size of record header;
                _trace2_ (" $pduLen (including the SSL/TLS header)\n");
                if ($recordLen > $MAXLEN) { # check the raw length without the specific size of the header
                    _trace1 ("_readRecord: Server '$host:$port': Expected len of the SSL/TLS record ($recordLen) is higher than the maximum ($MAXLEN) -> cut at maximum length!");
                    carp ("_readRecord: Server '$host:$port': Expected len of the SSL/TLS record ($recordLen) is higher than the maximum ($MAXLEN) -> cut at maximum length!");
                    $pduLen += -$recordLen +$MAXLEN; # => MAXLEN + size of record header
                }
                $readLen = $pduLen; # read only pduLen Octetts (-> only by one record)
                $retryCnt = 0 if ($readLen > 0); # detection of the recordLen is no retry -> reset counter
            } else {
                $segmentCnt++;
                _trace4 ("_readRecord: Server '$host:$port': ... Received $len bytes in $segmentCnt segment(s)\n");
                $retryCnt = 0 if ($segmentCnt <= _MAX_SEGMENT_COUNT_TO_RESET_RETRY_COUNT); # reset retry count to 0 (in next loop)
            }
            if (defined ($client_protocol)) {
                if ($client_protocol != $recordVersion) {
                    my %rhash = reverse %PROTOCOL_VERSION;
                    my $ssl_client = $rhash{$client_protocol};
                    my $ssl_server = $rhash{$recordVersion};
                    if (! defined $ssl_client) {
                        $ssl_client = "--unknown protocol--";
                    }
                    if (! defined $ssl_server) {
                        $ssl_server = "--unknown protocol--";
                    }
                    if ($recordVersion == 0) { # some servers respond with the dummy protocol '0x0000' if they do *not* support the requested protocol
                        OSaft::error_handler->new( {
                            type    => (OERR_SSLHELLO_ABORT_PROTOCOL),
                            id      => 'check record protocol (1)',
                            message => sprintf ("unsupported protocol $ssl_client (0x%04X) by $host:$port, answered with (0x%04X)", $client_protocol, $recordVersion),
                            warn    => 0,
                        } );
                    } else { # unknown protocol
                        OSaft::error_handler->new( {
                            type    => (OERR_SSLHELLO_ABORT_PROTOCOL),
                            id      => 'check record protocol (2)',
                            message => sprintf ("unsupported protocol $ssl_client (0x%04X) by $host:$port, answered with $ssl_server (0x%04X)", $client_protocol, $recordVersion),
                            warn    => 0,
                        } );
                    }
                    return ($input, $recordType, $recordVersion, 0, "", $recordEpoch, $recordSeqNr);
                }
            }
        }
    } # end while
    if (!($my_error) && (length($input) < $pduLen) ) { # no error, but the loop did *NOT* get all data within the maximal retries
        $my_error = "Server '$host:$port': Overrun the maximal number of $retryCnt retries in _readRecord after reading $len of $pduLen expected bytes in the ". $segmentCnt . "th segment; $!";
        _trace1 ("_readRecord ... Error receiving data: $my_error\n");
        _trace4 ("_readRecord -> LAST: Received (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($input)." bytes (from $pduLen expected) after $retryCnt tries:\n");
    }
    chomp ($my_error);

    if ($client_protocol >= 0) {
        _trace3("_readRecord: Server '$host:$port': (expected protocol= >".sprintf ("%04X", $client_protocol)."<,\n      (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($input)." bytes >".hexCodedString (substr($input,0,48),"       ")."< ...)\n");
    } else {
        _trace4("_readRecord: Server '$host:$port': (any protocol, (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($input)." bytes\n       Data=".hexCodedString ($input,"       ").")\n");
    }

    ($recordData) = unpack ("x[$recordHeaderLen] a*", $input);  # get recordData from input skipping the header
    if (length($recordData) != $recordLen) {
        _trace1 ("_readRecord: Server '$host:$port': (expected protocol= >".sprintf ("%04X", $client_protocol)."<, (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)
                .": recordLen ".sprintf ("%04X",length($recordData))." is not equal to the expected value ".sprintf ("%04X",$recordLen). "\n");
        carp    ("_readRecord: Server '$host:$port': (expected protocol= >".sprintf ("%04X", $client_protocol)."<, (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)
                .": recordLen ".sprintf ("%04X",length($recordData))." is not equal to the expected value ".sprintf ("%04X",$recordLen). "\n");
    }
    return ($input, $recordType, $recordVersion, $recordLen, $recordData, $recordEpoch, $recordSeqNr, $my_error); 
} # _readRecord


###############################################################
sub _readText ($;$) {
    #? receive the answer e. of a proxy or STARTTLS
    #
    my $socket = shift || "";
    my $isUdp = shift || 0;
    my $input = shift || ""; # input that has been read before
    my $my_local_error = "";
    my $untilFound = shift || "";
    my $len = 0;
    my $MAXLEN= 32767;
    my $alarmTimeout = $Net::SSLhello::timeout +1; # 1 sec more than normal timeout as a time line of second protection
    my ($rin, $rout);
    my $input2 = "";
    my $retryCnt = 0; # 1st read with up to 5 bytes will be not counted

    ###### receive the answer
    vec($rin = '',fileno($socket),1 ) = 1; # mark SOCKET in $rin
RECEVICE_ANSWER:
    while ( ($untilFound) && ( ! m {\A$untilFound\Z}) ) {{
        $my_local_error = "";
        local $@ = "";
        eval { # check this for timeout, protect it against an unexpected exit of the program
            # set alarm and timeout
            local $SIG{ALRM}= "Net::SSLhello::_timedOut";
            alarm($alarmTimeout);
            # Opimized with reference to 'https://github.com/noxxi/p5-ssl-tools/blob/master/check-ssl-heartbleed.pl'
            if ( ! select($rout = $rin,undef,undef,$Net::SSLhello::timeout) ) { # Nor data NEITHER special event => Timeout
                alarm (0); #clear alarm
                $my_local_error = "Timeout in _readText $!";
                last RECEVICE_ANSWER;
            }
            alarm (0); #clear alarm
        } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {              # End of eval section, begin of an error section ('or do'), that works for Windows, too.
            $my_local_error = "failed to select text: $@"
        }};                                                         # End of the section 'or do { if () { ...'. Do NOT forget the;
        #$my_error .= $@;                                           # save the error message as soon as possible
        alarm (0);                                                  # protection against race conditions
        if ($my_local_error) {
            $my_local_error = "_readText: unknown Timeout-Error (1): $my_error";
             carp ("_readText: $my_local_error");
             return ($input, $my_local_error);
        }
        if (vec($rout, fileno($socket),1)) { # got data
            local $@ = "";
            eval { # check this for timeout, protect it against an unexpected exit of the program
                # set alarm and timeout
                local $SIG{ALRM}= "Net::SSLhello::_timedOut";
                alarm($alarmTimeout);
                ## read only up to 5 bytes in the first round, then up to the expected pduLen
                recv($socket, $input2, $MAXLEN - length($input), 0 );  # EOF or other Error while reading data
                $input .= $input2;
                alarm (0); # clear alarm
            } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {          # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                $my_error = "failed to receice text: $@"
            }};                                                     # End of the section 'or do { if () { ...'. Do NOT forget the;
            #$my_error .= $@;                                        # save the error message as soon as possible
            alarm (0);                                              # protection against race conditions
            if ($my_local_error) {
                $my_local_error = "_readText unknown Timeout-Error (2): $my_error";
                 carp ("_readText: $my_local_error");
                 last RECEVICE_ANSWER;
            }
            if ($len <= 0) { # error no data
                $my_local_error = "NULL-Len-Data in _readText $!";
                _trace1 ("_readText: $my_local_error\n");
                last RECEVICE_ANSWER;
            }
        } else {# got NO (more) data
            last RECEVICE_ANSWER;
        }
        if ($retryCnt++ < $Net::SSLhello::retry) {
            $my_local_error = "Retry-Counter exceeded $Net::SSLhello::retry while reading Text";
            _trace1 ("_readText: $my_local_error\n");
            last;
        }
    }}
    alarm (0);   # race condition protection
    chomp ($my_local_error);
    $my_error = $my_local_error if (defined($my_error));
    return ($input, $my_local_error);
} # _readText


############################################################
sub compileClientHello ($$$$;$$$$) {
    #? compile a Client Hello Packet
    #
    my $record_version = shift || "";
    my $version        = shift || "";
    my $ciphers        = shift || "";
    my $host           = shift || "";
    my $dtls_epoch     = shift || 0; # optional
    my $dtls_sequence  = shift || 0; # optional
    my $dtls_cookieLen = shift || 0; # optional
    my $dtls_cookie    = shift || ""; # optional
    my $clientHello    = "";         # return value
    my $clientHello_tmp = "";
    my $clientHello_extensions = "";
    my $challenge      = $CHALLENGE; # 16-32 bytes,
    my $i; #counter
    my %rhash = reverse %PROTOCOL_VERSION;
    my $ssl   = $rhash{$version};

    _trace4 (sprintf("compileClientHello (%04X, %04X,\n          >%s<, %s) {\n", $record_version, $version, hexCodedString ($ciphers,"           "), $host) );

    $challenge= pack("Na[28]", time(), $challenge); # 4 bytes: uint32 gmt_unix_time;, 28 byte random
    _trace4_("#   --->   challenge >".hexCodedString ($challenge)."<\n");

    my %clientHello =  ( #V2ClientHello
        'record_type'            => $RECORD_TYPE {'handshake'},# from SSL3:  Handshake (22=0x16) #uint8
        'record_version'         => $record_version,           # from SSL3:  #uint16
        'record_epoch'           => 0x0000,                    # DTLS only:  #uint16
        'record_seqNr'           => 0x000000,                  # DTLS only:  #uint24 (!)
        'record_len'             => 0x0000,                    # from SSL3:  #uint16
        'msg_type'               => $SSL_MT_CLIENT_HELLO,      # 0x01        #uint8
        'msg_len'                => 0x000000,                  # SSL2: uint16 | 0x8000, from SSL3: uint24 (!)
        'msg_seqNr'              => 0x0000,                    # DTLS only:  #uint16
        'fragment_offset'        => 0x000000,                  # DTLS only:  #uint24 (!)
        'fragment_len'           => 0x000000,                  # DTLS only:  #uint24 (!)
        'version'                => $version,                  # SSL2:0x0002,SSL3:0x3000,TLS1:0x0301 #uint16
        'cipher_spec_len'        => length($ciphers),          # uint16
        'session_id_len'         => 0x0000,                    # uint16
        'cookie_len'             => 0x00,                      # DTLS only:  #uint8
        'cookie'                 => "",                        # DTLS only: 0.32 bytes (rfc 4347)
        'challenge_len'          => length($challenge),        # uint16
        'cipher_spec'            => $ciphers,                  # sslv2: 3 bytes, SSL3/TLS: 2 bytes
        'session_id'             => "",                        # client_helo => len=0,
        'challenge'              => $challenge,                # 16-32 bytes | SSL3/TLS: 32 bytes
        'compression_method_len' => 0x01,                      # len = 1
        'compression_method'     => 0x00,                      # SSL3/TLS1.x 00
    );

    if ($version == $PROTOCOL_VERSION{'SSLv2'}) { #SSL2
        _trace2 ("compileClientHello: Protocol: SSL2\n");

        $clientHello_tmp = pack ("C n n n n a* a*",
            $clientHello{'msg_type'},       #C
            $clientHello{'version'},        #n
            $clientHello{'cipher_spec_len'},#n
            $clientHello{'session_id_len'}, #n
            $clientHello{'challenge_len'},  #n
            $clientHello{'cipher_spec'},    #A
####           $clientHello{'session_id'},      # len = 0
            $clientHello{'challenge'},      #A
        );

        $clientHello{'msg_len'} = length ($clientHello_tmp) | 0x8000;

          _trace2_ (
            sprintf (
              "# --> msg_len \| 0x8000 (added): >%04X<\n".
              "# --> msg_type:          >%02X<\n".
              "# --> version:         >%04X< (%s)\n".
              "# --> cipher_spec_len: >%04X<\n".
              "# --> session_id_len:  >%04X<\n".
              "# --> challenge_len:   >%04X<\n".
              "# --> cipher_spec:     >%s<\n".
              "# --> session_id:      >%s<\n".
              "# --> challenge:       >%s<\n",
              $clientHello{'msg_len'},
              $clientHello{'msg_type'},
              $clientHello{'version'},
              $ssl,
              $clientHello{'cipher_spec_len'},
              $clientHello{'session_id_len'},
              $clientHello{'challenge_len'},
              hexCodedString ($clientHello{'cipher_spec'},"                       >"),
              hexCodedString ($clientHello{'session_id'}),
              hexCodedString ($clientHello{'challenge'})
            )
        );

          if  (($Net::SSLhello::trace > 3)) {
            printSSL2CipherList ($clientHello{'cipher_spec'});
        }

        $clientHello = pack ("n a*",
            $clientHello{'msg_len'},
              $clientHello_tmp,
        );

        _trace4 (sprintf ("compileClientHello:   ClientHello(Version= %04X)\n          >%s<\n",$version, hexCodedString ($clientHello,"           ")));

    } elsif (($record_version & 0xFF00) == $PROTOCOL_VERSION{'SSLv3'}) { #SSL3 , TLS1.x
        _trace2 ("compileClientHello: Protocol: SSL3/TLS1.x\n");

        $clientHello_extensions = _compileClientHelloExtensions ($record_version, $version, $ciphers, $host, %clientHello);

        $clientHello{'extensions_total_len'} = length($clientHello_extensions);

         _trace4    ("compileClientHello (SSL3/TLS) (1):\n");

        $clientHello_tmp = pack ("n a[32] C n a[$clientHello{'cipher_spec_len'}] C C[$clientHello{'compression_method_len'}] a[$clientHello{'extensions_total_len'}]",
            $clientHello{'version'},                # n
            $clientHello{'challenge'},              # A[32] = gmt + random [4] + [28] bytes
            $clientHello{'session_id_len'},         # C
            $clientHello{'cipher_spec_len'},        # n
            $clientHello{'cipher_spec'},            # A[$clientHello{'cipher_spec_len'}]
            $clientHello{'compression_method_len'}, # C (0x01)
            $clientHello{'compression_method'},     # C[len] (0x00)
            $clientHello_extensions                 # optional
        );

        _trace4_    ("          >".hexCodedString ($clientHello_tmp,"           ")."<\n");

        $clientHello{'msg_len'} = length ($clientHello_tmp);
        $clientHello{'record_len'} = $clientHello{'msg_len'} + 4;

        $clientHello = pack ("C n n C C n a*",
            $clientHello{'record_type'},    # C
            $clientHello{'record_version'}, # n
            $clientHello{'record_len'},     # n
            $clientHello{'msg_type'},       # C
            0x00,                           # C (0x00)
            $clientHello{'msg_len'},        # n
            $clientHello_tmp                # a
        );

        _trace3 ( "compileClientHello (SSL3/TLS) (2):\n       >".hexCodedString ($clientHello,"        ")."<\n");
        _trace2_ ( sprintf (
                "# -->SSL3/TLS-clientHello:\n".
                "# -->   record_type:       >%02X<\n".
                "# -->   record_version:  >%04X< (%s)\n".
                "# -->   record_len:      >%04X<\n".
                "# -->   Handshake protocol: \n".
                "# -->       msg_type:                >%02X<\n".
                "# -->       msg_len:             >00%04X<\n".
                "# -->       version:               >%04X< (%s)\n".
                "# -->       challenge/random:      >%s<\n".
                "# -->       session_id_len:          >%02X<\n".
                "# -->       cipher_spec_len:       >%04X<\n".
                "# -->       cipher_spec:           >%s<\n",    #Comma!!
                $clientHello{'record_type'},
                $clientHello{'record_version'},
                $ssl,
                $clientHello{'record_len'},
                $clientHello{'msg_type'},
                $clientHello{'msg_len'},
                $clientHello{'version'},
                $ssl,
                hexCodedString ($clientHello{'challenge'}),
                $clientHello{'session_id_len'},
                $clientHello{'cipher_spec_len'},
                hexCodedString ($clientHello{'cipher_spec'}),
        ));

        if  ($Net::SSLhello::trace > 3) {
            printTLSCipherList ($clientHello{'cipher_spec'});
        }

        _trace2_ ( sprintf (
                "# -->       compression_method_len:  >%02X<\n".
                "# -->       compression_method:      >%02X<\n".
                "# -->       extensions_total_len:  >%04X<\n",   #Comma!!
                $clientHello{'compression_method_len'}, # C (0x01)
                $clientHello{'compression_method'},     # C[1] (0x00)
                $clientHello{'extensions_total_len'},
        ));

        _trace4_ (
            sprintf (
              "#        --->       extensions:      >%s<\n",
              hexCodedString ($clientHello_extensions),
            )
        );

        _trace4 (sprintf ("compileClientHello (%04X)\n          >",$record_version).hexCodedString ($clientHello,"           ")."<\n");

    } elsif ( (($record_version & 0xFF00) == $PROTOCOL_VERSION{'DTLSfamily'}) || ($version == $PROTOCOL_VERSION{'DTLSv09'})  ) { #DTLS1.x or DTLSv09 (OpenSSL pre 0.9.8f)
        _trace2 ("compileClientHello: Protocol: DTLS\n");

        $clientHello_extensions = _compileClientHelloExtensions ($record_version, $version, $ciphers, $host, %clientHello);
        $clientHello{'extensions_total_len'} = length($clientHello_extensions);

        $clientHello{'cookie_len'} = $dtls_cookieLen;
        $clientHello{'cookie'} = $dtls_cookie;
        _trace4    ("compileClientHello (DTLS) (1):\n");

        $clientHello_tmp = pack ("n a[32] C C A[$clientHello{'cookie_len'}] n a[$clientHello{'cipher_spec_len'}] C C[$clientHello{'compression_method_len'}] a[$clientHello{'extensions_total_len'}]",
            $clientHello{'version'},                # n
            $clientHello{'challenge'},              # A[32] = gmt + random [4] + [28] bytes
            $clientHello{'session_id_len'},         # C
            $clientHello{'cookie_len'},             # C, DTLS only
            $clientHello{'cookie'},                 # A[$clientHello{'cookie_len'}], DTLS
            $clientHello{'cipher_spec_len'},        # n
            $clientHello{'cipher_spec'},            # A[$clientHello{'cipher_spec_len'}]
            $clientHello{'compression_method_len'}, # C (0x01)
            $clientHello{'compression_method'},     # C[len] (0x00)
            $clientHello_extensions                 # optional
        );

        _trace4_    ("          >".hexCodedString ($clientHello_tmp,"           ")."<\n");

        $clientHello{'msg_len'} = length ($clientHello_tmp);
        $clientHello{'fragment_len'} = $clientHello{'msg_len'}; ## Up to now no fragmented packets (TBD?)
        $clientHello{'record_len'} = $clientHello{'msg_len'} + 12; #=+4 +8 (DTLS)
        $clientHello{'record_epoch'} = $dtls_epoch;
        $clientHello{'record_seqNr'} = $dtls_sequence;
        $clientHello{'msg_seqNr'} = $dtls_sequence; ## Up to now no fragmented packets (TBD?)$

        $clientHello = pack ("C n n n N n C C n n C n C n a*",
            $clientHello{'record_type'},     # C
            $clientHello{'record_version'},  # n
            $clientHello{'record_epoch'},    # n
            0x0000,                          # n (0x0000)
            $clientHello{'record_seqNr'},    # N
            $clientHello{'record_len'},      # n
            $clientHello{'msg_type'},        # C
            0x00,                            # C (0x00)
            $clientHello{'msg_len'},         # n
            $clientHello{'msg_seqNr'},       # n
            0x00,                            # C (0x00)
            $clientHello{'fragment_offset'}, # n TBD: verify
            0x00,                            # C (0x00)
            $clientHello{'fragment_len'},    # n TBD: verify
            $clientHello_tmp                 # a
        );

        _trace2 ( "compileClientHello (DTLS) (2):\n       >".hexCodedString ($clientHello,"        ")."<\n");
        _trace2_ ( sprintf (
                "# --> DTLS-clientHello (Record):\n".
                "# -->   record_type:       >%02X<\n".
                "# -->   record_version:  >%04X< (%s)\n".
                "# -->   record_epoch:    >%04X<\n".  # DTLS
                "# -->   record_seqNr:    >%012X<\n". # DTLS
                "# -->   record_len:      >%04X<\n".
                "# -->   Handshake protocol: \n".
                "# -->       msg_type:                >%02X<\n".
                "# -->       msg_len:             >%06X<\n".
                "# -->       msg_seqNr:             >%04X<\n". # DTLS
                "# -->       fragment_offset:     >%06X<\n".   # DTLS = 0x000000 if not fragmented
                "# -->       fragment_len:        >%06X<\n".   # DTLS = msg_len if not fragmented
                "# -->       version:               >%04X< (%s)\n".
                "# -->       challenge/random:      >%s<\n".
                "# -->       session_id_len:          >%02X<\n".
                "# -->       cookie_len:              >%02X<\n". # DTLS
                "# -->       cookie:                >%s<\n". # DTLS
                "# -->       cipher_spec_len:       >%04X<\n".
                "# -->       cipher_spec:           >%s<\n",  # Comma!!
                $clientHello{'record_type'},
                $clientHello{'record_version'},
                $ssl,
                $clientHello{'record_epoch'},            # DTLS
                $clientHello{'record_seqNr'},            # DTLS
                $clientHello{'record_len'},
                $clientHello{'msg_type'},
                $clientHello{'msg_len'},
                $clientHello{'msg_seqNr'},               # DTLS
                $clientHello{'fragment_offset'},         # DTLS
                $clientHello{'fragment_len'},            # DTLS
                $clientHello{'version'},
                $ssl,
                hexCodedString ($clientHello{'challenge'}),
                $clientHello{'session_id_len'},
                $clientHello{'cookie_len'},              # DTLS
                hexCodedString ($clientHello{'cookie'},"        "), # DTLS
                $clientHello{'cipher_spec_len'},
                hexCodedString ($clientHello{'cipher_spec'},"        "),
        ));

        if  ($Net::SSLhello::trace > 3) {
            printTLSCipherList ($clientHello{'cipher_spec'});
        }

        _trace2_ ( sprintf (
                "# -->       compression_method_len:  >%02X<\n".
                "# -->       compression_method:      >%02X<\n".
                "# -->       extensions_total_len:  >%04X<\n", #Comma!
                $clientHello{'compression_method_len'},  # C (0x01)
                $clientHello{'compression_method'},      # C[1] (0x00)
                $clientHello{'extensions_total_len'},
        ));

        _trace4 (sprintf ("compileClientHello (%04X)\n          >",$record_version).hexCodedString ($clientHello,"           ")."<\n");
    } else {
        if (! defined $ssl) {
            $ssl = "--unknown protocol--";
        }
#        my ($ssl) = grep {$record_version ~~ ${$cfg{'openssl_version_map'}}{$_}} keys %{$cfg{'openssl_version_map'}};
        local $my_error = "**WARNING: compileClientHello: protocol version $ssl (0x". sprintf("%04X", $record_version) .") not (yet) defined in Net::SSLhello.pm -> protocol ignored";
        carp($my_error);
    }
    if ( ($Net::SSLhello::max_sslHelloLen > 0) && (length($clientHello) > $Net::SSLhello::max_sslHelloLen) ) { # According RFC: 16383+5 bytes; handshake messages between 256 and 511 bytes in length caused sometimes virtual servers to stall, cf.: https://code.google.com/p/chromium/issues/detail?id=245500
        if (! defined $ssl) {
            $ssl = "--unknown protocol--";
        }
        if  ($Net::SSLhello::experimental >0) { # experimental function is are activated
            _trace_("\n");
            _trace ("compileClientHello: WARNING: Server $host (protocol: $ssl): use of ClintHellos > $Net::SSLhello::max_sslHelloLen bytes did cause some virtual servers to stall in the past. This protection is overridden by '--experimental'");
        } else { # use of experimental functions is not permitted (option is not activated)
            local $my_error = "**WARNING: compileClientHello: Server $host: the ClientHello is longer than $Net::SSLhello::max_sslHelloLen bytes, this caused sometimes virtual servers to stall, e.g. 256 bytes: https://code.google.com/p/chromium/issues/detail?id=245500;\n    Please add '--experimental' to override this protection; -> This time the protocol $ssl is ignored";
            carp ($my_error);
        }
    }
    return ($clientHello);
} # compileClientHello


###########################
sub compileAlertRecord ($$$$;$$) {
    #? compile an alert record
    my $record_version = shift || "";
    my $host           = shift || "";
    my $level          = shift || "";
    my $description    = shift || "";
    my $dtls_epoch     = shift || 0; # optional
    my $dtls_sequence  = shift || 0; # optional
    my $alertRecord    = "";         # return value
    my %rhash = reverse %PROTOCOL_VERSION;
    my $ssl   = $rhash{$record_version};

    _trace4 ("compileAlertRecord ($host) {\n");

    local $my_error = ""; # reset error message

    my %alertRecord =  ( # alert record
        'record_type'            => $RECORD_TYPE {'handshake'},# from SSL3:  Handshake (22=0x16) #uint8
        'record_version'         => $record_version,           # from SSL3:  #uint16
        'record_epoch'           => 0x0000,                    # DTLS only:  #uint16
        'record_seqNr'           => 0x000000,                  # DTLS only:  #uint24 (!)
        'record_len'             => 0x0002,                    # from SSL3:  #uint16: always 2 bytes!
        'level'                  => $level,                    # from SSL3:  #uint8: Alarm-Level
        'description'            => $description,              # from SSL3:  #uint8: Alarm
    );

    if ($record_version == $PROTOCOL_VERSION{'SSLv2'}) { #SSL2
#        _trace2 ("compileAlertRecord: Protocol: SSL2\n");
        $my_error = "compileAlert for SSL2 is not yet supported";
        _trace1 ("compileAlertRecord: $my_error\n");
        carp ($my_error);

#        $alertRecord_tmp = pack ("C n ",
#            $alertRecord{'msg_type'},       #C
#            $alertRecord{'version'},        #n
#        );

#        $alertRecord{'msg_len'} = length ($alertRecord_tmp) | 0x8000;

#          _trace2_ (
#            sprintf (
#              "# --> msg_len \| 0x8000 (added): >%04X<\n".
#              "# --> msg_type:          >%02X<\n".
#              "# --> version:         >%04X< (%s)\n".
#              $alertRecord{'msg_len'},
#              $alertRecord{'msg_type'},
#              $alertRecord{'version'},
#              $ssl,
#            )
#        );


#        $alertRecord = pack ("n a*",
#            $alertRecord{'msg_len'},
#            $alertRecord_tmp,
#        );

#        _trace4 (sprintf ("compileAlertRecord (Version= %04X)\n          >%s<\n",$version, hexCodedString ($alertRecord,"           ")));

    } elsif (($record_version & 0xFF00) == $PROTOCOL_VERSION{'SSLv3'}) { #SSL3 , TLS1.x
        _trace2    ("compileAlertRecord (SSL3/TLS) (1):\n");
        $alertRecord{'record_type'} = $RECORD_TYPE {'alert'};

        $alertRecord = pack("C n n C C", # compile alert-messages
             $alertRecord{'record_type'},    # C
             $alertRecord{'record_version'}, # n
             $alertRecord{'record_len'},     # n
             $alertRecord{'level'},          # C
             $alertRecord{'description'}     # C
        );

        if ($TLS_AlertDescription {$alertRecord{'description'}} ) { # defined, no Null-String
            $description = $TLS_AlertDescription {$alertRecord{'description'}}[0]." ".$TLS_AlertDescription {$alertRecord{'description'}}[2];
        } else {
            $description = "Unknown/Undefined";
        }

        _trace2_ ( sprintf (
                "# -->SSL3/TLS-AlertRecord:\n".
                "# -->   record_type:       >%02X<\n".
                "# -->   record_version:  >%04X< (%s)\n".
                "# -->   record_len:      >%04X<\n".
                "# -->   Alert Message:\n".
                "# -->       Level:                >%02X<\n".
                "# -->       Description:          >%02X< (%s)\n",
                $alertRecord{'record_type'},
                $alertRecord{'record_version'},
                $ssl,
                $alertRecord{'record_len'},
                $alertRecord{'level'},
                $alertRecord{'description'},
                $description,
        ));

    _trace4 (sprintf ("compileAlertRecord (%04X)\n          >",$record_version).hexCodedString ($alertRecord,"           ")."<\n");

    } elsif ( (($record_version & 0xFF00) == $PROTOCOL_VERSION{'DTLSfamily'}) || ($record_version == $PROTOCOL_VERSION{'DTLSv09'})  ) { #DTLS1.x or DTLSv09 (OpenSSL pre 0.9.8f)
        _trace2 ("compileAlertRecord: Protocol: DTLS\n");

        $alertRecord{'record_type'} = $RECORD_TYPE {'alert'};
        $alertRecord{'record_epoch'} = $dtls_epoch;
        $alertRecord{'record_seqNr'} = $dtls_sequence;

        $alertRecord = pack ("C n n n N n C C",
            $alertRecord{'record_type'},     # C
            $alertRecord{'record_version'},  # n
            $alertRecord{'record_epoch'},    # n
            0x0000,                          # n (0x0000)
            $alertRecord{'record_seqNr'},    # N
            $alertRecord{'record_len'},      # n
            $alertRecord{'level'},           # C
            $alertRecord{'description'}      # C
        );
        if ($TLS_AlertDescription {$alertRecord{'description'}} ) { # defined, no Null-String
            $description = $TLS_AlertDescription {$alertRecord{'description'}}[0]." ".$TLS_AlertDescription {$alertRecord{'description'}}[2];
        } else {
            $description = "Unknown/Undefined";
        }

        _trace2 ( "compileAlertRecord (DTLS) (2):\n       >".hexCodedString ($alertRecord,"        ")."<\n");
        _trace2_ ( sprintf (
                "# --> DTLS-Record (Alert):\n".
                "# -->   record_type:       >%02X<\n".
                "# -->   record_version:  >%04X< (%s)\n".
                "# -->   record_epoch:    >%04X<\n".  # DTLS
                "# -->   record_seqNr:    >%012X<\n". # DTLS
                "# -->   record_len:      >%04X<\n".
                "# -->   Alert Message:\n".
                "# -->       Level:                >%02X<\n".
                "# -->       Description:          >%02X< (%s)\n",
                $alertRecord{'record_type'},
                $alertRecord{'record_version'},
                $ssl,
                $alertRecord{'record_epoch'},            # DTLS
                $alertRecord{'record_seqNr'},            # DTLS
                $alertRecord{'record_len'},
                $alertRecord{'level'},
                $alertRecord{'description'},
                $description,
        ));

        _trace4 (sprintf ("compileAlertRecord (%04X)\n          >",$record_version).hexCodedString ($alertRecord,"           ")."<\n");
    } else {
        if (! defined $ssl) {
            $ssl = "--unknown protocol--";
        }
#        my ($ssl) = grep {$record_version ~~ ${$cfg{'openssl_version_map'}}{$_}} keys %{$cfg{'openssl_version_map'}};
        $my_error = "**WARNING: compileAlertRecord protocol version $ssl (0x". sprintf("%04X", $record_version) .") not (yet) defined in Net::SSLhello.pm -> protocol ignored";
        carp($my_error);
    }
    if ( ($Net::SSLhello::max_sslHelloLen > 0) && (length($alertRecord) > $Net::SSLhello::max_sslHelloLen) ) { # According RFC: 16383+5 bytes; handshake messages between 256 and 511 bytes in length caused sometimes virtual servers to stall, cf.: https://code.google.com/p/chromium/issues/detail?id=245500
        if (! defined $ssl) {
            $ssl = "--unknown protocol--";
        }
        if  ($Net::SSLhello::experimental >0) { # experimental function is are activated
            _trace_("\n");
            _trace ("compileAlertRecord: WARNING: Server $host (protocol: $ssl): use of alert message > $Net::SSLhello::max_sslHelloLen bytes did cause some virtual servers to stall in the past. This protection is overridden by '--experimental'");
        } else { # use of experimental functions is not permitted (option is not activated)
            $my_error = "**WARNING: compileAlertRecord: Server $host: the alert message is longer than $Net::SSLhello::max_sslHelloLen bytes, this caused sometimes virtual servers to stall, e.g. 256 bytes: https://code.google.com/p/chromium/issues/detail?id=245500;\n    Please add '--experimental' to override this protection; -> This time the protocol $ssl is ignored";
            carp ($my_error);
        }
    }
    return ($alertRecord);
} # compileAlertRecord


############################
sub _compileClientHelloExtensions ($$$$@) {
    #? <<description missing>> # FIXME:
    my ($record_version, $version, $ciphers, $host, %clientHello) = @_;
    #my $record_version    = shift || "";
    #my $version    = shift || "";
    #my $ciphers    = shift || "";
    #my $host = shift || "";
    #my (%clientHello) = @_;
    my $clientHello_extensions = "";
    my %rhash = reverse %PROTOCOL_VERSION;
    my $ssl   = $rhash{$version};

    if ( ( ($version == $PROTOCOL_VERSION{'SSLv3'}) && (!$Net::SSLhello::force_TLS_extensions) ) || ($version == $PROTOCOL_VERSION{'SSLv2'}) ) { # prevent to not to use tls extensions with SSLv2 or SSLv3
        _trace2 ("compileClientHelloExtensions: Protocol $ssl does not support TLS extensions including SNI -> no extension added\n");
        return ("");
    }

    # ggf auch prüfen, ob Host ein DNS-Name ist
    if ($Net::SSLhello::usesni) { # allow to test SNI (with version TLSv1 and above or DTLSv09 (OpenSSL pre 0.9.8f), DTLSv1 and above)
    ### data for extension 'Server Name Indication' in reverse order
        $Net::SSLhello::sni_name =~ s/\s*(.*?)\s*\r?\n?/$1/gx if ($Net::SSLhello::sni_name);     # delete Spaces, \r and \n
        $Net::SSLhello::use_sni_name = 1 if ( ($Net::SSLhello::use_sni_name == 0) && ($Net::SSLhello::sni_name) && ($Net::SSLhello::sni_name ne "1") ); ###FIX: quickfix until migration of o-saft.pl is compleated (tbd)
        unless ($Net::SSLhello::use_sni_name) {
            $clientHello{'extension_sni_name'}     = $host;                                      # Server Name, should be a Name no IP
        } else {
            $clientHello{'extension_sni_name'}     = ($Net::SSLhello::sni_name) ? $Net::SSLhello::sni_name : ""; # Server Name, should be a Name no IP
        }
        $clientHello{'extension_sni_len'}          = length($clientHello{'extension_sni_name'}); # len of server name
        $clientHello{'extension_sni_type'}         = 0x00;                                       # 0x00= host_name
        $clientHello{'extension_sni_list_len'}     = $clientHello{'extension_sni_len'} + 3;      # len of server name + 3 bytes (sni_len, sni_type)
        $clientHello{'extension_len'}              = $clientHello{'extension_sni_list_len'} + 2; # len of this extension = sni_list_len + 2 bytes (sni_list_len)
        $clientHello{'extension_type_server_name'} = 0x0000;                                     # 0x0000
#        $clientHello{'extensions_total_len'}       = $clientHello{'extension_len'} + 4;          # war +2 len server name extension + 2 bytes (extension_type) #??? +4?!!##

        $clientHello_extensions = pack ("n n n C n a[$clientHello{'extension_sni_len'}]",
            $clientHello{'extension_type_server_name'}, #n
            $clientHello{'extension_len'},              #n
            $clientHello{'extension_sni_list_len'},     #n
            $clientHello{'extension_sni_type'},         #C
            $clientHello{'extension_sni_len'},          #n
            $clientHello{'extension_sni_name'},         #a[$clientHello{'extension_sni_len'}]
        );
        _trace2 ("compileClientHelloExtensions ($ssl): extension_sni_name extension added (name='$clientHello{'extension_sni_name'}', len=$clientHello{'extension_sni_len'})\n");
    } else {
        _trace2 ("compileClientHelloExtensions ($ssl): NO extension_sni_name extension added\n");
    }
    if ($Net::SSLhello::usereneg) { # use secure Renegotiation
        my $anzahl = int length ($clientHello{'cipher_spec'}) / 2;
        my @cipherTable = unpack("a2" x $anzahl, $clientHello{'cipher_spec'});
        unless ( ($Net::SSLhello::double_reneg == 0) && (grep {/\x00\xff/x} @cipherTable) ) { # Protection against double renegotiation info is active
            # do *NOT* send a reneg_info extension if the cipher_spec includes already Signalling Cipher Suite Value (SCSV)
            # "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" {0x00, 0xFF}

            ### data for extension 'renegotiation_info'
            $clientHello{'extension_type_renegotiation_info'} = 0xff01; # Tbd: hier, oder zentrale Definition?!
            $clientHello{'extension_reneg_len'}               = 0x0001; # Tbd: hier, oder zentrale Definition?!
            $clientHello{'extension_reneg_info_ext_len'}      = 0x00;   # Tbd: hier, oder zentrale Definition?!

            $clientHello_extensions .= pack ("n n c",
                $clientHello{'extension_type_renegotiation_info'},      #n = 0xff01
                $clientHello{'extension_reneg_len'},                    #n = 0x0001
                $clientHello{'extension_reneg_info_ext_len'},           #c = 0x00
            );
            _trace2 ("compileClientHelloExtensions ($ssl): reneg_info Extension added\n");
        } else {
            _trace2 ("compileClientHelloExtensions ($ssl): *NOT* sent a reneg_info Extension as the cipher_spec includes already the Signalling Cipher Suite Value (TLS_EMPTY_RENEGOTIATION_INFO_SCSV {0x00, 0xFF})\n");
        }
    }

    # extension_type_signature_algorithms
    if (    ($Net::SSLhello::use_signature_alg >1)
        || (($Net::SSLhello::use_signature_alg >0)
            && (   (($record_version >= $PROTOCOL_VERSION{'TLSv12'})     && ($record_version  < $PROTOCOL_VERSION{'DTLSfamily'}))
                || (($record_version >= $PROTOCOL_VERSION{'DTLSfamily'}) && ($record_version <= $PROTOCOL_VERSION{'DTLSv12'}))
            )
        ) ) {
        # use_signature_alg: 0 (off), 1(auto on if >=TLSv1.2, >=DTLS1.2), 2: always on
        ### data for extension 'signature_algorithms'
        $clientHello{'extension_type_signature_algorithms'}   = 0x000d; ##TBD hier, oder zentrale Definition?!
        $clientHello{'extension_hash_algorithms_list'}        = ""
            ."\x06\x01\x06\x02\x06\x03"                                 #SHA512: RSA/DSA/ECDSA
            ."\x05\x01\x05\x02\x05\x03"                                 #SHA384: RSA/DSA/ECDSA
            ."\x04\x01\x04\x02\x04\x03"                                 #SHA256: RSA/DSA/ECDSA
            ."\x03\x01\x03\x02\x03\x03"                                 #SHA224: RSA/DSA/ECDSA
            ."\x02\x01\x02\x02\x02\x03"                                 #SHA1:   RSA/DSA/ECDSA
            ."";
        $clientHello{'extension_hash_algorithms_list_len'}    = length ($clientHello{'extension_hash_algorithms_list'}); #30 = 0x1E
        $clientHello{'extension_signature_algorithms_len'}    = $clientHello{'extension_hash_algorithms_list_len'} + 2;  #32 = 0x20

        $clientHello_extensions .= pack ("n n n a[$clientHello{'extension_hash_algorithms_list_len'}]",
            $clientHello{'extension_type_signature_algorithms'},        #n = 0x001d
            $clientHello{'extension_signature_algorithms_len'},         #n
            $clientHello{'extension_hash_algorithms_list_len'},         #n
            $clientHello{'extension_hash_algorithms_list'},             #a[$clientHello{'extension_hash_algorithms_list_len'}]
        );
        _trace2 ("compileClientHelloExtensions ($ssl): signature_algorithms Extension added\n");
    }

    # extension elliptic_curves
    my $anzahl = int length ($clientHello{'cipher_spec'}) / 2;
    my @cipherTable = unpack("a2" x $anzahl, $clientHello{'cipher_spec'});

    # send always ECC extensions if not switched off manually
    #if ( grep(/\xc0./, @cipherTable) || 1==1 ) {           # found cipher C0xx, lazy check; ### TBD: check with a range of ECC-ciphers ###
        if ($Net::SSLhello::useecc) {                       # use Elliptic Curves Extension
            ### Data for Extension 'elliptic_curves' (in reverse order)
            $clientHello{'extension_ecc_list'} = ""         # TBD: should be altered to get all supported ECurves (not only the primary
#                # disable one line after the other to find manually the secondary, tertiary etc curve
#                 ."\x00\x00" # 0x0000 (Unassigned_0)       ## disabled by default
                 ."\x00\x01" # 0x0001 (sect163k1)
                 ."\x00\x02" # 0x0002 (sect163r1)
                 ."\x00\x03" # 0x0003 (sect163r2)
                 ."\x00\x04" # 0x0004 (sect193r1)
                 ."\x00\x05" # 0x0005 (sect193r2)
                 ."\x00\x06" # 0x0006 (sect233k1)
                 ."\x00\x07" # 0x0007 (sect233r1)
                 ."\x00\x08" # 0x0008 (sect239k1)
                 ."\x00\x09" # 0x0009 (sect283k1)
                 ."\x00\x0a" # 0x000a (sect283r1)
                 ."\x00\x0b" # 0x000b (sect409k1)
                 ."\x00\x0c" # 0x000c (sect409r1)
                 ."\x00\x0d" # 0x000d (sect571k1)
                 ."\x00\x0e" # 0x000e (sect571r1)
                 ."\x00\x0f" # 0x000f (secp160k1)
                 ."\x00\x10" # 0x0010 (secp160r1)
                 ."\x00\x11" # 0x0011 (secp160r2)
                 ."\x00\x12" # 0x0012 (secp192k1)
                 ."\x00\x13" # 0x0013 (secp192r1)
                 ."\x00\x14" # 0x0014 (secp224k1)
                 ."\x00\x15" # 0x0015 (secp224r1)
                 ."\x00\x16" # 0x0016 (secp256k1)
                 ."\x00\x17" # 0x0017 (secp256r1)           ## => common default curve
                 ."\x00\x18" # 0x0018 (secp384r1)
                 ."\x00\x19" # 0x0019 (secp512r1)
                 ."\x00\x1a" # 0x001a (brainpoolP256r1)
                 ."\x00\x1b" # 0x001b (brainpoolP384r1)
                 ."\x00\x1c" # 0x001c (brainpoolP512r1)
                 ."\x00\x1d" # 0x001d (ecdh_x25519)
                 ."\x00\x1e" # 0x001e (ecdh_x25519)
                 ."\x00\x1f" # 0x001f (eddsa_ed25519)       ## Signature curves, vanished in  https://tools.ietf.org/html/draft-ietf-tls-tls13-12
                 ."\x00\x20" # 0x0020 (eddsa_ed448)         ## Signature curves, vanished in  https://tools.ietf.org/html/draft-ietf-tls-tls13-12
                 ."";   # ALL defined ECCs; TBD: move general list to osaft.pl TBD
            $clientHello{'extension_ecc_list_len'}            = length($clientHello{'extension_ecc_list'}); # len of ECC List
            $clientHello{'extension_elliptic_curves_len'}     = $clientHello{'extension_ecc_list_len'}+2;   # len of ECC Extension
            $clientHello{'extension_type_elliptic_curves'}    = 0x000a; # Tbd: hier, oder zentrale Definition?!

            $clientHello_extensions .= pack ("n n n a[$clientHello{'extension_ecc_list_len'}]",
              $clientHello{'extension_type_elliptic_curves'},         #n    = 0x000a
              $clientHello{'extension_elliptic_curves_len'},          #n    = 0x00xz
              $clientHello{'extension_ecc_list_len'},                 #n    = 0x00xy
              $clientHello{'extension_ecc_list'},                     #a[$clientHello{'extension_ecc_list_len'}] = 0x00....
            );
            _trace2 ("compileClientHelloExtensions ($ssl): elliptic_curve Extension added\n");
        }

        if ($Net::SSLhello::useecpoint ) { # use Elliptic Point Formats Extension
            ### Data for Extension 'ec_point_formats'
            $clientHello{'extension_type_ec_point_formats'}   = 0x000b; # Tbd: hier, oder zentrale Definition?!
            $clientHello{'extension_ec_point_formats_len'}    = 0x0002; # Tbd: hier, oder zentrale Definition?!
            $clientHello{'extension_ec_point_formats_list_ele'} = 0x01; # Tbd: hier, oder zentrale Definition?!
            $clientHello{'extension_ec_point_formats_list'}   = "\x00"; # Tbd: hier, oder zentrale Definition?!

            $clientHello_extensions .= pack ("n n C a[$clientHello{'extension_ec_point_formats_list_ele'}]",
              $clientHello{'extension_type_ec_point_formats'},        #n    = 0x000b
              $clientHello{'extension_ec_point_formats_len'},         #n    = 0x00xz
              $clientHello{'extension_ec_point_formats_list_ele'},    #C    = 0xxy
              $clientHello{'extension_ec_point_formats_list'},        #a[$clientHello{'extension_ec_point_formats_list_ele'}] = 0x00....
            );
            _trace2 ("compileClientHelloExtensions ($ssl): ec_point_formats Extension added\n");
        }
    #} #end send always ECC extensions

    $clientHello{'extensions_total_len'} = length($clientHello_extensions);

    if ($clientHello_extensions) { # not empty
        $clientHello_extensions = pack ("n a*",
            length($clientHello_extensions),            #n
            $clientHello_extensions                     #a[length($clientHello_extensions)]
        );
        _trace4 (sprintf ("_compileClientHelloExtensions ($ssl) (extensions_total_len = %04X)\n          >", $clientHello{'extensions_total_len'}).hexCodedString ($clientHello_extensions ,"           ")."<\n");
    }
    return ($clientHello_extensions);
} # _compileClientHelloExtensions

=pod

=head2 parseServerKeyExchange( )

Manually parse a Server Kex Exchange Packet from
- DHE handshake to detect the length of the DHparam (needed for openssl <= 1.0.1), e.g. dh, 2048 bits (dh in small letters to be different from openssl (large letters)
- ECDHE handshake to check for the most priorized Curve
=cut

sub parseServerKeyExchange($$$) {
    #? parse a ServerKeyExchange packet to detect length of DHparam
    my ($keyExchange, $len, $d) = @_;
    my ($_tmpLen, $_null, $_handshake_type, $_bits) = 0;
    my %_mySSLinfo;
    _trace2("parseServerKeyExchange($keyExchange, $len, ...)\n");
    _trace4("parseServerKeyExchange(KeyExchange= $keyExchange, Len= $len, Data= ".unpack("H*",$d)."\n");
    $_tmpLen = length (unpack("H*",$d))/2;
    carp ("parseServerKeyExchange: Error in ServerKeyExchange Message: unexpected len ($_tmpLen) should be $len bytes") if ($len != $_tmpLen);
    return if ($len != $_tmpLen);

    if ($keyExchange eq "DH") {

        ($_mySSLinfo{'DH_ServerParams_p_len'},    # n
         $d) = unpack("n a*", $d);

        ($_mySSLinfo{'DH_ServerParams_p'},         # a[$_mySSLinfo{'IDH_ServerParams_p_len'}]
         $_mySSLinfo{'DH_ServerParams_g_len'},     # n
         $d) = unpack("a[$_mySSLinfo{'DH_ServerParams_p_len'}] n a*", $d);
         $_mySSLinfo{'DH_ServerParams_p'} = unpack ("H*", $_mySSLinfo{'DH_ServerParams_p'}); # Convert to a readable HEX-String

        ($_mySSLinfo{'DH_ServerParams_g'},         # a[$_mySSLinfo{'IDH_ServerParams_g_len'}]
         $_mySSLinfo{'DH_ServerParams_PubKeyLen'}, # n
         $d) = unpack("a[$_mySSLinfo{'DH_ServerParams_g_len'}] n a*", $d);
        $_mySSLinfo{'DH_ServerParams_g'} = unpack ("H*", $_mySSLinfo{'DH_ServerParams_g'}); # Convert to a readable HEX-String

        ($_mySSLinfo{'DH_ServerParams_PubKey'},    # a[$_mySSLinfo{'IDH_ServerParams_g_len'}]
         $d) = unpack("a[$_mySSLinfo{'DH_ServerParams_PubKeyLen'}] a*", $d);
        $_mySSLinfo{'DH_ServerParams_PubKey'} = unpack ("H*", $_mySSLinfo{'DH_ServerParams_PubKey'}); # Convert to a readable HEX-String
        _trace2( sprintf (
                " DH_ServerParams (len=%d):\n".
                "# -->       p: (len=0x%04X=%4d)        >%s<\n".
                "# -->       g: (len=0x%04X=%4d)        >%s<\n".
                "# -->       PubKey: (len=0x%04X=%4d)   >%s<\n",
                $len,
                $_mySSLinfo{'DH_ServerParams_p_len'},
                $_mySSLinfo{'DH_ServerParams_p_len'},
                $_mySSLinfo{'DH_ServerParams_p'},
                $_mySSLinfo{'DH_ServerParams_g_len'},
                $_mySSLinfo{'DH_ServerParams_g_len'},
                $_mySSLinfo{'DH_ServerParams_g'},
                $_mySSLinfo{'DH_ServerParams_PubKeyLen'},
                $_mySSLinfo{'DH_ServerParams_PubKeyLen'},
                $_mySSLinfo{'DH_ServerParams_PubKey'}
        ));
        $_bits = $_mySSLinfo{'DH_ServerParams_p_len'} * 8;
        $_mySSLinfo{'DH_serverParam'} = "dh, ". $_bits ." bits"; # manually generate the same message that is generated by openssl >= 1.0.2 but here with 'dh' in small letters
        ###TEST TEST $_mySSLinfo{$keyExchange.'_serverParam'} = "dh, ". $_bits ." bits"; # manually generate the same message that is generated by openssl >= 1.     0.2 but here with 'dh' in small letters
        _trace4("parseServerKeyExchange: DH_serverParam: ".$_mySSLinfo{'DH_serverParam'}."\n");
        _trace2("parseServerKeyExchange() done.\n");
        return ($_mySSLinfo{'DH_serverParam'});

    } elsif ($keyExchange eq "ECDH") { # check for the most priorized Curve; TBD: check for all supported Curves later (by sending more Client_hellos, like to check the ciphers); this should be managed by a superior routine
        ($_mySSLinfo{'ECDH_eccurve_type'},    # C
         $d) = unpack("C a*", $d);

        if ($_mySSLinfo{'ECDH_eccurve_type'} == $ECCURVE_TYPE{'named_curve'}) {
            ($_mySSLinfo{'ECDH_namedCurve'},    # n
            $d) = unpack("n a*", $d);
            $_mySSLinfo{'ECDH_serverParam'} = "(primary) named_curve: <<unknown: ".$_mySSLinfo{'ECDH_namedCurve'}.">>"; # set a default value
            $_mySSLinfo{'ECDH_serverParam'} = "(primary) named_curve: ". $ECC_NAMED_CURVE {$_mySSLinfo{'ECDH_namedCurve'}}[0] .", ". $ECC_NAMED_CURVE {$_mySSLinfo{'ECDH_namedCurve'}}[1] . " bits" if ( defined ($ECC_NAMED_CURVE {$_mySSLinfo{'ECDH_namedCurve'}}[0]) );
        } elsif ($_mySSLinfo{'ECDH_eccurve_type'} == $ECCURVE_TYPE{'explicit_prime'}) { # only basic parsing, no additional trace information about additional parameters, yet,
            ($_mySSLinfo{'ECDH_explicit_prime_p_len'},    # C
             $d) = unpack("C a*", $d);
            $_bits = $_mySSLinfo{'ECDH_explicit_prime_p_len'} * 8;
            $_mySSLinfo{'ECDH_serverParam'} = "(primary) explicite_prime: ". $_bits ." bits"; # manually generate a message that could ressemble to openssl >= 1.0.2 but here with 'ecdh' in small letters (TBD: get an original Message from OpenSSL for this special type of Curves
        } elsif ($_mySSLinfo{'ECDH_eccurve_type'} == $ECCURVE_TYPE{'explicit_char2'}) { # no parsing yet: #TBD: support this type later
            $_mySSLinfo{'ECDH_serverParam'} = "(primary) explicite_char2: <<not parsed, yet>>";
        } else {
            $_mySSLinfo{'ECDH_serverParam'} = "<<unknown ECC Curve type: ".$_mySSLinfo{'ECDH_eccurve_type'}.">>";
        }
        _trace4("parseServerKeyExchange: ECDH_serverParam: '".$_mySSLinfo{'ECDH_serverParam'}."'\n");
        _trace2("parseServerKeyExchange() done.\n");
        return ("ecdh, ".$_mySSLinfo{'ECDH_serverParam'});
    } elsif (($keyExchange =~ /^RSA/x) || ($keyExchange =~ /^EXP/x)) { # check for RSA
        ($_mySSLinfo{'RSA_ServerParams_modulus_len'},   # n
         $d) = unpack("n a*", $d);

        ($_mySSLinfo{'RSA_ServerParams_modulus'},       # a[$_mySSLinfo{'RSA_ServerParams_modulus_len'}]
         $_mySSLinfo{'RSA_ServerParams_exponent_len'},  # n
         $d) = unpack("a[$_mySSLinfo{'RSA_ServerParams_modulus_len'}] n a*", $d);
         $_mySSLinfo{'RSA_ServerParams_modulus'} = unpack ("H*", $_mySSLinfo{'RSA_ServerParams_modulus'}); # Convert to a readable HEX-String

        ($_mySSLinfo{'RSA_ServerParams_exponent'},       # a[$_mySSLinfo{'RSA_ServerParams_exponent_len'}]
         $d) = unpack("a[$_mySSLinfo{'RSA_ServerParams_exponent_len'}] a*", $d);
        $_mySSLinfo{'RSA_ServerParams_exponent'} = unpack ("H*", $_mySSLinfo{'RSA_ServerParams_exponent'}); # Convert to a readable HEX-String
        _trace2( sprintf (
                " RSA_ServerParams (len=%d):\n".
                "# -->       modulus: (len=0x%04X=%4d)  >%s<\n".
                "# -->       exponent: (len=0x%04X=%4d) >%s<\n",
                $len,
                $_mySSLinfo{'RSA_ServerParams_modulus_len'},
                $_mySSLinfo{'RSA_ServerParams_modulus_len'},
                $_mySSLinfo{'RSA_ServerParams_modulus'},
                $_mySSLinfo{'RSA_ServerParams_exponent_len'},
                $_mySSLinfo{'RSA_ServerParams_exponent_len'},
                $_mySSLinfo{'RSA_ServerParams_exponent'}
        ));
        $_bits = $_mySSLinfo{'RSA_ServerParams_modulus_len'} * 8;
        $_mySSLinfo{'RSA_serverParam'} = "rsa, ". $_bits ." bits"; # manually generate the same message that is generated by openssl >= 1.0.2 but here with 'rsa' in small letters
        ###TEST TEST $_mySSLinfo{$keyExchange.'_serverParam'} = "dh, ". $_bits ." bits"; # manually generate the same message that is generated by openssl >= 1.     0.2 but here with 'dh' in small letters
        _trace4("parseServerKeyExchange: RSA_serverParam: ".$_mySSLinfo{'RSA_serverParam'}."\n");
        _trace2("parseServerKeyExchange() done.\n");
        return ($_mySSLinfo{'RSA_serverParam'});
    } else { # nor DH neither ECDH
        _trace2("parseServerKeyExchange: The only supported KeyExchange types are DH, ECDH and RSA yet (not $keyExchange)\n");
        _trace2("parseServerKeyExchange() done.\n");
        return ("");
    }

} # parseServerKeyExchange


sub parseHandshakeRecord ($$$$$$$;$) {
    #? <<description missing>> <<POD missing>> # FIXME:
    # return (<cipher>, <cookie-len (DTLDS)>, <cookie (DTLS)>
    my $host        = shift || ""; # for warn- and trace messages
    my $port        = shift || ""; # for warn- and trace messages
    my $recordType  = shift || 0;  # recordType
    my $recordVersion = shift || 0; # recordVersion or SSLv2
    my $recordLen   = shift || 0;  # recordLen
    my $recordData  = shift || ""; # record
    my $lastCipher  = shift || ""; # lastCipher
    my $client_protocol = shift || "";  # optional

    my $rest        = "";
    my $tmp_len     = 0;
    my $message     = "";
    my $nextMessages = "";
    my %serverHello;
    my $cipher      = "";
    my $keyExchange = "";
    my $description = "";
    my $lastMsgType = $HANDSHAKE_TYPE {'<<undefined>>'}; #undefined

    local $my_error = ""; # reset error message

    my $sni = "";
    my %rhash = reverse %PROTOCOL_VERSION;
    my $ssl_client = $rhash{$client_protocol};

    #reset error_handler and set basic information for this sub
    OSaft::error_handler->reset_err( {module => (SSLHELLO), sub => 'parseHandshakeRecord', print => ($Net::SSLhello::trace > 0), trace => $Net::SSLhello::trace} );

    $Net::SSLhello::use_sni_name = 1 if ( ($Net::SSLhello::use_sni_name == 0) && ($Net::SSLhello::sni_name) && ($Net::SSLhello::sni_name ne "1") ); ###FIX: quickfix until migration of o-saft.pl is compleated (tbd)
    unless ($Net::SSLhello::use_sni_name) {
        $sni = "'$host'" if ($Net::SSLhello::use_sni_name); # Server Name, should be a Name no IP
    } else { # different sni_name
        $sni = ($Net::SSLhello::sni_name) ? "'$Net::SSLhello::sni_name'" : "''"; # allow empty nonRFC-SNI-Names
    }

    if (defined $client_protocol) {
        _trace2("parseHandshakeRecord: Server '$host:$port': (expected protocol= >".sprintf ("%04X", $client_protocol)."<,\n      (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($recordData)." bytes >".hexCodedString (substr($recordData,0,48),"       ")."< ...)\n");
    } else {
        _trace2("parseHandshakeRecord: Server '$host:$port': (any protocol, (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($recordData)." bytes\n       recordData=".hexCodedString (substr($recordData,0,48),"       ").")... \n");
    }

    if (length ($recordData) >=1) { # received data in the record, at least 1 byte

        if ($recordVersion == $PROTOCOL_VERSION{'SSLv2'}) { #SSL2 (no real record -> get MessageData from data that has been parsed before)
            _trace2_ ("# -->SSL: Message type SSL2-Msg\n");
            # SSLV2 uses Messages directly, no records -> get data from record-parameters
            $serverHello{'msg_len'}  =  $recordLen;   # n (MSB already deleted)
            $serverHello{'msg_type'} =  $recordType;  # C
            ($message) = unpack("x a*", $recordData); # Skip '$serverHello{'msg_type'}, # C' -> 'x', which is already parsed as a dummy 'recordType'
            _trace2_ (sprintf (
                "# -->        msg_len:              >%04X<\n".
                "# -->        msg_type:               >%02X<\n",
                $serverHello{'msg_len'},
                $serverHello{'msg_type'}
            ));
            _trace4 ("parseHandshakeRecord: Server '$host:$port': MessageData:\n".hexCodedString ($message,"             ")."\n");

            $lastMsgType = $serverHello{'msg_type'} || $HANDSHAKE_TYPE {'<<undefined>>'};

            if ($serverHello{'msg_type'} == $SSL_MT_SERVER_HELLO) {
                _trace4 ("    Handshake protocol: SSL2 Server Hello\n");
                _trace4 ("        Message type: (Server Hello (2)\n");
                return (parseSSL2_ServerHello ($host, $port, $message, $client_protocol), $lastMsgType, 0, ""); # cipher_spec-Liste
            } elsif ($serverHello{'msg_type'} == $SSL_MT_ERROR) { # simple error handling for ssl2
                ($serverHello{'err_code'}        # n
                 ) = unpack("n", $message);

                _trace2 ("parseHandshakeRecord: Server '$host:$port': received a SSLv2 error message, code: >0x".hexCodedString ($serverHello{'err_code'})."<\n");
                unless ($serverHello{'err_code'} == 0x0001) { # SSLV2_No_Cipher, TBD: this could be improved later (if needed)
                    carp ("**WARNING: parseHandshakeRecord: Server '$host:$port': received a SSLv2 error message: , code: >0x".hexCodedString ($serverHello{'err_code'})." -> answer ignored\n");
                }
                return ("", $lastMsgType, 0, "");
            } else { # if ($serverHello{'msg_type'} == 0 => unsupported protocol (?!)
                $my_error= "    Unknown SSLv2 message type (Dez): ".$serverHello{'msg_type'}.", Msg: >".hexCodedString ($message)."< -> check for SSLv2 is aborted\n";
                return ("",$lastMsgType, 0 , "");
            }
        } else { # SSLv3, TLS or DTLS:a parse messages
            if ($recordType == $RECORD_TYPE {'handshake'}) {
                $nextMessages = $recordData;
                while ($nextMessages ne "") { # read and parse all included messages and return the cipher at the end
                    if (($recordVersion & 0xFF00) == $PROTOCOL_VERSION{'SSLv3'}) { #SSL3 , TLS1.
                        ($serverHello{'msg_type'},          # C
                         $serverHello{'msg_len_3rd_byte'},  # C: 3rd, most significant byte
                         $serverHello{'msg_len'},           # n
                         $rest) = unpack("C C n a*", $nextMessages);

                        _trace2_ (sprintf (
                            "# -->     Handshake-Message:\n".
                            "# -->       msg_type:            >%02X<\n".
                            "# -->       msg_len:         >%02X%04X<\n",    #value with 3 bytes!
                            $serverHello{'msg_type'},
                            $serverHello{'msg_len_3rd_byte'},  # prefetched for record_type handshake
                            $serverHello{'msg_len'}            # prefetched for record_type handshake
                        ));

                        $lastMsgType = $serverHello{'msg_type'} || $HANDSHAKE_TYPE {'<<undefined>>'};

                    } elsif ( (($recordVersion & 0xFF00) == $PROTOCOL_VERSION{'DTLSfamily'}) || ($recordVersion == $PROTOCOL_VERSION{'DTLSv09'})  ) { #DTLS1.x or DLSv09 (OpenSSL pre 0.9.8f)
                        ($serverHello{'msg_type'},                  # C
                         $serverHello{'msg_len_3rd_byte'},          # C: 3rd, most significant byte
                         $serverHello{'msg_len'},                   # n
                         $serverHello{'msg_seqNr'},                 # n
                         $serverHello{'fragment_offset_3rd_byte'},  # C (0x00)
                         $serverHello{'fragment_offset'},           # n TBD: verify
                         $serverHello{'fragment_len_3rd_byte'},     # C (0x00)
                         $serverHello{'fragment_len'},              # n TBD: verify
                         $rest) = unpack ("C C n n C n C n a*", $nextMessages);

                        _trace2_ (sprintf (
                            "# -->     Handshake-Message:\n".
                            "# -->       msg_type:             >%02X<\n".
                            "# -->       msg_len:          >%02X%04X<\n".     # C n: value with 3 bytes!
                            "# -->       msg_seqNr:          >%04X<\n".       # n
                            "# -->       fragment_offset:  >%02X%04X<\n".     # C n: TBD: verify
                            "# -->       fragment_len:     >%02X%04X<\n",     # C n: TBD: verify,
                            $serverHello{'msg_type'},
                            $serverHello{'msg_len_3rd_byte'},            # prefetched for record_type handshake
                            $serverHello{'msg_len'},                     # prefetched for record_type handshake
                            $serverHello{'msg_seqNr'},                   # n
                            $serverHello{'fragment_offset_3rd_byte'},    # C (0x00)
                            $serverHello{'fragment_offset'},             # n TBD: verify
                            $serverHello{'fragment_len_3rd_byte'},       # C (0x00)
                            $serverHello{'fragment_len'},                # n TBD: verify,
                        )); ### if ($serverHello{'record_type'} == $RECORD_TYPE {'handshake'});

                        $lastMsgType = $serverHello{'msg_type'} || $HANDSHAKE_TYPE {'<<undefined>>'};

                        if ( ( (defined ($serverHello{'fragment_offset'}) ) && ($serverHello{'fragment_offset'} > 0) ) || ( (defined ($serverHello{'fragment_offset_3rd_byte'}) ) && ($serverHello{'fragment_offset_3rd_byte'} > 0) ) ) {

                            $serverHello{'fragment_offset'} |= $serverHello{'fragment_offset_3rd_byte'} <<16 if ($serverHello{'fragment_offset_3rd_byte'} > 0);
                            _trace ("parseHandshakeRecord: $host:$port: Received a huge fragment offset of $serverHello{'fragment_offset'} bytes\n") if ($serverHello{'fragment_offset_3rd_byte'} > 0);
                            $my_error= "$host:$port: sorry, fragmented DTLS packets are not yet supported -> Retry";   ####TBD TBD TBD ###
                            _trace2 ("parseHandshakeRecord: $my_error\n");
                            carp ("parseHandshakeRecord: $my_error");
                            return ("", $lastMsgType, 0, "");
                        }
                        $serverHello{'fragment_len'} |= $serverHello{'fragment_len_3rd_byte'} <<16 if ($serverHello{'fragment_len_3rd_byte'} > 0);
                        _trace ("parseHandshakeRecord: >>>WARNING: $host:$port: Received a huge fragment with $serverHello{'fragment_len'} bytes\n") if ($serverHello{'fragment_len_3rd_byte'} > 0);
                        carp   ("parseHandshakeRecord: >>>WARNING: $host:$port: Received a huge fragment with $serverHello{'fragment_len'} bytes\n") if ($serverHello{'fragment_len_3rd_byte'} > 0);
                    }
                    $serverHello{'msg_len'} |= $serverHello{'msg_len_3rd_byte'} <<16 if ($serverHello{'msg_len_3rd_byte'} > 0);
                    if (length ($rest) < $serverHello{'msg_len'}) { #The message is fragmented .... rare, but it may occur
                        #  fragmented message -> Read next Packet, parse the packet Haeder go on with the message)
                        ## fragmented message (real length is shorter than the claimed length); test with STARTTLS at smtp.rzone.de:25 -> and receive a very long Certificate Request
                        # test huge messages using '10000-sans.badssl.com' (https)
                        _trace2_ ("parseHandshakeRecord: Server '$host:$port': Received a huge message with $serverHello{'msg_len'} bytes\n") if ($serverHello{'msg_len_3rd_byte'} > 0);
                        _trace2_ ("parseHandshakeRecord: fragmented message with $serverHello{'msg_len'} bytes length -> get next record\n");
                        return ($nextMessages, $HANDSHAKE_TYPE {'<<fragmented_message>>'}, $serverHello{'cookie_length'}, $serverHello{'cookie'});
                    }

                    _trace ("parseHandshakeRecord: >>> WARNING: Server '$host:$port': Received a huge message with $serverHello{'msg_len'} bytes\n") if ($serverHello{'msg_len_3rd_byte'} > 0);
                    carp   ("parseHandshakeRecord: >>> WARNING: Server '$host:$port': Received a huge message with $serverHello{'msg_len'} bytes\n") if ($serverHello{'msg_len_3rd_byte'} > 0);

                    ($message,                        #a[$serverHello{'msg_len'}]
                    $nextMessages) = unpack("a[$serverHello{'msg_len'}] a*", $rest);
                    _trace4_ ( sprintf (
                        "# --->      message [len= %d]: >%s<\n",
                        length ($message),                      #real length
                        hexCodedString ($message, "                               ")
                    ));

                    # parse several messages types (only those that we do need....)
                    if ($serverHello{'msg_type'} == $HANDSHAKE_TYPE {'server_hello'}) { ### Serever Hello -> to get the cipher and some supported extensions (planned)
                        _trace2_ ("# -->     Handshake type:    Server Hello (22)\n");

                        $cipher =  parseTLS_ServerHello ($host, $port, $message, $serverHello{'msg_len'},$client_protocol);
                        $lastCipher = $cipher; # to link further Information to this cipher
#                       return (parseTLS_ServerHello ($host, $port, $message, $serverHello{'msg_len'},$client_protocol),$lastMsgType, 0,""); # moved bebind the 'while-loop'
                        _trace2_ ("# ==>       found cipher:      >0x0300".hexCodedCipher($cipher)."<\n");
                    } elsif ($serverHello{'msg_type'} == $HANDSHAKE_TYPE {'hello_verify_request'}) { # DTLS only: get the Cookie to resend the request
                        if (length($message) >= 3) {
                            ($serverHello{'version'},              # n
                             $serverHello{'cookie_length'},        # C
                             $rest) = unpack("n C a*", $message);

                            $serverHello{'cookie'} = "";
                            ($serverHello{'cookie'},               # a[$serverHello{'cookie_length'}
                             $rest) = unpack("a[$serverHello{'cookie_length'}] a*", $rest) if ($serverHello{'cookie_length'} > 0) ;

                            _trace2_ ( sprintf ( #added to check the supported Version
                                "# -->       version:            >%04X<\n".
                                "# -->       cookie_length:        >%02X<\n".    # C
                                "# -->       cookie:             >%s<\n",        # a[$serverHello{'cookie_length'}
                                $serverHello{'version'},
                                $serverHello{'cookie_length'},        # C
                                hexCodedString ($serverHello{'cookie'})               # a[$serverHello{'cookie_length'}
                            ));
                            if (length ($serverHello{'cookie'}) != $serverHello{'cookie_length'}) {
                                $my_error = "Server '$host:$port': DTLS-HelloVerifyRequest: Len of Cookie (".length ($serverHello{'cookie'}).") <> 'cookie_length' ($serverHello{'cookie_length'})";
                                $serverHello{'cookie_length'} = length ($serverHello{'cookie'});
                                carp ("parseHandshakeRecord: $my_error");
                            }
                            if ($serverHello{'cookie_length'} > 32) {
                                $my_error = "Server '$host:$port': DTLS-HelloVerifyRequest: 'cookie_length' ($serverHello{'cookie_length'}) out of Range <0..32)";
                                carp ("parseHandshakeRecord: $my_error");
                            }
                            return ("", $lastMsgType, $serverHello{'cookie_length'}, $serverHello{'cookie'});
                        }
                    } elsif ($serverHello{'msg_type'} == $HANDSHAKE_TYPE {'server_key_exchange'}) { ##### Server Key Exchange: to check DHE und ECDHE parameters
                        _trace2 ("parseHandshakeRecord: Cipher: ".hexCodedCipher ($lastCipher)."\n");
                        $keyExchange = $cipherHexHash {'0x0300'.hexCodedCipher($lastCipher)}[0];
                        if (defined ($keyExchange)) { # found a cipher
                            _trace2_ (" --> Cipher(1): $keyExchange\n");
                            $keyExchange =~ s/((?:EC)?DHE?)_anon.*/A$1/x;   # DHE_anon -> EDH, ECDHE_anon -> AECDH, DHE_anon -> ADHE
                            _trace4_ (" --> Cipher(2): $keyExchange\n");
                            $keyExchange =~ s/((?:EC)?DH)E.*/E$1/x;         # DHE -> EDH, ECDHE -> EECDH
                            _trace4_ (" --> Cipher(3): $keyExchange\n");
                            $keyExchange =~ s/^(?:EXP[_-])?(?:E|A|EA)((?:EC)?DH).*/$1/x; # EDH -> DH, ADH -> DH, EECDH -> ECDH
                            _trace2_ (" --> KeyExchange (DH or ECDH) = $keyExchange\n"); # => ECDH or DH

#                           $_SSLhello {hexCodedString($pduVersion)."\|".$sni."\|".hexCodedCipher($lastCipher)."\|ServerKey"} = parseServerKeyExchange ($keyExchange, length($message), $message);
                            $_SSLhello {'0x0300'.hexCodedCipher($lastCipher)."\|ServerKey"} = parseServerKeyExchange ($keyExchange, length($message), $message);
                            if (defined ($_SSLhello {'0x0300'.hexCodedCipher($lastCipher)."\|ServerKey"})) {

                                _trace2_("\n   parseHandshakeRecord: Cipher:".hexCodedCipher ($lastCipher)." -> DH_serverParam: ".$_SSLhello {'0x0300'.hexCodedCipher($lastCipher)."\|ServerKey"});
                            }
                        } else { # no cipher found
                            _trace2 ("parseHandshakeRecord: No name found for cipher: >0x3000".hexCodedCipher($lastCipher)."< -> counld NOT check the ServerKeyExchange\n");
                            $_SSLhello{'0x0300'.hexCodedCipher($lastCipher)."\|ServerKey"} = "---unknown--";
                        }
                    } elsif ($serverHello{'msg_type'} == $HANDSHAKE_TYPE {'certificate'}) {
                         _trace2("parseHandshakeRecord: MessageType \"Certificate\" = ".sprintf("0x%02X", $serverHello{'msg_type'}) . " not yet analyzed\n");
                    } elsif ($serverHello{'msg_type'} == $HANDSHAKE_TYPE {'certificate_request'}) {
                         _trace2("parseHandshakeRecord: MessageType \"Certificate request\" = ".sprintf("0x%02X", $serverHello{'msg_type'}) . " not yet analyzed\n");
                    } elsif ($serverHello{'msg_type'} == $HANDSHAKE_TYPE {'server_hello_done'}) {
                         _trace4("parseHandshakeRecord: MessageType \"ServerHelloDone\" = ".sprintf("0x%02X", $serverHello{'msg_type'}) . " -> Final hello Message\n");
                         last; # hello message phase of the handshake is completed
                    } else {
                        _trace2("parseHandshakeRecord: MessageType ".sprintf("%02X", $serverHello{'msg_type'}) . " not yet analyzed\n");
                    }
                    _trace2_("\n"); # next message
                } # while (nextMessages ne ""()
                return ($cipher,$lastMsgType, 0,"");
            } elsif ($recordType == $RECORD_TYPE {'alert'}) {
                $serverHello{'msg_type'} = 0;           # NO Handshake => set 0
                $serverHello{'msg_len_3rd_byte'} = 0;   # NO Handshake => set 0
                $serverHello{'msg_len'} = 0;            # NO Handshake => set 0
                $serverHello{'fragment_3rd_byte'} = 0;  # NO Handshake => set 0
                $serverHello{'fragment_offset'} = 0;    # NO Handshake => set 0
                $serverHello{'fragment_3rd_byte'} = 0;  # NO Handshake => set 0
                $serverHello{'fragment_len'} = 0;       # NO Handshake => set 0

                ($serverHello{'level'},      # C
                 $serverHello{'description'} # C
                ) = unpack("C C", $recordData); # parse alert messages

                if ($TLS_AlertDescription {$serverHello{'description'}} ) { # defined, no Null-String
                        $description = $TLS_AlertDescription {$serverHello{'description'}}[0]." ".$TLS_AlertDescription {$serverHello{'description'}}[2];
                } else {
                        $description = "Unknown/Undefined";
                }

                _trace2_ ("# -->  Alert Message (Record type 21):\n");
                _trace2_ ("# -->      Level:       $serverHello{'level'}\n");
                _trace2_ ("# -->      Description: $serverHello{'description'} ($description)\n");

                if ($recordVersion == 0x0000) { # some servers use this dummy version to indicate that the requested version is not supported
                    if (! defined $ssl_client) {
                        $ssl_client = "--unknown protocol--";
                    }
                    OSaft::error_handler->new( {
                        type    => (OERR_SSLHELLO_ABORT_PROTOCOL),
                        id      => 'parse alert record (1)',
                        message => sprintf ("unsupported protocol $ssl_client (0x%04X) by $host:$port, answered with (0x%04X)", $client_protocol, $recordVersion),
                        warn    => 0,
                    } );
                    return ("", $lastMsgType, 0 , "");
                }
                # error handling according to # http://www.iana.org/assignments/tls-parameters/tls-parameters-6.csv
                unless ( ($serverHello{'level'} == 2) &&
                        (  ($serverHello{'description'} == 40) # handshake_failure(40): usually cipher not found is suppressed
                           || ($serverHello{'description'} == 71) # insufficient_security(71): no (secure) cipher found, is suppressed
                        ) ) {
                    if ($serverHello{'level'} == 1) { # warning
                        if ($serverHello{'description'} == 112) { #SNI-Warning: unrecognized_name
                            if ( ($Net::SSLhello::usesni) && !( ( ($client_protocol == $PROTOCOL_VERSION{'SSLv3'}) && (!$Net::SSLhello::force_TLS_extensions) ) || ($client_protocol == $PROTOCOL_VERSION{'SSLv2'}) ) ) {           # SNI sent
                                $sni = "";
                                unless ($Net::SSLhello::use_sni_name) {
                                    $sni = "'$host'";           # Server Name, should be a Name no IP
                                } else {                        # different sni_name
                                    $sni = ($Net::SSLhello::sni_name) ? "'$Net::SSLhello::sni_name'" : "''"; # allow empty nonRFC-SNI-Names
                                }
                                $my_error = sprintf ("parseHandshakeRecord: Server '$host:$port' ($ssl_client): received SSL/TLS warning: Description: $description ($serverHello{'description'}) -> check of virtual server $sni aborted!\n");
                                _trace4 ($my_error);
                                carp ("**WARNING: $my_error\n");
                            } else {                            # NO SNI extension sent
                                $my_error = sprintf ("parseHandshakeRecord: Server '$host:$port' ($ssl_client): received SSL/TLS warning: Description: $description ($serverHello{'description'}), but NO SNI extension has been sent. -> check of server aborted!");
                                _trace4 ($my_error);
                                carp ("**WARNING: $my_error\n");
                                _hint ("Server seens to to be a virtual server, consider adding the option '--sni' (Server Name Indication)for TLSv1 and higher");
                            }
                            return ("", $lastMsgType, 0 , "");
                        } else {
                            carp ("**WARNING: parseHandshakeRecord: Server '$host:$port' ($ssl_client): received SSL/TLS warning (1): Description: $description ($serverHello{'description'})\n");
                        }
                    } elsif ($serverHello{'level'} == 2) { # fatal
                        if ($serverHello{'description'} == 70) { # protocol_version(70): (old) protocol recognized but not supported, is suppressed
                            OSaft::error_handler->new( {
                                type    => (OERR_SSLHELLO_ABORT_PROTOCOL),
                                id      => 'parse alert record (2)',
                                message => sprintf ("unsupported protocol $ssl_client (0x%04X) by $host:$port: received a SSL/TLS-Warning: Description: $description ($serverHello{'description'})", $client_protocol),
                                warn    => 0,
                            } );
                        } elsif ($serverHello{'description'} == 112) { #SNI-Warning: unrecognized_name
                            if ( ($Net::SSLhello::usesni) && !( ( ($client_protocol == $PROTOCOL_VERSION{'SSLv3'}) && (!$Net::SSLhello::force_TLS_extensions) ) || ($client_protocol == $PROTOCOL_VERSION{'SSLv2'}) ) ) {           # SNI sent
                                $sni = "";
                                unless ($Net::SSLhello::use_sni_name) {
                                    $sni = "'$host'" if ($Net::SSLhello::usesni); # Server Name, should be a Name no IP
                                } else {                            # different sni_name
                                    $sni = ($Net::SSLhello::sni_name) ? "'$Net::SSLhello::sni_name'" : "''"; # allow empty nonRFC-SNI-Names
                                }
                                $my_error = sprintf ("parseHandshakeRecord: Server '$host:$port' ($ssl_client): received fatal SSL/TLS error (2a): Description: $description ($serverHello{'description'}) -> check of virtual server $sni aborted!\n");
                                _trace4 ($my_error);
                                carp ("**WARNING: $my_error\n");
                            } else {                                # NO SNI extension sent
                                $my_error = sprintf ("parseHandshakeRecord: Server '$host:$port' ($ssl_client): received fatal SSL/TLS error (2b): Description: $description ($serverHello{'description'}), but NO SNI extension has been sent. -> check of server aborted!");
                                _trace4 ($my_error);
                                carp ("**WARNING: $my_error\n");
                                _hint ("Server seens to to be a virtual server, consider adding the option '--sni' (Server Name Indication)for TLSv1 and higher");
                            }
                            return ("", $lastMsgType, 0 , "");
                        } else {
                            _trace4 ($my_error);
                            carp ("**WARNING: parseHandshakeRecord: Server '$host:$port' ($ssl_client): received fatal SSL/TLS error (2c): Description: $description ($serverHello{'description'})\n");
                            if ($serverHello{'description'} == 50) { # decode_error (50)
                                _hint("The server may not support the extension for elliptic curves (ECC) nor discard it silently, consider adding the option '--ssl-nouseecc'.");
                            }
                        }
                    } else { # unknown
                        carp ("**WARNING: parseHandshakeRecord: Server '$host:$port' ($ssl_client): received unknown SSL/TLS error level ($serverHello{'level'}): Description: $description ($serverHello{'description'})\n");
                    }
                }
            } else { ################################ to get information about record types that are not parsed, yet #############################
                _trace_ ("\n");
                carp ("**WARNING: parseHandshakeRecord: Server '$host:$port': Unknown SSL/TLS record type received that is not (yet) defined in Net::SSLhello.pm:\n");
                carp ("#        Record type:     Unknown value (0x".hexCodedString($recordType)."), not (yet) defined in Net::SSLhello.pm\n");
                carp ("#        Record version:  $recordVersion (0x".hexCodedString ($recordVersion).")\n");
                carp ("#        Record len:      $recordLen (0x".hexCodedString ($recordLen).")\n\n");
            }
            return ("", $lastMsgType, 0 , "");
        } #End SSL3/TLS or DTLS
    } else {
        carp ("**WARNING: parseHandshakeRecord: Server '$host:$port': (no SSL/TLS record) : ".hexCodedString ($recordData)."\n");
        return ("",$lastMsgType, 0 , "");
    }
    carp ("**WARNING: parseHandshakeRecord: Server '$host:$port': Internal error: ".hexCodedString ($recordData)."\n");
    return ("",$lastMsgType, 0 , "");
} # parseHandshakeRecord


sub parseServerHello ($$$;$) {
    #? <<description missing>> <<POD missing>> # FIXME:
    # Variable: String/Octet, dass das Server-Hello-Paket enthält  ; second (opional) variable: protocol-version, that the client uses
    my $host            = shift || "";  # for carp- and trace messages
    my $port            = shift || "";  # for carp- and trace messages
    my $buffer          = shift || "";
    my $client_protocol = shift || "";  # optional
    my $rest            = "";
    my $tmp_len         = 0;
    my $message         = "";
    my $nextMessages    = "";
    my %serverHello;
    my $description     = "";
    local $my_error     = "";

    if (length ($buffer) >=5) { # received data in the buffer, at least 5 bytes
        my $firstByte = unpack ("C", $buffer);

        if (defined $client_protocol) {
            _trace2("parseServerHello: Server '$host:$port': (expected protocol= >".sprintf ("%04X", $client_protocol)."<,\n      >".hexCodedString (substr($buffer,0,48),"       ")."< ...)\n");
        } else {
            _trace2("parseServerHello: Server '$host:$port': (any protocol,\n Data=".hexCodedString (substr($buffer,0,48),"       ").")... \n");
        }
        _trace4 (sprintf ("parseServerHello: Server '$host:$port': 1. Byte:  %02X\n\n", $firstByte) );
        if ($firstByte >= 0x80) {   # SSL2 with 2 byte Length
            _trace2_ ("# -->SSL: Message type SSL2-Msg");
            ($serverHello{'msg_len'},         # n
             $serverHello{'msg_type'},        # C
             $rest) = unpack("n C a*", $buffer);

            $serverHello{'msg_len'} -= 0x8000;  # delete MSB

            _trace2_ (sprintf (
                "# -->        ParseServerHello(1):\n".
                "# -->        msg_len:              >%04X<\n".
                "# -->        msg_type:               >%02X<\n",
                $serverHello{'msg_len'},
                $serverHello{'msg_type'}
            ));
            _trace4 ("parseServerHello: Server '$host:$port': Rest: >".hexCodedString ($rest)."<\n");

            if ($serverHello{'msg_type'} == $SSL_MT_SERVER_HELLO) {
                _trace4 ("    Handshake Protocol: SSL2 Server Hello\n");
                _trace4 ("        Message Type: (Server Hello (2)\n");
                return (parseSSL2_ServerHello ($host, $port, $rest,$client_protocol)); # cipher_spec-Liste
            } elsif ($serverHello{'msg_type'} == $SSL_MT_ERROR) { #TBD error handling for ssl2
                ($serverHello{'err_code'}        # n
                 ) = unpack("n", $rest);

                _trace2 ("parseServerHello: Server '$host:$port': received a SSLv2-Error-Message, Code: >0x".hexCodedString ($serverHello{'err_code'})."<\n");
                unless ($serverHello{'err_code'} == 0x0001) { # SSLV2_No_Cipher
                    carp ("**WARNING: parseServerHello: Server '$host:$port': received a SSLv2-Error_Message: , Code: >0x".hexCodedString ($serverHello{'err_code'})." -> Target Ignored\n");
                }
                return ("");
            } else { # if ($serverHello{'msg_type'} == 0 => NOT supported protocol (?!)
                $my_error = "    Unknown SSLv2 message type (Dez): ".$serverHello{'msg_type'}.", Msg: >".hexCodedString ($buffer)."< -> Target Ignored\n"; }
                return ("");
        } else { # TLS record
            _trace2_("# -->TLS record layer:\n");
            ($serverHello{'record_type'},       # C
             $serverHello{'record_version'},    # n
             $serverHello{'record_len'},        # n
### perhaps this could be a good point to start a new function to parse a Message => to check certificates etc later###
             $serverHello{'msg_type'},          # C
             $serverHello{'msg_len_3rd_byte'},  # C
             $serverHello{'msg_len'},           # n
             $rest) = unpack("C n n C C n a*", $buffer);

            if ($serverHello{'record_type'} == $RECORD_TYPE {'handshake'}) {
                _trace2_ (sprintf (
                     "# -->    => SSL3/TLS record type: Handshake  (%02X):\n".
                     "# -->    record_version:  >%04X<\n".
                     "# -->    record_len:      >%04X<\n".
                     "# -->       msg_type:         >%02X<\n".
                     "# -->       msg_len:         >%02X%04X<\n",
                       $serverHello{'record_type'},
                       $serverHello{'record_version'},
                       $serverHello{'record_len'},
                       $serverHello{'msg_type'},
                       $serverHello{'msg_len_3rd_byte'},  # prefetched for record_type handshake
                       $serverHello{'msg_len'}            # prefetched for record_type handshake
                ));

                $serverHello{'msg_len'} |= $serverHello{'msg_len_3rd_byte'} <<16 if ($serverHello{'msg_len_3rd_byte'} > 0);
                _trace ("parseServerHello: >>> WARNING: Server '$host:$port': Received a huge message with $serverHello{'msg_len'} bytes\n") if ($serverHello{'msg_len_3rd_byte'} > 0);
                carp   ("parseServerHello: >>> WARNING: Server '$host:$port': Received a huge message with $serverHello{'msg_len'} bytes\n") if ($serverHello{'msg_len_3rd_byte'} > 0);
                ($message,                        #a[$serverHello{'msg_len'}]
                $nextMessages) = unpack("a[$serverHello{'msg_len'}] a*", $rest);

                _trace4_ ( sprintf (
                    "# --->      message:       >%s<\n",
                    hexCodedString ($message)
                ));

                if ($serverHello{'msg_type'} == $HANDSHAKE_TYPE {'server_hello'}) {
                    _trace3_ ("# -->     Handshake type:    Server Hello (22)\n");
                    _trace4_ ("# --->    Handshake type:    Server Hello (22)\n");

                    return (parseTLS_ServerHello ($host, $port, $message, $serverHello{'msg_len'},$client_protocol));
                }
            } elsif    ($serverHello{'record_type'} == $RECORD_TYPE {'alert'}) {
                _trace2_ ("# -->  Record type:    Alert (21)\n");
                _trace2_ (sprintf("# -->  Record version:  $serverHello{'record_version'} (0x%04X)\n",$serverHello{'record_version'}));
                _trace2_ (sprintf("# -->  Record len:      $serverHello{'record_len'}   (0x%04X)\n",$serverHello{'record_len'}));
                $serverHello{'msg_type'} = 0;          # KEIN Handshake = löschen
                $serverHello{'msg_len_3rd_byte'} = 0;  # KEIN Handshake = löschen
                $serverHello{'msg_len'} = 0;           # KEIN Handshake = löschen
                ($serverHello{'level'},      # C
                 $serverHello{'description'} # C
                ) = unpack("x5 C C", $buffer); # Workaroud, da oben zu viel gelesen wird

                if ($TLS_AlertDescription {$serverHello{'description'}} ) { # defined, no Null-String
                        $description = $TLS_AlertDescription {$serverHello{'description'}}[0]." ".$TLS_AlertDescription {$serverHello{'description'}}[2];
                } else {
                        $description = "Unknown/Undefined";
                }

                _trace2_ ("# -->  Alert Message:\n");
                _trace2_ ("# -->      Level:       $serverHello{'level'}\n");
                _trace2_ ("# -->      Description: $serverHello{'description'} ($description)\n");

                if ($serverHello{'record_version'} == 0x0000) { # some servers use this dummy version to indicate that the requested version is not supported
                    my %rhash = reverse %PROTOCOL_VERSION;
                    my $ssl_client = $rhash{$client_protocol};
                    if (! defined $ssl_client) {
                        $ssl_client = "--unknown protocol--";
                    }
                    $my_error = sprintf ("parseServerHello: Server '$host:$port': requested protocol $ssl_client (0x%04X) is not supported by the Server (the server answered with the protocol 0x%04X) -> protocol_version recognized but not supported!", $client_protocol, $serverHello{'record_version'});
                    _trace2 ("$my_error\n");
                    return ("");
                }

                # error handling according to # http://www.iana.org/assignments/tls-parameters/tls-parameters-6.csv
                unless ( ($serverHello{'level'} == 2) &&
                        (  ($serverHello{'description'} == 40) # handshake_failure(40): usually cipher not found is suppressed
                           || ($serverHello{'description'} == 71) # insufficient_security(71): no (secure) cipher found, is suppressed
                        ) ) {
                    if ($serverHello{'level'} == 1) { # warning
                        if ($serverHello{'description'} == 112) { #SNI-Warning: unrecognized_name
                            my $sni = "";
                            $Net::SSLhello::use_sni_name = 1 if ( ($Net::SSLhello::use_sni_name == 0) && ($Net::SSLhello::sni_name ne "1") ); ###FIX: quickfix until migration of o-saft.pl is compleated (tbd)
                            unless ($Net::SSLhello::use_sni_name) {
                                $sni = "'$host'" if ($Net::SSLhello::usesni); # server name, should be a name no IP
                            } else { # different sni_name
                                $sni = ($Net::SSLhello::sni_name) ? "'$Net::SSLhello::sni_name'" : "''"; # allow empty nonRFC-SNI-Names
                            }
                            $my_error = sprintf ("parseServerHello: Server '$host:$port': received SSL/TLS-Warning: Description: $description ($serverHello{'description'}) -> check of virtual Server $sni aborted!\n");
                            print $my_error;
                            return ("");
                        } else {
                            carp ("**WARNING: parseServerHello: Server '$host:$port': received SSL/TLS-Warning (1): Description: $description ($serverHello{'description'})\n");
                        }
                    } elsif ($serverHello{'level'} == 2) { # fatal
                        if ($serverHello{'description'} == 70) { # protocol_version(70): (old) protocol recognized but not supported, is suppressed
                            $my_error = sprintf ("parseServerHello: Server '$host:$port': received SSL/TLS-Warning: Description: $description ($serverHello{'description'}) -> protocol_version recognized but not supported!\n");
                        } else {
                            carp ("**WARNING: parseServerHello: Server '$host:$port': received fatal SSL/TLS-Error (2): Description: $description ($serverHello{'description'})\n");
                            if ($serverHello{'description'} == 50) { # decode_error (50)
                                _hint("The server may not support the extension for elliptic curves (ECC) nor discard it silently, consider adding the option '--ssl-nouseecc'.");
                            }
                        }
                    } else { # unknown
                        carp ("**WARNING: parseServerHello: Server '$host:$port': received unknown SSL/TLS-Error-Level ($serverHello{'level'}): Description: $description ($serverHello{'description'})\n");
                    }
                }
            } else { ################################ to get information about record types that are not parsed, yet #############################
                _trace_ ("\n");
                carp ("**WARNING: parseServerHello: Server '$host:$port': Unknown SSL/TLS record type received that is not (yet) defined in Net::SSLhello.pm:\n");
                carp ("#        Record type:     Unknown value (".$serverHello{'record_type'}."), not (yet) defined in Net::SSLhello.pm\n");
                carp ("#        Record version:  $serverHello{'record_version'} (0x".hexCodedString ($serverHello{'record_version'}).")\n");
                carp ("#        Record len:      $serverHello{'record_len'} (0x".hexCodedString ($serverHello{'record_len'}).")\n\n");
            }
            return ("");
        } #End SSL3/TLS
    } else {
        carp ("**WARNING: parseServerHello Server '$host:$port': (no SSL/TLS record) : ".hexCodedString ($buffer)."\n");
    }
    return;
} # parseServerHello


sub parseSSL2_ServerHello ($$$;$) {
    #? <<description missing>> <<POD missing>> # FIXME:
    # Variable: String/Octet, das den Rest des Server-Hello-Pakets enthält
    my $host            = shift || "";  # for warn- and trace messages
    my $port            = shift || "";  # for warn- and trace messages
    my $buffer          = shift || "";
    my $client_protocol = shift || "";  # optional
    my $rest;
    my %serverHello;

    $serverHello{'cipher_spec'} = "";

    if (defined $client_protocol) {
        _trace3("parseSSL2_ServerHello: Server '$host:$port': (expected protocol=".sprintf ("%04X", $client_protocol).", Data=".hexCodedString (substr($buffer,0,48),"       ")."...)\n");
    } else {
        _trace4("parseSSL2_ServerHello: Server '$host:$port': (any protocol, Data=".hexCodedString (substr($buffer,0,48),"         ")."...)\n");
    }

    ($serverHello{'session_id_hit'},        # C
     $serverHello{'certificate_type'},        # C
     $serverHello{'version'},            # n
     $serverHello{'certificate_len'},    # n
     $serverHello{'cipher_spec_len'},    # n
     $serverHello{'connection_id_len'},    # n
     $rest) = unpack("C C n n n n a*", $buffer);


    _trace2_ ( sprintf (
           "# -->                      => SSL2: ServerHello (%02X):\n".
           "# -->        session_id_hit:         >%02X<\n".
           "# -->        certificate_type:       >%02X<\n".
           "# -->        version:              >%04X<\n".
           "# -->        certificate_len:      >%04X<\n".
           "# -->        cipher_spec_len:      >%04X<\n".
           "# -->        connection_id_len:    >%04X<\n",
           $SSL_MT_SERVER_HELLO,
           $serverHello{'session_id_hit'},
           $serverHello{'certificate_type'},
           $serverHello{'version'},
           $serverHello{'certificate_len'},
           $serverHello{'cipher_spec_len'},
           $serverHello{'connection_id_len'}
    ));

    _trace4  ("Rest: Server '$host:$port': >".hexCodedString ($rest)."<\n");

    ( $serverHello{'certificate'},    # n
      $serverHello{'cipher_spec'},    # n
      $serverHello{'connection_id'}   # n
    ) = unpack("a[$serverHello{'certificate_len'}] a[$serverHello{'cipher_spec_len'}] a[$serverHello{'connection_id_len'}]", $rest);

    _trace4 ("parseSSL2_ServerHello(2): Server '$host:$port':\n");

    _trace2_ ( sprintf (
            "# -->       certificate:          >%s<\n".    # n
            "# -->       cipher_spec:          >%s<\n".    # n
            "# -->       connection_id:        >%s<\n".    # n
            "# -->       parseServerHello-Cipher:\n",      # headline for next actions
             hexCodedString ($serverHello{'certificate'}),
             hexCodedString ($serverHello{'cipher_spec'},"     "),
             hexCodedString ($serverHello{'connection_id'})
    ));

    if ($Net::SSLhello::trace >= 3) { #trace3+4: added to check the supported version
        printf "## Server Server '$host:$port': accepts the following Ciphers with SSL-Version: >%04X<\n",
               $serverHello{'version'};
        printSSL2CipherList($serverHello{'cipher_spec'});
        print "\n";
    }
    ### added to check if there is a bug in getting the cipher_spec
    if (length ($serverHello{'cipher_spec'}) != int ($serverHello{'cipher_spec_len'}) ) { # did not get all ciphers?
            carp("**WARNING: parseSSL2_ServerHello: Server '$host:$port': Can't get all Ciphers from Server-Hello (String-Len: ".length ($serverHello{'cipher_spec'})." != cipher_spec_len: ".$serverHello{'cipher_spec_len'}."): >". hexCodedSSL2Cipher ($serverHello{'cipher_spec'})."<");
            printf "#                       => SSL2: ServerHello (%02X):\n".
                "#         session_id_hit:         >%02X<\n".
                "#         certificate_type:       >%02X<\n".
                "#         version:              >%04X<\n".
                "#         certificate_len:      >%04X<\n".
                "#         cipher_spec_len:      >%04X<\n".
                "#         connection_id_len:    >%04X<\n",
                $SSL_MT_SERVER_HELLO,
                $serverHello{'session_id_hit'},
                $serverHello{'certificate_type'},
                $serverHello{'version'},
                $serverHello{'certificate_len'},
                $serverHello{'cipher_spec_len'},
                $serverHello{'connection_id_len'};

            printf  "##        certificate:          >%s<\n".    # n
                "##        cipher_spec:          >%s<\n".    # n
                "##        connection_id:        >%s<\n",    # n
                hexCodedString ($serverHello{'certificate'}),
                hexCodedString ($serverHello{'cipher_spec'},"   "),
                hexCodedString ($serverHello{'connection_id'});
    }
    return ($serverHello{'cipher_spec'});
} # parseSSL2_ServerHello

=pod

=head2 parseTLS_ServerHello( )

# FIXME: missing

=cut


sub parseTLS_ServerHello {
    #? parse and get data from a ServerHello message that has been received via SSLv3 or TLS
    #? according RFC6101 (SSL3), RFC2246 (TLS1), RFC4346 (TLS1.1), RFC5246 (TLS1.2) and draft-ietf-tls-tls13 (TLS1.3)
    #? Variableis:
    #? $host and $port:   used for error and trave messages
    #? $buffer:           unparsed data of the ServerHello
    #? $len:              Len if the buffer
    #? $client_protokoll: optional the protocol used by the client
    #
    my $host            = shift || ""; #for warn- and trace-messages
    my $port            = shift || ""; #for warn- and trace-messages
    my $buffer          = shift || "";
    my $len             = shift || 0;
    my $client_protocol = shift || "";  # optional
    my $rest            = "";
    my $rest2           = "";
    my %serverHello;

    $serverHello{'cipher_spec'} = "";
    $serverHello{'extensions_len'} = 0;

    #reset error_handler and set basic information for this sub
    OSaft::error_handler->reset_err( {module => (SSLHELLO), sub => 'parseTLS_ServerHello', print => ($Net::SSLhello::trace > 0), trace => $Net::SSLhello::trace} );

    if (defined $client_protocol) {
        _trace3("parseTLS_ServerHello: Server '$host:$port': (expected protocol=".sprintf ("%04X", $client_protocol).",\n     ".hexCodedString (substr($buffer,0,48),"       ")."...)\n");
    } else {
        _trace4("parseTLS_ServerHello: Server '$host:$port': (any protocol, Data=".hexCodedString (substr($buffer,0,48),"         ")."...)\n");
    }

    if (length($buffer) || $len >= 35) {
        ($serverHello{'version'},           # n
        $serverHello{'random_gmt_time'},    # N    # A4
        $serverHello{'random'},             # A28
        $serverHello{'session_id_len'},     # C
        $rest) = unpack("n N a[28] C a*", $buffer);

        _trace2_ ( sprintf ( # added to check the supported version
                "# -->       => SSL/TLS-Version: (%04X):\n",
                $serverHello{'version'}
        ));

        if (defined ($client_protocol)) {
            if ($client_protocol != $serverHello{'version'}) {
                my %rhash = reverse %PROTOCOL_VERSION;
                my $ssl_client = $rhash{$client_protocol};
                my $ssl_server = $rhash{$serverHello{'version'}};
                if (! defined $ssl_client) {
                    $ssl_client = "--unknown protocol--";
                }
                if (! defined $ssl_server) {
                    $ssl_server = "--unknown protocol--";
                }
                if ($serverHello{'version'} == 0) {
                    # some servers respond with the dummy prtotocol '0x0000' if they do *not* support the requested protocol
                    OSaft::error_handler->new( {
                        type    => (OERR_SSLHELLO_ABORT_PROTOCOL),
                        id      => 'check record protocol (1)',
                        message => sprintf ("unsupported protocol $ssl_client (0x%04X) by $host:$port, answered with $ssl_server (0x%04X)", $client_protocol, $serverHello{'version'}),
                        warn    => 0,
                    } );
                } else { # unknown protocol
                    OSaft::error_handler->new( {
                        type    => (OERR_SSLHELLO_ABORT_PROTOCOL),
                        id      => 'check record protocol (2)',
                        message => sprintf ("unsupported protocol $ssl_client (0x%04X) by $host:$port, answered with $ssl_server (0x%04X)", $client_protocol, $serverHello{'version'}),
                        warn    => 0,
                    } );
                }
                return ("");
            }
        } else {
            carp ("**WARNING: parseTLS_ServerHello: Server '$host:$port': internal error: All Server Versions are accepted, because there is no information provided which version the client has requested.\n");
        }

        _trace2_ ( sprintf (
                "# -->       version:           >%04X<\n".
        #        "# -->       random_gmt_time:  >%08X< (%s)\n".
                "# -->       random_gmt_time:   >%08X<\n".
                "# -->       random:            >%s<\n".
                "# -->       session_id_len:      >%02X<\n",
                $serverHello{'version'},
                $serverHello{'random_gmt_time'},
        #        localtime($serverHello{'random_gmt_time'}),
                hexCodedString ($serverHello{'random'}),
                $serverHello{'session_id_len'}
        ));
        _trace4_ ( sprintf (
                "# -->       Rest: (len=%04X)   >%s<\n",
                length ($rest),
                hexCodedString ($rest, "                                    ")
        ));

        ($serverHello{'session_id'},        # A[]
        $serverHello{'cipher_spec'},        # A2: cipher_spec_len = 2
        $serverHello{'compression_method'}, # C
        $serverHello{'extensions_len'},     # n
        $rest2) = unpack("a[$serverHello{'session_id_len'}] a2 C n a*", $rest);

        _trace2_ ( sprintf (
                "# -->       session_id:        >%s<\n".
                "# -->       cipher_spec: (len=%2s) >%s<\n",
                hexCodedString ($serverHello{'session_id'}),
                length ($serverHello{'cipher_spec'}),
                hexCodedCipher ($serverHello{'cipher_spec'})
        ));

        ### added to check if there is a bug in getting the cipher_spec: cipher_spec_len = 2 ###
        if (length ($serverHello{'cipher_spec'}) !=  2 ) { # did not get the 2-Octet-Cipher?
            carp("**WARNING: parseTLS_ServerHello: Server '$host:$port': Can't get the Cipher from Server-Hello (String-Len: ".length ($serverHello{'cipher_spec'})." != cipher_spec_len: 2): >". hexCodedString ($serverHello{'cipher_spec'})."<");
        }
        _trace2_ ( sprintf (
            # added to check the supported version
            "# -->       The Server Server '$host:$port': accepts the following Cipher(s) with SSL3/TLS-Version: >%04X<:\n",
            $serverHello{'version'}
        ));

        if ($Net::SSLhello::trace > 2) {
            printTLSCipherList ($serverHello{'cipher_spec'});
        }

        _trace2_ ( sprintf (
            "\n# -->       compression_method:   >%02X<\n",
            $serverHello{'compression_method'}
        ));
        if ( $serverHello{'extensions_len'} !~ /(?:^$|[\x00]+)/x) { # extensions_len > 0
            ($serverHello{'extensions'},            # A[]
            $rest) = unpack("a[$serverHello{'extensions_len'}] a*", $rest2);

            _trace2_ ( sprintf (
                "# -->       extensions_len:   >%04X<\n",
                $serverHello{'extensions_len'}
            ));

            _trace4_ ( sprintf (
                "# -->       extensions:           >%s<\n".
                "# -->       Rest:                 >%s<\n",
                hexCodedString ($serverHello{'extensions'}),
                hexCodedString ($rest)
            ));
            parseTLS_Extension ($serverHello{'extensions'}, $serverHello{'extensions_len'});

            if  (length($rest) > 0) { # should be 0
                _trace2 ( sprintf ("\n\n## parseTLSServerHello Server '$host:$port': did not parse the whole message (rest): >".hexCodedString ($rest)."< To Be Done\n"));
            }
        }
        return ($serverHello{'cipher_spec'});
    } else {
        return ("");
    }
} # parseTLS_ServerHello


sub parseTLS_Extension {
    #? <<description missing>> <<POD missing>> # FIXME:
    # Variable: String/Octet, das die Extension-Bytes enthält
    my $buffer = shift || "";
    my $len    = shift || 0;

    my $rest   = "";
    my %serverHello;

    if (length($buffer) || $len >= 2) {
        ($serverHello{'extension_type'},     # n
         $serverHello{'extension_type_len'}, # n
         $rest) = unpack("n n a*", $buffer);

         _trace2_ ( sprintf (
            "# -->       extension_type:      >%04X<\n".
            "# -->       extension_type_len:  >%04X<\n",
            $serverHello{'extension_type'},
            $serverHello{'extension_type_len'}
        ));
        if (($rest) && ($serverHello{'extension_type_len'}) ) {
            ($serverHello{'extension_data'},    # A[]
            $rest) = unpack("a[$serverHello{'extension_type_len'}] a*", $rest);

              _trace2_ ( sprintf (
                "# -->           extension_data:  >%s<\n".
                "# -->           Rest:            >%s<\n",
                hexCodedString ($serverHello{'extension_data'}),
                hexCodedString ($rest)
            ));
            if (($rest) && (($len -4 -$serverHello{'extension_type_len'}) >0) ) {
                parseTLS_Extension ($rest, ($len -4 -$serverHello{'extension_type_len'}));
            }
        }
    }
    return;
} # parseTLS_Extension


sub _timedOut {
    croak "NET::SSLhello: Receive data timed out -> Received NO data (timeout)";
}

sub _chomp_r { # chomp \r\n
    my $string = shift || "";
    $string =~ s/(.*?)\r?\n?$/$1/gx;
    if ($string =~ /[^\x20-\x7E\t\r\n]/x) { # non printable charachers in string
        $string =~ s/([\x00-\xFF])/sprintf("%02X ", ord($1))/eigx; #Code all Octets as HEX values and seperate then with a 'space'
    }
    return ($string);
}

sub hexCodedString {
    #? <<description missing>> <<POD missing>> # FIXME:
    # Variable: String/Octet, der in HEX-Werten dargestellt werden soll, gibt Ausgabestring zurück
    my $codedString = shift || "";
    my $prefix      = shift; # set an optional prefix after '\n'
    return ("") if ($codedString eq "");
    if (!defined($prefix)) { # undefined -> ""
            $prefix = "";
    }
    $codedString =~ s/([\x00-\xFF])/sprintf("%02X ", ord($1))/eigx; # code all octets as HEX values and seperate then with a 'space'
    $codedString =~ s/((?:[0-9A-Fa-f]{2}\s){48})(?=[0-9A-Fa-f]{2})/"$1\n$prefix"/eigx; # add a new line each 48 HEX-octetts (=144 symbols incl. spaces) if not last octett reached
    chomp ($codedString); # delete CR at the end
    chop ($codedString);  # delete 'space' at the end
    return ($codedString);
} # hexCodedString


sub hexCodedCipher {
    #? <<description missing>> <<POD missing>> # FIXME:
    # Variable: String/Octet, der in HEX-Werten dargestellt werden soll, gibt Ausgabestring zurück
    my $codedString= shift || "";
    my $prefix= shift; # set an optional prefix after '\n'
    return ("") if ($codedString eq "");
    if (!defined($prefix)) { # undefined -> ""
            $prefix = "";
    }
    $codedString =~ s/([\x00-\xFF])/sprintf("%02X", ord($1))/eigx; # code all octets as HEX values and seperate then with a 'space'
    $codedString =~ s/((?:[0-9A-Fa-f]{2}){64})/"$1\n$prefix"/eigx; # add a new line each 64 HEX octetts (=128 symbols incl. spaces)
    chomp ($codedString); #delete CR at the end
    return ($codedString); #delete 'space' at the end
} # hexCodedCipher


sub hexCodedSSL2Cipher {
    #? <<description missing>> <<POD missing>> # FIXME:
    # Variable: String/Octet, der in HEX-Werten dargestellt werden soll, gibt Ausgabestring zurück
    my $codedString = shift || "";
    my $prefix      = shift; # set an optional prefix after '\n'
    return ("") if ($codedString eq "");
    if (!defined($prefix)) { # undefined -> ""
            $prefix = "";
    }
    $codedString =~ s/([\x00-\xFF])([\x00-\xFF])([\x00-\xFF])/sprintf("%02X%02X%02X ", ord($1), ord($2), ord($3))/eigx; #Code all 3-Octet-Ciphers as HEX value-Pairs and separate then with a 'space'
    $codedString =~ s/((?:[0-9A-Fa-f]{6}){16}\s)/"$1\n$prefix"/eigx; # add a new line each 16 ciphers (=112 symbols incl. spaces)
    chomp ($codedString); #delete CR at the end
    return ($codedString); #delete 'space' at the end
}

sub hexCodedTLSCipher {
    #? <<description missing>> <<POD missing>> # FIXME:
    # Variable: String/Octet, der in HEX-Werten dargestellt werden soll, gibt Ausgabestring zurück
    my $codedString = shift || "";
    my $prefix      = shift; # set an optional prefix after '\n'
    return ("") if ($codedString eq "");
    if (!defined($prefix)) { # undefined -> ""
            $prefix = "";
    }
    $codedString =~ s/([\x00-\xFF])([\x00-\xFF])/sprintf("%02X%02X ", ord($1), ord($2))/eigx; # code all 2-Octet-Ciphers as HEX value pairs and separate then with a 'space'
    $codedString =~ s/((?:[0-9A-Fa-f]{4}){16}\s)/"$1\n$prefix"/eigx; # add a new line each 16 ciphers (=80 symbols incl. spaces)
    chomp ($codedString);  # delete CR at the end
    return ($codedString); # delete 'space' at the end
} # hexCodedSSL2Cipher


sub compileSSL2CipherArray ($) {
    #? <<description missing>> <<POD missing>> # FIXME:
    my $cipherList  = shift || "";
    my $protocolCipher="";
    my $firstByte   = "";
    my @cipherArray = ();

    my $anzahl = int length ($cipherList) / 3;
    my @cipherTable = unpack("a3" x $anzahl, $cipherList);

    _trace4 ("compileSSL2CipherArray ($anzahl) {\n");
    for (my $i = 0; $i < $anzahl; $i++) {
        _trace4_ ( sprintf ("               Cipher[%2d]: ", $i));
        _trace4_ ( sprintf (" >".hexCodedSSL2Cipher ($cipherTable[$i])."< -> "));
        $firstByte = unpack ("C", $cipherTable[$i]);
        _trace4_ ( sprintf ("1. Byte: %02X -> ", $firstByte));
        if ($firstByte == 0x00) { # Version 3 Cipher 0x00xxxx
            $protocolCipher = pack ("a4a*", "0x03", hexCodedCipher($cipherTable[$i]));
        } else { # V2Cipher
            $protocolCipher = pack ("a4a*", "0x02", hexCodedCipher($cipherTable[$i]));
        }
        if ($Net::SSLhello::trace > 2) {
            if ($cipherHexHash {$protocolCipher} ) { # defined, no Null-String
                _trace_ (sprintf "%s -> %-32s -> %s", $protocolCipher, $cipherHexHash {$protocolCipher}[1], $cipherHexHash {$protocolCipher}[0]);
            } else {
                _trace_ ("$protocolCipher"." -> NO-RFC-".$protocolCipher);
            }
            _trace4_ ("\n");
        }
        push (@cipherArray, $protocolCipher); # add protocolCipher to Array
    }
    _trace4 ("compileSSL2CipherArray: }\n");
    return (@cipherArray);
} # compileSSL2CipherArray


sub compileTLSCipherArray ($) {
    #? <<description missing>> <<POD missing>> # FIXME:
    my $cipherList  = shift || "";
    my $protocolCipher = "";
    my $firstByte   = "";
    my @cipherArray = ();

    my $anzahl      = int length ($cipherList) / 2;
    my @cipherTable = unpack("a2" x $anzahl, $cipherList);

    _trace4 ("compileTLSCipherArray ($anzahl):\n");

    for(my $i = 0; $i < $anzahl; $i++) {
        _trace4_ (sprintf ("           Cipher[%2d]: ", $i));
        _trace4_ (sprintf (" >".hexCodedCipher ($cipherTable[$i])."< -> "));
        $protocolCipher = pack ("a6a*", "0x0300", hexCodedCipher($cipherTable[$i]));
        if ($Net::SSLhello::trace > 2) {
            if ( (defined ($cipherHexHash {$protocolCipher})) && ($#{$cipherHexHash {$protocolCipher}}>0) ) { # definiert, max index >0
                _trace4_ (sprintf ("%s -> %-32s -> %s", $protocolCipher, $cipherHexHash {$protocolCipher}[1], $cipherHexHash {$protocolCipher}[0]));
            } else {
                _trace4_ ("$protocolCipher -> NO-RFC-".$protocolCipher);
            }
            _trace4_ ("\n");
        }
        push (@cipherArray, $protocolCipher); # add protocolCipher to array
    }
    _trace4 ("compileTLSCipherArray: }\n");
    return (@cipherArray);
} # compileTLSCipherArray


sub printSSL2CipherList ($) {
    #? <<description missing>> <<POD missing>> # FIXME:
    my $cipherList  = shift || "";
    my $protocolCipher = "";
    my $firstByte   = "";

    my $anzahl      = int length ($cipherList) / 3;
    my @cipherTable = unpack("a3" x $anzahl, $cipherList);
    local $\ = ""; # no auto '\n' at the end of the line

    if ($Net::SSLhello::trace > 3) {
        _trace4 ("printSSL2CipherList ($anzahl):\n");
        for (my $i = 0; $i < $anzahl; $i++) {

            _trace4_ ( sprintf ("           Cipher[%2d]: ", $i));
            _trace4_ (" >".hexCodedCipher ($cipherTable[$i])."< -> ");
            $firstByte = unpack ("C", $cipherTable[$i]);
            _trace4_ (sprintf ("  1. Byte: %02X -> ", $firstByte));
            if ($firstByte == 0x00) { # Version 3 Cipher 0x00xxxx
                $protocolCipher = pack ("a4a*", "0x03", hexCodedCipher($cipherTable[$i]));
            } else { # V2Cipher
                $protocolCipher = pack ("a4a*", "0x02", hexCodedCipher($cipherTable[$i]));
            }
            if ( (defined ($cipherHexHash {$protocolCipher})) && ($#{$cipherHexHash {$protocolCipher}}>0) ) { # definiert, max index >0
                _trace4_ (sprintf ("%s -> %-32s -> %s", $protocolCipher, $cipherHexHash {$protocolCipher}[1], $cipherHexHash {$protocolCipher}[0]));
            } else {
                _trace4_ ("$protocolCipher -> NO-RFC-".$protocolCipher);
            }
            _trace_ "\n";
        }
        _trace_ "\n";
    }
    return;
} # printSSL2CipherList


sub printTLSCipherList ($) {
    #? <<description missing>> <<POD missing>> # FIXME:
    my $cipherList  = shift || "";
    my $protocolCipher = "";

    my $anzahl      = int length ($cipherList) / 2;
    my @cipherTable = unpack("a2" x $anzahl, $cipherList);
    local $\ = ""; # no auto '\n' at the end of the line

#    if ($Net::SSLhello::trace > 2)
    if ($Net::SSLhello::trace > 1) {

        _trace4 ("printTLSCipherList ($anzahl):\n");
        for(my $i = 0; $i < $anzahl; $i++) {
            _trace4_ (sprintf("           Cipher[%2d]: ", $i));
            _trace4_ (" >".hexCodedCipher ($cipherTable[$i])."< -> ");
            $protocolCipher = pack ("a6a*", "0x0300", hexCodedCipher($cipherTable[$i]));
            if ( (defined ($cipherHexHash {$protocolCipher})) && ($#{$cipherHexHash {$protocolCipher}}>0) ) { # definiert, max index >0
                _trace_ (sprintf "%s -> %-32s -> %s", $protocolCipher, $cipherHexHash {$protocolCipher}[1], $cipherHexHash {$protocolCipher}[0]);
            } else {
                _trace_ ("$protocolCipher -> NO-RFC-".$protocolCipher);
            }
            _trace4_ "\n";
        }
        _trace4_ ("\n");
    }
    return;
} # printTLSCipherList


=pod

=head1 EXAMPLES

See DESCRIPTION above.

=head1 LIMITATIONS

=head1 KNOWN PROBLEMS

=head1 DEENDENCIES

L<IO::Socket(1)>
L<IO::Socket::INET(1)>
L<OSaft::error_handler>

=head1 SEE ALSO

L<IO::Socket(1)>

=head1 AUTHOR

19-November-2014 Torsten Gigler

=cut

sub net_sslhello_done() {};     # dummy to check successful include
## PACKAGE }

unless (defined caller) {       # print myself or open connection
    printf("# %s %s\n", __PACKAGE__, $VERSION);
    if (eval {require POD::Perldoc;}) {
        # pod2usage( -verbose => 1 );
        exit( Pod::Perldoc->run(args=>[$0]) );
    }
    if (qx(perldoc -V)) {   ## no critic qw(InputOutput::ProhibitBacktickOperators)
        # may return:  You need to install the perl-doc package to use this program.
        #exec "perldoc $0"; # scary ...
        printf("# no POD::Perldoc installed, please try:\n  perldoc $0\n");
        exit 0;
    }
}

1;
