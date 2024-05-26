#!/usr/bin/perl -w
## PACKAGE {
# Filename : SSLhello.pm
#!#############################################################################
#!#                     Copyright (c) 2024, Torsten Gigler
#!#             This module is part of the OWASP-Project 'o-saft'
#!# It simulates the SSLhello packets to check SSL parameters like the ciphers
#!#         indepenantly from any SSL library like Openssl or gnutls.
#!#----------------------------------------------------------------------------
#!#       THIS Software is in ALPHA state, please give us feed back via
#!#                      https://github.com/OWASP/O-Saft
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
#!# modified by humans (you:) easily. Please see the documentation  in file
#!# Doc/coding.txt

package SSLhello;

# TODO:  TLSv13: Decrypt and parse also the encrypted extensions.

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

use strict;
use warnings;

my  $SID_sslhello = "@(#) SSLhello.pm 3.24 24/05/26 14:54:25";
our $VERSION    = "24.01.24";
my  $SSLHELLO   = "SSLhello";

BEGIN {
    # SEE Perl:@INC
    my $_path = $0; $_path =~ s#[/\\][^/\\]*$##;
    my $_pwd  = $ENV{PWD} || ".";   # . as fallback if $ENV{PWD} not defined
    unshift(@INC, $_path)   if (1 > (grep{/^$_path$/} @INC));
    unshift(@INC, $_pwd)    if (1 > (grep{/^$_pwd$/}  @INC));
    unshift(@INC, "lib")    if (1 > (grep{/^lib$/}    @INC));
    unshift(@INC, ".")      if (1 > (grep{/^\.$/}     @INC));
}

use Socket;     # constants and methods are used with full qualified name
#               # (contribution to stand-alone mode)
use IO::Socket::INET; #require IO::Select if ($SSLhello::trace > 1);
use Carp;
use OText         qw(%STR);
use OCfg;   # main parameters, lists and functions that are used by o-saft and SSLhello
use error_handler qw(%OERR);
    # use internal error_handler, get all constants used for SSLHELLO, for subs
    # the full names will be used (includung error_handler-><sub>)
# OSAFT_STANDALONE my  %OERR = %error_handler::OERR;
    # in stand-alone mode %OERR must be used as %error_handler::OERR

my %CST = (
    '_MY_SSL3_MAX_CIPHERS'                => 64, # Max nr of ciphers sent in a SSL3/TLS Client-Hello to test if they are supported by the server, e.g. 32, 48, 64, 128, ...
    '_MY_PRINT_CIPHERS_PER_LINE'          =>  8, # Nr of ciphers printed in a trace
    '_PROXY_CONNECT_MESSAGE1'             => "CONNECT ",
    '_PROXY_CONNECT_MESSAGE2'             => " HTTP/1.1\n\n",
    '_MAX_SEGMENT_COUNT_TO_RESET_RETRY_COUNT' => 16, # Max number og TCP-Segments that can reset the retry counter to '0' for next read
    '_SLEEP_B4_2ND_READ'                  => 0.5,  # Sleep before second read (STARTTLS and proxy) [in sec.x]
    '_DTLS_SLEEP_AFTER_FOUND_A_CIPHER'    => 0.75, # DTLS-Protocol: Sleep after found a cipher to segregate the following request [in sec.x]
    '_DTLS_SLEEP_AFTER_NO_CIPHERS_FOUND'  => 0.05  # DTLS-Protocol: Sleep after not found a cipher to segregate the following request [in sec.x]
); # %CST

#_____________________________________________________________________________
#___________________________________________________ package initialisation __|

$SSLhello::verbose              = 0;# 1=print checked ciphers
$SSLhello::prefix_verbose       = '#' . __PACKAGE__ . ' ';  # prefix string used in verbose messages
$SSLhello::prefix_trace         = '#' . __PACKAGE__ . '::'; # prefix string used in trace messages
$SSLhello::trace                = 0;# 1=simple debugging SSLhello
$SSLhello::traceTIME            = 0;# 1=trace prints timestamp
$SSLhello::usesni               = 1;# 0=do not use SNI extension, 1=use SNI extension (protocol >=tlsv1), 2(or 3): toggle sni (run twice per protocol without and with sni)
$SSLhello::use_sni_name         = 0;# 0=use hostname (default), 1: use sni_name for SNI mode connections
$SSLhello::sni_name             = "1";# name to be used for SNI mode connection is use_sni_name=1; ###FIX: "1": quickfix until migration of o-saft.pl is compleated (tbd)
$SSLhello::force_TLS_extensions = 0;# prevent to not to use TLS extensions in SSLv3
$SSLhello::timeout              = 2;# time in seconds
$SSLhello::retry                = 3;# number of retry when timeout occurs
$SSLhello::connect_delay        = 0;# time to wait in seconds for starting next cipher check
$SSLhello::usereneg             = 0;# secure renegotiation
$SSLhello::use_signature_alg    = 1;# signature_algorithm: 0 (off), 1 (auto on if >=TLSv1.2, >=DTLS1.2), 2: always on
$SSLhello::useecc               = 1;# use 'Supported Elliptic' Curves Extension
$SSLhello::useecpoint           = 1;# use 'ec_point_formats' extension
$SSLhello::starttls             = 0;# 1= do STARTTLS
$SSLhello::starttlsType         = "SMTP";# default: SMTP
$SSLhello::starttlsPhaseArray   = [];# STARTTLS: customised phases (1-5) and error handling (6-8)
$SSLhello::starttlsDelay        = 0;# STARTTLS: time to wait in seconds (to slow down the requests)
$SSLhello::slowServerDelay      = 0;# proxy and STARTTLS: time to wait in seconds (for slow proxies and STARTTLS servers)
$SSLhello::double_reneg         = 0;# 0=Protection against double renegotiation info is active
$SSLhello::proxyhost            = "";#
$SSLhello::proxyport            = "";#
$SSLhello::experimental         = 0;# 0: experimental functions are protected (=not active)
$SSLhello::max_ciphers          = $CST{'_MY_SSL3_MAX_CIPHERS'}; # max nr of ciphers sent in a SSL3/TLS Client-Hello to test if they are supported by the server
$SSLhello::max_sslHelloLen      = 16388; # according RFC: 16383+5 bytes; max len of SSLhello messages (some implementations had issues with packets longer than 256 bytes)
$SSLhello::noDataEqNoCipher     = 1; # 1= for some TLS intolerant servers 'NoData or timeout equals to no cipher' supported -> Do NOT abort to test next ciphers
$SSLhello::extensions_by_prot   = \%{$cfg{extensions_by_prot}}; # get the list of all extensions used by protocol, SSLv2 does not support any extensions by design
$SSLhello::check_extensions     = [ qw(supported_groups) ]; # List of extensions to be checked for all supported params
$SSLhello::extensions_max_values= 50; # max retries to check for additional variables of extensions. Acts as watchdog protecting against endless loops while checking for extensions
# avoid Perl warning "... used only once: possible typo ..."
my $dumm = $SSLhello::prefix_trace;
   $dumm = $SSLhello::prefix_verbose;

BEGIN {
    # section required only when called as: lib/SSLhello.pm or ./SSLhello.pm
    my $_me   = $0; $_me   =~ s#.*[/\\]##;
    # define trace functions, required if called in stand-alone mode
    if (not exists &_trace) {   # lazy check
        sub __ytime    { my $now = 1; return (0 >= $SSLhello::traceTIME) ? "" : sprintf(" [%02s:%02s:%02s]", (localtime($now))[2,1,0]); }
              #$now = time() if ($cfg_out('time_absolut'));# not supported here
        sub __y_me_ts  { return sprintf("#%s%s:", $SSLHELLO, __ytime()); }
        sub __trace    { my @txt = @_; printf("%s %s", __y_me_ts(), "@txt"); return; }
        sub _trace($)  { my @txt = @_; __trace($txt[0])     if ($SSLhello::trace > 0); return; }
        sub _trace1($) { my @txt = @_; __trace(@txt)        if ($SSLhello::trace > 1); return; }
        sub _trace2($) { my @txt = @_; __trace(@txt)        if ($SSLhello::trace > 2); return; }
        sub _trace3($) { my @txt = @_; __trace(@txt)        if ($SSLhello::trace ==3); return; }
        sub _trace4($) { my @txt = @_; __trace(@txt)        if ($SSLhello::trace > 3); return; }
        sub _trace5($) { my @txt = @_; __trace(@txt)        if ($SSLhello::trace > 4); return; }
        sub _trace_($) { my @txt = @_; printf(" %s", @txt)  if ($SSLhello::trace > 0); return; }
        sub _trace1_($){ my @txt = @_; printf("%s",  @txt)  if ($SSLhello::trace > 1); return; }
        sub _trace2_($){ my @txt = @_; printf("%s",  @txt)  if ($SSLhello::trace > 2); return; }
        sub _trace3_($){ my @txt = @_; printf("%s",  @txt)  if ($SSLhello::trace ==3); return; }
        sub _trace4_($){ my @txt = @_; printf("%s",  @txt)  if ($SSLhello::trace > 3); return; }
        sub _trace5_($){ my @txt = @_; printf("%s",  @txt)  if ($SSLhello::trace > 4); return; }
    }
}
# TODO: error_handler->reset_err() prints wrong prefix for trace>3

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=head1 NAME

SSLhello - Perl module for SSL to simulate SSLhello packets to check SSL parameters (especially ciphers).
Connections via proxy and using STARTTLS (SMTP, IMAP, POP3, FTPS, LDAP, RDP, XMPP and experimental: ACAP) are supported.

=head1 SYNOPSIS

use SSLhello;

=head1 DESCRIPTION

SSLhello.pm is a Perl Module that is part of the OWASP-Project 'o-saft'.
It checks some basic SSL/TLS configuration of a server, like ciphers and extensions (planned) of the SSL/TLS protocol. These checks work independently from any SSL library like OpenSSL or gnutls. It does this by simulating the first packets of a SSL/TLS connection. It sends a ClientHello message and analyses the ServerHello packet that is answered by the server. It gives you a wide range of options for this, so you can even check ciphers that are not yet defined, reserved or obsolete, by their 2-octet-values (see http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4).

As it simulates only the first part of the SSL/TLS handshake, it is really fast. Another advantage of this is that it can even analyse SSL/TLS ciphers of servers that verify client certificates without any need to provide a certificate (which is normally done later in the SSL/TLS handshake).

Export Functions:
$socket = openTcpSSLconnection ($host; $port); # Open a TCP/IP connection to a host on a port (via proxy) and doing STARTTLS if requested
@accepted = SSLhello::checkSSLciphers ($host, $port, $ssl, @testing); # Check a list if ciphers (@testing), output: @accepted ciphers (if the first 2 ciphers are equal the server has an order)
SSLhello::printCipherStringArray ($cfg{'legacy'}, $host, $port, $ssl, $sni, @accepted); # print the list of ciphers (@accepted ciphers)

=head1 OPTIONS

Following options are for internal testing:

=over 2

=item --help

=item --test-init

=item --test-parameters

=item --test-constants

List constants and/or parameters used by SSLhello.

=back

=head1 METHODS

=cut

#_____________________________________________________________________________
#____________________________________________________ export public methods __|

use Exporter qw(import);
use base qw(Exporter);
our @EXPORT_OK  = qw(
        net_sslhello_done
        checkSSLciphers
        getSSLciphersWithParam
        openTcpSSLconnection
        printCipherStringArray
        printParameters
        version
);

#_____________________________________________________________________________
#___________________________________________________________ initialisation __|

#our %main::cfg;    # provided by caller
our $dtlsEpoch = 0; # for DTLS only (globally)
our %_SSLhello;     # our internal data structure
our %resultHash;    # Hash that collects results
our %extensions_params_hash; # hasgh that (temporarily) defines parameters for an extension
our $my_error = ""; # global store for error message

#our $LONG_PACKET = 1940; # try to get a 2nd or 3rd segment for long packets

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
    'hello_verify_request'  => 3,       # rfc4347 DTLS
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
    'DTLSv09'    => 0x0100, # DTLS, OpenSSL pre 0.9.8f, not finally standardised (udp)
    'DTLSfamily' => 0xFE00, # DTLS1.FF, no defined PROTOCOL, for internal usea only (udp)
    'DTLSv1'     => 0xFEFF, # DTLS1.0 (udp)
    'DTLSv11'    => 0xFEFE, # DTLS1.1 (udp), has NEVER been used
    'DTLSv12'    => 0xFEFD, # DTLS1.2 (udp)
    'DTLSv13'    => 0xFEFC, # DTLS1.3 (udp), not YET specified
    'SCSV'       => 0x03FF  # adapted to o-saft.pl, was TLS1.FF # FIXME: TLS1.FF was better ;-) TBD: change it at o-saft.pl and delete it here
);

# reverse hash of PROTOCOL_VERSION
my %PROTOCOL_NAME_BY_HEX = reverse %PROTOCOL_VERSION;

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
    109 => [qw(missing_extension Y [RFC8446])],
    110 => [qw(unsupported_extension  Y  [RFC5246])],
    111 => [qw(certificate_unobtainable  Y  [RFC6066])],
    112 => [qw(unrecognized_name  Y  [RFC6066])],
    113 => [qw(bad_certificate_status_response  Y  [RFC6066])],
    114 => [qw(bad_certificate_hash_value  Y  [RFC6066])],
    115 => [qw(unknown_psk_identity  Y  [RFC4279])],
    116 => [qw(certificate_required  Y   [RFC8446])],
    120 => [qw(no_application_protocol Y [RFC7301][RFC8447])],
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
#Value =>     Description   bits(added) DTLS-OK RECOMMENDED Reference
#my %TLS_SUPPORTED_GROUPS = (
my %ECC_NAMED_CURVE = (
     0 => [qw(Reverved_0              0 N   N   [RFC8447])],
     1 => [qw(sect163k1             163 Y   N   [RFC4492])],
     2 => [qw(sect163r1             163 Y   N   [RFC4492])],
     3 => [qw(sect163r2             163 Y   N   [RFC4492])],
     4 => [qw(sect193r1             193 Y   N   [RFC4492])],
     5 => [qw(sect193r2             193 Y   N   [RFC4492])],
     6 => [qw(sect233k1             233 Y   N   [RFC4492])],
     7 => [qw(sect233r1             233 Y   N   [RFC4492])],
     8 => [qw(sect239k1             239 Y   N   [RFC4492])],
     9 => [qw(sect283k1             283 Y   N   [RFC4492])],
    10 => [qw(sect283r1             283 Y   N   [RFC4492])],
    11 => [qw(sect409k1             409 Y   N   [RFC4492])],
    12 => [qw(sect409r1             409 Y   N   [RFC4492])],
    13 => [qw(sect571k1             571 Y   N   [RFC4492])],
    14 => [qw(sect571r1             571 Y   N   [RFC4492])],
    15 => [qw(secp160k1             160 Y   N   [RFC4492])],
    16 => [qw(secp160r1             160 Y   N   [RFC4492])],
    17 => [qw(secp160r2             160 Y   N   [RFC4492])],
    18 => [qw(secp192k1             192 Y   N   [RFC4492])],
    19 => [qw(secp192r1             192 Y   N   [RFC4492])],
    20 => [qw(secp224k1             224 Y   N   [RFC4492])],
    21 => [qw(secp224r1             224 Y   N   [RFC4492])],
    22 => [qw(secp256k1             256 Y   N   [RFC4492])],
    23 => [qw(secp256r1             256 Y   Y   [RFC4492])],
    24 => [qw(secp384r1             384 Y   Y   [RFC4492])],
    25 => [qw(secp521r1             521 Y   N   [RFC4492])],
    26 => [qw(brainpoolP256r1       256 Y   Y   [RFC7027])],
    27 => [qw(brainpoolP384r1       384 Y   Y   [RFC7027])],
    28 => [qw(brainpoolP512r1       512 Y   Y   [RFC7027])],
    29 => [qw(x25519                255 Y   Y   [RFC8446][RFC8422])],
    30 => [qw(x448                  448 Y   Y   [RFC8446][RFC8422])],
    31 => [qw(brainpoolP256r1tls13  256 Y   N   [RFC8734])],
    32 => [qw(brainpoolP384r1tls13  384 Y   N   [RFC8734])],
    33 => [qw(brainpoolP512r1tls13  512 Y   N   [RFC8734])],
    34 => [qw(GC256A                256 Y   N   [draft-smyshlyaev-tls12-gost-suites])],
    35 => [qw(GC256B                256 Y   N   [draft-smyshlyaev-tls12-gost-suites])],
    36 => [qw(GC256C                256 Y   N   [draft-smyshlyaev-tls12-gost-suites])],
    37 => [qw(GC256D                256 Y   N   [draft-smyshlyaev-tls12-gost-suites])],
    38 => [qw(GC512A                512 Y   N   [draft-smyshlyaev-tls12-gost-suites])],
    39 => [qw(GC512B                512 Y   N   [draft-smyshlyaev-tls12-gost-suites])],
    40 => [qw(GC512C                512 Y   N   [draft-smyshlyaev-tls12-gost-suites])],
    41 => [qw(curveSM2              256 N   N   [draft-yang-tls-tls13-sm-suites])],
#   42-255  Unassigned
   256 => [qw(ffdhe2048            2048 Y   N   [RFC7919])],
   257 => [qw(ffdhe3072            3072 Y   N   [RFC7919])],
   258 => [qw(ffdhe4096            4096 Y   N   [RFC7919])],
   259 => [qw(ffdhe6144            6144 Y   N   [RFC7919])],
   260 => [qw(ffdhe8192            8192 Y   N   [RFC7919])],
#  261-507 Unassigned,
   508 => [qw(Private_508             NN Y   N   [RFC7919])],
   509 => [qw(Private_509             NN Y   N   [RFC7919])],
   510 => [qw(Private_510             NN Y   N   [RFC7919])],
   511 => [qw(Private_511             NN Y   N   [RFC7919])],
#  512-2569    Unassigned           ,
  2570 => [qw(Reserved_2570          NN Y   N   [RFC8701])],
# 2571-6681    Unassigned           ,
  6682 => [qw(Reserved_6682          NN Y   N   [RFC8701])],
# 6683-10793   Unassigned           ,
 10794 => [qw(Reserved_10794         NN Y   N   [RFC8701])],
#10795-14905   Unassigned           ,
 14906 => [qw(Reserved_14906         NN Y   N   [RFC8701])],
#14907-19017   Unassigned           ,
 19018 => [qw(Reserved_19018         NN Y   N   [RFC8701])],
#19019-23129   Unassigned           ,
 23130 => [qw(Reserved_23130         NN Y   N   [RFC8701])],
#23131-27241   Unassigned           ,
 27242 => [qw(Reserved_27242         NN Y   N   [RFC8701])],
#27243-31353   Unassigned           ,
 31354 => [qw(Reserved_31354         NN Y   N   [RFC8701])],
#31355-35465   Unassigned           ,
 35466 => [qw(Reserved_35466         NN Y   N   [RFC8701])],
#35467-39577   Unassigned           ,
 39578 => [qw(Reserved_39578         NN Y   N   [RFC8701])],
#39579-43689   Unassigned           ,
 43690 => [qw(Reserved_43690         NN Y   N   [RFC8701])],
#43691-47801   Unassigned           ,
 47802 => [qw(Reserved_47802         NN Y   N   [RFC8701])],
#47803-51913   Unassigned           ,
 51914 => [qw(Reserved_51914         NN Y   N   [RFC8701])],
#51915-56025   Unassigned           ,
 56026 => [qw(Reserved_56026         NN Y   N   [RFC8701])],
#56027-60137   Unassigned           ,
 60138 => [qw(Reserved_60138         NN Y   N   [RFC8701])],
#60139-64249   Unassigned           ,
 64250 => [qw(Reserved_64250         NN Y   N   [RFC8701])],
#64251-65023   Unassigned           ,
#65024-65279   Reserved_for_Private_Use NN Y N [RFC8422],
#65280         Unassigned
 65281 => [qw(arbitrary_explicit_prime_curves  -variable- Y    N   [RFC8422])],
 65282 => [qw(arbitrary_explicit_char2_curves  -variable- Y    N   [RFC8422])],
#65283-65535  Unassigned          ,
);

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

sub checkSSLciphers         ($$$@);
sub printCipherStringArray  ($$$$$@);
sub _timedOut;
sub _error;
sub _compileAllBytes        ($$$$$$;$$);
sub _decode_val             ($$$;$$$$$$);
sub _sprintf_hex_val        ($$;$);

# This module prints most warning and error messages using Perl's carp(),
# only those related to runtime problems (connection, target support, etc.)
# are printed using Perl's warn().
# I.g. we do not want carp() because it prints the line number of the
# outermost sub calling this sub, which may be misleading for the user, and
# these line numbers also break our checks done with make as these numbers
# often change.
# Finally, carp() is used for serious or rare runtime problems, and  warn()
# (with a unique message number) is used for common runtime problems.

sub _warn   {
    #? print warning message if wanted
    # don't print if --no-warning given
    my @txt = @_;
    return if ((grep{/(:?--no.?warn)/ix} @main::ARGV) > 0);
    printf("%s%s\n", $STR{WARN}, join(" ", @txt));
    return;
}

sub _hint   {
    #? print hint message if wanted
    # don't print if --no-hint given
    my @txt = @_;
    return if ((grep{/(:?--no.?hint)/ix} @main::ARGV) > 0);
    printf("%s%s\n", $STR{HINT}, join(" ", @txt));
    return;
}

sub _trace_array2str {
    #? return array in human readable internal repesentation ('0x0300xxxx' or '0x02yyyyyy')
    my @arr = @_;
    my $str = "";
    my $i   = 0;
    foreach my $item (@arr) {
        $str .= "\n  " if (($i++) % $CST{'_MY_PRINT_CIPHERS_PER_LINE'} == 0);  #  print up to $CST{'_MY_PRINT_CIPHERS_PER_LINE'} ciphers per line
        $str .= " >$item<";
    }
    return $str;
} # _trace_array2str

sub _trace_cipher_array {
    #? print human readable in internal repesentation ('0x0300xxxx' or '0x02yyyyyy')
    #  just prints values, hence no prefix in printf()
    my ($suffix, @ciphers) = @_;
    my $i = 0;
    return if (0 >= $SSLhello::trace);
    if (1 == $SSLhello::trace) {
        printf(" [ @ciphers ]$suffix\n");
        return;
    }
    printf("%s%s\n", _trace_array2str(@ciphers), $suffix);
    return;
} # _trace_cipher_array

#   trace output for known and unknown formts
sub _sprintf_hex_val ($$;$) {
    my $_format         = shift;
    my $_val_ref        = shift;
    my $_indent         = shift || 0;
    my $_hex_str        = "";
    my $_format_string  = $_format || $STR{'UNDEF'};

    _trace5_(" " x $_indent . "#   ---> _sprintf_hex_val: \$_format: '$_format_string' -> ");
    if (! defined ($_format)) {                                     # guess format, if not defined
        if (! defined ($_val_ref)) {
            _trace5 ("$STR{'UNDEF'}\n");
            return ($STR{'UNDEF'});
        }
        _trace5_ ("if (\$\$_val_ref =~ /\^\\d+\$/); defined (\$\$_val_ref) = " . defined ($$_val_ref) ." -> ");
        if (! defined ($$_val_ref)) {
            _trace5_ ("'' (empty value)\n");
            return ("");
        }
        if ($$_val_ref =~ /^\d+$/) {                                # number
            _trace5_ ("number (auto) -> ");
            if ($$_val_ref <= 0xFF) {
                $_format = "%02X";
            } elsif ($$_val_ref <= 0xFFFF) {
                $_format = "%04X";
            } elsif ($$_val_ref <= 0xFFFFFFFF) {
                $_format = "%08X";
            } else {                                                # number is too big
                $_format = "%016X";
            }
        } else {                                                    # no number
            $_format = "";
        }
    }
    if ($_format ne "") {
        _trace5_ ("formated string: ");
        $_hex_str = sprintf($_format, $$_val_ref);
        $_hex_str =~ s/[0-9A-Fa-f]{2}/"$& "/eigx;                   # add a space after 2 Hex vals
    } else {                                                        # unformated string
        _trace5_ ("val: unformated string: ");
        $_hex_str = sprintf("%*v2.2x", ' ', $$_val_ref);
    }
    $_hex_str =~ s/\s*$//;                                          # remove whitespaces at line ends
    $_hex_str =~ s/((?:[0-9A-Fa-f]{2}\s){16})(?=[0-9A-Fa-f]{2})/"$&\n"." " x $_indent/eigx; # addd a colon and a space between value and descriptiond a new line each 16 HEX-octetts if last octett has not been reached
    _trace5_ ("$_hex_str\n");
    return ($_hex_str);
}

sub _sprintf_val_description ($$;$$) {
    my $_def_hash_ref   = shift;
    my $_val_ref        = shift;
    my $_indent         = shift || 0;
    my $_descr_sep      = shift || " ";
    my $_descr_str      = "";
    my $_text_sep       = ": ";                                     # add a colon and a space between value and description
    if ($SSLhello::trace >= 5) {                               #               ? value if TRUE                         : value if FALSE
        my $_val_ref_print      = (defined ($_val_ref))                             ? ref ($_val_ref) . ": "
                                                                                       . _sprintf_hex_val (undef, $_val_ref, $_indent)
                                                                                                                            : $STR{'UNDEF'};
        my $_def_hash_ref_print = (defined ($_def_hash_ref))                        ? ref ($_def_hash_ref)                  : $STR{'UNDEF'};
        if ( (defined ($_def_hash_ref)) && (ref ($_def_hash_ref) eq "HASH") ) {
            $_def_hash_ref_print   .= ": ->{FORMAT}: ";
            $_def_hash_ref_print   .= (defined ($_def_hash_ref->{FORMAT}))          ? "defined"                             : $STR{'UNDEF'};
            if (defined($_val_ref)) {
                $_def_hash_ref_print   .= ", ->{$$_val_ref}: ";
                $_def_hash_ref_print   .= (defined ($_def_hash_ref->{$$_val_ref}))  ? "defined"                             : $STR{'UNDEF'};
            }
        }
        print " " x $_indent . "#   ---> _sprintf_val_description: (\$_val_ref = <<$_val_ref_print>>, \$_def_hash_ref = <<$_def_hash_ref_print>>)\n";
    }
    return ("") if (! defined($_def_hash_ref));
    return ("") if (! defined($_val_ref));
    if (ref ($_def_hash_ref) eq "HASH") {                           # $_def_hash_ref is a REF to a HASH
        # _trace5_ (" " x ($_indent + 3) . "#   ---> _sprintf_val_description: \$_def_hash_ref is a HASH\n");
        if (defined ($_def_hash_ref->{FORMAT})) {
            # _trace5_ (" " x ($_indent + 3) . "#   ---> _sprintf_val_description: \$_def_hash_ref->{FORMAT} is defined\n");
            if (defined ($_def_hash_ref->{$$_val_ref})) {
                # _trace5_ (" " x ($_indent + 3) . "#   ---> _sprintf_val_description: \$_def_hash_ref->{$$_val_ref} is defined\n");
                if (ref ($_def_hash_ref->{FORMAT}) eq "ARRAY") {
                    _trace5_ (" " x $_indent . "#   ---> add ".(@{$_def_hash_ref->{FORMAT}})." description(s)\n");
                    $_descr_str .= $_text_sep;                      # add a colon and a space between value and description(s)
                    for (my $_j = 0; $_j < (@{$_def_hash_ref->{FORMAT}}); $_j++) { # all elements of the description array for $$_val_ref
                        $_descr_str .= $_descr_sep if ($_j >= 1);
                        _trace5_ (" " x $_indent . "#   ---> \$_descr_str .= sprintf \($_def_hash_ref->{FORMAT}[$_j], $_def_hash_ref->{$$_val_ref}[$_j]\)\n");
                        $_descr_str .= sprintf ($_def_hash_ref->{FORMAT}[$_j], $_def_hash_ref->{$$_val_ref}[$_j]) if (defined ($_def_hash_ref->{$$_val_ref}[$_j]));
                    }
                }
            }
        }
    } elsif (ref ($_def_hash_ref) eq "SCALAR") {                    # $_def_hash_ref is a REF to a SCALAR, e.g. text
        $_descr_str .= $_text_sep.$$_def_hash_ref;
    } elsif (ref (\$_def_hash_ref) eq "SCALAR") {                   # $_def_hash_ref is not a REF but a SCALAR, e.g. text
        $_descr_str .= $_text_sep.$_def_hash_ref;
    }
    _trace5_(" " x ($_indent). "# ---> _sprintf_val_description: \$_descr_str = '$_descr_str'\n");
    return ($_descr_str);
}

sub _decode_val ($$$;$$$$$$) {
    #? decodes and (s)sprints values and up to double nested arrays (= arrays of arrays of arrays)
    #? prints and adds warnings to the output if the variable is even more deeply nestested or in an unsupported format
    my $_format         = shift;            # reference to a sprintf-format to print the value, or "" for unformatted strings or undef for autoformat for unknown formats (best effort)
    my $_val_ref        = shift;            # reference to a scalar or an up to double nested array (= array of array of array)
    my $_def_hash_ref   = shift;            # definition to decode the value: might be a ref to a hash, a ref to this ref or a simple scalara or undef
    my $_first_indent   = shift || 0;       # optional: ident in the first line
    my $_next_indent    = shift || 0;       # optional: ident from the second line onwards
    my $_text_sep       = shift || ":\n". " " x $_next_indent;  # optional: add a colon, a new line and an indent between section headline (e.g. 'sequence') and value
    my $_sub_sep        = shift || ", ";    # optional: sub seperators of elements or arrays
    my $_sub_sub_sep    = shift || " | ";   # optional: sub-sub seperators of array elements or nested arrays (arrays of arrays)
    my $_sub3_sep       = shift || " / ";   # optional: sub³ seperators of nested array elements (or error messages for more deeply nested attays
    my $_sub_lines      = 0;
    my $_sub_sub_lines  = 0;
    my $_sub3_lines     = 0;
    my $_decode_str     = "";
    my $_format_print   = $_format;
    $_format_print      = $STR{'UNDEF'} if (! defined ($_format));

    _trace5_ (" " x $_next_indent . "# _decode_val (\$_format: '$_format_print', \$val_ref, \$_def_hash_ref, \$_first_indent: '$_first_indent', \$_next_indent: '$_next_indent', \$_text_sep: '$_text_sep', \$_sub_sep: '$_sub_sep', \$_sub_sub_sep: '$_sub_sub_sep', \$_sub3_sep: '$_sub3_sep ')\n");
    $_decode_str = " " x $_first_indent;
    if (defined ($_def_hash_ref)) {
        _trace5_ (" " x ($_next_indent + 2) ."# --->> def_hash-ref-Type:     ".ref($_def_hash_ref)."<<\n");
        _trace5_ (" " x ($_next_indent + 2) ."# --->> def_hash-ref-ref-Type: ".ref($$_def_hash_ref)."<<\n") if (ref ($_def_hash_ref) eq 'REF');
        _trace5_ (" " x ($_next_indent + 2) ."# --->> def_hash-val-Type:     ".ref(\$_def_hash_ref)."<<\n");
        $_def_hash_ref = $$_def_hash_ref if (ref ($_def_hash_ref) eq 'REF');           # reference to a reference => reference
        if (ref ($_def_hash_ref) eq "HASH") {                       # $_def_hash_ref is a REF to a HASH
            $_decode_str .= $_def_hash_ref->{TEXT}.$_text_sep if (defined ($_def_hash_ref->{TEXT}));
        }
        if (! defined($_val_ref)) {                                 # check for (simple) SCALAR info if any value define (e.g. section headline, e.g. 'sequence'
            if (ref ($_def_hash_ref) eq "SCALAR") {                 # $_def_hash_ref is a REF to a SCALAR, e.g. text
                $_decode_str .= $$_def_hash_ref.$_text_sep;
            } elsif (ref (\$_def_hash_ref) eq "SCALAR") {           # $_def_hash_ref is not a REF but a SCALAR, e.g. text
                $_decode_str .= $_def_hash_ref.$_text_sep;
            }
        }
        _trace5_ (" " x ($_next_indent + 2) . "# \$_decode_str: $_decode_str\n");
    }
    return ($_decode_str) if (! defined($_val_ref));
    _trace5_ (" " x ($_next_indent + 2) ."# ---> val-Type:     ".ref($_val_ref)."<\n");
    _trace5_ (" " x ($_next_indent + 2) ."# ---> val-ref-Type: ".ref($$_val_ref)."<\n") if (ref ($_val_ref) eq 'REF');
    $_val_ref = $$_val_ref if (ref ($_val_ref) eq 'REF');           # reference to a reference => reference
    if (ref ($_val_ref) eq 'SCALAR') {                              # value
        $_decode_str .= _sprintf_hex_val         ($_format,       $_val_ref, $_next_indent + 2);
        $_decode_str .= _sprintf_val_description ($_def_hash_ref, $_val_ref, $_next_indent + 2);
    } elsif (ref ($_val_ref) eq 'ARRAY') {                          # array
        $_decode_str .= "[ ";
        $_next_indent += 2;
        if ( (@{$_val_ref}) >= 1) {
            foreach my $ele (@{$_val_ref}) {
                _trace5_ (" " x ($_next_indent + 2)."# ---|> val-ref-Type (\$ele): ".ref(\$ele)."<|\n");
                $_decode_str .=  $_sub_sep if ($_sub_lines++ > 0);  # add a sup-sep an a new line with an indent für next nested array;
                if (ref (\$ele) eq 'SCALAR') {                      # values of the array
                    $_decode_str .= _sprintf_hex_val         ($_format,       \$ele, $_next_indent + 2);
                    $_decode_str .= _sprintf_val_description ($_def_hash_ref, \$ele, $_next_indent + 2);
                } elsif (ref ($ele) eq 'ARRAY') {                   # nested array, e.g. sequence
                    $_decode_str .=  "[ ";
                    $_next_indent += 2;
                    if ( (@{$ele}) >= 1) {
                        $_sub_sub_lines = 0;                        # reset sub_sub_lines
                        foreach my $ele_ele (@{$ele}) {
                            _trace5_ (" " x ($_next_indent + 2)."# ---||> val-ref-Type (\$ele_ele): ".ref(\$ele_ele)."<||\n");
                            $_decode_str .= $_sub_sub_sep if ($_sub_sub_lines++ > 0);                           # add a sub-sub-separator if not the first element
                            if (ref (\$ele_ele) eq 'SCALAR') {      # values of the nested array (array of arrays)
                                $_decode_str .= _sprintf_hex_val         ($_format,       \$ele_ele, $_next_indent + 2);
                                $_decode_str .= _sprintf_val_description ($_def_hash_ref, \$ele_ele, $_next_indent + 2);
                            } elsif (ref ($ele_ele) eq 'ARRAY') {   # doulble nested array (array of array of arrays)
                                $_decode_str .=  "[ ";
                                $_next_indent += 2;
                                if ( (@{$ele_ele}) >= 1) {
                                    $_sub3_lines = 0;               # reset sub_sub_lines
                                    foreach my $ele3 (@{$ele_ele}) {
                                        _trace5_ (" " x ($_next_indent + 2)."# --|||> val-ref-Type (\$ele3):    ".ref(\$ele3)."<|||\n");
                                        $_decode_str .= $_sub3_sep if ($_sub3_lines++ > 0); # add a sub3-separator if not the first element
                                        if (ref (\$ele3) eq 'SCALAR') { # values of the double nested array (array of array of arrays)
                                            $_decode_str .= _sprintf_hex_val         ($_format,       \$ele3, $_next_indent + 2);
                                            $_decode_str .= _sprintf_val_description ($_def_hash_ref, \$ele3, $_next_indent + 2);
                                        } else {                    # deeply nested array is not supported
                                            _trace2_ (" " x ($_next_indent + 2) ."# --|||> **WARNING: SSLhello::_decode_val: try to print unsupported or deeply nested val type (\$ele3): '" . ref(\$ele3) ."/". ref($ele3) ."' <|||\n");
                                            carp("$STR{WARN} SSLhello::_decode_val: try to print unsupported or deeply nested val type (\$ele3): '" . ref(\$ele3) ."/". ref($ele3) ."'\n");

                                            $_decode_str .= "[ --- unsupported or deeply nested val type (\$ele3): '". ref(\$ele3) ."/". ref($ele3) ."' --- ]";
                                        } # ref (\$ele3)
                                    } # foreach $ele3
                                }
                                $_decode_str .= " ]";
                                $_next_indent -= 2;
                            } else {                                # unsupported val type of $ele_ele
                                _trace2_ (" " x ($_next_indent + 2) ."**WARNING: SSLhello::_decode_val: try to print unsupported val-refref-Type (\$ele_ele):    ".ref($ele_ele)."<\n");
                                carp("$STR{WARN} SSLhello::_decode_val: try to print unsupported val type (\$ele_ele): '" . ref(\$ele_ele) ."/". ref($ele_ele) ."'\n");
                                $_decode_str .= "[ --- unsupported val type (\$ele_ele): '". ref(\$ele_ele) ."/". ref($ele_ele) ."' --- ]";
                            } # ref (\$ele_ele)
                        } # foreach $ele_ele
                    }
                    $_decode_str .= " ]";
                    $_next_indent -= 2;
                } else {                                            # unsupported val type of $ele
                    _trace2_ (" " x ($_next_indent + 2) ."**WARNING: SSLhello::_decode_val: try to print unsupported val-refref-Type (\$ele):    ".ref($ele)."<\n");
                    carp("$STR{WARN} SSLhello::_decode_val: try to print unsupported val type (\$ele): '" . ref(\$ele) ."/". ref($ele) . "'\n");
                    $_decode_str .= "[ --- unsupported val type (\$ele_ele): '". ref(\$ele) ."/". ref($ele) ."' --- ]";
                } # ref (\$ele)
            } # foreach $ele
        }
        $_decode_str .= " ]";
        $_next_indent -= 2;
    } else {                                                        # unsupported val type of $$_val_ref
        _trace2_ (" " x ($_next_indent + 2) ."**WARNING: SSLhello::_decode_val: try to print unsupported val-refref-Type:             " . ref($_val_ref)."<\n");
        carp("$STR{WARN} SSLhello::_decode_val: try to print unsupported val type: '" . ref(\$_val_ref) ."/". ref($_val_ref) ."'\n");
        $_decode_str .= "[ --- unsupported val type: '". ref(\$_val_ref) ."/". ref($_val_ref) ."' --- ]";
    } # if ref ($_val_ref)
#    $_next_indent -= 3;
    _trace5_ (" " x $_next_indent . "#   ---> _decode_val: \$_decode_str: '$_decode_str'\n");
    return ($_decode_str);
} # end of _decode_val ();

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
  '0x02060040'=> [qw(DES_CBC_WITH_MD5                         DES-CBC-MD5)],
  '0x02060140'=> [qw(DES_CBC_WITH_SHA                         DES-CBC-SHA)],
  '0x02FF0800'=> [qw(DES_64_CFB64_WITH_MD5_1                  DES-CFB-M1)],
  '0x02050080'=> [qw(IDEA_CBC_WITH_MD5                        IDEA-CBC-MD5)],
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
  '0x0300001B'=> [qw(DH_anon_WITH_3DES_EDE_CBC_SHA            ADH-DES-CBC3-SHA)],
  '0x03000019'=> [qw(DH_anon_EXPORT_WITH_DES40_CBC_SHA        EXP-ADH-DES-CBC-SHA)],
  '0x0300001A'=> [qw(DH_anon_WITH_DES_CBC_SHA                 ADH-DES-CBC-SHA)],
  '0x03000018'=> [qw(DH_anon_WITH_RC4_128_MD5                 ADH-RC4-MD5)],
  '0x03000017'=> [qw(DH_anon_EXPORT_WITH_RC4_40_MD5           EXP-ADH-RC4-MD5)],
  '0x0300000D'=> [qw(DH_DSS_WITH_3DES_EDE_CBC_SHA             DH-DSS-DES-CBC3-SHA)],
  '0x0300000B'=> [qw(DH_DSS_EXPORT_WITH_DES40_CBC_SHA         EXP-DH-DSS-DES-CBC-SHA)],
  '0x0300000C'=> [qw(DH_DSS_WITH_DES_CBC_SHA                  DH-DSS-DES-CBC-SHA)],
  '0x03000010'=> [qw(DH_RSA_WITH_3DES_EDE_CBC_SHA             DH-RSA-DES-CBC3-SHA)],
  '0x0300000E'=> [qw(DH_RSA_EXPORT_WITH_DES40_CBC_SHA         EXP-DH-RSA-DES-CBC-SHA)],
  '0x0300000F'=> [qw(DH_RSA_WITH_DES_CBC_SHA                  DH-RSA-DES-CBC-SHA)],
  '0x03000013'=> [qw(EDH_DSS_WITH_3DES_EDE_CBC_SHA            EDH-DSS-DES-CBC3-SHA)],
  '0x03000011'=> [qw(EDH_DSS_EXPORT_WITH_DES40_CBC_SHA        EXP-EDH-DSS-DES-CBC-SHA)],
  '0x03000012'=> [qw(EDH_DSS_WITH_DES_CBC_SHA                 EDH-DSS-DES-CBC-SHA)],
  '0x03000016'=> [qw(EDH_RSA_WITH_3DES_EDE_CBC_SHA            EDH-RSA-DES-CBC3-SHA)],
  '0x03000014'=> [qw(EDH_RSA_EXPORT_WITH_DES40_CBC_SHA        EXP-EDH-RSA-DES-CBC-SHA)],
  '0x03000015'=> [qw(EDH_RSA_WITH_DES_CBC_SHA                 EDH-RSA-DES-CBC-SHA)],
  '0x0300001D'=> [qw(FZA_DMS_FZA_SHA                          FZA-FZA-CBC-SHA)],
  '0x0300001C'=> [qw(FZA_DMS_NULL_SHA                         FZA-NULL-SHA)],
  '0x0300001E'=> [qw(FZA_DMS_RC4_SHA/KRB5_WITH_DES_CBC_SHA    FZA-RC4-SHA/KRB5-DES-SHA)],
  '0x03000023'=> [qw(KRB5_WITH_3DES_EDE_CBC_MD5               KRB5-DES-CBC3-MD5)],
  '0x0300001F'=> [qw(KRB5_WITH_3DES_EDE_CBC_SHA               KRB5-DES-CBC3-SHA)],
  '0x03000029'=> [qw(KRB5_EXPORT_WITH_DES_CBC_40_MD5          EXP-KRB5-DES-CBC-MD5)],
  '0x03000026'=> [qw(KRB5_EXPORT_WITH_DES_CBC_40_SHA          EXP-KRB5-DES-CBC-SHA)],
  '0x03000022'=> [qw(KRB5_WITH_DES_CBC_MD5                    KRB5-DES-CBC-MD5)],
  '0x0300001E'=> [qw(KRB5_WITH_DES_CBC_SHA                    KRB5-DES-CBC-SHA)],
  '0x03000025'=> [qw(KRB5_WITH_IDEA_CBC_MD5                   KRB5-IDEA-CBC-MD5)],
  '0x03000021'=> [qw(KRB5_WITH_IDEA_CBC_SHA                   KRB5-IDEA-CBC-SHA)],
  '0x0300002A'=> [qw(KRB5_WITH_RC2_CBC_40_MD5                 EXP-KRB5-RC2-CBC-MD5)],
  '0x03000027'=> [qw(KRB5_EXPORT_WITH_RC2_CBC_40_SHA          EXP-KRB5-RC2-CBC-SHA)],
  '0x03000024'=> [qw(KRB5_WITH_RC4_128_MD5                    KRB5-RC4-MD5)],
  '0x03000020'=> [qw(KRB5_WITH_RC4_128_SHA                    KRB5-RC4-SHA)],
  '0x0300002B'=> [qw(KRB5_EXPORT_WITH_RC4_40_MD5              EXP-KRB5-RC4-MD5)],
  '0x03000028'=> [qw(KRB5_EXPORT_WITH_RC4_40_SHA              EXP-KRB5-RC4-SHA)],
  '0x0300000A'=> [qw(RSA_WITH_3DES_EDE_CBC_SHA                DES-CBC3-SHA)],
  '0x03000008'=> [qw(RSA_EXPORT_WITH_DES40_CBC_SHA            EXP-DES-CBC-SHA)],
  '0x03000009'=> [qw(RSA_WITH_DES_CBC_SHA                     DES-CBC-SHA)],
  '0x03000007'=> [qw(RSA_WITH_IDEA_SHA                        IDEA-CBC-SHA)],
  '0x03000000'=> [qw(NULL_WITH_NULL_NULL                      NULL-NULL)],
  '0x03000001'=> [qw(RSA_WITH_NULL_MD5                        NULL-MD5)],
  '0x03000002'=> [qw(RSA_WITH_NULL_SHA                        NULL-SHA)],
  '0x03000006'=> [qw(RSA_EXPORT_WITH_RC2_CBC_40_MD5           EXP-RC2-CBC-MD5)],
  '0x03000004'=> [qw(RSA_WITH_RC4_128_MD5                     RC4-MD5)],
  '0x03000005'=> [qw(RSA_WITH_RC4_128_SHA                     RC4-SHA)],
  '0x03000003'=> [qw(RSA_EXPORT_WITH_RC4_40_MD5               EXP-RC4-MD5)],
  '0x030000FF'=> [qw(EMPTY_RENEGOTIATION_INFO_SCSV            SCSV-RENEG)], #activated 'Signaling Cipher Suite Value'
  '0x03005600'=> [qw(FALLBACK_SCSV_DRAFT                      SCSV-FALLBACK-DRAFT)], ### added according 'https://datatracker.ietf.org/doc/draft-bmoeller-tls-downgrade-scsv/?include_text=1'

#!#----------------------------------------+-------------+--------------------+
#!# Protocol:  TLS 1.0 (invented)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
  '0x030000A6'=> [qw(DH_anon_WITH_AES_128_GCM_SHA256          ADH-AES128-GCM-SHA256)],
  '0x03000034'=> [qw(DH_anon_WITH_AES_128_CBC_SHA             ADH-AES128-SHA)],
  '0x0300006C'=> [qw(DH_anon_WITH_AES_128_CBC_SHA256          ADH-AES128-SHA256)],
  '0x030000A7'=> [qw(DH_anon_WITH_AES_256_GCM_SHA384          ADH-AES256-GCM-SHA384)],
  '0x0300003A'=> [qw(DH_anon_WITH_AES_256_CBC_SHA             ADH-AES256-SHA)],
  '0x0300006D'=> [qw(DH_anon_WITH_AES_256_CBC_SHA256          ADH-AES256-SHA256)],
  '0x03000046'=> [qw(DH_anon_WITH_CAMELLIA_128_CBC_SHA        ADH-CAMELLIA128-SHA)],
  '0x03000089'=> [qw(DH_anon_WITH_CAMELLIA_256_CBC_SHA        ADH-CAMELLIA256-SHA)],
  '0x0300009B'=> [qw(DH_anon_WITH_SEED_CBC_SHA                ADH-SEED-SHA)],
  '0x03000063'=> [qw(DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA      EXP1024-DHE-DSS-DES-CBC-SHA)],
  '0x03000065'=> [qw(DHE_DSS_EXPORT1024_WITH_RC4_56_SHA       EXP1024-DHE-DSS-RC4-SHA)],
  '0x030000A2'=> [qw(DHE_DSS_WITH_AES_128_GCM_SHA256          DHE-DSS-AES128-GCM-SHA256)],
  '0x03000032'=> [qw(DHE_DSS_WITH_AES_128_CBC_SHA             DHE-DSS-AES128-SHA)],
  '0x03000040'=> [qw(DHE_DSS_WITH_AES_128_CBC_SHA256          DHE-DSS-AES128-SHA256)],
  '0x030000A3'=> [qw(DHE_DSS_WITH_AES_256_GCM_SHA384          DHE-DSS-AES256-GCM-SHA384)],
  '0x03000038'=> [qw(DHE_DSS_WITH_AES_256_CBC_SHA             DHE-DSS-AES256-SHA)],
  '0x0300006A'=> [qw(DHE_DSS_WITH_AES_256_CBC_SHA256          DHE-DSS-AES256-SHA256)],
  '0x03000044'=> [qw(DHE_DSS_WITH_CAMELLIA_128_CBC_SHA        DHE-DSS-CAMELLIA128-SHA)],
  '0x03000087'=> [qw(DHE_DSS_WITH_CAMELLIA_256_CBC_SHA        DHE-DSS-CAMELLIA256-SHA)],
  '0x03000066'=> [qw(DHE_DSS_WITH_RC4_128_SHA                 DHE-DSS-RC4-SHA)],
  '0x03000099'=> [qw(DHE_DSS_WITH_SEED_CBC_SHA                DHE-DSS-SEED-SHA)],
  '0x0300009E'=> [qw(DHE_RSA_WITH_AES_128_GCM_SHA256          DHE-RSA-AES128-GCM-SHA256)],
  '0x03000033'=> [qw(DHE_RSA_WITH_AES_128_CBC_SHA             DHE-RSA-AES128-SHA)],
  '0x03000067'=> [qw(DHE_RSA_WITH_AES_128_CBC_SHA256          DHE-RSA-AES128-SHA256)],
  '0x0300009F'=> [qw(DHE_RSA_WITH_AES_256_GCM_SHA384          DHE-RSA-AES256-GCM-SHA384)],
  '0x03000039'=> [qw(DHE_RSA_WITH_AES_256_CBC_SHA             DHE-RSA-AES256-SHA)],
  '0x0300006B'=> [qw(DHE_RSA_WITH_AES_256_CBC_SHA256          DHE-RSA-AES256-SHA256)],
  '0x03000045'=> [qw(DHE_RSA_WITH_CAMELLIA_128_CBC_SHA        DHE-RSA-CAMELLIA128-SHA)],
  '0x03000088'=> [qw(DHE_RSA_WITH_CAMELLIA_256_CBC_SHA        DHE-RSA-CAMELLIA256-SHA)],
  '0x0300009A'=> [qw(DHE_RSA_WITH_SEED_CBC_SHA                DHE-RSA-SEED-SHA)],
  '0x030000A4'=> [qw(DH_DSS_WITH_AES_128_GCM_SHA256           DH-DSS-AES128-GCM-SHA256)],
  '0x03000030'=> [qw(DH_DSS_WITH_AES_128_CBC_SHA              DH-DSS-AES128-SHA)],
  '0x0300003E'=> [qw(DH_DSS_WITH_AES_128_CBC_SHA256           DH-DSS-AES128-SHA256)],
  '0x030000A5'=> [qw(DH_DSS_WITH_AES_256_GCM_SHA384           DH-DSS-AES256-GCM-SHA384)],
  '0x03000036'=> [qw(DH_DSS_WITH_AES_256_CBC_SHA              DH-DSS-AES256-SHA)],
  '0x03000068'=> [qw(DH_DSS_WITH_AES_256_CBC_SHA256           DH-DSS-AES256-SHA256)],
  '0x03000042'=> [qw(DH_DSS_WITH_CAMELLIA_128_CBC_SHA         DH-DSS-CAMELLIA128-SHA)],
  '0x03000085'=> [qw(DH_DSS_WITH_CAMELLIA_256_CBC_SHA         DH-DSS-CAMELLIA256-SHA)],
  '0x03000097'=> [qw(DH_DSS_WITH_SEED_CBC_SHA                 DH-DSS-SEED-SHA)],
  '0x030000A0'=> [qw(DH_RSA_WITH_AES_128_GCM_SHA256           DH-RSA-AES128-GCM-SHA256)],
  '0x03000031'=> [qw(DH_RSA_WITH_AES_128_CBC_SHA              DH-RSA-AES128-SHA)],
  '0x0300003F'=> [qw(DH_RSA_WITH_AES_128_CBC_SHA256           DH-RSA-AES128-SHA256)],
  '0x030000A1'=> [qw(DH_RSA_WITH_AES_256_GCM_SHA384           DH-RSA-AES256-GCM-SHA384)],
  '0x03000037'=> [qw(DH_RSA_WITH_AES_256_CBC_SHA              DH-RSA-AES256-SHA)],
  '0x03000069'=> [qw(DH_RSA_WITH_AES_256_CBC_SHA256           DH-RSA-AES256-SHA256)],
  '0x03000043'=> [qw(DH_RSA_WITH_CAMELLIA_128_CBC_SHA         DH-RSA-CAMELLIA128-SHA)],
  '0x03000086'=> [qw(DH_RSA_WITH_CAMELLIA_256_CBC_SHA         DH-RSA-CAMELLIA256-SHA)],
  '0x03000098'=> [qw(DH_RSA_WITH_SEED_CBC_SHA                 DH-RSA-SEED-SHA)],
  '0x0300C009'=> [qw(ECDHE_ECDSA_WITH_AES_128_CBC_SHA         ECDHE-ECDSA-AES128-SHA)],
  '0x0300C02B'=> [qw(ECDHE_ECDSA_WITH_AES_128_GCM_SHA256      ECDHE-ECDSA-AES128-GCM-SHA256)],
  '0x0300C023'=> [qw(ECDHE_ECDSA_WITH_AES_128_CBC_SHA256      ECDHE-ECDSA-AES128-SHA256)],
  '0x0300C00A'=> [qw(ECDHE_ECDSA_WITH_AES_256_CBC_SHA         ECDHE-ECDSA-AES256-SHA)],
  '0x0300C02C'=> [qw(ECDHE_ECDSA_WITH_AES_256_GCM_SHA384      ECDHE-ECDSA-AES256-GCM-SHA384)],
  '0x0300C024'=> [qw(ECDHE_ECDSA_WITH_AES_256_CBC_SHA384      ECDHE-ECDSA-AES256-SHA384)],
  '0x0300C008'=> [qw(ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA        ECDHE-ECDSA-DES-CBC3-SHA)],
  '0x0300C006'=> [qw(ECDHE_ECDSA_WITH_NULL_SHA                ECDHE-ECDSA-NULL-SHA)],
  '0x0300C007'=> [qw(ECDHE_ECDSA_WITH_RC4_128_SHA             ECDHE-ECDSA-RC4-SHA)],
  '0x0300C013'=> [qw(ECDHE_RSA_WITH_AES_128_CBC_SHA           ECDHE-RSA-AES128-SHA)],
  '0x0300C02F'=> [qw(ECDHE_RSA_WITH_AES_128_GCM_SHA256        ECDHE-RSA-AES128-GCM-SHA256)],
  '0x0300C027'=> [qw(ECDHE_RSA_WITH_AES_128_CBC_SHA256        ECDHE-RSA-AES128-SHA256)],
  '0x0300C014'=> [qw(ECDHE_RSA_WITH_AES_256_CBC_SHA           ECDHE-RSA-AES256-SHA)],
  '0x0300C030'=> [qw(ECDHE_RSA_WITH_AES_256_GCM_SHA384        ECDHE-RSA-AES256-GCM-SHA384)],
  '0x0300C028'=> [qw(ECDHE_RSA_WITH_AES_256_CBC_SHA384        ECDHE-RSA-AES256-SHA384)],
  '0x0300C012'=> [qw(ECDHE_RSA_WITH_3DES_EDE_CBC_SHA          ECDHE-RSA-DES-CBC3-SHA)],
  '0x0300C010'=> [qw(ECDHE_RSA_WITH_NULL_SHA                  ECDHE-RSA-NULL-SHA)],
  '0x0300C011'=> [qw(ECDHE_RSA_WITH_RC4_128_SHA               ECDHE-RSA-RC4-SHA)],
  '0x0300C004'=> [qw(ECDH_ECDSA_WITH_AES_128_CBC_SHA          ECDH-ECDSA-AES128-SHA)],
  '0x0300C02D'=> [qw(ECDH_ECDSA_WITH_AES_128_GCM_SHA256       ECDH-ECDSA-AES128-GCM-SHA256)],
  '0x0300C025'=> [qw(ECDH_ECDSA_WITH_AES_128_CBC_SHA256       ECDH-ECDSA-AES128-SHA256)],
  '0x0300C005'=> [qw(ECDH_ECDSA_WITH_AES_256_CBC_SHA          ECDH-ECDSA-AES256-SHA)],
  '0x0300C02E'=> [qw(ECDH_ECDSA_WITH_AES_256_GCM_SHA384       ECDH-ECDSA-AES256-GCM-SHA384)],
  '0x0300C026'=> [qw(ECDH_ECDSA_WITH_AES_256_CBC_SHA384       ECDH-ECDSA-AES256-SHA384)],
  '0x0300C003'=> [qw(ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA         ECDH-ECDSA-DES-CBC3-SHA)],
  '0x0300C001'=> [qw(ECDH_ECDSA_WITH_NULL_SHA                 ECDH-ECDSA-NULL-SHA)],
  '0x0300C002'=> [qw(ECDH_ECDSA_WITH_RC4_128_SHA              ECDH-ECDSA-RC4-SHA)],
  '0x0300C00E'=> [qw(ECDH_RSA_WITH_AES_128_CBC_SHA            ECDH-RSA-AES128-SHA)],
  '0x0300C031'=> [qw(ECDH_RSA_WITH_AES_128_GCM_SHA256         ECDH-RSA-AES128-GCM-SHA256)],
  '0x0300C029'=> [qw(ECDH_RSA_WITH_AES_128_CBC_SHA256         ECDH-RSA-AES128-SHA256)],
  '0x0300C00F'=> [qw(ECDH_RSA_WITH_AES_256_CBC_SHA            ECDH-RSA-AES256-SHA)],
  '0x0300C032'=> [qw(ECDH_RSA_WITH_AES_256_GCM_SHA384         ECDH-RSA-AES256-GCM-SHA384)],
  '0x0300C02A'=> [qw(ECDH_RSA_WITH_AES_256_CBC_SHA384         ECDH-RSA-AES256-SHA384)],
  '0x0300C00D'=> [qw(ECDH_RSA_WITH_3DES_EDE_CBC_SHA           ECDH-RSA-DES-CBC3-SHA)],
  '0x0300C00B'=> [qw(ECDH_RSA_WITH_NULL_SHA                   ECDH-RSA-NULL-SHA)],
  '0x0300C00C'=> [qw(ECDH_RSA_WITH_RC4_128_SHA                ECDH-RSA-RC4-SHA)],
  '0x0300C018'=> [qw(ECDH_anon_WITH_AES_128_CBC_SHA           AECDH-AES128-SHA)],
  '0x0300C019'=> [qw(ECDH_anon_WITH_AES_256_CBC_SHA           AECDH-AES256-SHA)],
  '0x0300C017'=> [qw(ECDH_anon_WITH_3DES_EDE_CBC_SHA          AECDH-DES-CBC3-SHA)],
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
  '0x0300002F'=> [qw(RSA_WITH_AES_128_CBC_SHA                 AES128-SHA)],
  '0x0300003C'=> [qw(RSA_WITH_AES_128_CBC_SHA256              AES128-SHA256)],
  '0x0300009D'=> [qw(RSA_WITH_AES_256_GCM_SHA384              AES256-GCM-SHA384)],
  '0x03000035'=> [qw(RSA_WITH_AES_256_CBC_SHA                 AES256-SHA)],
  '0x0300003D'=> [qw(RSA_WITH_AES_256_CBC_SHA256              AES256-SHA256)],
  '0x03000041'=> [qw(RSA_WITH_CAMELLIA_128_CBC_SHA            CAMELLIA128-SHA)],
  '0x03000084'=> [qw(RSA_WITH_CAMELLIA_256_CBC_SHA            CAMELLIA256-SHA)],
  '0x0300003B'=> [qw(RSA_WITH_NULL_SHA256                     NULL-SHA256)],
  '0x03000096'=> [qw(RSA_WITH_SEED_CBC_SHA                    SEED-SHA)],
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
  '0x03000080'=> [qw(GOSTR341094_WITH_28147_CNT_IMIT      GOST94-GOST89-GOST89)],
  '0x03000081'=> [qw(GOSTR341001_WITH_28147_CNT_IMIT      GOST2001-GOST89-GOST89)],
  '0x03000082'=> [qw(GOSTR341094_WITH_NULL_GOSTR3411      GOST94-NULL-GOST94)],
  '0x03000083'=> [qw(GOSTR341001_WITH_NULL_GOSTR3411      GOST2001-NULL-GOST94)],

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
  '0x030000BF'=> [qw(DH_anon_WITH_CAMELLIA_128_CBC_SHA256 ADH-CAMELLIA128-SHA256)],


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
  '0x030000C5'=> [qw(DH_anon_WITH_CAMELLIA_256_CBC_SHA256 ADH-CAMELLIA256-SHA256)],

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
  '0x0300C084'=> [qw(DH_anon_DSS_WITH_CAMELLIA_128_GCM_SHA256   ADH-DSS-CAMELLIA128-GCM-SHA256)],
  '0x0300C085'=> [qw(DH_anon_DSS_WITH_CAMELLIA_256_GCM_SHA384   ADH-DSS-CAMELLIA256-GCM-SHA384)],

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
  '0x0300C09E'=> [qw(DHE_RSA_WITH_AES_128_CCM    DHE-RSA-AES128-CCM)],
  '0x0300C09F'=> [qw(DHE_RSA_WITH_AES_256_CCM    DHE-RSA-AES256-CCM)],
  '0x0300C0A0'=> [qw(RSA_WITH_AES_128_CCM_8      RSA-AES128-CCM8)],
  '0x0300C0A1'=> [qw(RSA_WITH_AES_256_CCM_8      RSA-AES256-CCM8)],
  '0x0300C0A2'=> [qw(DHE_RSA_WITH_AES_128_CCM_8  DHE-RSA-AES128-CCM8)],
  '0x0300C0A3'=> [qw(DHE_RSA_WITH_AES_256_CCM_8  DHE-RSA-AES256-CCM8)],
  '0x0300C0A4'=> [qw(PSK_WITH_AES_128_CCM        PSK-AES128-CCM)],
  '0x0300C0A5'=> [qw(PSK_WITH_AES_256_CCM        PSK-AES256-CCM)],
  '0x0300C0A6'=> [qw(DHE_PSK_WITH_AES_128_CCM    DHE-PSK-AES128-CCM)],
  '0x0300C0A7'=> [qw(DHE_PSK_WITH_AES_256_CCM    DHE-PSK-AES256-CCM)],
  '0x0300C0A8'=> [qw(PSK_WITH_AES_128_CCM_8      PSK-AES128-CCM8)],
  '0x0300C0A9'=> [qw(PSK_WITH_AES_256_CCM_8      PSK-AES256-CCM8)],
  '0x0300C0AA'=> [qw(PSK_DHE_WITH_AES_128_CCM_8  DHE-PSK-AES128-CCM8)],
  '0x0300C0AB'=> [qw(PSK_DHE_WITH_AES_256_CCM_8  DHE-PSK-AES256-CCM8)],

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
#!# Protocol: some  PSK and CCM ciphers (from o-saft.pl, name1 <-> name2)
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

   '0x0300C0AC' => [qw(ECDHE_ECDSA_WITH_AES_128_CCM      ECDHE-ECDSA-AES128-CCM)],
   '0x0300C0AD' => [qw(ECDHE_ECDSA_WITH_AES_256_CCM      ECDHE-ECDSA-AES256-CCM)],
   '0x0300C0AE' => [qw(ECDHE_ECDSA_WITH_AES_128_CCM_8    ECDHE-ECDSA-AES128-CCM-8)],
   '0x0300C0AF' => [qw(ECDHE_ECDSA_WITH_AES_256_CCM_8    ECDHE-ECDSA-AES256-CCM-8)],

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
   '0x0300C064'=>[qw(PSK_WITH_ARIA_128_CBC_SHA256          PSK-ARIA128-SHA256)],
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
#!# Protocol: TLS 1.3 ciphers (prefix TLS13 added)
#!# added manually 20201106
#!# RFC8446
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
   '0x03001301'=>[qw(TLS13_AES_128_GCM_SHA256              TLS13-AES-128-GCM-SHA256)],
   '0x03001302'=>[qw(TLS13_AES_256_GCM_SHA384              TLS13-AES-256-GCM-SHA384)],
   '0x03001303'=>[qw(TLS13_CHACHA20_POLY1305_SHA256        TLS13-CHACHA20-POLY1305-SHA256)],
   '0x03001304'=>[qw(TLS13_AES_128_CCM_SHA256              TLS13-AES-128-CCM-SHA256)],
   '0x03001305'=>[qw(TLS13_AES_128_CCM_8_SHA256            TLS13-AES-128-CCM-8-SHA256)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol: some further TLS 1.3 ciphers (prefix TLS13 added)
#!# added manually 20201106
#!# DRAFT yang-tls-tls13-sm-suites; OpenSSL-Names are expected (TBD: verify names later)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
   '0x030000C6'=>[qw(TLS13_SM4_GCM_SM3                     TLS13-SM4-GCM)],
   '0x030000C7'=>[qw(TLS13_SM4_CCM_SM3                     TLS13-SM4-CCM)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol: DRAFT for GOST cipher suites (TLS 1.2 and TLS 1.3 (prefix TLS13 added)
#!# added manually 20201109
#!# DRAFT draft-smyshlyaev-tls12-gost-suites; OpenSSL-Names are expected (TBD: verify names later)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
   '0x0300C100'=>[qw(GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC    GOSTR341112-256-KUZNYECHIK-CTR-OMAC)],
   '0x0300C101'=>[qw(GOSTR341112_256_WITH_MAGMA_CTR_OMAC         GOSTR341112-256-MAGMA-CTR-OMAC)],
   '0x0300C102'=>[qw(GOSTR341112_256_WITH_28147_CNT_IMIT         GOSTR341112-256-28147-CNT-IMIT)],
   '0x0300C103'=>[qw(TLS13_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L GOSTR341112-256-KUZNYECHIK-MGM-L)],
   '0x0300C104'=>[qw(TLS13_GOSTR341112_256_WITH_MAGMA_MGM_L      GOSTR341112-256-MAGMA-MGM-L)],
   '0x0300C105'=>[qw(TLS13_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S GOSTR341112-256-KUZNYECHIK-MGM-S)],
   '0x0300C106'=>[qw(TLS13_GOSTR341112_256_WITH_MAGMA_MGM_S      GOSTR341112-256-MAGMA-MGM-S)],

#!# Protocol: some further TLS 1.3 ciphers (prefix TLS13 added)
#!# added manually 20201106
#!# DRAFT draft-camwinget-tls-ts13-macciphersuites; OpenSSL-Names are expected (TBD: verify names later)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
   '0x0300C4B4'=>[qw(TLS13_SHA256_SHA256                   TLS13-SHA256-SHA256)],
   '0x0300C4B5'=>[qw(TLS13_SHA384_SHA384                   TLS13-SHA384-SHA384)],

#!#----------------------------------------+-------------+--------------------+
#!# Protocol: RFC8442 PSK cipher suites (TLS 1.2)
#!# added manually 20201109
#!# RFC8442 OpenSSL-Names are expected (TBD: verify names later)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
   '0x0300D001'=>[qw(ECDHE_PSK_WITH_AES_128_GCM_SHA256     ECDHE_PSK_WITH_AES_128_GCM_SHA256)],
   '0x0300D002'=>[qw(ECDHE_PSK_WITH_AES_256_GCM_SHA384     ECDHE_PSK_WITH_AES_256_GCM_SHA384)],
   '0x0300D003'=>[qw(ECDHE_PSK_WITH_AES_128_CCM_8_SHA256   ECDHE_PSK_WITH_AES_128_CCM_8_SHA256)],
   '0x0300D005'=>[qw(ECDHE_PSK_WITH_AES_128_CCM_SHA256     ECDHE_PSK_WITH_AES_128_CCM_SHA256)],

#!#----------------------------------------+-------------+--------------------+
#!# and more ....
#!#----------------------------------------+-------------+--------------------+
); # cipherHexHash

#################################################################

# TLS_PROTOCOL_MESSAGE_CODES
my $TLS_CLIENT_HELLO    = 1;
my $TLS_SERVER_HELLO    = 2;

my %SSL2_CIPHER_STRINGS = (
  '0x020700C0'=> [qw(DES_192_EDE3_CBC_WITH_MD5                DES-CBC3-MD5       SSL_CK_DES_192_EDE3_CBC_WITH_MD5)],
  '0x020701C0'=> [qw(DES_192_EDE3_CBC_WITH_SHA                DES-CBC3-SHA)],
  '0x02060040'=> [qw(DES_CBC_WITH_MD5                         DES-CBC-MD5        SSL_CK_DES_64_CBC_WITH_MD5)],
  '0x02060140'=> [qw(DES_CBC_WITH_SHA                         DES-CBC-SHA)],
  '0x02FF0800'=> [qw(DES_64_CFB64_WITH_MD5_1                  DES-CFB-M1)],
  '0x02050080'=> [qw(IDEA_CBC_WITH_MD5                        IDEA-CBC-MD5       SSL_CK_IDEA_128_CBC_WITH_MD5)],
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
  '0x0300001B'=> [qw(DH_anon_WITH_DES_192_CBC_SHA                 ADH-DES-CBC3-SHA)],
  '0x03000019'=> [qw(DH_anon_EXPORT_WITH_DES40_CBC_SHA            EXP-ADH-DES-CBC-SHA)],
  '0x0300001A'=> [qw(DH_anon_WITH_DES_CBC_SHA                     ADH-DES-CBC-SHA)],
  '0x03000018'=> [qw(DH_anon_WITH_RC4_128_MD5                     ADH-RC4-MD5)],
  '0x03000017'=> [qw(DH_anon_WITH_RC4_40_MD5                      EXP-ADH-RC4-MD5)],
  '0x0300000D'=> [qw(DH_DSS_WITH_3DES_EDE_CBC_SHA                 DH-DSS-DES-CBC3-SHA)],
  '0x0300000B'=> [qw(DH_DSS_EXPORT_WITH_DES40_CBC_SHA             EXP-DH-DSS-DES-CBC-SHA)],
  '0x0300000C'=> [qw(DH_DSS_WITH_DES_CBC_SHA                      DH-DSS-DES-CBC-SHA)],
  '0x03000010'=> [qw(DH_RSA_WITH_3DES_EDE_CBC_SHA                 DH-RSA-DES-CBC3-SHA)],
  '0x0300000E'=> [qw(DH_RSA_EXPORT_WITH_DES40_CBC_SHA             EXP-DH-RSA-DES-CBC-SHA)],
  '0x0300000F'=> [qw(DH_RSA_WITH_DES_CBC_SHA                      DH-RSA-DES-CBC-SHA)],
  '0x03000013'=> [qw(EDH_DSS_WITH_3DES_EDE_CBC_SHA                EDH-DSS-DES-CBC3-SHA)],
  '0x03000011'=> [qw(EDH_DSS_EXPORT_WITH_DES40_CBC_SHA            EXP-EDH-DSS-DES-CBC-SHA)],
  '0x03000012'=> [qw(EDH_DSS_WITH_DES_CBC_SHA                     EDH-DSS-DES-CBC-SHA)],
  '0x03000016'=> [qw(EDH_RSA_WITH_3DES_EDE_CBC_SHA                EDH-RSA-DES-CBC3-SHA)],
  '0x03000014'=> [qw(EDH_RSA_EXPORT_WITH_DES40_CBC_SHA            EXP-EDH-RSA-DES-CBC-SHA)],
  '0x03000015'=> [qw(EDH_RSA_WITH_DES_CBC_SHA                     EDH-RSA-DES-CBC-SHA)],
  '0x0300001D'=> [qw(FZA_DMS_FZA_SHA                              FZA-FZA-CBC-SHA)],
  '0x0300001C'=> [qw(FZA_DMS_NULL_SHA                             FZA-NULL-SHA)],
#  '0x0300001E'=> [qw(FZA_DMS_RC4_SHA                             FZA-RC4-SHA)], #doppelt => prüfen
  '0x03000023'=> [qw(KRB5_WITH_3DES_EDE_CBC_MD5                   KRB5-DES-CBC3-MD5)],
  '0x0300001F'=> [qw(KRB5_WITH_3DES_EDE_CBC_SHA                   KRB5-DES-CBC3-SHA)],
  '0x03000029'=> [qw(KRB5_EXPORT_WITH_DES40_CBC_MD5               EXP-KRB5-DES-CBC-MD5)],
  '0x03000026'=> [qw(KRB5_EXPORT_WITH_DES40_CBC_SHA               EXP-KRB5-DES-CBC-SHA)],
  '0x03000022'=> [qw(KRB5_WITH_DES_CBC_MD5                        KRB5-DES-CBC-MD5)],
  '0x0300001E'=> [qw(KRB5_WITH_DES_CBC_SHA                        KRB5-DES-CBC-SHA)],
  '0x03000025'=> [qw(KRB5_WITH_IDEA_CBC_MD5                       KRB5-IDEA-CBC-MD5)],
  '0x03000021'=> [qw(KRB5_WITH_IDEA_CBC_SHA                       KRB5-IDEA-CBC-SHA)],
  '0x0300002A'=> [qw(KRB5_WITH_RC2_40_CBC_MD5                     EXP-KRB5-RC2-CBC-MD5)],
  '0x03000027'=> [qw(KRB5_WITH_RC2_40_CBC_SHA                     EXP-KRB5-RC2-CBC-SHA)],
  '0x03000024'=> [qw(KRB5_WITH_RC4_128_MD5                        KRB5-RC4-MD5)],
  '0x03000020'=> [qw(KRB5_WITH_RC4_128_SHA                        KRB5-RC4-SHA)],
  '0x0300002B'=> [qw(KRB5_WITH_RC4_40_MD5                         EXP-KRB5-RC4-MD5)],
  '0x03000028'=> [qw(KRB5_WITH_RC4_40_SHA                         EXP-KRB5-RC4-SHA)],
  '0x0300000A'=> [qw(RSA_WITH_3DES_EDE_CBC_SHA                    DES-CBC3-SHA)],
  '0x03000008'=> [qw(RSA_EXPORT_WITH_DES40_CBC_SHA                EXP-DES-CBC-SHA)],
  '0x03000009'=> [qw(RSA_WITH_DES_CBC_SHA                         DES-CBC-SHA)],
  '0x03000007'=> [qw(RSA_WITH_IDEA_SHA                            IDEA-CBC-SHA)],
  '0x03000000'=> [qw(NULL_WITH_NULL_NULL                          NULL-NULL)],
  '0x03000001'=> [qw(RSA_WITH_NULL_MD5                            NULL-MD5)],
  '0x03000002'=> [qw(RSA_WITH_NULL_SHA                        NULL-SHA)],
  '0x030000FF'=> [qw(EMPTY_RENEGOTIATION_INFO_SCSV            SCSV-RENEG)],
);

#_____________________________________________________________________________
#__________________________________________________ help and test functions __|

sub version { # version of SSLhello
    #? prints the official version number of SSLhello (yy-mm-dd)
    local $\ = ""; # no auto '\n' at the end of the line
    print "NET::SSLhello        ($VERSION)\n";
    return;
} # version

sub __print { return sprintf("#%s: %s\n", $SSLHELLO, @_); } ## no critic qw(Subroutines::RequireArgUnpacking)
sub _yprint { return __print(sprintf("%21s=%s", $_[0], $_[1])); } ## no critic qw(Subroutines::RequireArgUnpacking)

sub printConstants {
    #? prints the global constants
    #
    local $\ = ""; # no auto '\n' at the end of the line
    _trace("printConstants() {\n");
    my $line = "#--------------------+-------------------------------------------";
    print __print("#----------------------------------- SSLhello::Constants {");
    print __print($line);
    print ("#OCfg::TLS_EXTENSIONS:\n");
    foreach my $key (sort {lc $a cmp lc $b} keys %OCfg::TLS_EXTENSIONS) {
        print "TLS_EXTENSIONS\{$key\}:\n";
        print "    \{ID\}          \= "; if (defined ($OCfg::TLS_EXTENSIONS{$key}{ID}))            { print "$OCfg::TLS_EXTENSIONS{$key}{ID}\n";               }
        print "    \{CH\}          \= "; if (defined ($OCfg::TLS_EXTENSIONS{$key}{CH}))            { foreach my $val (@{$OCfg::TLS_EXTENSIONS{$key}{CH}})         { print "$val, "; } } print "\n";
#        print "    \{CH_TEXT\}     \= "; if (defined ($OCfg::TLS_EXTENSIONS{$key}{CH_TEXT}))       { foreach my $val (@{$OCfg::TLS_EXTENSIONS{$key}{CH_TEXT}})    { print "$val, "; } } print "\n";
        print "    \{RX\}          \= "; if (defined ($OCfg::TLS_EXTENSIONS{$key}{RX}))            { foreach my $val (@{$OCfg::TLS_EXTENSIONS{$key}{RX}})         { print "$val, "; } } print "\n";
#        print "    \{RX_TEXT\}     \= "; if (defined ($OCfg::TLS_EXTENSIONS{$key}{RX_TEXT}))       { foreach my $val (@{$OCfg::TLS_EXTENSIONS{$key}{RX_TEXT}})    { print "$val, "; } } print "\n";
        print "    \{RECOMMENDED\} \= "; if (defined ($OCfg::TLS_EXTENSIONS{$key}{RECOMMENDED}))   { print "$OCfg::TLS_EXTENSIONS{$key}{RECOMMENDED}\n";      }
        print "    \{TLS13\}       \= "; if (defined ($OCfg::TLS_EXTENSIONS{$key}{TLS13}))         { foreach my $val (@{$OCfg::TLS_EXTENSIONS{$key}{TLS13}})      { print "$val, "; } } print "\n";
        print "    \{RFC\}         \= "; if (defined ($OCfg::TLS_EXTENSIONS{$key}{RFC}))           { foreach my $val (@{$OCfg::TLS_EXTENSIONS{$key}{RFC}})        { print "$val, "; } } print "\n";
        print "    \{DEFAULT\}     \= "; if (defined ($OCfg::TLS_EXTENSIONS{$key}{DEFAULT}))       { foreach my $val (@{$OCfg::TLS_EXTENSIONS{$key}{DEFAULT}}){
                                                                                                                my $__first_indent = 0;
                                                                                                                _trace2_ (", \n" . " " x $__first_indent) if ($__first_indent > 0); # add a newline if not the first line
                                                                                                                my $__decode_str = _decode_val (undef, \$val, \$OCfg::TLS_EXTENSIONS{$key}, $__first_indent, 20, ": ", ", ", " | ", " / ");

                                                                                                                _trace5_ (" " x 20) if ($__first_indent < 1);
                                                                                                                print $__decode_str;
                                                                                                                $__first_indent = 20;
                                                                                                                                                                                      } } print "\n";
        print "    \{CHECK\}       \= "; if (defined ($OCfg::TLS_EXTENSIONS{$key}{CHECK}))         { print "$OCfg::TLS_EXTENSIONS{$key}{CHECK}\n";            }
        print "    \{COMMENT\}     \= "; if (defined ($OCfg::TLS_EXTENSIONS{$key}{COMMENT}))       { print "$OCfg::TLS_EXTENSIONS{$key}{COMMENT}\n";          }
        print "\n";
    }
    print __print($line);
    print __print("#----------------------------------- SSLhello::Constants }");
    print "\n";
    _trace("printConstants() }\n");
    return;
} # printConstants

sub printParameters {
    #? prints the global parameters
    #
    local $\ = ""; # no auto '\n' at the end of the line
    _trace("printParameters() {\n");
    my $line = "#--------------------+-------------------------------------------";
    print __print("#---------------------------------- SSLhello::Parameters {");
    print __print($line);
    print _yprint("retry",           $SSLhello::retry)           if (defined($SSLhello::retry));
    print _yprint("timeout",         $SSLhello::timeout)         if (defined($SSLhello::timeout));
    print _yprint("timeout",         $SSLhello::timeout)         if (defined($SSLhello::timeout));
    print _yprint("connect_delay",   $SSLhello::connect_delay)   if (defined($SSLhello::connect_delay));
    print _yprint("trace",           $SSLhello::trace)           if (defined($SSLhello::trace));
    print _yprint("traceTIME",       $SSLhello::traceTIME)       if (defined($SSLhello::traceTIME));
    print _yprint("usereneg",        $SSLhello::usereneg)        if (defined($SSLhello::usereneg));
    print _yprint("double_reneg",    $SSLhello::double_reneg)    if (defined($SSLhello::double_reneg));
    print _yprint("usesni",          $SSLhello::usesni)          if (defined($SSLhello::usesni));
    print _yprint("use_sni_name",    $SSLhello::use_sni_name)    if (defined($SSLhello::use_sni_name));
    print _yprint("sni_name",        $SSLhello::sni_name)        if (defined($SSLhello::sni_name));
    print _yprint("use_signature_alg", $SSLhello::use_signature_alg)  if (defined($SSLhello::use_signature_alg));
    print _yprint("useecc",          $SSLhello::useecc)          if (defined($SSLhello::useecc));
    print _yprint("useecpoint",      $SSLhello::useecpoint)      if (defined($SSLhello::useecpoint));
    if (%{$SSLhello::extensions_by_prot}) {
        print __print("extensions_by_prot");
        foreach my $_prot (sort keys %{$SSLhello::extensions_by_prot}) {
            print _yprint("->{$_prot}", join(", ",@{$SSLhello::extensions_by_prot->{$_prot}})) if defined($SSLhello::extensions_by_prot->{$_prot});
        }
    }
    print _yprint("check_extensions",       join(", ",@{$SSLhello::check_extensions})) if (defined($SSLhello::check_extensions));
    print _yprint("extensions_max_values",  $SSLhello::extensions_max_values) if (defined($SSLhello::extensions_max_values));
    print _yprint("starttls",        $SSLhello::starttls)        if (defined($SSLhello::starttls));
    print _yprint("starttlsType",    $SSLhello::starttlsType)    if (defined($SSLhello::starttlsType));
    for my $i (1..5) {
        print _yprint("starttlsPhaseArray[$i]", $SSLhello::starttlsPhaseArray[$i])   if (defined($SSLhello::starttlsPhaseArray[$i]));
    }
    for my $i (6..8) {
        print _yprint("starttlsErrorArray[".($i-5)."]", $SSLhello::starttlsPhaseArray[$i] . " = starttlsPhaseArray[$i] (internally)")   if (defined($SSLhello::starttlsPhaseArray[$i]));
    }
    print _yprint("starttlsDelay",   $SSLhello::starttlsDelay)   if (defined($SSLhello::starttlsDelay));
    print _yprint("slowServerDelay", $SSLhello::slowServerDelay) if (defined($SSLhello::slowServerDelay));
    print _yprint("experimental",    $SSLhello::experimental)    if (defined($SSLhello::experimental));
    print _yprint("proxyhost",       $SSLhello::proxyhost)       if (defined($SSLhello::proxyhost));
    print _yprint("proxyport",       $SSLhello::proxyport)       if (defined($SSLhello::proxyport));
    print _yprint("max_ciphers",     $SSLhello::max_ciphers)     if (defined($SSLhello::max_ciphers));
    print _yprint("max_sslHelloLen", $SSLhello::max_sslHelloLen) if (defined($SSLhello::max_sslHelloLen));
    print __print("# information about the OS and some socket constants and functions");
    print __print($line);
    print _yprint("OS",                  $^O)                         if (defined($^O));
    my $_pf_inet =                                      Socket::PF_INET;
    print _yprint("socket::PF"."_INET",  $_pf_inet);
    my $_af_inet =                                      Socket::AF_INET;
    print _yprint("socket::AF"."_INET",  $_af_inet);
    my $_sock_stream = (defined(Socket::SOCK_STREAM)) ? Socket::SOCK_STREAM : $STR{'UNDEF'};
    print _yprint("socket::SOCK_STREAM", $_sock_stream);
    my $_sol_socket =  (defined(Socket::SOL_SOCKET))  ? Socket::SOL_SOCKET  : $STR{'UNDEF'};
    print _yprint("socket::SOL_SOCKET",  $_sol_socket);
    my $_so_sndtimeo = (defined(Socket::SO_SNDTIMEO)) ? Socket::SO_SNDTIMEO : $STR{'UNDEF'};
    print _yprint("socket::SO_SNDTIMEO", $_so_sndtimeo);
    my $_so_rcvtimeo = (defined(Socket::SO_RCVTIMEO)) ? Socket::SO_RCVTIMEO : $STR{'UNDEF'};
    print _yprint("socket::SO_RCVTIMEO", $_so_rcvtimeo);
    my ($_dummy1, $_dummy2, $_protocol) = getprotobyname('tcp'); # is failsafer than '(getprotobyname('tcp'))[2]'
        if (! $_protocol) {
            $_protocol = Socket::IPPROTO_TCP;
        }
    print _yprint("socket::getprotobyname('tcp')", $_protocol);
    print __print($line);
    print __print("#---------------------------------- SSLhello::Parameters }");
    _trace("printParameters() }\n");
    return;
} # printParameters

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

### --------------------------------------------------------------------------------------------------------- ###
### compile packets functions
### ---------------------------------------------------------------------------------------------------------
### Aufruf mit printCipherStringArray ($cfg{'legacy'}, $host, $port, "TLS1.2 0x0303", $cfg{'usesni'}, @acceptedCipherArray);
sub printCipherStringArray ($$$$$@) {
    #? <<description missing>> # FIXME:
    # @cipherArray: string representation of the cipher octets, e.g. 0x0300000A
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
    my $sep_sep = " | ";
    my $protocol = $PROTOCOL_VERSION{$ssl}; # 0x0002, 0x3000, 0x0301, 0x0302
    my $cipher  = "";
    local $\    = ""; # no auto '\n' at the end of the line

    _trace("printCipherStringArray($legacy, $host, $port, $ssl, $usesni, ...) {\n");
    $legacy = "csv" if ($legacy eq "compact");                      # backward compatibility: old 'compact' style => new 'csv' style
    if ($usesni) {
        $sni = "SNI";
        $SSLhello::use_sni_name = 1 if ( ($SSLhello::use_sni_name == 0) && ($SSLhello::sni_name) && ($SSLhello::sni_name ne "1") ); ###FIX: quickfix until migration of o-saft.pl is compleated (tbd)
        $sni .= " ($SSLhello::sni_name)" if ( ($SSLhello::use_sni_name) && ($SSLhello::sni_name) );
    } else {
        $sni = "no SNI";
    }

    my $firstEle = 0;
    if ($arrayLen > 1) { # 2 or more ciphers
        if ( ($cipherArray[0] eq $cipherArray[1]) ) { # cipher suites in server-preferred order
            if ($legacy eq 'csv') { $cipherOrder = "Server Order"; } else { print "# cipher suites in server-preferred order:\n"; }
            $firstEle = 1;
        } else {
            if ($legacy eq 'csv') { $cipherOrder = "No Order"; } else { print "# server has NO preferred order for cipher suites\n"; }
        }
    } elsif ($arrayLen == 0) { # no cipher for this protocol
        if ($legacy eq 'csv') { # csv-style, protocol without cipher
            printf "%s%s%s%s%-6s%s%-8s%s%-12s%s%8s%s\n",
                $host, $sep,            # %s%s
                $port, $sep,            # %s%s
                $ssl,  $sep,            # %-6s%s
                $sni, $sep,             # %-8s%s%
                "", $sep,               # %-12s%s
                "", $sep;               # %8s%s
        }
    }

    foreach my $protocolCipher (@cipherArray[$firstEle .. $#cipherArray]) { # array may have the first element twice to signal a server-preferred order
        if ($usesni) {
            if ($protocol != 0x0304) { # get results for SNI support from tls extension 'server_name'
                if (exists($_SSLhello{$protocolCipher}{param}{server_name}{RX}{values}) ) { # SNI is suppoted by the server
                    $sni = "SNI: yes";
                } else {                                            # the server does not support sni
                    $sni = "SNI: no";
                }
            } else {                                                ## workaround for TLS 1.3, sni extension is not decrypted, yet
                $sni = "SNI";
            }
            $SSLhello::use_sni_name = 1 if ( ($SSLhello::use_sni_name == 0) && ($SSLhello::sni_name) && ($SSLhello::sni_name ne "1") ); ###FIX: quickfix until migration of o-saft.pl is compleated (tbd)
            $sni .= " ($SSLhello::sni_name)" if ( ($SSLhello::use_sni_name) && ($SSLhello::sni_name) );
        } else {
            $sni = "no SNI";
        }
        if ($protocol > 0x0002) {                                   # SSLv3 and TLS
            $cipher = "0x".substr($protocolCipher,-4,4);            # IANA HEX-value
        } else {                                                    # SSLv2
            $cipher = "0x".substr($protocolCipher,-6,6);
        }
        if ($legacy eq 'csv') {                                     # csv-style output
            printf "%s%s%s%s%-6s%s%-8s%s%-12s%s%8s%s",
                $host, $sep,            # %s%s
                $port, $sep,            # %s%s
                $ssl,  $sep,            # %-6s%s
                $sni,  $sep,            # %-8s%s%
                $cipherOrder, $sep,     # %-12s%s
                $cipher, $sep;          # %8s%s
            if ( (defined ($cipherHexHash{$protocolCipher}) ) && ($#{$cipherHexHash{$protocolCipher}}>0) ) { # definiert, max index >0
                printf "%-36s%s%-41s",
                    $cipherHexHash{$protocolCipher}[1], $sep,
                    $cipherHexHash{$protocolCipher}[0];
            } else { # no RFC-Defined cipher
                printf "%-36s%s%-41s\n", "NO-RFC-".$cipher, $sep, "NO-RFC-".$cipher;
            }
            print $sep;
            # Print parameters by the cipher
            print getCipherParameter($protocolCipher, "Paramters: ", $sep_sep) . "\n";
        } else {                                                    # human readable output
            printf "# Cipher-String: >%s<,",$cipher;
            if ( (defined ($cipherHexHash{$protocolCipher}) ) && ($#{$cipherHexHash{$protocolCipher}}>0) ) { # definiert, max index >0
                printf " %-36s, %s", $cipherHexHash{$protocolCipher}[1], $cipherHexHash{$protocolCipher}[0];
                # Print parameters by the cipher
                print getCipherParameter($protocolCipher, ", Paramters: ", $sep_sep);
            } else {
                print  " NO-RFC-" . $cipher;
            }
            print "\n";
        }
    } # foreach my $protocolCipher ...
    if ($legacy eq 'csv') { # csv-style
        print "\n";
    }
    _trace("printCipherStringArray() }\n");
    return;
} # printCipherStringArray


sub checkSSLciphers ($$$@) {
    #? simulate SSL handshake to check any ciphers by the HEX value
    #? @cipher_str_array: string representation of the cipher octets, e.g. >=SSLv3: 0x0300000Aa, SSLv2: 0x02800102
    #? if the first 2 ciphers are identical the array is sorted by priority of the server
    #
    my($host, $port, $ssl, @cipher_str_array) = @_;
    my $cipher_spec     = "";               # raw data with all hex values, SSLv2: 3 bytes, SSLv3 and later: 2 bytes
    my $acceptedCipher  = "";
    my @cipherSpecArray = ();               # temporary Array for all ciphers to be tested in the next _doCheckSSLciphers
    my @acceptedCipherArray = ();           # all ciphers accepted by the server
    my @acceptedCipherSortedArray = ();     # all ciphers accepted by the server with server order
    my $arrayLen = 0;
    my $i = 0;
    my $protocol = $PROTOCOL_VERSION{$ssl}; # 0x0002, 0x3000, 0x0301, 0x0302
    my $maxCiphers = $SSLhello::max_ciphers;
    local $\ = ""; # no auto '\n' at the end of the line
    %_SSLhello = ();                        # delete result hash '_SSLhello'
    printConstants ()  if ($SSLhello::trace > 3);              # additional trace information
    printParameters () if ($SSLhello::trace > 3);              # additional trace information

    error_handler->reset_err( {module => ($SSLHELLO), sub => 'checkSSLciphers', print => ($SSLhello::trace > 3), trace => $SSLhello::trace} );

    _trace("checkSSLciphers($host, $port, $ssl,");
    _trace_cipher_array( " ) {", @cipher_str_array);

    if ($protocol == $PROTOCOL_VERSION{'SSLv2'}) { #SSL2
        _trace4_ ("\n");
        foreach my $cipher_str (@cipher_str_array) {
            _trace4 (" checkSSLciphers: Cipher-String: >$cipher_str< -> ");
            ($cipher_str) =~ s/(?:0x03|0x02|0x)?\s?([a-fA-F0-9]{2})\s?/chr(hex $1)/egx; ## Str2hex
            _trace4_ (" >". hexCodedCipher($cipher_str)."<\n");

            $cipher_spec .= $cipher_str; # collect cipher specs
        }
        _trace4_ ("\n");
        $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_spec);
        my $anzahl = int length ($acceptedCipher) / 3;
        _trace(" checkSSLciphers: Accepted ". $anzahl ." Ciphers:");
        _trace_cipher_array("", compileSSL2CipherArray ($acceptedCipher));
        _trace("checkSSLciphers() }\n");
        return (compileSSL2CipherArray ($acceptedCipher));
    } else { # SSL3, TLS, DTLS .... check by the cipher
        $cipher_spec = ""; # collect cipher specs
        _trace4_ ("\n");
        my $tot = scalar(@cipher_str_array);;
        my $cnt = 0;
        my $len = 0;
        foreach my $cipher_str (@cipher_str_array) {
            $cnt++;
            $len = ($len < length($cipher_str)) ? 1 : ($len - length($cipher_str));
            printf("$STR{'INFO'}  cipher %4d/%d %s%s\n", $cnt, $tot, $cipher_str, " "x $len) if (1 < $SSLhello::verbose);
                # TBD: \r not possible due to too many following messages
            _trace5 (" checkSSLciphers: add cipher >$cipher_str< to cipher-string -> ");
            if ($cipher_str !~ /0x02/x) { # No SSL2 cipher
                ($cipher_str) =~ s/(?:0x0[3-9a-fA-F]00|0x)?\s?([a-fA-F0-9]{2})\s?/chr(hex $1)/egx; ## Str2hex
                _trace5_ ("  >". hexCodedCipher($cipher_str)."<");
            } else {
                _trace5_ ("  SSL2-Cipher suppressed\n");
                next; # nothing to do for this cipher
            }
            _trace5_ ("\n");

            push (@cipherSpecArray, $cipher_str); # add cipher to next test
            $arrayLen = @cipherSpecArray;
            if ( $arrayLen >= $maxCiphers) { # test up to ... ciphers ($SSLhello::max_ciphers = $CST{'_MY_SSL3_MAX_CIPHERS'}) with 1 doCheckSSLciphers (=> Client Hello)
                $my_error = ""; # reset error message
                # reset error_handler and set basic information for this sub
                error_handler->reset_err( {module => ($SSLHELLO), sub => 'checkSSLciphers', print => ($SSLhello::trace > 3), trace => $SSLhello::trace} );
                $cipher_spec = join ("",@cipherSpecArray); # all ciphers to test in this round

                if ($SSLhello::trace > 1) { # print ciphers that are tested this round:
                    $i = 0;
                    my $txt = "";
                       $txt = " (STARTTLS)" if $SSLhello::starttls;
                    _trace1(" checkSSLciphers:$txt Checking ". scalar(@cipherSpecArray)." Ciphers, this round (1):");
                    _trace4_("\n");
                    _trace_(_trace_array2str(compileTLSCipherArray($cipher_spec))."\n");
                }
                $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_spec, $dtlsEpoch); # test ciphers and collect accepted ciphers, $dtlsEpoch is only used in DTLS
                _trace2_ ("       ");
                if ($acceptedCipher) { # received an accepted cipher
                    _trace1_("=> found >0x0300".hexCodedCipher($acceptedCipher)."<\n");
                    if (grep { $_ eq $acceptedCipher } @cipherSpecArray) { #accepted cipher that was in the checklist
                        @cipherSpecArray = grep { $_ ne $acceptedCipher } @cipherSpecArray;    # delete accepted cipher from ToDo-Array '@cipherSpecArray'
                    } else { # cipher was *NOT* in the checklist
                        carp("$STR{WARN} Server replied (again) with cipher '0x".hexCodedCipher($acceptedCipher)."' that has not been requested this time (1): ('0x".hexCodedCipher($cipherSpecArray[0])." ... 0x".hexCodedCipher($cipherSpecArray[-1])."'.");
                        @cipherSpecArray = (); # => Empty @cipherSpecArray
                     }
                    push (@acceptedCipherArray, $acceptedCipher); # add the cipher to the list of accepted ciphers
                } else { # no ciphers accepted
                    _trace1_ ("=> no Cipher found\n");
                if ( ((error_handler->get_err_type()) <= $OERR{'SSLHELLO_RETRY_HOST'})
                     || ($my_error =~ /Fatal Exit/)
                     || ($my_error =~ /make a connection/ )
                     || ($my_error =~ /create a socket/) ) {
                        #### Fatal Errors -> Useless to check more protocols

                        _trace (" checkSSLciphers (1.1): '$my_error'\n") if ($my_error);
                        _trace ("**WARNING: checkSSLciphers => Exit loop (1.1): -> Abort '$host:$port' caused by ".error_handler->get_err_str."\n");
                        @cipherSpecArray =(); # server did not accept any cipher => nothing to do for these ciphers => empty @cipherSpecArray
                        last;
                    } elsif ( ((error_handler->get_err_type()) <= $OERR{'SSLHELLO_RETRY_PROTOCOL'})
                      || ($my_error =~ /answer ignored/)
                      || ($my_error =~ /protocol_version.*?not supported/)
                      || ($my_error =~ /check.*?aborted/x) ) { # Just stop, no warning
                        _trace2 (" checkSSLciphers (1.2): '$my_error'\n") if ($my_error);
                        @cipherSpecArray =(); # server did not accept any cipher => nothing to do for these ciphers => empty @cipherSpecArray
                        last;
                    } elsif ( ($my_error =~ /target.*?ignored/x)
                      || ($my_error =~ /protocol.*?ignored/x) ) {
                         #### Fatal Errors -> Useless to check more ciphers
                        _trace2 (" checkSSLciphers (1.3): \'$my_error\'\n") if ($my_error);
                        carp("$STR{WARN} checkSSLciphers => Exit loop (1.3)");
                        @cipherSpecArray =(); # server did not accept any cipher => nothing to do for these ciphers => empty @cipherSpecArray
                        last;
                    } elsif ( ((error_handler->get_err_type()) <= $OERR{'SSLHELLO_RETRY_CIPHERS'}) || ($my_error =~ /\-> Received NO Data/)) { # some servers 'Respond' by closing the TCP connection => check each cipher individually
                        if ($SSLhello::noDataEqNoCipher == 1) { # ignore error messages for TLS intolerant servers that do not respond if non of the ciphers are supported
                            _trace2 (" checkSSLciphers (1.4): Ignore error messages for TLS intolerant servers that do not respond if non of the ciphers are supported. Ignored: '$my_error'\n");
                            @cipherSpecArray =(); # => empty @cipherSpecArray
                            $my_error = ""; # reset error message
                            next;
                        } else { # noDataEqNoCipher == 0
                            _trace2 (" checkSSLciphers (1.5): \'$my_error\', => Please use the option \'--noDataEqNoCipher\' for servers not answeing if none of the requested ciphers are supported. Retry to test the following cipheres individually:\n");
                            carp("$STR{WARN} checkSSLciphers (1.5): \'$my_error\', => Please use the option \'--noDataEqNoCipher\' for servers not answeing if none of the requested ciphers are supported.");
                        }
                    } elsif ( ((error_handler->get_err_type()) <= $OERR{'SSLHELLO_RETRY_RECORD'}) || ($my_error =~ /Error 1: too many requests/)) {   #### Too many connections: Automatic suspension and higher timeout did not help
                        _trace2 (" checkSSLciphers (1.6): \'$my_error\', => Please use the option \'--starttls_delay=SEC\' to slow down\n");
                        carp("$STR{WARN} checkSSLciphers (1.6): \'$my_error\', => Please use the option \'--starttls_delay=SEC\' to slow down");
                        next;
                    } elsif ((error_handler->is_err) || $my_error) { # error found
                        unless (error_handler->is_err) { # no error set, but no socket obtaied
                            error_handler->new( {
                                type    => $OERR{'SSLHELLO_ERROR_MESSAGE_IGNORED'},
                                id      => '(1.9)',
                                message => "Unexpected Error Message ignored: \'$my_error\'",
                                warn    => 1,
                            } );
                        }
                        $my_error = ""; # reset error message
                        #reset error_handler and set basic information for this sub
                        error_handler->reset_err( {module => ($SSLHELLO), sub => 'checkSSLciphers', print => ($SSLhello::trace > 3), trace => $SSLhello::trace} );
                    } # else: no cipher accepted but no error
                    @cipherSpecArray =(); # => Empty @cipherSpecArray
                } # end: if 'no ciphers accepted'
            } # end: test ciphers
        } # end: foreach my $cipher_str...

        while ( (@cipherSpecArray > 0) && (!error_handler->is_err) && (!$my_error) ) { # there are still ciphers to test in this last round
            $cipher_spec = join ("",@cipherSpecArray); # all ciphers to test in this round;
            if ($SSLhello::trace > 1) { #print ciphers that are tested this round:
                $i = 0;
                _trace(" checkSSLciphers: Checking ". scalar(@cipherSpecArray)." Ciphers, this round (2):");
                _trace4_("\n");
                _trace_(_trace_array2str(compileTLSCipherArray($cipher_spec))."\n");
            }
            $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_spec, $dtlsEpoch); # test ciphers and collect Accepted ciphers
            _trace2_ ("       ");
            if ($acceptedCipher) { # received an accepted cipher ## TBD: error handling using `given'/`when' TBD
                _trace1_("=> found >0x0300".hexCodedCipher($acceptedCipher)."<\n");
                if (grep { $_ eq $acceptedCipher } @cipherSpecArray) { # accepted cipher that was in the checklist
                    @cipherSpecArray = grep { $_ ne $acceptedCipher } @cipherSpecArray;    # delete accepted cipher from ToDo-Array '@cipherSpecArray'
                } else { # cipher was *NOT* in the checklist
                    carp("$STR{WARN} Server replied (again) with cipher '0x".hexCodedCipher($acceptedCipher)."' that has not been requested this time (2): ('0x".hexCodedCipher($cipherSpecArray[0])." ... 0x".hexCodedCipher($cipherSpecArray[-1])."'.");
                    @cipherSpecArray = (); # => Empty @cipherSpecArray
                }
                push (@acceptedCipherArray, $acceptedCipher); # add the cipher to the list of accepted ciphers
            } else { # no cipher accepted
                _trace1_ ("=> no cipher found\n");
                if ( ($my_error =~ /Fatal Exit/) || ($my_error =~ /make a connection/ ) || ($my_error =~ /create a socket/) ) { #### Fatal Errors -> Useless to check more ciphers
                    _trace2 (" checkSSLciphers (2.1): '$my_error'\n");
                    carp("$STR{WARN} checkSSLciphers => Exit loop (2.1)");
                    @cipherSpecArray =(); # server did not accept any cipher => nothing to do for these ciphers => empty @cipherSpecArray
                    last;
                } elsif ( ($my_error =~ /answer ignored/) || ($my_error =~ /protocol_version.*?not supported/) || ($my_error =~ /check.*?aborted/) ) { # just stop, no warning
                    _trace1 (" checkSSLciphers (2.2): Exit loop");
                    @cipherSpecArray =(); # server did not accepty any cipher => nothing to do for these ciphers => empty @cipherSpecArray
                    last;       # no more ciphers to test
                } elsif ( ($my_error =~ /target.*?ignored/x) || ($my_error =~ /protocol.*?ignored/x) ) {   #### Fatal Errors -> Useless to check more ciphers
                    _trace2 (" checkSSLciphers (2.3): '$my_error'\n");
                    carp("$STR{WARN} checkSSLciphers => Exit loop (2.3)");
                    @cipherSpecArray =(); # server did not accept any cipher => nothing to do for these ciphers => empty @cipherSpecArray
                    last;
                } elsif ( $my_error =~ /\-> Received NO Data/) { # some servers 'Respond' by closing the TCP connection => check each cipher individually
                    if ($SSLhello::noDataEqNoCipher == 1) { # ignore error messages for TLS intolerant servers that do not respond if non of the ciphers are supported
                        _trace1 (" checkSSLciphers (2.4): Ignore Error Messages for TLS intolerant Servers that do not respond if non of the Ciphers are supported. Ignored: '$my_error'\n");
                        @cipherSpecArray =(); # => Empty @cipherSpecArray
                        $my_error = ""; # reset error message
                        next;   # here: eq last
                    } else {    # noDataEqNoCipher == 0
                        _trace2 (" checkSSLciphers (2.5): '$my_error', => Please use the option \'--noDataEqNoCipher\' for Servers not answering if none of the requested Ciphers are supported. Retry to test the following Cipheres individually:\n");
                        carp("$STR{WARN} checkSSLciphers (2.5): '$my_error', => Please use the option \'--noDataEqNoCipher\' for Servers not answering if none of the requested Ciphers are supported.");
                    }
                } elsif ($my_error =~ /Error 1: too many requests/) {   #### Too many connections: Automatic suspension and higher timeout did not help
                    _trace2 (" checkSSLciphers (1.6): \'$my_error\', => Please use the option \'--starttls_delay=SEC\' to slow down\n");
                    carp("$STR{WARN} checkSSLciphers (1.6): \'$my_error\', => Please use the option \'--starttls_delay=SEC\' to slow down");
                    next;
                } elsif ($my_error) {  # error found
                    _trace2 (" checkSSLciphers (2.6): Unexpected Error Message ignored: '$my_error'\n");
                    carp("$STR{WARN} checkSSLciphers (2.6): Unexpected Error Message ignored: '$my_error'\n");
                    $my_error = ""; # reset error message
                }
                @cipherSpecArray =(); # => Empty @cipherSpecArray
            }
        } # end while ...

        _trace(" checkSSLciphers: Accepted ". scalar(@acceptedCipherArray)." Ciphers (unsorted):");
        _trace_cipher_array("", compileTLSCipherArray(join("",@acceptedCipherArray)));

        # >>>>> Check priority of ciphers <<<<<
        ####################################################################################################################
        ######      Derzeit wird der 1. Cipher doppelt in die Liste eingetragen, wenn der Server die Prio vorgibt      #####
        ####################################################################################################################
        my $cipher_str = join ("",@acceptedCipherArray);
        printTLSCipherList ($cipher_str) if ($SSLhello::trace > 3); # abt: _trace4

        while ($cipher_str) { # found some cipher => Check priority
            _trace2 (" checkSSLciphers: Check Cipher Priority for Cipher-Spec >". hexCodedString($cipher_str)."<\n");
            $my_error = ""; # reset error message
            $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_str, $dtlsEpoch, 1); # collect accepted ciphers by priority
            _trace2_ ("# -->". hexCodedCipher($acceptedCipher)."<\n");
            if ($my_error) {
                _trace2 (" checkSSLciphers (3): '$my_error'\n");
                # list untested ciphers
                my $str = _trace_array2str(compileTLSCipherArray(join("",@acceptedCipherArray)));
                if ( ($my_error =~ /Fatal Exit/) || ($my_error =~ /make a connection/ ) || ($my_error =~ /create a socket/) || ($my_error =~ /target.*?ignored/x) || ($my_error =~ /protocol.*?ignored/x) ) {
                    _trace1 (" checkSSLciphers (3.1): => Unexpected Loss of Connection while checking the priority of the ciphers \'$str\' -> Exit loop. Reason: '$my_error'\n");
                    carp("$STR{WARN} checkSSLciphers (3.1): => Unexpected Loss of Connection while checking the priority of the ciphers \'$str\' -> Exit loop. Reason: '$my_error'");
                    $my_error = ""; # reset error message
                    last;
                } elsif ( ($my_error =~ /answer ignored/) || ($my_error =~ /protocol_version.*?not supported/) || ($my_error =~ /check.*?aborted/x) ) { # Just stop, no warning
                    _trace1 (" checkSSLciphers (3.2): => Unexpected Lack of Data or unexpected Answer while checking the priority of the ciphers \'$str\' -> Exit loop. Reason: '$my_error'\n");
                    carp("$STR{WARN} checkSSLciphers (3.2): => Unexpected Lack of Data or unexpected Answer while checking the priority of the ciphers \'$str\' -     > Exit loop. Reason: '$my_error'");
                    _hint("The server may have an IPS in place. To slow down the test, consider adding the option '--connect-delay=SEC'.");
                    $my_error = ""; # reset error message
                    last;
                } else { #any other Error like: #} elsif ( ( $my_error =~ /\-> Received NO Data/) || ($my_error =~ /answer ignored/) || ($my_error =~ /protocol_version.*?not supported/) || ($my_error =~ /check.*?aborted/) ) {
                    _trace1 (" checkSSLciphers (3.3): => Received no cipher while checking the priority of the ciphers \'$str\' -> Exit loop. Reason: ''\n");
                    carp("$STR{WARN} checkSSLciphers (3.3): => Received no cipher while checking the priority of the ciphers \'$str\' -> Exit loop. Reason: '$my_error'");
                    _hint("The server may have an IPS in place. To slow down the test, consider adding the option '--connect-delay=SEC'.");
                    $my_error = ""; # reset error message
                    last;
                }
            }
            if ($acceptedCipher) { # received an accepted cipher
                push (@acceptedCipherSortedArray, $acceptedCipher); # add found cipher to sorted List
                _doCheckAllExtensions ($host, $port, $protocol, $acceptedCipher, $dtlsEpoch, 1); # check Extension parameters for this cipher
                $arrayLen = @acceptedCipherSortedArray;
                if ( $arrayLen == 1) { # 1st cipher
                    if ($acceptedCipher eq ($acceptedCipherArray[0])) { # is equal to 1st cipher of requested cipher_spec
                        _trace3_ ("# --> Got back 1st cipher of unsorted List => Check again with this Cipher >".hexCodedTLSCipher($acceptedCipher)."< at the end of the List\n");
                        shift (@acceptedCipherArray); # delete first cipher in this array
                        $cipher_str = join ("",@acceptedCipherArray).$acceptedCipher; # test again with the first cipher as the last
                        _trace3_ ("# --> Check Cipher Prioity for Cipher-S(2) > ". hexCodedString($cipher_str)."<\n");
                        _trace4_ ("# ---> backup parameters to values of the first check of cipher " . hexCodedTLSCipher($acceptedCipher) . "\n");
                        my %_param_tmp_hash = ();
                        %_param_tmp_hash = %{$_SSLhello{'0x0300'.hexCodedCipher($acceptedCipher)}{param}} if (exists ($_SSLhello{'0x0300'.hexCodedCipher($acceptedCipher)}{param}));# save the param hash, just in case we will get the same cipher again
                        $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_str, $dtlsEpoch, 1); # if server uses a priority List we get the same cipher again!
                        _trace3_ ("# -->". hexCodedCipher($acceptedCipher)."<\n");
                        _trace4_ ("# --->". hexCodedCipher($acceptedCipher)."<\n");
                        if ($acceptedCipher) { # received an accepted cipher
                            push (@acceptedCipherSortedArray, $acceptedCipher);
                            if ($acceptedCipher eq $acceptedCipherSortedArray[0]) { # got 1st cipher again  => order -> restore param hash
                                _trace4_ ("# ---> restore stored parameters to values of first check of cipher ". hexCodedTLSCipher($acceptedCipher) . "\n");
                                $_SSLhello{'0x0300'.hexCodedCipher($acceptedCipher)}{param} = \%_param_tmp_hash;
                            } else { # check Extensions for new cipher
                                _trace4_ ("# ---> is a new cipher => noi preferred order by the server\n");
                                _doCheckAllExtensions ($host, $port, $protocol, $acceptedCipher, $dtlsEpoch, 1); # check Extension parameters for this cipher
                            }
                        }
                    } else { # 1st element is nOT equal of 1st checked cipher => sorted => NOW: add cipher again to mark it as sorted list
                        push (@acceptedCipherSortedArray, $acceptedCipher); # add found cipher again to sorted List
                    }
                } # not the first cipher

                if ( (grep { $_ eq $acceptedCipher } @acceptedCipherArray) || (($arrayLen == 1) && ($acceptedCipher eq $acceptedCipherSortedArray[1])) ) { # accepted cipher was in the checklist
                    @acceptedCipherArray = grep { $_ ne $acceptedCipher } @acceptedCipherArray;    # delete accepted cipher in ToDo-Array '@acceptedCipherArray'
                } else { # cipher was *NOT* in the checklist
                    carp("$STR{WARN} checkSSLciphers: Server replied (again) with cipher '0x".hexCodedCipher($acceptedCipher)."' that has not been requested this time (3): ('0x".hexCodedCipher($acceptedCipherArray[0])." ... 0x".hexCodedCipher($acceptedCipherArray[-1])."'. Untested Ciphers:");
                    # list untested ciphers
                    my $str = _trace_array2str(compileTLSCipherArray(join("",@acceptedCipherArray)));
                    @acceptedCipherArray = (); # => Empty @cipherSpecArray
                } # End cipher was *NOT* in the ckecklist

                $cipher_str = join ("",@acceptedCipherArray); # check prio for next ciphers
            } else { # nothing received => lost connection
                _trace2 (" checkSSLciphers (6): '$my_error'\n");
                # list untested ciphers
                my $str = _trace_array2str(compileTLSCipherArray(join("",@acceptedCipherArray)));
                if (  ($my_error =~ /Fatal Exit/) || ($my_error =~ /make a connection/ ) || ($my_error =~ /create a socket/) || ($my_error =~ /target.*?ignored/x) || ($my_error =~ /protocol.*?ignored/x) ) {
                    _trace1 (" checkSSLciphers (6.1): => Unexpected Loss of Connection while checking the priority of the ciphers \'$str\' -> Exit loop. Reason: '$my_error'\n");
                    carp("$STR{WARN} checkSSLciphers (6.1): => Unexpected Loss of Connection while checking the priority of the ciphers \'$str\' -> Exit loop. Reason: '$my_error'");
                    $my_error = ""; # reset error message
                    last;
                } elsif ($my_error =~ /Error 1: too many requests/) {   #### Too many connections: Automatic suspension and higher timeout did not help
                    _trace2 (" checkSSLciphers (1.6): \'$my_error\', => Please use the option \'--starttls_delay=SEC\' to slow down\n");
                    carp("$STR{WARN} checkSSLciphers (1.6): \'$my_error\', => Please use the option \'--starttls_delay=SEC\' to slow down");
                    next;
                } elsif ($my_error) { #any other Error like: #} elsif ( ( $my_error =~ /\-> Received NO Data/) || ($my_error =~ /answer ignored/) || ($my_error =~ /protocol_version.*?not supported/) || ($my_error =~ /check.*?aborted/) ) {
                    _trace1 (" checkSSLciphers (6.2): => Unexpected Lack of Data or unexpected Answer while checking the priority of the ciphers \'$str\' -> Exit loop. Reason: ''\n");
                    carp("$STR{WARN} checkSSLciphers (6.2): => Unexpected Lack of Data or unexpected Answer while checking the priority of the ciphers \'$str\' -> Exit loop. Reason: '$my_error'");
                    _hint("The server may have an IPS in place. To slow down the test, consider adding the option '--connect-delay=SEC'.");
                    $my_error = ""; # reset error message
                    last;
                } else { #any other Error like: #} elsif ( ( $my_error =~ /\-> Received NO Data/) || ($my_error =~ /answer ignored/) || ($my_error =~ /protocol_version.*?not supported/) || ($my_error =~ /check.*?aborted/) ) {
                    _trace1 (" checkSSLciphers (6.3): => Received no cipher while checking the priority of the ciphers \'$str\' -> Exit loop. Reason: ''\n");
                    carp("$STR{WARN} checkSSLciphers (6.3): => Received no cipher while checking the priority of the ciphers \'$str\' -> Exit loop. Reason: '$my_error'");
                    _hint("The server may have an IPS in place. To slow down the test, consider adding the option '--connect-delay=SEC'.");
                    $my_error = ""; # reset error message
                    last;
                }
            }
        } # end while-Loop
    ###      _trace4 ("#   Accepted (sorted) Ciphers [cipher1 = cipher 2 => sorted by Server]:\n");
    ### TBD: _trace4: print all ciphers?!!

        ### Ckeck all Extension Parameters for extensions that have been previously flagged to get more than one answer, eg. supported_groups
        # my $_first = 0;
        # $_first = 1 if ( ((@acceptedCipherSortedArray) > 1) && ($acceptedCipherSortedArray[0] eq $acceptedCipherSortedArray[1]) ); # jump over the first cipher if equal to the second (sorted list)
        # foreach my $_i ($_first .. (@acceptedCipherSortedArray)) {
        #     _doCheckAllExtensions ($host, $port, $protocol, $acceptedCipherSortedArray[$_i], $dtlsEpoch, 1); # if server uses a priority List we get the same cipher again!$
        # }

        _trace("checkSSLciphers() }\n");
        return (compileTLSCipherArray (join ("",@acceptedCipherSortedArray)));
    }
} # checkSSLciphers

sub getSSLciphersWithParam {
    #? get ciphers with paramters using checkSSLciphers()
    #? parameters are the same as for checkSSLciphers()
    #? returns numerical hash, each entry with array [ciphers, parameters]
    #? entry {0} is the array returned by checkSSLciphers()
    # FIXME: <<POD missing>>
    my($host, $port, $ssl, @cipher_str_array) = @_;
    my %ciphers;
    my $_i = 0;
    my $lastkey   = "";
    _trace("getSSLciphersWithParam($host, $port, $ssl, ...) {\n");
    @{$ciphers{0}} = checkSSLciphers($host, $port, $ssl, @cipher_str_array);
    foreach my $key (@{$ciphers{0}}) {
        next if ($lastkey eq $key); # should happen only once
        $lastkey  = $key;
        $_i++;
        $ciphers{$_i} = [ $key, getCipherParameter($key, "", " | ") ];
    }
    _trace("getSSLciphersWithParam()\t= %ciphers }\n");
    return %ciphers
} # getSSLciphersWithParam

sub openTcpSSLconnection ($$) {
    #? open a TCP connection to a server and port and send STARTTLS if requested
    #? this SSL connection could be made via a http proxy
    my $host            = shift || ""; # hostname
    my $port            = shift || "";
    my $socket;
    my $connect2ip;
    my $alarmTimeout    = $SSLhello::timeout +1; # 1 sec more than normal timeout as a time line of second protection
    my $proxyConnect    = "";
    my $clientHello     = "";
    my $input           = "";
    my $input2          = "";
    my $retryCnt        = 0;
    my $sleepSecs       = $SSLhello::starttlsDelay   || 0;
    my $slowServerDelay = $SSLhello::slowServerDelay || 0;
    my $suspendSecs     = 0;
    my $firstMessage    = "";
    my $secondMessage   = "";
    my $starttlsType=0; # SMTP
#   15 Types defined: 0:SMTP, 1:SMTP_2, 2:IMAP, 3:IMAP_CAPACITY, 4:IMAP_2, 5:POP3, 6:POP3_CAPACITY, 7:FTPS, 8:LDAP, 9:RDP, 10:RDP_SSL, 11:XMPP, 12:ACAP, 13:IRC, 14:IRC_CAPACITY
#
#   ##TBD new subs openTcpSSLconnectionViaProxy, openTcpSSLconnectionUsingStarttls
#
    _trace2("openTcpSSLconnection($host, $port) {\n");

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
            "",                                         # Phase2: send    -unused-
            "",                                         # Phase3: receive -unused-
            "STLS\r\n",                                 # Phase4: send    'STLS' (-> STARTTLS)'
            ".*?(?:^|\\n)\\+\\s*OK",                    # Phase5: receive '+OK Begin TLS'
            "",                                         # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: This SSL/TLS-Protocol is not supported
            ".*?(?:^|\\n)\\-\\s*ERR.*?(?:invalid command|TLS.*?(?:isn\\'t|not)|\\s+no\\s+.*?(?:SSL|TLS)|authoriz)", # Error3: fatal Error/STARTTLS not supported: '-ERR TLS support isn't enabled'
          ],
          ["POP3_CAPACITY",                             # according RFC2595; found good hints at 'https://github.com/iSECPartners/sslyze/blob/master/utils/SSLyzeSSLConnection.py'
            ".*?(?:^|\\n)\\+\\s*OK(?:\\s+|.*?ready|\\r|\\n)",   # Phase1: receive '+ OK...ready.'
            "CAPA\r\n",                                 # Phase2: send view CAPABILITY (optional)
            ".*?(?:^|\\n)\\+\\s*OK",                    # Phase3: receive List of should include STLS
            "STLS\r\n",                                 # Phase4: send    'STLS' (-> STARTTLS)'
            ".*?(?:^|\\n)\\+\\s*OK",                    # Phase5: receive '+OK Begin TLS'
            "",                                         # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: This SSL/TLS-Protocol is not supported
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
          ], #  Typical ErrorMsg if STARTTLS is *not* supported:  ---> SSLhello ::openTcpSSLconnection: ## STARTTLS (Phase 5): ... Received STARTTLS answer: 19 bytes
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
            "",                                         # Phase1: receive -unused-$
            "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'".
             " to='".$host."' xml:lang='en' version='1.0'>",        # Phase2: send  Client initiates stream to server (no from to try to avoid to get blocked due to too much connects!)
##             " from='osaft\@im.owasp.org' to='".$host."' xml:lang='en' version='1.0'>", # Phase2: send  Client initiates stream to server
###          " xmlns:tls='http://www.ietf.org/rfc/rfc2595.txt' to='".$host."' xml:lang='en' version='1.0'>", # Phase2: send  Client initiates stream to server
            "<stream:stream.*?>",                       # Phase3: receive response steam header
            "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",  # Phase4: send    'STARTTLS'$
            "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",   # Phase5: receive 'Start TLS request accepted.'
                                                        # Errors: text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>You exceeded the number of connections/logins allowed in 60 seconds, good bye.</text>
            "",                                         # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: This SSL/TLS-Protocol is not supported
            "",                                         # Error3: fatal Error/STARTTLS not supported
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
          ["IRC",                                       # according https://github.com/ircv3/ircv3-specifications/blob/master/extensions/tls-3.1 and
                                                        #           https://gist.github.com/grawity/f661adc10fb2d7a580ea
            ".*?NOTICE.*?",                             # Phase1: receive ':<Server> NOTICE AUTH :*** No ident response; username prefixed with ~'
            "",                                         # Phase2: send    -unused-
            "",                                         # Phase2: receive -unused-
            "STARTTLS\r\n",                             # Phase4: send    'STARTTLS'
            ".*?(?:^|\n)\\:.*?\\s670\\s+\\:STARTTLS\\s",# Phase5: receive ':<Server> 670  :STARTTLS successful, go ahead with TLS handshake'
            ".*?(?:^|\n)ERROR\\s.*?too.*?(?:fast|much|many)",   # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: this SSL/TLS-Protocol is not supported
            ".*?(?:^|\\n)421\\s",                       # Error3: fatal Error/STARTTLS not supported: '421 ERR_UNKNOWNCOMMAND "<command> :Unknown command"'
          ],
          ["IRC_CAPACITY",                              # according https://github.com/ircv3/ircv3-specifications/blob/master/extensions/tls-3.1 and
                                                        #           https://gist.github.com/grawity/f661adc10fb2d7a580ea
            ".*?NOTICE.*?",                             # Phase1: receive ':<Server> NOTICE AUTH :*** No ident response; username prefixed with ~'
            "CAP LS\r\n",                               # Phase2: send    view CAPABILITY (optional)
            ".*?(?:^|\n)\\:.*?\\sCAP\\s.*?\\:.*tls(?:\\s|$|\r\n)",    # Phase3: receive :<Server> CAP * LS :account-notify away-notify multi-prefix tls us     erhost-in-names
            "STARTTLS\r\n",                             # Phase4: send    'STARTTLS'
            ".*?(?:^|\n)\\:.*?\\s670\\s+\\:STARTTLS\\s",# Phase5: receive ':<Server> 670  :STARTTLS successful, go ahead with TLS handshake'
            ".*?(?:^|\n)ERROR\\s.*?too.*?(?:fast|much|many)",   # Error1: temporary unreachable (too many connections);
            "",                                         # Error2: this SSL/TLS-Protocol is not supported
            ".*?(?:^|\\n)421\\s",                       # Error3: fatal Error/STARTTLS not supported: '421 ERR_UNKNOWNCOMMAND "<command> :Unknown command"'
          ],
          ["CUSTOM",                                    # CUSTOMise your own starttls sequence with up to 5 phases
            "",                                         # Phase1: receive <placeholder|-unused->
            "",                                         # Phase2: send    <placeholder|-unused->
            "",                                         # Phase2: receive <placeholder|-unused->
            "",                                         # Phase4: send    <placeholder|-unused-> STARTTLS'
            "",                                         # Phase5: receive <placeholder|-unused-> OK (Begin TLS Negotiation)'
            "",                                         # Error1: temporary unreachable (too many connections): <placeholder|-unused->
            "",                                         # Error2: this SSL/TLS-Protocol is not supported: <placeholder|-unused->
            "",                                         # Error3: fatal Error/STARTTLS not supported: <placeholder|-unused->
          ],
        );

    my %startTlsTypeHash;
    local $my_error = ""; # reset error message
    error_handler->reset_err( {module => ($SSLHELLO), sub => 'openTcpSSLconnection', print => ($SSLhello::trace > 3), trace => $SSLhello::trace} );
    if ( ($SSLhello::proxyhost) && ($SSLhello::proxyport) ) { # via proxy
        _trace2 (" openTcpSSLconnection: Try to connect and open a SSL connection to $host:$port via proxy ".$SSLhello::proxyhost.":".$SSLhello::proxyport."\n");
    } else {
        _trace2 (" openTcpSSLconnection: Try to connect and open a SSL connection to $host:$port\n");
    }
    $retryCnt = 0;
    if ($SSLhello::starttls)  {                    # starttls -> find STARTTLS type
        $startTlsTypeHash{$starttls_matrix[$_][0]} = $_ for 0 .. scalar(@starttls_matrix) - 1;
        _trace4 (" openTcpSSLconnection: nr of Elements in starttlsTypeMatrix: ".scalar(@starttls_matrix)."; looking for starttlsType $SSLhello::starttlsType\n");

        if (defined($startTlsTypeHash{uc($SSLhello::starttlsType)})) {
            $starttlsType = $startTlsTypeHash{uc($SSLhello::starttlsType)};
            _trace4 (" openTcpSSLconnection: Index-Nr of StarttlsType $SSLhello::starttlsType is $starttlsType\n");
            if ( grep {/^$starttlsType$/x} ('12', '13', '14','15') ) { # ('12', '13', ...) -> Use of an experimental STARTTLS type
                if  ($SSLhello::experimental >0) {         # experimental function is are  activated
                    _trace_("\n");
                    _trace (" openTcpSSLconnection: WARNING: use of STARTTLS type $starttls_matrix[$starttlsType][0] is experimental! Send us feedback to o-saft (at) lists.owasp.org, please\n");
                } else {                                        # use of experimental functions is not permitted (option is not activated)
                    if ( grep {/^$starttlsType$/x} ('12', '13', '14', '15') ) { # experimental and untested
                        error_handler->new( {
                            type    => $OERR{'SSLHELLO_ABORT_PROGRAM'},
                            id      => 'ckeck starttls type (1)',
                            message => "WARNING: use of STARTTLS type $starttls_matrix[$starttlsType][0] is experimental and *untested*!! Please take care! Please add option '--experimental' to use it. Please send us your feedback to o-saft (at) lists.owasp.org",
                            warn    => 1,
                        } );
                    } else {                                    # tested, but still experimental # experimental but tested
                        error_handler->new( {
                            type    => $OERR{'SSLHELLO_ABORT_PROGRAM'},
                            id      => 'ckeck starttls type (2)',
                            message => "WARNING: use of STARTTLS type $starttls_matrix[$starttlsType][0] is experimental! Please add option '--experimental' to use it. Please send us your feedback to o-saft (at) lists.owasp.org",
                            warn    => 1,
                        } );
                    }
                    exit (1);                                   # stop program
                }
            }
            if ($starttls_matrix[$starttlsType][0] eq 'CUSTOM') { # customise the starttls_matrix
                for my $i (1..8) {
                    if (defined($SSLhello::starttlsPhaseArray[$i])) {
                        _trace4 (" openTcpSSLconnection: Customise starttls_matrix: \$SSLhello::starttlsPhaseArray[$i]= >$SSLhello::starttlsPhaseArray[$i]< = hex: >".unpack("H*",$SSLhello::starttlsPhaseArray[$i])."<\n");
                        if (($i == 2) || ($i == 4)) { #TX Data needs a different handling
                            $starttls_matrix[$starttlsType][$i] = "$SSLhello::starttlsPhaseArray[$i]";
                            #($starttls_matrix[$starttlsType][$i]) =~ s/(\[^xc]|\c.)/chr(ord('$1'))/eg; ## escape2hex does not work
                            ($starttls_matrix[$starttlsType][$i]) =~ s/\\r/chr(13)/egx; ## return character
                            ($starttls_matrix[$starttlsType][$i]) =~ s/\\n/chr(10)/egx; ## new line character
                            ($starttls_matrix[$starttlsType][$i]) =~ s/\\t/chr(9)/egx;  ## tab character
                            ($starttls_matrix[$starttlsType][$i]) =~ s/\\e/chr(27)/egx; ## 'esc' character
                            ($starttls_matrix[$starttlsType][$i]) =~ s/\\x([a-fA-F0-9]{2})/chr(hex $1)/egx; ## Str2hex
                            ($starttls_matrix[$starttlsType][$i]) =~ s/\\\\/\\/gx;      ## escaping the escape character
                        } else { # normal copy
                            $starttls_matrix[$starttlsType][$i] = $SSLhello::starttlsPhaseArray[$i];
                        }
                        _trace2 (" openTcpSSLconnection: Customise \$starttls_matrix[$starttlsType][$i]= >$starttls_matrix[$starttlsType][$i]< = hex: >".unpack("H*",$starttls_matrix[$starttlsType][$i])."<\n");
                    }
                }
            }
        } else {
            $starttlsType=0;
            carp("$STR{WARN} openTcpSSLconnection: Undefined StarttlsType, use $starttls_matrix[$starttlsType][0] instead");
        }
    }

    RETRY_TO_OPEN_SSL_CONNECTION: { do { # connect to #server:port (via proxy) and open a ssl connection (use STARTTLS if activated)
        error_handler->reset_err( {module => ($SSLHELLO), sub => 'openTcpSSLconnection', print => ($SSLhello::trace > 3), trace => $SSLhello::trace} );
        if ( defined($SSLhello::connect_delay) && ($SSLhello::connect_delay > 0) ) {
            _trace_ ("\n");
            _trace  (" openTcpSSLconnection: connect delay $cfg{'connect_delay'} second(s)\n");
            sleep($SSLhello::connect_delay);
            _trace4 (" openTcpSSLconnection: connect delay $cfg{'connect_delay'} second(s) [End]\n");
        }
        alarm (0); # switch off alarm (e.g. for  next retry )
        if ($retryCnt >0) { # retry
            _trace1_ ("\n") if (($retryCnt == 1) && ($SSLhello::trace < 3)); # to catch up '\n' if 1st retry and trace-level is 2 (1 < trace-level < 3)
            if ( ($SSLhello::proxyhost) && ($SSLhello::proxyport) ) { # via proxy
                _trace1 (" openTcpSSLconnection: $retryCnt. Retry to connect and open a SSL connection to $host:$port via proxy ".$SSLhello::proxyhost.":".$SSLhello::proxyport);
                if ($retryCnt > $SSLhello::retry) {
                    _trace1_ (" (this is an additional retry after suspension)");
                }
                _trace1_ ("\n");
            } else {
                _trace1 (" openTcpSSLconnection: $retryCnt. Retry to connect and open a SSL connection to $host:$port\n");
            }
        }
        if ($SSLhello::starttls) {
            _trace (" openTcpSSLconnection: $host:$port: wait $sleepSecs sec(s) to prevent too many connects\n") if ( ($SSLhello::trace >2) || ($sleepSecs > 0) );
            sleep ($sleepSecs);
        }

        { # >> start a block
            local $@ = "";
            eval {
                local $SIG{ALRM}= "SSLhello::_timedOut";
                alarm($alarmTimeout);                       # set Alarm for get-socket and set-socketoptions->timeout(s)
                my ($_dummy1, $_dummy2, $_protocol) = getprotobyname('tcp'); # is failsafer than '(getprotobyname('tcp'))[2]'
                if (! $_protocol) {
                    $_protocol = Socket::IPPROTO_TCP;
                }
                socket($socket, Socket::PF_INET, Socket::SOCK_STREAM, $_protocol) or croak("Can't create a socket \'$!\' -> target $host:$port ignored ");
                setsockopt($socket, Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, pack('L!L!', $SSLhello::timeout, 0) ) or croak("Can't set socket Sent-Timeout \'$!\' -> target $host:$port ignored"); #L!L! => compatible to 32 and 64-bit
                setsockopt($socket, Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, pack('L!L!', $SSLhello::timeout, 0) ) or croak("Can't set socket Receive-Timeout \'$!\' -> target $host:$port ignored");
                alarm (0);      # clear alarm
            } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {  # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                $my_error = $@;                             # save the error message as soon as possible
                alarm (0);                                  # clear alarm if not done before
                error_handler->new( {
                    type    => $OERR{'SSLHELLO_RETRY_HOST'},
                    id      => 'socket (1)',
                    message => $my_error,
                    warn    => 0,
                } );
                next RETRY_TO_OPEN_SSL_CONNECTION;          # error -> next retry
            }};                                             # end of the section 'or do { if () { ...'. Do NOT forget the;
            alarm (0);                                      # clear alarm if not done before
        } # << end a block

        ######## Connection via a proxy ########
        if ( ($SSLhello::proxyhost) && ($SSLhello::proxyport) ) { # via proxy
            GET_PROXY_IP: { # >> start a block
                $my_error = "";
                $connect2ip = Socket::inet_aton($SSLhello::proxyhost);
                if (!defined ($connect2ip) ) {                      # no IP address
                    $my_error = "$STR{WARN} Can't get the IP address of the proxy $SSLhello::proxyhost:$SSLhello::proxyport -> target $host:$port ignored";
                    carp($my_error);
                    error_handler->new( {
                        type    => $OERR{'SSLHELLO_ABORT_HOST'},
                        id      => 'get proxy IP',
                        message => $my_error,
                        warn    => 0,
                    } );
                    last RETRY_TO_OPEN_SSL_CONNECTION;      # retry
                }
            } # << end a block

            { # >> start a block
                $my_error = "";
                local $@ = "";
                eval {
                    local $SIG{ALRM}= "SSLhello::_timedOut";
                    alarm($alarmTimeout); # set Alarm for Connect
                    connect($socket, Socket::pack_sockaddr_in($SSLhello::proxyport, $connect2ip) ) or croak("Can't make a connection to proxy $SSLhello::proxyhost:$SSLhello::proxyport -> target $host:$port ignored");
                    # TBD will be: TBD
                    # $sock = new IO::Socket::INET(
                    #   Proto     => "tcp",
                    #   PeerAddr => "$SSLhello::proxyhost:$SSLhello::proxyport",
                    #   Blocking  => 1, # Default
                    #   Timeout => $timeout,
                    # ) or die "Can't make a connection to proxy $SSLhello::proxyhost:$SSLhello::proxyport ($@, $!) -> target $host:$port ignored"; # error handling
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) { # end of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = $@;                         # save the error message as soon as possible
                    alarm (0);                              # clear alarm if not done before
                    error_handler->new( {
                        type    => $OERR{'SSLHELLO_RETRY_HOST'},
                        id      => 'connection via proxy (1)',
                        message => $my_error,
                        warn    => 0,
                    } );
                    close ($socket) or carp("$STR{WARN} ". error_handler->get_err_str() ."; Can't close socket, too: $!"); #tbd löschen ###
                    #_trace2 (" openTcpSSLconnection: $@ -> Fatal Exit in openTcpSSLconnection");
                    sleep (1);
                    # last; # no retry
                    next RETRY_TO_OPEN_SSL_CONNECTION;      # next retry
                }};                                         # end of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                  # clear alarm if not done before
            } # << end a block

            { # >> start a block
                $my_error = "";
                local $@ = "";
                eval {
                    $proxyConnect=$CST{'_PROXY_CONNECT_MESSAGE1'}.$host.":".$port.$CST{'_PROXY_CONNECT_MESSAGE2'};
                    _trace4 (" openTcpSSLconnection: ## ProxyConnect-Message: >$proxyConnect<\n");
                    local $SIG{ALRM}= "SSLhello::_timedOut";
                    alarm($alarmTimeout); # set Alarm for Connect
                    defined(send($socket, $proxyConnect, 0)) || croak("Can't make a connection to $host:$port via proxy $SSLhello::proxyhost:$SSLhello::proxyport [".Socket::inet_ntoa($connect2ip).":$SSLhello::proxyport] -> target $host:$port ignored");
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) { # end of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = $@;                         # save the error message as soon as possible
                    alarm (0);                              # clear alarm if not done before
                    error_handler->new( {
                        type    => $OERR{'SSLHELLO_RETRY_HOST'},
                        id      => 'connection via proxy (2)',
                        message => $my_error,
                        warn    => 0,
                    } );
                    close ($socket) or carp("$STR{WARN} ". error_handler->get_err_str() ."; Can't close socket, too: $!");
                    if (defined($slowServerDelay) && ($slowServerDelay>0)) {
                        _trace2 (" openTcpSSLconnection: via proxy $host:$port: wait $slowServerDelay sec(s) to wait for slow proxies\n");
                        sleep ($slowServerDelay);
                    }
                    next RETRY_TO_OPEN_SSL_CONNECTION;      # retry
                }};                                         # end of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                  # clear alarm if not done before
            } # << end a block

            { # start a block
                $my_error = "";
                local $@ = "";
                # CONNECT via proxy
                eval {
                    $input = "";
                    _trace2 (" openTcpSSLconnection ## CONNECT via proxy: try to receive the Connected-Message from the proxy $SSLhello::proxyhost:$SSLhello::proxyport, Retry = $retryCnt\n");
                    # select(undef, undef, undef, $CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 0); # if retry: sleep some ms
                    OCfg::ocfg_sleep($CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 0); # if retry: sleep some ms
                    local $SIG{ALRM}= "SSLhello::_timedOut";
                    alarm($alarmTimeout);
                    recv ($socket, $input, 32767, 0);
                    if (length ($input)==0) { # did not receive a Message
                        _trace4 (" openTcpSSLconnection: ... Received Connected-Message from proxy (1a): received NO Data\n");
                        sleep(1) if ($retryCnt > 0);
                        # Sleep for 250 milliseconds
                        OCfg::ocfg_sleep($CST{'_SLEEP_B4_2ND_READ'});
                        # select(undef, undef, undef, $CST{'_SLEEP_B4_2ND_READ'});
                        recv ($socket, $input, 32767, 0); # 2nd try
                        #### TBD TBD received NO Data TBD TBD ###
                    }
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) { # end of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = $@;                         # save the error message as soon as possible
                    alarm (0);                              # clear alarm if not done before
                    error_handler->new( {
                        type    => $OERR{'SSLHELLO_RETRY_HOST'},
                        id      => 'connection via proxy (3)',
                        message => $my_error,
                        warn    => 0,
                    } );
                    close ($socket) or carp("$STR{WARN} ". error_handler->get_err_str() ."; Can't close socket, too: $!");
                    if (defined($slowServerDelay) && ($slowServerDelay>0)) {
                        _trace2 (" openTcpSSLconnection: via proxy $host:$port: wait $slowServerDelay sec(s) to wait for slow proxies\n");
                        sleep ($slowServerDelay);
                    }
                    next RETRY_TO_OPEN_SSL_CONNECTION;      # retry
                }};                                         # end of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                  # clear alarm if not done before
            } # << end a block

            if (length ($input) >0) { # got data
                _trace3 (" openTcpSSLconnection: ... Received data via proxy: ".length($input)." bytes\n          >".substr(_chomp_r($input),0,64)."< ...\n");
                _trace4 (" openTcpSSLconnection: ... Received data via proxy: ".length($input)." bytes\n          >"._chomp_r($input)."<\n");
                if ($input =~ /(?:^|\s)200\s/x) { # HTTP/1.0 200 Connection established\r\nProxy-agent: ... \r\n\r\n
                    $my_error = ""; # connection established
                    _trace2 (" openTcpSSLconnection: Connection established to $host:$port via proxy ".$SSLhello::proxyhost.":".$SSLhello::proxyport."\n");
                } else {
                    if ($SSLhello::trace == 0) { # no trace => shorten the output
                        $input =~ /^((?:.+?(?:\r?\n|$)){1,4})/x; # maximal 4 lines
                        $input = _chomp_r($1); ## no critic qw(RegularExpressions::ProhibitCaptureWithoutTest)
                    }
                    error_handler->new( {
                        type    => $OERR{'SSLHELLO_RETRY_HOST'},
                        id      => 'connection via proxy (4)',
                        message => "Can't make a connection to $host:$port via proxy $SSLhello::proxyhost:$SSLhello::proxyport; target ignored. Proxy error: ".$input, # error message received from the proxy
                        warn    => 0,
                    } );
                    close ($socket) or carp("$STR{WARN} ". error_handler->get_err_str() ."; Can't close socket, too: $!");
                    if (defined($slowServerDelay) && ($slowServerDelay>0)) {
                        _trace2 (" openTcpSSLconnection: via proxy $host:$port: wait $slowServerDelay sec(s) to wait for slow proxies\n");
                        sleep ($slowServerDelay);
                    }
                    next RETRY_TO_OPEN_SSL_CONNECTION;
                }
            }
        } else { #### no proxy ####
            { # >> start a block
                $my_error = "";
                $connect2ip = Socket::inet_aton($host);
                if (!defined ($connect2ip) ) {                      # no IP address
                    $my_error = "$STR{WARN} Can't get the IP address of $host -> target $host:$port ignored in openTcpSSLconnection";
                    carp($my_error);
                    error_handler->new( {
                        type    => $OERR{'SSLHELLO_ABORT_HOST'},
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
                    local $SIG{ALRM}= "SSLhello::_timedOut";
                    alarm($alarmTimeout);                           # set alarm for connect
                    connect( $socket, Socket::pack_sockaddr_in($port, $connect2ip) ) or croak("Can't make a connection to $host:$port [".Socket::inet_ntoa($connect2ip).":$port]; -> target ignored ");
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = $@;                                 # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    if (defined ($connect2ip) ) {
                        $my_error .= " -> No connection to $host:$port [".Socket::inet_ntoa($connect2ip).":$port]; -> target ignored in openTcpSSLconnection";
                    } else {
                        $my_error .= " -> No connection to $host:$port; -> target ignored in openTcpSSLconnection";
                    }
                    error_handler->new( {
                        type    => $OERR{'SSLHELLO_RETRY_HOST'},
                        id      => 'connect (1)',
                        message => $my_error,
                        warn    => 0,
                    } );
                    close ($socket) or carp("$STR{WARN} ". error_handler->get_err_str() ."; Can't close socket, too: $!");
                    next RETRY_TO_OPEN_SSL_CONNECTION;      # retry
                }};                                         # end of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                  # clear alarm if not done before
                _trace2 (" openTcpSSLconnection: Connected to server $host:$port\n");
            } # << end a block
        }

        if ( !(error_handler->is_err) && ($SSLhello::starttls) )  { # no error and starttls ###############  Begin STARTTLS Support #############
            _trace2 (" openTcpSSLconnection: try to STARTTLS using the ".$starttls_matrix[$starttlsType][0]." protocol for server $host:$port, Retry = $retryCnt\n");
            # select(undef, undef, undef, $CST{'_SLEEP_B4_2ND_READ'}) if ($sleepSecs > 0) || ($retryCnt > 0); # if slowed down or retry: sleep some ms
            if (($slowServerDelay > 0) || ($retryCnt > 0)) { # slow server or retry: sleep some secs
                _trace2 (" openTcpSSLconnection: $host:$port: wait ".($slowServerDelay||1)." sec(s) to cope with slow servers\n");
                sleep ($slowServerDelay||1); # sleep $slowServerDelay secs or min 1 sec
                #select(undef, undef, undef, $CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 1); # if retry: sleep some ms
            }
            ### STARTTLS_Phase1 (receive)
            if ($starttls_matrix[$starttlsType][1]) {
                local $@ = "";
                eval {
                    $input = "";
                    _trace2 (" openTcpSSLconnection: ## STARTTLS (Phase 1): try to receive the ".$starttls_matrix[$starttlsType][0]."-Ready-Message from the Server $host:$port\n");
                    #select(undef, undef, undef, $CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 0); # if retry: sleep some ms
                    OCfg::ocfg_sleep($CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 0); # if retry: sleep some ms
                    local $SIG{ALRM}= "SSLhello::_timedOut";
                    alarm($alarmTimeout);
                    recv ($socket, $input, 32767, 0); #|| die "openTcpSSLconnection: STARTTLS (Phase 1aa): Did *NOT* get any ".$starttls_matrix[$starttlsType][0]." Message from $host:$port\n"; # did not receive a Message ## unless seems to work better than if!!
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # end of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = "STARTTLS phase #1 failed): $@";    # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # error -> next retry
                }};                                                 # end of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # clear alarm if not done before
                if (length ($input) >0) { # received Data => 220 smtp.server.com Simple Mail Transfer Service Ready?
                    _trace2 (" openTcpSSLconnection: ## STARTTLS (Phase 1):  ... Received ".$starttls_matrix[$starttlsType][0]."-Message (1): ".length($input)." bytes: >"._chomp_r($input)."<\n");
                    if ($input =~ /$starttls_matrix[$starttlsType][1]/) { # e.g. SMTP: 220 smtp.server.com Simple Mail Transfer Service Ready
                        $my_error = "";    # server is ready
                    } else {
                        $input=_chomp_r($input);
                        if ( ($starttls_matrix[$starttlsType][6]) && ($input =~ /$starttls_matrix[$starttlsType][6]/) ) {
                            # did receive a temporary error message
                            if ($retryCnt > $SSLhello::retry) { # already an additional final retry -> restore last error message
                                $my_error = "STARTTLS (Phase 1): Error 1: too many requests: $host:$port \'$input\' -> suspend $suspendSecs second(s) and all subsequent packets will be slowed down by $sleepSecs second(s)";
                                last RETRY_TO_OPEN_SSL_CONNECTION;
                            }
                            $SSLhello::starttlsDelay = $sleepSecs; # adopt global variable 1 step later
                            $sleepSecs += $retryCnt + 2;
                            $suspendSecs= 60 * ($retryCnt +1);
                            $my_error = "STARTTLS (Phase 1): Error 1: too many requests: $host:$port \'$input\' -> suspend $suspendSecs second(s) and all subsequent packets will be slowed down by $sleepSecs second(s)";
                            _trace2  (" openTcpSSLconnection: $my_error\n");
                            carp("$STR{WARN} openTcpSSLconnection: ... $my_error"); #if ($retryCnt > 1); # warning if at least 2nd retry
                            close ($socket) or carp("$STR{WARN} STARTTLS: $my_error; Can't close socket, too: $!");
                            sleep($suspendSecs);
                            _trace4 (" openTcpSSLconnection: STARTTLS (Phase 1): End suspend\n");
                            if ($retryCnt == $SSLhello::retry) { # signal to do an additional retry
                                $retryCnt++;
                                _trace4 (" openTcpSSLconnection: STARTTLS (Phase 1): 1 additional final retry after too many requests => retry number $retryCnt represented by $retryCnt+1\n");
                                redo RETRY_TO_OPEN_SSL_CONNECTION;      # extra retry
                            }
                            next RETRY_TO_OPEN_SSL_CONNECTION;          # next retry
                        } elsif ( ($starttls_matrix[$starttlsType][7]) && ($input =~ /$starttls_matrix[$starttlsType][7]/) ) { # did receive a protocol error message
                            error_handler->new( {
                                type    => $OERR{'SSLHELLO_ABORT_PROTOCOL'},
                                id      => 'STARTTLS (Phase 1): Error 2',
                                message => "unsupported protocol: $host:$port \'$input\'",
                                warn    => 0,
                            } );
                            close ($socket) or carp("$STR{WARN} ". error_handler->get_err_str() ."; Can't close socket, too: $!");
                            last;
                        } elsif ( ($starttls_matrix[$starttlsType][8]) && ($input =~ /$starttls_matrix[$starttlsType][8]/) ) { # did receive a fatal error message
                            $my_error = "STARTTLS (Phase 1): Error 3: Fatal Error: $host:$port \'$input\' -> target $host:$port ignored";
                            _trace2  (" openTcpSSLconnection: $my_error\n");
                            close ($socket) or carp("$STR{WARN} STARTTLS: $my_error; Can't close socket, too: $!");
                            last RETRY_TO_OPEN_SSL_CONNECTION;
                        } else {
                            if ($SSLhello::trace == 0) {   # no trace => shorten the output
                                $input =~ s/^(.+?)(?:\r?\n|$)/$1/x; # maximal 1 line  of error message
                                # if (($startType == x) || () ....) { $input = hexString ($input) } #
                            }
                            $my_error = "STARTTLS (Phase 1): Did *NOT* get a ".$starttls_matrix[$starttlsType][0]." Server Ready Message from $host:$port; target ignored. Server-Error: >"._chomp_r($input)."<"; # error message received from the server
                            _trace2 (" openTcpSSLconnection: $my_error\n");
                            close ($socket) or carp("$STR{WARN} STARTTLS: $my_error; Can't close socket, too: $!");
                            next RETRY_TO_OPEN_SSL_CONNECTION;   # next retry
                        }
                    }
                } else {
                    $my_error = ("STARTTLS (Phase 1): Did *NOT* get any ".$starttls_matrix[$starttlsType][0]." message from $host:$port -> slow down and try to retry target.");
                    _trace (" openTcpSSLconnection: $my_error\n");
                    $SSLhello::starttlsDelay = $sleepSecs; # adopt global variable 1 step later
                    $sleepSecs += $retryCnt + 2;
                    close ($socket) or carp("$STR{WARN} openTcpSSLconnection: STARTTLS: $my_error; Can't close socket, too: $!");
                    next RETRY_TO_OPEN_SSL_CONNECTION;
                }
            } else {
                _trace2 (" openTcpSSLconnection: ## STARTTLS (Phase 1): Nothing to do for ".$starttls_matrix[$starttlsType][0]."\n");
            } # end-if $starttls_matrix[$starttlsType][1]

            ### STARTTLS_Phase2 (send) #####
            if ($starttls_matrix[$starttlsType][2]) {
                local $@ = "";
                eval {
                    _trace2 (" openTcpSSLconnection: ## STARTTLS (Phase 2): send $starttls_matrix[$starttlsType][0] Message: >"._chomp_r($starttls_matrix[$starttlsType][2])."<\n");
                    local $SIG{ALRM}= "SSLhello::_timedOut";
                    alarm($alarmTimeout); # set Alarm for Connect
                    defined(send($socket, $starttls_matrix[$starttlsType][2], 0)) || die  "Could *NOT* send $starttls_matrix[$starttlsType][0] message '$starttls_matrix[$starttlsType][2]' to $host:$port; target ignored\n";
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = "STARTTLS phase #2 failed): $@";    # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    _trace2 (" openTcpSSLconnection: $my_error\n");
                    close ($socket) or carp("$STR{WARN} openTcpSSLconnection: $my_error Can't close socket, too: $!");
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # next retry
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # clear alarm if not done before
                # wait before next read
                # select(undef, undef, undef, $CST{'_SLEEP_B4_2ND_READ'}) if ($sleepSecs > 0) || ($retryCnt > 0); # if slowed down or retry: sleep some ms
                OCfg::ocfg_sleep($CST{'_SLEEP_B4_2ND_READ'}) if ($sleepSecs > 0) || ($retryCnt > 0); # if slowed down or retry: sleep some ms
                # select(undef, undef, undef, $CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 1); # if retry: sleep some ms
                OCfg::ocfg_sleep($CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 1); # if retry: sleep some ms
            ### STARTTLS_Phase1 (receive)
            } else {
                _trace2 (" openTcpSSLconnection: ## STARTTLS (Phase 2): Nothing to do for ".$starttls_matrix[$starttlsType][0]."\n");
            } # end-if $starttls_matrix[$starttlsType][2]

            ### STARTTLS_Phase3: receive (SMTP) Hello Answer
            if ($starttls_matrix[$starttlsType][3]) {
                local $@ = "";
                eval {
                    $input = "";
                    _trace2 (" openTcpSSLconnection: ## STARTTLS (Phase 3): try to receive the $starttls_matrix[$starttlsType][0] Hello Answer from the Server $host:$port\n");
                    OCfg::ocfg_sleep($CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 0); # if retry: sleep some ms
                    # select(undef, undef, undef, $CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 0); # if retry: sleep some ms
                    local $SIG{ALRM}= "SSLhello::_timedOut";
                    alarm($alarmTimeout);
                    recv ($socket, $input, 32767, 0);
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # end of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = "STARTTLS phase #3 failed): $@";    # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # error -> next retry
                }};                                                 # end of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # clear alarm if not done before
                if (length ($input) >0) { # received Data => 250-smtp.server.com Hello o-saft.localhost?
                    _trace3 (" openTcpSSLconnection: ## STARTTLS (Phase 3): ... Received  $starttls_matrix[$starttlsType][0]-Hello: ".length($input)." bytes\n      >".substr(_chomp_r($input),0,64)." ...<\n");
                    _trace4 (" openTcpSSLconnection: ## STARTTLS (Phase 3):  ... Received  $starttls_matrix[$starttlsType][0]-Hello: ".length($input)." bytes\n      >"._chomp_r($input)."<\n");
                    if ($input =~ /$starttls_matrix[$starttlsType][3]/) { # e.g. SMTP: 250-smtp.server.com Hello o-saft.localhost
                        $my_error = "";                             # server is ready
                        _trace2 (" openTcpSSLconnection: ## STARTTLS (Phase 3): received a $starttls_matrix[$starttlsType][0] Hello Answer from the Server $host:$port: >"._chomp_r($input)."<\n");
                    } else {
                        $input=_chomp_r($input);
                        if ( ($starttls_matrix[$starttlsType][6]) && ($input =~ /$starttls_matrix[$starttlsType][6]/) ) { # did receive a temporary error message
                           if ($retryCnt > $SSLhello::retry) { # already an additional final retry -> restore last error message
                                $my_error = "STARTTLS (Phase 3): Error 1: too many requests: $host:$port \'$input\' -> too many retries ($retryCnt)";
                                last RETRY_TO_OPEN_SSL_CONNECTION;
                            }
                            $SSLhello::starttlsDelay = $sleepSecs; # adopt global variable 1 step later
                            $sleepSecs += $retryCnt + 2;
                            $suspendSecs= 60 * ($retryCnt +1);
                            $my_error = "STARTTLS (Phase 3): Error 1: too many requests: $host:$port \'$input\' -> suspend $suspendSecs second(s) and all subsequent packets will be slowed down by $sleepSecs second(s)";
                            _trace2  (" openTcpSSLconnection: $my_error\n");
                            carp("$STR{WARN} openTcpSSLconnection: ... $my_error"); # if ($retryCnt > 1); # warning if at least 2nd retry
                            close ($socket) or carp("$STR{WARN} STARTTLS: $my_error; Can't close socket, too: $!");
                            sleep($suspendSecs);
                            _trace4 (" openTcpSSLconnection: STARTTLS (Phase 3): End suspend\n");
                            if ($retryCnt == $SSLhello::retry) { # signal to do an additional retry
                                $retryCnt++;
                                _trace4 (" openTcpSSLconnection: STARTTLS (Phase 3): 1 additional final retry after too many requests => retry number $retryCnt represented by $retryCnt+1\n");
                            }
                            next RETRY_TO_OPEN_SSL_CONNECTION;
                        } elsif ( ($starttls_matrix[$starttlsType][7]) && ($input =~ /$starttls_matrix[$starttlsType][7]/) ) {
                            # did receive a protocol error message
                            error_handler->new( {
                                type    => $OERR{'SSLHELLO_ABORT_PROTOCOL'},
                                id      => 'STARTTLS (Phase 3): Error 2',
                                message => "unsupported protocol: $host:$port \'$input\'",
                                warn    => 0,
                            } );
                            close ($socket) or carp("$STR{WARN} ". error_handler->get_err_str() ."; Can't close socket, too: $!");
                            last RETRY_TO_OPEN_SSL_CONNECTION;
                        } elsif ( ($starttls_matrix[$starttlsType][8]) && ($input =~ /$starttls_matrix[$starttlsType][8]/) ) { # did receive a fatal error message
                            $my_error = "STARTTLS (Phase 3): Error 3: Fatal Error: $host:$port \'$input\' -> target $host:$port ignored";
                            _trace2  (" openTcpSSLconnection: $my_error\n");
                            close ($socket) or carp("$STR{WARN} STARTTLS: $my_error; Can't close socket, too: $!");
                            last RETRY_TO_OPEN_SSL_CONNECTION;
                        } else {
                            if ($SSLhello::trace == 0) {       # no trace => shorten the output
                                $input =~ s/^(.+?)(?:\r?\n|$)/$1/x; # maximal 1 line of error message
                                # if (($startType == x) || () ....) { $input = hexString ($input) } #
                            }
                            $my_error = "STARTTLS (Phase 3): Did *NOT* get a $starttls_matrix[$starttlsType][0] Server Hello Answer from $host:$port; target ignored. Server-Error: >"._chomp_r($input)."<"; # error message received from the SMTP-Server
                            _trace2 (" openTcpSSLconnection: $my_error; try to retry\n");
                            close ($socket) or carp("$STR{WARN} STARTTLS: $my_error; Can't close socket, too: $!");
                            next RETRY_TO_OPEN_SSL_CONNECTION;
                        }
                    }
                } else { # did receive a message with length = 0 ?!
                    $my_error = ("STARTTLS (Phase 3): Did *NOT* get any answer to".$starttls_matrix[$starttlsType][0]." client message from $host:$port -> slow down and try to retry target.");
                    _trace (" openTcpSSLconnection: $my_error\n");
                    $SSLhello::starttlsDelay = $sleepSecs; # adopt global variable 1 step later
                    $sleepSecs += $retryCnt + 2;
                     close ($socket) or carp("$STR{WARN} STARTTLS: $my_error; Can't close socket, too: $!");
                     next RETRY_TO_OPEN_SSL_CONNECTION; # next retry
                }
            } else {
                _trace2 (" openTcpSSLconnection: ## STARTTLS (Phase 3): Nothing to do for ".$starttls_matrix[$starttlsType][0]."\n");
            } # end-if $starttls_matrix[$starttlsType][3]

            #### STARTTLS_Phase4: Do STARTTLS
            if ($starttls_matrix[$starttlsType][4]) {
                local $@ = "";
                eval {
                    _trace2 (" openTcpSSLconnection: ## STARTTLS (Phase 4): $starttls_matrix[$starttlsType][0] Do STARTTLS message: >"._chomp_r($starttls_matrix[$starttlsType][4])."<\n");
                    local $SIG{ALRM}= "SSLhello::_timedOut";
                    alarm($SSLhello::timeout); # set Alarm for Connect
                    defined(send($socket, $starttls_matrix[$starttlsType][4], 0)) || die "Could *NOT* send a STARTTLS message to $host:$port; target ignored\n";
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = "STARTTLS phase #4 failed): $@";    # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    _trace2 (" openTcpSSLconnection: $my_error\n");
                    close ($socket) or carp("$STR{WARN} openTcpSSLconnection: ## $my_error Can't close socket, too: $!");
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # next retry
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the;
                # wait before next read
                OCfg::ocfg_sleep($CST{'_SLEEP_B4_2ND_READ'}) if ($sleepSecs > 0) || ($retryCnt > 0); # if slowed down or retry: sleep some ms
                # select(undef, undef, undef, $CST{'_SLEEP_B4_2ND_READ'}) if ($sleepSecs > 0) || ($retryCnt > 0); # if slowed down or retry: sleep some ms
                OCfg::ocfg_sleep($CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 1); # if retry: sleep some ms
                # select(undef, undef, undef, $CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 1); # if retry: sleep some ms
             } else {
                _trace2 (" openTcpSSLconnection: ## STARTTLS (Phase 4): Nothing to do for ".$starttls_matrix[$starttlsType][0]."\n");
             } # endi-if $starttls_matrix[$starttlsType][4]

            #### STARTTLS_Phase 5: receive STARTTLS answer
            if ($starttls_matrix[$starttlsType][5]) {
                local $@ = "";
                eval {
                    $input = "";
                    _trace2 (" openTcpSSLconnection: ## STARTTLS (Phase 5): Try to receive the $starttls_matrix[$starttlsType][0] STARTTLS answer from the server $host:$port\n");
                    OCfg::ocfg_sleep($CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 0); # if retry: sleep some ms
                    # select(undef, undef, undef, $CST{'_SLEEP_B4_2ND_READ'}) if ($retryCnt > 0); # if retry: sleep some ms
                    local $SIG{ALRM}= "SSLhello::_timedOut";
                    alarm($alarmTimeout);
                    recv ($socket, $input, 32767, 0);
                    alarm (0);
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # end of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_error = "STARTTLS phase #5 failed): $@";    # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    next RETRY_TO_OPEN_SSL_CONNECTION;              # error -> next retry
                }};                                                 # end of the section 'or do { if () { ...'. Do NOT forget the;
                alarm (0);                                          # clear alarm if not done before
                if (length ($input) >0)  { # received Data => 220
                    _trace3 (" openTcpSSLconnection: ## STARTTLS (Phase 5): ... Received STARTTLS-Answer: ".length($input)." bytes\n      >".substr(_chomp_r($input),0,64)." ...<\n");
                    _trace4 (" openTcpSSLconnection: ## STARTTLS (Phase 5): ... Received STARTTLS-Answer: ".length($input)." bytes\n      >"._chomp_r($input)."<\n");
                    if ($input =~ /$starttls_matrix[$starttlsType][5]/) { # e.g. SMTP: 220
                        $my_error = "";     # server is ready to do SSL/TLS
                        _trace2 (" openTcpSSLconnection: ## STARTTLS: Server is ready to do SSL/TLS\n");
                    } else {
                        $input=_chomp_r($input);
                        if ( ($starttls_matrix[$starttlsType][6]) && ($input =~ /$starttls_matrix[$starttlsType][6]/) ) { # did receive a temporary error message
                            if ($retryCnt > $SSLhello::retry) { # already an additional final retry -> restore last error message
                                $my_error = "STARTTLS (Phase 5): Error 1: Too many requests: $host:$port \'$input\' -> suspend $suspendSecs second(s) and all subsequent packets will be slowed down by $sleepSecs second(s)";
                                last RETRY_TO_OPEN_SSL_CONNECTION;
                            }
                            $SSLhello::starttlsDelay = $sleepSecs; # adopt global Variable 1 step later
                            $sleepSecs += $retryCnt + 2;
                            $suspendSecs = 60 * ($retryCnt +1);
                            $my_error = "STARTTLS (Phase 5): Error 1: Too many requests: $host:$port \'$input\' -> suspend $suspendSecs second(s) and all subsequent packets will be slowed down by $sleepSecs second(s)";
                            _trace2  (" openTcpSSLconnection: $my_error\n");
                            carp("$STR{WARN} openTcpSSLconnection: ... $my_error"); # if ($retryCnt > 1); # warning if at least 2nd retry
                            close ($socket) or carp("$STR{WARN} STARTTLS: $my_error; Can't close socket, too: $!");
                            sleep($suspendSecs);
                            _trace4 (" openTcpSSLconnection: STARTTLS (Phase 5): End suspend\n");
                            if ($retryCnt == $SSLhello::retry) { # signal to do an additional retry
                                $retryCnt++;
                                _trace4 (" openTcpSSLconnection: STARTTLS (Phase 5): 1 additional final retry after too many requests => retry number $retryCnt represented by $retryCnt+1\n");
                            }
                            next RETRY_TO_OPEN_SSL_CONNECTION;
                        } elsif ( ($starttls_matrix[$starttlsType][7]) && ($input =~ /$starttls_matrix[$starttlsType][7]/) ) {
                            # did receive a protocol error message
                            error_handler->new( {
                                type    => $OERR{'SSLHELLO_ABORT_PROTOCOL'},
                                id      => 'STARTTLS (Phase 5): Error 2',
                                message => "unsupported protocol: $host:$port \'$input\'",
                                warn    => 0,
                            } );
                            close ($socket) or carp("$STR{WARN} ". error_handler->get_err_str() ."; Can't close socket, too: $!");
                            last RETRY_TO_OPEN_SSL_CONNECTION;
                        } elsif ( ($starttls_matrix[$starttlsType][8]) && ($input =~ /$starttls_matrix[$starttlsType][8]/) ) { # did receive a Fatal Error Message
                            $my_error = "STARTTLS (Phase 5): Error 3: Fatal Error: $host:$port \'$input\' -> target $host:$port ignored";
                            _trace2  (" openTcpSSLconnection: $my_error\n");
                            close ($socket) or carp("$STR{WARN} STARTTLS: $my_error; Can't close socket, too: $!");
                            last RETRY_TO_OPEN_SSL_CONNECTION;
                        } else {
                            if ($SSLhello::trace == 0) {   # no trace => shorten the output
                                $input =~ s/^(.+?)(?:\r?\n|$)/$1/x; # maximal 1 line  of error message
                                # if (($startType == x) || () ....) { $input = hexString ($input) } #
                            }
                            $my_error = "STARTTLS (Phase 5): Did *NOT* get a server SSL/TLS confirmation from $host:$port (retry: $retryCnt); target ignored. Server-Error: >"._chomp_r($input)."<"; # error message received from the SMTP-Server
                            _trace2 (" openTcpSSLconnection: ## $my_error; try to retry;\n");
                            close ($socket) or carp("$STR{WARN} STARTTLS: $my_error; Can't close socket, too: $!");
                            next RETRY_TO_OPEN_SSL_CONNECTION;
                        }
                    }
                } else { # did not receive a message
                    $my_error = ("STARTTLS (Phase 5): Did *NOT* get any answer to".$starttls_matrix[$starttlsType][0]." STARTTLS request from $host:$port -> slow down and try to retry target.");
                    _trace (" openTcpSSLconnection: $my_error\n");
                    $SSLhello::starttlsDelay = $sleepSecs; # adopt global variable 1 step later
                    $sleepSecs += $retryCnt + 2;
                    close ($socket) or carp("$STR{WARN} STARTTLS: $my_error; Can't close socket, too: $!");
                    next RETRY_TO_OPEN_SSL_CONNECTION; # next retry
                }
            } else {
                _trace2 (" openTcpSSLconnection: ## STARTTLS (Phase 5): Nothing to do for ".$starttls_matrix[$starttlsType][0]."\n");
            } # end-if $starttls_matrix[$starttlsType][5]
        } ###############    End STARTTLS Support  ##################
    } while ( ($my_error) && ( ($retryCnt++ < $SSLhello::retry) || ($retryCnt == $SSLhello::retry + 2) ) ); } # 1 Extra retry if $retryCnt++ == $SSLhello::retry +2
    if ($my_error) { #error
        chomp($my_error);
        carp("$STR{WARN} openTcpSSLconnection: $my_error");
        _trace2 ("openTcpSSLconnection: Exit openTcpSSLconnection }\n");
        return (undef);
    }
    alarm (0);   # race condition protection
    _trace2 ("openTcpSSLconnection: Connected to '$host:$port' }\n");
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
    my $parseAllRecords = shift || 0; # option to read, parse and analyse all received records (-> 1)
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
    my $dummy=""; # if the return value is not used in this case
    my $retryCnt = 0;
    my $firstMessage = "";
    my $secondMessage = "";
    my $segmentCnt=0;
    my $dtlsSequence = 0;
    my $dtlsCookieLen = 0;
    my $dtlsCookie = "";
    my $dtlsNewCookieLen = 0;
    my $dtlsNewCookie = "";
    my $alarmTimeout = $SSLhello::timeout +1; # 1 sec more than normal timeout as a time line of second protection
    my $isUdp = 0; # for DTLS
    my $buffer = "";
    my $lastMsgType = $HANDSHAKE_TYPE {'<<undefined>>'}; # undefined message type
    my $lastRecordType = $RECORD_TYPE {'<<undefined>>'}; # undefined record type
    my $lastRecordData = "";

    my $ssl = $PROTOCOL_NAME_BY_HEX{$protocol};
    if (! defined $ssl) {
        $ssl = "--unknown protocol--";
    }

    _trace4 (sprintf ("_doCheckSSLciphers ($host, $port, $ssl: >0x%04X<\n          >",$protocol).hexCodedString ($cipher_spec,"           ") ."<) {\n");
    local $my_error = ""; # reset error message
    error_handler->reset_err( {module => ($SSLHELLO), sub => '_doCheckSSLciphers', print => ($SSLhello::trace > 3), trace => $SSLhello::trace} );
    $isUdp = ( (($protocol & 0xFF00) == $PROTOCOL_VERSION{'DTLSfamily'}) || ($protocol == $PROTOCOL_VERSION{'DTLSv09'})  ); # udp for DTLS1.x or DTLSv09 (OpenSSL pre 0.9.8f)

    unless ($isUdp) { # NO UDP = TCP
        #### Open TCP connection (direct or via a proxy) and do STARTTLS if requested
        $socket=openTcpSSLconnection ($host, $port); # open TCP/IP, connect to the server (via proxy if needes) and STARTTLS if nedded
        if ( (!defined ($socket)) || (error_handler->is_err()) || ($@) ) { # no SSL connection
            if ((error_handler->get_err_type) == $OERR{'SSLHELLO_RETRY_HOST'}) { # no more retries
                error_handler->new( {
                   type     => $OERR{'SSLHELLO_ABORT_HOST'},
#                   warn     => 1,
                } );
            }
            unless (error_handler->is_err) { # no error set, but no socket obtaied
                error_handler->new( {
                    type    => $OERR{'SSLHELLO_ABORT_HOST'},
                    id      => 'open TCP SSL connection (1)',
                    message => "WARNING: Did not get a valid SSL-socket from function openTcpSSLconnection -> fatal exit of openTcpSSLconnection", # generic error message
#                    warn    => 1,
                } );
            }
            return ("");
        }
    } else { # udp (no proxy nor STARTTLS)
        if ( defined($SSLhello::connect_delay) && ($SSLhello::connect_delay > 0) ) {
            _trace_ ("\n");
            _trace  (" _doCheckSSLciphers (udp): connect delay $cfg{'connect_delay'} second(s)\n");
            sleep($SSLhello::connect_delay);
            _trace4 (" _doCheckSSLciphers (udp): connect delay $cfg{'connect_delay'} second(s) [End]\n");
        }
        { # >> start a block
            $my_error = "";
            $socket = IO::Socket::INET->new (
                Proto    => "udp",
                PeerAddr => "$host:$port",
                Timeout  => $SSLhello::timeout,
                #Blocking  => 1, #Default
            ) or $my_error = " \'$@\', \'$!\'";
            if ( (!defined ($socket)) || ($my_error) ) { # no UDP socket
                error_handler->new( {
                    type    => $OERR{'SSLHELLO_ABORT_HOST'},
                    id      => 'open UDP socket (1)',
                    message => "WARNING: Did not get a valid socket for UDP: $my_error -> fatal exit of _doCheckSSLciphers (udp)",
#                    warn    => 1,
                } );
                return ("");
            }
        } # << end a block
        _trace4 (" _doCheckSSLciphers: ## New UDP socket to >$host:$port<\n");
    } # end udp socket

    $retryCnt = 0;
    $my_error = ""; # reset error message
    RETRY_TO_EXCHANGE_CLIENT_AND_SERVER_HELLO: while ($retryCnt++ < $SSLhello::retry) { # no error and still retries to go
        #### compile ClientHello
        $clientHello = compileClientHello ($protocol, $protocol, $cipher_spec, $host, $dtls_epoch, $dtlsSequence++, $dtlsCookieLen, $dtlsCookie);

        #### send ClientHello
        _trace3 (" _doCheckSSLciphers: sending Client_Hello\n      >".hexCodedString(substr($clientHello,0,64),"        ")." ...< (".length($clientHello)." bytes)\n\n");
        _trace4 (" _doCheckSSLciphers: sending Client_Hello\n          >".hexCodedString ($clientHello,"           ")."< (".length($clientHello)." bytes)\n\n");
        local $@ = "";
        eval {
            local $SIG{ALRM}= "SSLhello::_timedOut";
            alarm($alarmTimeout); # set alarm for connect
            defined(send($socket, $clientHello, 0)) || die "Could *NOT* send ClientHello to $host:$port; $! -> target ignored\n";
            alarm (0);
        } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # end of eval section, begin of an error section ('or do'), that works for Windows, too.
            $my_error = "send client hello failed: $@";     # save the error message as soon as possible
            alarm (0);                                      # protection against race conditions
            error_handler->new( {
                type    => $OERR{'SSLHELLO_ABORT_HOST'},
                id      => 'send client hello failed',
                message => $my_error,
                warn    => 0,
            } );
            return ("");
        }};                                                 # end of the section 'or do { if () { ...'. Do NOT forget the;
        alarm (0);                                          # protection against race conditions

        ###### receive the answer (SSL+TLS: ServerHello, DTLS: Hello Verify Request or ServerHello)
        ###### errors are reported in local $my_error
        ($recordType, $recordVersion, $recordLen, $recordData, $recordEpoch, $recordSeqNr, $my_error) = _readRecord ($socket, $isUdp, \$input, $host, $port, $protocol);
        # error handling
        if ((error_handler->get_err_type()) <= $OERR{'SSLHELLO_RETRY_PROTOCOL'}) {
            if ((error_handler->get_err_type()) == $OERR{'SSLHELLO_RETRY_HOST'}) { # no more retries
                error_handler->new( {
                    type     => $OERR{'SSLHELLO_ABORT_HOST'}, # upgrade error to abort
#                   warn     => 1,
                } );
            }
            _trace ("**WARNING: ".error_handler->get_err_str."\n");
            return ("");
        }
        if ( ($my_error) && ((length($input)==0) && ($SSLhello::noDataEqNoCipher==0)) ) {
            _trace2 (" _doCheckSSLciphers: ... Received Data: Got a timeout receiving Data from $host:$port (protocol: $ssl ".sprintf ("(0x%04X)",$protocol).", ".length($input)." bytes): Eval-Message: >$my_error<\n");
            carp("$STR{WARN} _doCheckSSLciphers: ... Received Data: Got a timeout receiving Data from $host:$port (protocol: $ssl ".sprintf ("(0x%04X)",$protocol).", ".length($input)." bytes): Eval-Message: >$my_error<\n");
            return ("");
        } elsif (length($input) ==0) { # len == 0 without any timeout
            $my_error= "... Received NO Data from $host:$port (protocol: $ssl ".sprintf ("(0x%04X)",$protocol).") after $SSLhello::retry retries; This may occur if the server responds by closing the TCP connection instead with an Alert. -> Received NO Data";
            _trace2 ("_doCheckSSLciphers: $my_error }\n");
            return ("");
        } elsif ($my_error) { # any other error
             _trace2 ("_doCheckSSLciphers: Error-Message: $my_error }\n");
            return ("");
        }
        _trace2(" _doCheckSSLciphers: Server '$host:$port': (protocol $ssl [".sprintf ("0x%04X", $protocol)."], (record) type $recordType: received a record with ".length($recordData)." bytes payload (recordData) >".hexCodedString (substr($recordData,0,48),"       ")."< ...)     \n");

        if ($recordVersion <= 0) { # got no SSL/TLS/DTLS-PDU
            # Try to read the whole input buffer
            ($input, $my_error) = _readText ($socket, $isUdp, $input, "");

            if ($SSLhello::starttls)  {
                if ($input =~ /(?:^|\s)554(?:\s|-)security.*?$/ix)  { # 554 Security failure; TBD: perhaps more general in the future
                _trace2  (" _doCheckSSLciphers ## STARTTLS: received SMTP Reply Code '554 Security failure': (Is the STARTTLS command issued within an existing TLS session?) -> input ignored and try to Retry\n");
                    # retry to send clientHello
                    $my_error = ""; # reset error message
                    $input = ""; # reset input data
                    $pduLen=0;
                    next; # retry to send and receive a SSL/TLS or DTLS-Packet
                }
            } elsif ($input =~ /(?:^|\s)220(?:\s|-).*?$/x)  { # service might need STARTTLS
                $my_error= "$STR{WARN} _doCheckSSLciphers: $host:$port looks like an SMTP-Service, probably the option '--starttls' is needed -> target ignored\n";
                carp($my_error);
                return ("");
            }
            $my_error = "$STR{WARN} _doCheckSSLciphers: $host:$port dosen't look like a SSL or a SMTP-Service (1) -> Received data ignored -> target ignored\n";
            carp($my_error);
            _trace_ ("\n") if ($retryCnt <=1);
            _trace ("_doCheckSSLciphers: Ignored data: ".length($input)." bytes\n        >".hexCodedString($input,"        ")."<\n        >"._chomp_r($input)."< }\n");
            $input  = "";
            $pduLen = 0;
            return ("");
        }
        if (length($input) >0) {
            _trace2 ("_doCheckSSLciphers: Total data received: ". length($input). " bytes }\n");
            ($buffer, $lastMsgType, $dtlsNewCookieLen, $dtlsNewCookie, $acceptedCipher) = parseHandshakeRecord ($host, $port, $recordType, $recordVersion, $recordLen, $recordData, "", $protocol);
            if ((error_handler->get_err_type()) <= $OERR{'SSLHELLO_RETRY_PROTOCOL'}) {
                if ((error_handler->get_err_type()) == $OERR{'SSLHELLO_RETRY_HOST'}) { # no more retries
                    error_handler->new( {
                        type     => $OERR{'SSLHELLO_ABORT_HOST'},
#                       warn     => 1,
                    } );
                }
                _trace ("**WARNING: ".error_handler->get_err_str."\n");
                return ("");
            }

            if ( ($acceptedCipher ne "") && ($parseAllRecords > 0) && ($lastMsgType != $HANDSHAKE_TYPE {'server_hello_done'}) ) {
                _trace4 (" _doCheckSSLciphers: Try to get and parse next records\n");
                while ( (length($input) >0) && ($lastMsgType != $HANDSHAKE_TYPE {'server_hello_done'}) ) {
                    ###### receive next record
                    _trace4 (" _doCheckSSLciphers: receive next record\n");
                    $input = $buffer;
                    $buffer = "";
                    ($recordType, $recordVersion, $recordLen, $recordData, $recordEpoch, $recordSeqNr, $my_error) = _readRecord ($socket, $isUdp, \$input, $host, $port, $protocol);
                    last if ( (length($input)==0) || ($my_error) );
                    _trace4 (" _doCheckSSLciphers: record type '$recordType' is no handshake record -> stop receiving records\n") if ($recordType ne $RECORD_TYPE{'handshake'});
#TBD: wieder aktivieren                    last if ($recordType ne $RECORD_TYPE{'handshake'});
                    last if ($recordType eq $RECORD_TYPE{'application_data'}); ## replace the 'last' command above by this to test or to develop
                    if ( ($lastMsgType == $HANDSHAKE_TYPE {'<<fragmented_message>>'}) && ($recordType == $lastRecordType) ) { # last message was fragmented
                        $recordData = $lastRecordData.$recordData;
                        $recordLen += length($lastRecordData);
                        $lastRecordData = "";
                        _trace4 (" _doCheckSSLciphers: recompiled fragmented message -> compiled RecordLen: $recordLen\n");
                    }
                    # parse the next record (no cipher expected...)
                    ($buffer, $lastMsgType, $dtlsNewCookieLen, $dtlsNewCookie, $dummy) = parseHandshakeRecord ($host, $port, $recordType, $recordVersion, $recordLen, $recordData, $acceptedCipher, $protocol); # get more information received together with the accepted cipher
                    $lastRecordType = $recordType; # only used for fragmented messages
                    if ($lastMsgType == $HANDSHAKE_TYPE {'<<fragmented_message>>'}) { # last message has been fragmented
                        $lastRecordData = $buffer;
                        $buffer = "";
                    }
                }
            }

            if ( ($acceptedCipher ne "") || (! $isUdp) ) {
                last;
            }
            if ($my_error ne "") {
                _trace4 ("_doCheckSSLciphers: Exit with error: '$my_error' }\n");
                return ("");
            }
            if ( ($dtlsNewCookieLen > 0) && $isUdp) {
                $dtlsCookieLen = $dtlsNewCookieLen;
                $dtlsCookie = $dtlsNewCookie;
                $dtlsNewCookieLen = 0;
                $dtlsNewCookie = "";
                _trace2 (" _doCheckSSLciphers: received a cookie ($dtlsCookieLen bytes): >".hexCodedString($dtlsCookie,"        ")."<\n");
                $retryCnt--;
            }
            _trace4 (" _doCheckSSLciphers: DTLS: sleep ".$CST{'_DTLS_SLEEP_AFTER_NO_CIPHERS_FOUND'}." sec(s) after *NO* cipher found\n");
            OCfg::ocfg_sleep($CST{'_DTLS_SLEEP_AFTER_NO_CIPHERS_FOUND'}); # sleep after NO cipher found
            # select(undef, undef, undef, $CST{'_DTLS_SLEEP_AFTER_NO_CIPHERS_FOUND'}); # sleep after NO cipher found
        }
    } # end while (RETRY_TO_EXCHANGE_CLIENT_AND_SERVER_HELLO)

    if ($isUdp) { # reset DTLS connection using an alert record
        local $@ = "";
        eval {
            local $SIG{ALRM}= "SSLhello::_timedOut";
            my $level = 2; #fatal
            my $description = 90; #### selected alert 90: user_canceled [RFC5246]
            alarm($alarmTimeout); # set alarm for connect
            defined(send($socket, compileAlertRecord ($protocol, $host, $level, $description, $dtls_epoch, $dtlsSequence++), 0)) || die "Could *NOT* send an alert record to $host:$port; $! -> Error ignored\n";
            alarm (0);
        } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {              # End of eval section, begin of an error section ('or do'), that works for Windows, too.
            $my_error = "reset DTLS failed: $@";                    # save the error message as soon as possible
            alarm (0);                                              # protection against race conditions
            error_handler->new( {
                type    => $OERR{'SSLHELLO_RETRY_PROTOCOL'},
                id      => 'reset DTLS failed',
                message => $my_error,
                warn    => 0,
            } );
            # carp("$STR{WARN} _doCheckSSLciphers: $my_error");
            return ("");
        }};                                                         # End of the section 'or do { if () { ...'. Do NOT forget the;
        alarm (0);                                                  # protection against race conditions
    }

    unless ( close ($socket)  ) {
        carp("$STR{WARN} _doCheckSSLciphers: Can't close socket: $!");
    }
    if (($isUdp) && (defined ($acceptedCipher) ) && ($acceptedCipher ne "") ) {
        _trace4 (" _doCheckSSLciphers: DTLS: sleep ".$CST{'_DTLS_SLEEP_AFTER_FOUND_A_CIPHER'}." sec(s) after received cipher >".hexCodedCipher($acceptedCipher)."<\n");
        # select(undef, undef, undef, $CST{'_DTLS_SLEEP_AFTER_FOUND_A_CIPHER'});
        OCfg::ocfg_sleep($CST{'_DTLS_SLEEP_AFTER_FOUND_A_CIPHER'});
    }
    _trace2 ("_doCheckSSLciphers: }\n");
    return ($acceptedCipher);
} # _doCheckSSLciphers


############################################################
sub _readRecord ($$$;$$$$) {
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

    my $socket          = shift || "";
    my $isUdp           = shift || 0;
    my $input_ref       = shift;
    my $host            = shift || ""; # for warn and trace messages
    my $port            = shift || ""; # for warn and trace messages
    my $client_protocol = shift || -1;  # optional

    my $MAXLEN  = 16384; # according RFC 5246: 16384 bytes for the packetData (without the packet header)
    my $pduLen  = 0;     # no PDUlen detected, yet
    my $readLen = ($isUdp) ? $MAXLEN : 7;
        # minimum len is:
        #    all readable octets for UDP (-> MAXLEN),
        #    7 octets for TCP (=len of an alert message);
        # remark rk: the minimum record len is 5 bytes, but it is better to
        #            read 7 bytes to get a compete alert message before any
        #            disconnects can occure #### was: $MAXLEN; # read up to MAXLEN octets
    my $recordType      = 0;
    my $recordVersion   = 0;
    my $recordEpoch     = 0;
    my $recordSeqNr_null= 0; # (0x0000)
    my $recordSeqNr     = 0;
    my $my_local_error  = "";
    my $recordLen       = 0;
    my $recordData      = "";
    my $recordHeaderLen = 0;
    my ($rin, $rout);
    my $alarmTimeout    = $SSLhello::timeout +1; # 1 sec more than normal timeout as a time line of second protection$
    my $retryCnt        = 0;
    my $segmentCnt      = 0;

    return ($recordType, $recordVersion, $recordLen, $recordData, $recordEpoch, $recordSeqNr, $my_local_error) if (! defined ($input_ref) );
    my $input2          = "";
    my @socketsReady    = ();
    my $len             = length ($$input_ref);

    require IO::Select if ($SSLhello::trace > 0);
    my $select; #used for tracing only
    $select = IO::Select->new if ($SSLhello::trace > 0);
    my $success=0;
    $select->add($socket) if ($SSLhello::trace > 0);

    #reset error_handler and set basic information for this sub
    error_handler->reset_err( {module => ($SSLHELLO), sub => '_readRecord', print => ($SSLhello::trace > 3), trace => $SSLhello::trace} );

    ###### receive the answer (SSL+TLS: ServerHello, DTLS: Hello Verify Request or ServerHello)
    vec($rin = '',fileno($socket),1 ) = 1; # mark SOCKET in $rin
    RETRY_TO_RECEIVE_A_RECORD: while ( ( (length($$input_ref) < $pduLen) || ($pduLen == 0) ) && ($retryCnt++ <= $SSLhello::retry) ) {
        if ($isUdp) { # #still use select for udp
            $my_local_error = "";
            local $@ = "";
            eval { # check this for timeout, protect it against an unexpected exit of the program
                # set alarm and timeout
                local $SIG{ALRM}= "SSLhello::_timedOut";
                alarm($alarmTimeout);
                # opimised with reference to 'https://github.com/noxxi/p5-ssl-tools/blob/master/check-ssl-heartbleed.pl'
                $success = select($rout = $rin,undef,undef,$SSLhello::timeout);
                alarm (0); #clear alarm
            } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {          # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                $my_local_error = "failed to select data: $@";            # save the error message as soon as possible
                alarm (0);                                          # clear alarm if not done before
                error_handler->new( {
                    type    => $OERR{'SSLHELLO_RETRY_CIPHERS'},
                    id      => '_readRecord (udp): unknown Timeout error (1)',
                    message => $my_local_error,
                    warn    => 0,
                } );
                carp("_readRecord (udp): $my_local_error");
                _trace4 ("_readRecord (udp) from Server '$host:$port' -> LAST: Received (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($$input_ref)." bytes (from $pduLen expected) after $retryCnt tries:\n");
                last RETRY_TO_RECEIVE_A_RECORD;
            }};                                                     # End of the section 'or do { if () { ...'. Do NOT forget the; => '}};'
            alarm (0);                                              # protection against race conditions
            if ( ! $success) { # nor data NEITHER special event => timeout
                error_handler->new( {
                    type    => $OERR{'SSLHELLO_RETRY_CIPHERS'},
                    id      => '_readRecord (udp): Timeout error (1)',
                    message => $my_local_error,
                    warn    => 0,
                } );
                _trace4 ("_readRecord (udp): Server '$host:$port' -> Timeout (received nor data NEITHER special event) while reading a record with".length($$input_ref)." bytes (from $pduLen expected) after $retryCnt tries:\n");
                last RETRY_TO_RECEIVE_A_RECORD; # resend the UDP packet
            }
            if (vec($rout, fileno($socket),1)) { # got data
                local $@ = "";
                eval { # check this for timeout, protect it against an unexpected exit of the program
                    # set alarm and timeout
                    local $SIG{ALRM}= "SSLhello::_timedOut";
                    alarm($alarmTimeout);
                    @socketsReady = $select->can_read(0) if ($SSLhello::trace > 3); ###additional debug (use IO::select needed)
                    _trace4 ("_readRecord (udp): can read (1): (Segement: $segmentCnt, retry: $retryCnt, position: ".length($$input_ref)." bytes)\n") if (scalar (@socketsReady));
                    $success = sysread ($socket, $$input_ref, $readLen - length($$input_ref), length($$input_ref)); #if NO success: EOF or other error while reading Data
                    alarm (0); #clear alarm
                } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                    $my_local_error = "failed to read data with sysread: $@";     # save the error message as soon as possible
                    alarm (0);                                      # clear alarm if not done before
                    error_handler->new( {
                        type    => $OERR{'SSLHELLO_RETRY_CIPHERS'},
                        id      => '_readRecord (udp): unknown Timeout error (2)',
                        message => $my_local_error,
                        warn    => 0,
                    } );
                    carp("_readRecord (udp): $my_local_error");
                    _trace4 ("_readRecord (udp) -> LAST: Received (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($$input_ref)." bytes (from $pduLen expected) after $retryCnt tries:\n");
                    last RETRY_TO_RECEIVE_A_RECORD;                 # resend the UDP packet
                }};                                                 # End of the section 'or do { if () { ...'. Do NOT forget the; '}};'
                alarm (0);                                          # protection against race conditions
                @socketsReady = $select->can_read(0) if ($SSLhello::trace > 3); ###additional debug (use IO::select needed)
                _trace4 ("_readRecord (udp) can read (2): (Segement: $segmentCnt, retry: $retryCnt, position: ".length($$input_ref)." bytes)\n") if (scalar (@socketsReady));
                if (! $success ) { # EOF or other error while reading Data
                    if (length ($$input_ref) == 0) { # Disconnected, no Data
                        $my_local_error = "Server '$host:$port': received EOF (Disconnect), no Data\n";
                        error_handler->new( {
                            type    => $OERR{'SSLHELLO_RETRY_CIPHERS'},
                            id      => '_readRecord (udp): no Data',
                            message => $my_local_error,
                            warn    => 0,
                        } );
                        _trace4 ("_readRecord (udp) : $my_local_error\n");
                        last RETRY_TO_RECEIVE_A_RECORD;
                    } else {
                        $my_local_error = "Server '$host:$port': No data (EOF) after ".length($$input_ref)." of expected $pduLen bytes: '$!' -> Retry to read\n";
                        error_handler->new( {
                            type    => $OERR{'SSLHELLO_RETRY_CIPHERS'},
                            id      => '_readRecord (udp): EOF',
                            message => $my_local_error,
                            warn    => 0,
                        } );
                        _trace1 ("_readRecord (udp): $my_local_error\n");
                        @socketsReady = $select->can_read(0) if ($SSLhello::trace > 1); ###additional debug (use IO::select needed)
                        _trace1 ("_readRecord (udp): can read (3): (Segement: $segmentCnt, retry: $retryCnt, position: ".length($$input_ref)." bytes)\n") if (scalar (@socketsReady));
                        #select (undef, undef, undef, $CST{'_SLEEP_B4_2ND_READ'});
                        OCfg::ocfg_sleep($CST{'_SLEEP_B4_2ND_READ'});
                        next RETRY_TO_RECEIVE_A_RECORD;
                    }
                }
            } else {# got NO data
                $my_local_error = "Server '$host:$port': No data in _readRecord after reading $len of $pduLen expected bytes; $!";
                error_handler->new( {
                    type    => $OERR{'SSLHELLO_RETRY_CIPHERS'},
                    id      => '_readRecord (udp): Received (no more) data',
                    message => $my_local_error,
                    warn    => 0,
                } );
                _trace1 ("_readRecord (udp): ... Received data: $my_local_error\n");
                _trace4 ("_readRecord (udp) :-> LAST: Received (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($$input_ref)." bytes (from $pduLen expected) after $retryCnt tries:\n");
                last RETRY_TO_RECEIVE_A_RECORD;
            } ###  End got Data
        } else { # TCP
            local $@ = "";
            eval { # check this for timeout, protect it against an unexpected exit of the program
                # set alarm and timeout
                local $SIG{ALRM}= "SSLhello::_timedOut";
                alarm($alarmTimeout);
                my $_missing_readLen = $readLen - length($$input_ref);
                _trace4 ("_readRecord (tcp): try to recv (1): (Segement: $segmentCnt, retry: $retryCnt, position: ".length($$input_ref)." bytes, missing Bytes: $_missing_readLen)\n");
                $success = ($_missing_readLen <= 0) || (recv ($socket, $input2, $readLen - length($$input_ref), 0) ); #if NO success: $success undefined
                alarm (0); #clear alarm
            } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {          # End of eval section, begin of an error section ('or do'), that works for Windows, too.
                $my_local_error = "failed to receive data (recv) $@";     # save the error message as soon as possible
                alarm (0);                                          # clear alarm if not done before
                error_handler->new( {
                    type    => $OERR{'SSLHELLO_RETRY_CIPHERS'},
                    id      => '_readRecord (tcp): recv: unknown Timeout error',
                    message => $my_local_error,
                    warn    => 0,
                } );
                carp("_readRecord (tcp): $my_local_error");
                _trace4 ("_readRecord (tcp): recv -> LAST: Received (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($$input_ref)." bytes (from $pduLen expected) after $retryCnt tries:\n");
                last RETRY_TO_RECEIVE_A_RECORD;
            }};                                                     # End of the section 'or do { if () { ...'. Do NOT forget the; => '}};'
            alarm (0);                                              # protection against race conditions
            $$input_ref .= $input2;                                 # append new input
            $success = length ($input2);                            # same usage as sysread
            _trace4 ("_readRecord (tcp): recv: (Segement: $segmentCnt, retry: $retryCnt, position: ".length($$input_ref)." bytes)\n");
        } # End TCP
        $len = length($$input_ref);
        if ($success) { # got new data
            if ($pduLen == 0) { # no PduLen decoded, yet
                _trace4 ("_readRecord (tcp): Server '$host:$port': ... Received first $len bytes to detect PduLen\n");
                if ( (! $isUdp) && ($len >= 5) ) { # try to get the pduLen of the SSL/TLS Pdu (=protocol aware length detection)
                    # Check PDUlen; parse the first 5 bytes to check the len of the PDU (SSL3/TLS)
                    ($recordType,       #C (record_type)
                     $recordVersion,    #n (record_version)
                     $recordLen,        #n (record_len)
                    ) = unpack("C n n", $$input_ref); # assuming to parse a SSLv3/TLS record, will be redone if it is SSLv2

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
                        ) = unpack("n C", $$input_ref);
                        if ( ($recordLen > 0x8000) && (($recordType == $SSL_MT_SERVER_HELLO) || ($recordType == $SSL_MT_ERROR)) ) { # SSLv2 check
                            $recordLen     -= 0x8000;
                            $recordHeaderLen = 2; # Message Data starts at position 3
                            $pduLen         = $recordLen + $recordHeaderLen;
                            $recordVersion  = $PROTOCOL_VERSION{'SSLv2'}; # added the implicitly detected protocol
                            _trace2 ("_readRecord (tcp): Server '$host:$port': ... Received data: Expected SSLv2-PDU-Len:");
                        } else { ### no SSL/TLS/DTLS PDU => Last
                            $my_local_error = "no known SSL/TLS PDU type";
                            $recordType     = 0;
                            $recordVersion  = 0;
                            $recordLen      = 0;
                            _trace1 ("_readRecord (tcp): $my_local_error\n");
                            _trace4 ("_readRecord (tcp): -> LAST: received (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($$input_ref)." bytes (from $pduLen expected) after $retryCnt tries:\n");
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
                    ) = unpack ("C n n n N n", $$input_ref);

                    _trace2_ (sprintf (
                     "# -->    => DTLS record type: Handshake  (%02X):\n". ### only for handshake records that we analyse, yet
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
                        # isUdp is set, but no DTLS-Record recognised
                        $my_local_error = "Server '$host:$port': no known DTLS PDU type -> unknown protocol";
                        _trace1 ("_readRecord (udp): $my_local_error\n");
                        _trace1 ("_readRecord (udp): -> LAST: Received (record) type $recordType, -version: ".sprintf ("(0x%04X)", $recordVersion)." with ".length($$input_ref)." bytes (from $recordLen expected) after $retryCnt tries: reset all the mentioned parameters to 0\n");
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
                    carp("_readRecord: Server '$host:$port': Expected len of the SSL/TLS record ($recordLen) is higher than the maximum ($MAXLEN) -> cut at maximum length!");
                    $pduLen += -$recordLen +$MAXLEN; # => MAXLEN + size of record header
                }
                $readLen = $pduLen; # read only pduLen octets (-> only by one record)
                $retryCnt = 0 if ($readLen > 0); # detection of the recordLen is no retry -> reset counter
            } else {
                $segmentCnt++;
                _trace4 ("_readRecord: Server '$host:$port': ... Received $len bytes in $segmentCnt segment(s)\n");
                $retryCnt = 0 if ($segmentCnt <= $CST{'_MAX_SEGMENT_COUNT_TO_RESET_RETRY_COUNT'}); # reset retry count to 0 (in next loop)
            }
            if (defined ($client_protocol)) {
                my $client_ssl = $PROTOCOL_NAME_BY_HEX{$client_protocol};
                if (! defined $client_ssl) {
                    $client_ssl = "--unknown protocol--";
                }
                if ($recordVersion == 0) { # some servers respond with the dummy protocol '0x0000' if they do *not* support the requested protocol
                    error_handler->new( {
                        type    => $OERR{'SSLHELLO_ABORT_PROTOCOL'},
                        id      => 'check record protocol (1)',
                        message => sprintf ("unsupported protocol $client_ssl (0x%04X) by $host:$port, answered with (0x%04X)", $client_protocol, $recordVersion),
                        warn    => 0,
                    } );
                    last RETRY_TO_RECEIVE_A_RECORD;
                }
            }
        }
    } # end while
    if (!($my_local_error) && (length($$input_ref) < $pduLen) ) { # no error, but the loop did *NOT* get all data within the maximal retries
        $my_local_error = "Server '$host:$port': Overrun the maximal number of $retryCnt retries in _readRecord after reading $len of $pduLen expected bytes in the ". $segmentCnt . "th segment; $!";
        _trace1 ("_readRecord ... Error receiving data: $my_local_error\n");
        _trace4 ("_readRecord -> LAST: Received (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($$input_ref)." bytes (from $pduLen expected) after $retryCnt tries:\n");
    }
    chomp ($my_local_error);

    if ($client_protocol >= 0) {
        _trace3("_readRecord: Server '$host:$port': (expected protocol= >".sprintf ("%04X", $client_protocol)."<,\n      (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($$input_ref)." bytes >".hexCodedString (substr($$input_ref,0,48),"       ")."< ...)\n");
    } else {
        _trace4("_readRecord: Server '$host:$port': (any protocol, (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)." with ".length($$input_ref)." bytes\n       Data=".hexCodedString ($$input_ref,"       ").")\n");
    }

    ($recordData) = unpack ("x[$recordHeaderLen] a*", $$input_ref);  # get recordData with up to $recordLen bytes from input skipping the header
    if (length($recordData) < $recordLen) {
        _trace1 ("_readRecord: Server '$host:$port': (expected protocol= >".sprintf ("%04X", $client_protocol)."<, (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)
                .": recordLen ".sprintf ("%04X",length($recordData))." is smaller than the expected value ".sprintf ("%04X",$recordLen). "\n");
        carp    ("_readRecord: Server '$host:$port': (expected protocol= >".sprintf ("%04X", $client_protocol)."<, (record) type $recordType, -version: ".sprintf ("(0x%04X)",$recordVersion)
                .": recordLen ".sprintf ("%04X",length($recordData))." is smaller than the expected value ".sprintf ("%04X",$recordLen). "\n");
    }
    return ($recordType, $recordVersion, $recordLen, $recordData, $recordEpoch, $recordSeqNr, $my_local_error);
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
    my $alarmTimeout = $SSLhello::timeout +1; # 1 sec more than normal timeout as a time line of second protection
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
            local $SIG{ALRM}= "SSLhello::_timedOut";
            alarm($alarmTimeout);
            # Opimised with reference to 'https://github.com/noxxi/p5-ssl-tools/blob/master/check-ssl-heartbleed.pl'
            if ( ! select($rout = $rin,undef,undef,$SSLhello::timeout) ) { # Nor data NEITHER special event => Timeout
                alarm (0); #clear alarm
                $my_local_error = "Timeout in _readText $!";
                last RECEVICE_ANSWER;
            }
            alarm (0); #clear alarm
        } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {      # end of eval section, begin of an error section ('or do'), that works for Windows, too.
            $my_local_error = "failed to select text: $@"
        }};                                                 # end of the section 'or do { if () { ...'. Do NOT forget the;
        #$my_error .= $@;                                   # save the error message as soon as possible
        alarm (0);                                          # protection against race conditions
        if ($my_local_error) {
            $my_local_error = "_readText: unknown Timeout-Error (1): $my_error";
             carp("_readText: $my_local_error");
             return ($input, $my_local_error);
        }
        if (vec($rout, fileno($socket),1)) { # got data
            local $@ = "";
            eval { # check this for timeout, protect it against an unexpected exit of the program
                # set alarm and timeout
                local $SIG{ALRM}= "SSLhello::_timedOut";
                alarm($alarmTimeout);
                my $_missing_readLen = $MAXLEN - length($input);
                _trace4 ("_readText: try to recv (1): (retry: $retryCnt, position: ".length($input)." bytes, missing Bytes: $_missing_readLen)\n");
                ## read only up to 5 bytes in the first round, then up to the expected pduLen
                my $success = ($_missing_readLen <= 0) || (recv($socket, $input2, $MAXLEN - length($input), 0 ) );  # EOF or other error while reading data
                $input .= $input2;
                alarm (0); # clear alarm
            } or do { if ( ($@) or ($^O !~ m/MSWin32/) ) {  # end of eval section, begin of an error section ('or do'), that works for Windows, too.
                $my_error = "failed to receice text: $@"
            }};                                             # end of the section 'or do { if () { ...'. Do NOT forget the;
            #$my_error .= $@;                               # save the error message as soon as possible
            alarm (0);                                      # protection against race conditions
            if ($my_local_error) {
                $my_local_error = "_readText unknown Timeout-Error (2): $my_error";
                 carp("_readText: $my_local_error");
                 last RECEVICE_ANSWER;
            }
            $len = length($input2);
            if ($len <= 0) { # error no data
                $my_local_error = "NULL-Len-Data in _readText $!";
                _trace1 ("_readText: $my_local_error\n");
                last RECEVICE_ANSWER;
            }
        } else {# got NO (more) data
            last RECEVICE_ANSWER;
        }
        if ($retryCnt++ < $SSLhello::retry) {
            $my_local_error = "Retry-Counter exceeded $SSLhello::retry while reading Text";
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

    my $ssl = $PROTOCOL_NAME_BY_HEX{$version};
    if (! defined $ssl) {
        $ssl = "--unknown protocol--";
    }
    _trace4 (sprintf("compileClientHello (%04X, %04X,\n          >%s<, %s) {\n", $record_version, $version, hexCodedString ($ciphers,"           "), $host) );

    $challenge= pack("Na[28]", time(), $challenge); # 4 bytes: uint32 gmt_unix_time;, 28 byte random
    _trace4_("#   --->   challenge >".hexCodedString ($challenge)."<\n");

    my $handshake_version = $version;
    if ( ($version > $PROTOCOL_VERSION{'TLSv12'}) && ($version < $PROTOCOL_VERSION{'DTLSv12'}) ) {
        $handshake_version  = $PROTOCOL_VERSION{'TLSv12'};
        $record_version     = $PROTOCOL_VERSION{'TLSv12'};
    }

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
        'version'                => $handshake_version,        # SSL2:0x0002,SSL3:0x3000,TLS1:0x0301 #uint16
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

          if  (($SSLhello::trace > 3)) {
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

         _trace4 ("compileClientHello (SSL3/TLS) (1):\n");

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

        if  ($SSLhello::trace > 3) {
            printTLSCipherList ($clientHello{'cipher_spec'});
        }

        _trace2_ ( sprintf (
                "# -->       compression_method_len:  >%02X<\n".
                "# -->       compression_method:      >%02X<\n",    #Comma!!
                $clientHello{'compression_method_len'}, # C (0x01)
                $clientHello{'compression_method'},     # C[1] (0x00)
        ));

        _trace5_ ( sprintf (
                "#   --->    extensions_total_len:  >%04X<\n".      #Point!!
                "#   --->    extensions:            >%s<\n",        #Comma!!
                $clientHello{'extensions_total_len'},
                hexCodedString ($clientHello_extensions),
            )
        );

        _parseExtensions ("CH", undef, \$clientHello_extensions, -1) if ($SSLhello::trace > 2);  # only for trace purposes; $clientHello_extensions includes the length -> length = '-1' as indicator
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

        if  ($SSLhello::trace > 3) {
            printTLSCipherList ($clientHello{'cipher_spec'});
        }

        _trace2_ ( sprintf (
                "# -->       compression_method_len:  >%02X<\n".
                "# -->       compression_method:      >%02X<\n",    # Comma!!
                $clientHello{'compression_method_len'},  # C (0x01)
                $clientHello{'compression_method'},      # C[1] (0x00)
        ));

        _trace5_ ( sprintf (
                "#   --->    extensions_total_len:  >%04X<\n".      #Point!!
                "#   --->    extensions:            >%s<\n",        #Comma!!
                $clientHello{'extensions_total_len'},
                hexCodedString ($clientHello_extensions),
            )
        );

        _parseExtensions ("CH", undef, \$clientHello_extensions, -1) if ($SSLhello::trace > 2);  # only for trace purposes; $clientHello_extensions includes the length -> length = '-1' as indicator

        _trace4 (sprintf ("compileClientHello (%04X)\n          >",$record_version).hexCodedString ($clientHello,"           ")."<\n");
    } else {
        if (! defined $ssl) {
            $ssl = "--unknown protocol--";
        }
#        my ($ssl) = grep {$record_version ~~ ${$cfg{'openssl_version_map'}}{$_}} keys %{$cfg{'openssl_version_map'}};
        local $my_error = "$STR{WARN} compileClientHello: protocol version $ssl (0x". sprintf("%04X", $record_version) .") not (yet) defined in SSLhello.pm -> protocol ignored";
        carp($my_error);
    }
    if ( ($SSLhello::max_sslHelloLen > 0) && (length($clientHello) > $SSLhello::max_sslHelloLen) ) { # According RFC: 16383+5 bytes; handshake messages between 256 and 511 bytes in length caused sometimes virtual servers to stall, cf.: https://code.google.com/p/chromium/issues/detail?id=245500
        if (! defined $ssl) {
            $ssl = "--unknown protocol--";
        }
        if  ($SSLhello::experimental >0) { # experimental function is are activated
            _trace_("\n");
            _trace ("compileClientHello: WARNING: Server $host (protocol: $ssl): use of ClientHellos > $SSLhello::max_sslHelloLen bytes did cause some virtual servers to stall in the past. This protection is overridden by '--experimental'");
        } else { # use of experimental functions is not permitted (option is not activated)
            local $my_error = "$STR{WARN} compileClientHello: Server $host: the ClientHello is longer than $SSLhello::max_sslHelloLen bytes, this caused sometimes virtual servers to stall, e.g. 256 bytes: https://code.google.com/p/chromium/issues/detail?id=245500;\n    Please add '--experimental' to override this protection; -> This time the protocol $ssl is ignored";
            carp($my_error);
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
    my $ssl = $PROTOCOL_NAME_BY_HEX{$record_version};
    if (! defined $ssl) {
        $ssl = "--unknown protocol--";
    }

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
        $my_error = "$STR{WARN} compileAlert for SSL2 is not yet supported";
        _trace1 ("compileAlertRecord: $my_error\n");
        carp($my_error);

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
        $my_error = "$STR{WARN} compileAlertRecord protocol version $ssl (0x". sprintf("%04X", $record_version) .") not (yet) defined in SSLhello.pm -> protocol ignored";
        carp($my_error);
    }
    if ( ($SSLhello::max_sslHelloLen > 0) && (length($alertRecord) > $SSLhello::max_sslHelloLen) ) { # According RFC: 16383+5 bytes; handshake messages between 256 and 511 bytes in length caused sometimes virtual servers to stall, cf.: https://code.google.com/p/chromium/issues/detail?id=245500
        if (! defined $ssl) {
            $ssl = "--unknown protocol--";
        }
        if  ($SSLhello::experimental >0) { # experimental function is are activated
            _trace_("\n");
            _trace ("compileAlertRecord: WARNING: Server $host (protocol: $ssl): use of alert message > $SSLhello::max_sslHelloLen bytes did cause some virtual servers to stall in the past. This protection is overridden by '--experimental'");
        } else { # use of experimental functions is not permitted (option is not activated)
            $my_error = "$STR{WARN} compileAlertRecord: Server $host: the alert message is longer than $SSLhello::max_sslHelloLen bytes, this caused sometimes virtual servers to stall, e.g. 256 bytes: https://code.google.com/p/chromium/issues/detail?id=245500;\n    Please add '--experimental' to override this protection; -> This time the protocol $ssl is ignored";
            carp($my_error);
        }
    }
    return ($alertRecord);
} # compileAlertRecord

#? sub subs that compile parts of records, e.g. bytes for extensions ####################
    #? sub __compile_bytes_* and _compileNextByte, _compileAllBytes
    #? the following subs use the same set of variables:
    #? $__pdu_name:        for tracing and warnings: name of the PDU that is parsed, eg. extension
    #? $__format_ref:      reference to an array including the format of the PDU, %__compile_bytes_subs maps the format names to the sub functions
    #? $__param_ref:       reference to an array of the values to be compiled
    #? $__format_pos_ref:  reference to the position in the array $__format_ref->[pos]
    #? $__param_pos_ref:   reference to the position in the array $__param_ref->[pos]
    #? $__buffer_ref:      reference to the buffer that stores the compiled PDU
    #? $__buffer_size:     size of the buffer
    #? optional:
    #? $__format_text_ref: reference to an array describing the semantic of the parts of the PDU
    #? $__indent:          indent for tracing
    #?
    #? return($_size):     return the size of the buffer
    #? use this subs via '%__compile_bytes_subs' a self defined general description for the structure of for PDUs, e.g. tls extensions

sub __compile_bytes_len1 ($$$$$$;$$) {
    #? compiles the len1 byte the following value fields
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $_size = 0;
    my $_next_data = "";

    _trace4_ (" " x $__indent . "# SSLhello: __compile_bytes_len1 for '$__pdu_name'     ($$__format_pos_ref, $$__param_pos_ref)\n");
    $$__format_pos_ref++;                                           # Next format element
    $_size = _compileAllBytes ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, \$_next_data, $__format_text_ref, $__indent);
    my $__len = length ($_next_data);
    _trace4_ (_decode_val ("%02X", \$__len, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . " (len1)\n");
    carp("$STR{WARN} SSLhello::__compile_bytes_len1 for '$__pdu_name': Length $__len too big\n") if ($__len > 0xFF); ### TBD: add WARNING Nr
    $$__buffer_ref .= pack ("C a*",
            $__len,                                                 #C
            $_next_data,                                            #a[$len]
        );
    $_size += 1;
    return ($_size);
}

sub __compile_bytes_len2 ($$$$$$;$$) {
    #? compiles the len2 bytes the following value fields
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $_size = 0;
    my $_next_data = "";

    _trace4_ (" " x $__indent . "# SSLhello: __compile_bytes_len2 for '$__pdu_name'     ($$__format_pos_ref, $$__param_pos_ref)\n");
    $$__format_pos_ref++;                                           # Next format element
    $_size = _compileAllBytes ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, \$_next_data, $__format_text_ref, $__indent);
    my $__len = length ($_next_data);
    _trace4_ (_decode_val ("%04X", \$__len, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . " (len2)\n");
    carp("$STR{WARN} SSLhello::__compile_bytes_len2 for '$__pdu_name': Length $__len too big\n") if ($__len > 0xFFFF); ### TBD: add WARNING Nr
    $$__buffer_ref .= pack ("n a*",
            $__len,                                                 #n
            $_next_data,                                            #a[$len]
        );
    $_size += 2;
    return ($_size);
}

sub __compile_bytes_len3 ($$$$$$;$$) {
    #? compiles the len3 bytes the following value fields
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $_size = 0;
    my $_next_data = "";

    _trace4_ (" " x $__indent . "# SSLhello: __compile_bytes_len3 for '$__pdu_name'     ($$__format_pos_ref, $$__param_pos_ref)\n");
    $$__format_pos_ref++;                                           # Next format element
    $_size = _compileAllBytes ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, \$_next_data, $__format_text_ref, $__indent);
    my $__len  = length ($_next_data);
    my $__len1 = $__len >> 16;
    my $__len2 = $__len & 0xFFFF;
    _trace4_ (_decode_val ("%06X", \$__len, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . " (len3)\n");
    carp("$STR{WARN} SSLhello::_compile_bytes_len3 for '$__pdu_name': Length $__len too big\n") if ($__len > 0xFFFFFF); ### TBD: add WARNING Nr
    $$__buffer_ref .= pack ("C n a*",
            $__len1,                                                #C
            $__len2,                                                #n
            $_next_data,                                            #a*
        );
    $_size += 3;
    return ($_size);
}

sub __compile_bytes_raw ($$$$$$;$$) {
    #? compiles a raw bytes value field
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $_size = 0;

    _trace4_ (" " x $__indent . "# SSLhello: __compile_bytes_raw  for '$__pdu_name'     ($$__format_pos_ref, $$__param_pos_ref)\n");
    return (0) if (! defined ($__param_ref->[$$__param_pos_ref]) ); # no value
    my $__val = $__param_ref->[$$__param_pos_ref++];
    _trace4_ (_decode_val ("", \$__val, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n", " | ", " / ") . " (raw)\n");
    $$__buffer_ref .= pack ("a*",
            $__val,                                                 #a*
        );
    $_size = length ($__val);
    return ($_size);
}

sub __compile_bytes_sequence ($$$$$$;$$) {
    #? compiles a sequence of fields
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    my $_size               = 0;
    my $_sequence_data      = "";
    my $_sequence_param_pos = 0;
    my $_sequence_param_list_ref;

    _trace4_ (" " x $__indent . "# SSLhello: __compile_bytes_sequence for '$__pdu_name' ($$__format_pos_ref, $$__param_pos_ref)\n");
    _trace4_ (_decode_val (undef, undef, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent + 3, ":\n" . " " x ($__indent + 3), ",\n" . " " x ($__indent + 3), " | ", " / ") );
    _trace5_ ("\n");
    $$__format_pos_ref++;                                           # Next format element
    my $_sequence_format_pos = $$__format_pos_ref;                  # store start position of sequence
    $__indent += 3;
    while (defined ($__param_ref->[$$__param_pos_ref]) ) {
        $_sequence_param_list_ref = \@{$__param_ref->[$$__param_pos_ref]};
        _trace5_ (" " x $__indent);
        _trace4_ ("sequence parameter for '$__pdu_name':\n" . _decode_val (undef, $_sequence_param_list_ref, undef, $__indent + 3, $__indent + 3, ":\n" . " " x ($__indent + 3), ",\n" . " " x ($__indent + 3), " | ", " / ") . "\n");
        $$__format_pos_ref      = $_sequence_format_pos;            # reset format_pos to first element of sequence format
        $_sequence_param_pos    = 0;                                # reset to first Element of $_sequence_param_list
        $_sequence_data         = "";                               # reset sequence_data
        $_size += _compileAllBytes ($__pdu_name, $__format_ref, $_sequence_param_list_ref, $__format_pos_ref, \$_sequence_param_pos, \$_sequence_data, $__format_text_ref, $__indent);
        $$__buffer_ref .= $_sequence_data;                          # add sequence data to _data
        _trace4_ (" " x $__indent);
        _trace4_ ("=> size of sequence(s) for '$__pdu_name': " . _sprintf_hex_val ("%04X", \$_size, $__indent) ."\n" );
        $$__param_pos_ref++;
    }
    return ($_size);
}

sub __compile_bytes_size1 ($$$$$$;$$) {
    #? compiles the size1 byte the following value field
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $_size = 0;
    my $_next_data = "";

    _trace4_ (" " x $__indent . "# SSLhello: __compile_bytes_size1 for '$__pdu_name'    ($$__format_pos_ref, $$__param_pos_ref)\n");
    $$__format_pos_ref++;                                           # Next format element
    $_size = _compileNextByte ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, \$_next_data, $__format_text_ref, $__indent);
    _trace4_ (_decode_val ("%02X", \$_size, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ",\n" . " " x $__indent, " | ", " / ") . " (size1)\n");
    carp("$STR{WARN} SSLhello::__compile_bytes_size1 for '$__pdu_name': Length $_size too big\n") if ($_size > 0xFF); ### TBD: add WARNING Nr
    $$__buffer_ref .= pack ("C a*",
            $_size,                                                 #C
            $_next_data,                                            #a[$len]
        );
    $_size += 1;
    return ($_size);
}

sub __compile_bytes_size2 ($$$$$$;$$) {
    #? compiles the size2 bytes the following value field
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    my $_size = 0;
    my $_next_data = "";
    _trace4_ (" " x $__indent . "# SSLhello: __compile_bytes_size2 for '$__pdu_name'    ($$__format_pos_ref, $$__param_pos_ref)\n");
    $$__format_pos_ref++;                                           # Next format element
    $_size = _compileNextByte ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, \$_next_data, $__format_text_ref, $__indent);
    _trace4_ (_decode_val ("%04X", \$_size, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . " (size2)\n");
    carp("$STR{WARN} SSLhello::__compile_bytes_size2 for '$__pdu_name': Length $_size too big\n") if ($_size > 0xFFFF); ### TBD: add WARNING Nr
    $$__buffer_ref .= pack ("n a*",
            $_size,                                                 #n
            $_next_data,                                            #a[$len]
        );
    $_size += 2;
    return ($_size);
}

sub __compile_bytes_val1 ($$$$$$;$$) {
    #? compiles a val1 byte value field
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    my $_size = 0;
    _trace4_ (" " x $__indent . "# SSLhello: __compile_bytes_val1 for '$__pdu_name'     ($$__format_pos_ref, $$__param_pos_ref)\n");
    return (0) if (! defined ($__param_ref->[$$__param_pos_ref]) ); # no value
    my $__val = $__param_ref->[$$__param_pos_ref++];
    _trace4_ (_decode_val ("%02X", \$__val, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . " (val1)\n");
    carp("$STR{WARN} SSLhello::__compile_bytes_val1 for '$__pdu_name': value $__val too big\n") if ($__val > 0xFF); ### TBD: add WARNING Nr
    $$__buffer_ref .= pack ("C",
            $__val,                                                 #C
        );
    $_size += 1;
    return ($_size);
}

sub __compile_bytes_val2 ($$$$$$;$$) {
    #? compiles a val2 bytes value field
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    my $_size = 0;
    _trace4_ (" " x $__indent . "# SSLhello: __compile_bytes_val2 for '$__pdu_name'     ($$__format_pos_ref, $$__param_pos_ref)\n");
    return (0) if (! defined ($__param_ref->[$$__param_pos_ref]) ); # no value
    my $__val = $__param_ref->[$$__param_pos_ref++];
    _trace4_ (_decode_val ("%04X", \$__val, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . " (val2)\n");
    carp("$STR{WARN} SSLhello::__compile_bytes_val2 for '$__pdu_name': value $__val too big\n") if ($__val > 0xFFFF); ### TBD: add WARNING Nr
    $$__buffer_ref .= pack ("n",
            $__val,                                                 #n
        );
    $_size += 2;
    return ($_size);
}

sub __compile_bytes_val4 ($$$$$$;$$) {
    #? compiles a val4 bytes value field
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    my $_size = 0;
    _trace4_ (" " x $__indent . "# SSLhello: __compile_bytes_val4 for '$__pdu_name'     ($$__format_pos_ref, $$__param_pos_ref)\n");
    return (0) if (! defined ($__param_ref->[$$__param_pos_ref]) ); # no value
    my $__val = $__param_ref->[$$__param_pos_ref++];
    _trace4_ (_decode_val ("%04X", \$__val, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . " (val4)\n");
    carp("$STR{WARN} SSLhello::__compile_bytes_val4 for '$__pdu_name': value $__val too big\n") if ($__val > 0xFFFFFFFF); ### TBD: add WARNING Nr
    $$__buffer_ref .= pack ("N",
            $__val,                                                 #N
        );
    $_size += 4;
    return ($_size);
}

sub __compile_bytes_val1List ($$$$$$;$$) {
    #? compiles a value list of val1 bytes
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    my $_size = 0;
    _trace4_ (" " x $__indent . "# SSLhello: __compile_bytes_val1List for '$__pdu_name' ($$__format_pos_ref, $$__param_pos_ref)\n");
    return (0) if (! defined ($__param_ref->[$$__param_pos_ref]) ); # no value
    my @__list = @{$__param_ref->[$$__param_pos_ref++]};
    _trace4_ (_decode_val ("%02X", \@__list, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x ($__indent + 2), " | ", " / ") . " (val1List)\n");
    $$__buffer_ref .= pack ("C" x (@__list),
            @__list,                                                  #C
        );
    $_size += (@__list);
    return ($_size);
}

sub __compile_bytes_val2List ($$$$$$;$$) {
    #? compiles a value list of val2 bytes
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    my $_size = 0;
    _trace4_ (" " x $__indent . "# SSLhello: __compile_bytes_val2List for '$__pdu_name' ($$__format_pos_ref, $$__param_pos_ref)\n");
    return (0) if (! defined ($__param_ref->[$$__param_pos_ref]) ); # no value
    my @__list = @{$__param_ref->[$$__param_pos_ref++]};
    _trace4_ (_decode_val ("%04X", \@__list, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x ($__indent + 2), " | ", " / ") . " (val2List)\n");
    $$__buffer_ref .= pack ("n" x (@__list),
            @__list,                                                  #n
        );
    $_size += 2 * (@__list);
    return ($_size);
}

#? Hash with all subs __compile_bytes_*
#? A self defined general description for the structure of for PDUs, e.g. tls extensions:
#? len1:     Len of the next bytes, coded in 1 byte      (-> max 0xFF)
#? len2:     Len of the next bytes, coded in 2 bytes     (-> max 0xFFFF)
#? len3:     Len of the next bytes, coded in 3 bytes     (-> max 0xFFFFFF)
#? size1:    Size of the next value, coded in 1 byte     (-> max 0xFF)
#? size2:    Size of the next value, coded in 2 bytes    (-> max 0xFFFF)
#? val1:     value, coded in 1 byte                      (-> max 0xFF)
#? val2:     value, coded in 2 bytes                     (-> max 0xFFFF)
#? val4:     value, coded in 4 byters                    (-> max 0xFFFFFFFF)
#? val1List: List of value, coded in 1 byte              (-> max 0xFF, 0xFF, ...)
#? val2List: List of value, coded in 2 bytes             (-> max 0xFFFF, 0xFFFF, ...)
#? raw:      Raw bytes (number needs to be previously defined by a len or size element)
#? sequence: Sequence of structured elements that form lists of compound values
my %__compile_bytes_subs = (
    len1        => \&__compile_bytes_len1,
    len2        => \&__compile_bytes_len2,
    len3        => \&__compile_bytes_len3,
    raw         => \&__compile_bytes_raw,
    sequence    => \&__compile_bytes_sequence,
    size1       => \&__compile_bytes_size1,
    size2       => \&__compile_bytes_size2,
    val1        => \&__compile_bytes_val1,
    val2        => \&__compile_bytes_val2,
    val4        => \&__compile_bytes_val4,
    val1List    => \&__compile_bytes_val1List,
    val2List    => \&__compile_bytes_val2List,
);


sub _compileNextByte ($$$$$$;$$) {
    #? compiles the next byte(s) to a PDU, e.g. extension
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $_size = 0;
    return (0) if (! defined ($__format_ref->[$$__format_pos_ref]) );
    if ($__compile_bytes_subs{$__format_ref->[$$__format_pos_ref]}) {
        $_size = $__compile_bytes_subs{$__format_ref->[$$__format_pos_ref]}->($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref, $__format_text_ref, $__indent);
        _trace5_ ("\n");
    } else {
        carp("$STR{WARN} SSLhello::_compileNextByte  for '$__pdu_name': \'No such format sub: $__format_ref->[$$__format_pos_ref]\', => Please verify hash 'CH'-format definition in OCfg.pm e.g. in \%TLS_EXTENSIONS");
    }
    _trace4_ (" " x ($__indent + 3). "# SSLhello: _CompileNextByte for '$__pdu_name' ->" . _sprintf_hex_val ("", $__buffer_ref, ($__indent + 31)) ."\n" );
    $$__format_pos_ref++;                                           # Next format element
    return ($_size);
}

sub _compileAllBytes ($$$$$$;$$) {
    #? compile all byte(s) according the $__format_ref and the $__param_ref to a PDU, e.g. extension
    my ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    my $_size = 0;
    while (defined ($__format_ref->[$$__format_pos_ref]) ) {        # $$__format_pos_ref is increased by _compileNextByte and subs '__compile_bytes_*'
        $_size += _compileNextByte ($__pdu_name, $__format_ref, $__param_ref, $__format_pos_ref, $__param_pos_ref, $__buffer_ref, $__format_text_ref, $__indent);
    }
    return ($_size);
}

#? END of: sub subs that compile parts of records, e.g. bytes for extensions ####################


sub _compileClientHelloExtensions ($$$$@) {
    #? compile all ClientHello extensions according $SSLhello::extensions_by_prot->{$ssl},
    #? protocol version and some other global parameters:
    #?      $SSLhello::force_TLS_extensions
    #?      $SSLhello::usereneg
    #?      $SSLhello::double_reneg
    #?      $SSLhello::usesni
    #?      $SSLhello::sni_name
    #?      $SSLhello::use_sni_name
    #?      %OCfg::TLS_EXTENSIONS defines and describes the extensions (add there new extensions if needed)
    #?      $SSLhello::extensions_params_hash{$_extension}: temporary parameters defined for an extension if not empty
    #?
    #?      return ($clientHello_extensions): returns all compiled extensions headed by the total length
    #? ---------------------------------------------------------------------------
    my ($record_version, $version, $ciphers, $host, %clientHello) = @_;
    #my $record_version    = shift || "";
    #my $version    = shift || "";
    #my $ciphers    = shift || "";
    #my $host = shift || "";
    #my (%clientHello) = @_;
    my $clientHello_extensions = "";

    my $ssl = $PROTOCOL_NAME_BY_HEX{$version};
    if (! defined $ssl) {
        $ssl = "--unknown protocol--";
    }
    my $_ext_format_pos     = 0;
    my $_ext_param_pos      = 0;
    my $_extensions_data    = "";
    my $_extensions_params_ref;

    if ( ( ($version == $PROTOCOL_VERSION{'SSLv3'}) && (!$SSLhello::force_TLS_extensions) ) || ($version == $PROTOCOL_VERSION{'SSLv2'}) ) { # prevent to not to use tls extensions with SSLv2 or SSLv3
        _trace2 ("compileClientHelloExtensions: Protocol $ssl does not support TLS extensions including SNI -> no extension added\n");
        return ("");
    }

    if ($SSLhello::usereneg) { # use secure Renegotiation
        my $anzahl = int length ($clientHello{'cipher_spec'}) / 2;
        my @cipherTable = unpack("a2" x $anzahl, $clientHello{'cipher_spec'});
        unless ( ($SSLhello::double_reneg == 0) && (grep {/\x00\xff/x} @cipherTable) ) {       # Protection against double renegotiation info is active
            # do *NOT* send a reneg_info extension if the cipher_spec includes already Signalling Cipher Suite Value (SCSV)
            # "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" {0x00, 0xFF}
            if (!grep {/^renegotiation_info$/x} @{$SSLhello::extensions_by_prot->{$ssl}}) {    # renegotiation_info not listed as extension, yet
                unshift @{$SSLhello::extensions_by_prot->{$ssl}}, 'renegotiation_info';        # Add renegotiation_info extension as 1st extension
            }
            _trace2 ("compileClientHelloExtensions ($ssl): extension renegotiation_info will be added\n");
        } else {
            _trace2 ("compileClientHelloExtensions ($ssl): Extension renegotiation_info will *NOT* be sent as the cipher_spec includes already the Signalling Cipher Suite Value (TLS_EMPTY_RENEGOTIATION_INFO_SCSV {0x00, 0xFF})\n");
            @{$SSLhello::extensions_by_prot->{$ssl}} = grep { $_ ne 'renegotiation_info' } @{$SSLhello::extensions_by_prot->{$ssl}}; # delete all extension elements 'renegotiation_info' for this protocol
        }
    }

    # TBD: optional check if $host is a name and no IP
    if ($SSLhello::usesni) {                                   # allow to test SNI (with version TLSv1 and above or DTLSv09 (OpenSSL pre 0.9.8f), DTLSv1 and above)
    ### data for extension 'Server Name Indication' in reverse order
        $SSLhello::sni_name =~ s/\s*(.*?)\s*\r?\n?/$1/gx if ($SSLhello::sni_name);        # delete spaces, \r and \n
        $SSLhello::use_sni_name = 1 if ( ($SSLhello::use_sni_name == 0) && ($SSLhello::sni_name) && ($SSLhello::sni_name ne "1") ); ###FIX: quickfix until migration of o-saft.pl is compleated (TBD)
        unless ($SSLhello::use_sni_name) {
            $clientHello{'extension_sni_name'}     = $host;                                         # Server Name, should be a Name no IP
        } else {
            $clientHello{'extension_sni_name'}     = ($SSLhello::sni_name) ? $SSLhello::sni_name : ""; # Server Name, should be a Name no IP
        }
        _trace2 ("compileClientHelloExtensions ($ssl): extension server_name for '$clientHello{'extension_sni_name'}' will be added\n");
        $OCfg::TLS_EXTENSIONS{server_name}{DEFAULT}[0][1] = $clientHello{'extension_sni_name'};    # add servername as 2nd parameter of first sequence element; TBD: move to {$cfg}....
        if (!grep {/^server_name$/x} @{$SSLhello::extensions_by_prot->{$ssl}}) {               # sni_name not listed as extension, yet
            unshift @{$SSLhello::extensions_by_prot->{$ssl}}, 'server_name';                   # Add sni_name extension as 1st extension
        }
    } else {
        _trace2 ("compileClientHelloExtensions ($ssl): NO server_name extension will be added\n");
        @{$SSLhello::extensions_by_prot->{$ssl}} = grep { $_ ne 'server_name' } @{$SSLhello::extensions_by_prot->{$ssl}}; # delete all extension elements 'sni_name' for this protocol
    }

    my $_indent = 6;                                                # for trace
    _trace4_ (" " x $_indent . "Compile extensions ($ssl):\n");
    foreach my $_extension (@{$SSLhello::extensions_by_prot->{$ssl}}) {
        $_indent = 6;                                               # reset $_indent
        _trace4_ (" " x $_indent . "extension '$_extension':\n");
        $_extensions_data = "";
        if (defined $OCfg::TLS_EXTENSIONS{$_extension}) {
            _trace4_(" " x $_indent . "ID = ($OCfg::TLS_EXTENSIONS{$_extension}{ID}: CH:");
            if (@{$OCfg::TLS_EXTENSIONS{$_extension}{CH}}) {
                for (my $nr = 0; $nr < (@{$OCfg::TLS_EXTENSIONS{$_extension}{CH}}); $nr++) {
                    _trace4_ (", ") if $nr > 0;
                    _trace4_ ("$OCfg::TLS_EXTENSIONS{$_extension}{CH}[$nr]");
                }
                _trace5_ ("\n" . " " x $_indent . "#  ---> Use temporary defined parameters for extension '$_extension': ". exists ($SSLhello::extensions_params_hash{$_extension}));
                $_extensions_params_ref = (exists ($SSLhello::extensions_params_hash{$_extension})) ? \@{$SSLhello::extensions_params_hash{$_extension}}: \@{$OCfg::TLS_EXTENSIONS{$_extension}{DEFAULT}}; # use special params for this extension if defined
                _trace4_ (" (");
                if (@$_extensions_params_ref)  {
#                    _trace5_ ("\n");
                    for (my $nr = 0; $nr < (@$_extensions_params_ref); $nr++) {
                        my $val = $_extensions_params_ref->[$nr];
                        _trace5_ ("\n" . " " x ($_indent + 2));
                        _trace4_ (_decode_val (undef, \$val, undef, 0, ($_indent + 2) , ":\n" . " " x ($_indent + 2), ", ", " | ", " / ")); #TBD: Check
                    }
                }
                _trace4_ (")):\n");
                $_ext_format_pos     = 0;
                $_ext_param_pos      = 0;
                $_indent            += 3;                           # for trace
                _trace5_(" " x $_indent . _sprintf_hex_val ("ID: 0x%04X", \$OCfg::TLS_EXTENSIONS{$_extension}{ID}, $_indent + 3) . "\n");
                $_extensions_data = pack ("n",
                    $OCfg::TLS_EXTENSIONS{$_extension}{ID},        #n
                );
                _compileAllBytes ($_extension, \@{$OCfg::TLS_EXTENSIONS{$_extension}{CH}}, $_extensions_params_ref, \$_ext_format_pos, \$_ext_param_pos, \$_extensions_data, \@{$OCfg::TLS_EXTENSIONS{$_extension}{CH_TEXT}}, $_indent + 3);
                _trace5_ (" " x ($_indent  + 3). _sprintf_hex_val ("", \$_extensions_data, ($_indent + 6)) . " " x ($_indent). ")\n" );

                _trace5_ ("------------- show the compiled extension --------------\n");
                _parseExtensions ("CH", undef, \$_extensions_data, length($_extensions_data)) if ($SSLhello::trace > 4);  # only for trace purposes
                 $clientHello_extensions .= $_extensions_data;
            }
            _trace4_ ("\n");
        }
    }
    ##### End Test
    $clientHello{'extensions_total_len'} = length($clientHello_extensions);

    if ($clientHello_extensions) {                                  # not empty
        $clientHello_extensions = pack ("n a*",
            length($clientHello_extensions),                        #n
            $clientHello_extensions                                 #a[length($clientHello_extensions)]
        );
        _trace4 (sprintf ("_compileClientHelloExtensions ($ssl) (extensions_total_len = %04X)\n          >", $clientHello{'extensions_total_len'}).hexCodedString ($clientHello_extensions ,"           ")."<\n");
    }
    return ($clientHello_extensions);
} # _compileClientHelloExtensions


#? sub subs that parse parts of records, e.g. bytes for extensions ###############################
    #? sub __parse_bytes_* and _parseNextByte, _parseAllBytes
    #? the following subs use the same set of variables:
    #? $__pdu_name:        for tracing and warnings: name of the PDU that is parsed, eg. extension
    #? $__format_ref:      reference to an array including the format of the PDU, %__parse_bytes_subs maps the format names to the sub functions
    #? $__param_hash_ref:  reference to an hash that stores the parsed values
    #? $__format_pos_ref:  reference to the position in the array $__format_ref->[pos]
    #? $__buffer_ref:      reference to the buffer that is going to be parsed
    #? $__buffer_size:     size of the buffer
    #? optional:
    #? $__format_text_ref: reference to an array describing the semantic of the parts of the PDU
    #? $__indent:          indent for tracing
    #? use this subs via '%__parse_bytes_subs' a self defined general description for the structure of for PDUs, e.g. tls extensions

sub __parse_bytes_len1 ($$$$$$;$$) {
    #? parses a len1 bytes field
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $__next_data = "";
    my $__len;

    _trace4_ (" " x $__indent);
    _trace4  ("__parse_bytes_len1 for '$__pdu_name'      ($$__format_pos_ref, $__buffer_size)\n");
    return (0) if ($__buffer_size < 1);
    ($__len,                                                        #C
     $$__buffer_ref) = unpack("C a*", $$__buffer_ref);
    _trace2_ (_decode_val ("%02X", \$__len, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . "\n");
    $$__format_pos_ref++;                                           # Next format element
    ($__next_data,                                                  #a[$len]
     $$__buffer_ref) = unpack("a[$__len] a*", $$__buffer_ref);
    _parseAllBytes ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, \$__next_data, $__len, $__format_text_ref, $__indent + 3) if ($__len > 0);
    $__buffer_size -= (1 + $__len);
    return ($__buffer_size);
}

sub __parse_bytes_len2 ($$$$$$;$$) {
    #? parses a len2 bytes field
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $__next_data = "";
    my $__len;

    _trace4_ (" " x $__indent);
    _trace4  ("__parse_bytes_len2 for '$__pdu_name'      ($$__format_pos_ref, $__buffer_size)\n");
    return (0) if ($__buffer_size < 2);
    ($__len,                                                        #n
     $$__buffer_ref) = unpack("n a*", $$__buffer_ref);
    _trace2_ (_decode_val ("%04X", \$__len, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . "\n");
    $$__format_pos_ref++;                                           # Next format element
    ($__next_data,                                                  #a[$len]
     $$__buffer_ref) = unpack("a[$__len] a*", $$__buffer_ref);
    _parseAllBytes ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, \$__next_data, $__len, $__format_text_ref, $__indent + 3) if ($__len > 0);
    $__buffer_size -= (2 + $__len);
    return ($__buffer_size);
}

sub __parse_bytes_len3 ($$$$$$;$$) {
    #? parses a len3 bytes field
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $__next_data = "";
    my $__len;
    my $__len1;
    my $__len2;

    _trace4_ (" " x $__indent);
    _trace4  ("__parse_bytes_len3 for '$__pdu_name'      ($$__format_pos_ref, $__buffer_size)\n");
    return (0) if ($__buffer_size < 3);
    ($__len1,                                                       #C
     $__len2,                                                       #n
     $$__buffer_ref) = unpack("C n a*", $$__buffer_ref);
    $__len  = $__len1 << 16;
    $__len += $__len2;
    _trace2_ (_decode_val ("%06X", \$__len, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . "\n");
    $$__format_pos_ref++;                                           # Next format element
    ($__next_data,                                                  #a[$len]
     $$__buffer_ref) = unpack("a[$__len] a*", $$__buffer_ref);
    _parseAllBytes ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, \$__next_data, $__len, $__format_text_ref, $__indent + 3) if ($__len >0);
    $__buffer_size -= (3 + $__len);
    return ($__buffer_size);
}

sub __parse_bytes_raw ($$$$$$;$$) {
    #? parses a raw bytes field
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $_hex_str = "";

    _trace4_ (" " x $__indent);
    _trace4  ("__parse_bytes_raw for '$__pdu_name'       ($$__format_pos_ref, $__buffer_size)\n");
    return (0) if ($__buffer_size < 1);                             # nothing to parse
    return (0) if ($__buffer_size > length ($$__buffer_ref));       #TBD: Warn
    (my $__val,                                                     #n
     $$__buffer_ref) = unpack("a[$__buffer_size] a*", $$__buffer_ref);
    _trace2_ (_decode_val ("", \$__val, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . "\n");
    if ( (defined ($__param_hash_ref)) && (ref($__param_hash_ref) eq "HASH") ) {
        push @{$__param_hash_ref->{values}}, $__val;                        # array of values
        push @{$__param_hash_ref->{format_positions}}, $$__format_pos_ref;  # array of format positions
    }
    # $__buffer_size = length ($$__buffer_ref);
    return (0);
}

sub __parse_bytes_sequence ($$$$$$;$$) {
    #? parses a sequence of bytes fields
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $__sequence_pos = 0;
    my %__sequence_param_hash;
    my $__sequence_param_hash_ref = (defined ($__param_hash_ref))? \%__sequence_param_hash : undef;   # (condition)? <value if true> : <value if false>

    _trace4_ (" " x $__indent);
    _trace4  ("__parse_bytes_sequence for '$__pdu_name'  ($$__format_pos_ref, $__buffer_size):\n");
    _trace4_ (_decode_val (undef, undef, $__format_text_ref->[$$__format_pos_ref], ($__indent + 3), ($__indent + 3), ":\n" . " " x ($__indent + 3), ",\n" . " " x ($__indent + 3), " | ", " / ") . "\n");
    $$__format_pos_ref++;                                           # Next format element
    $__sequence_pos = $$__format_pos_ref;                           # store start position of sequence
    my $_counter = 0;
    while (defined ($$__buffer_ref) && ($__buffer_size > 0)) {      # still data
        $$__format_pos_ref = $__sequence_pos;                       # reset format_pos to first element of sequence format
        _trace4_ (" " x $__indent);
        _trace4  ("__parse_bytes_sequence: (next) sequence elements for '$__pdu_name' ($$__format_pos_ref, $__buffer_size)\n");
        $__buffer_size = _parseAllBytes ($__pdu_name, $__format_ref, $__sequence_param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size, $__format_text_ref, $__indent);
        if ( (defined ($__param_hash_ref)) && (ref($__param_hash_ref) eq "HASH") ) {
            push @{$__param_hash_ref->{values}},           [$__sequence_param_hash_ref->{values}];    # array of array of values
            push @{$__param_hash_ref->{format_positions}},  $__sequence_param_hash_ref->{format_positions} if ($_counter++ == 0);   # store format positions ony once
        }
    }
    _trace4_ (" " x $__indent);
    _trace4_ ("__parse_bytes_sequence for '$__pdu_name': ------ End of sequence ------\n");
    return ($__buffer_size);
}

sub __parse_bytes_size1 ($$$$$$;$$) {
    #? parses a size1 bytes field and the next value(s)
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $__next_data = "";
    my $__len = 0;

    _trace4_ (" " x $__indent);
    _trace4  ("__parse_bytes_size1 for '$__pdu_name'     ($$__format_pos_ref, $__buffer_size)\n");
    return (0) if ($__buffer_size < 1);
    ($__len,                                                        #C
     $$__buffer_ref) = unpack("C a*", $$__buffer_ref);
    _trace2_ (_decode_val ("%02X", \$__len, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . "\n");
    $$__format_pos_ref++;                                           # Next format element
    ($__next_data,                                                  #a[$len]
     $$__buffer_ref) = unpack("a[$__len] a*", $$__buffer_ref);
    _parseNextByte ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, \$__next_data, $__len, $__format_text_ref, $__indent + 3) if ($__len >0);
    $__buffer_size -= (1 + $__len);
    return ($__buffer_size);
}

sub __parse_bytes_size2 ($$$$$$;$$) {
    #? parses a size2 bytes field and the next value(s)
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $__next_data = "";
    my $__len = 0;

    _trace4_ (" " x $__indent);
    _trace4  ("__parse_bytes_size2 for '$__pdu_name'     ($$__format_pos_ref, $__buffer_size)\n");
    return (0) if ($__buffer_size < 2);
    ($__len,                                                        #n
     $$__buffer_ref) = unpack("n a*", $$__buffer_ref);
    _trace2_ (_decode_val ("%04X", \$__len, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . "\n");
    $$__format_pos_ref++;                                           # Next format element
    ($__next_data,                                                  #a[$len]
     $$__buffer_ref) = unpack("a[$__len] a*", $$__buffer_ref);
    _parseNextByte ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, \$__next_data, $__len, $__format_text_ref, $__indent + 3) if ($__len >0);
    $__buffer_size -= (2 + $__len);
    return ($__buffer_size);
}

sub __parse_bytes_val1 ($$$$$$;$$) {
    #? parses a val1 bytes value
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    _trace4_ (" " x $__indent);
    _trace4  ("__parse_bytes_val1 for '$__pdu_name':     ($$__format_pos_ref, $__buffer_size)\n");
    return (0) if ($__buffer_size < 1);
    (my $__val,                                                     #C
     $$__buffer_ref) = unpack("C a*", $$__buffer_ref);
    _trace2_ (_decode_val ("%02X", \$__val, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . "\n");
    if ( (defined ($__param_hash_ref)) && (ref($__param_hash_ref) eq "HASH") ) {
        push @{$__param_hash_ref->{values}}, $__val;                        # array of values
        push @{$__param_hash_ref->{format_positions}}, $$__format_pos_ref;  # array of format positions
    }
    $__buffer_size -= 1;
    return ($__buffer_size);
}

sub __parse_bytes_val2 ($$$$$$;$$) {
    #? parses a val2 bytes value
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    _trace4_ (" " x $__indent);
    _trace4  ("__parse_bytes_val2 for '$__pdu_name':     ($$__format_pos_ref, $__buffer_size)\n");
    return (0) if ($__buffer_size < 2);
    (my $__val,                                                     #n
     $$__buffer_ref) = unpack("n a*", $$__buffer_ref);
    _trace2_ (_decode_val ("%04X", \$__val, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . "\n");
    if ( (defined ($__param_hash_ref)) && (ref($__param_hash_ref) eq "HASH") ) {
        push @{$__param_hash_ref->{values}}, $__val;                        # array of values
        push @{$__param_hash_ref->{format_positions}}, $$__format_pos_ref;  # array of format positions
    }
    $__buffer_size -= 2;
    return ($__buffer_size);
}

sub __parse_bytes_val4 ($$$$$$;$$) {
    #? parses a val4 bytes value
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    _trace4_ (" " x $__indent);
    _trace4  ("__parse_bytes_val4 for '$__pdu_name':     ($$__format_pos_ref, $__buffer_size)\n");
    return (0) if ($__buffer_size < 4);
    (my $__val,                                                     #N
     $$__buffer_ref) = unpack("N a*", $$__buffer_ref);
    _trace2_ (_decode_val ("%08X", \$__val, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x $__indent, " | ", " / ") . "\n");
    if ( (defined ($__param_hash_ref)) && (ref($__param_hash_ref) eq "HASH") ) {
        push @{$__param_hash_ref->{values}}, $__val;                        # array of values
        push @{$__param_hash_ref->{format_positions}}, $$__format_pos_ref;  # array of format positions
    }
    $__buffer_size -= 4;
    return ($__buffer_size);
}

sub __parse_bytes_val1List ($$$$$$;$$) {
    #? parses a list of val1 byte values
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    _trace4_ (" " x $__indent);
    _trace4  ("__parse_bytes_val1List for '$__pdu_name': ($$__format_pos_ref, $__buffer_size):\n");
    return (0) if ($__buffer_size < 1);
    (my $__data,                                                    #(a)
     $$__buffer_ref) = unpack("a[$__buffer_size] a*", $$__buffer_ref);
    (my @__list)     = unpack("C*", $__data);                       #C
    _trace2_ (_decode_val ("%02X", \@__list, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x ($__indent + 2), " | ", " / ") . "\n");
    if ( (defined ($__param_hash_ref)) && (ref($__param_hash_ref) eq "HASH") ) {
        push @{$__param_hash_ref->{values}}, [@__list];                     # array of array of values
        push @{$__param_hash_ref->{format_positions}}, $$__format_pos_ref;  # array of format positions
    }
    $__buffer_size -= (@__list);                                    # 0
    return ($__buffer_size);
}

sub __parse_bytes_val2List ($$$$$$;$$) {
    #? parses a list of val2 bytes values
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    _trace4_ (" " x $__indent);
    _trace4  ("__parse_bytes_val2List for '$__pdu_name': ($$__format_pos_ref, $__buffer_size):\n");
    return (0) if ($__buffer_size < 2);
    (my $__data,                                                    #(a)
     $$__buffer_ref) = unpack("a[$__buffer_size] a*", $$__buffer_ref);
    (my @__list)     = unpack("n*", $__data);                       #n
    _trace2_ (_decode_val ("%04X", \@__list, $__format_text_ref->[$$__format_pos_ref], $__indent, $__indent, ":\n" . " " x $__indent, ",\n" . " " x ($__indent + 2), " | ", " / ") . "\n");
    if ( (defined ($__param_hash_ref)) && (ref($__param_hash_ref) eq "HASH") ) {
        push @{$__param_hash_ref->{values}}, [@__list];                     # array of array of values
        push @{$__param_hash_ref->{format_positions}}, $$__format_pos_ref;  # array of format positions
    }
    $__buffer_size -= 2 * (@__list);                                # 0
    return ($__buffer_size);
}

# Hash with all subs __parse_bytes_*_
#? A self defined general description for the structure of for PDUs, e.g. tls extensions:
#? len1:     Len of the next bytes, coded in 1 byte      (-> max 0xFF)
#? len2:     Len of the next bytes, coded in 2 bytes     (-> max 0xFFFF)
#? len3:     Len of the next bytes, coded in 3 bytes     (-> max 0xFFFFFF)
#? size1:    Size of the next value, coded in 1 byte     (-> max 0xFF)
#? size2:    Size of the next value, coded in 2 bytes    (-> max 0xFFFF)
#? val1:     value, coded in 1 byte                      (-> max 0xFF)
#? val2:     value, coded in 2 bytes                     (-> max 0xFFFF)
#? val4:     value, coded in 4 byters                    (-> max 0xFFFFFFFF)
#? val1List: List of value, coded in 1 byte              (-> max 0xFF, 0xFF, ...)
#? val2List: List of value, coded in 2 bytes             (-> max 0xFFFF, 0xFFFF, ...)
#? raw:      Raw bytes (number needs to be previously defined by a len or size element)
#? sequence: Sequence of structured elements that form lists of compound values

my %__parse_bytes_subs = (
    len1        => \&__parse_bytes_len1,
    len2        => \&__parse_bytes_len2,
    len3        => \&__parse_bytes_len3,
    raw         => \&__parse_bytes_raw,
    sequence    => \&__parse_bytes_sequence,
    size1       => \&__parse_bytes_size1,
    size2       => \&__parse_bytes_size2,
    val1        => \&__parse_bytes_val1,
    val2        => \&__parse_bytes_val2,
    val4        => \&__parse_bytes_val4,
    val1List    => \&__parse_bytes_val1List,
    val2List    => \&__parse_bytes_val2List,
);

sub _parseNextByte ($$$$$$;$$) {
    #? parse the next byte(s)
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;
    my $_hex_str = "";

    _trace5_ (" " x ($__indent). "_parseNextByte for '$__pdu_name' ($$__format_pos_ref, $__buffer_size)\n" );
    return ($__buffer_size) if ($$__format_pos_ref >= (@$__format_ref));
    return (0) if (! defined ($__format_ref->[$$__format_pos_ref]) );
    return (0) if ($__buffer_size < 1);
    if ($__parse_bytes_subs{$__format_ref->[$$__format_pos_ref]}) {
        $__buffer_size = $__parse_bytes_subs{$__format_ref->[$$__format_pos_ref]}->($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size, $__format_text_ref, $__indent);
    } else {
        carp("$STR{WARN} SSLhello::_parseNextByte ($__pdu_name): \'No such format sub: $__format_ref->[$$__format_pos_ref]\', => Please verify hash format definition in OCfg.pm e.g. in \%TLS_EXTENSIONS");
    }
    $$__format_pos_ref++;                                           # Next format element
    return ($__buffer_size);
}

sub _parseAllBytes ($$$$$$;$$) {
    #? parse all byte(s) according the $__buffer_size
    my ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size) = (shift, shift, shift, shift, shift, shift);
    my $__format_text_ref   = shift;
    my $__indent            = shift || 0;

    _trace5_ (" " x ($__indent). "_parseAllBytes for '$__pdu_name' ($$__format_pos_ref, $__buffer_size)\n");
    while ( ($$__format_pos_ref < (@$__format_ref)) && (defined ($__format_ref->[$$__format_pos_ref])) && ($__buffer_size > 0) ) {
        $__buffer_size = _parseNextByte ($__pdu_name, $__format_ref, $__param_hash_ref, $__format_pos_ref, $__buffer_ref, $__buffer_size, $__format_text_ref, $__indent);
    }
    return ($__buffer_size);
}

#? END of: sub subs that parse parts of records, e.g. bytes for extensions ####################

sub _parseExtensions ($$$$;$$) {
    #? Parse one or more TLS extensions according %OCfg::TLS_EXTENSIONS and its reverse hash %OCfg::TLS_ID_TO_EXTENSIONS
    #? and store the values in the hash $_param_hash_ref->{$_extension}{$_ext_ch_rx} if defined
    #? redundant values and value arrays are skipped
    #? $_ext_ch_rx:       Clienthello 'CH' or received record 'RX'
    #? $_param_hash_ref:  Reference to a hash where store the parsed results or undef if not needed
    #? $_buffer_ref:      Reference to the data buffer that will be parsed
    #? $_buffer_size:     size of the buffer:
    #?                    >=0: The extension data starts with the first extension or is empty
    #?                    < 0: The extension data starts with the length field for all extensions
    #? optional:
    #? $protocolCipher:   internal Hex value of the cipher, for tracing
    #? $_indent:          indent for tracing, default = 12
    #? ---------------------------------------------------------------------------
    my ($_ext_ch_rx, $_param_hash_ref, $_buffer_ref, $_buffer_size) = (shift, shift, shift, shift);
    my $protocolCipher      = shift || "";
    my $_indent             = shift || 12;
    my $_format_pos         = 0;
    my $_name               = "_parseExtensions: ";
    my $_extensions_data    = $$_buffer_ref;                        # do not chance referenced data
    my @__local_format_text = ( \%OCfg::TLS_ID_TO_EXTENSIONS );    # array with a reference to the reverse TLS_EXTENSIONS hash
    my $__local_format_pos  = 0;                                    # use first element to decode extension type

    _trace4_ (" " x $_indent . "# SSLhello::_parseExtensions ():\n");
    if (($_buffer_size < 0) && (length ($_extensions_data) > 2)) {  # get the 2 bytes len from $_extension_data
        ($_buffer_size,                                             #n
         $_extensions_data) = unpack("n a*", $_extensions_data);
        _trace2_ (_decode_val ("%04X", \$_buffer_size, "length of extensions", $_indent, $_indent, ":\n" . " " x $_indent, ",\n" . " " x $_indent, " | ", " / ") . "\n");
        $_indent += 3;
    }
    PARSE_EXTENSION: while ($_buffer_size > 2) {
        $__local_format_pos = 0;                                    # no extension type selected, yet
        $_format_pos        = 0;                                    # reset to first format element of an extension type
        my %_extension_type_hash;
        $_extension_type_hash{values}            = ();              # reset array to store values
        $_extension_type_hash{format_positions}  = ();              # reset array to store format positions
        $_buffer_size       = __parse_bytes_val2 ($_name, undef, \%_extension_type_hash, \$__local_format_pos, \$_extensions_data, $_buffer_size, \@__local_format_text, $_indent);  # get extensions type
        if (!defined ($_extension_type_hash{values}[0])) {          # found no extension
            carp("$STR{WARN} SSLhello::_parseExtensions: warn: no (more) defined extensionus found parsing the record\n");
            next PARSE_EXTENSION;
        }
        my $_extension      = $OCfg::TLS_ID_TO_EXTENSIONS{$_extension_type_hash{values}[0]}[0]; # get Extension type from $extension{description}[0]
        $_extension         = "-- unknown (" . $_extension_type_hash{values}[0] . ") --" if (!defined ($_extension));
        _trace5_ (" " x ($_indent + 4) . "== Extension '$_extension' ($_extension_type_hash{values}[0]):\n");

        my %_param_hash;
        $_param_hash{values}            = ();                       # initialize array to store values
        $_param_hash{format_positions}  = ();                       # initialize array to store format positions
        $_buffer_size       = _parseAllBytes ($_extension, \@{$OCfg::TLS_EXTENSIONS{$_extension}{$_ext_ch_rx}}, \%_param_hash, \$_format_pos, \$_extensions_data, $_buffer_size, \@{$OCfg::TLS_EXTENSIONS{$_extension}{"$_ext_ch_rx"."_TEXT"}}, $_indent + 3);
        next PARSE_EXTENSION if (!defined ($_param_hash_ref));# do not store the results
        _trace5_ (" " x ($_indent + 4) . "#      ---> _parseExtensions: ref (\$_param_hash_ref) = " . ref ($_param_hash_ref) ."\n" );#
        next PARSE_EXTENSION if (ref ($_param_hash_ref) ne "HASH");                 # reference is no hash
        _trace5_ (" " x ($_indent + 4) . "#      ---> format:           \@{\$_param_hash{format_positions}} = "
                  . _decode_val (undef, \@{$_param_hash{format_positions}}, undef, 0, $_indent + 4, ":\n" . " " x ($_indent + 4), ", ", " | ", " / ") . "\n");
        _trace5_ (" " x ($_indent + 4) . "#      ---> raw value:        \@{\$_param_hash{values}}           = "
                  . _decode_val (undef, \@{$_param_hash{values}},           undef, 0, $_indent + 4, ":\n" . " " x ($_indent + 4), ", ", " | ", " / ") . "\n");
        _trace5_ (" " x ($_indent + 4) . "#      ---> Complex format: (\@{\$_param_hash{format_positions}}) = " . (@{$_param_hash{format_positions}}) . " > 1?\n");
        if ( (@{$_param_hash{format_positions}}) > 1) {             # complex format => array of arrays
            @{$_param_hash{values}} = [@{$_param_hash{values}}];    # store values of complex parameter formats as array of arrays
        } elsif (ref ($_param_hash{values}[0]) eq 'ARRAY') {        # simple format for 1 format results
            @{$_param_hash{values}} = $_param_hash{values}[0];      # so one answer with val1/2List = multible anwers with val1 or val2
        }
        _trace5_ (" " x ($_indent + 4) . "#      ---> standardized value(s): \@{\$_param_hash{values}}      = "
                  . _decode_val (undef, \@{$_param_hash{values}},           undef, 0, $_indent + 4, ":\n" . " " x ($_indent + 4), ", ", " | ", " / ") . "\n"); # ready to store value

        if (! exists($_param_hash_ref->{$_extension}{$_ext_ch_rx}) ) { # first %_param_hash
            _trace4_ (" " x ($_indent + 4) . "#      ===> store first results in \%{\$_param_hash_ref->{$_extension}{$_ext_ch_rx}}\n");
            $_param_hash_ref->{$_extension}{$_ext_ch_rx} = \%_param_hash; # add sub hash to $_param_hash_ref->{$_extension}{$_ext_ch_rx}
            _trace4_ (" " x ($_indent + 4) . "#      ===> value(s):     \@{\$_param_hash{values}}           = "
                  . _decode_val (undef, \@{$_param_hash{values}},           undef, 0, $_indent + 4, ":\n" . " " x ($_indent + 4), ", ", " | ", " / ") . "\n");
            _trace4_ (" " x ($_indent + 4) . "#      ===> format(s):    \@{\$_param_hash{format_positions}} = "
                  . _decode_val (undef, \@{$_param_hash{format_positions}}, undef, 0, $_indent + 4, ":\n" . " " x ($_indent + 4), ", ", " | ", " / ") . "\n");
        } else { # check if formats are identical and if values have not been stored before
            _trace5_ (" " x ($_indent + 4) . "#      ---> Check if format is a SCALAR:       ref (\\\$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}[0]) = '" . ref (\$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}[0]) . "'\n");
            _trace5_ (" " x ($_indent + 4) . "#      ---> Check if format is a nested array: ref (\$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}[0]) =  '" . ref ($_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}[0]) . "'\n");
            if (ref (\$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}[0]) eq 'SCALAR') {    # format is no nested array
                _trace5_ (" " x ($_indent + 4) . "#      ---> merge new results and format_positions with hash '\$_param_hash_ref->{$_extension}{$_ext_ch_rx}}'\n");
                my $found = 1;                                  # 1: true
                _trace5_ (" " x ($_indent + 4) . "#      ---> (\@{\$_param_hash{format_positions}}) (" . (@{$_param_hash{format_positions}})
                          . ") == (\@{\$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}}) ) (" . (@{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}}) . ")?\n");
                next PARSE_EXTENSION if ( (@{$_param_hash{format_positions}}) == 0); # format is empty = nothing to add => parse next extension
                if ( (@{$_param_hash{format_positions}}) == (@{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}}) ) { # the number of format_positions is identical: necessary condition
                    CHECK_FORMAT: for (my $__pos = 0; $__pos < (@{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}}); $__pos++) {   # check if all format positions are identical
                       _trace5_ (" " x ($_indent + 4) . "#      ---> \$_param_hash{format_positions}[$__pos] (" . $_param_hash{format_positions}[$__pos]
                                 . ") == \$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}[$__pos] (" . $_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}[$__pos] . ")?\n");
                       if ($_param_hash{format_positions}[$__pos] ne $_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}[$__pos]) { # format is not equal
                            # TBD: different format: move stored format to 1st emement of a nested array, add new sequence of new formats to 2nd element; Do the same with the values
                            _trace4_ (" " x ($_indent + 4) . "#      ---> merging values and format_positions to the result hash with different format sequences is not yet implemented! New values are lost: "
                                      . _decode_val (undef, \@{$_param_hash{values}}, $OCfg::TLS_EXTENSIONS{$_extension}{"$_ext_ch_rx"."_TEXT"}[$_format_pos], 0, $_indent + 17, ", ", " | ", " / ") . "\n");
                            carp("$STR{WARN} SSLhello::_parseExtensions: merging values and format_positions to the result hash with different format sequences is not yet implemented! New values are lost: "
                                      . _decode_val (undef, \@{$_param_hash{values}}, $OCfg::TLS_EXTENSIONS{$_extension}{"$_ext_ch_rx"."_TEXT"}[$_format_pos], 0, $_indent + 17, ", ", " | ", " / ") ."\n");
                            $found = 0; # false
                            last CHECK_FORMAT; # exit the loop
                       }
                    } # CHECK_FORMAT: for ...
                    if ($found > 0) {                               # format is identical
                        _trace5_ (" " x ($_indent + 4) . "#      ---> check for new results to be stored in '\$_param_hash_ref->{$_extension}{$_ext_ch_rx}}'\n");
                        _trace5_ (" " x ($_indent + 4) . "#      ---> number of values to check: (\@{\$_param_hash{values}}) (" . (@{$_param_hash{values}})
                                . ") <=> (\@{\$_param_hash_ref->{$_extension}{$_ext_ch_rx}{values}}) ) (" . (@{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{values}}) . ")?\n");
                        next PARSE_EXTENSION if ( (@{$_param_hash{values}}) == 0); # values are empty = nothing to add => parse next extension
                        FOREACH_NEW_VALUE: foreach my $_new_ele (@{$_param_hash{values}}) { # all new values or arrys of values
                            _trace5_ (" " x ($_indent + 4)."#        ---|> new values-ref-type (\\\$new_ele):       >".ref(\$_new_ele)."<|\n");
                            _trace5_ (" " x ($_indent + 4)."#        --||> new values-ref-type (\$new_ele):        >".ref($_new_ele)."<||\n");
                            FOREACH_STORED_VALUE: foreach my $_stored_ele (@{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{values}}) { # all stored values or arrys of values
                                _trace5_ (" " x ($_indent + 4)."#        ---|> stored values-ref-type (\\\$stored_ele): >".ref(\$_stored_ele)."<|\n");
                                _trace5_ (" " x ($_indent + 4)."#        --||> stored values-ref-type (\$stored_ele):   >".ref($_stored_ele) ."<||\n");
                                if ( (ref (\$_new_ele) eq "SCALAR") && (ref (\$_stored_ele) eq "SCALAR") ) {        # both arrays are an simple array
                                    _trace5_ (" " x ($_indent + 4)."#        ---> check if value is new (\$new_ele): '" . _decode_val (undef, \$_new_ele, undef, 0, $_indent + 4, ", ", " | ", " / ")
                                              . "' == (\$_stored_ele): '" . _decode_val (undef, \$_new_ele, undef, 0, $_indent + 4, ", ", " | ", " / ") . "'?\n");
                                    next FOREACH_STORED_VALUE if ($_new_ele ne $_stored_ele);
                                    # value is identical
                                    _trace5_ (" " x ($_indent + 4) . "#        ---> \$_new_ele (" . _decode_val (undef, \$_new_ele, undef, 0, $_indent + 4, ", ", " | ", " / ") . ") has been alteady stored. Try next ele.\n");
                                    next FOREACH_NEW_VALUE;
                                } elsif ( (ref ($_new_ele) eq "ARRAY") && (ref ($_stored_ele) eq "ARRAY") ) {       # both arrays are nested arrays (arrays of arrays)
                                    FOREACH_POSITION: foreach my $__pos (0..$#{$_param_hash{format_positions}}) {   # all values = all format positions
                                        _trace5_ (" " x ($_indent + 4) . "#        ---> \$_new_ele[$__pos] (" . _decode_val (undef, \@{$_new_ele}[$__pos], undef, 0, $_indent + 4, ", ", " | ", " / ") . ") == \$_stored_ele[$__pos] (" . _decode_val (undef, \@{$_stored_ele}[$__pos], undef, 0, $_indent + 4, ", ", " | ", " / ") . ")?\n");
                                        next FOREACH_STORED_VALUE if (@{$_new_ele}[$__pos] ne @{$_stored_ele}[$__pos]);   # value is not equal
                                    } # FOREACH_POSITION
                                    # all positions are identical
                                    next FOREACH_NEW_VALUE; # check next new value
                                } else {
                                    _trace (" " x ($_indent + 4)."**WARNING: SSLhello::_parseExtensions: internal error in result hash: new values-ref-type (\$_new_ele):       ".ref(\$_new_ele)."<| !=  (\$_stored_ele): ".ref(\$_stored_ele)."<| OR both neiter a SCALAR nor an ARRAY\n");
                                    carp("$STR{WARN} SSLhello::_parseExtensions: internal error in result hash: can't compare and store new values: "
                                          . _decode_val (undef, \$_new_ele, undef, 0, $_indent + 4, ", ", " | ", " / ") . "\n");
                                    next FOREACH_NEW_VALUE; # check next new value # TBD check if 'next' should change to 'last'?
                                } # if ref \$new_ele ...
                            } # FOREACH_STORED_VALUE
                            # new_ele is new => store a new value array
                            _trace4_ (" " x ($_indent + 4) . "#      ===> add new value (array) to the result hash: " . _decode_val (undef, \$_new_ele, undef, 0, $_indent + 4, ", ", " | ", " / ") . "\n");
                            push @{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{values}}, $_new_ele; # store new value array to nested result array
                        } # FOREACH_NEW_VALUE
                    }
                } # number of format positions is identical
            } else { # nested format arrays => not used and not implemented, yet!
                _trace4_ (" " x ($_indent + 4) . "#      ---> merging values and format_positions to the result hash with various formats is not yet implemented! New values are lost: "
                          . _decode_val (undef, \@{$_param_hash{values}}, undef, 0, $_indent + 17, ", ", " | ", " / ") ."\n");
                carp("$STR{WARN} SSLhello::_parseExtensions: merging values and format_positions to the result hash with various formats is not yet implemented! New values are lost: "
                          . _decode_val (undef, \@{$_param_hash{values}}, undef, 0, $_indent + 17, ", ", " | ", " / ") ."\n");
            }
        } # end of check if formats are identical and if values have not been stored before
        _trace5_ (" " x ($_indent + 4) . "# -> values           = " . @{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{values}} . "\n");
        _trace5_ (" " x ($_indent + 4) . "# -> format_positions = " . @{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}} . "\n");
        _trace5_ (" " x ($_indent + 4) . "# ---> _parseExtensions: \@{\$_param_hash_ref->{$_extension}{$_ext_ch_rx}{values}}          = "
                  . _decode_val (undef, \@{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{values}},           undef, 0 , $_indent + 4, ":\n" . " " x ($_indent + 4), ", ", " | ", " / ") . "\n");
        _trace5_ (" " x ($_indent + 4) . "# ---> _parseExtensions: \@{\$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions} = "
                  . _decode_val (undef, \@{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}}, undef, 0 , $_indent + 4, ":\n" . " " x ($_indent + 4), ", ", " | ", " / ") . "\n\n");

        _trace2_ (" " x ($_indent + 4) . "# ===> Cipher '$protocolCipher', Extension '$_extension': accumulated $_ext_ch_rx values (" . @{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{values}}
                  . "): " . _decode_val (undef, \@{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{values}},           undef, 0 , $_indent + 4, ":\n" . " " x ($_indent + 4), ", ", " | ", " / ") . "\n");
        _trace2_ (" " x ($_indent + 4) . "# ===> Cipher '$protocolCipher', Extension '$_extension': $_ext_ch_rx format positions   (" . @{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}}
                  . "): " . _decode_val (undef, \@{$_param_hash_ref->{$_extension}{$_ext_ch_rx}{format_positions}}, undef, 0 , $_indent + 4, ":\n" . " " x ($_indent + 4), ", ", " | ", " / ") . "\n\n");
    } # end of PARSE_EXTENSION
    return;
} # _parseExtensions


sub _doCheckAllExtensions ($$$$;$) {
    #? simulate SSL handshake to check any extensions for a dedicated cipher
    #? called by checkSSLciphers to check some extensions by the call
    #
    my $host            = shift || ""; # hostname
    my $port            = shift || 443;
    my $protocol        = shift || 0;  # 0x0002, 0x3000, 0x0301, 0x0302, 0x0303, etc
    my $cipher          = shift || "";
    my $dtls_epoch      = shift || 0;  # optional, used in DTLS only
    my $parseAllRecords = 1;           # read, parse and analyse all received records (-> 1)
    my $found_values    = 0;
    my $acceptedCipher;
    my $_last_extension = "";
    my $protocolCipher  = '0x0300'.hexCodedCipher($cipher);

    _trace4_ ("_doCheckAllExtensions {(Cipher: " . hexCodedCipher($cipher) . "):\n");
    return if (!$cipher);
    foreach my $_extension (@{$SSLhello::check_extensions}) {
        _trace4_ ("#  ---> _doCheckAllExtensions: extension '$_extension': ");
        next if ( (! exists ($_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values})) || ((@{$_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values}}) < 1) );
        $_last_extension = $_extension;
        for (my $_i = 0; $_i < (@{$OCfg::TLS_EXTENSIONS{$_extension}{DEFAULT}} ); $_i++) { # copy all values of 2 dim array
            for (my $_j = 0; $_j < (@{$OCfg::TLS_EXTENSIONS{$_extension}{DEFAULT}[$_i]} ); $_j++) {
                $SSLhello::extensions_params_hash{$_extension}[$_i][$_j] = $OCfg::TLS_EXTENSIONS{$_extension}{DEFAULT}[$_i][$_j]; # copy default value
            }
            _trace5_ (" (copied values         = [$_i][" . (@{$SSLhello::extensions_params_hash{$_extension}[$_i]}) . "], ");
        }
        _trace5_ (" parameter arrays       = " . (@{$SSLhello::extensions_params_hash{$_extension}}) . "/" . (@{$OCfg::TLS_EXTENSIONS{$_extension}{DEFAULT}}) . ", ");
        _trace5_ (" format_positions       = " . (@{$_SSLhello{$protocolCipher}{param}{$_extension}{RX}{format_positions}}) . ", ") if (exists ($_SSLhello{$protocolCipher}{param}{$_extension}{RX}{format_positions}) );
        _trace5_ (" found values           = " . (@{$_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values}}) ) if (exists ($_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values}) );
        _trace5_ ("):\n");
        if ((@{$OCfg::TLS_EXTENSIONS{$_extension}{DEFAULT}}) == 1) {
##        if ( ((@{$OCfg::TLS_EXTENSIONS{$_extension}{DEFAULT}}) == 1)
##          && (exists ($SSLhello::{param}{$_extension}{RX}{format_positions}) )
##          && ((@{$SSLhello::{param}{$_extension}{RX}{format_positions}}) == 1)) { # only one parameter array ([0][x]) as default and only one dimensional result array ### }
            _trace5_ ("#    ---> extension '$_extension':\n");
            $found_values = 0;
            while ( (exists ($_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values})) && ((@{$_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values}}) > $found_values) ) { # received a new value
                _trace5_ ("#     ---> parameter arrays[0]    = " . (@{$SSLhello::extensions_params_hash{$_extension}[0]}) . "/" . (@{$OCfg::TLS_EXTENSIONS{$_extension}{DEFAULT}[0]}) . "\n");
                _trace5_ ("#     ---> parameter values type  = " . (ref($_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values})) . "\n");
                last if (!defined($_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values}->[$#{$_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values}}]) ); # found value is not defined => Exit Loop
                last if (!(grep { $_ eq $_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values}->[$#{$_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values}}] } @{$SSLhello::extensions_params_hash{$_extension}[0]})); # found value has NOT been in the offered list => Exit Loop
                $found_values++;
                _trace5_ ("#     ---> extension found $found_values value(s) " . _decode_val (undef, \@{$_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values}}, \$OCfg::TLS_EXTENSIONS{$_extension}, 12, 12, ": ", ", ", " | ", " / ") . "\n");
                @{$SSLhello::extensions_params_hash{$_extension}[0]} = grep { $_ ne $_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values}->[$#{$_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values}}] }
                                                                                   @{$SSLhello::extensions_params_hash{$_extension}[0]};  # delete accepted cipher from ToDo-Array '@cipherSpecArray'
                _trace5_ ("#     ---> extensions_params_hash: " . _decode_val (undef, \@{$SSLhello::extensions_params_hash{$_extension}[0]}, \$OCfg::TLS_EXTENSIONS{$_extension}, 12, 12, ": ", ", ", " | ", " / ") . "\n");

                last if ( (@{$SSLhello::extensions_params_hash{$_extension}[0]}) < 1); # no more elements to check
                if ($found_values > $SSLhello::extensions_max_values) { ## protect ftom staying in an endless loop
                    _trace2_ ("**WARNING: SSLhello::_doCheckAllExtension ($_extension): To much checks for this extension. Watchdog aborted checks after getting $found_values values.\n**Hint: Please verify the hash '%OCfg::TLS_EXTENSIONS' and the variable '\$SSLhello::check_extensions', or '\$SSLhello::extensions_max_values' if necessary.\n");
                    carp("$STR{WARN} SSLhello::_doCheckAllExtension ($_extension): To much checks for this extension. Watchdog aborted checks after getting $found_values values.\n**Hint: Please verify the hash '%OCfg::TLS_EXTENSIONS' and the variable '\$SSLhello::check_extensions', or '\$SSLhello::extensions_max_values' if necessary.\n");
                    last; ## protect ftom staying in an endless loop
                }
                _trace5_ ("#     ---> check next extension '$_extension' parameter for cipher: " . hexCodedCipher($cipher) . ":\n");
                $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher, $dtls_epoch, $parseAllRecords);
                _trace5_ ("#     ---> received cipher: " . hexCodedCipher($acceptedCipher) . " == " . hexCodedCipher($cipher) . "?\n");
                last if ($acceptedCipher ne $cipher);
                _trace5_ ("#     ---> next while (" . (@{$_SSLhello{$protocolCipher}{param}{$_extension}{RX}{values}}) . " > $found_values)\n");
            }
            _trace1_ ("# _doCheckAllExtensions (Cipher: " . hexCodedCipher($cipher) . ") ==> extension '$_extension': found $found_values values.\n");
        } else {
            _trace_ ("SSLhello::_doCheckAllExtensions ($_extension): Detailled checks for extensions with multiple parameters are not supported, yet. Please check variable '\$SSLhello::check_extensions').");
            carp("$STR{WARN} SSLhello::_doCheckAllExtensions ($_extension): Detailled checks for extensions with multiple parameters are not supported, yet. Please check variable '\$SSLhello::check_extensions').");
        }
        delete ($SSLhello::extensions_params_hash{$_extension}); # delete temporary hash
    }
    delete ($SSLhello::extensions_params_hash{$_last_extension}) if (defined ($SSLhello::extensions_params_hash{$_last_extension})); # delete temporary hash
    return;
} # _doCheckAllExtensions


=pod

=head3 parseServerKeyExchange( )

Manually parse a Server Kex Exchange packet and detect KeyExchange length, according https://tools.ietf.org/html/rfc5246#section-7.4.3

=over 2

=item * DHE:   length of the DHparam (needed for openssl <= 1.0.1), e.g. dh, 2048 bits (dh in small letters to be different from openssl (large letters)

=item * ECDHE: check for the most prioritized Curve (supported_group):
~        RFC 8422: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier

=item * RSA:   RFC 6101: The Secure Sockets Layer (SSL) Protocol Version 3.0, e.g. EXPORT ciphers

=item * PSK:   Pre-Shared Keys can be used alone or in combination with all other 3 server key types:
~        RFC 4279: Pre-Shared Key Ciphersuites for Transport Layer Security (TLS),
~        RFC 4785: Pre-Shared Key (PSK) Ciphersuites with NULL Encryption for Transport Layer Security (TLS),
~        RFC 5487: Pre-Shared Key Cipher Suites for TLS with SHA-256/384 and AES Galois Counter Mode,
~        RFC 5489: ECDHE_PSK Cipher Suites for Transport Layer Security (TLS)

=back

=cut

sub parseServerKeyExchange($$$) {
    #? parse a ServerKeyExchange packet to detect length of DHparam, ECDHE 'supprted_group', RSA Key length, optional usage of PSK
    #? Test PSK ciphers locally with: "openssl s_server -4 -psk 1a2b3c4d -psk_hint 01020304 -nocert -www -msg"
    #? Verfied size of DHparam etc manually with "openssl s_client -showcerts -msg -psk 1a2b3c4d -tls1_2 -cipher 'DHE-PSK-AES128-CBC-SHA' -connect localhost:4433"
    #? TBD: parse independant from cipher name; could be needed for TLSv13
    my ($keyExchange, $len, $d) = @_;
    my ($_tmpLen, $_null, $_handshake_type, $_bits) = 0;
    my %_mySSLinfo;
    my $psk = "";                                                   # set to postfix '_psk' if PSK is additionally used.
    _trace2("parseServerKeyExchange($keyExchange, $len, ...)\n");
    _trace4("parseServerKeyExchange(KeyExchange= $keyExchange, Len= $len, Data= ".unpack("H*",$d)."\n");
    $_tmpLen = length (unpack("H*",$d))/2;
    carp("$STR{WARN} parseServerKeyExchange: Error in ServerKeyExchange Message: unexpected len ($_tmpLen) should be $len bytes") if ($len != $_tmpLen);
    return ("-- Error in ServerKeyExchange --", "", undef) if ($len != $_tmpLen);
    if ($keyExchange =~ /PSK/) { # PSK-Cipher => 'Prefix': psk_identity_hint, rfc4279)
        ($_mySSLinfo{'psk_identity_hint_len'},     # n
         $d) = unpack("n a*", $d);

        ($_mySSLinfo{'psk_identity_hint'},         # a[$_mySSLinfo{'psk_identity_hint_len'}]
         $d) = unpack("a[$_mySSLinfo{'psk_identity_hint_len'}] a*", $d);
         $_mySSLinfo{'psk_identity_hint'} = unpack ("H*", $_mySSLinfo{'psk_identity_hint'}); # Convert to a readable HEX-String
        _trace2( sprintf (
                " PSK Key Exchange (len=%d):\n".
                "# -->     psk_identity_hint: (len=%4d) >%s<\n",
                $len,
                $_mySSLinfo{'psk_identity_hint_len'},
                $_mySSLinfo{'psk_identity_hint'}
        ));
        if ($keyExchange =~ /^PSK/x) { #  nothing more to do
            _trace4("parseServerKeyExchange: PSK_serverParam\n");
            _trace2("parseServerKeyExchange() done.\n");
            return ("psk", "" , undef);
        }
        $psk = "_psk";                                              # set '_psk' as postfix for the following ServerKeyExchanges
        $len -= ($_mySSLinfo{'psk_identity_hint_len'}+2);
        $keyExchange =~ s/^((?:EC)?DH)(?:_PSK)?.*/$1/x; # EDH_PSK -> DH, ADH_PSK -> DH, EECDH_PSK -> ECDH
        _trace2_ (" --> KeyExchange (DH, ECDH) = $keyExchange\n"); # => ECDH or DH, or ECDH_PSK o DH_PSK
    } # PSK
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
        $_mySSLinfo{'DH_serverParam'} = $_bits ." bits"; # manually generate the same message that is generated by openssl >= 1.0.2 but here with 'dh' in small letters
        _trace4("parseServerKeyExchange: DH_serverParam: ".$_mySSLinfo{'DH_serverParam'}."\n");
        _trace2("parseServerKeyExchange() done.\n");
        return ("dh" . $psk, $_mySSLinfo{'DH_serverParam'}, undef);

    } elsif ($keyExchange eq "ECDH") { # check for the selected Curve (supported_group) # TBD verify if this is the default check for TLSv13?
        ($_mySSLinfo{'ECDH_eccurve_type'},    # C
         $d) = unpack("C a*", $d);
        if ($_mySSLinfo{'ECDH_eccurve_type'} == $ECCURVE_TYPE{'named_curve'}) {
            ($_mySSLinfo{'ECDH_namedCurve'},    # n
            $d) = unpack("n a*", $d);
            $_mySSLinfo{'ECDH_serverParam'} = "<<unknown: ".$_mySSLinfo{'ECDH_namedCurve'}.">>"; # set a default value
            $_mySSLinfo{'ECDH_serverParam'} = $OCfg::TLS_SUPPORTED_GROUPS{$_mySSLinfo{'ECDH_namedCurve'}}[0] ." (". $OCfg::TLS_SUPPORTED_GROUPS{$_mySSLinfo{'ECDH_namedCurve'}}[1] . " bits)" if ( defined ($OCfg::TLS_SUPPORTED_GROUPS{$_mySSLinfo{'ECDH_namedCurve'}}[0]) );
            _trace4("parseServerKeyExchange: ECDH_serverParam supported group: '" . $_mySSLinfo{'ECDH_serverParam'} . "'\n");
            _trace2("parseServerKeyExchange() done.\n");
            return ("ecdh"  . $psk . " supported_group(s)", $_mySSLinfo{'ECDH_serverParam'}, $_mySSLinfo{'ECDH_namedCurve'});
            # $_mySSLinfo{'ECDH_namedCurve'} will be returned to be deleted from extensions list supported_groups
        } elsif ($_mySSLinfo{'ECDH_eccurve_type'} == $ECCURVE_TYPE{'explicit_prime'}) { # only basic parsing, no additional trace information about additional parameters, yet,
            ($_mySSLinfo{'ECDH_explicit_prime_p_len'},    # C
             $d) = unpack("C a*", $d);
            $_bits = $_mySSLinfo{'ECDH_explicit_prime_p_len'} * 8;
            $_mySSLinfo{'ECDH_serverParam'} = "explicite_prime: ". $_bits ." bits"; # manually generate a message that could ressemble to openssl >= 1.0.2 but here with 'ecdh' in small letters (TBD: get an original Message from OpenSSL for this special type of Curves
        } elsif ($_mySSLinfo{'ECDH_eccurve_type'} == $ECCURVE_TYPE{'explicit_char2'}) { # no parsing yet: #TBD: support this type later
            $_mySSLinfo{'ECDH_serverParam'} = "explicite_char2: <<not parsed, yet>>";
        } else {
            $_mySSLinfo{'ECDH_serverParam'} = "<<unknown ECC Curve type: ".$_mySSLinfo{'ECDH_eccurve_type'}.">>";
        }
        _trace4("parseServerKeyExchange: ECDH_serverParam: '".$_mySSLinfo{'ECDH_serverParam'}."'\n");
        _trace2("parseServerKeyExchange() done.\n");
        return ("ecdh" . $psk, $_mySSLinfo{'ECDH_serverParam'}, undef);
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
        $_mySSLinfo{'RSA_serverParam'} = $_bits ." bits"; # manually generate the same message that is generated by openssl >= 1.0.2 but here with 'rsa' in small letters
        _trace4("parseServerKeyExchange: RSA_serverParam: ".$_mySSLinfo{'RSA_serverParam'}."\n");
        _trace2("parseServerKeyExchange() done.\n");
        return ("rsa" . $psk, $_mySSLinfo{'RSA_serverParam'}, undef);
    } else { # nor DH neither ECDH
        _trace2("parseServerKeyExchange: The only supported KeyExchange types are DH, ECDH and RSA yet (not $keyExchange)\n");
        _trace2("parseServerKeyExchange() done.\n");
        return ("-- unsupported KeyExchange --" . $psk, "", undef);
    }
} # parseServerKeyExchange


sub parseHandshakeRecord ($$$$$$$;$) {
    #? <<description missing>> <<POD missing>> # FIXME:
    # return (<nextData>, <cookie-len (DTLDS)>, <cookie (DTLS)>, <cipher>)
    my $host        = shift || ""; # for warn- and trace messages
    my $port        = shift || ""; # for warn- and trace messages
    my $recordType  = shift || 0;  # recordType
    my $recordVersion = shift || 0; # recordVersion or SSLv2
    my $recordLen   = shift || 0;  # recordLen
    my $recordData  = shift || ""; # record
    my $lastCipher  = shift || ""; # lastCipher
    my $client_protocol = shift || "";  # optional

    my $buffer      = "";          # temporarily store data of next record if alredy available
    my $rest        = "";
    my $tmp_len     = 0;
    my $message     = "";
    my $nextMessages = "";
    my %serverHello;
    my $cipher      = "";
    my $keyExchange = "";
    my $description = "";
    my $lastMsgType = $HANDSHAKE_TYPE {'<<undefined>>'}; #undefined
    my $lastProtocolCipher = '0x0300'.hexCodedCipher($lastCipher);

    local $my_error = ""; # reset error message

    my $sni = "";
    my $client_ssl = $PROTOCOL_NAME_BY_HEX{$client_protocol};
    if (! defined $client_ssl) {
        $client_ssl = "--unknown protocol--";
    }

    #reset error_handler and set basic information for this sub
    error_handler->reset_err( {module => ($SSLHELLO), sub => 'parseHandshakeRecord', print => ($SSLhello::trace > 3), trace => $SSLhello::trace} );

    $SSLhello::use_sni_name = 1 if ( ($SSLhello::use_sni_name == 0) && ($SSLhello::sni_name) && ($SSLhello::sni_name ne "1") ); ###FIX: quickfix until migration of o-saft.pl is compleated (tbd)
    unless ($SSLhello::use_sni_name) {
        $sni = "'$host'" if ($SSLhello::use_sni_name); # Server Name, should be a Name no IP
    } else { # different sni_name
        $sni = ($SSLhello::sni_name) ? "'$SSLhello::sni_name'" : "''"; # allow empty nonRFC-SNI-Names
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
                return ("",  $lastMsgType, 0, "", parseSSL2_ServerHello ($host, $port, $message, $client_protocol)); # cipher_spec-Liste
            } elsif ($serverHello{'msg_type'} == $SSL_MT_ERROR) { # simple error handling for ssl2
                ($serverHello{'err_code'}        # n
                 ) = unpack("n", $message);

                _trace2 ("parseHandshakeRecord: Server '$host:$port': received a SSLv2 error message, code: >0x".hexCodedString ($serverHello{'err_code'})."<\n");
                unless ($serverHello{'err_code'} == 0x0001) { # SSLV2_No_Cipher, TBD: this could be improved later (if needed)
                    carp("$STR{WARN} parseHandshakeRecord: Server '$host:$port': received a SSLv2 error message: , code: >0x".hexCodedString ($serverHello{'err_code'})." -> answer ignored\n");
                }
                return ("", $lastMsgType, 0, "", "");
            } else { # if ($serverHello{'msg_type'} == 0 => unsupported protocol (?!)
                $my_error= "    Unknown SSLv2 message type (Dez): ".$serverHello{'msg_type'}.", Msg: >".hexCodedString ($message)."< -> check for SSLv2 is aborted\n";
                return ("", $lastMsgType, 0 , "", "");
            }
        } else { # SSLv3, TLS or DTLS:a parse messages
            if ($recordType == $RECORD_TYPE {'handshake'}) {
               ($nextMessages,                                      #a[$recordLen}]
                $buffer) = unpack("a[$recordLen] a*", $recordData);

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
                            carp("parseHandshakeRecord: $my_error");
                            # return ($nextMessages, $lastMsgType, 0, "", ""); # maybe later, if fragmented dtls messages will be isupported
                            return ("", $lastMsgType, 0, "", "");
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
                        return ($nextMessages.$buffer, $HANDSHAKE_TYPE {'<<fragmented_message>>'}, $serverHello{'cookie_length'}, $serverHello{'cookie'}, "");
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
                        $lastProtocolCipher = '0x0300'.hexCodedCipher($lastCipher);
#                       return ("", $lastMsgType, 0,"", parseTLS_ServerHello ($host, $port, $message, $serverHello{'msg_len'},$client_protocol) ); # moved bebind the 'while-loop'
                        _trace2_ ("# ==>       found cipher:      >$lastProtocolCipher<\n");
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
                                carp("parseHandshakeRecord: $my_error");
                            }
                            if ($serverHello{'cookie_length'} > 32) {
                                $my_error = "Server '$host:$port': DTLS-HelloVerifyRequest: 'cookie_length' ($serverHello{'cookie_length'}) out of Range <0..32)";
                                carp("parseHandshakeRecord: $my_error");
                            }
                            return ($rest.$buffer, $lastMsgType, $serverHello{'cookie_length'}, $serverHello{'cookie'},""); # TBD: check if .$buffer is really needed
                        }
                    } elsif ($serverHello{'msg_type'} == $HANDSHAKE_TYPE {'server_key_exchange'}) { ##### Server Key Exchange: to check DHE und ECDHE parameters
                        _trace2 ("parseHandshakeRecord: Cipher: ".hexCodedCipher ($lastCipher)."\n");
                        $keyExchange = $cipherHexHash {$lastProtocolCipher}[0];
                        if (defined ($keyExchange)) { # found a cipher
                            _trace5_ (" --> Cipher(1): $keyExchange\n");
                            $keyExchange =~ s/((?:EC)?DHE?)_anon((_PSK)?).*/A$1$2/x;   # DHE_anon -> EDH, ECDHE_anon -> AECDH, DHE_anon -> ADHE
                            _trace5_ (" --> Cipher(2): $keyExchange\n");
                            $keyExchange =~ s/((?:EC)?DH)E((_PSK)?).*/E$1$2/x;         # DHE -> EDH, ECDHE -> EECDH
                            _trace5_ (" --> Cipher(3): $keyExchange\n");
                            $keyExchange =~ s/^(?:EXP[_-])?(?:E|A|EA)((?:EC)?DH(?:_PSK)?).*/$1/x; # EDH -> DH, ADH -> DH, EECDH -> ECDH; EDH_PSK -> DH_PSK, ADH_PSK -> DH_PSK, EECDH_PSK -> ECDH_PSK
                            _trace2_ (" --> KeyExchange (DH, ECDH, DH_PSK or ECDH_PSK) = $keyExchange\n"); # => ECDH or DH, or ECDH_PSK o DH_PSK

                            my ($_description, $_param, $_supported_group) = parseServerKeyExchange ($keyExchange, length($message), $message);
                            if (defined ($_param)) {
                                _trace2_("\n   parseHandshakeRecord: $host:$port, $client_ssl, Cipher: $lastProtocolCipher -> SeverKey Type: $_description: $_param\n");
                            }
                            _trace5_ ("#     ---> values of 'supported_groups': " . _decode_val (undef, \@{$_SSLhello{$lastProtocolCipher}{param}{supported_groups}{RX}{values}}, \$OCfg::TLS_EXTENSIONS{supported_groups}, 0, 12, ": ", ", ", " | ", " / ") . "\n");
                            push (@{$_SSLhello{$lastProtocolCipher}{param}{supported_groups}{RX}{values}}, $_supported_group)
                                 if ( (defined ($_supported_group)) && (!grep {$_supported_group eq $_ } @{$_SSLhello{$lastProtocolCipher}{param}{supported_groups}{RX}{values}}) );
                                                                    # add new supported_group to array in the result hash
                            _trace4_ ("#     ---> found 'supported_groups':     " . _decode_val (undef, \@{$_SSLhello{$lastProtocolCipher}{param}{supported_groups}{RX}{values}}, \$OCfg::TLS_EXTENSIONS{supported_groups}, 0, 12, ": ", ", ", " | ", " / ") . "\n");
                            if (! exists ($_SSLhello{$lastProtocolCipher}{param}{ServerKey}{description}) ) {
                                $_SSLhello{$lastProtocolCipher}{param}{ServerKey}{description} = $_description;
                                $_SSLhello{$lastProtocolCipher}{param}{supported_groups}{RX}{format_positions}[0] = 1; # -> supported_groups{RX}[1]
                                @{$_SSLhello{$lastProtocolCipher}{param}{ServerKey}{values}} = ();                     # define the hash; it may stay empty, e.g for PSK (only) keys
                            } elsif ($_SSLhello{$lastProtocolCipher}{param}{ServerKey}{description} ne $_description) {  ## Error in parseServerKeyExchange: found different types of ServerKeys for the same Cipher
                                carp("$STR{WARN} SSLhello::parseHandshakeRecord: found different types of ServerKeys for the same Cipher '$lastProtocolCipher': '$_description' != '"
                                      . $_SSLhello{$lastProtocolCipher}{param}{ServerKey}{description} . "'\n");
                                $_SSLhello{$lastProtocolCipher}{param}{ServerKey}{description} .= " ## " . $_description; # segregate next parameter with '##'
                                $_param = " ## " . $_param;         # segregate next parameter with '##'
                            }
                            push (@{$_SSLhello{$lastProtocolCipher}{param}{ServerKey}{values}}, $_param)
                                 if ( (defined ($_param)) && ($_param ne "")
                                      && (!grep {$_param eq $_ } @{$_SSLhello{$lastProtocolCipher}{param}{ServerKey}{values}}) );
                                                                    # add new ServerKey parameters to an array in the result hash
                        } else { # no cipher found
                            _trace2 ("parseHandshakeRecord: No name found for cipher: >$lastProtocolCipher< -> counld NOT check the ServerKeyExchange\n");
                            push (@{$_SSLhello{$lastProtocolCipher}{param}{ServerKey}{values}}, "---unknown---");
                        }
                    } elsif ($serverHello{'msg_type'} == $HANDSHAKE_TYPE {'certificate'}) {
                         _trace2("parseHandshakeRecord: MessageType \"Certificate\" = ".sprintf("0x%02X", $serverHello{'msg_type'}) . " not yet analysed\n");
                    } elsif ($serverHello{'msg_type'} == $HANDSHAKE_TYPE {'certificate_request'}) {
                         _trace2("parseHandshakeRecord: MessageType \"Certificate request\" = ".sprintf("0x%02X", $serverHello{'msg_type'}) . " not yet analysed\n");
                    } elsif ($serverHello{'msg_type'} == $HANDSHAKE_TYPE {'server_hello_done'}) {
                         _trace4("parseHandshakeRecord: MessageType \"ServerHelloDone\" = ".sprintf("0x%02X", $serverHello{'msg_type'}) . " -> Final hello Message\n");
                         last; # hello message phase of the handshake is completed
                    } else {
                        _trace2("parseHandshakeRecord: MessageType ".sprintf("%02X", $serverHello{'msg_type'}) . " not yet analysed\n");
                    }
                    _trace2_("\n"); # next message
                } # while (nextMessages ne ""()
                return ($nextMessages.$buffer, $lastMsgType, 0, "", $cipher);
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

                # error handling according to # http://www.iana.org/assignments/tls-parameters/tls-parameters-6.csv
                unless ( ($serverHello{'level'} == 2) &&
                        (  ($serverHello{'description'} == 40) # handshake_failure(40): usually cipher not found is suppressed
                           || ($serverHello{'description'} == 71) # insufficient_security(71): no (secure) cipher found, is suppressed
                        ) ) {
                    if ($serverHello{'level'} == 1) { # warning
                        if ($serverHello{'description'} == 112) { #SNI-Warning: unrecognised_name
                            if ( ($SSLhello::usesni) && !( ( ($client_protocol == $PROTOCOL_VERSION{'SSLv3'}) && (!$SSLhello::force_TLS_extensions) ) || ($client_protocol == $PROTOCOL_VERSION{'SSLv2'}) ) ) {           # SNI sent
                                $sni = "";
                                unless ($SSLhello::use_sni_name) {
                                    $sni = "'$host'";           # Server Name, should be a Name no IP
                                } else {                        # different sni_name
                                    $sni = ($SSLhello::sni_name) ? "'$SSLhello::sni_name'" : "''"; # allow empty nonRFC-SNI-Names
                                }
                                $my_error = sprintf ("parseHandshakeRecord: Server '$host:$port' ($client_ssl): received SSL/TLS warning: Description: $description ($serverHello{'description'}) -> check of virtual server $sni aborted!\n");
                                _trace4 ($my_error);
                                carp("$STR{WARN} $my_error\n");
                            } else {                            # NO SNI extension sent
                                $my_error = sprintf ("parseHandshakeRecord: Server '$host:$port' ($client_ssl): received SSL/TLS warning: Description: $description ($serverHello{'description'}), but NO SNI extension has been sent. -> check of server aborted!");
                                _trace4 ($my_error);
                                carp("$STR{WARN} $my_error\n");
                                _hint ("Server seens to to be a virtual server, consider adding the option '--sni' (Server Name Indication) for TLSv1 and higher");
                            }
                            return ("", $lastMsgType, 0 , "", "");
                        } elsif ($serverHello{'description'} == 0) { # closure alert: close_notify is suppressed
                            _trace2_ ("parseHandshakeRecord: Server '$host:$port' ($client_ssl): received SSL/TLS closure alert (1) has been ignored: Description: $description ($serverHello{'description'})\n");
                        } else {
                            _trace4_ ("**WARNING: parseHandshakeRecord: Server '$host:$port' ($client_ssl): received SSL/TLS warning (1): Description: $description ($serverHello{'description'})\n");
                            carp("$STR{WARN} parseHandshakeRecord: Server '$host:$port' ($client_ssl): received SSL/TLS warning (1): Description: $description ($serverHello{'description'})\n");
                        }
                    } elsif ($serverHello{'level'} == 2) { # fatal
                        if (($serverHello{'description'} == 70)
                        or  ($serverHello{'description'} == 80)) {
                            # protocol_version(70) SSLv2, protocol_version(80) SSLv3:
                            # (old) protocol recognised but not supported, is suppressed
                            error_handler->new( {
                                type    => $OERR{'SSLHELLO_ABORT_PROTOCOL'},
                                id      => 'parse alert record (2)',
                                message => sprintf ("unsupported protocol $client_ssl (0x%04X) by $host:$port: received a SSL/TLS-Warning: Description: $description ($serverHello{'description'})", $client_protocol),
                                warn    => 0,
                            } );
                            if ((grep{/(:?--v)$/ix} @main::ARGV) > 0) { # warning with --v only
                                # TODO: warning here disabled, as it is considered a server problem; needs to be tested again
                                _warn("430: SSL version '$client_ssl' not supported by '$host:$port'; no ciphers detected, ignored\n");
                                _hint("consider using '--ciphermode=openssl' also\n");
                            };
                        } elsif ($serverHello{'description'} == 112) { #SNI-Warning: unrecognized_name
                            if ( ($SSLhello::usesni) && !( ( ($client_protocol == $PROTOCOL_VERSION{'SSLv3'}) && (!$SSLhello::force_TLS_extensions) ) || ($client_protocol == $PROTOCOL_VERSION{'SSLv2'}) ) ) {           # SNI sent
                                $sni = "";
                                unless ($SSLhello::use_sni_name) {
                                    $sni = "'$host'" if ($SSLhello::usesni); # Server Name, should be a Name no IP
                                } else {                            # different sni_name
                                    $sni = ($SSLhello::sni_name) ? "'$SSLhello::sni_name'" : "''"; # allow empty nonRFC-SNI-Names
                                }
                                $my_error = sprintf ("parseHandshakeRecord: Server '$host:$port' ($client_ssl): received fatal SSL/TLS error (2a): Description: $description ($serverHello{'description'}) -> check of virtual server $sni aborted!\n");
                                _trace4 ($my_error);
                                carp("$STR{WARN} $my_error\n");
                            } else {                                # NO SNI extension sent
                                $my_error = sprintf ("parseHandshakeRecord: Server '$host:$port' ($client_ssl): received fatal SSL/TLS error (2b): Description: $description ($serverHello{'description'}), but NO SNI extension has been sent. -> check of server aborted!");
                                _trace4 ($my_error);
                                carp("$STR{WARN} $my_error\n");
                                _hint ("Server seens to to be a virtual server, consider adding the option '--sni' (Server Name Indication)for TLSv1 and higher");
                            }
                            return ("", $lastMsgType, 0 , "", "");
                        } else {
                            _trace4 ($my_error);
                            carp("$STR{WARN} parseHandshakeRecord: Server '$host:$port' ($client_ssl): received fatal SSL/TLS error (2c): Description: $description ($serverHello{'description'})\n");
                            if ($serverHello{'description'} == 50) { # decode_error (50)
                                _hint("The server may not support the extension for elliptic curves (ECC) nor discard it silently, consider adding the option '--ssl-nouseecc'.");
                            }
                        }
                    } else { # unknown
                        carp("$STR{WARN} parseHandshakeRecord: Server '$host:$port' ($client_ssl): received unknown SSL/TLS error level ($serverHello{'level'}): Description: $description ($serverHello{'description'})\n");
                    }
                }
                if ($recordVersion == 0x0000) { # some servers use this dummy version to indicate that the requested version is not supported
                    error_handler->new( {
                        type    => $OERR{'SSLHELLO_ABORT_PROTOCOL'},
                        id      => 'parse alert record (1)',
                        message => sprintf ("unsupported protocol $client_ssl (0x%04X) by $host:$port, answered with (0x%04X)", $client_protocol, $recordVersion),
                        warn    => 0,
                    } );
                    return ("", $lastMsgType, 0 , "", "");
                }
            } elsif ($recordType == $RECORD_TYPE {'change_cipher_spec'}) {
                $serverHello{'msg_type'} = 0;           # NO Handshake => set 0
                $serverHello{'msg_len_3rd_byte'} = 0;   # NO Handshake => set 0
                $serverHello{'msg_len'} = 0;            # NO Handshake => set 0
                $serverHello{'fragment_3rd_byte'} = 0;  # NO Handshake => set 0
                $serverHello{'fragment_offset'} = 0;    # NO Handshake => set 0
                $serverHello{'fragment_3rd_byte'} = 0;  # NO Handshake => set 0
                $serverHello{'fragment_len'} = 0;       # NO Handshake => set 0

                ($serverHello{'payload'},                           # a[$record len]
                $rest) = unpack("a[$recordLen] a*", $recordData);

                _trace2_ (sprintf (
                   "# -->     Record-Type 'change_cipher_spec' [Len = %d]:\n".
                   "# -->       payload:                >%s<\n",
                   $recordLen,
                   _sprintf_hex_val ("", \$serverHello{'payload'}, 37),
                ));
                return ($rest, $lastMsgType, 0 , "", "");
            } elsif ($recordType == $RECORD_TYPE {'application_data'}) {
                $serverHello{'msg_type'} = 0;           # NO Handshake => set 0
                $serverHello{'msg_len_3rd_byte'} = 0;   # NO Handshake => set 0
                $serverHello{'msg_len'} = 0;            # NO Handshake => set 0
                $serverHello{'fragment_3rd_byte'} = 0;  # NO Handshake => set 0
                $serverHello{'fragment_offset'} = 0;    # NO Handshake => set 0
                $serverHello{'fragment_3rd_byte'} = 0;  # NO Handshake => set 0
                $serverHello{'fragment_len'} = 0;       # NO Handshake => set 0

                ($serverHello{'application_data'},                  # a[$record len]
                $rest) = unpack("a[$recordLen] a*", $recordData);

                _trace2_ (sprintf (
                   "# -->     Record-Type 'application_data' [Len = %d]:\n".
                   "# -->       application_data:       >%s<\n",
                   $recordLen,
                   _sprintf_hex_val ("", \$serverHello{'application_data'}, 37),
                ));
            } else { ################################ to get information about record types that are not parsed, yet #############################
                _trace_ ("\n");
                _trace_ ("**WARNING: parseHandshakeRecord: Server '$host:$port': Unknown SSL/TLS record type received that is not (yet) defined in SSLhello.pm:\n");
                _trace_ ("#        Record type:     Unknown value (0x".hexCodedString($recordType)."), not (yet) defined in SSLhello.pm\n");
                _trace_ ("#        Record version:  $recordVersion (0x".hexCodedString ($recordVersion).")\n");
                _trace_ ("#        Record len:      $recordLen (0x".hexCodedString ($recordLen).")\n\n");
                carp("$STR{WARN} parseHandshakeRecord: Server '$host:$port': Unknown SSL/TLS record type received that is not (yet) defined in SSLhello.pm:\n");
                carp("#        Record type:     Unknown value (0x".hexCodedString($recordType)."), not (yet) defined in SSLhello.pm\n");
                carp("#        Record version:  $recordVersion (0x".hexCodedString ($recordVersion).")\n");
                carp("#        Record len:      $recordLen (0x".hexCodedString ($recordLen).")\n\n");
                #($serverHello{'--unknown record type--'},           # a[$record len]
                # $rest) = unpack("a[$recordLen] a*", $recordData);
                return ("", $lastMsgType, 0 , "", "");
            }
            return ($buffer, $lastMsgType, 0 , "", "");
        } #End SSL3/TLS or DTLS
    } else {
        carp("$STR{WARN} parseHandshakeRecord: Server '$host:$port': (no SSL/TLS record) : ".hexCodedString ($recordData)."\n");
        ($serverHello{'--unknown record type--'},           # a[$record len]
         $rest) = unpack("a[$recordLen] a*", $recordData);
        return ($rest, $lastMsgType, 0 , "", "");
    }
    carp("$STR{WARN} parseHandshakeRecord: Server '$host:$port': Internal error: ".hexCodedString ($recordData)."\n");
    ($serverHello{'--unknown record type--'},           # a[$record len]
     $rest) = unpack("a[$recordLen] a*", $recordData);
    return ($rest, $lastMsgType, 0 , "", "");
} # parseHandshakeRecord


sub parseSSL2_ServerHello ($$$;$) {
    #? <<description missing>> <<POD missing>> # FIXME:
    # Variable: String/Octett, das den Rest des Server-Hello-Pakets enthält
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

    if ($SSLhello::trace >= 3) { #trace3+4: added to check the supported version
        printf "## Server Server '$host:$port': accepts the following Ciphers with SSL-Version: >%04X<\n",
               $serverHello{'version'};
        printSSL2CipherList($serverHello{'cipher_spec'});
        print "\n";
    }
    ### added to check if there is a bug in getting the cipher_spec
    if (length ($serverHello{'cipher_spec'}) != int ($serverHello{'cipher_spec_len'}) ) { # did not get all ciphers?
            carp("$STR{WARN} parseSSL2_ServerHello: Server '$host:$port': Can't get all Ciphers from Server-Hello (String-Len: ".length ($serverHello{'cipher_spec'})." != cipher_spec_len: ".$serverHello{'cipher_spec_len'}."): >". hexCodedSSL2Cipher ($serverHello{'cipher_spec'})."<");
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

=head3 parseTLS_ServerHello( )

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
    my $host            = shift || ""; #for warn and trace messages
    my $port            = shift || ""; #for warn and trace messages
    my $buffer          = shift || "";
    my $len             = shift || 0;
    my $client_protocol = shift || "";
    my $server_protocol = "";
    my $rest            = "";
    my $rest2           = "";
    my %serverHello;
    my $protocolCipher  = "";

    $serverHello{'cipher_spec'} = "";
    $serverHello{'extensions_len'} = 0;

    #reset error_handler and set basic information for this sub
    error_handler->reset_err( {module => ($SSLHELLO), sub => 'parseTLS_ServerHello', print => ($SSLhello::trace > 3), trace => $SSLhello::trace} );

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


        _trace2_ ( sprintf (
                "# -->       (legacy) version:  >%04X<\n".
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
        _trace5_ ( sprintf (
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
        if (length ($serverHello{'cipher_spec'}) !=  2 ) { # did not get the 2-octet-cipher?
            carp("$STR{WARN} parseTLS_ServerHello: Server '$host:$port': Can't get the Cipher from Server-Hello (String-Len: ".length ($serverHello{'cipher_spec'})." != cipher_spec_len: 2): >". hexCodedString ($serverHello{'cipher_spec'})."<");
        }
        $protocolCipher = '0x0300'.hexCodedCipher($serverHello{cipher_spec});
        if ($SSLhello::trace > 3) {
            printTLSCipherList ($serverHello{'cipher_spec'});
        }

        _trace2_ ( sprintf (
              "\n# -->       compression_method:   >%02X<\n",
                $serverHello{'compression_method'}
        ));

        # check the tls extensions:
        my %_param_tmp_hash = ();
        %_param_tmp_hash = %{$_SSLhello{$protocolCipher}{param}} if (exists ($_SSLhello{$protocolCipher}{param}));# save the param hash, just in case of a protocol mismatch
        if ( $serverHello{'extensions_len'} !~ /(?:^$|[\x00]+)/x) { # extensions_len > 0
            ($serverHello{'extensions'},            # A[]
            $rest) = unpack("a[$serverHello{'extensions_len'}] a*", $rest2);

            _trace2_ ( sprintf (
                "# -->       extensions_len:     >%04X<\n",
                $serverHello{'extensions_len'}
            ));

            _trace4_ ( sprintf (
                "# -->       extensions:           >%s<\n".
                "# -->       Rest:                 >%s<\n",
                hexCodedString ($serverHello{'extensions'}),
                hexCodedString ($rest)
            ));
            _parseExtensions ("RX", \%{$_SSLhello{$protocolCipher}{param}}, \$serverHello{'extensions'}, $serverHello{'extensions_len'}, $protocolCipher);
            if  (length($rest) > 0) { # should be 0
                _trace2 ( sprintf ("\n\n## parseTLSServerHello Server '$host:$port': did not parse the whole message (rest): >".hexCodedString ($rest)."< To Be Done\n"));
            }
        }
        # Check the protocol version (client vs server)
#        $client_protocol = 0x0303 if ($client_protocol == 0x0304); # Quick Patch for TLS 1.2; TBD: DTLS!check record_protocol, extension_protocol
        # get version from extension 'supported_versions' if it has been received : if not use legacy version from record
        $server_protocol = (defined ($_SSLhello{$protocolCipher}{param}{supported_versions}{RX}{values}[$#{$_SSLhello{$protocolCipher}{param}{supported_versions}{RX}{values}}]))
                                   ? $_SSLhello{$protocolCipher}{param}{supported_versions}{RX}{values}[$#{$_SSLhello{$protocolCipher}{param}{supported_versions}{RX}{values}}]
                                   : $serverHello{'version'};
        _trace5_ ( sprintf ( # added to check the supported version
                "# -->       => check server SSL/TLS-Version: legacy: %04X / effective %04X vs client: %04X\n",
                 $serverHello{'version'}, $server_protocol, $client_protocol
        ));
        if (defined ($client_protocol)) {
            if ($client_protocol != $server_protocol) {
                my $client_ssl = $PROTOCOL_NAME_BY_HEX{$client_protocol};
                my $server_ssl = $PROTOCOL_NAME_BY_HEX{$server_protocol};
                if (! defined $client_ssl) {
                    $client_ssl = "--unknown protocol--";
                }
                if (! defined $server_ssl) {
                    $server_ssl = "--unknown protocol--";
                }
                _trace5_ (" " x 9 . "# --> parseTLSServerHello Server '$host:$port': protocol mismatch (expected $client_ssl != $server_ssl). Restoring hash \%{\$_SSLhello{$protocolCipher}{cipher_spec}{param}}.\n");
                $_SSLhello{$protocolCipher}{param} = \%_param_tmp_hash;
                if ($server_protocol == 0) {
                    # some servers respond with the dummy prtotocol '0x0000' if they do *not* support the requested protocol
                    error_handler->new( {
                        type    => $OERR{'SSLHELLO_ABORT_PROTOCOL'},
                        id      => 'check record protocol (1)',
                        message => sprintf ("unsupported protocol $client_ssl (0x%04X) by $host:$port, answered with $server_ssl (0x%04X)", $client_protocol, $server_protocol),
                        warn    => 0,
                    } );
                } else { # unknown protocol
                    error_handler->new( {
                        type    => $OERR{'SSLHELLO_ABORT_PROTOCOL'},
                        id      => 'check record protocol (2)',
                        message => sprintf ("unsupported protocol $client_ssl (0x%04X) by $host:$port, answered with $server_ssl (0x%04X)", $client_protocol, $server_protocol),
                        warn    => 0,
                    } );
                }
                return ("");
            }
        } else {
            carp("$STR{WARN} parseTLS_ServerHello: server '$host:$port': internal error: All server protocol versions are accepted, because there is no information provided which version the client has requested.\n");
        }
        _trace2_ ( sprintf (
            # added to check the supported version
            "# --> The server '$host:$port': accepts the following cipher(s) with SSL3/TLS-version: >%04X<:\n", $server_protocol
        ));
        return ($serverHello{'cipher_spec'});
    } else {
        return ("");
    }
} # parseTLS_ServerHello


sub _timedOut { ## no critic qw(Subroutines::ProhibitUnusedPrivateSubroutines) # Perl::Critic does not know signal handlers
    croak("NET::SSLhello: Receive data timed out -> Received NO data (timeout)");
}

sub _chomp_r { # chomp \r\n
    my $string = shift || "";
    $string =~ s/(.*?)\r?\n?$/$1/gx;
    if ($string =~ /[^\x20-\x7E\t\r\n]/x) { # non printable charachers in string
        $string =~ s/([\x00-\xFF])/sprintf("%02X ", ord($1))/eigx; # code all octets as HEX values and separate them with a 'space'
    }
    return ($string);
}

sub getCipherParameter {
    #? print parameters for cipher, i.e. DH, ECDH
    #? returns string with parameters, or empty string if none available
    #? given $prefix is used if parameters are available,
    #? multiple paramters are separated by given $sep
    # FIXME: <<POD missing>>
    my $protocolCipher = shift;
    my $prefix  = shift || "";
    my $sep     = shift || " | ";
    my $string  = "";
    my $param   = $_SSLhello{$protocolCipher}{param}{ServerKey};
    # Print parameters by the cipher
    if (exists ($param->{values})) { #length of dh_param, supported_group
        #$string = "$prefix$param->{description} (". (@{$param->{values}}) . "): "; # until version 1.61
        $string = "$prefix$param->{description}: ";
        for (my $_i = 0; $_i <= $#{$param->{values}}; $_i++) {
            $string .= $sep if 0 < ($_i);
            $string .= $param->{values}[$_i];
        }
    }
    return $string;
} # getCipherParameter

sub hexCodedString {
    # FIXME: <<description missing>> <<POD missing>>
    # Variable: String/Octet, der in HEX-Werten dargestellt werden soll, gibt Ausgabestring zurück
    my $codedString = shift || "";
    my $prefix      = shift; # set an optional prefix after '\n'
    return ("") if ($codedString eq "");
       $prefix      = "" if not defined($prefix); # undefined -> ""
    $codedString =~ s/([\x00-\xFF])/sprintf("%02X ", ord($1))/eigx; # code all octets as HEX values and separate then with a 'space'
    $codedString =~ s/((?:[0-9A-Fa-f]{2}\s){48})(?=[0-9A-Fa-f]{2})/"$1\n$prefix"/eigx; # add a new line each 48 HEX-octetts (=144 symbols incl. spaces) if not last octett reached
    chomp ($codedString); # delete CR at the end
    chop  ($codedString); # delete 'space' at the end
    return ($codedString);
} # hexCodedString


sub hexCodedCipher {
    #? <<description missing>> <<POD missing>> # FIXME:
    # Variable: String/Octet, der in HEX-Werten dargestellt werden soll, gibt Ausgabestring zurück
    my $codedString = shift || "";
    my $prefix      = shift; # set an optional prefix after '\n'
    return ("") if ($codedString eq "");
       $prefix      = "" if not defined($prefix); # undefined -> ""
    $codedString =~ s/([\x00-\xFF])/sprintf("%02X", ord($1))/eigx; # code all octets as HEX values and separate then with a 'space'
    $codedString =~ s/((?:[0-9A-Fa-f]{2}){64})/"$1\n$prefix"/eigx; # add a new line each 64 HEX octetts (=128 symbols incl. spaces)
    chomp  ($codedString); # delete CR at the end
    return ($codedString); # delete 'space' at the end
} # hexCodedCipher


sub hexCodedSSL2Cipher {
    #? <<description missing>> <<POD missing>> # FIXME:
    # Variable: String/Octet, der in HEX-Werten dargestellt werden soll, gibt Ausgabestring zurück
    my $codedString = shift || "";
    my $prefix      = shift; # set an optional prefix after '\n'
    return ("") if ($codedString eq "");
       $prefix      = "" if not defined($prefix); # undefined -> ""
    $codedString =~ s/([\x00-\xFF])([\x00-\xFF])([\x00-\xFF])/sprintf("%02X%02X%02X ", ord($1), ord($2), ord($3))/eigx; # code all 3-octet-ciphers as HEX value pairs and separate them with a 'space'
    $codedString =~ s/((?:[0-9A-Fa-f]{6}){16}\s)/"$1\n$prefix"/eigx; # add a new line each 16 ciphers (=112 symbols incl. spaces)
    chomp  ($codedString); # delete CR at the end
    return ($codedString); # delete 'space' at the end
}

sub hexCodedTLSCipher {
    #? <<description missing>> <<POD missing>> # FIXME:
    # Variable: String/Octett, der in HEX-Werten dargestellt werden soll, gibt Ausgabestring zurück
    my $codedString = shift || "";
    my $prefix      = shift; # set an optional prefix after '\n'
    return ("") if ($codedString eq "");
       $prefix      = "" if not defined($prefix); # undefined -> ""
    $codedString =~ s/([\x00-\xFF])([\x00-\xFF])/sprintf("%02X%02X ", ord($1), ord($2))/eigx; # code all 2-octet-ciphers as HEX value pairs and separate then with a 'space'
    $codedString =~ s/((?:[0-9A-Fa-f]{4}){16}\s)/"$1\n$prefix"/eigx; # add a new line each 16 ciphers (=80 symbols incl. spaces)
    chomp  ($codedString); # delete CR at the end
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
        if ($SSLhello::trace > 3) {
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
        if ($SSLhello::trace > 3) {
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

    if ($SSLhello::trace > 3) {
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

#    if ($SSLhello::trace > 2)
    if ($SSLhello::trace > 1) {

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

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

sub _main_help  {
    #? print own help
    # if ($#argv < 0) { _main_help(); exit 0; }
    printf("# %s %s\n", __PACKAGE__, $VERSION);
    local $\ =""; undef $\; # not very perlish, but keeps perlcritic happy
    if (eval {require Pod::Perldoc;}) {
        # pod2usage( -verbose => 1 );
        exit( Pod::Perldoc->run(args=>[$0]) );
    }
    if (qx(perldoc -V)) {   ## no critic qw(InputOutput::ProhibitBacktickOperators)
        # may return:  You need to install the perl-doc package to use this program.
        printf("# no Pod::Perldoc installed, please try:\n  perldoc $0\n");
    }
    return;
} # _main_help

sub _main       {
    my @argv = @_;
    ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    #  SEE Perl:binmode()
    binmode(STDOUT, ":unix:utf8");
    binmode(STDERR, ":unix:utf8");
    if ($#argv < 0) { _main_help(); exit 0; }
    # got arguments, do something special; any -option or +command exits
    while (my $arg = shift @argv) {
        if ($arg =~ /^--?h(?:elp)?$/x)          { _main_help();         }
        if ($arg =~ /^version$/x)               { print "$SID_sslhello\n";}
        if ($arg =~ /^[+-]?VERSION/x)           { print "$VERSION\n";   }
        if ($arg =~ /^--test.?init/x)           { printParameters();    }
        if ($arg =~ /^--test.?para(?:meter)?/x) { printParameters();    }
        if ($arg =~ /^--test.?const(?:ant)?/x)  { printConstants();     }
        if ($arg =~ /^[+-]/)                    { exit 0; } # silently ignore unknown options
    }
    exit 0;
} # _main


=pod

=head1 EXAMPLES

See DESCRIPTION above.

=head1 LIMITATIONS

=head1 KNOWN PROBLEMS

=head1 DEENDENCIES

L<IO::Socket(1)>
L<IO::Socket::INET(1)>
L<error_handler>

=head1 SEE ALSO

L<IO::Socket(1)>

=head1 AUTHOR

19-November-2014 Torsten Gigler

=cut

sub net_sslhello_done() {};     # dummy to check successful include
## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|


_main(@ARGV) if (not defined caller);

1;
