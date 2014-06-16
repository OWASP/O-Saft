#!/usr/bin/perl -w
# Filename : SSLhello.pm
#!#############################################################################
#!#                    Copyright (c) Torsten Gigler 
#!#             This module is part of the OWASP-Project 'o-saft'
#!# It simulaes the SSLhello packets to check SSL parameters like the ciphers
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

#!# ToDo:
#!# Check is SNI-extension is supported by the Server, if 'usesni' is set

package Net::SSLhello;

use strict;
use Socket;

my $me      = $0; $me     =~ s#.*(?:/|\\)##;
my $mepath  = $0; $mepath =~ s#/[^/\\]*$##;
   $mepath  = "./" if ($mepath eq $me);
my $mename  = "yeast::Net::SSLhello ";
   $mename  = "O-Saft::Net::SSLhello " if ($me !~ /yeast/);

our %cfg=%main::cfg;  # FIXME: must be provided by caller
our $host; # FIXME: used in _timeOut()
our $port; # FIXME: used in _timeOut()

use vars   qw($VERSION @ISA @EXPORT @EXPORT_OK $HAVE_XS);

BEGIN {
    require Exporter;
    $VERSION    = 'NET::SSLhello_2014-06-16';
    @ISA        = qw(Exporter);
    @EXPORT     = qw(
        checkSSLciphers
        compileClientHello
        compileSSL2CipherArray
        compileTLSCipherArray
        hexCodedCipher
        hexCodedSSL2Cipher
        hexCodedString
        hexCodedTLSCipher
        parseServerHello
        parseSSL2_ServerHello
        parseTLS_Extension
        parseTLS_ServerHello
        printCipherStringArray
        printSSL2CipherList
        printTLSCipherList
        version
    );
    # insert above in vi with:
    # :r !sed -ne 's/^sub \([a-zA-Z][^ (]*\).*/        \1/p' % | sort -u

    $HAVE_XS = eval {
        local $SIG{'__DIE__'} = 'DEFAULT';
        eval {
            require XSLoader;
            XSLoader::load('Net::SSLhello', $VERSION);
            1;
        } or do {
            require DynaLoader;
            push @ISA, 'DynaLoader';
            bootstrap Net::SSLhello $VERSION;
            1;
        };

    } ? 1 : 0;
} # BEGIN

#defaults for global parameters
$Net::SSLhello::trace        = 0;# 1=simple debugging Net::SSLhello
$Net::SSLhello::usesni       = 0;# 1 use SNI to connect to target
$Net::SSLhello::timeout      = 2;# time in seconds
$Net::SSLhello::retry        = 3;# number of retry when timeout
$Net::SSLhello::usereneg     = 0;# secure renegotiation 
$Net::SSLhello::starttls     = 0;#
$Net::SSLhello::double_reneg = 0;# 0=Protection against double renegotiation info is active
$Net::SSLhello::proxyhost    = "";#
$Net::SSLhello::proxyport    = "";#

use constant {
    _MY_SSL3_MAX_CIPHERS       => 32, # Max nr of Ciphers sent in a SSL3/TLS Client-Hello to test if they are szupported by the Server
    _MY_PRINT_CIPHERS_PER_LINE =>  8, # Nr of Ciphers printed in a trace
    _PROXY_CONNECT_MESSAGE1    => "CONNECT ",
    _PROXY_CONNECT_MESSAGE2    => " HTTP/1.1\n\n",
    _MAX_SEGMENT_COUNT_TO_RESET_RETRY_COUNT => 3 # Max Number og TCP-Segments that can reset the Retry-Counter to '0' for next read
};

#our $LONG_PACKET = 1940; # try to get a 2nd or 3rd segment for long packets

my %RECORD_TYPE = ( # RFC 5246
    'change_cipher_spec'    => 20, 
    'alert'                 => 21,
    'handshake'             => 22,
    'application_data'      => 23,    
    'heartbeat'             => 24,
    '255'                   => 255
);

my %HANDSHAKE_TYPE = ( # RFC 5246
    'hello_request'         => 0,
    'client_hello'          => 1,
    'server_hello'          => 2,
    'certificate'           => 11,
    'server_key_exchange'   => 12,
    'certificate_request'   => 13,
    'server_hello_done'     => 14,
    'certificate_verify'    => 15,
    'client_key_exchange'   => 16,
    'finished'              => 20,
    '255'                   => 255
);

my %PROTOCOL_VERSION = (
    'SSLv2'      => 0x0002,
    'SSLv3'      => 0x0300,
    'TLSv1'      => 0x0301,
    'TLSv11'     => 0x0302, # adapted to o-saft.pl, was TLS1.1
    'TLSv12'     => 0x0303, # adapted to o-saft.pl, was TLS1.2
    'TLSv13'     => 0x0304, # adapted to o-saft.pl, was TLS1.3
    'DTLSv1'     => 0xFEFF, # adapted to o-saft.pl, was missing
    'SCSV'       => 0x03FF  # adapted to o-saft.pl, was TLS1.FF # FIXME: TLS1.FF was better ;-)
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

##################################################################################
# List of Functions
##################################################################################
sub checkSSLciphers ($$$@);
sub printCipherStringArray ($$$$$@);
sub _timedOut;
sub _error;

#ToDo: import/export of the trace-function from o-saft-dbx.pm;
#this is a workaround to get trace running using parameter '$main::cfg{'trace'}'
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

sub _trace($)  { local $\ = "";   print "#" . $mename . "::" . $_[0]          if ($main::cfg{'trace'} > 0); }
sub _trace0($) { local $\ = "";   print "#" . $mename . "::"                  if ($main::cfg{'trace'} > 0); }
sub _trace1($) { local $\ = "";   print "# " . $mename . "::" . join(" ", @_) if ($main::cfg{'trace'} > 1); }
sub _trace2($) { local $\ = "";   print "# --> " . $mename . "::" . join(" ", @_) if ($main::cfg{'trace'} > 2); }
sub _trace3($) { local $\ = "";   print "# --> " . $mename . "::" . join(" ", @_) if ($main::cfg{'trace'} == 3);}
sub _trace4($) { local $\ = "";   print "#   ---> " . $mename . "::" . join(" ", @_) if ($main::cfg{'trace'} > 3); }
sub _trace_($) { local $\ = "";   print " " . join(" ", @_)                   if ($main::cfg{'trace'} > 0); }
sub _trace1_($){ local $\ = "";   print " " . join(" ", @_)                   if ($main::cfg{'trace'} > 1); }
sub _trace2_($){ local $\ = "";   print join(" ", @_)                         if ($main::cfg{'trace'} > 2); }
sub _trace3_($){ local $\ = "";   print join(" ", @_)                         if ($main::cfg{'trace'} == 3); }
sub _trace4_($){ local $\ = "";   print join(" ", @_)                         if ($main::cfg{'trace'} > 3); }

#if (! eval("require o-saft-dbx.pm;")) {
#        # o-saft-dbx.pm may not be installed, try to find in program's directory
#        push(@INC, $main::mepath);
#        require "o-saft-dbx.pm";
#}
### end trace functions

###################################################################################

my $CHALLENGE = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20o-saft\xbb\xcc\xdd\xee\xff";    #16-32 Bytes,

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
  '0x0300001B'=> [qw(ADH_DES_192_CBC_SHA                      ADH-DES-CBC3-SHA)],
  '0x03000019'=> [qw(ADH_DES_40_CBC_SHA                       EXP-ADH-DES-CBC-SHA)],
  '0x0300001A'=> [qw(ADH_DES_64_CBC_SHA                       ADH-DES-CBC-SHA)],
  '0x03000018'=> [qw(ADH_RC4_128_MD5                          ADH-RC4-MD5)],
  '0x03000017'=> [qw(ADH_RC4_40_MD5                           EXP-ADH-RC4-MD5)],
  '0x0300000D'=> [qw(DH_DSS_DES_192_CBC3_SHA                  DH-DSS-DES-CBC3-SHA)],
  '0x0300000B'=> [qw(DH_DSS_DES_40_CBC_SHA                    EXP-DH-DSS-DES-CBC-SHA)],
  '0x0300000C'=> [qw(DH_DSS_DES_64_CBC_SHA                    DH-DSS-DES-CBC-SHA)],
  '0x03000010'=> [qw(DH_RSA_DES_192_CBC3_SHA                  DH-RSA-DES-CBC3-SHA)],
  '0x0300000E'=> [qw(DH_RSA_DES_40_CBC_SHA                    EXP-DH-RSA-DES-CBC-SHA)],
  '0x0300000F'=> [qw(DH_RSA_DES_64_CBC_SHA                    DH-RSA-DES-CBC-SHA)],
  '0x03000013'=> [qw(EDH_DSS_DES_192_CBC3_SHA                 EDH-DSS-DES-CBC3-SHA)],
  '0x03000011'=> [qw(EDH_DSS_DES_40_CBC_SHA                   EXP-EDH-DSS-DES-CBC-SHA)],
  '0x03000012'=> [qw(EDH_DSS_DES_64_CBC_SHA                   EDH-DSS-DES-CBC-SHA)],
  '0x03000016'=> [qw(EDH_RSA_DES_192_CBC3_SHA                 EDH-RSA-DES-CBC3-SHA)],
  '0x03000014'=> [qw(EDH_RSA_DES_40_CBC_SHA                   EXP-EDH-RSA-DES-CBC-SHA)],
  '0x03000015'=> [qw(EDH_RSA_DES_64_CBC_SHA                   EDH-RSA-DES-CBC-SHA)],
  '0x0300001D'=> [qw(FZA_DMS_FZA_SHA                          FZA-FZA-CBC-SHA)],
  '0x0300001C'=> [qw(FZA_DMS_NULL_SHA                         FZA-NULL-SHA)],
  '0x0300001E'=> [qw(FZA_DMS_RC4_SHA                          FZA-RC4-SHA)],
  '0x03000023'=> [qw(KRB5_DES_192_CBC3_MD5                    KRB5-DES-CBC3-MD5)],
  '0x0300001F'=> [qw(KRB5_DES_192_CBC3_SHA                    KRB5-DES-CBC3-SHA)],
  '0x03000029'=> [qw(KRB5_DES_40_CBC_MD5                      EXP-KRB5-DES-CBC-MD5)],
  '0x03000026'=> [qw(KRB5_DES_40_CBC_SHA                      EXP-KRB5-DES-CBC-SHA)],
  '0x03000022'=> [qw(KRB5_DES_64_CBC_MD5                      KRB5-DES-CBC-MD5)],
  '0x0300001E'=> [qw(KRB5_DES_64_CBC_SHA                      KRB5-DES-CBC-SHA)],
  '0x03000025'=> [qw(KRB5_IDEA_128_CBC_MD5                    KRB5-IDEA-CBC-MD5)],
  '0x03000021'=> [qw(KRB5_IDEA_128_CBC_SHA                    KRB5-IDEA-CBC-SHA)],
  '0x0300002A'=> [qw(KRB5_RC2_40_CBC_MD5                      EXP-KRB5-RC2-CBC-MD5)],
  '0x03000027'=> [qw(KRB5_RC2_40_CBC_SHA                      EXP-KRB5-RC2-CBC-SHA)],
  '0x03000024'=> [qw(KRB5_RC4_128_MD5                         KRB5-RC4-MD5)],
  '0x03000020'=> [qw(KRB5_RC4_128_SHA                         KRB5-RC4-SHA)],
  '0x0300002B'=> [qw(KRB5_RC4_40_MD5                          EXP-KRB5-RC4-MD5)],
  '0x03000028'=> [qw(KRB5_RC4_40_SHA                          EXP-KRB5-RC4-SHA)],
  '0x0300000A'=> [qw(RSA_DES_192_CBC3_SHA                     DES-CBC3-SHA)],
  '0x03000008'=> [qw(RSA_DES_40_CBC_SHA                       EXP-DES-CBC-SHA)],
  '0x03000009'=> [qw(RSA_DES_64_CBC_SHA                       DES-CBC-SHA)],
  '0x03000007'=> [qw(RSA_IDEA_128_SHA                         IDEA-CBC-SHA)],
  '0x03000001'=> [qw(RSA_NULL_MD5                             NULL-MD5)],
  '0x03000002'=> [qw(RSA_NULL_SHA                             NULL-SHA)],
  '0x03000006'=> [qw(RSA_RC2_40_MD5                           EXP-RC2-CBC-MD5)],
  '0x03000004'=> [qw(RSA_RC4_128_MD5                          RC4-MD5)],
  '0x03000005'=> [qw(RSA_RC4_128_SHA                          RC4-SHA)],
  '0x03000003'=> [qw(RSA_RC4_40_MD5                           EXP-RC4-MD5)],
  '0x030000FF'=> [qw(EMPTY_RENEGOTIATION_INFO_SCSV            SCSV)], #activated 'Signaling Cipher Suite Value'
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
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+  
  '0x0300CC12'=> [qw(RSA_WITH_CHACHA20_POLY1305         RSA-CHACHA20-POLY1305)],
  '0x0300CC13'=> [qw(ECDHE_RSA_WITH_CHACHA20_POLY1305   ECDHE-RSA-CHACHA20-POLY1305)],
  '0x0300CC14'=> [qw(ECDHE_ECDSA_WITH_CHACHA20_POLY1305 ECDHE-ECDSA-CHACHA20-POLY1305)],

  '0x0300CC15'=> [qw(DHE_RSA_WITH_CHACHA20_POLY1305     DHE-RSA-CHACHA20-POLY1305)],
  '0x0300CC16'=> [qw(DHE_PSK_WITH_CHACHA20_POLY1305     DHE-PSK-CHACHA20-POLY1305)],

  '0x0300CC17'=> [qw(PSK_WITH_CHACHA20_POLY1305         PSK-CHACHA20-POLY1305)],
  '0x0300CC18'=> [qw(ECDHE_PSK_WITH_CHACHA20_POLY1305   ECDHE-PSK-CHACHA20-POLY1305)],
  '0x0300CC19'=> [qw(RSA_PSK_WITH_CHACHA20_POLY1305     RSA-PSK-CHACHA20-POLY1305)],

  '0x0300CC20'=> [qw(RSA_WITH_CHACHA20_SHA              RSA-CHACHA20-SHA)],
  '0x0300CC21'=> [qw(ECDHE_RSA_WITH_CHACHA20_SHA        ECDHE-RSA-CHACHA20-SHA)],
  '0x0300CC22'=> [qw(ECDHE_ECDSA_WITH_CHACHA20_SHA      ECDHE-ECDSA-CHACHA20-SHA)],

  '0x0300CC23'=> [qw(DHE_RSA_WITH_CHACHA20_SHA          DHE-RSA-CHACHA20-SHA)],
  '0x0300CC24'=> [qw(DHE_PSK_WITH_CHACHA20_SHA          DHE-PSK-CHACHA20-SHA)],

  '0x0300CC25'=> [qw(PSK_WITH_CHACHA20_SHA              PSK-CHACHA20-SHA)],
  '0x0300CC26'=> [qw(ECDHE_PSK_WITH_CHACHA20_SHA        ECDHE-PSK-CHACHA20-SHA)],
  '0x0300CC27'=> [qw(RSA_PSK_WITH_CHACHA20_SHA          RSA-PSK-CHACHA20-SHA)],
#!#----------------------------------------+-------------+--------------------+



); # cipherHexHash

#################################################################

# TLS_PROTOCOL_MESSAGE_CODES 
my $TLS_CLIENT_HELLO    = 1;
my $TLS_SERVER_HELLO    = 2;

my $input="";

my %SSL2_CIPHER_STRINGS = (
  '0x020700C0'=> [qw(DES_192_EDE3_CBC_WITH_MD5                DES-CBC3-MD5        SSL_CK_DES_192_EDE3_CBC_WITH_MD5)],
  '0x020701C0'=> [qw(DES_192_EDE3_CBC_WITH_SHA                DES-CBC3-SHA)],
  '0x02060040'=> [qw(DES_64_CBC_WITH_MD5                      DES-CBC-MD5        SSL_CK_DES_64_CBC_WITH_MD5)],
  '0x02060140'=> [qw(DES_64_CBC_WITH_SHA                      DES-CBC-SHA)],
  '0x02FF0800'=> [qw(DES_64_CFB64_WITH_MD5_1                  DES-CFB-M1)],
  '0x02050080'=> [qw(IDEA_128_CBC_WITH_MD5                    IDEA-CBC-MD5        SSL_CK_IDEA_128_CBC_WITH_MD5)],
  '0x02FF0810'=> [qw(NULL                                     NULL)],
  '0x02000000'=> [qw(NULL_WITH_MD5                            NULL-MD5)],
  '0x02040080'=> [qw(RC2_128_CBC_EXPORT40_WITH_MD5            EXP-RC2-CBC-MD5    SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5)],
  '0x02030080'=> [qw(RC2_128_CBC_WITH_MD5                     RC2-CBC-MD5        SSL_CK_RC2_128_CBC_WITH_MD5)],
  '0x02020080'=> [qw(RC4_128_EXPORT40_WITH_MD5                EXP-RC4-MD5        SSL_CK_RC4_128_EXPORT40_WITH_MD5)],
  '0x02010080'=> [qw(RC4_128_WITH_MD5                         RC4-MD5            SSL_CK_RC4_128_WITH_MD5)],
  '0x02FFFFFF'=> [qw(SSL2_UNFFINED_CIPHER_0x02FFFFFF           SSL2_UNFFINED_CIPHER_0x02FFFFFF             SSL2_UNFFINED_CIPHER_0x02FFFFFF)],
#!#----------------------------------------+-------------+--------------------+
#!# Protocol: SSL3 (invented)
#!#----------------------------------------+-------------+--------------------+
#!# cipher suite hex value => [ cipher_name1 cipher_name2 ],
#!#----------------------------------------+-------------+--------------------+
  '0x0300001B'=> [qw(ADH_DES_192_CBC_SHA                      ADH-DES-CBC3-SHA)],
  '0x03000019'=> [qw(ADH_DES_40_CBC_SHA                       EXP-ADH-DES-CBC-SHA)],
  '0x0300001A'=> [qw(ADH_DES_64_CBC_SHA                       ADH-DES-CBC-SHA)],
  '0x03000018'=> [qw(ADH_RC4_128_MD5                          ADH-RC4-MD5)],
  '0x03000017'=> [qw(ADH_RC4_40_MD5                           EXP-ADH-RC4-MD5)],
  '0x0300000D'=> [qw(DH_DSS_DES_192_CBC3_SHA                  DH-DSS-DES-CBC3-SHA)],
  '0x0300000B'=> [qw(DH_DSS_DES_40_CBC_SHA                    EXP-DH-DSS-DES-CBC-SHA)],
  '0x0300000C'=> [qw(DH_DSS_DES_64_CBC_SHA                    DH-DSS-DES-CBC-SHA)],
  '0x03000010'=> [qw(DH_RSA_DES_192_CBC3_SHA                  DH-RSA-DES-CBC3-SHA)],
  '0x0300000E'=> [qw(DH_RSA_DES_40_CBC_SHA                    EXP-DH-RSA-DES-CBC-SHA)],
  '0x0300000F'=> [qw(DH_RSA_DES_64_CBC_SHA                    DH-RSA-DES-CBC-SHA)],
  '0x03000013'=> [qw(EDH_DSS_DES_192_CBC3_SHA                 EDH-DSS-DES-CBC3-SHA)],
  '0x03000011'=> [qw(EDH_DSS_DES_40_CBC_SHA                   EXP-EDH-DSS-DES-CBC-SHA)],
  '0x03000012'=> [qw(EDH_DSS_DES_64_CBC_SHA                   EDH-DSS-DES-CBC-SHA)],
  '0x03000016'=> [qw(EDH_RSA_DES_192_CBC3_SHA                 EDH-RSA-DES-CBC3-SHA)],
  '0x03000014'=> [qw(EDH_RSA_DES_40_CBC_SHA                   EXP-EDH-RSA-DES-CBC-SHA)],
  '0x03000015'=> [qw(EDH_RSA_DES_64_CBC_SHA                   EDH-RSA-DES-CBC-SHA)],
  '0x0300001D'=> [qw(FZA_DMS_FZA_SHA                          FZA-FZA-CBC-SHA)],
  '0x0300001C'=> [qw(FZA_DMS_NULL_SHA                         FZA-NULL-SHA)],
#  '0x0300001E'=> [qw(FZA_DMS_RC4_SHA                          FZA-RC4-SHA)], #doppelt => prüfen
  '0x03000023'=> [qw(KRB5_DES_192_CBC3_MD5                    KRB5-DES-CBC3-MD5)],
  '0x0300001F'=> [qw(KRB5_DES_192_CBC3_SHA                    KRB5-DES-CBC3-SHA)],
  '0x03000029'=> [qw(KRB5_DES_40_CBC_MD5                      EXP-KRB5-DES-CBC-MD5)],
  '0x03000026'=> [qw(KRB5_DES_40_CBC_SHA                      EXP-KRB5-DES-CBC-SHA)],
  '0x03000022'=> [qw(KRB5_DES_64_CBC_MD5                      KRB5-DES-CBC-MD5)],
  '0x0300001E'=> [qw(KRB5_DES_64_CBC_SHA                      KRB5-DES-CBC-SHA)],
  '0x03000025'=> [qw(KRB5_IDEA_128_CBC_MD5                    KRB5-IDEA-CBC-MD5)],
  '0x03000021'=> [qw(KRB5_IDEA_128_CBC_SHA                    KRB5-IDEA-CBC-SHA)],
  '0x0300002A'=> [qw(KRB5_RC2_40_CBC_MD5                      EXP-KRB5-RC2-CBC-MD5)],
  '0x03000027'=> [qw(KRB5_RC2_40_CBC_SHA                      EXP-KRB5-RC2-CBC-SHA)],
  '0x03000024'=> [qw(KRB5_RC4_128_MD5                         KRB5-RC4-MD5)],
  '0x03000020'=> [qw(KRB5_RC4_128_SHA                         KRB5-RC4-SHA)],
  '0x0300002B'=> [qw(KRB5_RC4_40_MD5                          EXP-KRB5-RC4-MD5)],
  '0x03000028'=> [qw(KRB5_RC4_40_SHA                          EXP-KRB5-RC4-SHA)],
  '0x0300000A'=> [qw(RSA_DES_192_CBC3_SHA                     DES-CBC3-SHA)],
  '0x03000008'=> [qw(RSA_DES_40_CBC_SHA                       EXP-DES-CBC-SHA)],
  '0x03000009'=> [qw(RSA_DES_64_CBC_SHA                       DES-CBC-SHA)],
  '0x03000007'=> [qw(RSA_IDEA_128_SHA                         IDEA-CBC-SHA)],
  '0x03000001'=> [qw(RSA_NULL_MD5                             NULL-MD5)],
  '0x03000002'=> [qw(RSA_NULL_SHA                             NULL-SHA)],
  '0x030000FF'=> [qw(EMPTY_RENEGOTIATION_INFO_SCSV            SCSV)],
);


#############################################################################################
############################################################################################
sub version { # Version of SSLhello
    print "$VERSION\n";
    _trace ("version: global Parameters: Timeout=$Net::SSLhello::timeout, Retry=$Net::SSLhello::retry\n");
#   test trace (see 'tbd: import/export of the trace-function from o-saft-dbx.pm;')
#    print "\$main::cfg\{\'trace\'\}=$main::cfg{'trace'}\n";
#    print "\$Net::SSLhello::trace=$Net::SSLhello::trace\n";
#    _trace("_trace\n");
#    _trace_("_trace_\n");
#    _trace1("_trace1\n");
#    _trace1_("_trace1_\n");
#    _trace2("_trace2\n");
#    _trace2_("_trace2_\n");
#    _trace3("_trace3\n");
#    _trace3_("_trace3_\n");
#    _trace4("_trace4\n");
#    _trace4_("_trace4_\n");
}

### --------------------------------------------------------------------------------------------------------- ###
### compile packets functions
### ---------------------------------------------------------------------------------------------------------
### Aufruf mit printCipherStringArray ($cfg{'legacy'}, $host, $port, "TLS1.2 0x0303", $cfg{'usesni'}, @acceptedCipherArray);
sub printCipherStringArray ($$$$$@) {
    #? @cipherArray: String Representation of the Cipher Octetts, fe.g. 0x0300000A
    #? The first two Ciphers are identical, if the Server has a preferred Order 
    #

    my($legacy, $host, $port, $ssl, $usesni, @cipherArray) = @_;
#    my $legacy    = shift; #$_[0]
#    my $host    = shift; #$_[1]
#    my $port    = shift; #$_[2]
#    my $ssl        = shift; #$_[3]
#    my $usesni    = shift; #$_[4]
#    my (@cipherArray) = @{$_[5]};

    my $protocolCipher ="";
    my $arrayLen = @cipherArray;
    my $cipherOrder = ""; # Cipher Suites in server-preferred order or not
    my $sni    = "";
    my $sep =", ";
    my $protocol = $PROTOCOL_VERSION{$ssl}; # 0x0002, 0x3000, 0x0301, 0x0302

    _trace4 ("printCipherStringArray: {\n");
    
    if ($usesni) {
        $sni = "SNI";
    } else {
        $sni = "no SNI";
    }
    
    my $firstEle = 0;
    if ($arrayLen > 1) { # 2 or more ciphers
        if ( ($cipherArray[0] eq $cipherArray[1]) ) { # Cipher Suites in Server-preferred order
            if ($legacy eq 'compact') { $cipherOrder = "Server Order"; } else { print "# Cipher Suites in server-preferred order:\n"; }
            $firstEle = 1;
        } else {
            if ($legacy eq 'compact') { $cipherOrder = "No Order"; } else { print "# Server has NO preferred order for Cipher Suites\n"; } 
        }
    } elsif ($arrayLen == 0) { # no Cipher for this Protocol
        if ($legacy eq 'compact') { # csv-style, protocol without cipher 
            printf "%20s%s%5s%s%-6s (0x%04X)%s%6s%s%-12s%s%10s%s\n",
                $host, $sep,        # %20s%s
                $port, $sep,        # %5s%s
                $ssl,                 # %-6s (
                $protocol, $sep,    # 0x%04X)%s
                $sni, $sep,             # %6s%s%
                "", $sep,            # %-12s%s
                  "", $sep;            # %10s%s
        }
    }
    
       foreach $protocolCipher (@cipherArray[$firstEle .. $#cipherArray]) { # Array may have the first Element twice to signal a Server-Preferred Order
        if ($legacy eq 'compact') { # csv-style
            printf "%20s%s%5s%s%-6s (0x%04X)%s%6s%s%-12s%s%10s%s",
                $host, $sep,        # %20s%s
                $port, $sep,        # %5s%s
                $ssl,                 # %-6s (
                $protocol, $sep,    # 0x%04X)%s
                $sni, $sep,             # %6s%s%
                $cipherOrder, $sep,    # %-12s%s
                  $protocolCipher, $sep;    # %10s%s
              if ($cipherHexHash {$protocolCipher} ) { # definiert, kein Null-String

                printf "%-32s%s%s\n",
                    $cipherHexHash {$protocolCipher}[1], $sep,    # %-32s%s
                    $cipherHexHash {$protocolCipher}[0];        # %s    

            } else { # no RFC-Defined Cipher
                printf "%-32s%s%s\n",
                    "NO-RFC-".$protocolCipher, $sep,        # %-32s%s
                    "NO-RFC-".$protocolCipher;             # %s
            }
        } else { # human readable output 
               if ($cipherHexHash {$protocolCipher} ) { # definiert, kein Null-String
                    printf "# Cipher-String: >%s<, %-32s, %s",$protocolCipher, $cipherHexHash {$protocolCipher}[1], $cipherHexHash {$protocolCipher}[0];     
            } else {
                print  "# Cipher-String: >".$protocolCipher."<, NO-RFC-".$protocolCipher;     
            }
            print "\n";
        }
    }
    if ($legacy eq 'compact') { # csv-style
        print "\n";    
    }
    _trace4 ("printCipherStringArray: }\n\n");
}


sub checkSSLciphers ($$$@) {
    #? Simulate SSL Handshake to check any Ciphers by the HEX value
    #? @cipher_str_array: String Representation of the Cipher Octet, e.g. 0x0300000A
    #? If the first 2 Ciphers are identical the Array is sorted by Priority of the Server
    #
    my($host, $port, $ssl, @cipher_str_array) = @_;
#    my $host        = shift; # hostname
#    my $port        = shift;
#   my $ssl            = shift; # SSLv2
#    my @cipher_str_array= @{$_[0]};
    my @cipher_spec_array;
    my $cipher_str="";
    my $cipher_spec="";
    my $acceptedCipher="";
    my @cipherSpecArray = (); #temporary Array for all Ciphers to be tested in the next _doCheckSSLciphers
    my @acceptedCipherArray = (); # All Ciphers accepted by the Server
    my @acceptedCipherSortedArray = (); # All Ciphers accepted by the Server with Server Order
    my $arrayLen=0;
    my $i=0;
    my $anzahl = 0;
    my $protocol = $PROTOCOL_VERSION{$ssl}; # 0x0002, 0x3000, 0x0301, 0x0302
        
    if ($Net::SSLhello::trace > 0) { 
        _trace("checkSSLciphers ($host, $port, $ssl, Cipher-Strings:");
           foreach $cipher_str (@cipher_str_array) {    
            if (($i++) %_MY_PRINT_CIPHERS_PER_LINE == 0) { #  print up to '_MY_PRINT_CIPHERS_PER_LINE' Ciphers per line
                _trace_ ("\n   >$cipher_str<"); 
            } else {
                _trace_ (" >$cipher_str<");
            } 
        }
        _trace_(") {\n");
        $cipher_str="";
    }    

    if ($protocol == $PROTOCOL_VERSION{'SSLv2'}) { #SSL2
        _trace4_ ("\n");
        foreach $cipher_str (@cipher_str_array) {
            _trace4 ("checkSSLciphers: Cipher-String: >$cipher_str< -> ");
            ($cipher_str) =~ s/(?:0x03|0x02|0x)? ?([a-fA-F0-9]{2}) ?/chr(hex $1)/eg; ## Str2hex
            _trace4_ (" >". hexCodedCipher($cipher_str)."<\n");

            $cipher_spec .= $cipher_str; # collect Cipher-Specs
        }
        _trace4_ ("\n");
        $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_spec);
        if ($Net::SSLhello::trace > 0) { #about: _trace
            $i = 0;
            my $anzahl = int length ($acceptedCipher) / 3;
            _trace(" checkSSLciphers: Accepted ". $anzahl ." Ciphers:\n");
            foreach $cipher_str (compileSSL2CipherArray ($acceptedCipher) ) {    
                if (($i++) %_MY_PRINT_CIPHERS_PER_LINE == 0) { #  print up to '_MY_PRINT_CIPHERS_PER_LINE' Ciphers per line
                    _trace_ ("\n          >" . $cipher_str . "<"); 
                } else {
                    _trace_ (" >" . $cipher_str . "<");
                }
            }
            _trace_("\n");
            _trace(" checkSSLciphers: }\n\n");
        }
        return (compileSSL2CipherArray ($acceptedCipher)); 
    } else { # SSL3, TLS,.... check by the cipher
        $cipher_spec = ""; # collect Cipher-Specs
        _trace4_ ("\n");
        foreach $cipher_str (@cipher_str_array) {
            _trace4 ("checkSSLciphers: Cipher-String: >$cipher_str< -> ");
            if ($cipher_str !~ /0x02/) { # No SSL2-Cipher
                ($cipher_str) =~ s/(?:0x0[3-9a-fA-F]00|0x)? ?([a-fA-F0-9]{2}) ?/chr(hex $1)/eg; ## Str2hex    
                _trace4_ ("  >". hexCodedCipher($cipher_str)."<");    
            } else { 
                _trace4_ ("  SSL2-Cipher suppressed\n");
                next; #nothing to do for this Cipher
            }
            _trace4_ ("\n");
            
            push (@cipherSpecArray , $cipher_str); # add Cipher to next Test
            $arrayLen = @cipherSpecArray;
            if ( $arrayLen >= _MY_SSL3_MAX_CIPHERS) { # test up to _MY_SSL3_MAX_CIPHERS with 1 doCheckSSLciphers (=> Client Hello)
                $@=""; # reset Error-Msg
                $cipher_spec = join ("",@cipherSpecArray); # All Ciphers to test in this round
                
                if ($Net::SSLhello::trace > 1) { #Print Ciphers that are tested this round:
                    $i = 0;
                    if (($Net::SSLhello::starttls > 0)) {
                        _trace1 ("checkSSLciphers ($host, $port (STARTTLS), $ssl): Checking ". scalar(@cipherSpecArray)." Ciphers, this round (1):");
                    } else {
                        _trace1 ("checkSSLciphers ($host, $port, $ssl): Checking ". scalar(@cipherSpecArray)." Ciphers, this round (1):");
                    }
                    _trace4_ ("\n");
                    foreach $cipher_str (compileTLSCipherArray (join ("",@cipherSpecArray)) ) {    
                        if (($i++) %_MY_PRINT_CIPHERS_PER_LINE == 0) { #  print up to '_MY_PRINT_CIPHERS_PER_LINE' Ciphers per line
                            _trace_ ("\n   >" . $cipher_str . "<"); 
                        } else {
                            _trace_ (" >" . $cipher_str . "<");
                        }    
                    }
                    _trace2_ ("\n");
                }
                $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_spec); # Test Ciphers and collect Accepted Ciphers
                _trace2_ ("       ");
                if ($acceptedCipher) { # received an accepted Cipher
                    _trace1_ ("=> found >0x0300".hexCodedCipher($acceptedCipher)."<\n");
                    @cipherSpecArray = grep { $_ ne $acceptedCipher } @cipherSpecArray;    # delete accepted Cipher from ToDo-Array '@cipherSpecArray'
                    push (@acceptedCipherArray, $acceptedCipher); # add the Cipher to the List of accepted Ciphers 
                } else {
                    _trace1_ ("=> no Cipher found\n");
                    @cipherSpecArray =(); # Server did not accept any Cipher => Nothing to do for these Ciphers => Empty @cipherSpecArray
                    if ( ($@ =~ /make a connection/ ) || ($@ =~ /create a socket/) || ($@ =~ /target.*?ignored/) || ($@ =~ /protocol.*?ignored/) ) {   #### Fatal Errors -> Useless to check more ciphers
                        _trace2 (">>> checkSSLciphers (1): '$@'\n"); 
                        warn ("**WARNING: checkSSLciphers => Exit Loop (1)");
                        last;
                    } elsif ( ($@ =~ /answer ignored/) || ($@ =~ /protocol_version.*?not supported/) || ($@ =~ /check.*?aborted/) ) { # Just stop, no warning
                        _trace1 (">>> checkSSLciphers (2): '$@'\n"); 
                        last;
                    } else {
                        $@=""; # reset Error-Msg
                    }
                }    
            }
        }
        while ( (@cipherSpecArray > 0) && (!$@) ) { # there are still ciphers to test in this last round
            $cipher_spec = join ("",@cipherSpecArray); # All Ciphers to test in this round
            if ($Net::SSLhello::trace > 1) { #Print Ciphers that are tested this round:
                $i = 0;
                _trace ("checkSSLciphers ($host, $port, $ssl): Checking ". scalar(@cipherSpecArray)." Ciphers, this round (2):");
                _trace4_ ("\n");
                foreach $cipher_str (compileTLSCipherArray (join ("",@cipherSpecArray)) ) {    
                    if (($i++) %_MY_PRINT_CIPHERS_PER_LINE == 0) { #  print up to '_MY_PRINT_CIPHERS_PER_LINE' Ciphers per line
                        _trace_ ("\n   >" . $cipher_str . "<"); 
                    } else {
                        _trace_ ( " >" . $cipher_str . "<");
                    }     
                }
                _trace2_ ("\n");
            }
            $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_spec); # Test Ciphers and collect Accepted Ciphers
            _trace2_ ("       ");
            if ($acceptedCipher) { # received an accepted Cipher
                _trace1_ ("=> found >0x0300".hexCodedCipher($acceptedCipher)."<\n");
                @cipherSpecArray = grep { $_ ne $acceptedCipher } @cipherSpecArray;    # delete accepted Cipher from ToDo-Array '@cipherSpecArray'
                push (@acceptedCipherArray, $acceptedCipher); # add the Cipher to the List of accepted Ciphers 
            } else {
                _trace1_ ("=> no Cipher found\n");
                @cipherSpecArray =(); # Server did not Accepty any Cipher => Nothing to do for these Ciphers => Empty @cipherSpecArray
                if ( ($@ =~ /make a connection/ ) || ($@ =~ /create a socket/) || ($@ =~ /target.*?ignored/) || ($@ =~ /protocol.*?ignored/) ) {   #### Fatal Warning -> Stop this Host
                    warn ("**WARNING: checkSSLciphers => Exit Loop (2)\n");
                } elsif ( ($@ =~ /answer ignored/) || ($@ =~ /protocol_version.*?not supported/) || ($@ =~ /check.*?aborted/) ) { # Just stop, no warning
                    _trace1 ("**checkSSLciphers => Exit Loop (3)\n"); 
                }
                $@=""; # reset Error-Msg
                last; # no more Ciphers to Test
            }    
        }

        if ($Net::SSLhello::trace > 0) { #about: _trace
            $i = 0;
            _trace(" checkSSLciphers ($host, $port, $ssl): Accepted ". scalar(@acceptedCipherArray)." Ciphers (unsorted):");
            foreach $cipher_str (compileTLSCipherArray (join ("",@acceptedCipherArray)) ) {    
                if (($i++) %_MY_PRINT_CIPHERS_PER_LINE == 0) { #  print up to '_MY_PRINT_CIPHERS_PER_LINE' Ciphers per line
                    _trace_ ("\n   >" . $cipher_str . "<"); 
                } else {
                    _trace_ (" >" . $cipher_str . "<");
                } 
            }
            _trace_("\n");
            $cipher_str="";
        }
        
        # >>>>> Check Priority of Ciphers <<<<<
        ####################################################################################################################
        ######      Derzeit wird der 1. Cipher doppelt in die Liste eingetragen, wenn der Server die Prio vorgibt      #####
        ####################################################################################################################
        $cipher_str = join ("",@acceptedCipherArray);
        printTLSCipherList ($cipher_str) if ($Net::SSLhello::trace > 3); # abt: _trace4

        while ($cipher_str) { # found some cipher => Check priority
            _trace3 ("checkSSLciphers: Check Cipher Prioity for Cipher-Spec >". hexCodedString($cipher_str)."<\n");
            _trace4 ("checkSSLciphers: Check Cipher Prioity for Cipher-Spec >". hexCodedString($cipher_str)."<\n");
            $@=""; # reset Error-Msg
            $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_str); # collect Accepted Ciphers by Priority
            _trace2_ ("#                                  -->". hexCodedCipher($acceptedCipher)."<\n");
            if ($@) { 
                _trace2 (">>> checkSSLciphers (4): '$@'\n"); 
                if ( ($@ =~ /make a connection/ ) || ($@ =~ /create a socket/) || ($@ =~ /target.*?ignored/) || ($@ =~ /protocol.*?ignored/) ) {
                    warn ("**WARNING: => Unexpected Loss of Connection while checking the priority of the ciphers: Exit Loop (1)");
                    $@=""; # reset Error-Msg
                    last;
                } elsif ( ($@ =~ /answer ignored/) || ($@ =~ /protocol_version.*?not supported/) || ($@ =~ /check.*?aborted/) ) { # Just stop, no warning
                    _trace1 (">>> checkSSLciphers (5): '$@'\n"); 
                    last;
                } 
            }
            if ($acceptedCipher) { # received an accepted Cipher
                push (@acceptedCipherSortedArray, $acceptedCipher); # add found Cipher to sorted List
                $arrayLen = @acceptedCipherSortedArray;
                if ( $arrayLen == 1) { # 1st Cipher 
                    if     ($acceptedCipher eq ($acceptedCipherArray[0])) { # is equal to 1st Cipher of requested cipher_spec
                        _trace3    ("#   Got back 1st Cipher of unsorted List => Check again with this Cipher >".hexCodedTLSCipher($acceptedCipher)."< at the end of the List\n");
                        shift (@acceptedCipherArray); # delete first cipher in this array
                        $cipher_str = join ("",@acceptedCipherArray).$acceptedCipher; # Test again with the first Cipher as the last 
                        _trace3 ("Check Cipher Prioity for Cipher-S(2) > ". hexCodedCipher($cipher_str)."< ");
                        _trace4 ("\n");
                        $acceptedCipher = _doCheckSSLciphers($host, $port, $protocol, $cipher_str); # If Server uses a Priority List we get the same Cipher again!
                        _trace3_ ("#                                  -->". hexCodedCipher($acceptedCipher)."<\n");
                        _trace4_ ("#                                 --->". hexCodedCipher($acceptedCipher)."<\n");
                        if ($acceptedCipher) { # received an accepted Cipher ### TBD: if ($acceptedCipher eq ($acceptedCipherArray[0]) => no Order => return (@acceptedCipherSortedArray[0].$acceptedCipherArray)  
                            push (@acceptedCipherSortedArray, $acceptedCipher); 
                        }
                    } else { # 1st Element is NOT equal of 1st checked Cipher => sorted => NOW: Add Cipher again to mark it as sorted list 
                        push (@acceptedCipherSortedArray, $acceptedCipher); # add found Cipher again to sorted List
                    }
                } # not the first Cipher
                @acceptedCipherArray = grep { $_ ne $acceptedCipher } @acceptedCipherArray;    # delete accepted Cipher in ToDo-Array '@acceptedCipherArray'
                $cipher_str = join ("",@acceptedCipherArray); # Check Prio for next Ciphers
            } else { # nothing received => Lost Connection
                _trace2 (">>> checkSSLciphers (6): '$@'\n");
                if ( ($@ =~ /make a connection/ ) || ($@ =~ /create a socket/) || ($@ =~ /target.*?ignored/) || ($@ =~ /protocol.*?ignored/) ) {
                    warn ("**WARNING: => Unexpected Loss of Connection while checking the priority of the ciphers: Exit Loop (2)");
                    $@=""; # reset Error-Msg
                    last;
                } elsif ( ($@ =~ /answer ignored/) || ($@ =~ /protocol_version.*?not supported/) || ($@ =~ /check.*?aborted/) ) { # Just stop, no warning
                    _trace1 (">>> checkSSLciphers (7): '$@'\n");
                    $@=""; # reset Error-Msg                    
                    last;
                } 
            }
        } # end while-Loop
        _trace4 ("#   Accepted (sorted) Ciphers [cipher1 = cipher 2 => sorted by Server]:\n");
### TBD: _trace4: print all Ciphers?!!
        _trace(" checkSSLciphers: }\n\n");
        return (compileTLSCipherArray (join ("",@acceptedCipherSortedArray))); 
       }
}

sub _doCheckSSLciphers ($$$$) {
    #? Simulate SSL Handshake to check any Ciphers by the HEX value
    #? $cipher_spec: RAW Octets according to RFC
    #
    my $host        = shift; # hostname
    my $port        = shift;
    my $protocol    = shift; # 0x0002, 0x3000, 0x0301, 0x0302, 0x0303, etc
    my $cipher_spec = shift;
    my $socket;
    my $connect2ip;
    my $proxyConnect="";
    my $clientHello="";
    my $input="";
    my $input2="";
    my $input3="";
    my $pduLen=0;
    my $v2len=0;
    my $v2type=0;
    my $v3len=0;
    my $v3type=0;
    my $v3version=0;
    my $acceptedCipher="";
    my $retryCnt = 0;
    my $firstMessage = "";
    my $secondMessage = "";
    my $segmentCnt=0;
    
    _trace4 (sprintf ("_doCheckSSLciphers ($host, $port, >%04X<\n          >",$protocol).hexCodedString ($cipher_spec,"           ") .") {\n");
    $@ ="";
    $clientHello = compileClientHello ($protocol, $protocol, $cipher_spec, $host); 
    if ($@) { #Error
        _trace2 (">>> Exit _doCheckSSLciphers }\n"); 
        return ("");
    }
    _trace4 ("_doCheckSSLciphers: clientHello:\n          >".hexCodedString ($clientHello,"           ")."<\n");

    if ( ($Net::SSLhello::proxyhost) && ($Net::SSLhello::proxyport) ) { # via Proxy
        _trace2 ("_doCheckSSLciphers: Try to connect to $host:$port via Proxy ".$Net::SSLhello::proxyhost.":".$Net::SSLhello::proxyport."\n");
    } else {
        _trace2 ("_doCheckSSLciphers: Try to connect to $host:$port\n");
    }    
    $retryCnt = 0;
    do {{
        $@ ="";
        $input="";
        $input2="";
        $input3="";
        alarm (0); # switch off alarm (e.g. for  next retry 
        if ($retryCnt >0) { ##20140528
            _trace1 ("_doCheckSSLciphers: $retryCnt. Retry to connect to '$host:$port'\n");
        }
        eval  {    
            $SIG{ALRM}= "Net::SSLhello::_timedOut"; 
            alarm($Net::SSLhello::timeout); # set Alarm for get-socket and set-socketoptions->timeout(s)        
            socket($socket,PF_INET,SOCK_STREAM,(getprotobyname('tcp'))[2]) or die "Can't create a socket \'$!\' -> target $host:$port ignored ";
            setsockopt($socket, SOL_SOCKET, SO_SNDTIMEO, pack('L!L!', $Net::SSLhello::timeout, 0) ) or die "Can't set socket Sent-Timeout \'$!\' -> target $host:$port ignored"; #L!L! => compatible to 32 and 64-bit
            setsockopt($socket, SOL_SOCKET, SO_RCVTIMEO, pack('L!L!', $Net::SSLhello::timeout, 0) ) or die "Can't set socket Receive-Timeout \'$!\' -> target $host:$port ignored";
            alarm (0);             #clear alarm
        }; # Do NOT forget the ;
        
        unless ($@) { # all OK
            if ( ($Net::SSLhello::proxyhost) && ($Net::SSLhello::proxyport) ) { # via Proxy
                eval {
                    $SIG{ALRM}= "Net::SSLhello::_timedOut"; 
                    alarm($Net::SSLhello::timeout); # set Alarm for Connect
                    $connect2ip = inet_aton($Net::SSLhello::proxyhost);
                    if (!defined ($connect2ip) ) {
                        $retryCnt = $Net::SSLhello::retry; #Fatal Error NO retry
                        die "Can't get the IP-Address of the Proxy $Net::SSLhello::proxyhost:$Net::SSLhello::proxyport -> target $host:$port ignored";
                    }
                    connect($socket, pack_sockaddr_in($Net::SSLhello::proxyport, $connect2ip) ) or die "Can't make a connection to Proxy $Net::SSLhello::proxyhost:$Net::SSLhello::proxyport -> target $host:$port ignored";
                    alarm (0);
                }; # Do NOT forget the ;
                if ($@) { # no Connect
                    close ($socket) or warn("**WARNING: _doCheckSSLciphers: $@; Can't close socket, too: $!");
                    warn ("*** WARNING: _doCheckSSLciphers: $@");
                    warn ("*** Fatal Error: _doCheckSSLciphers: No connection to the Proxy -> Exit");
                    sleep (1);
                    exit (1); # Exit with Error
                }
                eval {
                    $proxyConnect=_PROXY_CONNECT_MESSAGE1.$host.":".$port._PROXY_CONNECT_MESSAGE2;
                    _trace4 ("_doCheckSSLciphers## ProxyConnect-Message: >$proxyConnect<\n");
                    $SIG{ALRM}= "Net::SSLhello::_timedOut"; 
                    alarm($Net::SSLhello::timeout); # set Alarm for Connect
                    defined(send($socket, $proxyConnect, 0)) || die  "Can't make a connection to $host:$port via Proxy $Net::SSLhello::proxyhost:$Net::SSLhello::proxyport; target ignored ";
                    alarm (0);
                }; # Do NOT forget the ;
                if ($@) { # no Connect
                    warn "**WARNING: _doCheckSSLciphers: >>> ... Could not send a CONNECT-Command to the Proxy: $Net::SSLhello::proxyhost:$Net::SSLhello::proxyport\n"; 
                    close ($socket) or warn("**WARNING: _doCheckSSLciphers: $@; Can't close socket, too: $!");
                    # next retry
                } else { # CONNECT via Proxy
                     eval {
                        #Alarm: Set alarm function _timedOut and activate alarm with timeout Alarm
                        $SIG{ALRM}= "Net::SSLhello::_timedOut"; 
                        alarm($Net::SSLhello::timeout);
                        unless (recv ($socket, $input, 32767, 0)) { # received NO Data or additional Data is still waiting; 'unless' is the opposite of 'if'
                            _trace4 ("_doCheckSSLciphers >>> ... Received Proxy-Connect (1): ".length($input)." Bytes\n          >".$input."<\n"); ###### temp
                            if (length ($input) >0) { # get additional data
                                _trace3 ("_doCheckSSLciphers ... Received Proxy-Connect (1): ".length($input)." Bytes\n        >".substr($input,0,64)." ...<\n");
                                _trace4 ("_doCheckSSLciphers ... Received Proxy-Connect (1): ".length($input)." Bytes\n          >".$input."<\n"); 
#                                    alarm($Net::SSLhello::timeout); # reset alarm
####                            tried while {} and do{} until here, but did not work #### 
                                unless (recv ($socket, $input2, 32767, 0)) { # received NO Data or additional Data is still waiting; unless is the opposite of 'if'
                                    if (length ($input2) >0) { # got additional data
                                        _trace3 ("_doCheckSSLciphers ... Received Proxy-Connect (2): ".length($input2)." Bytes\n        >".substr($input2,0,64)." ...<\n");
                                        _trace4 ("_doCheckSSLciphers ... Received Proxy-Connect (2): ".length($input2)." Bytes\n          >".$input2."<\n");
                                        $input .= $input2;
                                    }
                                }

                            } else { # received NO Data 
                                _trace2 ("_doCheckSSLciphers ... Received Connected-Message from Proxy: received NO Data\n");
                                # next retry
                            }
                        }
                        #clear Alarm
                        alarm (0);
                    };
                
                    if (length ($input) >0) { # got Data
                        _trace3 ("_doCheckSSLciphers ... Received Data via Proxy: ".length($input)." Bytes\n          >".substr($input,0,64)."< ...\n");
                        _trace4 ("_doCheckSSLciphers ... Received Data via Proxy: ".length($input)." Bytes\n          >".$input."<\n"); 
                        
                        if ($input =~ /(?:^|\s)200\s/) { # HTTP/1.0 200 Connection established\r\nProxy-agent: ... \r\n\r\n
                            $@ ="";     # Connection established 
                            _trace2 ("_doCheckSSLciphers: Connection established to $host:$port via Proxy ".$Net::SSLhello::proxyhost.":".$Net::SSLhello::proxyport."\n");
                        } else {
                            unless ($Net::SSLhello::trace > 0) { # no trace => shorten the output
                                $input =~ /^((?:.+?\n){1,4})/; #maximal 4 lines
                                $input = $1;
                            }

                            $@ = "Can't make a connection to $host:$port via Proxy $Net::SSLhello::proxyhost:$Net::SSLhello::proxyport; target ignored.\nProxy-Error: ".$input; #error-message received from the proxy
                            # next retry
                        }
                    }
                }
            } else { # no Proxy
                eval {
                    $SIG{ALRM}= "Net::SSLhello::_timedOut"; 
                    alarm($Net::SSLhello::timeout); # set Alarm for Connect
                    $connect2ip = inet_aton($host);
                    if (!defined ($connect2ip) ) {
                        $retryCnt = $Net::SSLhello::retry; #Fatal Error NO retry
                        die "Can't get the IP-Address of $host -> target $host:$port ignored";
                    }
                    connect( $socket, pack_sockaddr_in($port, $connect2ip) ) or  die  "Can't make a connection to $host:$port; target ignored ";
                    alarm (0);
                }; # Do NOT forget the ;
                if ($@) { # no Connect
                    close ($socket) or warn("**WARNING: _doCheckSSLciphers: $@; Can't close socket, too: $!");
                    # next retry
                }
            }
################ Begin STARTTLS Support
            if ( !($@) && ($Net::SSLhello::starttls) )  { # no Error and starttls
                eval {
                    _trace2 ("_doCheckSSLciphers ## STARTTLS: try to receive the SMTP Ready Message from the Server $host:$port, Retry = $retryCnt\n"); 
                    alarm($Net::SSLhello::timeout);
                    unless (recv ($socket, $input, 32767, 0) ) { # did not receive a Message ## unless seems to work better than if!!
                        $@ = "STARTTLS: Did *NOT* get any Message from $host:$port; target ignored.\n";
                        # next retry
                    } elsif (length ($input) >0) { # received Data => 220 smtp.server.com Simple Mail Transfer Service Ready?
                        _trace4 ("_doCheckSSLciphers ## STARTTLS:  ... Received  SMTP-Message (1): ".length($input)." Bytes\n      >".$input."<\n"); 
                        if ($input =~ /(?:^|\s)220\s/) { # 220 smtp.server.com Simple Mail Transfer Service Ready
                            $@ ="";     # Server is Ready 
                        } else {
                            unless ($Net::SSLhello::trace > 0) { # no trace => shorten the output
                                $input =~ /^((?:.+?\n))/; #maximal 1 line
                                $input = $1;
                            }
                            $@ = "STARTTLS: Did *NOT* get a Server Ready Message from $host:$port; target ignored.\nServer-Error: ".$input; #error-message received from the SMTP-Server
                            # next retry
                        }
                    } else { # did receive a Message with length = 0 ?!
                            $@ = "STARTTLS: Did receive a Server Ready Message with length 0 to SMTP Client Hello from $host:$port; target ignored.\n";
                            print "_doCheckSSLciphers: STARTTLS: received 0 Bytes as a Server Ready Message; try to retry; $@\n";
                            # next retry
                    }
                };
                eval {
                    $firstMessage = "EHLO o-saft.localhost\r\n"; #### \n ->new: \r\n
                    _trace4 ("_doCheckSSLciphers ## STARTTLS:  first Client Message: >$firstMessage<\n");
                    $SIG{ALRM}= "Net::SSLhello::_timedOut"; 
                    alarm($Net::SSLhello::timeout); # set Alarm for Connect
                    defined(send($socket, $firstMessage, 0)) || die  "Could *NOT* send an ELHO message to $host:$port; target ignored\n";
                    alarm (0);
                }; # Do NOT forget the ;
                if ($@) { # no Connect
                    warn "**WARNING: _doCheckSSLciphers ## STARTTLS: $@\n"; 
                    close ($socket) or warn("**WARNING: _doCheckSSLciphers ## STARTTLS: $@; Can't close socket, too: $!");
                    # next retry
                } else { # receive SMTP Hello Answer
                    eval {
                        _trace2 ("_doCheckSSLciphers ## STARTTLS: try to receive the SMTP Hello Answer from the Server $host:$port\n"); 
                        alarm($Net::SSLhello::timeout);
                        unless (recv ($socket, $input, 32767, 0) ) { # did not receive a Message ## unless seems to work better than if!!
                            $@ = "STARTTLS: Did *NOT* get any Answer to SMTP Client Hello from $host:$port; target ignored.\n";
                            print "_doCheckSSLciphers ($host:$port): STARTTLS: received no Answer; try to retry; $@\n";
                            # next retry
                        } elsif (length ($input) >0) { # received Data => 250-smtp.server.com Hello o-saft.localhost?
                            _trace3 ("_doCheckSSLciphers ## STARTTLS: ... Received  SMTP-Hello: ".length($input)." Bytes\n      >".substr($input,0,64)." ...<\n");
                            _trace4 ("_doCheckSSLciphers ## STARTTLS:  ... Received  SMTP-Hello: ".length($input)." Bytes\n      >".$input."<\n");                             
                            if ($input =~ /(?:^|\s)250(?:\s|-)/) { # 250-smtp.server.com Hello o-saft.localhost
                                $@ ="";     # Server is Ready 
                            } else {
                                unless ($Net::SSLhello::trace > 0) { # no trace => shorten the output
                                    $input =~ /^((?:.+?\n))/; #maximal 1 line
                                    $input = $1;
                                }
                                $@ = "STARTTLS: Did *NOT* get a Server Hello Answer from $host:$port; target ignored.\nServer-Error: ".$input; #error-message received from the SMTP-Server
                                die $@;
                            }
                        } else { # did receive a Message with length = 0 ?!
                            $@ = "STARTTLS: Did receive an Answer with length 0 to SMTP Client Hello from $host:$port; target ignored.\n";
                            print "_doCheckSSLciphers '$host:$port' STARTTLS: received 0 Bytes as Answer to SMTP Client Hello; try to retry; $@\n";
                            # next retry
                        }
                        alarm (0);
                    };
                }
                if ($@) { # no Server Hello Answer
                    warn "**WARNING: STARTTLS: $@\n"; 
                    close ($socket) or warn("**WARNING: STARTTLS: $@; Can't close socket, too: $!");
                    # next retry
                } else { # Do STARTTLS    
                    eval {
                        $secondMessage="STARTTLS\r\n";
                        _trace2 ("_doCheckSSLciphers ## STARTTLS: second Client Message: >$secondMessage<\n");
                        $SIG{ALRM}= "Net::SSLhello::_timedOut"; 
                        alarm($Net::SSLhello::timeout); # set Alarm for Connect
                        defined(send($socket, $secondMessage, 0)) || die "Could *NOT* send a STARTTLS message to $host:$port; target ignored\n";
                        alarm (0);
                    }; # Do NOT forget the ;
                }
                if ($@) { # no Connect
                    warn "**WARNING: _doCheckSSLciphers ## $@\n"; 
                    close ($socket) or warn("**WARNING: _doCheckSSLciphers ## $@; Can't close socket, too: $!");
                    # next return
                } else { # receive STARTTLS Answer
                    eval {
                        _trace2 ("_doCheckSSLciphers ## STARTTLS: try to receive the SMTP STARTTLS Answer from the Server $host:$port\n"); 
                        alarm($Net::SSLhello::timeout);
                        unless (recv ($socket, $input, 32767, 0) ) { # did not receive a Message ## unless seems to work better than if!!
                            $@ = "STARTTLS: Did *NOT* get any Answer to STARTTLS Request from $host:$port; target ignored.\n";
                            _trace2 ("_doCheckSSLciphers ## STARTTLS: received no Answer to STARTTLS-Request; try to retry; $@\n");
                            # next retry
                        } elsif    (length ($input) >0)  { # received Data => 220 
                            _trace3 ("_doCheckSSLciphers ## STARTTLS: ... Received STARTTLS-Answer: ".length($input)." Bytes\n      >".substr($input,0,64)." ...<\n");
                            _trace4 ("_doCheckSSLciphers ## STARTTLS:  ... Received STARTTLS-Answer: ".length($input)." Bytes\n      >".$input."<\n"); 
                            if ($input =~ /(?:^|\s)220(?:\s|-)/) { # 220
                                $@ ="";     # Server is Ready to do SSL/TLS
                                _trace2 ("_doCheckSSLciphers ## STARTTLS: Server is ready to do SSL/TLS\n");
                            } else {
                                unless ($Net::SSLhello::trace > 0) { # no trace => shorten the output
                                    $input =~ /^((?:.+?\n))/; #maximal 1 line
                                    $input = $1;
                                }
                                $@ = "STARTTLS: Did *NOT* get a Server SSL/TLS confirmation from $host:$port (retry: $retryCnt); target ignored.\nServer-Error: ".$input; #error-message received from the SMTP-Server
                                _trace2 ("Exit _doCheckSSLciphers }\n");
                                warn ($@);
                                die $@;
#                                return (""); # fatal Error => Exit
                            }
                        } else { # did not receive a Message
                            $@ = "STARTTLS: Did *NOT* get an Answer with length 0 to STARTTLS Request from $host:$port; target ignored.\n";
                            _trace2 ("_doCheckSSLciphers ## STARTTLS: received 0 Bytes as Answer to STARTTLS-Request; try to retry; $@\n");
                            # next retry
                        }
                        alarm (0);
                    };
                }
            } 
###############    End STARTTLS Support        
        }
###        alarm (0);   # race condition protection
    }} while ( ($@) && ($retryCnt++ < $Net::SSLhello::retry) );
    
    if ($@) { #Error
        warn ("**WARNING: _doCheckSSLciphers: $@\n"); 
        _trace2 ("_doCheckSSLciphers: Exit _doCheckSSLciphers }\n");
        return ("");
    }
    
    _trace2 ("_doCheckSSLciphers: Connected to '$host:$port'\n");
    _trace3 ("_doCheckSSLciphers: sending Client_Hello\n      >".hexCodedString(substr($clientHello,0,64),"        ")." ...< (".length($clientHello)." Bytes)\n\n");
    _trace4 ("_doCheckSSLciphers: sending Client_Hello\n          >".hexCodedString ($clientHello,"           ")."< (".length($clientHello)." Bytes)\n\n");

    eval {
        $SIG{ALRM}= "Net::SSLhello::_timedOut"; 
        alarm($Net::SSLhello::timeout); # set Alarm for Connect
        defined(send($socket, $clientHello, 0)) || die "Could *NOT* send ClientHello to $host:$port; $! -> target ignored\n";
        alarm (0);
    }; # Do NOT forget the ;

    ###### receive the answer (=ServerHello) 
    $retryCnt = 0;
    $segmentCnt = 1;
    $input="";
    $input2="";
    do {{
        $@ ="";
        $input2="";
        if ($retryCnt >0) {
             _trace1 ("_doCheckSSLciphers: $retryCnt. Retry to receive $segmentCnt. TCP-segment-Data from '$host:$port' ");
            if ($pduLen >0) {
                _trace1_ ("(expecting $pduLen Bytes)\n");
            } else {
                _trace1_ ("\n");
            }
        }
        eval { # check this for timeout, protect it against an unexpected Exit of the Program
            #Set alarm and timeout 
            $SIG{ALRM}= "Net::SSLhello::_timedOut"; 
            alarm($Net::SSLhello::timeout);
            recv ($socket, $input2, 32767, 0); 
            alarm (0); #clear alarm 
        }; # end of eval recv
        unless ($@) { # no timeout received
           if (length ($input2) >0) { # got (additional) data 
                _trace3 ("_doCheckSSLciphers: ... Received Data (1): ".length($input2)." Bytes ($segmentCnt. TCP-segment)\n      >".hexCodedString(substr($input2,0,64),"        ")." ...<\n");
                _trace4 ("_doCheckSSLciphers: ... Received Data (1): ".length($input2)." Bytes ($segmentCnt. TCP-segment)\n        >".hexCodedString($input2,"        ")."<\n");
                $input .= $input2;
                $segmentCnt++;
                if ($segmentCnt <= _MAX_SEGMENT_COUNT_TO_RESET_RETRY_COUNT) { # reset Retry-Count to 0 (in next loop)
                    $retryCnt = -1;
                }
            } else {
                _trace2 ("_doCheckSSLciphers: ... Received Data (2): received NO (new) Data ($segmentCnt. TCP-segment, $retryCnt. Retry)\n");
                next;
            }
            
            #### check for other protocols than ssl (when starttls is used) ####
            if ($Net::SSLhello::starttls)  { 
                if ($input =~ /(?:^|\s)554(?:\s|-)security.*?$/i)  { # 554 Security failure
                    _trace2  ("_doCheckSSLciphers ## STARTTLS: received SMTP Reply Code '554 Security failure': (Is the STARTTLS command issued within an existing TLS session?) -> input ignoredi and try to Retry\n");
                    #retry to send clientHello
                    $@="";
                    $input=""; #reset input data
                    $pduLen=0;
                    eval { # check this for timeout, protect it against an unexpected Exit of the Program
                        #Set alarm and timeout 
                        $SIG{ALRM}= "Net::SSLhello::_timedOut"; 
                        alarm($Net::SSLhello::timeout);
                        defined(send($socket, $clientHello, 0)) || die "**WARNING: _doCheckSSLciphers: Could *NOT* send ClientHello to $host:$port (2 =retry); $! -> target ignored\n";
                        alarm (0);   # race condition protection 
                    }; # end of eval recv
                    if ($@) {
		                 warn ($@);
		                 return ("");
                    }
                    alarm (0);   # race condition protection
                    next;
                }
            } elsif ($input =~ /(?:^|\s)220(?:\s|-).*?$/)  { # service might need STARTTLS
                 $@= "**WARNING: _doCheckSSLciphers: $host:$port looks like an SMTP-Service, probably the option '--starttls' is needed -> target ignored\n";
                 warn ($@);
                 return ("");
            } 
            if ( ($pduLen == 0) && (length ($input) >4) ){ #try to get the pdulen of the ssl pdu (=protocol aware length detection)
                # Check PDUlen; Parse the first 5 Bytes to check the Len of the PDU (SSL3/TLS)
                ($v3type,       #C (record_type)    
                 $v3version,    #n (record_version)
                 $v3len)        #n (record_len)
                    = unpack("C n n", $input);

                if ( ($v3type < 0x80) && (($v3version & 0xFF00) == $PROTOCOL_VERSION{'SSLv3'}) ) { #SSLv3/TLS (no SSLv2)
                    $pduLen = $v3len + 5; # Check PDUlen = v3len + size of record-header; 
                    _trace2 ("_doCheckSSLciphers: ... Received Data: Expected SSLv3-PDU-Len of Server-Hello: $pduLen\n");
                } else { # Check for SSLv2
                    ($v2len,    # n (V2Len > 0x8000)
                     $v2type)    # C = 0
                        = unpack("n C", $input);
                     if ($v2type == $SSL_MT_SERVER_HELLO) { # SSLv2 check
                        $pduLen = $v2len - 0x8000 + 2;
                        _trace2 ("_doCheckSSLciphers: ... Received Data: Expected SSLv2-PDU-Len of Server-Hello: $pduLen\n");
                     } else { 
                         $@ = "**WARNING: _doCheckSSLciphers: $host:$port dosen't look like a SSL or a SMTP-Service -> Received Data ignored -> target ignored\n";
                         warn ($@);
                         _trace ("_doCheckSSLciphers: Ignored Data: ".length($input)." Bytes\n        >".hexCodedString($input,"        ")."<\n");
                         $input="";
                         $pduLen=0;
                         return ("");
                     }
                }
            }
        } else { # timeout received -> Retry
             _trace2 ("_doCheckSSLciphers: Timeoout received '$@'-> Retry\n");
        }
        alarm (0);   # race condition protection
    }} while ( ( (length($input) < $pduLen) || (length($input)==0) ) && ($retryCnt++ < $Net::SSLhello::retry) );
    alarm (0);   # race condition protection
    if ( ($@) && ( (length($input)==0) || ($Net::SSLhello::trace > 2) )) {    
        warn ("**WARNING: _doCheckSSLciphers: ... Received Data: Got a timeout receiving Data from $host:$port (".length($input)." Bytes): Eval-Message: >$@<\n"); 
    }
    if (length($input) >0) {
		_trace2 ("_doCheckSSLciphers: Total Data Received:". length($input). " Bytes in $segmentCnt. TCP-segments\n"); 
        $acceptedCipher = parseServerHello ($input, $protocol);
    }
    unless ( close ($socket)  ) {
        warn("**WARNING: _doCheckSSLciphers: Can't close socket: $!");
    }
    _trace2 ("_doCheckSSLciphers: }\n");
    return ($acceptedCipher);
}

############################################################

sub compileClientHello  {
    #? compile a Client Hello Packet
    #
    my $record_version    = shift;
    my $version    = shift;
    my $ciphers    = shift;
    my $host = shift;
    my $clientHello=""; #return value
    my $clientHello_tmp="";
    my $clientHello_extensions="";
    my $challenge = $CHALLENGE; #16-32 Bytes,
    my $i; #counter
    
    _trace4 (sprintf("compileClientHello (%04X, %04X,\n          >%s<, %s) {\n", $record_version, $version, hexCodedString ($ciphers,"           "), $host) );
    
    $challenge= pack("Na[28]", time(), $challenge); #4 Bytes: uint32 gmt_unix_time;, 28 Byte random
    _trace4_("#   --->   challenge >".hexCodedString ($challenge)."<\n");

    my %clientHello =  ( #V2ClientHello
        'record_type'            => $RECORD_TYPE {'handshake'},#ab SSL3: Handshake (22=0x16) #uint8
        'record_version'         => $record_version,           #ab SSL3    #uint16
        'record_len'             => 0x0000,                    #ab SSL3,    #uint16
        'msg_len'                => 0x000000,                  #SSL2: uint16 | 0x8000, ab SSL3: uint24 (!)
        'msg_type'               => $SSL_MT_CLIENT_HELLO,      # 0x01     #uint8  
        'version'                => $version,                  #SSL2:0x0002,SSL3:0x3000,TLS1:0x0301    #uint16
        'cipher_spec_len'        => length($ciphers),          #uint16
        'session_id_len'         => 0x0000,                    #uint16
        'challenge_len'          => length($challenge),        #uint16
        'cipher_spec'            => $ciphers,                  #sslv2: 3 Bytes, SSL3/TLS: 2Bytes
        'session_id'             => "",                        #client_helo => len=0,
        'challenge'              => $challenge,                #16-32 Bytes | SSL3/TLS: 32 Bytes
        'compression_method_len' => 0x01,                      # len = 1
        'compression_method'     => 0x00,                      #SSL3/TLS1.x 00 
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
              "# --> version:         >%04X<\n".
              "# --> cipher_spec_len: >%04X<\n".
              "# --> session_id_len:  >%04X<\n".
              "# --> challenge_len:   >%04X<\n".
              "# --> cipher_spec:     >%s<\n".
              "# --> session_id:      >%s<\n".
              "# --> challenge:       >%s<\n",
              $clientHello{'msg_len'},
              $clientHello{'msg_type'},
              $clientHello{'version'},
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
                
            
# ggf auch prüfen, ob Host ein DNS-Name ist
        if ( ($Net::SSLhello::usesni) && ($record_version >= $PROTOCOL_VERSION{'TLSv1'}) ) { # allow to test SNI with version TLSv1 and above
        ######## TBD: prüfen, ab welchem Protokoll SNI eingeführt wurde (z.B. TLS1.0)!!! #####
        ######## SSL3 erhält bei SSLLABS folgende Fußnote: This site requires support for virtual SSL hosting, 
        ########                                           but SSL 2.0 and SSL 3.0 do not support this feature.
        
            ### Data for Extension 'Server Name Indication' in reverse order 
            $clientHello{'extension_sni_name'}         = $host;                                      # Server Name, should be a Nmae no IP
            $clientHello{'extension_sni_len'}          = length($clientHello{'extension_sni_name'}); # len of Server Name        
            $clientHello{'extension_sni_type'}         = 0x00;                                       # 0x00= host_name
            $clientHello{'extension_sni_list_len'}     = $clientHello{'extension_sni_len'} + 3;      # len of Server Name + 3 Bytes (sni_len, sni_type)
            $clientHello{'extension_len'}              = $clientHello{'extension_sni_list_len'} + 2; # len of this extension = sni_list_len + 2 Bytes (sni_list_len)
            $clientHello{'extension_type_server_name'} = 0x0000;                                     # 0x0000
#            $clientHello{'extensions_total_len'}       = $clientHello{'extension_len'} + 4;          # war +2 len Server Name-Extension + 2 Bytes (extension_type) #??? +4?!!##

            $clientHello_extensions = pack ("n n n C n a[$clientHello{'extension_sni_len'}]",
#                $clientHello{'extensions_total_len'},        #n    
                $clientHello{'extension_type_server_name'}, #n
                $clientHello{'extension_len'},              #n    
                $clientHello{'extension_sni_list_len'},     #n    
                $clientHello{'extension_sni_type'},         #C
                $clientHello{'extension_sni_len'},          #n        
                $clientHello{'extension_sni_name'},         #a[$clientHello{'extension_sni_len'}]
            );
            _trace2 ("compileClientHello: extension_sni_name Extension added\n");
        } elsif ($Net::SSLhello::usesni) { # && ($record_version <= $PROTOCOL_VERSION{'TLSv1'})  
            $@ = sprintf ("Net::SSLhello: compileClientHello: Extended Client Hellos with Server Name Indication (SNI) are not enabled for SSL3 (a futue option could override this) -> check of virtual Server aborted!\n");
            print $@;
        }
        
        if ($Net::SSLhello::usereneg) { # use secure Renegotiation
            my $anzahl = int length ($clientHello{'cipher_spec'}) / 2;
            my @cipherTable = unpack("a2" x $anzahl, $clientHello{'cipher_spec'}); 
            unless ( ($Net::SSLhello::double_reneg == 0) && (grep(/\x00\xff/, @cipherTable)) ) { # Protection against double renegotiation info is active
                # do *NOT* send a reneg_info Extension if the cipher_spec includes already signalling Cipher Suite Value (SCSV) 
                # "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" {0x00, 0xFF}

                ### Data for Extension 'renegotiation_info' 
                $clientHello{'extension_type_renegotiation_info'} = 0xff01; # Tbd: hier, oder zentrale Definition?!
                $clientHello{'extension_reneg_len'}               = 0x0001; # Tbd: hier, oder zentrale Definition?!
                $clientHello{'extension_reneg_info_ext_len'}      = 0x00;   # Tbd: hier, oder zentrale Definition?!

                $clientHello_extensions .= pack ("n n a[1]",
                    $clientHello{'extension_type_renegotiation_info'},      #n    = 0xff01
                    $clientHello{'extension_reneg_len'},                    #n    = 0x0001
                    $clientHello{'extension_reneg_info_ext_len'},           #a[1] = 0x00
                );
                _trace2 ("compileClientHello: reneg_info Extension added\n");
            } else {
                _trace2 ("compileClientHello: *NOT* sent a reneg_info Extension as the cipher_spec includes already the Signalling Cipher Suite Value (TLS_EMPTY_RENEGOTIATION_INFO_SCSV {0x00, 0xFF})\n");
            }
        }

        $clientHello{'extensions_total_len'} = length($clientHello_extensions);
        
        if ($clientHello_extensions) { # not empty
            $clientHello_extensions = pack ("n a*",
                length($clientHello_extensions),            #n    
                $clientHello_extensions                     #a[length($clientHello_extensions)]
            );
        }

        my $extensions_size = length($clientHello_extensions);

         _trace4_ ( 
            sprintf (
              "#        ---> SSL3/TLS-clientHello-Handshake:\n".
              "#        --->   Handshake Protocol: \n".        
              "#        --->       version:               >%04X<\n".
              "#        --->       challenge/random:      >%s<\n".
              "#        --->       session_id_len:          >%02X<\n".
              "#        --->       cipher_spec_len:       >%04X<\n".
              "#        --->       cipher_spec:           >%s<\n".
              "#        --->       compression_method_len:  >%02X<\n".
              "#        --->       compression_method:      >%02X<\n".# 0x
              "#        --->       extensions:  (size=%02d) >%s<\n",
              $clientHello{'version'},
              hexCodedString ($clientHello{'challenge'}),
              $clientHello{'session_id_len'},
              $clientHello{'cipher_spec_len'},
              hexCodedString ($clientHello{'cipher_spec'}),
              $clientHello{'compression_method_len'}, # C (0x01)
              $clientHello{'compression_method'},     # C[len] (0x00)
              $clientHello{'extensions_total_len'},
              hexCodedString ($clientHello_extensions),
            )
        );
        
        $clientHello_tmp = pack ("n a[32] C n a[$clientHello{'cipher_spec_len'}] C C[$clientHello{'compression_method_len'}] a[$extensions_size]",
            $clientHello{'version'},                # n
            $clientHello{'challenge'},              # A[32] = gmt + random [4] + [28] Bytes
            $clientHello{'session_id_len'},         # C
            $clientHello{'cipher_spec_len'},        # n
            $clientHello{'cipher_spec'},            # A[$clientHello{'cipher_spec_len'}]
            $clientHello{'compression_method_len'}, # C (0x01)
            $clientHello{'compression_method'},     # C[len] (0x00)
            $clientHello_extensions                 # optional
        );

        _trace4    ("compileClientHello (SSL3/TLS) (1):\n          >".hexCodedString ($clientHello_tmp,"           ")."<\n"); 
        
        $clientHello{'msg_len'} = length ($clientHello_tmp);
        $clientHello{'record_len'} = $clientHello{'msg_len'} + 4;

        _trace4_    ( 
            sprintf (
              "#        ---> SSL3_TLS-clientHello (Record):\n".
              "#        --->   record_type:       >%02X<\n".     
              "#        --->   record_version:  >%04X<\n".    
              "#        --->   record_len:      >%04X<\n".        
              "#        --->   Handshake Protocol: \n".        
              "#        --->       msg_type:                >%02X<\n".
              "#        --->       msg_len:             >00%04X<\n",    
              $clientHello{'record_type'},     
              $clientHello{'record_version'},    
              $clientHello{'record_len'},        
              $clientHello{'msg_type'},
              $clientHello{'msg_len'}
            )
        );

        $clientHello = pack ("C n n C C n a*",
            $clientHello{'record_type'},     # C
            $clientHello{'record_version'},    # n
            $clientHello{'record_len'},        # n
            $clientHello{'msg_type'},         # C
            0x00,                            # C (0x00)
            $clientHello{'msg_len'},          # n
               $clientHello_tmp                  # a
        );

        _trace2 ( "compileClientHello (SSL3/TLS) (2):\n       >".hexCodedString ($clientHello,"        ")."<\n");
        _trace2_ ( sprintf (
                "# -->SSL3/TLS-clientHello:\n".
                "# -->   record_type:       >%02X<\n".     
                "# -->   record_version:  >%04X<\n".    
                "# -->   record_len:      >%04X<\n".        
                "# -->   Handshake Protocol: \n".        
                "# -->       msg_type:                >%02X<\n".
                "# -->       msg_len:             >00%04X<\n".
                "# -->       version:               >%04X<\n".
                "# -->       challenge/random:      >%s<\n".
                "# -->       session_id_len:          >%02X<\n".
                "# -->       cipher_spec_len:       >%04X<\n".
                "# -->       cipher_spec:           >%s<\n".
                "# -->       compression_method_len:  >%02X<\n".
                "# -->       compression_method:      >%02X<\n", #Comma!
#                "# -->       extensions_len:       >%04X<\n",
                $clientHello{'record_type'},     
                $clientHello{'record_version'},    
                $clientHello{'record_len'},        
                $clientHello{'msg_type'},
                $clientHello{'msg_len'},
                $clientHello{'version'},
                hexCodedString ($clientHello{'challenge'}),
                $clientHello{'session_id_len'},
                $clientHello{'cipher_spec_len'},
                hexCodedString ($clientHello{'cipher_spec'}),
                $clientHello{'compression_method_len'}, # C (0x01)
                $clientHello{'compression_method'},     # C[1] (0x00)
#                $clientHello{'extensions_len'}
        ));
    
        if  ($Net::SSLhello::trace > 3) { 
            printTLSCipherList ($clientHello{'cipher_spec'});
        }

        _trace4 (sprintf ("compileClientHello (%04X)\n          >",$record_version).hexCodedString ($clientHello,"           ")."<\n");
    } else {
        my %rhash = reverse %PROTOCOL_VERSION;
        my $ssl = $rhash{$record_version};
        if (! defined $ssl) {
            $ssl ="--unknown Protocol--";
        }
#        my ($ssl) = grep {$record_version ~~ ${$cfg{'openssl_version_map'}}{$_}} keys %{$cfg{'openssl_version_map'}};
        $@ = "**WARNING: compileClientHello: Protocol version $ssl (0x". sprintf("%04X", $record_version) .") not (yet) defined in Net::SSLhello.pm -> protocol ignored";
        warn($@);
    }
    return ($clientHello);
}

sub parseServerHello ($;$) { # Variable: String/Octet, dass das Server-Hello-Paket enthält  ; second (opional) variable: protocol-version, that the client uses
    my $buffer = shift; 
    my $client_protocol = shift;  # optional
    my $rest ="";
    my $tmp_len = 0;
    my $message = "";
    my $nextMessages = "";
    my %serverHello;
    my $description = "";

    if (length ($buffer) >0) { # Received Data in the buffer    
        my $firstByte = unpack ("C", $buffer);

        if (defined $client_protocol) {
            _trace2("parseServerHello (expected Protocol= >".sprintf ("%04X", $client_protocol)."<,\n      >".hexCodedString (substr($buffer,0,48),"       ")."< ...)\n");
        } else {
            _trace2("parseServerHello (any Protocol,\n Data=".hexCodedString (substr($buffer,0,48),"       ").")... \n");
        }
        _trace4 (sprintf ("parseServerHello: 1. Byte:  %02X\n\n", $firstByte) );
        if ($firstByte >= 0x80) { #SSL2 with 2Byte Length
            _trace2_ ("# -->SSL: Message-Type SSL2-Msg"); 
            _trace4_ ("#        --->    Record len 2 Byte Header:\n"); 
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
            _trace4 ("parseServerHello: Rest: >".hexCodedString ($rest)."<\n"); 

            if ($serverHello{'msg_type'} == $SSL_MT_SERVER_HELLO) { 
                _trace4 ("    Handshake Protocol: SSL2 Server Hello\n"); 
                _trace4 ("        Message Type: (Server Hello (2)\n"); 
                return (parseSSL2_ServerHello ($rest,$client_protocol)); # cipher_spec-Liste
            } else { # if ($serverHello{'msg_type'} == 0 => NOT supported Protocol (?!)
                print "    Unknown SSLv2-Message Type (Dez): ".$serverHello{'msg_type'}.", Msg: >".hexCodedString ($buffer)."<\n"; }
                return ("");
        } else { #TLS-Record
            _trace2_("# -->TLS Record Layer:\n"); 
            ($serverHello{'record_type'},       # C
             $serverHello{'record_version'},    # n
             $serverHello{'record_len'},        # n
### perhaps this could be a good point to start a new function to parse a Message => to check certificates etc later###
             $serverHello{'msg_type'},          # C
             $serverHello{'msg_len_null_byte'}, # C
             $serverHello{'msg_len'},           #n 
             $rest) = unpack("C n n C C n a*", $buffer);

            if ($serverHello{'record_type'} == $RECORD_TYPE {'handshake'}) { 
                _trace2_ (sprintf (
                     "# -->    => SSL3/TLS-Record Type: Handshake  (%02X):\n".
                     "# -->    record_version:  >%04X<\n".
                     "# -->    record_len:      >%04X<\n".
                     "# -->       msg_type:         >%02X<\n".
                     "# -->       msg_len_null_byte:    >%02X<\n".
                     "# -->       msg_len:           >%04X<\n",
                       $serverHello{'record_type'}, 
                       $serverHello{'record_version'},
                       $serverHello{'record_len'},
                       $serverHello{'msg_type'},
                       $serverHello{'msg_len_null_byte'}, # prefetched for record_type Handshake 
                       $serverHello{'msg_len'}              # prefetched for record_type Handshake 
                ));
            
                ($message,                        #a[$serverHello{'msg_len'}] 
                $nextMessages) = unpack("a[$serverHello{'msg_len'}] a*", $rest);
              
                _trace4_ ( sprintf (
                    "# --->      message:       >%s<\n",
                    hexCodedString ($message)
                ));

                if ($serverHello{'msg_type'} == $HANDSHAKE_TYPE {'server_hello'}) { 
                    _trace3_ ("# -->     Handshake Type:    Server Hello (22)\n"); 
                    _trace4_ ("# --->    Handshake Type:    Server Hello (22)\n"); 

                    if ($serverHello{'msg_len_null_byte'} != 0x00)  { 
                            _error (">>> WARNING (parseServerHello): 1st Msg-Len-Byte is *NOT* 0x00/n"); 
                    }
                    return (parseTLS_ServerHello ($message, $serverHello{'msg_len'},$client_protocol));    
                }
            } elsif    ($serverHello{'record_type'} == $RECORD_TYPE {'alert'}) { 
                _trace2_ ("# -->  Record Type:    Alert (21)\n"); 
                _trace2_ (sprintf("# -->  Record Version:  $serverHello{'record_version'} (0x%04X)\n",$serverHello{'record_version'}));
                _trace2_ (sprintf("# -->  Record Len:      $serverHello{'record_len'}   (0x%04X)\n",$serverHello{'record_len'})); 
                $serverHello{'msg_type'} = 0;          # KEIN Handshake = löschen
                $serverHello{'msg_len_null_byte'} = 0; # KEIN Handshake = löschen
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

#                Error-Handling according to # http://www.iana.org/assignments/tls-parameters/tls-parameters-6.csv                
                unless ( ($serverHello{'level'} == 2) &&
                        (  ($serverHello{'description'} == 40) # handshake_failure(40): usually cipher not found is suppressed
                           || ($serverHello{'description'} == 71) # insufficient_security(71): no (secure) cipher found, is suppressed
                        ) ) {
                    if ($serverHello{'level'} == 1) { # warning
                        if ($serverHello{'description'} == 112) { #SNI-Warning: unrecognized_name
                            $@ = sprintf ("parseServerHello: received SSL/TLS-Warning: Description: $description ($serverHello{'description'}) -> check of virtual Server aborted!\n");
                            print $@;
                            return (""); 
                        } else {
                            warn ("**WARNING: parseServerHello: received SSL/TLS-Warning (1): Description: $description ($serverHello{'description'})\n");
                        }
                    } elsif ($serverHello{'level'} == 2) { # fatal
                        if ($serverHello{'description'} == 70) { # protocol_version(70): (old) protocol recognized but not supported, is suppressed
                            $@ = sprintf ("parseServerHello: received SSL/TLS-Warning: Description: $description ($serverHello{'description'}) -> protocol_version recognized but not supported!\n");
                        } else {
                            warn ("**WARNING: parseServerHello: received fatal SSL/TLS-Error (2): Description: $description ($serverHello{'description'})\n");
                        }
                    } else { # unknown
                        warn ("**WARNING: parseServerHello: received unknown SSL/TLS-Error-Level ($serverHello{'level'}): Description: $description ($serverHello{'description'})\n");
                    }
                }
            } else { ################################ to get information about Record Types that are not parsed, yet #############################
                _trace_ ("\n");
                warn ("**WARNING: parseServerHello: Unknown SSL/TLS Record-Type received that is not (yet) defined in Net::SSLhello.pm:\n");
                warn ("#        Record Type:     Unknown Value (".$serverHello{'record_type'}."), not (yet) defined in Net::SSLhello.pm\n"); 
                warn ("#        Record Version:  $serverHello{'record_version'} (0x".hexCodedString ($serverHello{'record_version'}).")\n");
                warn ("#        Record Len:      $serverHello{'record_len'} (0x".hexCodedString ($serverHello{'record_len'}).")\n\n"); 
            }
            return ("");
        } #End SSL3/TLS
    } else {
        _trace2("parseServerHello (no Data)\n");
    }    
}


sub parseSSL2_ServerHello ($;$) { # Variable: String/Octet, das den Rest des Server-Hello-Pakets enthält  
    my $buffer = shift; 
    my $client_protocol = shift;  # optional
    my $rest;
    my %serverHello;

    $serverHello{'cipher_spec'} = "";

    if (defined $client_protocol) {
        _trace3("parseSSL2_ServerHello:  (expected Protocol=".sprintf ("%04X", $client_protocol).", Data=".hexCodedString (substr($buffer,0,48),"       ")."...)\n");
    } else {
        _trace4("parseSSL2_ServerHello:  (any Protocol, Data=".hexCodedString (substr($buffer,0,48),"         ")."...)\n");
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
    
    _trace4  ("Rest: >".hexCodedString ($rest)."<\n");

    ( $serverHello{'certificate'},    # n
      $serverHello{'cipher_spec'},    # n
      $serverHello{'connection_id'}    # n
    ) = unpack("a[$serverHello{'certificate_len'}] a[$serverHello{'cipher_spec_len'}] a[$serverHello{'connection_id_len'}]", $rest);

    _trace4 ("parseServerHello(2):\n"); 
    
    _trace2_ ( sprintf ( 
            "# -->       certificate:          >%s<\n".    # n
            "# -->       cipher_spec:          >%s<\n".    # n
            "# -->       connection_id:        >%s<\n".    # n
            "# -->       parseServerHello-Cipher:\n",        # Headline for next actions
             hexCodedString ($serverHello{'certificate'}),
             hexCodedString ($serverHello{'cipher_spec'},"     "),
             hexCodedString ($serverHello{'connection_id'})
    ));

    if ($Net::SSLhello::trace >= 3) { #trace3+4: added to check the supported Version
        printf "## Server accepts the following Ciphers with SSL-Version: >%04X<\n", 
               $serverHello{'version'};
        printSSL2CipherList($serverHello{'cipher_spec'});
        print "\n";
    }
    ### Added to check if there is a Bug in getting the cipher_spec 
    if (length ($serverHello{'cipher_spec'}) != int ($serverHello{'cipher_spec_len'}) ) { # did not get all ciphers?
            warn("**WARNING: parseSSL2_ServerHello: Can't get all Ciphers from Server-Hello (String-Len: ".length ($serverHello{'cipher_spec'})." != cipher_spec_len: ".$serverHello{'cipher_spec_len'}."): >". hexCodedSSL2Cipher ($serverHello{'cipher_spec'})."<");
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
}


sub parseTLS_ServerHello {
    # Variable: String/Octet, dass den Rest des Server-Hello-Pakets enthält, Länge, optional: Client-Protokoll  
    my $buffer = shift; 
    my $len = shift; 
    my $client_protocol = shift;  # optional
    my $rest ="";
    my $rest2 ="";
    my %serverHello;

    
    $serverHello{'cipher_spec'} = "";
    $serverHello{'extensions_len'} = 0;
    
    if (defined $client_protocol) {
        _trace3("parseTLS_ServerHello:  (expected Protocol=".sprintf ("%04X", $client_protocol).",\n     ".hexCodedString (substr($buffer,0,48),"       ")."...)\n");
    } else {
        _trace4("parseTLS_ServerHello:  (any Protocol, Data=".hexCodedString (substr($buffer,0,48),"         ")."...)\n");
    }
        
    if (length($buffer) || $len >= 35) { 
        ($serverHello{'version'},                # n
        $serverHello{'random_gmt_time'},        # N    # A4
        $serverHello{'random'},                # A28
        $serverHello{'session_id_len'},        # C
        $rest) = unpack("n N a[28] C a*", $buffer);

        _trace2_ ( sprintf ( #added to check the supported Version
                "# -->       => SSL/TLS-Version: (%04X):\n",
                $serverHello{'version'}
        ));

        if (defined ($client_protocol)) {
            if ($client_protocol != $serverHello{'version'}) {
                my %rhash = reverse %PROTOCOL_VERSION;
                my $ssl_client = $rhash{$client_protocol};
                my $ssl_server = $rhash{$serverHello{'version'}};
                if (! defined $ssl_client) {
                    $ssl_client ="--unknown Protocol--";
                } 
                if (! defined $ssl_server) {
                    $ssl_server ="--unknown Protocol--";
                } 
                $@ = sprintf ("parseTLS_ServerHello: Server Protocol $ssl_server (0x%04X) is NOT the same as the client reqested $ssl_client (0x%04X) -> answer ignored!\n", $serverHello{'version'}, $client_protocol);
                _trace2($@); 
                return ("");
            }    
        } else {
            warn ("**WARNING: parseTLS_ServerHello: internal error: All Server Versions are accepted, because there is no information provided which version the client has requested.\n");
        }
        
        _trace2_ ( sprintf (  
                "# -->       version:              >%04X<\n".
        #        "# -->       random_gmt_time:  >%08X< (%s)\n".
                "# -->       random_gmt_time:  >%08X<\n".
                "# -->       random:               >%s<\n".
                "# -->       session_id_len:         >%02X<\n",
                $serverHello{'version'},
                $serverHello{'random_gmt_time'},
        #        localtime($serverHello{'random_gmt_time'}),
                hexCodedString ($serverHello{'random'}),
                $serverHello{'session_id_len'}
        ));
        _trace4_ ( sprintf (  
                "# -->       Rest: (len=%04X)        >%s<\n",
                length ($rest),
                hexCodedString ($rest)
        ));
        
        ($serverHello{'session_id'},            # A[]
        $serverHello{'cipher_spec'},            # A2: cipher_spec_len = 2
        $serverHello{'compression_method'},        # C
        $serverHello{'extensions_len'},            # n
        $rest2) = unpack("a[$serverHello{'session_id_len'}] a2 C n a*", $rest);

        _trace2_ ( sprintf (
                "# -->       session_id:           >%s<\n".
                "# -->       cipher_spec: (len=%2s) >%s<\n",
                hexCodedString ($serverHello{'session_id'}),
                length ($serverHello{'cipher_spec'}),
                hexCodedCipher ($serverHello{'cipher_spec'})
        ));
        
        ### Added to check if there is a Bug in getting the cipher_spec: cipher_spec_len = 2 ###
        if (length ($serverHello{'cipher_spec'}) !=  2 ) { # did not get the 2-Octet-Cipher?
            warn("**WARNING: parseTLS_ServerHello: Can't get the Cipher from Server-Hello (String-Len: ".length ($serverHello{'cipher_spec'})." != cipher_spec_len: 2): >". hexCodedString ($serverHello{'cipher_spec'})."<");
        }
        _trace2_ ( sprintf ( 
            #added to check the supported Version
            "# -->       The Server accepts the following Cipher(s) with SSL3/TLS-Version: >%04X<: ", 
            $serverHello{'version'}
        ));

        if ($Net::SSLhello::trace > 2) {
            printTLSCipherList ($serverHello{'cipher_spec'});
        }

        _trace2_ ( sprintf ( 
            "# -->       compression_method:     >%02X<\n",
            $serverHello{'compression_method'}
        ));
        if ( $serverHello{'extensions_len'} !~ /(?:^$|[\x00]+)/) { # extensions_len > 0
            ($serverHello{'extensions'},            # A[]
            $rest) = unpack("a[$serverHello{'extensions_len'}] a*", $rest2);

            _trace2_ ( sprintf ( 
                "# -->       extensions_len:       >%04X<\n",
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
                _trace2 ( sprintf ("\n\n## parseTLSServerHello did not parse the whole message (rest): >".hexCodedString ($rest)."< To Be Done\n")); 
            }
        }
        return ($serverHello{'cipher_spec'});
    } else {
        return ("");
    }
}

sub parseTLS_Extension { # Variable: String/Octet, das die Extension-Bytes enthÃ¤lt
    my $buffer = shift; 
    my $len = shift; 

    my $rest ="";
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
}


sub _timedOut {
    die "NET::SSLhello: Received Data Timed out\n";
}

sub hexCodedString { # Variable: String/Octet, der in HEX-Werten dargestellt werden soll, gibt Ausgabestring zurück 
    my $codedString= shift; 
    my $prefix= shift; # set an optional prefix after '\n' 
    if (!defined($prefix)) { # undefined -> ""
            $prefix="";
    }
    $codedString =~ s/([\x00-\xFF])/sprintf("%02X ", ord($1))/eig; #Code all Octets as HEX values and seperate then with a 'space'
    $codedString =~ s/((?:[0-9A-Fa-f]{2}\s){48})/"$1\n$prefix"/eig; # Add a new line each 48 HEX-Octetts (=144 Symbols incl. Spaces)
    chomp ($codedString); #delete CR at the end
    chop ($codedString); #delete 'space' at the end
    return ($codedString);
}

sub hexCodedCipher { # Variable: String/Octet, der in HEX-Werten dargestellt werden soll, gibt Ausgabestring zurück 
    my $codedString= shift; 
    my $prefix= shift; # set an optional prefix after '\n' 
    if (!defined($prefix)) { # undefined -> ""
            $prefix="";
    }
    $codedString =~ s/([\x00-\xFF])/sprintf("%02X", ord($1))/eig; #Code all Octets as HEX values and seperate then with a 'space'
    $codedString =~ s/((?:[0-9A-Fa-f]{2}){64})/"$1\n$prefix"/eig; #  Add a new line each 64 HEX-Octetts (=128 Symbols incl. Spaces) 
    chomp ($codedString); #delete CR at the end
    return ($codedString); #delete 'space' at the end
}

sub hexCodedSSL2Cipher { # Variable: String/Octet, der in HEX-Werten dargestellt werden soll, gibt Ausgabestring zurÃ¼ck 
    my $codedString= shift;
    my $prefix= shift; # set an optional prefix after '\n' 
    if (!defined($prefix)) { # undefined -> ""
            $prefix="";
    }    
    $codedString =~ s/([\x00-\xFF])([\x00-\xFF])([\x00-\xFF])/sprintf("%02X%02X%02X ", ord($1), ord($2), ord($3))/eig; #Code all 3-Octet-Ciphers as HEX value-Pairs and separate then with a 'space'
    $codedString =~ s/((?:[0-9A-Fa-f]{6}){16} )/"$1\n$prefix"/eig; #  Add a new line each 16 Ciphers (=112 Symbols incl. Spaces) 
    chomp ($codedString); #delete CR at the end
    return ($codedString); #delete 'space' at the end
}

sub hexCodedTLSCipher { # Variable: String/Octet, der in HEX-Werten dargestellt werden soll, gibt Ausgabestring zurück 
    my $codedString= shift;
    my $prefix= shift; # set an optional prefix after '\n' 
    if (!defined($prefix)) { # undefined -> ""
            $prefix="";
    }        
    $codedString =~ s/([\x00-\xFF])([\x00-\xFF])/sprintf("%02X%02X ", ord($1), ord($2))/eig; #Code all 2-Octet-Ciphers as HEX value-Pairs and separate then with a 'space'
    $codedString =~ s/((?:[0-9A-Fa-f]{4}){16} )/"$1\n$prefix"/eig; #  Add a new line each 16 Ciphers (=80 Symbols incl. Spaces) 
    chomp ($codedString); #delete CR at the end
    return ($codedString); #delete 'space' at the end
}

sub compileSSL2CipherArray ($) {
    my $cipherList= shift;
    my $protocolCipher="";
    my $firstByte="";
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
}


sub compileTLSCipherArray ($) {
    my $cipherList= shift;
    my $protocolCipher="";
    my $firstByte="";
    my @cipherArray = ();

    my $anzahl = int length ($cipherList) / 2;
    my @cipherTable = unpack("a2" x $anzahl, $cipherList);  

    _trace4 ("compileTLSCipherArray ($anzahl):\n");
    
    for(my $i = 0; $i < $anzahl; $i++) {
        _trace4_ (sprintf ("           Cipher[%2d]: ", $i));
        _trace4_ (sprintf (" >".hexCodedCipher ($cipherTable[$i])."< -> "));
        $protocolCipher = pack ("a6a*", "0x0300", hexCodedCipher($cipherTable[$i]));
        if ($Net::SSLhello::trace > 2) {
            if ($cipherHexHash {$protocolCipher} ) { # definiert, kein Null-String
                _trace4_ (sprintf ("%s -> %-32s -> %s", $protocolCipher, $cipherHexHash {$protocolCipher}[1], $cipherHexHash {$protocolCipher}[0]));     
            } else {
                _trace4_ ("$protocolCipher -> NO-RFC-".$protocolCipher);     
            }
            _trace4_ ("\n");
        }    
        push (@cipherArray, $protocolCipher); # add protocolCipher to Array
    }
    _trace4 ("compileTLSCipherArray: }\n");
    return (@cipherArray);
}


sub printSSL2CipherList ($) {
    my $cipherList= shift;
    my $protocolCipher="";
    my $firstByte="";

    my $anzahl = int length ($cipherList) / 3;
    my @cipherTable = unpack("a3" x $anzahl, $cipherList);  

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
            if ($cipherHexHash {$protocolCipher} ) { # definiert, kein Null-String
                _trace4_ (sprintf ("%s -> %-32s -> %s", $protocolCipher, $cipherHexHash {$protocolCipher}[1], $cipherHexHash {$protocolCipher}[0]));     
            } else {
                _trace4_ ("$protocolCipher -> NO-RFC-".$protocolCipher);     
            }
            _trace_ "\n";
        }    
        _trace_ "\n";
    }
}


sub printTLSCipherList ($) {
    my $cipherList= shift;
    my $protocolCipher="";

    my $anzahl = int length ($cipherList) / 2;
    my @cipherTable = unpack("a2" x $anzahl, $cipherList);  

#    if ($Net::SSLhello::trace > 2) {
    if ($Net::SSLhello::trace > 1) {

        _trace4 ("printTLSCipherList ($anzahl):\n");
        for(my $i = 0; $i < $anzahl; $i++) {
            _trace4_ (sprintf("           Cipher[%2d]: ", $i));
            _trace4_ (" >".hexCodedCipher ($cipherTable[$i])."< -> ");
            $protocolCipher = pack ("a6a*", "0x0300", hexCodedCipher($cipherTable[$i]));
            if ($cipherHexHash {$protocolCipher} ) { # definiert, kein Null-String
                _trace_ (sprintf "%s -> %-32s -> %s", $protocolCipher, $cipherHexHash {$protocolCipher}[1], $cipherHexHash {$protocolCipher}[0]);     
            } else {
                _trace_ ("$protocolCipher -> NO-RFC-".$protocolCipher);     
            }
            _trace4_ "\n";
        }    
        _trace4_ ("\n");
    }
}

1;

######################################################## public documentation #

=pod

=head1 NAME

Net::SSLhello - perl extension for SSL to simulate SSLhello packets to check SSL parameters

=head1 SYNOPSIS

    use Net::SSLhello;

=head1 DESCRIPTION

TBD comming soon ...

=head1 EXAMPLES

See SYNOPSIS above.

=head1 LIMITATIONS

=head1 KNOWN PROBLEMS

=head1 METHODS

=head1 SEE ALSO

L<IO::Socket(1)>

=head1 AUTHOR

10-may-14 Torsten Gigler

=cut

