#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) 2024, Achim Hoffmann
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package OCfg;

# TODO: implement
#    require "o-saft-lib" "full";  # or "raw"
#       full: anything for o-saft.pl; raw partial for SSLhello.pm

## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
#       SEE Perl:binmode() (in o-saft.pl)

## no critic qw(Subroutines::RequireArgUnpacking)
#       Because we use @_ for better human readability.

## no critic qw(## no critic qw(Variables::ProhibitPackageVars)
#       Because variables are defined herein.

## no critic qw(RegularExpressions::RequireExtendedFormatting)
#       We believe that most RegEx are not too complex.

## no critic qw(ValuesAndExpressions::ProhibitImplicitNewlines)
#       That's intended in strings; perlcritic is too pedantic.

use strict;
use warnings;
use utf8;

our $SID_ocfg   =  "@(#) OCfg.pm 3.14 24/02/19 15:34:16";
$OCfg::VERSION  =  "24.01.24";  # official version number of this file

BEGIN {
    # SEE Perl:@INC
    # SEE Perl:BEGIN perlcritic
    my $_me   = $0;     $_me   =~ s#.*[/\\]##x;
    my $_path = $0;     $_path =~ s#[/\\][^/\\]*$##x;
    if (exists $ENV{'PWD'} and not (grep{/^$ENV{'PWD'}$/} @INC) ) {
        unshift(@INC, $ENV{'PWD'});
    }
    unshift(@INC, $_path)   if not (grep{/^$_path$/} @INC);
    unshift(@INC, "lib")    if not (grep{/^lib$/}    @INC);
}

use OText       qw(%STR);

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

# more public documentation, see start of methods section, and at end of file.

# HACKER's INFO
#       Following (internal) functions from o-saft.pl are used:
#       _is_ssl_pfs()

## no critic qw(Documentation::RequirePodSections)
#  our POD below is fine, perlcritic (severity 2) is too pedantic here.

=pod

=encoding utf8


=head1 NAME

OCfg.pm - Perl module for O-Saft configuration


=head1 SYNOPSIS

=over 2

=item use OCfg;         # in perl code

=item OCfg.pm --help    # on command-line will print help

=back

Thinking perlish, there are two variants to use this module and its constants
and variables:

=over 4

=item 1. Variant with BEGIN

    BEGIN {
        require "OCfg.pm";      # file may have any name
        ...
    }
    ...
    use strict;
    print "a variable : " . $OCfg::var;

=item 2. Variant outside BEGIN

    BEGIN {
        ...
    }
    use strict;
    use OCfg;                   # file must be named  OCfg.pm
    ...
    print "a variable : " . $var;

=back

None of the constants, variables, or methods should be defined in the caller,
otherwise the calling script must handle warnings properly.


=head1 OPTIONS

=over 4

=item --help

=item --regex, --test-regex

=back


=head1 DESCRIPTION

Utility package for O-Saft (o-saft.pl and related tools). This package declares
and defines common L</VARIABLES> and L</METHODS> to be used in the calling tool.
All variables and methods are defined in the  OCfg::  namespace.

=head2 Used Functions

Following functions (methods) must be defined in the calling program:

=over 4

=item _trace( )

=item _trace1( )

=item _trace2( )

=item _trace3( )

=back


=head1 NOTES

It's often recommended not to export constants and variables from modules, see
for example  http://perldoc.perl.org/Exporter.html#Good-Practices . The main
purpose of this module is defining variables. Hence we export them.


=head1 CONSTANTS

=over 4

=item $STR{ERROR}

=item $STR{WARN}

=item $STR{HINT}

=item $STR{USAGE}

=item $STR{DBX}

=item $STR{UNDEF}

=item $STR{NOTXT}

=item $STR{MAKEVAL}

=back


=head1 VARIABLES

=over 4

=item %cfg

=item %dbx

=item %prot

=item %prot_txt

=item %tls_handshake_type

=item %tls_record_type

=item %tls_error_alerts

=item %TLS_EXTENSIONS

=item %ec_curve_types

=item %tls_curves

=item %data_oid

=item %target_desc

=item @target_defaults

=back


=head1 METHODS

=cut

#_____________________________________________________________________________
#________________________________________________ public (export) variables __|

## no critic qw(Modules::ProhibitAutomaticExportation)
#  perlcritic complains to use @EXPORT_OK instead of @EXPORT, but we want any-
#  thing exported.

# See NOTES below also.

use Exporter qw(import);
use base     qw(Exporter);
our @EXPORT     = qw(
        %ciphers
        %prot
        %prot_txt
        %tls_compression_method
        %tls_handshake_type
        %tls_key_exchange_type
        %tls_record_type
        %tls_error_alerts
        %TLS_EXTENSIONS
        %TLS_EC_POINT_FORMATS
        %TLS_MAX_FRAGMENT_LENGTH
        %TLS_NAME_TYPE
        %TLS_PROTOCOL_VERSION
        %TLS_PSK_KEY_EXCHANGE_MODE
        %TLS_SIGNATURE_SCHEME
        %TLS_SUPPORTED_GROUPS
        %TLS_ID_TO_EXTENSIONS
        %ec_curve_types
        %tls_curves
        %target_desc
        @target_defaults
        %data_oid
        %dbx
        %cfg
        get_ciphers_range
        get_cipher_owasp
        get_openssl_version
        get_dh_paramter
        get_target_nr
        get_target_prot
        get_target_host
        get_target_port
        get_target_auth
        get_target_proxy
        get_target_path
        get_target_orig
        get_target_start
        get_target_open
        get_target_stop
        get_target_error
        set_target_nr
        set_target_prot
        set_target_host
        set_target_port
        set_target_auth
        set_target_proxy
        set_target_path
        set_target_orig
        set_target_start
        set_target_open
        set_target_stop
        set_target_error
        set_user_agent
        tls_const2text
        tls_key2text
        tls_text2key
        printhint
        test_cipher_regex
        ocfg_done
);
# not yet exported: ocfg_sleep
# insert above in vi with:
# :r !sed -ne 's/^sub \([a-zA-Z][^ (]*\).*/\t\t\1/p' %
# :r !sed -ne 's/^our \([\%$@][a-zA-Z0-9_][^ (]*\).*/\t\t\1/p' %
# :r !sed -ne 's/^ *\($STR_[A-Z][^ ]*\).*/\t\t\1/p' %

my  $cfg__me= $0;               # dirty hack to circumvent late initialisation
    $cfg__me=~ s#^.*[/\\]##;    # of $cfg{'me'} which is used in %cfg itself

#branch
our %ciphers    = ();   # defined in lib/Ciphers.pm; need forward here

our %prot       = (     # collected data for protocols and ciphers
    # NOTE: ssl must be same string as in %cfg, %ciphers[ssl] and Net::SSLinfo %_SSLmap
    # ssl           protocol  name        hex version value openssl  option     val LOW ...
    #--------------+---------------------+-----------------+-------------------+---+---+---+---
    'SSLv2'     => {'txt' => "SSL 2.0 ",  'hex' => 0x0002,  'opt' => "-ssl2"    },
    'SSLv3'     => {'txt' => "SSL 3.0 ",  'hex' => 0x0300,  'opt' => "-ssl3"    },
    'TLSv1'     => {'txt' => "TLS 1.0 ",  'hex' => 0x0301,  'opt' => "-tls1"    },
    'TLSv11'    => {'txt' => "TLS 1.1 ",  'hex' => 0x0302,  'opt' => "-tls1_1"  },
    'TLSv12'    => {'txt' => "TLS 1.2 ",  'hex' => 0x0303,  'opt' => "-tls1_2"  },
    'TLSv13'    => {'txt' => "TLS 1.3 ",  'hex' => 0x0304,  'opt' => "-tls1_3"  },
    'DTLSv09'   => {'txt' => "DTLS 0.9",  'hex' => 0x0100,  'opt' => "-dtls"    },  # see Notes
    'DTLSv1'    => {'txt' => "DTLS 1.0",  'hex' => 0xFEFF,  'opt' => "-dtls1"   },  #  "
    'DTLSv11'   => {'txt' => "DTLS 1.1",  'hex' => 0xFEFE,  'opt' => "-dtls1_1" },  #  "
    'DTLSv12'   => {'txt' => "DTLS 1.2",  'hex' => 0xFEFD,  'opt' => "-dtls1_2" },  #  "
    'DTLSv13'   => {'txt' => "DTLS 1.3",  'hex' => 0xFEFC,  'opt' => "-dtls1_3" },  #  "
    'TLS1FF'    => {'txt' => "--dummy--", 'hex' => 0x03FF,  'opt' => undef      },  #  "
    'DTLSfamily'=> {'txt' => "--dummy--", 'hex' => 0xFE00,  'opt' => undef      },  #  "
    'fallback'  => {'txt' => "cipher",    'hex' => 0x0000,  'opt' => undef      },  #  "
    'TLS_FALLBACK_SCSV'=>{'txt'=> "SCSV", 'hex' => 0x5600,  'opt' => undef      },
    #-----------------------+--------------+----------------+------------------+---+---+---+---
    # see _prot_init_value() for following values in
    #   "protocol"=> {cnt, -?-, WEAK, LOW, MEDIUM, HIGH, protocol}
    #   "protocol"=> {cipher_pfs, ciphers_pfs, default, cipher_strong, cipher_weak}
    # Notes:
    #  TLS1FF   0x03FF  # last possible version of TLS1.x (not specified, used internal)
    #  DTLSv09: 0x0100  # DTLS, OpenSSL pre 0.9.8f, not finally standardised; some versions use 0xFEFF
    #  DTLSv09: -dtls   # never defined and used in openssl
    #  DTLSv1   0xFEFF  # DTLS1.0 (udp)
    #  DTLSv11  0xFEFE  # DTLS1.1: has never been used (udp)
    #  DTLSv12  0xFEFD  # DTLS1.2 (udp)
    #  DTLSv13  0xFEFC  # DTLS1.3, NOT YET specified (udp)
    #  DTLSfamily       # DTLS1.FF, no defined PROTOCOL, for internal use only
    #  fallback         # no defined PROTOCOL, for internal use only
    #  TLS_FALLBACK_SCSV# 12/2023: not sure needed
    # 'hex' value will be copied to $cfg{'openssl_version_map'} below
    # 'opt' value will be copied to $cfg{'openssl_option_map'}  below
    # TODO: hex value should be same as %_SSLmap in Net::SSLinfo
); # %prot

our %prot_txt   = (     # texts for protocol checks
    'cnt'           => "Supported total ciphers for ",           # counter
    '-?-'           => "Supported ciphers with security unknown",# "
    'WEAK'          => "Supported ciphers with security WEAK",   #  "
    'LOW'           => "Supported ciphers with security LOW",    #  "
    'MEDIUM'        => "Supported ciphers with security MEDIUM", #  "
    'HIGH'          => "Supported ciphers with security HIGH",   #  "
    'ciphers_pfs'   => "PFS (all  ciphers)",            # list with PFS ciphers
    'cipher_pfs'    => "PFS (selected cipher)",         # cipher if offered as default
    'default'       => "Selected  cipher  by server",   # cipher offered as default
    'protocol'      => "Selected protocol by server",   # 1 if selected as default protocol
); # %prot_txt

our %tls_handshake_type = (
    #----+--------------------------+-----------------------
    # ID  name                       comment
    #----+--------------------------+-----------------------
    0 => 'hello_request',
    1 => 'client_hello',
    2 => 'server_hello',
    3 => 'hello_verify_request',    # RFC 4347 DTLS
    4 => 'new_session_ticket',
#   4 => 'NewSessionTicket',
    6 => 'hello_retry_request',     # RFC 8446
    8 => 'encrypted_extensions',    # RFC 8446
   11 => 'certificate',
   12 => 'server_key_exchange',
   13 => 'certificate_request',
   14 => 'server_hello_done',
   15 => 'certificate_verify',
   16 => 'client_key_exchange',
   20 => 'finished',
   21 => 'certificate_url',         # RFC 6066 10.2
   22 => 'certificate_status',      # RFC 6066 10.2
   23 => 'supplemental_data',       # RFC ??
   24 => 'key_update',              # RFC 8446
  254 => 'message_hash',            # RFC 8446
  255 => '255',
   -1 => '<<undefined>>',           # added for internal use
  -99 => '<<fragmented_message>>',  # added for internal use
    #----+--------------------------+-----------------------
); # tls_handshake_type

our %tls_key_exchange_type = (
    #----+--------------------------+-----------------------
    # ID  name                       comment
    #----+--------------------------+-----------------------
   20 => 'change_cipher_spec',
   21 => 'alert',
   22 => 'handshake',
   23 => 'application_data',
   24 => 'heartbeat',
  255 => '255',
   -1 => '<<undefined>>',           # added for internal use
    #----+--------------------------+-----------------------
); # %%tls_key_exchange_type

our %tls_record_type = (
    #----+--------------------------+-----------------------
    # ID  name                       comment
    #----+--------------------------+-----------------------
   20 => 'change_cipher_spec',
   21 => 'alert',
   22 => 'handshake',
   23 => 'application_data',
   24 => 'heartbeat',
  255 => '255',
   -1 => '<<undefined>>',           # added for internal use
    #----+--------------------------+-----------------------
); # %tls_record_type

our %tls_compression_method = (
    #----+--------------------------+-----------------------
    # ID  name                       comment
    #----+--------------------------+-----------------------
    0 => 'NONE',
    1 => 'zlib compression',
   64 => 'LZS compression',
   -1 => '<<undefined>>',           # added for internal use
    #----+--------------------------+-----------------------
); # %tls_record_type

our %tls_error_alerts = ( # mainly RFC 6066
    #----+-------------------------------------+----+--+---------------
    # ID      name                              RFC DTLS OID
    #----+-------------------------------------+----+--+---------------
    0 => [qw( close_notify                      6066  Y  -)],
#   1 => [qw( warning                           6066  Y  -)],   # ??
#   2 => [qw( fatal                             6066  Y  -)],   # ??
   10 => [qw( unexpected_message                6066  Y  -)],
   20 => [qw( bad_record_mac                    6066  Y  -)],
   21 => [qw( decryption_failed                 6066  Y  -)],
   22 => [qw( record_overflow                   6066  Y  -)],
   30 => [qw( decompression_failure             6066  Y  -)],
   40 => [qw( handshake_failure                 6066  Y  -)],
   41 => [qw( no_certificate_RESERVED           5246  Y  -)],
   42 => [qw( bad_certificate                   6066  Y  -)],
   43 => [qw( unsupported_certificate           6066  Y  -)],
   44 => [qw( certificate_revoked               6066  Y  -)],
   45 => [qw( certificate_expired               6066  Y  -)],
   46 => [qw( certificate_unknown               6066  Y  -)],
   47 => [qw( illegal_parameter                 6066  Y  -)],
   48 => [qw( unknown_ca                        6066  Y  -)],
   49 => [qw( access_denied                     6066  Y  -)],
   50 => [qw( decode_error                      6066  Y  -)],
   51 => [qw( decrypt_error                     6066  Y  -)],
   60 => [qw( export_restriction_RESERVED       6066  Y  -)],
   70 => [qw( protocol_version                  6066  Y  -)],
   71 => [qw( insufficient_security             6066  Y  -)],
   80 => [qw( internal_error                    6066  Y  -)],
   86 => [qw( inappropriate_fallback            7507  Y  -)],
   90 => [qw( user_canceled                     6066  Y  -)],
  100 => [qw( no_renegotiation                  6066  Y  -)],
  109 => [qw( missing_extension                 8446  Y  -)],
  110 => [qw( unsupported_extension             6066  Y  -)],
  111 => [qw( certificate_unobtainable          6066  Y  -)],
  112 => [qw( unrecognized_name                 6066  Y  -)],
  113 => [qw( bad_certificate_status_response   6066  Y  -)],
  114 => [qw( bad_certificate_hash_value        6066  Y  -)],
  115 => [qw( unknown_psk_identity              4279  Y  -)],
  116 => [qw( certificate_required              8446  Y  -)],
  120 => [qw( no_application_protocol           7301  Y  -)],
    #----+-------------------------------------+----+--+---------------
); # %tls_error_alerts

our %TLS_EC_POINT_FORMATS = (
   TEXT =>      "ec point format(s)",                            # define text for print
 FORMAT => [qw( "%s"                                          )],# define format for printf
    #----+-------------------------------------+----+---+----------------------------
    # ID        name                            DTLS RECOMMENDED  RFC
    #----+-------------------------------------+----+---+----------------------------
      0 => [qw( uncompressed                    Y    Y   4492 )],
      1 => [qw( ansiX962_compressed_prime       Y?   N?  4492 )],
      2 => [qw( ansiX962_compressed_char2       Y?   N?  4492 )],
    #----+-------------------------------------+----+---+----------------------------
);

# https://tools.ietf.org/html/rfc6066#section-3 

our %TLS_NAME_TYPE = (
   TEXT =>      "server name type",                             # define text for print
 FORMAT => [qw( %s                                           )],# define format for printf
    #----+-------------------------------------+----+-------+------------------------
    # ID        name                            DTLS RFC
    #----+-------------------------------------+----+-------+------------------------
   0x00 => [qw( host_name                       Y    6066    )],
    #----+-------------------------------------+----+-------+------------------------
);

# https://tools.ietf.org/html/rfc6066#section-4
# Default is 2^14 if this extension is not present
our %TLS_MAX_FRAGMENT_LENGTH = (
   TEXT =>      "max fragment length negotiation",              # define text for print
 FORMAT => [    "%s",   "(%s bytes)"                          ],# define format for printf
    #----+-------------------------------------+----+-------+------------------------
    # ID        name                    RECONMMENDED RFC
    #----+-------------------------------------+----+-------+------------------------
   0x01 => [qw( 2^9        512                  -    6066    )],
   0x02 => [qw( 2^10      1024                  -    6066    )],
   0x03 => [qw( 2^11      2048                  -    6066    )],
   0x04 => [qw( 2^12      4096                  -    6066    )],
    #----+-------------------------------------+----+-------+------------------------
);

# https://tools.ietf.org/html/rfc8446#appendix-B.3.1.1 (added versions manually)
our %TLS_PROTOCOL_VERSION  = (
   TEXT =>      "supported protocol version(s)",                # define text for print
 FORMAT => [qw( %s    ) ],                                      # define format for printf
    #----+-------------------------------------------------------------------------
    # ID        name
    #----+-------------------------------------------------------------------------
 0x0304 => [qq( TLS 1.3 )],
 0x0303 => [qq( TLS 1.2 )],
 0x0302 => [qq( TLS 1.1 )],
 0x0301 => [qq( TLS 1.0 )],
 0x0300 => [qq( SSL 3   )],
    #----+-------------------------------------------------------------------------
);

# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-pskkeyexchangemode
our %TLS_PSK_KEY_EXCHANGE_MODE  = (
   TEXT =>      "PSK key exchange mode(s)",                     # define text for print
 FORMAT => [qw( "%s"                                         )],# define format for printf
    #----+-------------------------------------+----+-------+------------------------
    # ID        name                    RECONMMENDED RFC
    #----+-------------------------------------+----+-------+------------------------
   0x00 => [qw( psk_ke                          Y    8446    )],
   0x01 => [qw( psk_dhe_ke                      Y    8446    )],
    #----+-------------------------------------+----+-------+------------------------
);

# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
our %TLS_SIGNATURE_SCHEME = (
   TEXT =>      "signature scheme(s)",                          # define text for print
 FORMAT => [qw( %s                                           )],# define format for printf
    #----+-------------------------------------+----+-------+------------------------
    # ID        name                            DTLS  RFC       # comment
    #----+-------------------------------------+----+-------+------------------------
 0x0201 => [qw( rsa_pkcs1_sha1                   Y   8446    )],
 0x0202 => [qw( dsa_sha1                         ?   8446    )],# Quelle suchen & prüfen!
 0x0203 => [qw( ecdsa_sha1                       Y   8446    )],

 0x0301 => [qw( rsa_sha224                       ?   ?       )],# Quelle suchen & prüfen!
 0x0302 => [qw( dsa_sha224                       ?   ?       )],# Quelle suchen & prüfen!
 0x0303 => [qw( ecdsa_sha224                     ?   ?       )],# Quelle suchen & prüfen!

 0x0401 => [qw( rsa_pkcs1_sha256                 Y   8446    )],
 0x0402 => [qw( dsa_sha256                       ?   8446    )],# Quelle suchen & prüfen!
 0x0403 => [qw( ecdsa_secp256r1_sha256           Y   8446    )],
 0x0420 => [qw( rsa_pkcs1_sha256_legacy          N   draft-davidben-tls13-pkcs1-00 )],

 0x0501 => [qw( rsa_pkcs1_sha384                 Y   8446    )],
 0x0502 => [qw( dsa_sha384                       ?   8446]   )],# Quelle suchen & prüfen!
 0x0503 => [qw( ecdsa_secp384r1_sha384           Y   8446    )],

 0x0520 => [qw( rsa_pkcs1_sha384_legacy          N   draft-davidben-tls13-pkcs1-00 )],

 0x0601 => [qw( rsa_pkcs1_sha512                 Y   8446    )],
 0x0602 => [qw( dsa_pkcs1_sha512                 Y   8446    )],# Quelle suchen & prüfen!
 0x0603 => [qw( ecdsa_secp521r1_sha512           Y   8446    )],

 0x0620 => [qw( rsa_pkcs1_sha512_legacy          N   draft-davidben-tls13-pkcs1-00 )],

 0x0704 => [qw( eccsi_sha256                     N   draft-wang-tls-raw-public-key-with-ibc )],
 0x0705 => [qw( iso_ibs1                         N   draft-wang-tls-raw-public-key-with-ibc])],
 0x0706 => [qw( iso_ibs2                         N   draft-wang-tls-raw-public-key-with-ibc])],
 0x0707 => [qw( iso_chinese_ibs                  N   draft-wang-tls-raw-public-key-with-ibc])],
 0x0708 => [qw( sm2sig_sm3                       N   draft-yang-tls-tls13-sm-suites )],
 0x0709 => [qw( gostr34102012_256a               N   draft-smyshlyaev-tls13-gost-suites )],
 0x070A => [qw( gostr34102012_256b               N   draft-smyshlyaev-tls13-gost-suites )],
 0x070B => [qw( gostr34102012_256c               N   draft-smyshlyaev-tls13-gost-suites )],
 0x070C => [qw( gostr34102012_256d               N   draft-smyshlyaev-tls13-gost-suites )],
 0x070D => [qw( gostr34102012_512a               N   draft-smyshlyaev-tls13-gost-suites )],
 0x070E => [qw( gostr34102012_512b               N   draft-smyshlyaev-tls13-gost-suites )],
 0x070F => [qw( gostr34102012_512c               N   draft-smyshlyaev-tls13-gost-suites )],

 0x0804 => [qw( rsa_pss_rsae_sha256              Y   8446    )],
 0x0805 => [qw( rsa_pss_rsae_sha384              Y   8446    )],
 0x0806 => [qw( rsa_pss_rsae_sha512              Y   8446    )],
 0x0807 => [qw( ed25519                          Y   8446    )],
 0x0808 => [qw( ed448                            Y   8446    )],
 0x0809 => [qw( rsa_pss_pss_sha256               Y   8446    )],
 0x080A => [qw( rsa_pss_pss_sha384               Y   8446    )],
 0x080B => [qw( rsa_pss_pss_sha512               Y   8446    )],

 0x081A => [qw( ecdsa_brainpoolP256r1tls13_sha256 N  8734    )],
 0x081B => [qw( ecdsa_brainpoolP384r1tls13_sha384 N  8734    )],
 0x081C => [qw( ecdsa_brainpoolP512r1tls13_sha512 N  8734    )],

# 0xFE00 .. 0xFFFF => [qw(private_use            ?   8446    )],
    #----+-------------------------------------+----+-------+------------------------
);

# Torsten: ex %ECC_NAMED_CURVE =
# http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-10
our %TLS_SUPPORTED_GROUPS = (
   TEXT =>      "supported group(s)",                               # define text for print
 FORMAT => [    "%s",           "(%s bits)"                       ],# define format for printf, space is needed -> no 'qw'
    #----+-----------------------------+-------+----+---+----------------------------
    # ID        name               (added:)bits DTLS RECOMMENDED  RFC
    #----+-----------------------------+-------+----+---+----------------------------
      0 => [qw( Reverved_0                 0    N    N   8447    )],
      1 => [qw( sect163k1                163    Y    N   4492    )],
      2 => [qw( sect163r1                163    Y    N   4492    )],
      3 => [qw( sect163r2                163    Y    N   4492    )],
      4 => [qw( sect193r1                193    Y    N   4492    )],
      5 => [qw( sect193r2                193    Y    N   4492    )],
      6 => [qw( sect233k1                233    Y    N   4492    )],
      7 => [qw( sect233r1                233    Y    N   4492    )],
      8 => [qw( sect239k1                239    Y    N   4492    )],
      9 => [qw( sect283k1                283    Y    N   4492    )],
     10 => [qw( sect283r1                283    Y    N   4492    )],
     11 => [qw( sect409k1                409    Y    N   4492    )],
     12 => [qw( sect409r1                409    Y    N   4492    )],
     13 => [qw( sect571k1                571    Y    N   4492    )],
     14 => [qw( sect571r1                571    Y    N   4492    )],
     15 => [qw( secp160k1                160    Y    N   4492    )],
     16 => [qw( secp160r1                160    Y    N   4492    )],
     17 => [qw( secp160r2                160    Y    N   4492    )],
     18 => [qw( secp192k1                192    Y    N   4492    )],
     19 => [qw( secp192r1                192    Y    N   4492    )],
     20 => [qw( secp224k1                224    Y    N   4492    )],
     21 => [qw( secp224r1                224    Y    N   4492    )],
     22 => [qw( secp256k1                256    Y    N   4492    )],
     23 => [qw( secp256r1                256    Y    Y   4492    )],
     24 => [qw( secp384r1                384    Y    Y   4492    )],
     25 => [qw( secp521r1                521    Y    N   4492    )],
     26 => [qw( brainpoolP256r1          256    Y    Y   7027    )],
     27 => [qw( brainpoolP384r1          384    Y    Y   7027    )],
     28 => [qw( brainpoolP512r1          512    Y    Y   7027    )],
     29 => [qw( x25519                   255    Y    Y   8446:8422 )],
     30 => [qw( x448                     448    Y    Y   8446:8422 )],
     31 => [qw( brainpoolP256r1tls13     256    Y    N   8734    )],
     32 => [qw( brainpoolP384r1tls13     384    Y    N   8734    )],
     33 => [qw( brainpoolP512r1tls13     512    Y    N   8734    )],
     34 => [qw( GC256A                   256    Y    N   draft-smyshlyaev-tls12-gost-suites )],
     35 => [qw( GC256B                   256    Y    N   draft-smyshlyaev-tls12-gost-suites )],
     36 => [qw( GC256C                   256    Y    N   draft-smyshlyaev-tls12-gost-suites )],
     37 => [qw( GC256D                   256    Y    N   draft-smyshlyaev-tls12-gost-suites )],
     38 => [qw( GC512A                   512    Y    N   draft-smyshlyaev-tls12-gost-suites )],
     39 => [qw( GC512B                   512    Y    N   draft-smyshlyaev-tls12-gost-suites )],
     40 => [qw( GC512C                   512    Y    N   draft-smyshlyaev-tls12-gost-suites )],
     41 => [qw( curveSM2                 256    N    N   draft-yang-tls-tls13-sm-suites )],
#    42-255  Unassigned
    256 => [qw( ffdhe2048               2048    Y    N   7919    )],
    257 => [qw( ffdhe3072               3072    Y    N   7919    )],
    258 => [qw( ffdhe4096               4096    Y    N   7919    )],
    259 => [qw( ffdhe6144               6144    Y    N   7919    )],
    260 => [qw( ffdhe8192               8192    Y    N   7919    )],
#   261-507 Unassigned
    508 => [qw( ffdhe_private_use_508     NN    Y    N   7919    )],
    509 => [qw( ffdhe_private_use_509     NN    Y    N   7919    )],
    510 => [qw( ffdhe_private_use_510     NN    Y    N   7919    )],
    511 => [qw( ffdhe_private_use_511     NN    Y    N   7919    )],
#   512-2569    Unassigned
   2570 => [qw( Reserved_2570             NN    Y    N   8701    )],
#  2571-6681    Unassigned
   6682 => [qw( Reserved_6682             NN    Y    N   8701    )],
# 6683-10793   Unassigned
  10794 => [qw( Reserved_10794            NN    Y    N   8701    )],
# 10795-14905   Unassigned
  14906 => [qw( Reserved_14906            NN    Y    N   8701    )],
# 14907-19017   Unassigned
  19018 => [qw( Reserved_19018            NN    Y    N   8701    )],
# 19019-23129   Unassigned
  23130 => [qw( Reserved_23130            NN    Y    N   8701    )],
# 23131-27241   Unassigned
  27242 => [qw( Reserved_27242            NN    Y    N   8701    )],
# 27243-31353   Unassigned
  31354 => [qw( Reserved_31354            NN    Y    N   8701    )],
# 31355-35465   Unassigned
  35466 => [qw( Reserved_35466            NN    Y    N   8701    )],
# 35467-39577   Unassigned
  39578 => [qw( Reserved_39578            NN    Y    N   8701    )],
# 39579-43689   Unassigned
  43690 => [qw( Reserved_43690            NN    Y    N   8701    )],
# 43691-47801   Unassigned
  47802 => [qw( Reserved_47802            NN    Y    N   8701    )],
# 47803-51913   Unassigned
  51914 => [qw( Reserved_51914            NN    Y    N   8701    )],
# 51915-56025   Unassigned
  56026 => [qw( Reserved_56026            NN    Y    N   8701    )],
# 56027-60137   Unassigned
  60138 => [qw( Reserved_60138            NN    Y    N   8701    )],
# 60139-64249   Unassigned
  64250 => [qw( Reserved_64250            NN    Y    N   8701    )],
# 64251-65023   Unassigned
# 65024-65279   Reserved_for_Private_Use  NN    Y    N   8422    ,
 0xFE00 => [qw( ecdhe_private_use_65024   NN    Y    N   NN      )],# 0xFE00..0xFEFF => "ecdhe_private_use",
 0xFE01 => [qw( ecdhe_private_use_65025   NN    Y    N   NN      )],# 0xFE00..0xFEFF => "ecdhe_private_use",
 0xFE02 => [qw( ecdhe_private_use_65026   NN    Y    N   NN      )],# 0xFE00..0xFEFF => "ecdhe_private_use",
 0xFE03 => [qw( ecdhe_private_use_65027   NN    Y    N   NN      )],# 0xFE00..0xFEFF => "ecdhe_private_use",
 0xFE04 => [qw( ecdhe_private_use_65028   NN    Y    N   NN      )],# 0xFE00..0xFEFF => "ecdhe_private_use",
 0xFE05 => [qw( ecdhe_private_use_65029   NN    Y    N   NN      )],# 0xFE00..0xFEFF => "ecdhe_private_use",
 0xFE06 => [qw( ecdhe_private_use_65030   NN    Y    N   NN      )],# 0xFE00..0xFEFF => "ecdhe_private_use",
 0xFE07 => [qw( ecdhe_private_use_65031   NN    Y    N   NN      )],# 0xFE00..0xFEFF => "ecdhe_private_use",
# 65280         Unassigned
  65281 => [qw( arbitrary_explicit_prime_curves  -variable- N   8422    )],
  65282 => [qw( arbitrary_explicit_char2_curves  -variable- Y   8422    )],
# 65283-65535   Unassigned
);

our %TLS_EXTENSIONS = (
# Generated on base of IANA (https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml#tls-extensiontype-values-1), RFCs and drafts for RFCs
#
# Added a self defined general description for the structure of for PDUs, e.g. tls extensions:
# len1:     Len of the next bytes, coded in 1 byte      (-> max 0xFF)
# len2:     Len of the next bytes, coded in 2 bytes     (-> max 0xFFFF)
# len3:     Len of the next bytes, coded in 3 bytes     (-> max 0xFFFFFF)
# size1:    Size of the next value, coded in 1 byte     (-> max 0xFF)
# size2:    Size of the next value, coded in 2 bytes    (-> max 0xFFFF)
# val1:     value, coded in 1 byte                      (-> max 0xFF)
# val2:     value, coded in 2 bytes                     (-> max 0xFFFF)
# val4:     value, coded in 4 byters                    (-> max 0xFFFFFFFF)
# val1List: List of value, coded in 1 byte              (-> max 0xFF, 0xFF, ...)
# val2List: List of value, coded in 2 bytes             (-> max 0xFFFF, 0xFFFF, ...)
# raw:      Raw bytes (number needs to be previously defined by a len or size element)
# sequence: Sequence of structured elements that form lists of compound values
#
# Hash values:
# <Hash>:       Extension name by IANA, RFC or draft for a RFCr
# ID:           Official nr by IANA, RFC or DRAFT for a RFC
# CH:           Client Hello: describes the structure of client hellos based on the general descrition language defined above
# CH_TEXT:      Descriptions and references to decoding hashes by the structure element of a CH
# RX:           Received Extension, e.g. Server Hellon: describes the structure of received hellos based on the general descrition language defined above
# RX_TEXT:      Descriptions and references to decoding hashes by the structure element of a RX
# RECOMMENDED:  From IANA, 'N' or '?' if the extension is taken from a RFC or draft for a RFC
# TLS13:        Whrere used by TLSv1.3 according IANA
# RFC:          RFC according, IANA, RFC or draft
# DEFAULT:      Default values for client hellos (used by val1 ... val4, val1List, val2List, raw, sequences define an array inside the array lists).
# CHECK:        Internal value, if the VALUE or CHECKing for a list of all (supporeted) values (might be reserved for future deployment)
# COMMENT:      Optional comments
#
#---------------------------------+---------------+------------+----------------------------------+--------------------------------+--------+---------------+--------------------------
#Extension Name: (ID (Value), CH* (Client Hello)*, RX* (Receive SH, ...), RECOMMENDED, TLS13 (TLS 1.3), RFC, COMMENT*; *= Added             comment
#---------------------------------+---------------+------------+----------------------------------+--------------------------------+--------+---------------+--------------------------
server_name => {
            ID      => 0,                                           # Hex:     0x0000
            CH         => [qw(len2 len2 sequence val1 len2 raw)],
            CH_TEXT    => ["length", "server name list length", "server name element", \%TLS_NAME_TYPE, "server name length", "server name" ],
            RX            => [qw(len2 raw)],                        # Example: 0x0000 (no data, only as marker)
            RX_TEXT       => ["length", "server name list length" ],
            RECOMMENDED      => q(Y),
            TLS13               => [qw(CH EE)],
            RFC                    => [qw(6066)],
            DEFAULT                   => [
                                             [                      # 1st sequence element
                                                 0x00,              # host_name
                                                 "localhost",       # $TLS_EXTENSION{server_name}{DEFAULT}[0][0][1], might be overwritten
                                             ],
                                         ],
            CHECK                        => q(VALUE),
            COMMENT                         => q(),
    },

max_fragment_length => {
            ID    => 1,
            CH       => [qw(len2 len2 val1List)],
            CH_TEXT  => ["length", "length of max fragment lenght", \%TLS_MAX_FRAGMENT_LENGTH ],
            RX          => [qw(len2 raw)],
            RX_TEXT  => ["length", \%TLS_MAX_FRAGMENT_LENGTH ],
            RECOMMENDED    => q(-),
            TLS13             => [qw(CH EE)],
            RFC                  => [qw(6066 8449)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q(replaced by extension 'record_size_limit'; Default max length is 2^14 if this extension is not negotiated),
    },

client_certificate_url => {
            ID    => 2,
            CH       => [qw(len2 len2 val1 sequence len2 val1 raw)],#TBD Check sequence position
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(-)],
            RFC                  => [qw(6066)],
            DEFAULT                 => [ ],                         # [ [<seqence>], ],
            CHECK                      => q(VALUE),
            COMMENT                       => q(val20 oder len2_val?),
    },

trusted_ca_keys => {
            ID    => 3,
            CH       => [qw(len2 len2 val1 len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(N)],
            RFC                  => [qw(6066)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q(?),
    },
truncated_hmac => {
            ID    => 4,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q[N],
            TLS13             => [qw(N)],
            RFC                  => [qw(6066 IESG_Action_2018-08-16)],
            DEFAULT                 => [],
            CHECK                      => q[VALUE],
            COMMENT                       => q[Shall be empty],
    },
status_request => {
            ID    => 5,
            CH       => [qw(len2 val1 len2 raw len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH CR CT)],
            RFC                  => [qw(6066)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[SH ext_form_val1_len2_val?],
    },
user_mapping => {
            ID    => 6,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(-)],
            RFC                  => [qw(4681)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q(),
    },
client_authz => {
            ID    => 7,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(N),
            TLS13             => [qw(-)],
            RFC                  => [qw(5878)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q(),
    },
server_authz => {
            ID    => 8,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(N),
            TLS13             => [qw(-)],
            RFC                  => [qw(5878)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q(),
    },
cert_type => {
            ID    => 9,
            CH       => [qw(len2 len1 val1List)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(N),
            TLS13             => [qw(-)],
            RFC                  => [qw(6091)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q(Server: val1),
    },
#elliptic_curves  =>                                                             # old name
supported_groups => {
            ID    => 10,
            CH       => [qw(len2 len2 val2List)],
            CH_TEXT  => ["length", "supported groups list length", \%TLS_SUPPORTED_GROUPS],
            RX          => [qw(len2 val2)],
            RX_TEXT     => ["length", \%TLS_SUPPORTED_GROUPS],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH EE)],
            RFC                  => [qw(8422 7919)],
            DEFAULT                 => [
                                         [ #0x0000, # 0x0000 (Unassigned_0)       ## disabled by default
                                            0x0001, # sect163k1
                                            0x0002, # sect163r1
                                            0x0003, # sect163r2
                                            0x0004, # sect193r1
                                            0x0005, # sect193r2
                                            0x0006, # sect233k1
                                            0x0007, # sect233r1
                                            0x0008, # sect239k1
                                            0x0009, # sect283k1
                                            0x000a, # sect283r1
                                            0x000b, # sect409k1
                                            0x000c, # sect409r1
                                            0x000d, # sect571k1
                                            0x000e, # sect571r1
                                            0x000f, # secp160k1
                                            0x0010, # secp160r1
                                            0x0011, # secp160r2
                                            0x0012, # secp192k1
                                            0x0013, # secp192r1
                                            0x0014, # secp224k1
                                            0x0015, # secp224r1
                                            0x0016, # secp256k1
                                            0x0017, # secp256r1     ## => common default curve
                                            0x0018, # secp384r1
                                            0x0019, # secp512r1
                                            0x001a, # brainpoolP256r1
                                            0x001b, # brainpoolP384r1
                                            0x001c, # brainpoolP512r1
                                            0x001d, # ecdh_x25519
                                            0x001e, # ecdh_x448
                                            0x001f, # brainpoolP256r1tls13
                                            0x0020, # brainpoolP384r1tls13
                                            0x0021, # brainpoolP512r1tls13
                                            0x0022, # GC256A        [draft-smyshlyaev-tls12-gost-suites]
                                            0x0023, # GC256B        [draft-smyshlyaev-tls12-gost-suites]
                                            0x0024, # GC256C        [draft-smyshlyaev-tls12-gost-suites]
                                            0x0025, # GC256D        [draft-smyshlyaev-tls12-gost-suites]
                                            0x0026, # GC512A        [draft-smyshlyaev-tls12-gost-suites]
                                            0x0027, # GC512B        [draft-smyshlyaev-tls12-gost-suites]
                                            0x0028, # GC512C        [draft-smyshlyaev-tls12-gost-suites]
                                            0x0029, # curveSM2      [draft-yang-tls-tls13-sm-suites]
                                                    # Finite Field Groups (DHE):
                                            0x0100, # ffdhe2048
                                            0x0101, # ffdhe3072
                                            0x0102, # ffdhe4096
                                            0x0103, # ffdhe6144
                                            0x0104, # ffdhe8192
                                         ],
                                       ],
            CHECK                      => q(VALUE),
            COMMENT                       => q(renamed from "elliptic_curves"),
    },
ec_point_formats => {
            ID    => 11,                            # Hex:      0x000b
            CH       => [qw(len2 len1 val1List)],   # Example:  0x0002 0x01 0x00
            CH_TEXT  => ["length", "ec point formats list length", \%TLS_EC_POINT_FORMATS],
            RX          => [qw(len2 len1 val1List)],
            RX_TEXT     => ["length", "ec point formats list length", \%TLS_EC_POINT_FORMATS],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(-)],
            RFC                  => [qw(8422)],
            DEFAULT                 => [ 
                                         [ 0x00,    # uncompressed,Y,[RFC8422]
                                           0x01,    # ansiX962_compressed_prime,Y,[RFC8422]
                                           0x02,    # ansiX962_compressed_char2,Y,[RFC8422]
                                         ],
                                       ],
            CHECK                      => q(VALUE),
            COMMENT                       => q(),
    },
srp => {
            ID    => 12,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(N),,
            TLS13             => [qw(-)],
            RFC                  => [qw(5054)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q(),
    },
signature_algorithms => {
            ID    => 13,                            # Hex: 0x000d
            CH       => [qw(len2 len2 val2List)],     # Example: 0x0020 0x001E 0x0601 0x0602 0x0603 0x0501 0x0502 0x0503 0x0401 0x0402 0x0403 0x0301 0x0302 0x0303 0x0201 0x0202 0x0203
            CH_TEXT  => ["length", "signature hash algorithms list length", \%TLS_SIGNATURE_SCHEME],
            RX          => [qw(len2 val2)],
            RX_TEXT     => ["length", \%TLS_SIGNATURE_SCHEME],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH CR)],
            RFC                  => [qw(8446)],
            DEFAULT                 => [
                                         [ 0x0201, # rsa_pkcs1_sha1,Y,[RFC8446]
                                           0x0202, # SHA1 DSA,[RFC8446] (Quelle suchen & prüfen!)
                                           0x0203, # ecdsa_sha1,Y,[RFC8446]

                                           0x0301, # SHA224 RSA (Quelle suchen & prüfen!)
                                           0x0302, # SHA224 DSA (Quelle suchen & prüfen!)
                                           0x0303, # SHA224 ECDSA (Quelle suchen & prüfen!)

                                           0x0401, # rsa_pkcs1_sha256,Y,[RFC8446]
                                           0x0402, # SHA256 DSA (Quelle suchen & prüfen!),[RFC8446] (Quelle suchen & prüfen!)
                                           0x0403, # ecdsa_secp256r1_sha256,Y,[RFC8446]
                                           0x0420, # rsa_pkcs1_sha256_legacy,N,[draft-davidben-tls13-pkcs1-00]

                                           0x0501, # rsa_pkcs1_sha384,Y,[RFC8446]
                                           0x0502, # Reserved for backward compatibility,,[RFC8446]
                                           0x0503, # ecdsa_secp384r1_sha384,Y,[RFC8446]

                                           0x0520, # rsa_pkcs1_sha384_legacy,N,[draft-davidben-tls13-pkcs1-00]

                                           0x0601, # rsa_pkcs1_sha512,Y,[RFC8446]
                                           0x0602, # dsa_pkcs1_sha512,Y,[RFC8446]? (Quelle suchen und prüfen!)
                                           0x0603, # ecdsa_secp521r1_sha512,Y,[RFC8446]

                                           0x0620, # rsa_pkcs1_sha512_legacy,N,[draft-davidben-tls13-pkcs1-00]

                                           0x0704, # eccsi_sha256,N,[draft-wang-tls-raw-public-key-with-ibc]
                                           0x0705, # iso_ibs1,N,[draft-wang-tls-raw-public-key-with-ibc]
                                           0x0706, # iso_ibs2,N,[draft-wang-tls-raw-public-key-with-ibc]
                                           0x0707, # iso_chinese_ibs,N,[draft-wang-tls-raw-public-key-with-ibc]
                                           0x0708, # sm2sig_sm3,N,[draft-yang-tls-tls13-sm-suites]
                                           0x0709, # gostr34102012_256a,N,[draft-smyshlyaev-tls13-gost-suites]
                                           0x070A, # gostr34102012_256b,N,[draft-smyshlyaev-tls13-gost-suites]
                                           0x070B, # gostr34102012_256c,N,[draft-smyshlyaev-tls13-gost-suites]
                                           0x070C, # gostr34102012_256d,N,[draft-smyshlyaev-tls13-gost-suites]
                                           0x070D, # gostr34102012_512a,N,[draft-smyshlyaev-tls13-gost-suites]
                                           0x070E, # gostr34102012_512b,N,[draft-smyshlyaev-tls13-gost-suites]
                                           0x070F, # gostr34102012_512c,N,[draft-smyshlyaev-tls13-gost-suites]

                                           0x0804, # rsa_pss_rsae_sha256,Y,[RFC8446]
                                           0x0805, # rsa_pss_rsae_sha384,Y,[RFC8446]
                                           0x0806, # rsa_pss_rsae_sha512,Y,[RFC8446]
                                           0x0807, # ed25519,Y,[RFC8446]
                                           0x0808, # ed448,Y,[RFC8446]
                                           0x0809, # rsa_pss_pss_sha256,Y,[RFC8446]
                                           0x080A, # rsa_pss_pss_sha384,Y,[RFC8446]
                                           0x080B, # rsa_pss_pss_sha512,Y,[RFC8446]

                                           0x081A, # ecdsa_brainpoolP256r1tls13_sha256,N,[RFC8734]
                                           0x081B, # ecdsa_brainpoolP384r1tls13_sha384,N,[RFC8734]
                                           0x081C, # ecdsa_brainpoolP512r1tls13_sha512,N,[RFC8734]
                                         ],
                                       ],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
use_srtp => {
            ID    => 14,
            CH       => [qw(len2 size2 val2List len1 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH EE)],
            RFC                  => [qw(5764)],
            DEFAULT                 => [
                                         [ 0x0001, # SRTPProtectionProfile SRTP_AES128_CM_HMAC_SHA1_80
                                           0x0002, # SRTPProtectionProfile SRTP_AES128_CM_HMAC_SHA1_32
                                           0x0005, # SRTPProtectionProfile SRTP_NULL_HMAC_SHA1_80
                                           0x0006, # SRTPProtectionProfile SRTP_NULL_HMAC_SHA1_32
                                         ]
                                       ],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
heartbeat => {
            ID    => 15,
            CH       => [qw(len2 val1)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH EE)],
            RFC                  => [qw(6520)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q(Syntax prüfen!),
    },
application_layer_protocol_negotiation => {
            ID    => 16,
            CH       => [qw(len2 len2 size1 raw size1 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH EE)],
            RFC                  => [qw(7301)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
status_request_v2 => {
            ID    => 17,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(-)],
            RFC                  => [qw(6961)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
signed_certificate_timestamp => {
            ID    => 18,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(N),
            TLS13             => [qw(CH CR CT)],
            RFC                  => [qw(6962)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
client_certificate_type => {
            ID    => 19,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH EE)],
            RFC                  => [qw(7250)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
server_certificate_type => {
            ID    => 20,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH EE)],
            RFC                  => [qw(7250)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
padding => {
            ID    => 21,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH)],
            RFC                  => [qw(7685)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q(val= 0x00-Bytes),
    },
encrypt_then_mac => {
            ID    => 22,                            # Hex:        0x0016
            CH       => [qw(len2 raw)],               # Example:    0x0000 (no data, only as marker)
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(-)],
            RFC                  => [qw(7366)],
            DEFAULT                 => [], #empty
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
extended_master_secret => {
            ID    => 23,                            # Hex:      0x0017
            CH       => [qw(len2 raw)],               # Example:  0x0000 (no data, only as marker)
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(-)],
            RFC                  => [qw(7627)],
            DEFAULT                 => [], #empty
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
token_binding => {
            ID    => 24,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(-)],
            RFC                  => [qw(8472)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
cached_info => {
            ID    => 25,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(-)],
            RFC                  => [qw(7924)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
tls_lts => {
            ID    => 26,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(N),
            TLS13             => [qw(-)],
            RFC                  => [qw(draft-gutmann-tls-lts)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
compress_certificate => {
            ID    => 27,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH CR)],
            RFC                  => [qw(draft-ietf-tls-certificate-compression)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q(TEMPORARY registered 2018-05-23 extension registered 2019-04-22 expires 2020-05-23),
    },
record_size_limit => {
            ID    => 28,
            CH       => [qw(len2 val2)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH EE)],
            RFC                  => [qw(8449)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
pwd_protect => {
            ID    => 29,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(N),
            TLS13             => [qw(CH)],
            RFC                  => [qw(8492)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
pwd_clear => {
            ID    => 30,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(N),
            TLS13             => [qw(CH)],
            RFC                  => [qw(8492)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
password_salt => {
            ID    => 31,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(N),
            TLS13             => [qw(CH SH HRR)],
            RFC                  => [qw(8492)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
#  32-34    Unassigned
session_ticket => {
            ID    => 35,                            # Hex:      0x0023
#            CH       => [qw(len2 val4 len2 raw)],     # Example:  0x0000 (no data)
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(-)],
            RFC                  => [qw(5077 8447)],
            DEFAULT                 => [], # empty
            CHECK                      => q(VALUE),
            COMMENT                       => q(renamed from "SessionTicket TLS"),
    },

#  36-40    Unassigned
# NOT official:
extended_random => {
            ID    => 40,
            CH        => [qw(len2 len2 raw)],
            RX           => [qw(len2 raw)],
            RECOMMENDED     => q(N!),
            TLS13              => [qw(?)],
            RFC                   => [qw(draft-rescorla-tls-extended-random-02)],
            DEFAULT                  => [],
            CHECK                       => q(VALUE),
            COMMENT                        => q(NSA; March 02, 2009; DO NOT USE!! https://gist.github.com/bonsaiviking/9921180: 0x0028, RSA BSAFE library),
    },
pre_shared_key => {
            ID    => 41,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH SH)],
            RFC                  => [qw(8446)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
early_data    => {
            ID    => 42,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH EE NST)],
            RFC                  => [qw(8446)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
supported_versions    => {
            ID    => 43,                            # Hex:      0x002b
            CH       => [qw(len2 len1 val2List)],     # Example:  0x0003 0x02 0x0304
            CH_TEXT  => ["length", "supported versions list length", \%TLS_PROTOCOL_VERSION],
            RX          => [qw(len2 val2)],
            RX_TEXT     => ["length", \%TLS_PROTOCOL_VERSION],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH SH HRR)],
            RFC                  => [qw(8446)],
            DEFAULT                 => [
                                         [ 0x0304, # TLS 1.3
                                           # 0x0303, # TLS 1.2
                                           # 0x0302, # TLS 1.1
                                           # 0x0301, # TLS 1.0
                                           # 0x0300, # SSL 3
                                         ],
                                       ],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
cookie    => {
            ID    => 44,
            CH       => [qw(len2 raw)],
            RX          => [qw(len2 raw)],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH HRR)],
            RFC                  => [qw(8446)],
            DEFAULT                 => [],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
psk_key_exchange_modes    => {                      # MUST be included if key_share is used
            ID    => 45,                            # Hex:      0x02d
            CH       => [qw(len2 len1 val1List)],   # Example:  0x0002 0x01 0x01
            CH_TEXT     => ["length", "PSK key exchange modes list length", %TLS_PSK_KEY_EXCHANGE_MODE],
            RX          => [qw(len2 val1)],
            RX_TEXT     => ["length", %TLS_PSK_KEY_EXCHANGE_MODE],
            RECOMMENDED    => q(Y),
            TLS13             => [qw(CH)],
            RFC                  => [qw(8446)],
            DEFAULT                 => [ 
                                         [ 0x00,    # psk_ke,Y,[RFC8446]
                                           0x01,    # psk_dhe_ke,Y,[RFC8446]
                                         ],
                                       ],
            CHECK                      => q(VALUE),
            COMMENT                       => q[],
    },
#  46    Unassigned
certificate_authorities    => {
            ID    => 47,
            CH        => [qw(len2 raw)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(Y),
            TLS13                => [qw(CH CR)],
            RFC                        => [qw(8446)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q[],
    },
oid_filters    => {
            ID    => 48,
            CH        => [qw(len2 raw)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(Y),
            TLS13                => [qw(CR)],
            RFC                        => [qw(8446)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q[],
    },
post_handshake_auth    => {
            ID    => 49,
            CH        => [qw(len2 raw)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(Y),
            TLS13                => [qw(CH)],
            RFC                        => [qw(8446)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q[],
    },
signature_algorithms_cert => {
            ID    => 50,
            CH        => [qw(len2 raw)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(Y),
            TLS13                => [qw(CH CR)],
            RFC                        => [qw(8446)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q[],
    },
key_share        => {                                               # MUST be the last extension if used
            ID    => 51,                                            # Hex: 0x0033
            CH        => [qw(len2 len2 sequence val2 size2 raw)],   # Example:  0x0026 0x0024 0x001d 0x0020 <raw32>
            CH_TEXT   => ["length", "client key share list length", "key share element", \%TLS_SUPPORTED_GROUPS, "key exchange length", "key exchange"],
            RX            => [qw(len2 val2 size2 raw)],
            RX_TEXT       => ["length", \%TLS_SUPPORTED_GROUPS, "key exchange length", "key exchange"],
            RECOMMENDED        => q(Y),
            TLS13                => [qw(CH SH HRR)],
            RFC                        => [qw(8446)],
            DEFAULT                        => [ 
                                                [                   # 1st sequence element
                                                  0x001d,           # Group x25519
                                                  "\x01\x02\x03\x04\x05\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20", # Key Exchange
                                                ],
                                                [                   # second sequence element
                                                  0x0017,           # Group secp256r1
                                                  "\x21\x22\x23\x24\x25\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40"
                                                  . "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F\x60\x61", # Key Exchange
                                                ],
                                              ],
            CHECK                            => q(VALUE),
            COMMENT                                => q[],
    },
transparency_info => {
            ID    => 52,
            CH        => [qw(len2 raw)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(Y),
            TLS13                => [qw(CH CR CT)],
            RFC                        => [qw(draft-ietf-trans-6962-bis)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q[],
    },
#  53-65279    Unassigned
supports_npn    => {
            ID    => 13172,                         # Hex:      0x3374
#            CH        => [qw(len2 len1 raw len1 raw)],# Example:  0x0000 (no data)
            CH        => [qw(len2 len1 raw)],# Example:  0x0000 (no data)
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(?),
            TLS13                => [qw(?)],
            RFC                        => [qw(draft-agl-tls-nextprotoneg-04)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q[],
    },
# NOT official:
channel_id_old    => {
            ID    => 33031,
            CH        => [qw(len2 val4 val4 val4 val4)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(N),
            TLS13                => [qw(?)],
            RFC                        => [qw(draft-balfanz-tls-channelid-00)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q(channel_id_old=0x754F),
    },
# NOT official:
channel_id    => {
            ID    => 33032,
            CH        => [qw(len2 val4 val4 val4 val4)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(N),
            TLS13                => [qw(?)],
            RFC                        => [qw(draft-balfanz-tls-channelid-01)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q(channel_id=0x7550),
    },
# NOT official:
opaque_prf_input    => {
            ID    => 38183,
            CH        => [qw(len2 raw)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(N!),
            TLS13                => [qw(?)],
            RFC                        => [qw(draft-rescorla-tls-opaque-prf-input-00)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q(NSA; December 13, 2006; DO NOT USE!! https://www.openssl.org/news/changelog.html#x44 [29 Mar 2010]: opaque_prf_input=0x9527),
    },
tack    => {
            ID    => 62208,
            CH        => [qw(len2 raw)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(?),
            TLS13                => [qw(?)],
            RFC                        => [qw(draft-perrin-tls-tack-02)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q(January 07, 2013, expired July 11, 2013),
    },

#
private_65280    => {
            ID    => 65280,
            CH        => [qw(len2 raw)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(?),
            TLS13                => [qw(?)],
            RFC                        => [qw(8446)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q(for private use),
    },
renegotiation_info    => {
            ID    => 65281,                             # Hex: 0xff01
            CH        => [qw(len2 len1 raw)],             # Example: 0x0001 0x00
            CH_TEXT   => ["length", "renegotiated connection data length", "client verify data"],
            RX            => [qw(len2 len1 raw)],
            RX_TEXT       => ["length", "renegotiated connection data length", "server verify data"],
            RECOMMENDED        => q(Y),
            TLS13                => [qw(-)],
            RFC                        => [qw(5746)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q(Default value is empty => len1=0x00 => len2=0x0001),
    },

#65282-65535 Reserved for Private Use
private_65282   => {
            ID    => 65282,
            CH        => [qw(len2 raw)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(?),
            TLS13                => [qw(?)],
            RFC                        => [qw(8446)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q(for private use),
    },
private_65283    => {
            ID    => 65283,
            CH        => [qw(len2 raw)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(?),
            TLS13                => [qw(?)],
            RFC                        => [qw(8446)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q(for private use),
    },
private_65284    => {
            ID    => 65284,
            CH        => [qw(len2 raw)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(?),
            TLS13                => [qw(?)],
            RFC                        => [qw(8446)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q(for private use),
    },
private_65285    => {
            ID    => 65285,
            CH        => [qw(len2 raw)],
            RX            => [qw(len2 raw)],
            RECOMMENDED        => q(?),
            TLS13                => [qw(?)],
            RFC                        => [qw(8446)],
            DEFAULT                        => [],
            CHECK                            => q(VALUE),
            COMMENT                                => q(for private use),
    },
); # %TLS_EXTENSIONS

# Compile a reverse Hash to %TLS_EXTENSIONS by the IDs
our %TLS_ID_TO_EXTENSIONS = (
    #----+-------------------------------------------------------------------------
    # ID        extension_name
    #----+-------------------------------------------------------------------------

 FORMAT => [    "Extension '%s':",                                   ],# define format for printf
);

foreach my $key (keys %TLS_EXTENSIONS) {                        # compile a reverse hash for extension IDs
    $TLS_ID_TO_EXTENSIONS{$TLS_EXTENSIONS{$key}{ID}}[0] = $key; # store it in the fiorstv element of an array for compatibility reasons with hashes above, e.g. %TLS_SUPPORTED_GROUPS
}


my %tls_extensions__text = ( # TODO: this information needs to be added to %tls_extensions above
    'extension' => {            # TLS extensions
        '00000'     => "renegotiation info length",     # 0x0000 ??
        '00001'     => "renegotiation length",          # 0x0001 ??
        '00009'     => "cert type",                     # 0x0009 ??
        '00010'     => "elliptic curves",               # 0x000a length=4
        '00011'     => "EC point formats",              # 0x000b length=2
        '00012'     => "SRP",                           # 0x000c ??
        '00015'     => "heartbeat",                     # 0x000f length=1
        '00035'     => "session ticket",                # 0x0023 length=0
        '13172'     => "next protocol",     # aka NPN   # 0x3374 length=NNN
        '62208'     => "TACK",                          # 0xf300 ??
        '65281'     => "renegotiation info",            # 0xff01 length=1
    },
); # %tls_extensions__text

our %tls_signature_algorithms = (
    #----------+--------------------+-----------------------
    # ID        name                 comment
    #----------+--------------------+-----------------------
                                    # Legacy algorithms
    0x0201  => "rsa_pkcs1_sha1",
    0x0203  => "ecdsa_sha1",
                                    # RSASSA-PKCS1-v1_5 algorithms
    0x0401  => "rsa_pkcs1_sha256",
    0x0501  => "rsa_pkcs1_sha384",
    0x0601  => "rsa_pkcs1_sha512",
                                    # ECDSA algorithms
    0x0403  => "ecdsa_secp256r1_sha256",
    0x0503  => "ecdsa_secp384r1_sha384",
    0x0603  => "ecdsa_secp521r1_sha512",
                                    # RSASSA-PSS algorithms with public key OID rsaEncryption
    0x0804  => "rsa_pss_rsae_sha256",
    0x0805  => "rsa_pss_rsae_sha384",
    0x0806  => "rsa_pss_rsae_sha512",
                                    # EdDSA algorithms
    0x0807  => "ed25519",
    0x0808  => "ed448",
                                    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    0x0809  => "rsa_pss_pss_sha256",
    0x080a  => "rsa_pss_pss_sha384",
    0x080b  => "rsa_pss_pss_sha512",
                                    # Reserved Code Points
    #0x0000..0x0200 => "obsolete_RESERVED",
    0x0202  => "dsa_sha1_RESERVED",
    #0x0204..0x0400 => "obsolete_RESERVED",
    0x0402  => "dsa_sha256_RESERVED",
    #0x0404..0x0500 => "obsolete_RESERVED",
    0x0502  => "dsa_sha384_RESERVED",
    #0x0504..0x0600 => "obsolete_RESERVED",
    0x0602  => "dsa_sha512_RESERVED",
    #0x0604..0x06FF => "obsolete_RESERVED",
    #0xFE00..0xFFFF => "private_use",
    0xFFFF  => "private_use",
    #----------+--------------------+-----------------------
); # %tls_signature_algorithms

our %tls_supported_groups = (   # RFC 8446
    #----------+--------------------+-----------------------
    # ID        name                 comment
    #----------+--------------------+-----------------------
    0x0001  => "obsolete_RESERVED", # 0x0001..0x0016 => "obsolete_RESERVED",
    0x0017  => "secp256r1",         # Elliptic Curve Groups (ECDHE)
    0x0018  => "secp384r1",         # 
    0x0019  => "secp521r1",         # 
    0x001A  => "obsolete_RESERVED", #0x001A..0x001C => "obsolete_RESERVED",
    0x001D  => "x25519",            #
    0x001E  => "x448",              #
    0x0100  => "ffdhe2048",         # Finite Field Groups (DHE)
    0x0101  => "ffdhe3072",         # 
    0x0102  => "ffdhe4096",         # 
    0x0103  => "ffdhe6144",         # 
    0x0104  => "ffdhe8192",         # 
                                    # Reserved Code Points
    0x01FC  => "ffdhe_private_use", # 0x01FC..0x01FF => "ffdhe_private_use",
    0xFE00  => "ecdhe_private_use", # 0xFE00..0xFEFF => "ecdhe_private_use",
    0xFF01  => "obsolete_RESERVED_ff01",
    0xFF02  => "obsolete_RESERVED_ff02",
    0xFFFF  => "FFFF",
    #----+--------------------------+-----------------------
); # %tls_supported_groups

our %ec_point_formats = (       # RFC 4492
    # http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
    #--------+-----------------------------+----+---+--------------------------
    # ID          name                      RFC  DTLS other names
    #--------+-----------------------------+----+---+--------------------------
        0 => [qw( uncompressed              4492  Y   )],
        1 => [qw( ansiX962_compressed_prime 4492  Y   )],
        2 => [qw( ansiX962_compressed_char2 4492  Y   )],
      248 => [qw( reserved_248              4492  N   )],
      249 => [qw( reserved_249              4492  N   )],
      250 => [qw( reserved_250              4492  N   )],
      251 => [qw( reserved_251              4492  N   )],
      252 => [qw( reserved_252              4492  N   )],
      253 => [qw( reserved_253              4492  N   )],
      254 => [qw( reserved_254              4492  N   )],
      255 => [qw( reserved_255              4492  N   )],
    #----+-----------------------------+----+---+------------------------------
); # ec_point_formats

# Torsten: %ECCURVE_TYPE
our %ec_curve_types = ( # RFC 4492
    # http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
    #--------+-----------------------------+----+---+--------------------------
    # ID          name                      RFC  DTLS other names
    #--------+-----------------------------+----+---+--------------------------
        0 => [qw( unassigned                4492  N   )],
        1 => [qw( explicit_prime            4492  Y   )],
        2 => [qw( explicit_char2            4492  Y   )],
        3 => [qw( named_curve               4492  Y   )],
      248 => [qw( reserved_248              4492  N   )],
      249 => [qw( reserved_249              4492  N   )],
      250 => [qw( reserved_250              4492  N   )],
      251 => [qw( reserved_251              4492  N   )],
      252 => [qw( reserved_252              4492  N   )],
      253 => [qw( reserved_253              4492  N   )],
      254 => [qw( reserved_254              4492  N   )],
      255 => [qw( reserved_255              4492  N   )],
    #--------+-----------------------------+----+---+--------------------------
); # ec_curve_types

# EX: incl. OIDs:
our %tls_curves = (
    #----+-------------------------------------+----+--+-------+---+-------------------------
    # ID      name                              RFC DTLS NIST  bits OID
    #----+-------------------------------------+----+--+-------+---+------------------------
    0 => [qw( unassigned                        IANA  -      -    0                      )],
    1 => [qw( sect163k1                         4492  Y  K-163  163 1.3.132.0.1          )],
    2 => [qw( sect163r1                         4492  Y      -  163 1.3.132.0.2          )],
    3 => [qw( sect163r2                         4492  Y  B-163  163 1.3.132.0.15         )],
    4 => [qw( sect193r1                         4492  Y      -  193 1.3.132.0.24         )],
    5 => [qw( sect193r2                         4492  Y      -  193 1.3.132.0.25         )],
    6 => [qw( sect233k1                         4492  Y  K-233  233 1.3.132.0.26         )],
    7 => [qw( sect233r1                         4492  Y  B-233  233 1.3.132.0.27         )],
    8 => [qw( sect239k1                         4492  Y      -  239 1.3.132.0.3          )],
    9 => [qw( sect283k1                         4492  Y  K-283  283 1.3.132.0.16         )],
   10 => [qw( sect283r1                         4492  Y  B-283  283 1.3.132.0.17         )],
   11 => [qw( sect409k1                         4492  Y  K-409  409 1.3.132.0.36         )],
   12 => [qw( sect409r1                         4492  Y  B-409  409 1.3.132.0.37         )],
   13 => [qw( sect571k1                         4492  Y  K-571  571 1.3.132.0.38         )],
   14 => [qw( sect571r1                         4492  Y  B-571  571 1.3.132.0.39         )],
   15 => [qw( secp160k1                         4492  Y      -  160 1.3.132.0.9          )],
   16 => [qw( secp160r1                         4492  Y      -  160 1.3.132.0.8          )],
   17 => [qw( secp160r2                         4492  Y      -  160 1.3.132.0.30         )],
   18 => [qw( secp192k1                         4492  Y      -  192 1.3.132.0.31         )], # ANSI X9.62 prime192v1, NIST P-192,
   19 => [qw( secp192r1                         4492  Y  P-192  192 1.2.840.10045.3.1.1  )], # ANSI X9.62 prime192v1
   20 => [qw( secp224k1                         4492  Y       - 224 1.3.132.0.32         )],
   21 => [qw( secp224r1                         4492  Y  P-224  224 1.3.132.0.33         )],
   22 => [qw( secp256k1                         4492  Y  P-256  256 1.3.132.0.10         )],
   23 => [qw( secp256r1                         4492  Y  P-256  256 1.2.840.10045.3.1.7  )], # ANSI X9.62 prime256v1
   24 => [qw( secp384r1                         4492  Y  P-384  384 1.3.132.0.34         )],
   25 => [qw( secp521r1                         4492  Y  P-521  521 1.3.132.0.35         )],
   26 => [qw( brainpoolP256r1                   7027  Y      -  256 1.3.36.3.3.2.8.1.1.7 )],
   27 => [qw( brainpoolP384r1                   7027  Y      -  384 1.3.36.3.3.2.8.1.1.11)],
   28 => [qw( brainpoolP512r1                   7027  Y      -  512 1.3.36.3.3.2.8.1.1.13)],
#  28 => [qw( brainpoolP521r1                   7027  Y      -  521 1.3.36.3.3.2.8.1.1.13)], # ACHTUNG: in manchen Beschreibungen dieser falsche String
   29 => [qw( ecdh_x25519                       4492bis Y    -  225                      )], # [draft-ietf-tls-tls][draft-ietf-tls-rfc4492bis])], #TEMPORARY-registered_2016-02-29,_expires 2017-03-01,
   30 => [qw( ecdh_x448                         4492bis Y    -  448                      )], # -"-
#  31 => [qw( eddsa_ed25519                     4492bis Y    -  448 1.3.101.100          )], # Signature curves, see https://tools.ietf.org/html/draft-ietf-tls-tls13-11
#  32 => [qw( eddsa_ed448                       4492bis Y    -  448 1.3.101.101          )], # -"-

  256 => [qw( ffdhe2048                         ietf-tls-negotiated-ff-dhe-10 Y - 2048   )],
  257 => [qw( ffdhe3072                         ietf-tls-negotiated-ff-dhe-10 Y - 3072   )],
  258 => [qw( ffdhe4096                         ietf-tls-negotiated-ff-dhe-10 Y - 4096   )],
  259 => [qw( ffdhe6144                         ietf-tls-negotiated-ff-dhe-10 Y - 6144   )],
  260 => [qw( ffdhe8192                         ietf-tls-negotiated-ff-dhe-10 Y - 8192   )],
65281 => [qw( arbitrary_explicit_prime_curves   4492  Y      -    ?                      )], # 0xFF01
65282 => [qw( arbitrary_explicit_char2_curves   4492  Y      -    ?                      )], # 0xFF02
    #----+-------------------------------------+----+--+-------+---+------------------------
    # following not from IANA
    # ID      name                              RFC DTLS NIST  bits OID
    #----+-------------------------------------+----+--+-------+---+------------------------
42001 => [qw( Curve3617                         ????  N      -   -1                      )],
42002 => [qw( secp112r1                         ????  N      -   -1 1.3.132.0.6          )],
42003 => [qw( secp112r2                         ????  N      -   -1 1.3.132.0.7          )],
42004 => [qw( secp113r1                         ????  N      -   -1 1.3.132.0.4          )],
42005 => [qw( secp113r2                         ????  N      -   -1 1.3.132.0.5          )],
42006 => [qw( secp131r1                         ????  N      -   -1 1.3.132.0.22         )],
42007 => [qw( secp131r2                         ????  N      -   -1 1.3.132.0.23         )],
42008 => [qw( secp128r1                         ????  N      -   -1 1.3.132.0.28         )],
42009 => [qw( secp128r2                         ????  N      -   -1 1.3.132.0.29         )],
42011 => [qw( ed25519                           ????  N Ed25519  -1 1.3.6.1.4.1.11591.15.1)], # PGP
42012 => [qw( brainpoolp160r1                   ????  N      -   -1 1.3.36.3.3.2.8.1.1.1 )],
42013 => [qw( brainpoolp192r1                   ????  N      -   -1 1.3.36.3.3.2.8.1.1.3 )],
42014 => [qw( brainpoolp224r1                   ????  N      -   -1 1.3.36.3.3.2.8.1.1.5 )],
42015 => [qw( brainpoolp320r1                   ????  N      -   -1 1.3.36.3.3.2.8.1.1.9 )],
42016 => [qw( brainpoolp512r1                   ????  N      -   -1 1.3.36.3.3.2.8.1.1.13)], # same as brainpoolP521r1
42020 => [qw( GOST2001-test                     ????  N      -   -1 1.2.643.2.2.35.0     )],
42021 => [qw( GOST2001-CryptoPro-A              ????  N      -   -1 1.2.643.2.2.35.1     )],
42022 => [qw( GOST2001-CryptoPro-B              ????  N      -   -1 1.2.643.2.2.35.2     )],
42023 => [qw( GOST2001-CryptoPro-C              ????  N      -   -1 1.2.643.2.2.35.3     )],
42024 => [qw( GOST2001-CryptoPro-A              ????  N      -   -1                      )], # GOST2001-CryptoPro-XchA
42025 => [qw( GOST2001-CryptoPro-C              ????  N      -   -1                      )], # GOST2001-CryptoPro-XchB
42026 => [qw( GOST2001-CryptoPro-A              ????  N      -   -1 1.2.643.2.2.36.0     )],
42027 => [qw( GOST2001-CryptoPro-C              ????  N      -   -1 1.2.643.2.2.36.1     )],
42031 => [qw( X9.62 prime192v2                  ????  N      -   -1 1.2.840.10045.3.1.2  )],
42032 => [qw( X9.62 prime192v3                  ????  N      -   -1 1.2.840.10045.3.1.3  )],
42033 => [qw( X9.62 prime239v1                  ????  N      -   -1 1.2.840.10045.3.1.4  )],
42034 => [qw( X9.62 prime239v2                  ????  N      -   -1 1.2.840.10045.3.1.5  )],
42035 => [qw( X9.62 prime239v3                  ????  N      -   -1 1.2.840.10045.3.1.6  )],
42041 => [qw( X9.62 c2tnb191v1                  ????  N      -   -1 1.2.840.10045.3.0.5  )],
42042 => [qw( X9.62 c2tnb191v2                  ????  N      -   -1 1.2.840.10045.3.0.6  )],
42043 => [qw( X9.62 c2tnb191v3                  ????  N      -   -1 1.2.840.10045.3.0.7  )],
42044 => [qw( X9.62 c2tnb239v1                  ????  N      -   -1 1.2.840.10045.3.0.11 )],
42045 => [qw( X9.62 c2tnb239v2                  ????  N      -   -1 1.2.840.10045.3.0.12 )],
42046 => [qw( X9.62 c2tnb239v3                  ????  N      -   -1 1.2.840.10045.3.0.13 )],
42047 => [qw( X9.62 c2tnb359v1                  ????  N      -   -1 1.2.840.10045.3.0.18 )],
42048 => [qw( X9.62 c2tnb431r1                  ????  N      -   -1 1.2.840.10045.3.0.20 )],
# fobidden curves
42061 => [qw( X9.62 c2pnb163v1                  ????  N      -   -1 1.2.840.10045.3.0.1  )],
42062 => [qw( X9.62 c2pnb163v2                  ????  N      -   -1 1.2.840.10045.3.0.2  )],
42063 => [qw( X9.62 c2pnb163v3                  ????  N      -   -1 1.2.840.10045.3.0.3  )],
42064 => [qw( X9.62 c2pnb176w1                  ????  N      -   -1 1.2.840.10045.3.0.4  )],
42065 => [qw( X9.62 c2pnb208w1                  ????  N      -   -1 1.2.840.10045.3.0.10 )],
42066 => [qw( X9.62 c2pnb272w1                  ????  N      -   -1 1.2.840.10045.3.0.16 )],
42067 => [qw( X9.62 c2pnb304w1                  ????  N      -   -1 1.2.840.10045.3.0.18 )],
42068 => [qw( X9.62 c2pnb368w1                  ????  N      -   -1 1.2.840.10045.3.0.19 )],
# unknown curves
42101 => [qw( prime192v1                        ????  N      -   92 )], # X9.62/SECG curve over a 192 bit prime field
42101 => [qw( prime192v2                        ????  N      -   92 )], # X9.62 curve over a 192 bit prime field
42101 => [qw( prime192v3                        ????  N      -   92 )], # X9.62 curve over a 192 bit prime field
42101 => [qw( prime239v1                        ????  N      -   39 )], # X9.62 curve over a 239 bit prime field
42101 => [qw( prime239v2                        ????  N      -   39 )], # X9.62 curve over a 239 bit prime field
42101 => [qw( prime239v3                        ????  N      -   39 )], # X9.62 curve over a 239 bit prime field
42101 => [qw( prime256v1                        ????  N      -   56 )], # X9.62/SECG curve over a 256 bit prime field
42101 => [qw( wap-wsg-idm-ecid-wtls1            ????  N      -  113 )], # WTLS curve over a 113 bit binary field
42101 => [qw( wap-wsg-idm-ecid-wtls3            ????  N      -  163 )], # NIST/SECG/WTLS curve over a 163 bit binary field
42101 => [qw( wap-wsg-idm-ecid-wtls4            ????  N      -  112 )], # SECG curve over a 113 bit binary field
42101 => [qw( wap-wsg-idm-ecid-wtls5            ????  N      -  163 )], # X9.62 curve over a 163 bit binary field
42101 => [qw( wap-wsg-idm-ecid-wtls6            ????  N      -  112 )], # SECG/WTLS curve over a 112 bit prime field
42101 => [qw( wap-wsg-idm-ecid-wtls7            ????  N      -  160 )], # SECG/WTLS curve over a 160 bit prime field
42101 => [qw( wap-wsg-idm-ecid-wtls8            ????  N      -  112 )], # WTLS curve over a 112 bit prime field
42101 => [qw( wap-wsg-idm-ecid-wtls9            ????  N      -  160 )], # WTLS curve over a 160 bit prime field
42101 => [qw( wap-wsg-idm-ecid-wtls10           ????  N      -  233 )], # NIST/SECG/WTLS curve over a 233 bit binary field
42101 => [qw( wap-wsg-idm-ecid-wtls11           ????  N      -  233 )], # NIST/SECG/WTLS curve over a 233 bit binary field
42101 => [qw( wap-wsg-idm-ecid-wtls12           ????  N      -  224 )], # WTLS curvs over a 224 bit prime field
42101 => [qw( Oakley-EC2N-3                     ????  N      -   55 )], # IPSec/IKE/Oakley curve #3 over a 155 bit binary field.
42101 => [qw( Oakley-EC2N-4                     ????  N      -   85 )], # IPSec/IKE/Oakley curve #4 over a 185 bit binary field
    #----+-------------------------------------+----+--+-------+---+------------------------
# unknown curves
41147 => [qw( Curve1147                         ????  N      -   -1 )], # http://www..wikipedia.org/wiki/Comparison_of_TLS_implementations
41187 => [qw( Curve511157                       ????  N      -   -1 )], # -"- ; aka M511
41417 => [qw( Curve41417                        ????  N      -   -1 )], # -"- ; aka Curve3617
42213 => [qw( Curve2213                         ????  N      -   -1 )], # -"- ; aka M221
42448 => [qw( Curve448                          ????  N      -   -1 )], # -"- ; aka Ed448-Goldilocks, aka ecdh_x448?
42519 => [qw( X25519                            ????  N      -   -1 )], # -"- ; aka ecdh_x25519?
42222 => [qw( E222                              ????  N      -   -1 )], # -"-
42382 => [qw( E382                              ????  N      -   -1 )], # -"-
42383 => [qw( E383                              ????  N      -   -1 )], # -"-
42521 => [qw( E521                              ????  N      -   -1 )], # -"-
42147 => [qw( GOST28147-89                      ????  N      -   -1 )], # -"-
42147 => [qw( GOST-R34.11-94                    ????  N      -   -1 )], # -"-
    #----+-------------------------------------+----+--+-------+---+------------------------
65165 => [qw( CurveCECPQ1                       ????  N      -   -1 )], # -"- ;
# unknown curves
#     => [qw( numsp256d1 )],
#     => [qw( numsp256t1 )],
#     => [qw( Curve25519 )],
); # %tls_curves

################
# FIPS-186-2 FIPS-186-3
#
# Aliases: P-256 -- NIST P-256 -- NIST-P256 -- NIST-256 -- secp256r1 -- prime256v1
#
# order_for_NIST_curves_by_ID = 23, 1, 3, 19, 21, 6, 7, 9, 10, 24, 11, 12, 25, 13, 14
################

our %data_oid   = (     # list of texts for some OIDs
        # TODO: nothing YET IMPLEMENTED except for EV
        # TODO: generate this table using Net::SSLeay functions like:
        #   Net::SSLeay::OBJ_nid2ln(),  Net::SSLeay::OBJ_ln2nid()
        #   Net::SSLeay::OBJ_nid2sn(),  Net::SSLeay::OBJ_sn2nid(),
        #   Net::SSLeay::OBJ_nid2obj(), Net::SSLeay::OBJ_obj2nid(),
        #   Net::SSLeay::OBJ_txt2obj(), Net::SSLeay::OBJ_txt2nid(),
        #   Net::SSLeay::OBJ_obj2txt(),
        # all constants and values are defined in openssl/crypto/objects/obj_dat.h
        #   print "nid ". Net::SSLeay::OBJ_txt2nid("CN"); # --> 13
        #   print "Nam ". Net::SSLeay::OBJ_obj2txt( Net::SSLeay::OBJ_txt2obj("1.3.6.1.5.5.7.3.3"), 0); # --> Code Signing
        #   print "nam ". Net::SSLeay::OBJ_obj2txt( Net::SSLeay::OBJ_txt2obj("CN"), 0); # --> commonName
        #   print "oid ". Net::SSLeay::OBJ_obj2txt( Net::SSLeay::OBJ_txt2obj("CN"), 1); # --> 2.5.4.3
        #   print "OID ". Net::SSLeay::OBJ_obj2txt( Net::SSLeay::OBJ_nid2obj( 13 ), 1); # --> 2.5.4.3
        # we should use NIDs to generate the hash, as all other strings are
        # case sensitive. get NIDs with:
        #   grep NID_ openssl/crypto/objects/objects.h | awk '{print $3}' | sort -n
        # so we can loop from 0..180 (or 300 if checks are possible)
        # see also: http://www.zytrax.com/books/ldap/apa/oid.html
        #
        # wir koennen dann einen Parser fuer OIDs bauen:
        #   loop ueber OID und dabei immer .N vom Ende wegnehmen und Rest mit OBJ_obj2txt() ausgeben
        #   # 1.3.6.1.4 -->  "" . identified-organization . dot . iana . Private
        #   # 2.5.29.32 -->  "" . directory services (X.500) . id-ce . X509v3 Certificate Policies

#   '1.3.6.1'                   => {iso(1) org(3) dod(6) iana(1)}
    '1.3.6.1'                   => {'txt' => "Internet OID"},
#   '1.3.6.1.5.5.7.1'           => {'txt' => "Private Extensions"},
    '1.3.6.1.5.5.7.1.1'         => {'txt' => "Authority Information Access"}, # authorityInfoAccess
    '1.3.6.1.5.5.7.1.12'        => {'txt' => $STR{UNDEF}},
    '1.3.6.1.5.5.7.1.14'        => {'txt' => "Proxy Certification Information"},
    '1.3.6.1.5.5.7.1.24'        => {'txt' => "id-pe-tlsfeature"},
    '1.3.6.1.5.5.7.3.1'         => {'txt' => "Server Authentication"},
    '1.3.6.1.5.5.7.3.2'         => {'txt' => "Client Authentication"},
    '1.3.6.1.5.5.7.3.3'         => {'txt' => "Code Signing"},
    '1.3.6.1.5.5.7.3.4'         => {'txt' => "Email Protection"},
    '1.3.6.1.5.5.7.3.5'         => {'txt' => "IPSec end system"},
    '1.3.6.1.5.5.7.3.6'         => {'txt' => "IPSec tunnel"},
    '1.3.6.1.5.5.7.3.7'         => {'txt' => "IPSec user"},
    '1.3.6.1.5.5.7.3.8'         => {'txt' => "Timestamping"},
    '1.3.6.1.5.5.7.48.1'        => {'txt' => "ocsp"},
    '1.3.6.1.5.5.7.48.2'        => {'txt' => "caIssuer"},
    '1.3.6.1.4.1.11129.2.5.1'   => {'txt' => $STR{UNDEF}},  # Certificate Policy?
    '1.3.6.1.4.1.14370.1.6'     => {'txt' => $STR{UNDEF}},  # Certificate Policy?
    '1.3.6.1.4.1.311.10.3.3'    => {'txt' => "Microsoft Server Gated Crypto"},
    '1.3.6.1.4.1.311.10.11'     => {'txt' => "Microsoft Server: EV additional Attributes"},
    '1.3.6.1.4.1.311.10.11.11'  => {'txt' => "Microsoft Server: EV ??friendly name??"},
    '1.3.6.1.4.1.311.10.11.83'  => {'txt' => "Microsoft Server: EV ??root program??"},
    '1.3.6.1.4.1.4146.1.10'     => {'txt' => $STR{UNDEF}},  # Certificate Policy?
    '1.3.6.1.5.5.7.8.7'         => {'txt' => "otherName"},
    '2.16.840.1.113730.4.1'     => {'txt' => "Netscape SGC"},
    '1.2.840.113549.1.1.1'      => {'txt' => "SubjectPublicKeyInfo"}, # ???
    '1.2.840.113549.1.1.5'      => {'txt' => "SignatureAlgorithm"},
#   '2.5.29'                    => {'txt' => "Standard Extensions according RFC 5280"},
    # EV: OIDs used in EV Certificates
    '2.5.4.10'                  => {'txt' => "EV Certificate: subject:organizationName"},
    '2.5.4.11'                  => {'txt' => "EV Certificate: subject:organizationalUnitName"},
    '2.5.4.15'                  => {'txt' => "EV Certificate: subject:businessCategory"},
    '2.5.4.3'                   => {'txt' => "EV Certificate: subject:commonName"}, # or SubjectAlternativeName:dNSName
    # EV: Jurisdiction of Incorporation or Registration
    '1.3.6.1.4.1.311.60.2.1.1'  => {'txt' => "EV Certificate: subject:jurisdictionOfIncorporationLocalityName"},
    '1.3.6.1.4.1.311.60.2.1.2'  => {'txt' => "EV Certificate: subject:jurisdictionOfIncorporationStateOrProvinceName"},
    '1.3.6.1.4.1.311.60.2.1.3'  => {'txt' => "EV Certificate: subject:jurisdictionOfIncorporationCountryName"},
    '2.5.4.5'                   => {'txt' => "EV Certificate: subject:serialNumber"},
    # EV: Physical Address of Place of Business
    '2.5.4.6'                   => {'txt' => "EV Certificate: subject:countryName"},
    '2.5.4.7'                   => {'txt' => "EV Certificate: subject:localityName"},
    '2.5.4.8'                   => {'txt' => "EV Certificate: subject:stateOrProvinceName"},
    '2.5.4.9'                   => {'txt' => "EV Certificate: subject:streetAddress"},
    '2.5.4.17'                  => {'txt' => "EV Certificate: subject:postalCode"},
    # EV: Compliance with European Union Qualified Certificates Standard In addition, RFC 3739
    '1.3.6.1.4.1.311.60.2.1'    => {'txt' => "EV Certificate: qcStatements:qcStatement:statementId"},
    # EV: others
    '1.3.6.1.4.1.311.60.1.1'    => {'txt' => "EV Certificate: ??fake root??"},
    '2.5.29.32.0'               => {'txt' => "EV Certificate: subject:anyPolicy"},
    '2.5.29.35'                 => {'txt' => "EV Certificate: subject:authorityKeyIdentifier"}, # Authority key id
    '2.5.29.37'                 => {'txt' => "EV Certificate: subject:extendedKeyUsage"}, # Extended key usage
    '0.9.2342.19200300.100.1.25'=> {'txt' => "EV Certificate: subject:domainComponent"},
    # others
    '2.5.4.4'                   => {'txt' => "subject:surname"},
    '2.5.4.12'                  => {'txt' => "subject:title"},
    '2.5.4.41'                  => {'txt' => "subject:name"},
    '2.5.4.42'                  => {'txt' => "subject:givenName"},
    '2.5.4.43'                  => {'txt' => "subject:intials"},
    '2.5.4.44'                  => {'txt' => "subject:generationQualifier"},
    '2.5.4.46'                  => {'txt' => "subject:dnQualifier"},
    '2.5.29.14'                 => {'txt' => "subject:subjectKeyIdentifier"}, # Subject key id
    '2.5.29.15'                 => {'txt' => "subject:keyUsage"},             # Key usage
    '2.5.29.17'                 => {'txt' => "subject:subjectAlternateName"}, # Subject alternative name
    '2.5.29.19'                 => {'txt' => "subject:basicConstraints"},     # Basic constraints
    '2.5.29.31'                 => {'txt' => "subject:crlDistributionPoints"},# CRL distribution points
    '2.5.29.32'                 => {'txt' => "subject:certificatePolicies"},  # Certificate Policies
    '2.5.29.37'                 => {'txt' => "subject:extendedKeyUsage"},     # Extended key usage
    '2.16.840.1.113733.1.7.23.6'=> {'txt' => $STR{UNDEF}},  # Certificate Policy?
    '2.16.840.1.113733.1.7.48.1'=> {'txt' => $STR{UNDEF}},  #  ''
    '2.16.840.1.113733.1.7.54'  => {'txt' => $STR{UNDEF}},  #  ''
    '0.9.2342.19200300.100.1.3' => {'txt' => "subject:mail"},
    # TODO: see http://oidref.com/
    #'2.16.840.1.114028.10.1.2'  => {'txt' => "Entrust Extended Validation (EV) Certification Practice Statement (CPS)"},
    #'2.16.840.1.114412.1.3.0.2' => {'txt' => "DigiCert Extended Validation (EV) Certification Practice Statement (CPS) v. 1.0.3"},
    #'2.16.840.1.114412.2.1'     => {'txt' => "DigiCert Extended Validation (EV) Certification Practice Statement (CPS) v. 1.0.3"},
    #'2.16.578.1.26.1.3.3'       => {'txt' => ""},
    #'1.3.6.1.4.1.17326.10.14.2.1.2' => {'txt' => "Camerfirma Certification Practice Statement (CPS) v3.2.3"},
    #'1.3.6.1.4.1.17326.10.8.12.1.2' => {'txt' => "Camerfirma Certification Practice Statement (CPS) v3.2.3"},
    #'1.3.6.1.4.1.13177.10.1.3.10'   => {'txt' => "SSL SECURE WEB SERVER CERTIFICATES"},
); # %data_oid

our %cfg = (    # main data structure for configuration
    'mename'        => "O-Saft ", # my name pretty printed
    'need_netdns'   => 0,       # used for better error message handling only
    'need_timelocal'=> 0,       # -"-
    'need_netinfo'  => 1,       # 0: do not load Net::SSLinfo
    # following initialised in _ocfg_init()
    'me'            => "",      # set in main
    'ARG0'          => "",
    'ARGV'          => [],      # arguments passed on command-line
    'RC-ARGV'       => [],      # arguments read from RC-FILE (set in caller)
    'RC-FILE'       => "",      # our RC-FILE, search in pwd only!
    # following should be in %text, but as %cfg is available everywhere,
    # it's better defined here and initialised in _ocfg_init()
    'prefix_trace'  => "",      # prefix string used in trace   messages
    'prefix_verbose'=> "",      # prefix string used in verbose messages

   #--------------+-------------+----------------------------------------------
    'dirs' => { # list of directories used for the tool, in ./ usually
        'lib'   =>  "lib",      # own modules
        'doc'   =>  "doc",      # additional documentation
        'usr'   =>  "usr",      # additional tools
        'test'  =>  "t",        # Canything for functional and quality tests
    }, # dirs

   # config. key        default   description
   #------------------+---------+----------------------------------------------
    'try'           => 0,       # 1: do not execute openssl, just show
    'exec'          => 0,       # 1: if +exec command used
    'trace'         => 0,       # 1: trace yeast, 2=trace Net::SSLeay and Net::SSLinfo also
    'traceME'       => 0,       # 1: trace yeast only, but no modules
                                # -1: trace modules only, but not yeast
    'time0'         => 0,       # current time, must be set in main
    'linux_debug'   => 0,       # passed to Net::SSLeay::linux_debug
    'verbose'       => 0,       # used for --v
    'v_cipher'      => 0,       # used for --v-cipher
    'proxyhost'     => "",      # FQDN or IP of proxy to be used
    'proxyport'     => 0,       # port for proxy
    'proxyauth'     => "",      # authentication string used for proxy
    'proxyuser'     => "",      # username for proxy authentication (Basic or Digest Auth)
    'proxypass'     => "",      # password for proxy authentication (Basic or Digest Auth)
    'starttls'      => "",      # use STARTTLS if not empty
                                # protocol to be used with STARTTLS; default: SMTP
                                # valid protocols: SMTP, IMAP, IMAP2, POP3, FTPS, LDAP, RDP, XMPP
    'starttls_delay'=> 0,       # STARTTLS: time to wait in seconds (to slow down the requests)
    'starttls_phase'=> [],      # STARTTLS: Array for customised STARTTLS sequences
    'starttls_error'=> [],      # STARTTLS: Array for customised STARTTLS sequences error handling
    'slow_server_delay' => 0,   # time to wait in seconds after a connection via proxy or before starting STARTTLS sequence
    'connect_delay' => 0,       # time to wait in seconds for starting next cipher check
    'socket_reuse'  => 1,       # 0: close and reopen sockets when SSL connect fails
                                # 1: reuse existing sockets, even if SSL connect failed
    'ignore_no_conn'=> 0,       # 1: ignore warnings if connection fails, check target anyway
    'protos_next'   =>          # all names known for ALPN or NPN
                       'http/1.1,h2c,h2c-14,spdy/1,npn-spdy/2,spdy/2,spdy/3,spdy/3.1,spdy/4a2,spdy/4a4,grpc-exp,h2-14,h2-15,http/2.0,h2',
                                # even Net::SSLeay functions most likely use an
                                # array,  this is a string with comma-separated
                                # names as used by openssl
                                # NOTE: must not contain any white spaces!
    'protos_alpn'   => [],      # initially same as cfg{protos_next}, see _cfg_init()
    'protos_npn'    => [],      # "-"
    'slowly'        => 0,       # passed to Net::SSLeay::slowly
    'usesni'        => 1,       # use SNI extensionn by default (for TLSv1 and above)
    'sni_name'      => undef,   # if set, name to be used for connection with SNI
                                # must be set to $host if undef and 'use_sni_name'=1 (see below)
                                # all other strings are used verbatim, even empty one
    'use_sni_name'  => 0,       # 0: use hostname; 1: use name provided by --sni-name
                                # used by Net::SSLhello only
    'sclient_opt'   => "",      # argument or option passed to openssl s_client command
    'no_cert_txt'   => "",      # change default text if no data from cert retrieved
    'ca_depth'      => undef,   # depth of peer certificate verification verification
    'ca_crl'        => undef,   # URL where to find CRL file
    'ca_file'       => undef,   # PEM format file with CAs
    'ca_path'       => undef,   # path to directory with PEM files for CAs
                                # see Net::SSLinfo why undef as default
    'ca_files'      => [qw(ca-certificates.crt certificates.crt certs.pem cert.pem)],
                                # common PEM filenames for CAs; 1st used as default
                                # cert.pem instead of certs.pem on Android :-(
    'ca_paths'      => [qw(/etc/ssl/certs       /usr/lib/certs           /System/Library/OpenSSL /etc/tls/certs)],
                                # common paths to PEM files for CAs; 1st used as default
    'openssl_cnfs'  => [qw(/etc/ssl/openssl.cnf /usr/lib/ssl/openssl.cnf /System//Library/OpenSSL/openssl.cnf /usr/ssl/openssl.cnf)],
                                # common openssl.cnf files for openssl; 1st used as default
    'openssl_cnf'   => undef,   # full path to openssl's openssl.cnf
    'openssl_env'   => undef,   # environment variable OPENSSL if defined
    'openssl_fips'  => undef,   # NOT YET USED
    'openssl_msg'   => "",      # '-msg': option needed for openssl versions older than 1.0.2 to get the dh_parameter
    'ignorecase'    => 1,       # 1: compare some strings case insensitive
    'ignorenoreply' => 1,       # 1: treat "no reply" as heartbeat not enabled
    'label'         => 'long',  # fomat of labels
    'labels'        => [qw(full long short key)],   # all supported label formats
    'version'       => [],      # contains the versions to be checked
    'versions'      =>          # all supported versions; SEE Note:%prot (in o-saft.pl)
                       # [reverse sort keys %prot], # do not use generic list 'cause we want special order
                       [qw(SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 TLSv13 DTLSv09 DTLSv1 DTLSv11 DTLSv12 DTLSv13)],
    'DTLS_versions' => [qw(DTLSv09 DTLSv1 DTLSv11 DTLSv12 DTLSv13)],
                                # temporary list 'cause DTLS not supported by openssl (6/2015)
    'SSLv2'         => 1,       # 1: check this SSL version
    'SSLv3'         => 1,       # 1:   "
    'TLSv1'         => 1,       # 1:   "
    'TLSv11'        => 1,       # 1:   "
    'TLSv12'        => 1,       # 1:   "
    'TLSv13'        => 1,       # 1:   "
    'DTLSv09'       => 0,       # 1:   "
    'DTLSv1'        => 1,       # 1:   "
    'DTLSv11'       => 0,       # 1: not supported by OpenSSL 3.0.x; used for testing warning
    'DTLSv12'       => 1,       # 1:   "
    'DTLSv13'       => 0,       # 1:   "
    'TLS1FF'        => 0,       # dummy for future use
    'DTLSfamily'    => 0,       # dummy for future use
    'cipher'        => [],      # ciphers we got with --cipher=
                                # if the passed value is any of cipherpatterns
                                # the value from cipherpatterns will be used
    'cipherpattern' => "ALL:NULL:eNULL:aNULL:LOW:EXP",  # default for openssl
                                # pattern for all ciphers known by openssl
                                # should simply be   ALL:COMPLEMENTOFALL
                                # but have seen implementations  where it does
                                # not list all compiled-in ciphers,  hence the
                                # long list
                                # NOTE: must be same as in Net::SSLinfo
    'cipherpatterns'    => {    # openssl patterns for cipher lists
        # key             description                cipher pattern for openssl
        #----------------+--------------------------+---------------------------
        'null'      => [ "Null Ciphers",            'NULL:eNULL'              ], 
        'anull'     => [ "Anonymous NULL Ciphers",  'aNULL'                   ], 
        'anon'      => [ "Anonymous DH Ciphers",    'ADH'                     ], 
        'adh'       => [ "Anonymous DH Ciphers",    'ADH'                     ], 
        'aes'       => [ "AES Ciphers",             'AES'   ], 
        'aes128'    => [ "AES128 Ciphers",          'AES128'], 
        'aes256'    => [ "AES256 Ciphers",          'AES256'], 
        'aesGCM'    => [ "AESGCM Ciphers",          'AESGCM'], 
        'chacha'    => [ "CHACHA20 Ciphers",        'CHACHA'], # NOTE: not possible with some openssl
        'dhe'       => [ "Ephermeral DH Ciphers",   'EDH'   ], # NOTE: DHE not possible some openssl
        'edh'       => [ "Ephermeral DH Ciphers",   'EDH'                     ], 
        'ecdh'      => [ "Ecliptical curve DH Ciphers",             'ECDH'    ], 
        'ecdsa'     => [ "Ecliptical curve DSA Ciphers",            'ECDSA'   ], 
        'ecdhe'     => [ "Ephermeral ecliptical curve DH Ciphers",  'EECDH'   ], # NOTE:  ECDHE not possible with openssl
        'eecdh'     => [ "Ephermeral ecliptical curve DH Ciphers",  'EECDH'   ], 
        'aecdh'     => [ "Anonymous ecliptical curve DH Ciphers",   'AECDH'   ], 
        'exp40'     => [ "40 Bit encryption",       'EXPORT40'                ], 
        'exp56'     => [ "56 Bit export ciphers",   'EXPORT56'                ], 
        'export'    => [ "all Export Ciphers",      'EXPORT'],
        'exp'       => [ "all Export Ciphers",      'EXPORT'], # alias for export
        'des'       => [ "DES Ciphers",             'DES:!ADH:!EXPORT:!aNULL' ], 
        '3des'      => [ "Triple DES Ciphers",      '3DES'  ], # TODO: 3DES:!ADH:!aNULL
        'fips'      => [ "FIPS compliant Ciphers",  'FIPS'  ], # NOTE: not possible with some openssl
        'gost'      => [ "all GOST Ciphers",        'GOST'  ], # NOTE: not possible with some openssl
        'gost89'    => [ "all GOST89 Ciphers",      'GOST89'], # NOTE: not possible with some openssl
        'gost94'    => [ "all GOST94 Ciphers",      'GOST94'], # NOTE: not possible with some openssl
        'idea'      => [ "IDEA Ciphers",            'IDEA'  ], # NOTE: not possible with some openssl
        'krb'       => [ "KRB5 Ciphers",            'KRB5'  ], # alias for krb5
        'krb5'      => [ "KRB5 Ciphers",            'KRB5'  ], 
        'md5'       => [ "Ciphers with MD5 Mac",    'MD5'   ], 
        'psk'       => [ "PSK Ciphers",             'PSK'   ], 
        'rc2'       => [ "RC2 Ciphers",             'RC2'   ], # NOTE: not possible with some openssl
        'rc4'       => [ "RC4 Ciphers",             'RC4'   ], 
        'rsa'       => [ "RSA Ciphers",             'RSA'   ], 
        'seed'      => [ "Seed Ciphers",            'SEED'  ], 
        'sslv2'     => [ "all SSLv2 Ciphers",       'SSLv2' ], # NOTE: not possible with some openssl
        'sslv3'     => [ "all SSLv3 Ciphers",       'SSLv3' ], # NOTE: not possible with some openssl
        'tlsv1'     => [ "all TLSv1 Ciphers",       'TLSv1' ], # NOTE: not possible with some openssl
        'tlsv11'    => [ "all TLSv11 Ciphers",      'TLSv1' ], # alias for tlsv1
        'tlsv12'    => [ "all TLSv12 Ciphers",      'TLSv1.2' ], # NOTE: not possible with openssl
#        'tlsv13'    => [ "all TLSv13 Ciphers",      'TLSv1.3' ], # NOTE: not possible with openssl
        'tls13'     => [ "some TLS13 Ciphers",      'TLS13' ], # NOTE: not possible with openssl
        'srp'       => [ "SRP Ciphers",             'SRP'   ], 
        'sha'       => [ "Ciphers with SHA1 Mac",   'SHA'   ], 
        'sha'       => [ "Ciphers with SHA1 Mac",   'SHA'   ], 
        'sha1'      => [ "Ciphers with SHA1 Mac",   'SHA1'  ], # NOTE: not possible with some openssl
        'sha2'      => [ "Ciphers with SHA256 Mac", 'SHA256'],
        'sha256'    => [ "Ciphers with SHA256 Mac", 'SHA256'],
        'sha384'    => [ "Ciphers with SHA384 Mac", 'SHA384'],
        'sha512'    => [ "Ciphers with SHA512 Mac", 'SHA512'], # NOTE: not possible with some openssl
        'weak'      => [ "Weak grade encryption",   'LOW:3DES:DES:RC4:ADH:EXPORT'  ],
#       'low'       => [ "Low grade encryption",    'LOW:!ADH'    ],    # LOW according openssl
        'low'       => [ "Low grade encryption",    'LOW:3DES:RC4:!ADH' ],
        'medium'    => [ "Medium grade encryption", 'MEDIUM:!NULL:!aNULL:!SSLv2:!3DES:!RC4' ], 
        'high'      => [ "High grade encryption",   'HIGH:!NULL:!aNULL:!DES:!3DES' ], 
        #----------------+--------------------------+---------------------------
        # TODO: list with 'key exchange': kRSA, kDHr, kDHd, kDH, kEDH, kECDHr, kECDHe, kECDH, kEECDH
    }, # cipherpatterns
    'ciphermode'    => 'intern',# cipher scan mode, any of 'ciphermodes'
    'ciphermodes'   => [qw(dump intern openssl ssleay)],
                    # modes how to scan for ciphers;
                    # NOTE: commands_int must contain the commands cipher_dump
                    #       cipher_intern, cipher_openssl and cipher_ssleay
    'ciphers'       => [],      # contains all cipher keys to be tested
                                # contains cipher names for ciphermode=openssl
    'cipherrange'   => 'intern',# the range to be used from 'cipherranges'
    'cipherranges'  => {        # constants for ciphers (NOTE: written as hex)
                    # Technical (perl) note for definition of these ranges:
                    # Each range is defined as a string like  key=>"2..5, c..f"
                    # instead of an array like  key=>[2..5, c..f]  which would
                    # result in  key=>[2 3 4 5 c d e f] .
                    # This expansion of the range is done at compile time  and
                    # so will consume a huge amount of memory at runtime.
                    # Using a string instead of the expanded array reduces the
                    # memory footprint,  but requires use of  eval()  when the
                    # range is needed:  eval($cfg{cipherranges}->{rfc})
                    # Each string must be syntax for perl's range definition.
        'rfc'       =>          # constants for ciphers defined in various RFC
                       "0x03000000 .. 0x030000FF, 0x03001300 .. 0x030013FF,
                        0x0300C000 .. 0x0300C1FF, 0x0300CC00 .. 0x0300CCFF,
                        0x0300D000 .. 0x0300D0FF,
                        0x0300FE00 .. 0x0300FFFF,
                       ",
                            # GREASE ciphers added in _cfg_init()
        'shifted'   =>          # constants for ciphers defined in various RFCs shifted with an offset of 64 (=0x40) Bytes
                       "0x03000100 .. 0x0300013F, 0x0300FE00 .. 0x0300FFFF,",
                                # see _cfg_init(): + rfc
        'long'      =>          # more lazy list of constants for cipher
                       "0x03000000 .. 0x030013FF, 0x0300C000 .. 0x0300FFFF,",
        'huge'      =>          # huge range of constants for cipher
                       "0x03000000 .. 0x0300FFFF",
        'safe'      =>          # safe full range of constants for cipher
                                # because some network stack (NIC) will crash for 0x033xxxxx
                       "0x03000000 .. 0x032FFFFF",
        'full'      =>          # full range of constants for cipher
                       "0x03000000 .. 0x03FFFFFF",
# TODO:                 0x03000000,   0x03FFFFFF,   # used as return by microsoft testserver and also by SSL-honeypot (US)
        'SSLv2_base'=>          # constants for ciphers for SSLv2
                       "0x02000000,   0x02010080, 0x02020080, 0x02030080, 0x02040080,
                        0x02050080,   0x02060040, 0x02060140, 0x020700C0, 0x020701C0,
                        0x02FF0800,   0x02FF0810, 0x02FFFFFF,
                       ",
                        # 0x02FF0810,   0x02FF0800, 0x02FFFFFF,   # obsolete SSLv2 ciphers
                        # 0x0300FEE0,   0x0300FEE1, 0x0300FEFE, 0x0300FEFF, # obsolete FIPS ciphers
        'SSLv2_rfc' =>          # additional constants for ciphers for SSLv2
                       "0x03000000 .. 0x03000002, 0x03000007 .. 0x0300002C, 0x030000FF,",
        'SSLv2_rfc+'=>          # additional constants for ciphers for SSLv2 long list
                       "0x03000000 .. 0x0300002F, 0x030000FF,",
        'SSLv2_FIPS'=>          # additional constants for FIPS ciphers (SSLv2 and SSLv3)
                       "0x0300FEE0,   0x0300FEE1, 0x0300FEFE, 0x0300FEFF,",
        'SSLv2'     => "",      # constants for ciphers according RFC for SSLv2
                                # see _cfg_init(): SSLv2_base + SSLv2_rfc + SSLv2_FIPS
                                # see Note(a) above also
# TODO:                 0x02000000,   0x02FFFFFF,   # increment even only
# TODO:                 0x03000000,   0x03FFFFFF,   # increment  odd only
        'SSLv2_long'=> "",      # more lazy list of constants for ciphers for SSLv2
                                # see _cfg_init(): SSLv2_base + SSLv2_rfc+ + SSLv2_FIPS
        'SSLv3'     =>          # constants for SSLv3 ciphers (without SSLv2 ciphers)
                       "0x03000000 .. 0x0300003A, 0x03000041 .. 0x03000046,
                        0x03000060 .. 0x03000066, 0x03000080 .. 0x0300009B,
                        0x0300C000 .. 0x0300C022, 0x0300FEE0 .. 0x0300FEFF,
                        0x0300FF00 .. 0x0300FF03, 0x0300FF80 .. 0x0300FF83, 0x0300FFFF,
                       ",
        'SSLv3_SSLv2' => "",    # SSLv3 and SSLv2 ciphers; initialised in _cfg_init()
                                # see _cfg_init(): SSLv2_base + SSLv2_rfc+ + SSLv3
# TODO: 'SSLv3_old' =>          # constants for SSLv3 ciphers (without SSLv2 ciphers)
# TODO:                "0x03000000 .. 0x0300002F, 0x030000FF",  # old SSLv3 ciphers
        'TLSv10'    => "",      # same as SSLv3
        'TLSv11'    => "",      # same as SSLv3
        'TLSv12'    =>          # constants for TLSv1.2 ciphers
                       "0x0300003B .. 0x03000040, 0x03000067 .. 0x0300006D,
                        0x0300009C .. 0x030000A7, 0x030000BA .. 0x030000C5,
                        0x0300C023 .. 0x0300C032, 0x0300C072 .. 0x0300C079,
                        0x0300CC13 .. 0x0300CC15, 0x0300D000 .. 0x0300D005,
                        0x0300C100 .. 0x0300C102, 0x0300FFFF,
                       ",
        'TLSv13'    =>          # constants for TLSv1.3 ciphers
                       "0x03001301 .. 0x03001305, 0x0300FF85, 0x0300FF87,
                        0x030000C6,   0x030000C7, 0x0300C0B4, 0x0300C0B5,
                        0x0300C100 .. 0x0300C107,
                       ",
                            # GREASE ciphers added in _cfg_init()
        'GREASE'    =>          # constants for GREASE ciphers
                       "0x03000A0A, 0x03001A1A, 0x03002A2A, 0x03003A3A, 0x03004A4A,
                        0x03005A5A, 0x03006A6A, 0x03007A7A, 0x03008A8A, 0x03009A9A,
                        0x0300AAAA, 0x0300BABA, 0x0300CACA, 0x0300DADA, 0x0300EAEA, 0x0300FAFA,
                       ",
        'c0xx'      => "0x0300C000 .. 0x0300C0FF",  # constants for ciphers using ecc
        'ccxx'      => "0x0300CC00 .. 0x0300CCFF",  # constants for ciphers using ecc
        'ecc'       =>          # constants for ciphers using ecc
                       "0x0300C000 .. 0x0300C0FF, 0x0300CC00 .. 0x0300CCFF,",
        'intern'    => "",      # internal list, computed later ...
                                # see _cfg_init(): shifted
    }, # cipherranges
    'cipher_dh'     => 0,       # 1: +cipher also prints DH parameters (default will be changed in future)
    'cipher_md5'    => 1,       # 0: +cipher does not use *-MD5 ciphers except for SSLv2
   #{ removed 10/2017 as they are not used
   #'cipher_alpn'   => 1,       # 0: +cipher does not use ALPN
   #'cipher_npn'    => 1,       # 0: +cipher does not use  NPN ($Net::SSLinfo::use_nextprot is for openssl only)
   #}
    'cipher_ecdh'   => 1,       # 0: +cipher does not use TLS curves extension
    'cipher_alpns'  => [],      # contains all protocols to be passed for +cipher checks
    'cipher_npns'   => [],      # contains all protocols to be passed for +cipher checks
    'ciphercurves'  =>          # contains all curves to be passed for +cipher checks
                       [
                        qw(prime192v1 prime256v1),
                        qw(sect163k1 sect163r1 sect193r1           sect233k1 sect233r1),
                        qw(sect283k1 sect283r1 sect409k1 sect409r1 sect571k1 sect571r1),
                        qw(secp160k1 secp160r1 secp160r2 secp192k1 secp224k1 secp224r1),
                        qw(secp256k1 secp384r1 secp521r1),
                        qw(brainpoolP256r1 brainpoolP384r1 brainpoolP512r1),
                                # TODO: list NOT YET complete, see %tls_curves
                                #       adapted to Mosman's openssl 1.0.2dev (5/2017)
                                #qw(ed25519 ecdh_x25519 ecdh_x448),
                                #qw(prime192v2 prime192v3 prime239v1 prime239v2 prime239v3),
                                #qw(sect193r2 secp256r1 ),
                        ],

    # List of all extensions sent by protocol
    'extensions_by_prot' => {   # List all Extensions used by protocol, SSLv2 does not support extensions by design
         'SSLv3'    => [],      # SSLv3 does not support extensions as originally defined, may be back-ported
         'TLSv1'    => [qw(renegotiation_info supported_groups ec_point_formats session_ticket)],
         'TLSv11'   => [qw(renegotiation_info supported_groups ec_point_formats session_ticket)],
         'TLSv12'   => [qw(renegotiation_info supported_groups ec_point_formats signature_algorithms )],
         'TLSv13'   => [qw(supported_versions supported_groups ec_point_formats signature_algorithms
                           session_ticket renegotiation_info encrypt_then_mac
                           extended_master_secret psk_key_exchange_modes key_share
                        )],
    }, # extensions_by_prot

   # following keys for commands, naming scheme:
   #     do         - the list off all commands to be performed
   #     commands_* - internal list for various types of commands
   #     cmd-*      - list for "summary" commands, can be redifined by user
   #     need-*     - list of commands which need a speciphic check
   #
   # TODO: need to unify  cmd-* and need-* and regex->cmd-*;
   #       see also _need_* functions and "construct list for special commands"
   #       in o-saft.pl
   # config. key       list       description
   #------------------+---------+----------------------------------------------
    'do'            => [],      # commands to be performed
    'commands'      => [],      # contains all commands from %data, %checks and commands_int
                                # will be constructed in main, see: construct list for special commands
    'commands_cmd'  => [],      # contains all cmd-* commands from below
    'commands_usr'  => [],      # contains all commands defined by user with
                                # option --cfg-cmd=* ; see _cfg_set()
    'commands_exp'  => [        # experimental commands
                       ],
    'commands_notyet'=>[        # commands and checks NOT YET IMPLEMENTED
                        qw(zlib lzo open_pgp fallback closure sgc scsv time
                           cps_valid cipher_order cipher_weak
                        ),
                       ],
    'commands_int'  => [        # add internal commands
                                # these have no key in %data or %checks
                        qw(
                         cipher cipher_intern cipher_openssl cipher_ssleay
                         cipher_dump   cipher_dh cipher_default
                         bsi check check_sni dump ev exec help info info--v http
                         quick list libversion sigkey sizes s_client version quit
                        ),
                                # internal (debugging) commands
                      # qw(options cert_type),  # will be seen with +info--v only
                                # keys not used as command
                        qw(cn_nosni valid_years valid_months valid_days valid_host)
                       ],
    'commands_hint' => [        # checks which are NOT YET fully implemented
                                # these are mainly all commands for compliance
                                # see also: cmd-bsi
                        qw(rfc_7525 tr_02102+ tr_02102- tr_03116+ tr_03116-)
                       ],
    'cmd-beast'     => [qw(beast)],                 # commands for +beast
    'cmd-crime'     => [qw(crime)],                 # commands for +crime
    'cmd-drown'     => [qw(drown)],                 # commands for +drown
    'cmd-freak'     => [qw(freak)],                 # commands for +freak
    'cmd-lucky13'   => [qw(lucky13)],               # commands for +lucky13
    'cmd-robot'     => [qw(robot)],                 # commands for +robot
    'cmd-sweet32'   => [qw(sweet32)],               # commands for +sweet32
    'cmd-http'      => [],      # commands for +http, computed below
    'cmd-hsts'      => [],      # commands for +hsts, computed below
    'cmd-info'      => [],      # commands for +info, simply anything from %data
    'cmd-info--v'   => [],      # commands for +info --v
    'cmd-check'     => [],      # commands for +check, simply anything from %checks
    'cmd-sizes'     => [],      # commands for +sizes
    'cmd-quick'     => [        # commands for +quick
                        qw(
                         sslversion hassslv2 hassslv3 hastls12
                         cipher_selected cipher_strong cipher_null cipher_adh
                         cipher_exp cipher_cbc cipher_des cipher_rc4 cipher_edh
                         cipher_pfs beast crime drown freak heartbleed logjam
                         lucky13 poodle rc4 robot sloth sweet32
                         fingerprint_hash fp_not_md5 sha2signature pub_encryption
                         pub_enc_known email serial subject dates verify heartbeat
                         expansion compression hostname hsts_sts crl master_secret
                         renegotiation resumption tr_02102+ tr_02102- rfc_7525
                       )],
    'cmd-ev'        => [qw(cn subject altname dv ev ev- ev+ ev_chars)], # commands for +ev
    'cmd-bsi'       => [        # commands for +bsi
                                # see also: commands_hint
                        qw(after dates crl cipher_rc4 renegotiation
                           tr_02102+ tr_02102- tr_03116+ tr_03116-
                       )],
    'cmd-pfs'       => [qw(cipher_pfs cipher_pfsall session_random)],   # commands for +pfs
    'cmd-sni'       => [qw(sni hostname certfqdn)],  # commands for +sni
    'cmd-sni--v'    => [qw(sni cn altname verify_altname verify_hostname hostname wildhost wildcard)],
    'cmd-vulns'     => [        # commands for checking known vulnerabilities
                        qw(
                         beast breach ccs crime drown freak heartbleed logjam
                         lucky13 poodle rc4 robot sloth sweet32 time
                         hassslv2 hassslv3 compression cipher_pfs session_random
                         renegotiation resumption
                       )],
    'cmd-prots'     => [        # commands for checking protocols
                        qw(hassslv2 hassslv3 hastls10 hastls11 hastls12 hastls13 hasalpn hasnpn session_protocol fallback_protocol alpn alpns npns next_protocols https_protocols http_protocols https_svc http_svc)
                       ],
    'cmd-NL'        => [        # commands which need NL when printed
                                # they should be available with +info --v only
                        qw(certificate extensions pem pubkey sigdump text
                         chain chain_verify ocsp_response_data)
                       ],

   # need-* lists used to improve performance and warning messages
    'need-sslv3'    => [        # commands which need SSLv3 protocol
                        qw(check cipher cipher_dh cipher_strong cipher_selected
                         cipher_weak protocols hassslv3 beast freak poodle
                         tr_02102+ tr_02102- tr_03116+ tr_03116- rfc_7525
                       )],
    'need-cipher'   => [        # commands which need +cipher
                        qw(check cipher cipher_dh  cipher_strong cipher_weak
                         cipher_dump cipher_intern cipher_ssleay cipher_openssl
                         cipher_null cipher_adh cipher_cbc cipher_des cipher_edh
                         cipher_exp  cipher_rc4 cipher_pfs cipher_pfsall
                         beast crime time breach drown freak logjam
                         lucky13 poodle rc4 robot sloth sweet32
                         tr_02102+ tr_02102- tr_03116+ tr_03116- rfc_7525
                         hassslv2 hassslv3 hastls10 hastls11 hastls12 hastls13
                       )],
                                # TODO: need simple check for protocols
    'need-default'  => [        # commands which need selected cipher
                        qw(check cipher cipher_default
                         cipher_dump cipher_intern cipher_ssleay cipher_openssl
                         cipher_pfs  cipher_order  cipher_strong cipher_selected),
                        qw(sslv3  tlsv1   tlsv10  tlsv11 tlsv12),
                                # following checks may cause errors because
                                # missing functionality (i.e in openssl) # 10/2015
                        qw(sslv2  tlsv13  dtlsv09 dtlvs1 dtlsv11 dtlsv12 dtlsv13)
                       ],
    'need-checkssl' => [        # commands which need checkssl() # TODO: needs to be verified
                        qw(check beast crime time breach freak
                         cipher_pfs cipher_pfsall cipher_cbc cipher_des
                         cipher_edh cipher_exp cipher_rc4 cipher_selected
                         ev+ ev- tr_02102+ tr_02102- tr_03116+ tr_03116-
                         ocsp_response ocsp_response_status ocsp_stapling
                         ocsp_uri ocsp_valid
                         rfc_7525 rfc_6125_names rfc_2818_names
                       )],
    'need-checkalnp'=> [        # commands which need checkalpn()
                        qw(alpns alpn hasalpn npns npn hasnpn),
                       ],
    'need-checkbleed'   => [ qw(heartbleed) ],
    'need-check_dh' => [        # commands which need check_dh()
                        qw(logjam dh_512 dh_2048 ecdh_256 ecdh_512)
                       ],
    'need-checkdest'=> [        # commands which need checkdest()
                        qw(reversehost ip resumption renegotiation
                         session_protocol session_ticket session_random session_lifetime
                         krb5 psk_hint psk_identity srp heartbeat ocsp_stapling
                         cipher_selected cipher_pfs ccs compression crime
                       )],
    'need-checkhttp'=> [qw(https_pins)],# commands which need checkhttp(); more will be added in _init
    'need-checkprot'=> [        # commands which need checkprot(), should be same as in 'cmd-prots'
                        qw(
                         sslversion
                         hassslv2 hassslv3 hastls10 hastls11 hastls12 hastls13
                         alpns alpn hasalpn npns npn hasnpn
                         crime drown poodle
                       )],
    'need-checksni' => [        # commands which need checksni()
                        qw(hostname certfqdn cn cn_nosni sni)
                       ],
    'need-checkchr' => [        # commands which always need checking various characters
                        qw(cn subject issuer altname ext_crl ocsp_uri),
                       ],
    'data_hex'      => [        # data values which are in hex values
                                # used in conjunction with --format=hex
                                # not useful in this list: serial extension
                        qw(
                         fingerprint fingerprint_hash fingerprint_md5
                         fingerprint_sha1 fingerprint_sha2
                         sigkey_value pubkey_value modulus
                         master_key session_id session_ticket
                       )],      # fingerprint is special, see _ishexdata()
   #------------------+---------+----------------------------------------------

    'ignore-out'    => [qw(https_body)],# commands (output) to be ignored, SEE Note:ignore-out
   # out->option key           default   description
   #--------------------------+-----+------------------------------------------
    'out' =>    {      # configurations for data to be printed
        'disabled'          => 1,   # 1: print disabled ciphers
        'enabled'           => 1,   # 1: print enabled ciphers
        'header'            => 0,   # 1: print header lines in output
        'hostname'          => 0,   # 1: print hostname (target) as prefix for each line
        'hint_cipher'       => 1,   # 1: print hints for +cipher command
        'hint_check'        => 1,   # 1: print hints for +check commands
        'hint_info'         => 1,   # 1: print hints for +info commands
        'hint'              => 1,   # 1: print hints for +cipher +check +info
        'http_body'         => 0,   # 1: print received HTTP body if explicitly requested
        'traceARG'          => 0,   # 1: (trace) print argument processing
        'traceCMD'          => 0,   # 1: (trace) print command processing
        'traceKEY'          => 0,   # 1: print internal variable names for %data and %checks
        'traceTIME'         => 0,   # 1: (trace) print additional time for benchmarking
        'time_absolut'      => 0,   # 1: (trace) --traceTIME uses absolut timestamps
        'warning'           => 1,   # 1: print warnings
        'score'             => 0,   # 1: print scoring
        'ignore'            => [qw(https_body)],
                                    # commands (output) to be ignored, SEE Note:ignore-out
        'warnings_no_dups'  => [qw(303 304 412)],
                                    # do not print these warnings multiple times
                                    # SEE  Note:warning-no-duplicates
                                    # 410 not added, as it appears once per protocol only
        'warnings_printed'  => [],  # list of unique warning numbers already printed
                                    # SEE  Note:warning-no-duplicates
        'exitcode'          => 0,   # 1: print verbose checks for exit status
        'exitcode_checks'   => 1,   # 0: do not count "no" checks for --exitcode
        'exitcode_cipher'   => 1,   # 0: do not count any ciphers for --exitcode
        'exitcode_medium'   => 1,   # 0: do not count MEDIUM ciphers for --exitcode
        'exitcode_weak'     => 1,   # 0: do not count  WEAK  ciphers for --exitcode
        'exitcode_low'      => 1,   # 0: do not count  LOW   ciphers for --exitcode
        'exitcode_pfs'      => 1,   # 0: do not count ciphers without PFS for --exitcode
        'exitcode_prot'     => 1,   # 0: do not count protocols other than TLSv12 for --exitcode
        'exitcode_sizes'    => 1,   # 0: do not count size checks for --exitcode
        'exitcode_quiet'    => 0,   # 1: do not print "EXIT status" message
    }, # out
   #--------------------------+-----+------------------------------------------

   # use->option key     default  description
   #----------------------+-----+----------------------------------------------
    'use' =>    {      # configurations to use or do some specials
        'mx'            => 0,   # 1: make MX-Record DNS lookup
        'dns'           => 1,   # 1: make DNS reverse lookup
        'http'          => 1,   # 1: make HTTP  request with default (Net::LLeay) settings
                                # 2: make HTTP  request without headers User-Agent and Accept
        'https'         => 1,   # 1: make HTTPS request with default (Net::LLeay) settings
                                # 2: make HTTPS request without headers User-Agent and Accept
        'forcesni'      => 0,   # 1: do not check if SNI seems to be supported by Net::SSLeay
        'sni'           => 1,   # 0: do not make connection in SNI mode
                                # 1: make connection with SNI set (can be empty string)
                                # 3: test with and without SNI mode (used with Net::SSLhello::checkSSLciphers only)
        'lwp'           => 0,   # 1: use perls LWP module for HTTP checks # TODO: NOT YET IMPLEMENTED
        'user_agent'    => undef,   # User-Agent header to be used in HTTP requests
        'alpn'          => 1,   # 0: do not use -alpn option for openssl
        'npn'           => 1,   # 0: do not use -nextprotoneg option for openssl
        'reconnect'     => 1,   # 0: do not use -reconnect option for openssl
        'extdebug'      => 1,   # 0: do not use -tlsextdebug option for openssl
        'cert'          => 1,   # 0: do not get data from certificate
        'no_comp'       => 0,   # 0: do not use OP_NO_COMPRESSION for connetion in Net::SSLeay
        'ssl_lazy'      => 0,   # 1: lazy check for available SSL protocol functionality (Net::SSLeay problem)
        'nullssl2'      => 0,   # 1: complain if SSLv2 enabled but no ciphers accepted
        'ssl_error'     => 1,   # 1: stop connecting to target after ssl-error-max failures
        'experimental'  => 0,   # 1: use, print experimental functionality
        'exitcode'      => 0,   # 1: exit with status code if any check is "no"
                                # see also 'out'->'exitcode'
    }, # use
   #----------------------+-----+----------------------------------------------

   # SEE Note:tty
   # following keys used when --tty (or similar) option was used
   # i.g. the code will use the values only   if defined $cfg{'tty'}->{'width'}
   # option key        default    description
   #------------------+---------+----------------------------------------------
    'tty' =>    {      # configuration for tty and behaviour according tty
        'width'     => undef,   # screen width (columns) of the tty
                                # NOTE: the value undef is used to detect if the
                                #       option --tty was used
        'ident'     => 2,       # left ident spaces, used to replace leftmost 8 spaces
        'arrow'     => "↲",     # "continous arrow when line is split
                                # ← 0x2190, ↲ 0x21b2, ⮠ 0x2ba0, ⤶ 0x2936, ⤸ 0x2938, 
                                # NOTE: it's mandatory to have:  "use utf8"
    }, # tty

   # option key        default    description
   #------------------+---------+----------------------------------------------
    'opt-v'         => 0,       # 1 when option -v was given
    'opt-V'         => 0,       # 1 when option -V was given
    'format'        => "",      # empty means some slightly adapted values (no \s\n)
    'formats'       => [qw(csv html json ssv tab xml fullxml raw hex 0x esc)],
                                # not yet used: csv html json ssv tab xml fullxml
    'tmplib'        => "/tmp/yeast-openssl/",   # temp. directory for openssl and its libraries
    'pass_options'  => "",      # options to be passeed thru to other programs
    'mx_domains'    => [],      # list of mx-domain:port to be processed
    'hosts'         => [],      # list of targets (host:port) to be processed
                                # since 18.07.18 used in checkAllCiphers.pl only
    'targets'       => [],      # list of targets (host:port, prot, path, etc.)
                                # to be processed;  anon. list, each element is
                                # array; first element contains defaults (see
                                # @target_defaults below)
    'port'          => undef,   # port for currently scanned target
    'host'          => "",      # currently scanned target
    'ip'            => "",      # currently scanned target's IP (machine readable format)
    'IP'            => "",      # currently scanned target's IP (human readable, doted octet)
    'rhost'         => "",      # currently scanned target's reverse resolved name
    'DNS'           => "",      # currently scanned target's other IPs and names (DNS aliases)
    'timeout'       => 2,       # default timeout in seconds for connections
                                # NOTE: some servers do not connect SSL within
                                #       this time,  this may result in ciphers
                                #       marked as  "not supported"
                                #       it's recommended to set timeout =3  or
                                #       higher, which results in a performance
                                #       bottleneck, obviously
                                #  see 'sslerror' settings and options also

   #----------------+----------------------------------------------------------
    'openssl'  =>   {  # configurations for various openssl functionality
                       # same data structure as Net::SSLinfo's %_OpenSSL_opt
                       # not all values used yet
                       # default value 1 means supported by openssl, will be
                       # initialised correctly in _check_openssl()
                       # which uses Net::SSLinfo::s_client_check()
        #------------------+-------+-------------------------------------------
        # key (=option) supported=1  warning message if option is missing
        #------------------+-------+-------------------------------------------
        '-CAfile'           => [ 1, "using -CAfile disabled"        ],
        '-CApath'           => [ 1, "using -CApath disabled"        ],
        '-alpn'             => [ 1, "checks with ALPN disabled"     ],
        '-npn'              => [ 1, "checks with NPN  disabled"     ],
        '-nextprotoneg'     => [ 1, "checks with NPN  disabled"     ], # alias for -npn
        '-reconnect'        => [ 1, "checks with openssl reconnect disabled"],
        '-fallback_scsv'    => [ 1, "checks for TLS_FALLBACK_SCSV wrong"    ],
        '-comp'             => [ 1, "<<NOT YET USED>>"              ],
        '-no_comp'          => [ 1, "<<NOT YET USED>>"              ],
        '-no_tlsext'        => [ 1, "<<NOT YET USED>>"              ],
        '-no_ticket'        => [ 1, "<<NOT YET USED>>"              ],
        '-serverinfo'       => [ 1, "checks without TLS extension disabled" ],
        '-servername'       => [ 1, "checks with TLS extension SNI disabled"],
        '-serverpref'       => [ 1, "<<NOT YET USED>>"              ],
        '-showcerts'        => [ 1, "<<NOT YET USED>>"              ],
        '-curves'           => [ 1, "using -curves disabled"        ],
        '-debug'            => [ 1, "<<NOT YET USED>>"              ],
        '-bugs'             => [ 1, "<<NOT YET USED>>"              ],
        '-key'              => [ 1, "<<NOT YET USED>>"              ],
        '-msg'              => [ 1, "using -msg disabled, DH paramaters missing or wrong"],
        '-nbio'             => [ 1, "<<NOT YET USED>>"              ],
        '-psk'              => [ 1, "PSK  missing or wrong"         ],
        '-psk_identity'     => [ 1, "PSK identity missing or wrong" ],
        '-pause'            => [ 1, "<<NOT YET USED>>"              ],
        '-prexit'           => [ 1, "<<NOT YET USED>>"              ],
        '-proxy'            => [ 1, "<<NOT YET USED>>"              ],
        '-quiet'            => [ 1, "<<NOT YET USED>>"              ],
        '-sigalgs'          => [ 1, "<<NOT YET USED>>"              ],
        '-state'            => [ 1, "<<NOT YET USED>>"              ],
        '-status'           => [ 1, "<<NOT YET USED>>"              ],
        '-strict'           => [ 1, "<<NOT YET USED>>"              ],
        '-nbio_test'        => [ 1, "<<NOT YET USED>>"              ],
        '-tlsextdebug'      => [ 1, "TLS extension missing or wrong"],
        '-client_sigalgs'   => [ 1, "<<NOT YET USED>>"              ],
        '-record_padding'   => [ 1, "<<NOT YET USED>>"              ],
        '-no_renegotiation' => [ 1, "<<NOT YET USED>>"              ],
        '-legacyrenegotiation'      => [ 1, "<<NOT YET USED>>"      ],
        '-legacy_renegotiation'     => [ 1, "<<NOT YET USED>>"      ],
        '-legacy_server_connect'    => [ 1, "<<NOT YET USED>>"      ],
        '-no_legacy_server_connect' => [ 1, "<<NOT YET USED>>"      ],
        #------------------+-------+-------------------------------------------
	# openssl > 1.x disabled various protocols, default enabled
        #------------------+-------+-------------------------------------------
        '-ssl2'             => [ 1, "SSLv2 for +cipher disabled"    ],
        '-ssl3'             => [ 1, "SSLv3 for +cipher disabled"    ],
        '-tls1'             => [ 1, "TLSv1 for +cipher disabled"    ],
        '-tls1_1'           => [ 1, "TLSv1.1 for +cipher disabled"  ],
        '-tls1_2'           => [ 1, "TLSv1.2 for +cipher disabled"  ],
        '-tls1_3'           => [ 1, "TLSv1.3 for +cipher disabled"  ],
        '-dtls'             => [ 1, "DTLSv1 for +cipher disabled"   ],
        '-dtls1'            => [ 1, "DTLSv1 for +cipher disabled"   ],
        '-dtls1_1'          => [ 1, "DTLSv1.1 for +cipher disabled" ],
        '-dtls1_2'          => [ 1, "DTLSv1.2 for +cipher disabled" ],
        '-dtls1_3'          => [ 1, "DTLSv1.3 for +cipher disabled" ],
        '-no_ssl2'          => [ 1, "option ignored" ],
        '-no_ssl3'          => [ 1, "option ignored" ],
        '-no_tls1'          => [ 1, "option ignored" ],
        '-no_tls1_1'        => [ 1, "option ignored" ],
        '-no_tls1_2'        => [ 1, "option ignored" ],
        '-no_tls1_3'        => [ 1, "option ignored" ],
        #------------------+-------+-------------------------------------------
    }, # openssl
    'openssl_option_map' => {   # map our internal option to openssl option; used our Net:SSL*
        # will be initialised from %prot
     },
    'openssl_version_map' => {  # map our internal option to openssl version (hex value); used our Net:SSL*
        # will be initialised from %prot
     },

   # ssleay->option      default  description
   #----------------------+-----+----------------------------------------------
    'ssleay'   =>   {  # configurations for various Net::SSLeay functionality
                                # 1: if available is default (see _check_functions())
        'openssl'       => 1,   # OPENSSL_VERSION_NUMBER()
        'get_alpn'      => 1,   # P_alpn_selected available()
        'get_npn'       => 1,   # P_next_proto_negotiated()
        'set_alpn'      => 1,   # CTX_set_alpn_protos()
        'set_npn'       => 1,   # CTX_set_next_proto_select_cb()
        'can_npn'       => 1,   # same as get_npn, just an alias
        'can_ecdh'      => 1,   # can_ecdh()
        'can_sni'       => 1,   # for openssl version > 0x01000000
        'can_ocsp'      => 1,   # OCSP_cert2ids
        'iosocket'      => 1,   # $IO::Socket::SSL::VERSION # TODO: wrong container
    },
    # 'ssl_error'               # see 'use' above
    'sslerror' =>   {  # configurations for TCP SSL protocol
        'timeout'       => 1,   # timeout to receive ssl-answer
        'max'           => 5,   # max. consecutive errors
        'total'         => 10,  # max. overall errors
                                # following are NOT YET fully implemented:
        'delay'         => 0,   # if > 0 continue trying to connect after this time
        'per_prot'      => 1,   # if > 0 detection and count are per SSL version
        'ignore_no_conn' => 0,  # 0: ignore warnings if connection fails, check target anyway
                                # 1: print  warnings if connection fails, don't check target
        'ignore_handshake' => 1,# 1: treat "failed handshake" as error,   don't check target
    }, # ssl_error
    'sslhello' =>   {  # configurations for TCP SSL protocol (mainly used in Net::SSLhello)
        'timeout'       => 2,   # timeout to receive ssl-answer
        'retry'         => 2,   # number of retry when timeout
        'maxciphers'    => 32,  # number of ciphers sent in SSL3/TLS Client-Hello
        'usesignaturealg' => 1, # 1: use extension "signature algorithm"
        'useecc'        => 1,   # 1: use supported elliptic curves
        'useecpoint'    => 1,   # 1: use ec_point_formats extension
        'usereneg'      => 0,   # 1: secure renegotiation
        'double_reneg'  => 0,   # 0: do not send reneg_info extension if the cipher_spec already includes SCSV
                                #    "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" {0x00, 0xFF}
        'nodatanocipher'=> 1,   # 1: do not abort testing next cipher for some TLS intolerant Servers 'NoData or Timeout Equals to No Cipher'
    },
   #----------------------+-----+----------------------------------------------
    'legacy'            => "simple",
    'legacys'           => [    # list of known values
                            qw(cnark sslaudit sslcipher ssldiagnos sslscan dump
                            ssltest ssltest-g sslyze testsslserver thcsslcheck
                            simple full compact quick owasp osaft o-saft
                            openssl openssl-v openssl-V)
                           ],
                           # SSLAudit, THCSSLCheck, TestSSLServer are converted using lc()
                           # openssl-v openssl-V osaft o-saft are used for convenience
    'usr_args'          => [],  # list of all arguments --usr* (to be used in o-saft-usr.pm)
   #------------------+---------+----------------------------------------------
    'data'  => {       # data provided (mainly used for testing and debugging)
        'file_sclient'  => "",  # file containing data from "openssl s_client "
        'file_ciphers'  => "",  # file containing data from "openssl ciphers"
        'file_pem'      => "",  # file containing certificate(s) in PEM format
        'file_pcap'     => "",  # file containing data in PCAP format
                                # i.e. "openssl s_client -showcerts ..."
    }, # data
   #------------------+---------+----------------------------------------------

   # regex->type           RegEx
   #----------------------+----------------------------------------------------
    'regex' => {
        # RegEx for matching commands and options
        'cmd-http'      => '^h?(?:ttps?|sts)_', # match keys for HTTP
        'cmd-hsts'      => '^h?sts',            # match keys for (H)STS
        'cmd-sizes'     => '^(?:cnt|len)_',     # match keys for length, sizes etc.
        'cmd-cfg'       => '(?:cmd|checks?|data|info|hint|text|scores?)',# --cfg-* commands
        'commands_int'  => '^(?:cn_nosni|valid_(?:year|month|day|host)s?)', # internal data only, no command
        'opt_empty'     => '(?:[+]|--)(?:cmd|help|host|port|format|legacy|timeout|trace|openssl|(?:cipher|proxy|sep|starttls|exe|lib|ca-|cfg-|ssl-|usr-).*)',
                           # these options may have no value
                           # i.e.  --cmd=   ; this may occour in CGI mode
        'std_format'    => '^(?:unix|raw|crlf|utf8|win32|perlio)$', # match keys for --std-format

        # RegEx for matching strings to anonymise in output 
        'anon_output'   => '',  # pattern for strings to be anonymised in output
                           # SEE Note:anon-out

        # RegEx for matching SSL protocol keys in %data and %checks
        'SSLprot'       => '^(SSL|D?TLS)v[0-9]',    # match keys SSLv2, TLSv1, ...

        # RegEx for matching SSL cipher-suite names
        # First some basic RegEx used later on, either in following RegEx or
        # as $cfg{'regex'}->{...}  itself.
        '_or-'          => '[\+_-]',
                           # tools use _ or - as separator character; + used in openssl
        'ADHorDHA'      => '(?:A(?:NON[_-])?DH|DH(?:A|[_-]ANON))[_-]',
                           # Anonymous DH has various acronyms:
                           #     ADH, ANON_DH, DHA, DH-ANON, DH_Anon, ...
                           # TODO:missing: AECDH
        'RC4orARC4'     => '(?:ARC(?:4|FOUR)|RC4)',
                           # RC4 has other names due to copyright problems:
                           #     ARC4, ARCFOUR, RC4
        '3DESorCBC3'    => '(?:3DES(?:[_-]EDE)[_-]CBC|DES[_-]CBC3)',
                           # Tripple DES is used as 3DES-CBC, 3DES-EDE-CBC, or DES-CBC3
        'DESor3DES'     => '(?:[_-]3DES|DES[_-]_192)',
                           # Tripple DES is used as 3DES or DES_192
        'DHEorEDH'      => '(?:DHE|EDH)[_-]',
                           # DHE and EDH are 2 acronyms for the same thing
        'EC-DSA'        => 'EC(?:DHE|EDH)[_-]ECDSA',
        'EC-RSA'        => 'EC(?:DHE|EDH)[_-]RSA',
                           # ECDHE-RSA or ECDHE-ECDSA
        'EC'            => 'EC(?:DHE|EDH)[_-]',
        'EXPORT'        => 'EXP(?:ORT)?(?:40|56|1024)?[_-]',
                           # EXP, EXPORT, EXPORT40, EXP1024, EXPORT1024, ...
        'FRZorFZA'      => '(?:FORTEZZA|FRZ|FZA)[_-]',
                           # FORTEZZA has abbreviations FZA and FRZ
                           # unsure about FORTEZZA_KEA
        'SHA2'          => 'sha(?:2|224|256|384|512)',
                           # any SHA2, just sha2 is too lazy
        'AES-GCM'       => 'AES(?:128|256)[_-]GCM[_-]SHA(?:256|384|512)',
                           # any AES128-GCM or AES256-GCM
        'SSLorTLS'      => '^(?:SSL[23]?|TLS[12]?|PCT1?)[_-]',
                           # Numerous protocol prefixes are in use:
                           #     PTC, PCT1, SSL, SSL2, SSL3, TLS, TLS1, TLS2,
        'aliases'       => '(?:(?:DHE|DH[_-]ANON|DSS|RAS|STANDARD)[_-]|EXPORT_NONE?[_-]?XPORT|STRONG|UNENCRYPTED)',
                           # various variants for aliases to select cipher groups

        # RegEx for matching various strings
        'compression'   =>'(?:DEFLATE|LZO)',    # if compression available
        'nocompression' =>'(?:NONE|NULL|^\s*$)',# if no compression available
        'encryption'    =>'(?:encryption|ecPublicKey)', # anything containing this string
        'encryption_ok' =>'(?:(?:(?:(?:md[245]|ripemd160|sha(?:1|224|256|384|512))with)?[rd]saencryption)|id-ecPublicKey)',
                           # well known strings to identify signature and public
                           # key encryption:
                           # rsaencryption, dsaencryption, md[245]withrsaencryption,
                           # ripemd160withrsa shaXXXwithrsaencryption
                           # id-ecPublicKey
        'encryption_no' =>'(?:rsa(?:ssapss)?|sha1withrsa|dsawithsha1?|dsa_with_sha256)',
                           # rsa, rsassapss, sha1withrsa, dsawithsha*, dsa_with_sha256
        'security'      => '(?:HIGH|MEDIUM|LOW|WEAK|NONE)',
                           # well known "security" strings, should be used case-insensitive
        'isIP'          => '(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
        'isDNS'         => '(?:[a-z0-9.-]+)',
        'isIDN'         => '(?:xn--)',
        'leftwild'      => '^\*(?:[a-z0-9.-]+)',
        'doublewild'    => '(?:[a-z0-9.-]+\*[a-z0-9-]+\*)', # x*x or x*.x*
        'invalidwild'   => '(?:\.\*\.)',            # no .*.
        'invalidIDN'    => '(?:xn--[a-z0-9-]*\*)',  # no * right of xn--
        'isSPDY3'       => '(?:spdy\/3)',           # match in protocols (NPN)
                           # TODO: lazy match as it matches spdy/3.1 also

        # TODO: replace following RegEx by concrete list of constants
        # RegEx matching OWASP TLS Cipher String Cheat Sheet
            # matching list of concrete constants would be more accurate, but
            # that cannot be done with RegEx or ranges, unfortunatelly
        'OWASP_AA'      => '^(TLS(?:v?13)?[_-](?:AES...|CHACHA20)[_-])',  # newer (2021 and later) openssl use strange names for TLSv1.3; i.e. TLS13-AES128-GCM-SHA256
        'OWASP_A'       => '^(?:TLSv?1[123]?)?(?:(EC)?(?:DHE|EDH).*?(?:AES...[_-]GCM|CHACHA20-POLY1305[_-]SHA))|TLS13[_-]AES-?...[_-]',
            # due to cipher name rodeo we have AESxxx-GCM-SHA* and AES-xxx-GCM-SHA*
        'OWASP_B'       => '^(?:TLSv1[123]?)?(?:(EC)?(?:DHE|EDH).*?(?:AES|CHACHA).*?(?!GCM|POLY1305)[_-]SHA)',
        'OWASP_C'       => '^((?:TLSv1[123]?)?.*?(?:AES...|RSA)[_-]|(?:(?:EC)?DHE-)?PSK[_-]CHACHA)',
            # all ECDHE-PSK-CHACHA* DHE-PSK-CHACHA* and PSK-CHACHA* are C too
        'OWASP_D'       => '(?:^SSLv[23]|(?:NULL|EXP(?:ORT)?(?:40|56|1024)|A(?:EC|NON[_-])?DH|DH(?:A|[_-]ANON)|ECDSA|DSS|CBC|DES|MD[456]|RC[24]|PSK[_-]SHA|UNFFINED))',
            # all PSK-SHA are aliases for PSK-NULL-SHA and hence D
            # TODO:  all AES128-SHA are aliases for AES128-CBC-SHA; severity depends on protocl version
        'OWASP_NA'      => '(?:^PCT_|ARIA|CAMELLIA|ECDS[AS]|GOST|IDEA|SEED|CECPQ|SM4|FZA[_-]FZA)',
            # PCT are not SSL/TLS; will produce 'miss' in internal tests
        # TODO: need exception, i.e. TLSv1 and TLSv11
        'notOWASP_A    '=> '^(?:TLSv11?)',
        'notOWASP_B'    => '',
        'notOWASP_C'    => '',
        'notOWASP_D'    => '',
        'notCipher'     => '^GREASE|SCSV',  # pseudo ciphers with a valid hex key

        # RegEx containing pattern to identify vulnerable ciphers
            #
            # In a perfect (perl) world we can use negative lokups like
            #     (ABC)(?!XYZ)
            # which means: contains `ABC' but not `XYZ' where `XYZ' could be to
            # the right or left of `ABC'.
            # But in real world,  some perl implementations  fail to match such
            # pattern correctly. Hence we define two pattern:  one for positive
            # match and second for the negative (not) match. Both patterns must
            # be used programatically.
            # Key 'TYPE' must match and key 'notTYPE' must not match.
        # The following RegEx define what is "vulnerable":
            # NOTE: the  (?:SSL[23]?|TLS[12]|PCT1?[_-])  protocol prefix is not
            #       yet used in the checks,  but its optional in the RegEx here
            #       note also that internal strings are like SSLv2, TLSv11, etc
            #       which would not match the protocol prefix in the RegEx here
        'BEAST'     => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?.*?[_-]CBC',# borrowed from 'Lucky13'. There may be another better RegEx.
#       'BREACH'    => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?',
        'FREAK'     => '^(?:SSL[23]?)?(?:EXP(?:ORT)?(?:40|56|1024)?[_-])',
                       # EXP? is same as regex{EXPORT} above
        'notCRIME'  => '(?:NONE|NULL|^\s*$)',   # same as nocompression (see above)
#       'TIME'      => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?',
        'Lucky13'   => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?.*?[_-]CBC',
        'Logjam'    => 'EXP(?:ORT)?(?:40|56|1024)?[_-]',        # match against cipher
                       # Logjam is same as regex{EXPORT} above
        'POODLE'    => '^(?:SSL[23]?|TLS1)?[A-Z].*?[_-]CBC',    # must not match TLS11, hence [A-Z]
        'ROBOT'     => '^(?:(?:SSLv?3|TLSv?1(?:[12]))[_-])?(?:A?DH[_-])?(RC2|RC4|RSA)[_-]',
        'notROBOT'  => '(?:(?:EC)?DHE[_-])',                    # match against cipher
                       # ROBOT are all TLS_RCA except those with DHE or ECDHE
        'SLOTH'     => '(?:(EXP(?:ORT)?|NULL).*MD5$|EC(?:DHE|EDH)[_-]ECDSA[_-].*(?:MD5|SHA)$)',
        'Sweet32'   => '(?:[_-](?:CBC||CBC3|3DES|DES|192)[_-])',# match against cipher
        'notSweet32'=> '(?:[_-]AES[_-])',                       # match against cipher
        # The following RegEx define what is "not vulnerable":
        'PFS'       => '^(?:(?:SSLv?3|TLSv?1(?:[12])?|PCT1?)[_-])?((?:EC)?DHE|EDH)[_-]',
        'TR-02102'  => '(?:DHE|EDH)[_-](?:PSK[_-])?(?:(?:EC)?[DR]S[AS])[_-]',
                       # ECDHE_ECDSA | ECDHE_RSA | DHE_DSS | DHE_RSA PSK_ECDSS
                       # ECDHE_ECRSA, ECDHE_ECDSS or DHE_DSA does not exist, hence lazy RegEx above
        'notTR-02102'     => '[_-]SHA$',
                       # ciphers with SHA1 hash are not allowed
        'TR-02102-noPFS'  => '(?:EC)?DH)[_-](?:EC)?(?:[DR]S[AS])[_-]',
                       # if PFS not possible, see TR-02102-2_2016 3.3.1
        'TR-03116+' => 'EC(?:DHE|EDH)[_-](?:PSK|(?:EC)?(?:[DR]S[AS]))[_-]AES128[_-](?:GCM[_-])?SHA256',
        'TR-03116-' => 'EC(?:DHE|EDH)[_-](?:PSK|(?:EC)?(?:[DR]S[AS]))[_-]AES(?:128|256)[_-](?:GCM[_-])?SHA(?:256|384)',
                       # in strict mode only:
                       #  ECDHE-ECDSA-AES128.*SHA256 ECDHE-RSA-AES128.*SHA256 RSA-PSK-AES128-SHA256 ECDHE-PSK-AES128-SHA256
                       # in lazy mode (for curiosity) we also allow:
                       #  ECDHE-ECDSA-AES256.*SHA256 ECDHE-RSA-AES256.*SHA256
                       #  ECDHE-ECDSA-AES256.*SHA384 ECDHE-RSA-AES256.*SHA384
        'notTR-03116'     => '(?:PSK[_-]AES256|[_-]SHA$)',
                       # NOTE: for curiosity again, notTR-03116 is for strict mode only
        'RFC7525'   => 'EC(?:DHE|EDH)[_-](?:PSK|(?:EC)?(?:[DR]S[AS]))[_-]AES128[_-](?:GCM[_-])?SHA256',
        '1.3.6.1.5.5.7.1.1'  =>  '(?:1\.3\.6\.1\.5\.5\.7\.1\.1|authorityInfoAccess)',
        'NSA-B'     =>'(?:ECD(?:H|SA).*?AES.*?GCM.*?SHA(?:256|384|512))',

        # RegEx containing pattern for compliance checks
        # The following RegEx define what is "not compliant":
        'notISM'    => '(?:NULL|A(?:NON[_-])?DH|DH(?:A|[_-]ANON)[_-]|(?:^DES|[_-]DES)[_-]CBC[_-]|MD5|RC)',
        'notPCI'    => '(?:NULL|(?:A(?:NON[_-])?DH|DH(?:A|[_-]ANON)|(?:^DES|[_-]DES)[_-]CBC|EXP(?:ORT)?(?:40|56|1024)?)[_-])',
        'notFIPS-140'=>'(?:(?:ARC(?:4|FOUR)|RC4)|MD5|IDEA)',
        'FIPS-140'  => '(?:(?:3DES(?:[_-]EDE)[_-]CBC|DES[_-]CBC3)|AES)', # these are compliant

        # RegEx for checking invalid characers (used in compliance and EV checks)
        'nonprint'  => '/[\x00-\x1f\x7f-\xff]+/',          # not printable;  m/[:^print:]/
        'crnlnull'  => '/[\r\n\t\v\0]+/',                  # CR, NL, TABS and NULL

        # RegEx for checking EV-SSL
        # they should matching:   /key=value/other-key=other-value
        '2.5.4.10'  => '(?:2\.5\.4\.10|organizationName|O)',
        '2.5.4.11'  => '(?:2\.5\.4\.1?|organizationalUnitName|OU)',
        '2.5.4.15'  => '(?:2\.5\.4\.15|businessCategory)',
        '2.5.4.3'   => '(?:2\.5\.4\.3|commonName|CN)',
        '2.5.4.5'   => '(?:2\.5\.4\.5|serialNumber)',
        '2.5.4.6'   => '(?:2\.5\.4\.6|countryName|C)',
        '2.5.4.7'   => '(?:2\.5\.4\.7|localityName|L)',
        '2.5.4.8'   => '(?:2\.5\.4\.8|stateOrProvinceName|SP|ST)', # TODO: is ST a bug?
        '2.5.4.9'   => '(?:2\.5\.4\.9|street(?:Address)?)', # '/street=' is very lazy
        '2.5.4.17'  => '(?:2\.5\.4\.17|postalCode)',
#       '?.?.?.?'   => '(?:?\.?\.?\.?|domainComponent|DC)',
#       '?.?.?.?'   => '(?:?\.?\.?\.?|surname|SN)',
#       '?.?.?.?'   => '(?:?\.?\.?\.?|givenName|GN)',
#       '?.?.?.?'   => '(?:?\.?\.?\.?|pseudonym)',
#       '?.?.?.?'   => '(?:?\.?\.?\.?|initiala)',
#       '?.?.?.?'   => '(?:?\.?\.?\.?|title)',
        '1.3.6.1.4.1.311.60.2.1.1' => '(?:1\.3\.6\.1\.4\.1\.311\.60\.2\.1\.1|jurisdictionOfIncorporationLocalityName)',
        '1.3.6.1.4.1.311.60.2.1.2' => '(?:1\.3\.6\.1\.4\.1\.311\.60\.2\.1\.2|jurisdictionOfIncorporationStateOrProvinceName)',
        '1.3.6.1.4.1.311.60.2.1.3' => '(?:1\.3\.6\.1\.4\.1\.311\.60\.2\.1\.3|jurisdictionOfIncorporationCountryName)',

        'EV-chars'  => '[a-zA-Z0-9,./:= @?+\'()-]',         # valid characters in EV definitions
        'notEV-chars'=>'[^a-zA-Z0-9,./:= @?+\'()-]',        # not valid characters in EV definitions
        'EV-empty'  => '^(?:n\/a|(?:in|not )valid)\s*$',    # empty string, or "invalid" or "not valid"

    }, # regex
   #----------------------+----------------------------------------------------

    'hints' => {       # texts used for hints, SEE Note:hints
       # key for hints must be same as a command (without leading +), otherwise
       # it will not be used automatically.
       # 'key'      => "any string, may contain \t and \n",
       #--------------+--------------------------------------------------------
        'help=warnings' => "consider building the file using: 'make warnings-info'",
        'renegotiation' => "checks only if renegotiation is implemented serverside according RFC 5746 ",
        'drown'     => "checks only if the target server itself is vulnerable to DROWN ",
        'robot'     => "checks only if the target offers ciphers vulnerable to ROBOT ",
        'cipher'    => "+cipher : functionality changed, please see '$cfg__me --help=TECHNIC'",
        'cipherall' => "+cipherall : functionality changed, please see '$cfg__me --help=TECHNIC'",
        'cipherraw' => "+cipherraw : functionality changed, please see '$cfg__me --help=TECHNIC'",
        'openssl3'  => "OpenSSL 3.x changed some functionality, please see '$cfg__me --help=TECHNIC'",
        'openssl3c' => "+cipher fow OpenSSL 3.x may result in many warnings, consider using '--no-warning'",
       #--------------+--------------------------------------------------------
    }, # hints
   #------------------+--------------------------------------------------------
    'ourstr' => {
        # RegEx to match strings of our own output, see OUTPUT in o-saft-man.pm
        # first all that match a line at beginning:
        'error'     => qr(^\*\*ERR),            # see STR{ERROR}
        'warning'   => qr(^\*\*WARN),           # see STR{WARN}
        'hint'      => qr(^\!\!Hint),           # see STR{HINT}
        'info'      => qr(^\*\*INFO),           # see STR{INFO}
        'dbx'       => qr(^#dbx#),              # see STR{DBX}
        'headline'  => qr(^={1,3} ),            # headlines
        'keyline'   => qr(^#\[),                # dataline prefixed with key
        'verbose'   => qr(^#[^[]),              # verbose output
        # matches somewhere in the line:
        'undef'     => qr(\<\<undef),           # see STR{UNDEF}
        'yeast'     => qr(\<\<.*?\>\>),         # additional information
        'na'        => qr(N\/A),                # N/A
        'yes'       => qr(:\s*yes),             # good check result; # TODO: : needs to be $text{separator}
        'no'        => qr(:\s*no ),             # bad check result
    }, # ourstr
   #------------------+--------------------------------------------------------
    'compliance' => {           # description of RegEx above for compliance checks
        'TR-02102'  => "no RC4, only eclipic curve, only SHA256 or SHA384, need CRL and AIA, no wildcards, and verifications ...",
        'TR-03116'  => "TLSv1.2, only ECDSA, RSA or PSK ciphers, only eclipic curve, only SHA224 or SHA256, need OCSP-Stapling CRL and AIA, no wildcards, and verifications ...",
        'ISM'       => "no NULL cipher, no Anonymous Auth, no single DES, no MD5, no RC ciphers",
        'PCI'       => "no NULL cipher, no Anonymous Auth, no single DES, no Export encryption, DH > 1023",
        'FIPS-140'  => "must be TLSv1 or 3DES or AES, no IDEA, no RC4, no MD5",
        'FIPS-140-2'=> "-- NOT YET IMPLEMENTED --",      # TODO:
        'RFC7525'   => "TLS 1.2; AES with GCM; ECDHE and SHA256 or SHA384; HSTS",
        #
        # NIST SP800-52 recommendations for clients (best first):
        #   TLS_DHE_DSS_WITH_AES_256_CBC_SHA
        #   TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        #   TLS_RSA_WITH_AES_256_CBC_SHA
        #   TLS_DH_DSS_WITH_AES_256_CBC_SHA
        #   TLS_DH_RSA_WITH_AES_256_CBC_SHA
        #   TLS_DHE_DSS_WITH_AES_128_CBC_SHA
        #   TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        #   TLS_RSA_WITH_AES_128_CBC_SHA
        #   TLS_DH_DSS_WITH_AES_128_CBC_SHA
        #   TLS_DH_RSA_WITH_AES_128_CBC_SHA
        #   TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
        #   TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        #   TLS_RSA_WITH_3DES_EDE_CBC_SHA
        #   TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
        #   TLS_DH_RSA_WITH_3DES_EDE_CBC
        #   TLS_RSA_WITH_RC4_128_SHA2
        #
        # NIST SP800-52 recommendations for server (best first):
        #    same as above except TLS_RSA_WITH_RC4_128_SHA2
        #
        # Supported by (most) browsers (see SSL_comp_report2011.pdf):
        #   TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384  (IE8 only)
        #   TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA*
        #   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA*
        #   TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        #   TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        #   TLS_RSA_WITH_RC4_128_SHA
        #   TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
        #
        # NIST SP800-57 recommendations for key management (part 1):
        'NSA-B'     => "must be AES with CTR or GCM; ECDSA or ECDH and SHA256 or SHA512",
    },
    'sig_algorithms' => [       # signature algorithms; (2016) not yet used
        qw(
           dsaEncryption dsaEncryption-old dsaWithSHA dsaWithSHA1 dsa_With_SHA256
           ecdsa-with-SHA256
           md2WithRSAEncryption    md4WithRSAEncryption  md5WithRSAEncryption
           None   ripemd160WithRSA rsa  rsaEncryption    rsassapss
           shaWithRSAEncryption    sha1WithRSAEncryption sha1WithRSA
           sha224WithRSAEncryption sha256WithRSAEncryption
           sha384WithRSAEncryption sha512WithRSAEncryption
        ),
           "rsassapss (invalid pss parameters)"
    ],
    'sig_algorithm_common' => [ # most common signature algorithms; (2016) not yet used
        qw(None ecdsa-with-SHA256
           sha1WithRSAEncryption   sha256WithRSAEncryption
           sha384WithRSAEncryption sha512WithRSAEncryption
        )
    ],
   #------------------+-----------------+--------------------------------------
    'files' => {       # list of files used in the tool
        'RC-FILE'   => "",              # computed at startup
        'SELF'      => "o-saft.pl",
        'coding'    => "coding.txt",
        'glossary'  => "glossary.txt",
        'help'      => "help.txt",
        'links'     => "links.txt",
        'rfc'       => "rfc.txt",
        'tools'     => "tools.txt",
        # following are used in o-saft.tcl, but are generate with lib/OMan.pm
        # keys and values are initilized dynamically, see _ocfg_init() below
        # the keys --help* are used as pattern;
        # key=value looks like:  '--help=opts'  => "o-saft.pl.--help=opts"
        'pattern-help'  => [ qw( --help --help=rfc --help=alias --help=checks
                                 --help=commands   --help=data  --help=opts
                                 --help=warnings --help=glossar --help=regex
                                 --help=ciphers-text   --help=ciphers-text
                               ) ],
    }, # files
   #------------------+-----------------+--------------------------------------
    'done'      => {},          # defined in caller
); # %cfg

our %target_desc = (    # description of table used for printing targets
    #--------------+-----------------------------------------------------------
    # key             description
    #--------------+-----------------------------------------------------------
    'Nr'          , # unique index number, idx=0 used for default settings
    'Protocol'    , # protocol to be checked (schema in URL)
    'Host'        , # hostname or IP passed as argument, IPv6 enclosed in []
    'Port'        , # port as passed as argument or default
    'Auth'        , # authentication string used in URL, if any
    'Proxy'       , # proxy to be used for connection, index to cfg{targets}[]
                    # 0 if no proxy, -1 for a proxy itself
    'Path'        , # path used in URL
    'orig. Argument', # original argument, used for debugging only
    # following are run-time values
    'Time started', # timestamp, connection request started
    'Time opened' , # timestamp, connection request completed
    'Time stopped', # timestamp, connection closed
    'Errors'      , # encountered connection errors
                    # TODO: may be changed to list of errors in future
    #--------------+-----------------------------------------------------------
); # %target_desc

#                       Nr, Prot., Host, Port, Auth, Proxy, Path, orig., run-time ...
our @target_defaults = [ 0, "https", "", "443",  "",  0,    "", "<<defaults>>", 0, 0, 0, 0, ];
   # <<defaults>> just for documentation when printed with --v, --trace, etc.

our %dbx = (    # save hardcoded settings (command lists, texts), and debugging data
                # used in o-saft-dbx.pm only
    'argv'      => undef,       # normal options and arguments
    'cfg'       => undef,       # config options and arguments
    'exe'       => undef,       # executable, library, environment
    'files'     => undef,       # read files
    'cmd-check' => undef,
    'cmd-http'  => undef,
    'cmd-info'  => undef,
    'cmd-quick' => undef,
); # %dbx

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

# SEE Perl:Undefined subroutine
*_warn    = sub { print(join(" ", "**WARNING:", @_), "\n"); return; } if not defined &_warn;
*_dbx     = sub { print(join(" ", "#dbx#"     , @_), "\n"); return; } if not defined &_dbx;
*_trace   = sub {
     local $\ = undef;
     my $func = shift;  # avoid space after :: below
     print(join(" ", "#$cfg{'me'}::$func", @_), "\n") if (0 < $cfg{'trace'});
     return;
} if not defined &_trace;
*_trace1  = sub { _trace(@_) if (1 < $cfg{'trace'});        return; } if not defined &_trace1;
*_trace2  = sub { _trace(@_) if (2 < $cfg{'trace'});        return; } if not defined &_trace2;
*_trace3  = sub { _trace(@_) if (3 < $cfg{'trace'});        return; } if not defined &_trace3;

sub _get_keys_list {
    # workaround to avoid "Undefined subroutine ... " if called standalone
    # only used in test_cipher_regex()
    return Ciphers::get_keys_list() if (defined(&Ciphers::get_keys_list));
    return ();
} # _get_keys_list

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

=pod

=head3 tls_text2key($text)

Convert text to internal key: 0x00,0x26 -> 0x03000026

=head3 tls_key2text($key)

Convert internal key to text: 0x03000026 -> 0x00,0x26

=head3 tls_const2text($constant_name)

Convert TLS constant name to text (just replace _ by space).

=head3 tls_valid_key($text)

Return internal key if it is a valid cipher hex key, empty string otherwise.

=cut

sub tls_valid_key       {
    my $key =  shift;
       $key = "0x$key" if $key !~ m/^0x/;
    return ($key =~ m/^0x[0-9a-fA-F]{8}$/) ? $key : "-";
}

sub tls_text2key        {
    my $txt = shift;
       $txt =~ s/(,|0x)//g;     # TODO: check if valid hex
    if (4 < length($txt)) {
       $txt = "0x02$txt";       # SSLv2
    } else {
       $txt = "0x0300$txt";     # SSLv3, TLSv1.x
    }
    return $txt;
}

sub tls_key2text        {
    my $key = shift;            # TODO: check if valid hex
    if ($key =~ m/^0x0300/) {
       $key =~ s/0x0300//;      #   03000004 ->     0004
    } else {
       $key =~ s/^0x02//;       # 0x02030080 ->   030080
    }
       $key =~ s/(..)/,0x$1/g;  #       0001 -> ,0x00,0x04
       $key =~ s/^,//;          # ,0x00,0x04 ->  0x00,0x04
       $key =  "     $key" if (10 > length($key));
    return "$key";
}

sub tls_const2text      {  my $c=shift; $c =~ s/_/ /g; return $c; }

=pod

=head3 get_ciphers_range($range)

Get cipher suite hex values for given C<$range>.

=head3 get_cipher_owasp($cipher)

Get OWASP rating of given C<%cipher>.

=head3 get_openssl_version($cmd)

Call external $cmd (which is a full path for L<openssl|openssl>, usually) executable
to retrive its version. Returns version string.
=cut

sub get_ciphers_range   {
    #? retrun array of cipher-suite hex values for given range
    my $ssl   = shift;
    my $range = shift;
       $range = 'SSLv2' if ($ssl eq 'SSLv2');   # but SSLv2 needs its own list
    my @all;
    _trace2("get_ciphers_range($ssl, $range)");
    #  NOTE: following eval must not use the block form because the value
    #        needs to be evaluated
    goto FIN if not exists $cfg{'cipherranges'}->{$range};
    goto FIN if ($cfg{'cipherranges'}->{$range} !~ m/^[x0-9A-Fa-f,.\s]+$/); # if someone tries to inject ...
    foreach my $c (eval($cfg{'cipherranges'}->{$range}) ) { ## no critic qw(BuiltinFunctions::ProhibitStringyEval)
        push(@all, sprintf("0x%08X",$c));
    }
    FIN:
    _trace2("get_ciphers_range()\t= @all");
    return @all;
} # get_ciphers_range

sub get_cipher_owasp    {
    #? return OWASP rating for cipher suite name (see $cfg{regex}->{{OWASP_*}
    my $cipher  = shift;
    my $sec     = "miss";
    _trace2("get_cipher_owasp($cipher, $sec)");
    return  $sec if not defined $cipher;    # defensive programming (key missing in %ciphers)
    return  $sec if ($cipher =~ m/^\s*$/);  # ..
    # following sequence is important:
    $sec = "-?-" if ($cipher =~ /$cfg{'regex'}->{'OWASP_NA'}/); # unrated in OWASP TLS Cipher Cheat Sheet (2018)
    $sec = "C"   if ($cipher =~ /$cfg{'regex'}->{'OWASP_C'}/);  # 1st legacy
    $sec = "B"   if ($cipher =~ /$cfg{'regex'}->{'OWASP_B'}/);  # 2nd broad compatibility
    $sec = "A"   if ($cipher =~ /$cfg{'regex'}->{'OWASP_A'}/);  # 3rd best practice
    $sec = "D"   if ($cipher =~ /$cfg{'regex'}->{'OWASP_D'}/);  # finally brocken ciphers, overwrite previous
    if (" D" ne $sec) {     # if it is A, B or C check OWASP_NA again
        $sec = "-?-" if ($cipher =~ /$cfg{'regex'}->{'OWASP_NA'}/);
    }
    $sec = "A"   if ($cipher =~ /$cfg{'regex'}->{'OWASP_AA'}/); # some special for TLSv1.3 only, always secure
    $sec = "-"   if ($cipher =~ /$cfg{'regex'}->{'notCipher'}/); # some specials
    # TODO: implement when necessary: notOWASP_A, notOWASP_B, notOWASP_C, notOWASP_D
    _trace2("get_cipher_owasp()\t= $sec");
    return $sec;
} # get_cipher_owasp

sub get_openssl_version {
    # we do a simple call, no checks, should work on all platforms
    # get something like: OpenSSL 1.0.1k 8 Jan 2015
    my $cmd     = shift;    # assume that $cmd cannot be injected
    my $data    = qx($cmd version); ## no critic qw(InputOutput::ProhibitBacktickOperators)
    chomp $data;
    _trace("get_openssl_version: $data");
    $data =~ s#^.*?(\d+(?:\.\d+)*).*$#$1#; # get version number without letters
    _trace("get_openssl_version()\t= $data");
    return $data;
} # get_openssl_version


=pod

=head3 get_dh_paramter($cipher, $data)

Parse output of `openssl -msg' (given in $data) and returns DH parameters.
Returns empty string if none found.
=cut

sub get_dh_paramter     {
    my ($cipher, $data) = @_;
    if ($data =~ m#Server Temp Key:#) {
        $data =~ s/.*?Server Temp Key:\s*([^\n]*)\n.*/$1/si;
        _trace("get_dh_paramter(){ Server Temp Key\t= $data }");
        return $data;
    }
    # else continue extracting DH parameters from ServerKeyExchange-Message
    my $dh = "";
    # we may get a ServerKeyExchange-Message with the -msg option
    # <<< TLS 1.2 Handshake [length 040f], ServerKeyExchange
    #     0c 00 04 0b 01 00 c1 41 38 da 2e b3 7e 68 71 31
    #     86 da 01 e5 95 fa 7e 83 9b a2 28 1b a5 fb d2 72
    #     ...
    # >>> TLS 1.2 ChangeCipherSpec [length 0001]
    return "" if ($data !~ m#ServerKeyExchange#);

    # this is a long RegEx and cannot be chunked
    ## no critic qw(RegularExpressions::ProhibitComplexRegexes)
    $data =~ s{
            .*?Handshake
            \s*?\[length\s*([0-9a-fA-F]{2,4})\]\,?
            \s*?ServerKeyExchange
            \s*[\n\r]+(.*?)
            [\n\r][<>]+.*
        }
        {$1_$2}xsi;
    ## use critic
    _trace("get_dh_paramter: #{ DHE RAW data:\n$data\n#}\n");
    $data =~ s/\s+/ /gi;          # squeeze multible spaces
    $data =~ s/[^0-9a-f_]//gi;    # remove all none hex characters and non separator
    my ($lenStr, $len) = 0;
    ($lenStr, $data) = split(/_/, $data);   # 2 strings with Hex Octetts!
    _trace3("get_dh_paramter: #{ DHE RAW data): len: $lenStr\n$data\n#}\n");
    $len = hex($lenStr);
    my $message = pack("H*", $data);

    # parse message header
    my $msgData = "";
    my ($msgType, $msgFirstByte, $msgLen) = 0;
       ($msgType,       # C
        $msgFirstByte,  # C
        $msgLen,        # n
        $msgData)   = unpack("C C n a*", $message);

    if (0x0C == $msgType) { # is ServerKeyExchange
        # get info about the session cipher and prepare parameter $keyExchange
        # for parseServerKeyExchange()
        my $keyExchange = $cipher;
        _trace1("get_dh_paramter: cipher: $keyExchange");
        $keyExchange =~ s/^((?:EC)?DHE?)_anon.*/A$1/;   # DHE_anon -> EDH, ECDHE_anon -> AECDH, DHE_anon -> ADHE
        $keyExchange =~ s/^((?:EC)?DH)E.*/E$1/;         # DHE -> EDH, ECDHE -> EECDH
        $keyExchange =~ s/^(?:E|A|EA)((?:EC)?DH).*/$1/; # EDH -> DH, ADH -> DH, EECDH -> ECDH
        _trace1(" get_dh_paramter: keyExchange (DH or ECDH) = $keyExchange");
        # get length of 'dh_parameter' manually from '-msg' data if the
        # 'session cipher' uses a keyExchange with DHE and DH_anon
        # (according RFC 2246/RFC 5246: sections 7.4.3)
        $dh = Net::SSLhello::parseServerKeyExchange($keyExchange, $msgLen, $msgData);
    }

    chomp $dh;
    _trace("get_dh_paramter(){ ServerKeyExchange\t= $dh }");
    return $dh;
} # get_dh_paramter

# TODO: get_target_* and set_target_* should be named get_cfg_target_* ...

=pod

=head3 get_target_nr($idx)

=head3 get_target_prot($idx)

=head3 get_target_host($idx)

=head3 get_target_port($idx)

=head3 get_target_auth($idx)

=head3 get_target_proxy($idx)

=head3 get_target_path($idx)

=head3 get_target_orig($idx)

=head3 get_target_start($idx)

=head3 get_target_open($idx)

=head3 get_target_stop($idx)

=head3 get_target_error($idx)

Get information from internal C<%cfg{'targets'}> data structure.

=head3 set_target_nr($idx, $index)

=head3 set_target_prot($idx, $protocol)

=head3 set_target_host($idx, $host_or_IP)

=head3 set_target_port($idx, $port)

=head3 set_target_auth($idx, $auth-string)

=head3 set_target_proxy($idx, $proxy-index))

=head3 set_target_path($idx $path)

=head3 set_target_orig($idx, $original-argument))

=head3 set_target_start($idx, $start-timestamp)

=head3 set_target_open($idx, $open-timestamp)

=head3 set_target_stop($idx, $end-timestamp)

=head3 set_target_error($idx, $errors)

Set information in internal C<%cfg{'targets'}> data structure.

=head3 set_user_agent($txt)

Set User-Agent to be used in HTTP requests in internal C<%cfg{'use'}> .


=cut

sub get_target_nr    { my $i=shift; return $cfg{'targets'}[$i][0];  }
sub get_target_prot  { my $i=shift; return $cfg{'targets'}[$i][1];  }
sub get_target_host  { my $i=shift; return $cfg{'targets'}[$i][2];  }
sub get_target_port  { my $i=shift; return $cfg{'targets'}[$i][3];  }
sub get_target_auth  { my $i=shift; return $cfg{'targets'}[$i][4];  }
sub get_target_proxy { my $i=shift; return $cfg{'targets'}[$i][5];  }
sub get_target_path  { my $i=shift; return $cfg{'targets'}[$i][6];  }
sub get_target_orig  { my $i=shift; return $cfg{'targets'}[$i][7];  }
sub get_target_start { my $i=shift; return $cfg{'targets'}[$i][8];  }
sub get_target_open  { my $i=shift; return $cfg{'targets'}[$i][9];  }
sub get_target_stop  { my $i=shift; return $cfg{'targets'}[$i][10]; }
sub get_target_error { my $i=shift; return $cfg{'targets'}[$i][11]; }
sub set_target_nr    { my $i=shift; $cfg{'targets'}[$i][0]  = shift; return; }
sub set_target_prot  { my $i=shift; $cfg{'targets'}[$i][1]  = shift; return; }
sub set_target_host  { my $i=shift; $cfg{'targets'}[$i][2]  = shift; return; }
sub set_target_port  { my $i=shift; $cfg{'targets'}[$i][3]  = shift; return; }
sub set_target_auth  { my $i=shift; $cfg{'targets'}[$i][4]  = shift; return; }
sub set_target_proxy { my $i=shift; $cfg{'targets'}[$i][5]  = shift; return; }
sub set_target_path  { my $i=shift; $cfg{'targets'}[$i][6]  = shift; return; }
sub set_target_orig  { my $i=shift; $cfg{'targets'}[$i][7]  = shift; return; }
sub set_target_start { my $i=shift; $cfg{'targets'}[$i][8]  = shift; return; }
sub set_target_open  { my $i=shift; $cfg{'targets'}[$i][9]  = shift; return; }
sub set_target_stop  { my $i=shift; $cfg{'targets'}[$i][10] = shift; return; }
sub set_target_error { my $i=shift; $cfg{'targets'}[$i][11] = shift; return; }
sub set_user_agent   { my $t=shift; $cfg{'use'}->{'user_agent'} = $t;return; }


=pod

=head3 OCfg::ocfg_sleep($wait)

Wrapper to simulate "sleep" with perl's select.

=head3 OCfg::printhint($cmd,@text)

Print hint for specified command, additionl text will be appended.

=cut

sub ocfg_sleep      {
    #? wrapper for IO::select
    my $wait = shift;
    select(undef, undef, undef, $wait); ## no critic qw(BuiltinFunctions::ProhibitSleepViaSelect)
    return;
} # ocfg_sleep

sub printhint       {
    #? Print hint for specified command.
    my $cmd  = shift;
    my @args = @_;
    print $STR{HINT}, $cfg{'hints'}->{$cmd}, join(" ", @args) if (defined $cfg{'hints'}->{$cmd});
    return;
} # printhint

=pod

=head3 OCfg::test_cipher_regex( )

Internal test function: apply regex to intended text/list.

=cut


#_____________________________________________________________________________
#____________________________________________________ internal test methods __|

sub _regex_head     { return sprintf("= %s\t%s\t%s\t%s", "PFS", "OWASP", "owasp", "cipher"); }
sub _regex_line     { return "=------+-------+-------+---------------------------------------"; }

sub test_cipher_regex   {
    #? check regex if cipher supports PFS, uses internal sub and not regex directly
    local $\ = "\n";
    print "
=== internal data structure: various RegEx to check cipher properties ===
=
= Check RegEx to detect ciphers, which support PFS using the internal function
= ::_is_ssl_pfs() .
    \$cfg{'regex'}->{'PFS'}:      # match ciphers supporting PFS
      $cfg{'regex'}->{'PFS'}
=
= Check to which RegEx for OWASP scoring a given cipher matches.
=
    \$cfg{'regex'}->{'OWASP_NA'}: # unrated in OWASP TLS Cipher Cheat Sheet (2018)
      $cfg{'regex'}->{'OWASP_NA'}
    \$cfg{'regex'}->{'OWASP_C'}:  # 1st legacy
      $cfg{'regex'}->{'OWASP_C'}
    \$cfg{'regex'}->{'OWASP_B'}:  # 2nd broad compatibility
      $cfg{'regex'}->{'OWASP_B'}
    \$cfg{'regex'}->{'OWASP_A'}:  # 3rd best practice
      $cfg{'regex'}->{'OWASP_A'}
    \$cfg{'regex'}->{'OWASP_D'}:  # finally brocken ciphers, overwrite previous
      $cfg{'regex'}->{'OWASP_D'}
    \$cfg{'regex'}->{'OWASP_AA'}: # last secure TLSv1.3
      $cfg{'regex'}->{'OWASP_AA'}
=
";
    print _regex_head();
    print _regex_line();
    foreach my $key (sort (_get_keys_list())) {
        my $ssl    = Ciphers::get_ssl( $key);
        my $cipher = Ciphers::get_name($key);
        my $is_pfs = (::_is_ssl_pfs($ssl, $cipher) eq "") ? "no" : "yes";
        my @o = ('', '', '', '', '');
        # following sequence of check should be the same as in get_cipher_owasp()
        $o[4] = "-?-" if ($cipher =~ /$cfg{'regex'}->{'OWASP_NA'}/);
        $o[2] = "C"   if ($cipher =~ /$cfg{'regex'}->{'OWASP_C'}/);
        $o[1] = "B"   if ($cipher =~ /$cfg{'regex'}->{'OWASP_B'}/);
        $o[0] = "A"   if ($cipher =~ /$cfg{'regex'}->{'OWASP_A'}/);
        $o[3] = "D"   if ($cipher =~ /$cfg{'regex'}->{'OWASP_D'}/);
        $o[0] = "A"   if ($cipher =~ /$cfg{'regex'}->{'OWASP_AA'}/);
        if ($cipher =~ /$cfg{'regex'}->{'notCipher'}/) {
            $is_pfs =  '-';
            $o[0]   = "-";
        }
        printf("  %s\t%s\t%s\t%s\n", $is_pfs, get_cipher_owasp($cipher), join("", @o), $cipher);
    }
    print _regex_line();
    print _regex_head();
    print <<'EoT';
= PFS values:
=   yes   cipher supports PFS
=   no    cipher does not supports PFS
=   -     pseudo cipher
= OWASP values:
=   x     value A or B or C or D or -?- as returned by get_cipher_owasp()
=   miss  cipher not matched by any RegEx, programming error
=   -     pseudo cipher
= owasp values:
=   xx    list of all matching OWASP_x RegEx (OWASP column picks best one)
EoT
    return;
} # test_cipher_regex

sub test_cipher_sort    {
    #? check sorting cipher according strength
    # TODO: see ../o-saft-dbx.pm  _yeast_ciphers_sorted()
    return;
} # test_cipher_sort

#_____________________________________________________________________________
#___________________________________________________ initialisation methods __|

sub _prot_init_value    {
    #? initialise default values in %prot
    foreach my $ssl (keys %prot) {
        $prot{$ssl}->{'cnt'}            = 0;
        $prot{$ssl}->{'-?-'}            = 0;
        $prot{$ssl}->{'WEAK'}           = 0;
        $prot{$ssl}->{'LOW'}            = 0;
        $prot{$ssl}->{'MEDIUM'}         = 0;
        $prot{$ssl}->{'HIGH'}           = 0;
        $prot{$ssl}->{'OWASP_AA'}       = 0;
        $prot{$ssl}->{'OWASP_A'}        = 0;
        $prot{$ssl}->{'OWASP_B'}        = 0;
        $prot{$ssl}->{'OWASP_C'}        = 0;
        $prot{$ssl}->{'OWASP_D'}        = 0;
        $prot{$ssl}->{'OWASP_NA'}       = 0;
        $prot{$ssl}->{'OWASP_miss'}     = 0;    # for internal use
        $prot{$ssl}->{'protocol'}       = 0;
        $prot{$ssl}->{'ciphers_pfs'}    = [];
        $prot{$ssl}->{'cipher_pfs'}     = $STR{UNDEF};
        $prot{$ssl}->{'default'}        = $STR{UNDEF};
        $prot{$ssl}->{'cipher_strong'}  = $STR{UNDEF};
        $prot{$ssl}->{'cipher_weak'}    = $STR{UNDEF};
    }
    return;
} # _prot_init_value

sub _cfg_init       {
    #? initialise dynamic settings in %cfg, copy data from %prot
    # initialise targets with entry containing defaults
    push(@{$cfg{'targets'}}, @target_defaults);
    $cfg{'openssl_option_map'} ->{$_} = $prot{$_}->{'opt'} foreach (keys %prot);
    $cfg{'openssl_version_map'}->{$_} = $prot{$_}->{'hex'} foreach (keys %prot);
    $cfg{'protos_alpn'} = [split(/,/, $cfg{'protos_next'})];
    $cfg{'protos_npn'}  = [split(/,/, $cfg{'protos_next'})];
    # initialise alternate protocols and curves for cipher checks
    $cfg{'cipher_alpns'}= [split(/,/, $cfg{'protos_next'})];
    $cfg{'cipher_npns'} = [split(/,/, $cfg{'protos_next'})];
    # incorporate some environment variables
    $cfg{'openssl_env'} = $ENV{'OPENSSL'}      if (defined $ENV{'OPENSSL'});
    $cfg{'openssl_cnf'} = $ENV{'OPENSSL_CONF'} if (defined $ENV{'OPENSSL_CONF'});
    $cfg{'openssl_fips'}= $ENV{'OPENSSL_FIPS'} if (defined $ENV{'OPENSSL_FIPS'});
    # initialise cipherranges
    $cfg{'cipherranges'}->{'SSLv2'}        = $cfg{'cipherranges'}->{'SSLv2_base'}
                                           . $cfg{'cipherranges'}->{'SSLv2_rfc'}
                                           . $cfg{'cipherranges'}->{'SSLv2_FIPS'};
    $cfg{'cipherranges'}->{'SSLv2_long'}   = $cfg{'cipherranges'}->{'SSLv2_base'}
                                           . $cfg{'cipherranges'}->{'SSLv2_rfc+'}
                                           . $cfg{'cipherranges'}->{'SSLv2_FIPS'};
    $cfg{'cipherranges'}->{'SSLv3_SSLv2'}  = $cfg{'cipherranges'}->{'SSLv2_base'}
                                           . $cfg{'cipherranges'}->{'SSLv2_rfc+'}
                                           . $cfg{'cipherranges'}->{'SSLv3'};
    $cfg{'cipherranges'}->{'TLSv10'}       = $cfg{'cipherranges'}->{'SSLV3'};
    $cfg{'cipherranges'}->{'TLSv11'}       = $cfg{'cipherranges'}->{'SSLV3'};
    $cfg{'cipherranges'}->{'rfc'}         .= $cfg{'cipherranges'}->{'GREASE'};
    $cfg{'cipherranges'}->{'shifted'}     .= $cfg{'cipherranges'}->{'rfc'};
    $cfg{'cipherranges'}->{'TLSv13'}      .= $cfg{'cipherranges'}->{'GREASE'};
    $cfg{'cipherranges'}->{'intern'}       = $cfg{'cipherranges'}->{'shifted'};
    return;
} # _cfg_init

sub _cmd_init       {
    #? initialise dynamic settings in %cfg for commands
    foreach my $key (sort keys %cfg) {  # well-known "summary" commands
        push(@{$cfg{'commands_cmd'}}, $key) if ($key =~ m/^cmd-/);
    }
    # SEE Note:Testing, sort
    @{$cfg{'commands_cmd'}} = sort(@{$cfg{'commands_cmd'}});
    @{$cfg{'cmd-info--v'}}  = sort(@{$cfg{'cmd-info--v'}});
    return;
} # _cmd_init

sub _doc_init       {
    #? initialise dynamic settings for path names, mainly documentation files
    # key=value looks like:  '--help=opts'  => "doc/o-saft.pl.--help=opts"
    # o-saft.pl must be hardcoded
    # ensure that files are located in directory where executed $0 resides
    foreach my $k (@{$cfg{'files'}->{'pattern-help'}}) {
        my $_path = $0;     $_path =~ s#[/\\][^/\\]*$##;
        $cfg{'files'}->{$k} = join("/", $_path, $cfg{'dirs'}->{'doc'}, "o-saft.pl.$k");
    }
    return;
} # _cmd_init

sub _dbx_init       {
    #? initialise settings for debugging
    $dbx{'cmd-check'} = $cfg{'cmd-check'};
    $dbx{'cmd-http'}  = $cfg{'cmd-http'};
    $dbx{'cmd-info'}  = $cfg{'cmd-info'};
    $dbx{'cmd-quick'} = $cfg{'cmd-quick'};
    push(@{$dbx{'files'}}, "lib/OCfg.pm");  # set myself
    return;
} # _dbx_init

sub _ocfg_init      {
    #? additional generic initialisations for data structures
    my $me =  $0;       # done here to instead of package's "main" to avoid
       $me =~ s#.*[/\\]##;  # multiple variable definitions of $me
    $cfg{'me'}      = $me;
    $cfg{'RC-FILE'} = "./.$me";
    $cfg{'ARG0'}    = $0;
    $cfg{'ARGV'}    = [@ARGV];
    $cfg{'prefix_trace'}    = "#${me}::";
    $cfg{'prefix_verbose'}  = "#${me}: ";
    _prot_init_value(); # initallise WEAK, LOW, MEDIUM, HIGH, default, pfs, protocol
    _cfg_init();        # initallise dynamic data in %cfg
    _cmd_init();        # initallise dynamic commands in %cfg
    _dbx_init();        # initallise debugging data in %dbx
    _doc_init();        # initialise dynamic settings for documentation files
    foreach my $k (keys %data_oid) {
        $data_oid{$k}->{val} = "<<check error>>"; # set a default value
    }
    $me = $cfg{'mename'}; $me =~ s/\s*$//;
    set_user_agent("$me/3.14"); # default version; needs to be corrected by caller
    return;
} # _ocfg_init

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

sub _ocfg_main      {
    #? print own documentation or special required one
    my @argv = @_;
    push(@argv, "--help") if (0 > $#argv);
    binmode(STDOUT, ":unix:utf8");
    binmode(STDERR, ":unix:utf8");
    # got arguments, do something special
    while (my $arg = shift @argv) {
        # ----------------------------- commands
        if ($arg =~ m/^--?h(?:elp)?$/)   {
            OText::print_pod($0, __FILE__, $SID_ocfg);
            exit 0;
        }
        if ($arg =~ /^version$/)         { print "$SID_ocfg\n"; next; }
        if ($arg =~ /^[-+]?V(ERSION)?$/) { print "$OCfg::VERSION\n";   next; }
        if ($arg =~ m/^--(?:test[_.-]?)regex/) {
            $arg = "--test-regex";
            test_cipher_regex();    # fails with: Undefined subroutine &Ciphers::get_keys_list called at ...
            printf("#$0: direct testing not yet possible, please try:\n   o-saft.pl $arg\n");
        }
    }
    exit 0;
} # _ocfg_main

sub ocfg_done      {};  # dummy to check successful include

_ocfg_init();           # complete initialisations

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=head1 SEE ALSO

# ...

=head1 VERSION

3.14 2024/02/19

=head1 AUTHOR

28-dec-15 Achim Hoffmann

=cut

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_ocfg_main(@ARGV) if (not defined caller);

1;

