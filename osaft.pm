#!/usr/bin/perl

# TODO: implement
#    require "o-saft-lib" "full";  # or "raw"
#	full: anything for o-saft.pl; raw partial for SSLhello.pm
# TODO: see comment at %cipher_names

## PACKAGE {
package osaft;

use strict;
use warnings;

use constant {
    OSAFT_VERSION   => '17.07.17',  # official version number of tis file
  # STR_VERSION => 'dd.mm.yy',      # this must be defined in calling program
    STR_ERROR   => "**ERROR: ",
    STR_WARN    => "**WARNING: ",
    STR_HINT    => "!!Hint: ",
    STR_USAGE   => "**USAGE: ",
    STR_DBX     => "#dbx# ",
    STR_UNDEF   => "<<undef>>",
    STR_NOTXT   => "<<>>",
    OSAFT_SID   => '@(#) o-saft-lib.pm 1.123 17/07/17 13:19:05',

};

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

# more public documentation, see start of methods section, and at end of file.

## no critic qw(Documentation::RequirePodSections)
#  our POD below is fine, perlcritic (severity 2) is too pedantic here.

=pod

=encoding utf8

=head1 NAME

o-saft-lib -- common perl modul for O-Saft and related tools

=head1 SYNOPSIS

    o-saft-lib.pm           # on command line will print help

Thinking perlish, there are two variants to use this module and its constants
and variables:

=over 4

=item 1. Variant with BEGIN

    BEGIN {
        require "o-saft-lib.pm";    # file may have any name
        ...
    }
    ...
    use strict;
    print "a constant : " . osaft::STD_HINT;
    print "a variable : " . $osaft::var;

=item 2. Variant outside BEGIN

    BEGIN {
        ...
    }
    use strict;
    use osaft;                      # file must be named  osaft.pm
    ...
    print "a constant : " . STD_HINT
    print "a variable : " . $var;

=back

None of the constants, variables, or methods should be defined in the caller,
otherwise the calling script must handle warnings properly.

=head1 OPTIONS

=head1 DESCRIPTION

Utility package for O-Saft (o-saft.pl and related tools). This package declares
and defines common L</VARIABLES> and L</METHODS> to be used in the calling tool.
All variables and methods are defined in the  osaft::  namespace.

=head2 Used Functions

Following functions (methods) must be defined in the calling program:

=over 4

=item _trace( )

=item _trace1( )

=item _trace2( )

=item _trace3( )

=back

=head1 CONSTANTS

=over 4

=item STR_ERROR

=item STR_WARN

=item STR_HINT

=item STR_USAGE

=item STR_DBX

=item STR_UNDEF

=item STR_NOTXT

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

=item %tls_extensions

=item %tls_curve_types

=item %tls_curves

=item %data_oid

=item %ciphers

=item %ciphers_desc

=item %cipher_names

=item %cipher_alias

=item %cipher_results

=back

=head1 METHODS

Only getter and setter methods are exported. All other methods must be used
with the full package name.

=cut

## no critic qw(Modules::ProhibitAutomaticExportation, Variables::ProhibitPackageVars)
# FIXME: perlcritic complains to use @EXPORT_OK instead of @EXPORT, but that
#        is not possible as long as constants are exported;
#        should be changed when "use constant" is replaced by "use Readonly"
# FIXME: perlcritic complains to not declare (global) package variables, but
#        the purpose of this module is to do that. This may change in future.

# See NOTES below also.

use Exporter qw(import);
use base qw(Exporter);
#our @ISA        = qw(Exporter);
our $VERSION    = OSAFT_VERSION;
our @EXPORT     = qw(
                STR_ERROR
                STR_WARN
                STR_HINT
                STR_USAGE
                STR_DBX
                STR_UNDEF
                STR_NOTXT
                %prot
                %prot_txt
                %tls_handshake_type
                %tls_record_type
                %tls_error_alerts
                %tls_extensions
                %tls_curve_types
                %tls_curves
                %data_oid
                %dbx
                %cfg
                %ciphers_desc
                %ciphers
                %cipher_names
                %cipher_alias
                @cipher_results
                get_cipher_suitename
                get_cipher_suiteconst
                get_cipher_suitealias
                get_cipher_sec
                get_cipher_ssl
                get_cipher_enc
                get_cipher_bits
                get_cipher_mac
                get_cipher_auth
                get_cipher_keyx
                get_cipher_score
                get_cipher_tags
                get_cipher_desc
                get_cipher_hex
                get_cipher_name
                get_openssl_version
                get_dh_paramter
                sort_cipher_names
                printhint
                osaft_done
);
# insert above in vi with:
# :r !sed -ne 's/^sub \([a-zA-Z][^ (]*\).*/\t\t\1/p' %
# :r !sed -ne 's/^our \([\%$@][a-zA-Z0-9_][^ (]*\).*/\t\t\1/p' %
# :r !sed -ne 's/^ *\(STR_[A-Z][^ ]*\).*/\t\t\1/p' %

#_____________________________________________________________________________
#________________________________________________________________ variables __|

our %prot   = (     # collected data for protocols and ciphers
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
   #'TLS_FALLBACK_SCSV'=>{'txt'=> "SCSV", 'hex' => 0x5600,  'opt' => undef      },
    #-----------------------+--------------+----------------+------------------+---+---+---+---
    # see _prot_init_value() for following values in
    #   "protocol"=> {cnt, -?-, WEAK, LOW, MEDIUM, HIGH, protocol}
    #   "protocol"=> {cipher_pfs, ciphers_pfs, default, cipher_strong, cipher_weak}
    # Notes:
    #  TLS1FF   0x03FF  # last possible version of TLS1.x (not specified, used internal)
    #  DTLSv09: 0x0100  # DTLS, OpenSSL pre 0.9.8f, not finally standardized; some versions use 0xFEFF
    #  DTLSv09: -dtls   # never defined and used in openssl
    #  DTLSv1   0xFEFF  # DTLS1.0 (udp)
    #  DTLSv11  0xFEFE  # DTLS1.1: has never been used (udp)
    #  DTLSv12  0xFEFD  # DTLS1.2 (udp)
    #  DTLSv13  0xFEFC  # DTLS1.3, NOT YET specified (udp)
    #  DTLSfamily       # DTLS1.FF, no defined PROTOCOL, for internal use only
    #  fallback         # no defined PROTOCOL, for internal use only
    # 'hex' value will be copied to $cfg{'openssl_version_map'} below
    # 'opt' value will be copied to $cfg{'openssl_option_map'}  below
    # TODO: hex value should be same as %_SSLmap in Net::SSLinfo
); # %prot

our %prot_txt = (
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
    'hello_request'         => 0,
    'client_hello'          => 1,
    'server_hello'          => 2,
    'hello_verify_request'  => 3,       # RFC4347 DTLS
    'certificate'           => 11,
    'server_key_exchange'   => 12,
    'certificate_request'   => 13,
    'server_hello_done'     => 14,
    'certificate_verify'    => 15,
    'client_key_exchange'   => 16,
    'finished'              => 20,
    'certificate_url'       => 21,      # RFC6066 10.2
    'certificate_status'    => 22,      # RFC6066 10.2
    '255'                   => 255,
    '<<undefined>>'         => -1,      # added for internal use
    '<<fragmented_message>>'=> -99      # added for internal use
); # tls_handshake_type

our %tls_record_type = (
    'change_cipher_spec'    => 20,
    'alert'                 => 21,
    'handshake'             => 22,
    'application_data'      => 23,
    'heartbeat'             => 24,
    '255'                   => 255,
    '<<undefined>>'         => -1       # added for internal use
); # %tls_record_type

our %tls_error_alerts = ( # mainly RFC6066
    #----+-------------------------------------+----+--+---------------
    # ID      name                              RFC DTLS OID
    #----+-------------------------------------+----+--+---------------
    0 => [qw( close_notify                      6066  Y  -)],
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
   86 => [qw( inappropriate_fallback            RFC5246_update-Draft-2014-05-31  Y  -)], # added according 'https://datatracker.ietf.org/doc/draft-bmoeller-tls-downgrade-scsv/?include_text=1'
   90 => [qw( user_canceled                     6066  Y  -)],
  100 => [qw( no_renegotiation                  6066  Y  -)],
  110 => [qw( unsupported_extension             6066  Y  -)],
  111 => [qw( certificate_unobtainable          6066  Y  -)],
  112 => [qw( unrecognized_name                 6066  Y  -)],
  113 => [qw( bad_certificate_status_response   6066  Y  -)],
  114 => [qw( bad_certificate_hash_value        6066  Y  -)],
  115 => [qw( unknown_psk_identity              4279  Y  -)],
    #----+-------------------------------------+----+--+---------------
); # %tls_error_alerts

our %tls_extensions = ( # RFC 6066
    #----+-----------------------------+----+---+------------------------------
    # ID      name                      RFC DTLS other names
    #----+-----------------------------+----+---+------------------------------
    0 => [qw( server_name               ????  -   )],
    1 => [qw( max_fragment_length       ????  -   )],
    2 => [qw( client_certificate_url    ????  -   )],
    3 => [qw( trusted_ca_keys           ????  -   )],
    4 => [qw( truncated_hmac            ????  -   )],
    5 => [qw( status_request            ????  -   )],
    6 => [qw( user_mapping              ????  -   )],
    7 => [qw( reserved_7                ????  -   )],
    8 => [qw( reserved_8                ????  -   )],
    9 => [qw( cert_tape                 5081  -   )],
   10 => [qw( ecliptic_curves           4492  -   )],
   11 => [qw( ec_point_formats          4492  -   )],
   12 => [qw( srp                       5054  -   )],
   13 => [qw( signature_algorithms      5246  -   )],
#  14 => [qw( unassigned                5246  -   )],
#  ...
#  34 => [qw( unassigned                5246  -   )],
   35 => [qw( SessionTicket             4507  -   )],
65535 => [qw( 65535                     ????  -   )],
); # %tls_extensions

my %tls_extensions__text = ( # TODO: this information needs to be added to %tls_extensions above
    'extension' => {            # TLS extensions
        '00000'     => "renegotiation info length",     # 0x0000 ??
        '00001'     => "renegotiation length",          # 0x0001 ??
        '00010'     => "elliptic curves",               # 0x000a length=4
        '00011'     => "EC point formats",              # 0x000b length=2
        '00015'     => "heartbeat",                     # 0x000f length=1
        '00035'     => "session ticket",                # 0x0023 length=0
        '13172'     => "next protocol",                 # 0x3374 length=NNN
        '65281'     => "renegotiation info",            # 0xff01 length=1
    },
); # %tls_extensions__text

our %ec_point_formats = ( # RFC 4492
    # http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
    #----+-----------------------------+----+---+------------------------------
    # ID      name                      RFC  DTLS other names
    #----+-----------------------------+----+---+------------------------------
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
    #----+-----------------------------+----+---+------------------------------
    # ID      name                      RFC DTLS other names
    #----+-----------------------------+----+---+------------------------------
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
    #----+-----------------------------+----+---+------------------------------
); # ec_curve_types

# Torsten: %ECC_NAMED_CURVE = 
# http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-10
# Value =>   Description bits(added) DTLS-OK Reference
# our %named_curves =
our %tls_curves = (
    # http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
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

our %data_oid = ( # TODO: nothing YET IMPLEMENTED except for EV
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
        #   loop ueber OID und dabei immer .N vom Ende wegnehmen und rest mit OBJ_obj2txt() ausgeben
        #   # 1.3.6.1.4 -->  "" . identified-organization . dot . iana . Private
        #   # 2.5.29.32 -->  "" . directory services (X.500) . id-ce . X509v3 Certificate Policies

#   '1.3.6.1'                   => {iso(1) org(3) dod(6) iana(1)}
    '1.3.6.1'                   => {'txt' => "Internet OID"},
#   '1.3.6.1.5.5.7.1'           => {'txt' => "Private Extensions"},
    '1.3.6.1.5.5.7.1.1'         => {'txt' => "Authority Information Access"}, # authorityInfoAccess
    '1.3.6.1.5.5.7.1.12'        => {'txt' => STR_UNDEF},
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
    '1.3.6.1.4.1.11129.2.5.1'   => {'txt' => STR_UNDEF},    # Certificate Policy?
    '1.3.6.1.4.1.14370.1.6'     => {'txt' => STR_UNDEF},    # Certificate Policy?
    '1.3.6.1.4.1.311.10.3.3'    => {'txt' => "Microsoft Server Gated Crypto"},
    '1.3.6.1.4.1.311.10.11'     => {'txt' => "Microsoft Server: EV additional Attributes"},
    '1.3.6.1.4.1.311.10.11.11'  => {'txt' => "Microsoft Server: EV ??friendly name??"},
    '1.3.6.1.4.1.311.10.11.83'  => {'txt' => "Microsoft Server: EV ??root program??"},
    '1.3.6.1.4.1.4146.1.10'     => {'txt' => STR_UNDEF},    # Certificate Policy?
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
    '2.16.840.1.113733.1.7.23.6'=> {'txt' => STR_UNDEF},    # Certificate Policy?
    '2.16.840.1.113733.1.7.48.1'=> {'txt' => STR_UNDEF},    #  ''
    '2.16.840.1.113733.1.7.54'  => {'txt' => STR_UNDEF},    #  ''
    '0.9.2342.19200300.100.1.3' => {'txt' => "subject:mail"},
); # %data_oid


our %ciphers_desc = (   # description of following %ciphers table
    'head'          => [qw(  sec  ssl   enc  bits mac  auth  keyx   score  tags)],
                            # abbreviations used by openssl:
                            # SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2
                            # Kx=  key exchange (DH is diffie-hellman)
                            # Au=  authentication
                            # Enc= encryption with bit size
                            # Mac= mac encryption algorithm
    'text'          => [ # full description of each column in 'ciphers' below
        'Security',         # LOW, MEDIUM, HIGH as reported by openssl 0.9.8 .. 1.0.1h
                            # WEAK as reported by openssl 0.9.8 as EXPORT
                            # weak unqualified by openssl or know vulnerable
                            # NOTE: weak includes NONE (no security at all)
                            #
                            # all following informations as reported by openssl 0.9.8 .. 1.0.1h
        'SSL/TLS',          # Protocol Version:
                            # SSLv2, SSLv3, TLSv1, TLSv11, TLSv12, TLSv13, DTLS0.9, DTLS1.0, PCT
                            # NOTE: all SSLv3 are also TLSv1, TLSv11, TLSv12
                            # (cross-checked with sslaudit.ini)
        'Encryption Algorithm', # None, AES, AESCCM, AESGCM, CAMELLIA, DES, 3DES, FZA, IDEA, RC4, RC2, SEED
        'Key Size',         # in bits
        'MAC Algorithm',    # MD5, SHA1, SHA256, SHA384, AEAD
        'Authentication',   # None, DSS, RSA, ECDH, ECDSA, KRB5, PSK
        'Key Exchange',     # DH, ECDH, ECDH/ECDSA, RSA, KRB5, PSK, SRP
                            # last column is a : separated list (only export from openssl)
                            # different versions of openssl report  ECDH or ECDH/ECDSA
        'score',            # score value as defined in sslaudit.ini (0, 20, 80, 100)
                            # additionally following sores are used:
                            #  10: have been 100 in sslaudit.ini (HIGH  in openssl)
                            #   8: have been 80 in sslaudit.ini  (MDIUM in openssl)
                            #   3:                               (LOW   in openssl)
                            #   2: have been 20 in sslaudit.ini
                            #   1: assumed weak security
                            #  11: unknown, assumed weak security
                            #  81: unknown, assumed MEDIUM security
                            #  91: unknown, assumed HIGH security
                            #   0: all anon and NULL and <56 bit ciphers dispite above settings
        'tags',             # export  as reported by openssl 0.9.8 .. 1.0.1h
                            # OSX     on Mac OS X only
                            # :    (colon) is empty marker (need for other tools
        ],
); # %ciphers_desc


our %ciphers = (
    #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,
    # hex,hex               => [qw(  sec  ssl   enc  bits mac  auth  keyx    score tags)],
    #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,
# ...
); # %ciphers


our %cipher_names = (
### Achtung: die hex-Wert sind intern, davon sind nur die letzten 4 oder 6
###          Stellen (je nach Protokoll) der eigentliche Wert.
    #
    #!#----------+-------------------------------------+--------------------------+
    #!# constant =>     cipher suite name              # cipher suite value
    #!#----------+-------------------------------------+--------------------------+
#       SSL2 ciphers?                                  # missing SSL_CK_ prefix
    '0x02010080' => [qw(RC4-MD5                         RC4_128_WITH_MD5)],
    '0x02020080' => [qw(EXP-RC4-MD5                     RC4_128_EXPORT40_WITH_MD5)],
    '0x02030080' => [qw(RC2-CBC-MD5                     RC2_128_CBC_WITH_MD5)],
    '0x02040080' => [qw(EXP-RC2-CBC-MD5                 RC2_128_CBC_EXPORT40_WITH_MD5)],
    '0x02050080' => [qw(IDEA-CBC-MD5                    IDEA_128_CBC_WITH_MD5)],
    '0x02060040' => [qw(DES-CBC-MD5                     DES_64_CBC_WITH_MD5)],
    '0x02060140' => [qw(DES-CBC-SHA                     DES_64_CBC_WITH_SHA)],
    '0x020700C0' => [qw(DES-CBC3-MD5                    DES_192_EDE3_CBC_WITH_MD5)],
    '0x020701C0' => [qw(DES-CBC3-SHA                    DES_192_EDE3_CBC_WITH_SHA)],
    '0x02080080' => [qw(RC4-64-MD5                      RC4_64_WITH_MD5)],
    '0x02FF0800' => [qw(DES-CFB-M1                      DES_64_CFB64_WITH_MD5_1)],
    '0x02FF0810' => [qw(NULL                            NULL)],
#
    '0x03000019' => [qw(EXP-ADH-DES-CBC-SHA             ADH_DES_40_CBC_SHA)],
    '0x0300001A' => [qw(ADH-DES-CBC-SHA                 ADH_DES_64_CBC_SHA)],
    '0x0300001B' => [qw(ADH-DES-CBC3-SHA                ADH_DES_192_CBC_SHA)],
    '0x03000017' => [qw(EXP-ADH-RC4-MD5                 ADH_RC4_40_MD5)],
    '0x03000018' => [qw(ADH-RC4-MD5                     ADH_RC4_128_MD5)],
    '0x030000A6' => [qw(ADH-AES128-GCM-SHA256           ADH_WITH_AES_128_GCM_SHA256)],
    '0x03000034' => [qw(ADH-AES128-SHA                  ADH_WITH_AES_128_SHA)],
    '0x0300006C' => [qw(ADH-AES128-SHA256               ADH_WITH_AES_128_SHA256)],
    '0x030000A7' => [qw(ADH-AES256-GCM-SHA384           ADH_WITH_AES_256_GCM_SHA384)],
    '0x030000A8' => [qw(PSK-AES128-GCM-SHA256           PSK_WITH_AES_128_GCM_SHA256)],
    '0x030000A8' => [qw(PSK-AES256-GCM-SHA384           PSK_WITH_AES_256_GCM_SHA384)],
    '0x0300003A' => [qw(ADH-AES256-SHA                  ADH_WITH_AES_256_SHA)],
    '0x0300006D' => [qw(ADH-AES256-SHA256               ADH_WITH_AES_256_SHA256)],
    '0x03000046' => [qw(ADH-CAMELLIA128-SHA             ADH_WITH_CAMELLIA_128_CBC_SHA)],
    '0x03000089' => [qw(ADH-CAMELLIA256-SHA             ADH_WITH_CAMELLIA_256_CBC_SHA)],
    '0x030000BF' => [qw(ADH-CAMELLIA128-SHA256          ADH_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x030000C5' => [qw(ADH-CAMELLIA256-SHA256          ADH_WITH_CAMELLIA_256_CBC_SHA256)],
    '0x0300009B' => [qw(ADH-SEED-SHA                    ADH_WITH_SEED_SHA)],
    '0x03000063' => [qw(EXP1024-DHE-DSS-DES-CBC-SHA     DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA)],
    '0x03000065' => [qw(EXP1024-DHE-DSS-RC4-SHA         DHE_DSS_EXPORT1024_WITH_RC4_56_SHA)],
    '0x030000A2' => [qw(DHE-DSS-AES128-GCM-SHA256       DHE_DSS_WITH_AES_128_GCM_SHA256)],
    '0x03000032' => [qw(DHE-DSS-AES128-SHA              DHE_DSS_WITH_AES_128_SHA)],
    '0x03000040' => [qw(DHE-DSS-AES128-SHA256           DHE_DSS_WITH_AES_128_SHA256)],
    '0x030000A3' => [qw(DHE-DSS-AES256-GCM-SHA384       DHE_DSS_WITH_AES_256_GCM_SHA384)],
    '0x03000038' => [qw(DHE-DSS-AES256-SHA              DHE_DSS_WITH_AES_256_SHA)],
    '0x0300006A' => [qw(DHE-DSS-AES256-SHA256           DHE_DSS_WITH_AES_256_SHA256)],
    '0x03000044' => [qw(DHE-DSS-CAMELLIA128-SHA         DHE_DSS_WITH_CAMELLIA_128_CBC_SHA)],
    '0x03000087' => [qw(DHE-DSS-CAMELLIA256-SHA         DHE_DSS_WITH_CAMELLIA_256_CBC_SHA)],
    '0x030000BD' => [qw(DHE-DSS-CAMELLIA128-SHA256      DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x030000C3' => [qw(DHE-DSS-CAMELLIA256-SHA256      DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256)],
    '0x03000066' => [qw(DHE-DSS-RC4-SHA                 DHE_DSS_WITH_RC4_128_SHA)],
    '0x03000099' => [qw(DHE-DSS-SEED-SHA                DHE_DSS_WITH_SEED_SHA)],
    '0x03000033' => [qw(DHE-RSA-AES128-SHA              DHE_RSA_WITH_AES_128_SHA)],
    '0x03000039' => [qw(DHE-RSA-AES256-SHA              DHE_RSA_WITH_AES_256_SHA)],
    '0x03000067' => [qw(DHE-RSA-AES128-SHA256           DHE_RSA_WITH_AES_128_SHA256)],
    '0x0300006B' => [qw(DHE-RSA-AES256-SHA256           DHE_RSA_WITH_AES_256_SHA256)],
    '0x0300009E' => [qw(DHE-RSA-AES128-GCM-SHA256       DHE_RSA_WITH_AES_128_GCM_SHA256)],
    '0x0300009F' => [qw(DHE-RSA-AES256-GCM-SHA384       DHE_RSA_WITH_AES_256_GCM_SHA384)],
    '0x03000045' => [qw(DHE-RSA-CAMELLIA128-SHA         DHE_RSA_WITH_CAMELLIA_128_CBC_SHA)],
    '0x03000088' => [qw(DHE-RSA-CAMELLIA256-SHA         DHE_RSA_WITH_CAMELLIA_256_CBC_SHA)],
    '0x030000BE' => [qw(DHE-RSA-CAMELLIA128-SHA256      DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x030000C4' => [qw(DHE-RSA-CAMELLIA256-SHA256      DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256)],
    '0x0300CCAA' => [qw(DHE-RSA-CHACHA20-POLY1305-SHA256   DHE_RSA_WITH_CHACHA20_POLY1305_SHA256)], # see Note(c)
    '0x0300CCAB' => [qw(PSK-CHACHA20-POLY1305-SHA256    PSK_WITH_CHACHA20_POLY1305_SHA256)],
    '0x0300CCAC' => [qw(ECDHE-PSK-CHACHA20-POLY1305-SHA256 ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256)],
    '0x0300CCAD' => [qw(DHE-PSK-CHACHA20-POLY1305-SHA256   DHE_PSK_WITH_CHACHA20_POLY1305_SHA256)],
    '0x0300CCAE' => [qw(RSA-PSK-CHACHA20-POLY1305-SHA256   RSA_PSK_WITH_CHACHA20_POLY1305_SHA256)],
    '0x0300009A' => [qw(DHE-RSA-SEED-SHA                DHE_RSA_WITH_SEED_SHA)],
    '0x03000042' => [qw(DH-DSS-CAMELLIA128-SHA          DH_DSS_WITH_CAMELLIA_128_CBC_SHA)],
    '0x03000085' => [qw(DH-DSS-CAMELLIA256-SHA          DH_DSS_WITH_CAMELLIA_256_CBC_SHA)],
    '0x030000BB' => [qw(DH-DSS-CAMELLIA128-SHA256       DH_DSS_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x030000C1' => [qw(DH-DSS-CAMELLIA256-SHA256       DH_DSS_WITH_CAMELLIA_256_CBC_SHA256)],
    '0x0300000B' => [qw(EXP-DH-DSS-DES-CBC-SHA          DH_DSS_DES_40_CBC_SHA)],
    '0x0300000C' => [qw(DH-DSS-DES-CBC-SHA              DH_DSS_DES_64_CBC_SHA)],
    '0x0300000D' => [qw(DH-DSS-DES-CBC3-SHA             DH_DSS_DES_192_CBC3_SHA)],
    '0x03000030' => [qw(DH-DSS-AES128-SHA               DH_DSS_WITH_AES_128_SHA)],
    '0x03000036' => [qw(DH-DSS-AES256-SHA               DH_DSS_WITH_AES_256_SHA)],
    '0x0300003E' => [qw(DH-DSS-AES128-SHA256            DH_DSS_WITH_AES_128_SHA256)],
    '0x03000068' => [qw(DH-DSS-AES256-SHA256            DH_DSS_WITH_AES_256_SHA256)],
    '0x030000A4' => [qw(DH-DSS-AES128-GCM-SHA256        DH_DSS_WITH_AES_128_GCM_SHA256)],
    '0x030000A5' => [qw(DH-DSS-AES256-GCM-SHA384        DH_DSS_WITH_AES_256_GCM_SHA384)],
    '0x03000097' => [qw(DH-DSS-SEED-SHA                 DH_DSS_WITH_SEED_SHA)],
    '0x03000098' => [qw(DH-RSA-SEED-SHA                 DH_RSA_WITH_SEED_SHA)],
    '0x0300000E' => [qw(EXP-DH-RSA-DES-CBC-SHA          DH_RSA_DES_40_CBC_SHA)],
    '0x0300000F' => [qw(DH-RSA-DES-CBC-SHA              DH_RSA_DES_64_CBC_SHA)],
    '0x03000010' => [qw(DH-RSA-DES-CBC3-SHA             DH_RSA_DES_192_CBC3_SHA)],
    '0x03000031' => [qw(DH-RSA-AES128-SHA               DH_RSA_WITH_AES_128_SHA)],
    '0x03000037' => [qw(DH-RSA-AES256-SHA               DH_RSA_WITH_AES_256_SHA)],
    '0x0300003F' => [qw(DH-RSA-AES128-SHA256            DH_RSA_WITH_AES_128_SHA256)],
    '0x03000069' => [qw(DH-RSA-AES256-SHA256            DH_RSA_WITH_AES_256_SHA256)],
    '0x030000A0' => [qw(DH-RSA-AES128-GCM-SHA256        DH_RSA_WITH_AES_128_GCM_SHA256)],
    '0x030000A1' => [qw(DH-RSA-AES256-GCM-SHA384        DH_RSA_WITH_AES_256_GCM_SHA384)],
    '0x03000043' => [qw(DH-RSA-CAMELLIA128-SHA          DH_RSA_WITH_CAMELLIA_128_CBC_SHA)],
    '0x03000086' => [qw(DH-RSA-CAMELLIA256-SHA          DH_RSA_WITH_CAMELLIA_256_CBC_SHA)],
    '0x030000BC' => [qw(DH-RSA-CAMELLIA128-SHA256       DH_RSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x030000C2' => [qw(DH-RSA-CAMELLIA256-SHA256       DH_RSA_WITH_CAMELLIA_256_CBC_SHA256)],
    '0x0300C009' => [qw(ECDHE-ECDSA-AES128-SHA          ECDHE_ECDSA_WITH_AES_128_CBC_SHA)],
    '0x0300C02B' => [qw(ECDHE-ECDSA-AES128-GCM-SHA256   ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)],
    '0x0300C023' => [qw(ECDHE-ECDSA-AES128-SHA256       ECDHE_ECDSA_WITH_AES_128_SHA256)],
    '0x0300C00A' => [qw(ECDHE-ECDSA-AES256-SHA          ECDHE_ECDSA_WITH_AES_256_CBC_SHA)],
    '0x0300C02C' => [qw(ECDHE-ECDSA-AES256-GCM-SHA384   ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)],
    '0x0300C024' => [qw(ECDHE-ECDSA-AES256-SHA384       ECDHE_ECDSA_WITH_AES_256_SHA384)],
    '0x03000072' => [qw(ECDHE-ECDSA-CAMELLIA128-SHA256  ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x03000073' => [qw(ECDHE-ECDSA-CAMELLIA256-SHA384  ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384)],
    '0x0300CCA9' => [qw(ECDHE-ECDSA-CHACHA20-POLY1305-SHA256 ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)], # see Note(c)
    '0x0300C006' => [qw(ECDHE-ECDSA-NULL-SHA            ECDHE_ECDSA_WITH_NULL_SHA)],
    '0x0300C007' => [qw(ECDHE-ECDSA-RC4-SHA             ECDHE_ECDSA_WITH_RC4_128_SHA)],
    '0x0300C008' => [qw(ECDHE-ECDSA-DES-CBC3-SHA        ECDHE_ECDSA_WITH_DES_192_CBC3_SHA)],
    '0x0300C013' => [qw(ECDHE-RSA-AES128-SHA            ECDHE_RSA_WITH_AES_128_CBC_SHA)],
    '0x0300C014' => [qw(ECDHE-RSA-AES256-SHA            ECDHE_RSA_WITH_AES_256_CBC_SHA)],
    '0x0300C027' => [qw(ECDHE-RSA-AES128-SHA256         ECDHE_RSA_WITH_AES_128_SHA256)],
    '0x0300C028' => [qw(ECDHE-RSA-AES256-SHA384         ECDHE_RSA_WITH_AES_256_SHA384)],
    '0x0300C02F' => [qw(ECDHE-RSA-AES128-GCM-SHA256     ECDHE_RSA_WITH_AES_128_GCM_SHA256)],
    '0x0300C030' => [qw(ECDHE-RSA-AES256-GCM-SHA384     ECDHE_RSA_WITH_AES_256_GCM_SHA384)],
    '0x03000076' => [qw(ECDHE-RSA-CAMELLIA128-SHA256    ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x03000077' => [qw(ECDHE-RSA-CAMELLIA256-SHA384    ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384)],
    '0x0300CCA8' => [qw(ECDHE-RSA-CHACHA20-POLY1305-SHA256  ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)], # see Note(c)
    '0x0300C010' => [qw(ECDHE-RSA-NULL-SHA              ECDHE_RSA_WITH_NULL_SHA)],
    '0x0300C011' => [qw(ECDHE-RSA-RC4-SHA               ECDHE_RSA_WITH_RC4_128_SHA)],
    '0x0300C012' => [qw(ECDHE-RSA-DES-CBC3-SHA          ECDHE_RSA_WITH_DES_192_CBC3_SHA)],
    '0x0300C004' => [qw(ECDH-ECDSA-AES128-SHA           ECDH_ECDSA_WITH_AES_128_CBC_SHA)],
    '0x0300C005' => [qw(ECDH-ECDSA-AES256-SHA           ECDH_ECDSA_WITH_AES_256_CBC_SHA)],
    '0x0300C025' => [qw(ECDH-ECDSA-AES128-SHA256        ECDH_ECDSA_WITH_AES_128_SHA256)],
    '0x0300C026' => [qw(ECDH-ECDSA-AES256-SHA384        ECDH_ECDSA_WITH_AES_256_SHA384)],
    '0x0300C02D' => [qw(ECDH-ECDSA-AES128-GCM-SHA256    ECDH_ECDSA_WITH_AES_128_GCM_SHA256)],
    '0x0300C02E' => [qw(ECDH-ECDSA-AES256-GCM-SHA384    ECDH_ECDSA_WITH_AES_256_GCM_SHA384)],
    '0x03000074' => [qw(ECDH-ECDSA-CAMELLIA128-SHA256   ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x03000075' => [qw(ECDH-ECDSA-CAMELLIA256-SHA384   ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384)],
    '0x0300C001' => [qw(ECDH-ECDSA-NULL-SHA             ECDH_ECDSA_WITH_NULL_SHA)],
    '0x0300C002' => [qw(ECDH-ECDSA-RC4-SHA              ECDH_ECDSA_WITH_RC4_128_SHA)],
    '0x0300C003' => [qw(ECDH-ECDSA-DES-CBC3-SHA         ECDH_ECDSA_WITH_DES_192_CBC3_SHA)],
    '0x0300C00E' => [qw(ECDH-RSA-AES128-SHA             ECDH_RSA_WITH_AES_128_CBC_SHA)],
    '0x0300C00F' => [qw(ECDH-RSA-AES256-SHA             ECDH_RSA_WITH_AES_256_CBC_SHA)],
    '0x0300C029' => [qw(ECDH-RSA-AES128-SHA256          ECDH_RSA_WITH_AES_128_SHA256)],
    '0x0300C02A' => [qw(ECDH-RSA-AES256-SHA384          ECDH_RSA_WITH_AES_256_SHA384)],
    '0x0300C031' => [qw(ECDH-RSA-AES128-GCM-SHA256      ECDH_RSA_WITH_AES_128_GCM_SHA256)],
    '0x0300C032' => [qw(ECDH-RSA-AES256-GCM-SHA384      ECDH_RSA_WITH_AES_256_GCM_SHA384)],
    '0x03000078' => [qw(ECDH-RSA-CAMELLIA128-SHA256     ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x03000079' => [qw(ECDH-RSA-CAMELLIA256-SHA384     ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384)],
    '0x0300C00B' => [qw(ECDH-RSA-NULL-SHA               ECDH_RSA_WITH_NULL_SHA)],
    '0x0300C00C' => [qw(ECDH-RSA-RC4-SHA                ECDH_RSA_WITH_RC4_128_SHA)],
    '0x0300C00D' => [qw(ECDH-RSA-DES-CBC3-SHA           ECDH_RSA_WITH_DES_192_CBC3_SHA)],
    '0x0300C015' => [qw(AECDH-NULL-SHA                  ECDH_anon_WITH_NULL_SHA)],
    '0x0300C016' => [qw(AECDH-RC4-SHA                   ECDH_anon_WITH_RC4_128_SHA)],
    '0x0300C017' => [qw(AECDH-DES-CBC3-SHA              ECDH_anon_WITH_DES_192_CBC3_SHA)],
    '0x0300C018' => [qw(AECDH-AES128-SHA                ECDH_anon_WITH_AES_128_CBC_SHA)],
    '0x0300C019' => [qw(AECDH-AES256-SHA                ECDH_anon_WITH_AES_256_CBC_SHA)],
    '0x03000011' => [qw(EXP-EDH-DSS-DES-CBC-SHA         EDH_DSS_DES_40_CBC_SHA)],
    '0x03000012' => [qw(EDH-DSS-DES-CBC-SHA             EDH_DSS_DES_64_CBC_SHA)],
    '0x03000013' => [qw(EDH-DSS-DES-CBC3-SHA            EDH_DSS_DES_192_CBC3_SHA)],
    '0x03000014' => [qw(EXP-EDH-RSA-DES-CBC-SHA         EDH_RSA_DES_40_CBC_SHA)],
    '0x03000015' => [qw(EDH-RSA-DES-CBC-SHA             EDH_RSA_DES_64_CBC_SHA)],
    '0x03000016' => [qw(EDH-RSA-DES-CBC3-SHA            EDH_RSA_DES_192_CBC3_SHA)],
    '0x0300001D' => [qw(FZA-FZA-SHA                     FZA_DMS_FZA_SHA)],     # FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA
    '0x0300001C' => [qw(FZA-NULL-SHA                    FZA_DMS_NULL_SHA)],    # FORTEZZA_KEA_WITH_NULL_SHA
    '0x0300001e' => [qw(FZA-RC4-SHA                     FZA_DMS_RC4_SHA)],     # <== 1e so that it is its own hash entry in crontrast to 1E (duplicate constant definition in openssl)
    '0x03000023' => [qw(KRB5-DES-CBC3-MD5               KRB5_DES_192_CBC3_MD5)],
    '0x0300001F' => [qw(KRB5-DES-CBC3-SHA               KRB5_DES_192_CBC3_SHA)],
    '0x03000029' => [qw(EXP-KRB5-DES-CBC-MD5            KRB5_DES_40_CBC_MD5)],
    '0x03000026' => [qw(EXP-KRB5-DES-CBC-SHA            KRB5_DES_40_CBC_SHA)],
    '0x03000022' => [qw(KRB5-DES-CBC-MD5                KRB5_DES_64_CBC_MD5)],
    '0x0300001E' => [qw(KRB5-DES-CBC-SHA                KRB5_DES_64_CBC_SHA)],
    '0x03000025' => [qw(KRB5-IDEA-CBC-MD5               KRB5_IDEA_128_CBC_MD5)],
    '0x03000021' => [qw(KRB5-IDEA-CBC-SHA               KRB5_IDEA_128_CBC_SHA)],
    '0x0300002A' => [qw(EXP-KRB5-RC2-CBC-MD5            KRB5_RC2_40_CBC_MD5)],
    '0x03000027' => [qw(EXP-KRB5-RC2-CBC-SHA            KRB5_RC2_40_CBC_SHA)],
    '0x03000024' => [qw(KRB5-RC4-MD5                    KRB5_RC4_128_MD5)],
    '0x03000020' => [qw(KRB5-RC4-SHA                    KRB5_RC4_128_SHA)],
    '0x0300002B' => [qw(EXP-KRB5-RC4-MD5                KRB5_RC4_40_MD5)],
    '0x03000028' => [qw(EXP-KRB5-RC4-SHA                KRB5_RC4_40_SHA)],
    '0x02000000' => [qw(NULL-MD5                        NULL_WITH_MD5)],
    '0x03000000' => [qw(NULL-NULL                       NULL_WITH_NULL_NULL)], # O-Saft dummy
    '0x0300008A' => [qw(PSK-RC4-SHA                     PSK_WITH_RC4_128_SHA)],
    '0x0300008B' => [qw(PSK-3DES-EDE-CBC-SHA            PSK_WITH_3DES_EDE_CBC_SHA)],
    '0x0300008C' => [qw(PSK-AES128-CBC-SHA              PSK_WITH_AES_128_CBC_SHA)],
    '0x0300008D' => [qw(PSK-AES256-CBC-SHA              PSK_WITH_AES_256_CBC_SHA)],
    '0x03000008' => [qw(EXP-DES-CBC-SHA                 RSA_DES_40_CBC_SHA)],
    '0x03000009' => [qw(DES-CBC-SHA                     RSA_DES_64_CBC_SHA)],
    '0x0300000A' => [qw(DES-CBC3-SHA                    RSA_DES_192_CBC3_SHA)],
    '0x03000061' => [qw(EXP1024-RC2-CBC-MD5             RSA_EXPORT1024_WITH_RC2_CBC_56_MD5)],
    '0x03000062' => [qw(EXP1024-DES-CBC-SHA             RSA_EXPORT1024_WITH_DES_CBC_SHA)],
    '0x03000060' => [qw(EXP1024-RC4-MD5                 RSA_EXPORT1024_WITH_RC4_56_MD5)],
    '0x03000064' => [qw(EXP1024-RC4-SHA                 RSA_EXPORT1024_WITH_RC4_56_SHA)],
    '0x03000007' => [qw(IDEA-CBC-SHA                    RSA_IDEA_128_SHA)],
    '0x03000001' => [qw(NULL-MD5                        RSA_NULL_MD5)],
    '0x03000002' => [qw(NULL-SHA                        RSA_NULL_SHA)],
    '0x03000003' => [qw(EXP-RC4-MD5                     RSA_RC4_40_MD5)],
    '0x03000004' => [qw(RC4-MD5                         RSA_RC4_128_MD5)],
    '0x03000005' => [qw(RC4-SHA                         RSA_RC4_128_SHA)],
    '0x03000006' => [qw(EXP-RC2-CBC-MD5                 RSA_RC2_40_MD5)],
    '0x0300009C' => [qw(AES128-GCM-SHA256               RSA_WITH_AES_128_GCM_SHA256)],
    '0x0300002F' => [qw(AES128-SHA                      RSA_WITH_AES_128_SHA)],
    '0x0300003C' => [qw(AES128-SHA256                   RSA_WITH_AES_128_SHA256)],
    '0x0300009D' => [qw(AES256-GCM-SHA384               RSA_WITH_AES_256_GCM_SHA384)],
    '0x03000035' => [qw(AES256-SHA                      RSA_WITH_AES_256_SHA)],
    '0x0300003D' => [qw(AES256-SHA256                   RSA_WITH_AES_256_SHA256)],
    '0x03000041' => [qw(CAMELLIA128-SHA                 RSA_WITH_CAMELLIA_128_CBC_SHA)],
    '0x03000084' => [qw(CAMELLIA256-SHA                 RSA_WITH_CAMELLIA_256_CBC_SHA)],
    '0x030000BA' => [qw(CAMELLIA128-SHA256              RSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x030000C0' => [qw(CAMELLIA256-SHA256              RSA_WITH_CAMELLIA_256_CBC_SHA256)],
    '0x0300003B' => [qw(NULL-SHA256                     RSA_WITH_NULL_SHA256)],
    '0x03000096' => [qw(SEED-SHA                        RSA_WITH_SEED_SHA)],
#
#    http://tools.ietf.org/html/draft-mavrogiannopoulos-chacha-tls-01
    '0x0300CC12' => [qw(RSA-CHACHA20-POLY1305           RSA_WITH_CHACHA20_POLY1305)],       # see Note(c)
    '0x0300CC13' => [qw(ECDHE-RSA-CHACHA20-POLY1305-SHA256  ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)], # -"-
    '0x0300CC14' => [qw(ECDHE-ECDSA-CHACHA20-POLY1305-SHA256 ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)], # -"-
    '0x0300CC15' => [qw(DHE-RSA-CHACHA20-POLY1305-SHA256   DHE_RSA_WITH_CHACHA20_POLY1305_SHA256)], # -"-
    '0x0300CC20' => [qw(RSA-CHACHA20-SHA                RSA_WITH_CHACHA20_SHA)],
    '0x0300CC21' => [qw(ECDHE-RSA-CHACHA20-SHA          ECDHE_RSA_WITH_CHACHA20_SHA)],
    '0x0300CC22' => [qw(ECDHE-ECDSA-CHACHA20-SHA        ECDHE_ECDSA_WITH_CHACHA20_SHA)],
    '0x0300CC23' => [qw(DHE-RSA-CHACHA20-SHA            DHE_RSA_WITH_CHACHA20_SHA)],
    '0x0300CC24' => [qw(DHE-PSK-CHACHA20-SHA            DHE_PSK_WITH_CHACHA20_SHA)],
    '0x0300CC25' => [qw(PSK-CHACHA20-SHA                PSK_WITH_CHACHA20_SHA)],
    '0x0300CC26' => [qw(ECDHE-PSK-CHACHA20-SHA          ECDHE_PSK_WITH_CHACHA20_SHA)],
    '0x0300CC27' => [qw(RSA-PSK-CHACHA20-SHA            RSA_PSK_WITH_CHACHA20_SHA)],
#
# http://tools.ietf.org/html/draft-mavrogiannopoulos-chacha-tls-05
    '0x0300CCA0' => [qw(RSA-CHACHA20-POLY1305           RSA_WITH_CHACHA20_POLY1305)],
    '0x0300CCA1' => [qw(ECDHE-RSA-CHACHA20-POLY1305     ECDHE_RSA_WITH_CHACHA20_POLY1305)],
    '0x0300CCA2' => [qw(ECDHE-ECDSA-CHACHA20-POLY1305   ECDHE_ECDSA_WITH_CHACHA20_POLY1305)],
    '0x0300CCA3' => [qw(DHE-RSA-CHACHA20-POLY1305       DHE_RSA_WITH_CHACHA20_POLY1305)],
    '0x0300CCA4' => [qw(DHE-PSK-CHACHA20-POLY1305       DHE_PSK_WITH_CHACHA20_POLY1305)],
    '0x0300CCA5' => [qw(PSK-CHACHA20-POLY1305           PSK_WITH_CHACHA20_POLY1305)],
    '0x0300CCA6' => [qw(ECDHE-PSK-CHACHA20-POLY1305     ECDHE_PSK_WITH_CHACHA20_POLY1305)],
    '0x0300CCA7' => [qw(RSA-PSK-CHACHA20-POLY1305       RSA_PSK_WITH_CHACHA20_POLY1305)],
#
    '0x0300002C' => [qw(PSK-SHA                         PSK_WITH_NULL_SHA)],
    '0x0300002D' => [qw(DHE-PSK-SHA                     DHE_PSK_WITH_NULL_SHA)],
    '0x0300002E' => [qw(RSA-PSK-SHA                     RSA_PSK_WITH_NULL_SHA)],
    '0x0300008E' => [qw(DHE-PSK-RC4-SHA                 DHE_PSK_WITH_RC4_128_SHA)],
    '0x0300008F' => [qw(DHE-PSK-3DES-SHA                DHE_PSK_WITH_3DES_EDE_CBC_SHA)],
    '0x03000090' => [qw(DHE-PSK-AES128-SHA              DHE_PSK_WITH_AES_128_CBC_SHA)],
    '0x03000091' => [qw(DHE-PSK-AES256-SHA              DHE_PSK_WITH_AES_256_CBC_SHA)],
    '0x03000092' => [qw(RSA-PSK-RC4-SHA                 RSA_PSK_WITH_RC4_128_SHA)],
    '0x03000093' => [qw(RSA-PSK-3DES-EDE-CBC-SHA        RSA_PSK_WITH_3DES_EDE_CBC_SHA)],
    '0x03000094' => [qw(RSA-PSK-AES128-SHA              RSA_PSK_WITH_AES_128_CBC_SHA)],
    '0x03000095' => [qw(RSA-PSK-AES256-SHA              RSA_PSK_WITH_AES_256_CBC_SHA)],
    '0x030000AA' => [qw(DHE-PSK-AES128-GCM-SHA256       DHE_PSK_WITH_AES_128_GCM_SHA256)],
    '0x030000AB' => [qw(DHE-PSK-AES256-GCM-SHA384       DHE_PSK_WITH_AES_256_GCM_SHA384)],
    '0x030000AC' => [qw(RSA-PSK-AES128-GCM-SHA256       RSA_PSK_WITH_AES_128_GCM_SHA256)],
    '0x030000AD' => [qw(RSA-PSK-AES256-GCM-SHA384       RSA_PSK_WITH_AES_256_GCM_SHA384)],
    '0x030000AE' => [qw(PSK-AES128-SHA256               PSK_WITH_AES_128_CBC_SHA256)],
    '0x030000AF' => [qw(PSK-AES256-SHA384               PSK_WITH_AES_256_CBC_SHA384)],
    '0x030000B0' => [qw(PSK-SHA256                      PSK_WITH_NULL_SHA256)],
    '0x030000B1' => [qw(PSK-SHA384                      PSK_WITH_NULL_SHA384)],
    '0x030000B2' => [qw(DHE-PSK-AES128-SHA256           DHE_PSK_WITH_AES_256_CBC_SHA256)],
    '0x030000B3' => [qw(DHE-PSK-AES256-SHA384           DHE_PSK_WITH_AES_256_CBC_SHA384)],
    '0x030000B4' => [qw(DHE-PSK-SHA256                  DHE_PSK_WITH_NULL_SHA256)],
    '0x030000B5' => [qw(DHE-PSK-SHA384                  DHE_PSK_WITH_NULL_SHA384)],
    '0x030000B6' => [qw(RSA-PSK-AES128-SHA256           RSA_PSK_WITH_AES_256_CBC_SHA256)],
    '0x030000B7' => [qw(RSA-PSK-AES256-SHA384           RSA_PSK_WITH_AES_256_CBC_SHA384)],
    '0x030000B8' => [qw(RSA-PSK-SHA256                  RSA_PSK_WITH_NULL_SHA256)],
    '0x030000B9' => [qw(RSA-PSK-SHA384                  RSA_PSK_WITH_NULL_SHA384)],
#
    '0x0300C09C' => [qw(RSA-AES128-CCM                  RSA_WITH_AES_128_CCM)],
    '0x0300C09D' => [qw(RSA-AES256-CCM                  RSA_WITH_AES_256_CCM)],
    '0x0300C09E' => [qw(DHE-RSA-AES128-CCM              DHE_RSA_WITH_AES_128_CCM)],
    '0x0300C09F' => [qw(DHE-RSA-AES256-CCM              DHE_RSA_WITH_AES_256_CCM)],
    '0x0300C0A4' => [qw(PSK-RSA-AES128-CCM              PSK_WITH_AES_128_CCM)],
    '0x0300C0A5' => [qw(PSK-RSA-AES256-CCM              PSK_WITH_AES_256_CCM)],
    '0x0300C0A6' => [qw(DHE-PSK-RSA-AES128-CCM          DHE_PSK_WITH_AES_128_CCM)],
    '0x0300C0A7' => [qw(DHE-PSK-RSA-AES256-CCM          DHE_PSK_WITH_AES_256_CCM)],
    '0x0300C0AC' => [qw(ECDHE-RSA-AES128-CCM            ECDHE_ECDSA_WITH_AES_128_CCM)], # RFC 7251
    '0x0300C0AD' => [qw(ECDHE-RSA-AES256-CCM            ECDHE_ECDSA_WITH_AES_256_CCM)], # RFC 7251
    '0x0300C0A0' => [qw(RSA-AES128-CCM8                 RSA_WITH_AES_128_CCM_8)],
    '0x0300C0A1' => [qw(RSA-AES256-CCM8                 RSA_WITH_AES_256_CCM_8)],
    '0x0300C0A2' => [qw(DHE-RSA-AES128-CCM8             DHE_RSA_WITH_AES_128_CCM_8)],
    '0x0300C0A3' => [qw(DHE-RSA-AES256-CCM8             DHE_RSA_WITH_AES_256_CCM_8)],
    '0x0300C0A8' => [qw(PSK-RSA-AES128-CCM8             PSK_WITH_AES_128_CCM_8)],
    '0x0300C0A9' => [qw(PSK-RSA-AES256-CCM8             PSK_WITH_AES_256_CCM_8)],
    '0x0300C0AA' => [qw(DHE-PSK-RSA-AES128-CCM8         DHE_PSK_WITH_AES_128_CCM_8)],
    '0x0300C0AB' => [qw(DHE-PSK-RSA-AES256-CCM8         DHE_PSK_WITH_AES_256_CCM_8)],
    '0x0300C0AE' => [qw(ECDHE-RSA-AES128-CCM8           ECDHE_ECDSA_WITH_AES_128_CCM_8)], # RFC 7251
    '0x0300C0AF' => [qw(ECDHE-RSA-AES256-CCM8           ECDHE_ECDSA_WITH_AES_256_CCM_8)], # RFC 7251
    '0x03005600' => [qw(SCSV                            TLS_FALLBACK_SCSV)], # FIXME: according http://tools.ietf.org/html/7507.html
    '0x030000FF' => [qw(INFO_SCSV                       EMPTY_RENEGOTIATION_INFO_SCSV)],
    '0x0300C01D' => [qw(SRP-AES-128-CBC-SHA             SRP_SHA_WITH_AES_128_CBC_SHA)],
    '0x0300C020' => [qw(SRP-AES-256-CBC-SHA             SRP_SHA_WITH_AES_256_CBC_SHA)],
    '0x0300C01A' => [qw(SRP-3DES-EDE-CBC-SHA            SRP_SHA_WITH_3DES_EDE_CBC_SHA)],
    '0x0300C01B' => [qw(SRP-RSA-3DES-EDE-CBC-SHA        SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)],
    '0x0300C01C' => [qw(SRP-DSS-3DES-EDE-CBC-SHA        SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA)],
    '0x0300C01E' => [qw(SRP-RSA-AES-128-CBC-SHA         SRP_SHA_RSA_WITH_AES_128_CBC_SHA)],
    '0x0300C01F' => [qw(SRP-DSS-AES-128-CBC-SHA         SRP_SHA_DSS_WITH_AES_128_CBC_SHA)],
    '0x0300C021' => [qw(SRP-RSA-AES-256-CBC-SHA         SRP_SHA_RSA_WITH_AES_256_CBC_SHA)],
    '0x0300C022' => [qw(SRP-DSS-AES-256-CBC-SHA         SRP_SHA_DSS_WITH_AES_256_CBC_SHA)],
    '0x0300C03C' => [qw(RSA-ARIA128-SHA256              RSA_WITH_ARIA_128_CBC_SHA256)],
    '0x0300C03D' => [qw(RSA-ARIA256-SHA384              RSA_WITH_ARIA_256_CBC_SHA384)],
    '0x0300C03E' => [qw(DH-DSS-ARIA128-SHA256           DH_DSS_WITH_ARIA_128_CBC_SHA256)],
    '0x0300C03F' => [qw(DH-DSS-ARIA256-SHA384           DH_DSS_WITH_ARIA_256_CBC_SHA384)],
    '0x0300C040' => [qw(DH-RSA-ARIA128-SHA256           DH_RSA_WITH_ARIA_128_CBC_SHA256)],
    '0x0300C041' => [qw(DH-RSA-ARIA256-SHA384           DH_RSA_WITH_ARIA_256_CBC_SHA384)],
    '0x0300C042' => [qw(DHE-DSS-ARIA128-SHA256          DHE_DSS_WITH_ARIA_128_CBC_SHA256)],
    '0x0300C043' => [qw(DHE-DSS-ARIA256-SHA384          DHE_DSS_WITH_ARIA_256_CBC_SHA384)],
    '0x0300C044' => [qw(DHE-RSA-ARIA256-SHA256          DHE_RSA_WITH_ARIA_256_CBC_SHA256)],
    '0x0300C045' => [qw(DHE-RSA-ARIA256-SHA384          DHE_RSA_WITH_ARIA_256_CBC_SHA384)],
    '0x0300C046' => [qw(ADH-ARIA128-SHA256              DH_anon_WITH_ARIA_128_CBC_SHA256)],
    '0x0300C047' => [qw(ADH-ARIA256-SHA384              DH_anon_WITH_ARIA_256_CBC_SHA384)],
    '0x0300C048' => [qw(ECDHE-ECDSA-ARIA128-SHA256      ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256)],
    '0x0300C049' => [qw(ECDHE-ECDSA-ARIA256-SHA384      ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384)],
    '0x0300C04A' => [qw(ECDH-ECDSA-ARIA128-SHA256       ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 )],
    '0x0300C04B' => [qw(ECDH-ECDSA-ARIA256-SHA384       ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 )],
    '0x0300C04C' => [qw(ECDHE-RSA-ARIA128-SHA256        ECDHE_RSA_WITH_ARIA_128_CBC_SHA256  )],
    '0x0300C04D' => [qw(ECDHE-RSA-ARIA256-SHA384        ECDHE_RSA_WITH_ARIA_256_CBC_SHA384  )],
    '0x0300C04E' => [qw(ECDH-RSA-ARIA128-SHA256         ECDH_RSA_WITH_ARIA_128_CBC_SHA256   )],
    '0x0300C04F' => [qw(ECDH-RSA-ARIA256-SHA384         ECDH_RSA_WITH_ARIA_256_CBC_SHA384   )],
    '0x0300C050' => [qw(RSA-ARIA128-GCM-SHA256          RSA_WITH_ARIA_128_GCM_SHA256        )]    ,
    '0x0300C051' => [qw(RSA-ARIA256-GCM-SHA384          RSA_WITH_ARIA_256_GCM_SHA384        )],
    '0x0300C052' => [qw(DHE-RSA-ARIA128-GCM-SHA256      DHE_RSA_WITH_ARIA_128_GCM_SHA256    )],
    '0x0300C053' => [qw(DHE-RSA-ARIA256-GCM-SHA384      DHE_RSA_WITH_ARIA_256_GCM_SHA384    )],
    '0x0300C054' => [qw(DH-RSA-ARIA128-GCM-SHA256       DH_RSA_WITH_ARIA_128_GCM_SHA256     )],
    '0x0300C055' => [qw(DH-RSA-ARIA256-GCM-SHA384       DH_RSA_WITH_ARIA_256_GCM_SHA384     )],
    '0x0300C056' => [qw(DHE-DSS-ARIA128-GCM-SHA256      DHE_DSS_WITH_ARIA_128_GCM_SHA256    )],
    '0x0300C057' => [qw(DHE-DSS-ARIA256-GCM-SHA384      DHE_DSS_WITH_ARIA_256_GCM_SHA384    )],
    '0x0300C058' => [qw(DH-DSS-ARIA128-GCM-SHA256       DH_DSS_WITH_ARIA_128_GCM_SHA256     )],
    '0x0300C059' => [qw(DH-DSS-ARIA256-GCM-SHA384       DH_DSS_WITH_ARIA_256_GCM_SHA384     )],
    '0x0300C05A' => [qw(ADH-ARIA128-GCM-SHA256          DH_anon_WITH_ARIA_128_GCM_SHA256    )],
    '0x0300C05B' => [qw(ADH-ARIA256-GCM-SHA384          DH_anon_WITH_ARIA_256_GCM_SHA384    )],
    '0x0300C05C' => [qw(ECDHE-ECDSA-ARIA128-GCM-SHA256  ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256)],
    '0x0300C05D' => [qw(ECDHE-ECDSA-ARIA256-GCM-SHA384  ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384)],
    '0x0300C05E' => [qw(ECDH-ECDSA-ARIA128-GCM-SHA256   ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 )],
    '0x0300C05F' => [qw(ECDH-ECDSA-ARIA256-GCM-SHA384   ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 )],
    '0x0300C060' => [qw(ECDHE-RSA-ARIA128-GCM-SHA256    ECDHE_RSA_WITH_ARIA_128_GCM_SHA256  )],
    '0x0300C061' => [qw(ECDHE-RSA-ARIA256-GCM-SHA384    ECDHE_RSA_WITH_ARIA_256_GCM_SHA384  )],
    '0x0300C062' => [qw(ECDH-RSA-ARIA128-GCM-SHA256     ECDH_RSA_WITH_ARIA_128_GCM_SHA256   )],
    '0x0300C063' => [qw(ECDH-RSA-ARIA256-GCM-SHA384     ECDH_RSA_WITH_ARIA_256_GCM_SHA384   )],
    '0x0300C064' => [qw(PSK-ARIA128-SHA256              PSK_WITH_ARIA_128_CBC_SHA256        )],
    '0x0300C065' => [qw(PSK-ARIA256-SHA384              PSK_WITH_ARIA_256_CBC_SHA384        )],
    '0x0300C066' => [qw(DHE-PSK-ARIA128-SHA256          DHE_PSK_WITH_ARIA_128_CBC_SHA256    )],
    '0x0300C067' => [qw(DHE-PSK-ARIA256-SHA384          DHE_PSK_WITH_ARIA_256_CBC_SHA384    )],
    '0x0300C068' => [qw(RSA-PSK-ARIA128-SHA256          RSA_PSK_WITH_ARIA_128_CBC_SHA256    )],
    '0x0300C069' => [qw(RSA-PSK-ARIA256-SHA384          RSA_PSK_WITH_ARIA_256_CBC_SHA384    )],
    '0x0300C06A' => [qw(PSK-ARIA128-GCM-SHA256          PSK_WITH_ARIA_128_GCM_SHA256        )],
    '0x0300C06B' => [qw(PSK-ARIA256-GCM-SHA384          PSK_WITH_ARIA_256_GCM_SHA384        )],
    '0x0300C06C' => [qw(DHE-PSK-ARIA128-GCM-SHA256      DHE_PSK_WITH_ARIA_128_GCM_SHA256    )],
    '0x0300C06D' => [qw(DHE-PSK-ARIA256-GCM-SHA384      DHE_PSK_WITH_ARIA_256_GCM_SHA384    )],
    '0x0300C06E' => [qw(RSA-PSK-ARIA128-GCM-SHA256      RSA_PSK_WITH_ARIA_128_GCM_SHA256    )],
    '0x0300C06F' => [qw(RSA-PSK-ARIA256-GCM-SHA384      RSA_PSK_WITH_ARIA_256_GCM_SHA384    )],
    '0x0300C070' => [qw(ECDHE-PSK-ARIA128-SHA256        ECDHE_PSK_WITH_ARIA_128_CBC_SHA256  )],
    '0x0300C071' => [qw(ECDHE-PSK-ARIA256-SHA384        ECDHE_PSK_WITH_ARIA_256_CBC_SHA384  )],
    '0x0300FEE0' => [qw(RSA-FIPS-3DES-EDE-SHA           RSA_FIPS_WITH_3DES_EDE_CBC_SHA)],
    '0x0300FEE1' => [qw(RSA-FIPS-DES-CBC-SHA            RSA_FIPS_WITH_DES_CBC_SHA)],
    '0x0300FEFE' => [qw(RSA-FIPS-DES-CBC-SHA            RSA_FIPS_WITH_DES_CBC_SHA)],
    '0x0300FEFF' => [qw(RSA-FIPS-3DES-EDE-SHA           RSA_FIPS_WITH_3DES_EDE_CBC_SHA)],
#
    '0x03000080' => [qw(GOST94-GOST89-GOST89            GOSTR341094_WITH_28147_CNT_IMIT)], #ok
    '0x03000081' => [qw(GOST2001-GOST89-GOST89          GOSTR341001_WITH_28147_CNT_IMIT)], #ok
    '0x03000082' => [qw(GOST94-NULL-GOST94              GOSTR341094_WITH_NULL_GOSTR3411)], # unklar, siehe 0x0300FF00
    '0x03000083' => [qw(GOST2001-NULL-GOST94            GOSTR341001_WITH_NULL_GOSTR3411)], # unklar, siehe 0x0300FF01
#   '0x0300FF00' => [qw(GOST94-NULL-GOST94              GOSTR341001_WITH_NULL_GOSTR3411)], # unklar, siehe 0x03000082 und muesste sein  GOSTR341094_WITH_NULL_GOSTR3411
    '0x0300FF00' => [qw(GOST-MD5                        GOSTR341094_RSA_WITH_28147_CNT_MD5)],
    '0x0300FF01' => [qw(GOST-GOST94                     RSA_WITH_28147_CNT_GOST94)],
#    '0x0300FF01' => [qw(GOST2001-NULL-GOST94           GOSTR341001_WITH_NULL_GOSTR3411)], # unklar da nummer doppelt
    '0x0300FF02' => [qw(GOST-GOST89MAC                  -?-)],
    '0x0300FF03' => [qw(GOST-GOST89STREAM               -?-)],
# TODO:  following PCT...
    '0x00800001' => [qw(PCT_SSL_CERT_TYPE               PCT1_CERT_X509)],
    '0x00800003' => [qw(PCT_SSL_CERT_TYPE               PCT1_CERT_X509_CHAIN)],
    '0x00810001' => [qw(PCT_SSL_HASH_TYPE               PCT1_HASH_MD5)],
    '0x00810003' => [qw(PCT_SSL_HASH_TYPE               PCT1_HASH_SHA)],
    '0x00820003' => [qw(PCT_SSL_EXCH_TYPE               PCT1_EXCH_RSA_PKCS1)],
    '0x00823004' => [qw(PCT_SSL_CIPHER_TYPE_1ST_HALF    PCT1_CIPHER_RC4)],
    '0x00842840' => [qw(PCT_SSL_CIPHER_TYPE_2ND_HALF    PCT1_ENC_BITS_40|PCT1_MAC_BITS_128)],
    '0x00848040' => [qw(PCT_SSL_CIPHER_TYPE_2ND_HALF    PCT1_ENC_BITS_128|PCT1_MAC_BITS_128)],
    '0x008f8001' => [qw(PCT_SSL_COMPAT                  PCT_VERSION_1)],
    # from: https://chromium.googlesource.com/chromium/src/net/+/master/ssl/ssl_cipher_suite_names_unittest.cc
    '0x030016B7' => [qw(CECPQ1-RSA-CHACHA20-POLY1305-SHA256   CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256)],
    '0x030016B8' => [qw(CECPQ1-ECDSA-CHACHA20-POLY1305-SHA256 CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256)],
    '0x030016B9' => [qw(CECPQ1-RSA-AES256-GCM-SHA384    CECPQ1_RSA_WITH_AES_256_GCM_SHA384)],
    '0x030016BA' => [qw(CECPQ1-ECDSA-AES256-GCM-SHA384  CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384)],
    #!#----------+-------------------------------------+--------------------------+
#
    # Note(c)
    #   according https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305-04
    #   some hex keys for ciphers changed
    #   see also: http://tools.ietf.org/html/draft-mavrogiannopoulos-chacha-tls-05
); # %cipher_names

our %cipher_alias = ( # TODO: list not yet used
    #!#----------+-------------------------------------+--------------------------+
    #!# constant =>     cipher suite name alias        # comment (where found)
    #!#----------+-------------------------------------+--------------------------+
    '0x02030080' => [qw(RC2-MD5)],                     #
    '0x02040080' => [qw(EXP-RC2-MD5)],                 # from sslaudit.ini
    '0x03000012' => [qw(EDH-DSS-CBC-SHA)],             # from sslaudit.ini and mozilla
    '0x0300001D' => [qw(FZA-FZA-CBC-SHA)],
    '0x03000032' => [qw(EDH-DSS-AES128-SHA)],          # from RSA BSAFE SSL-C
    '0x0300002C' => [qw(PSK-NULL-SHA)],                # from openssl
    '0x0300002D' => [qw(DHE-PSK-NULL-SHA)],
    '0x0300002E' => [qw(RSA-PSK-NULL-SHA)],
    '0x03000033' => [qw(EDH-RSA-AES128-SHA)],          # -"-
    '0x03000038' => [qw(EDH-DSS-AES256-SHA)],          # -"-
    '0x03000039' => [qw(EDH-RSA-AES256-SHA)],          # -"-
    '0x03000062' => [qw(EXP-DES-56-SHA)],              # -"-
    '0x03000063' => [qw(EXP-EDH-DSS-DES-56-SHA)],      # -"-
    '0x03000064' => [qw(EXP-RC4-56-SHA)],              # -"-
    '0x03000065' => [qw(EXP-EDH-DSS-RC4-56-SHA)],
    '0x03000066' => [qw(EDH-DSS-RC4-SHA)],             # from RSA BSAFE SSL-C

    # TODO: need to mark following 10 as old ciphers with changed IDs
    '0x03000093' => [qw(RSA-PSK-3DES-SHA)],            # ??
    '0x03000094' => [qw(RSA-PSK-AES128-CBC-SHA)],      # openssl 1.0.2
    '0x03000095' => [qw(RSA-PSK-AES256-CBC-SHA)],      # openssl 1.0.2
    '0x0300CC13' => [qw(ECDHE-RSA-CHACHA20-POLY1305)], # see Note(c) above
    '0x0300CC14' => [qw(ECDHE-ECDSA-CHACHA20-POLY1305)], # -"-
    '0x0300CC15' => [qw(DHE-RSA-CHACHA20-POLY1305)],   # -"-
    '0x0300CC16' => [qw(DHE-PSK-CHACHA20-POLY1305)],   # -"-
    '0x0300CC17' => [qw(PSK-CHACHA20-POLY1305)],       # -"-
    '0x0300CC18' => [qw(ECDHE-PSK-CHACHA20-POLY1305)], # -"-
    '0x0300CC19' => [qw(RSA-PSK-CHACHA20-POLY1305)],   # -"-

    '0x0300009B' => [qw(DHanon-SEED-SHA)],
    '0x0300C0A0' => [qw(RSA-AES128-CCM-8)],            # ?? some java
    '0x0300C0A1' => [qw(RSA-AES256-CCM-8)],            # -"-
    '0x0300C0A2' => [qw(DHE-RSA-AES128-CCM-8)],        # -"-
    '0x0300C0A3' => [qw(DHE-RSA-AES256-CCM-8)],        # -"-
    '0x0300C0A8' => [qw(PSK-RSA-AES128-CCM-8)],        # -"-
    '0x0300C0A9' => [qw(PSK-RSA-AES256-CCM-8)],        # -"-
    '0x0300C0AE' => [qw(ECDHE-RSA-AES128-CCM-8)],      # -"-
    '0x0300C0AF' => [qw(ECDHE-RSA-AES256-CCM-8)],      # -"-

# following are cipher suite values; alias for them not yet implemented
#   '0x03000003' => [qw(RSA_WITH_RC4_40_MD5)],
#   '0x03000004' => [qw(RSA_WITH_RC4_128_MD5)],
#   '0x03000005' => [qw(RSA_WITH_RC4_128_SHA)],
#   '0x03000006' => [qw(RSA_WITH_RC2_40_MD5)],
#   '0x03000017' => [qw(DH_anon_EXPORT_WITH_RC4_40_MD5)],
#   '0x03000019' => [qw(DH_anon_EXPORT_WITH_DES40_CBC_SHA)],
#   '0x0300001A' => [qw(DH_anon_WITH_DES_CBC_SHA)],
#   '0x0300001B' => [qw(DH_anon_WITH_3DES_EDE_CBC_SHA)],#
#   '0x03000033' => [qw(DHE_RSA_WITH_AES_128_CBC_SHA)],
#   '0x03000039' => [qw(DHE_RSA_WITH_AES_256_CBC_SHA)],
#   '0x0300C0AA' => [qw(PSK_DHE_WITH_AES_128_CCM_8)],  # from openssl
#   '0x0300C0AB' => [qw(PSK_DHE_WITH_AES_256_CCM_8)],  # from openssl
    #!#----------+-------------------------------------+--------------------------+
); # %cipher_alias


our @cipher_results = [ # list of checked ciphers
# currently (12/2015)
#   [ sslv3, rc4-md5, yes ]
#   [ sslv3, NULL,    no ]

# in future (01/2016)
#   [ ssl, cipher, pos+cipher, pos+cipherraw, dh-bits, dh-param, "comment"]
#
#   # ssl      : SSLv2, SSLv3, TLS10, ...
#   # cipher   : hex-Wert (als String)
#   # pos+*    : -1 = undef (noch nicht berechnet), 0 = keine Reihenfolge
#                       beim Server, 1 .. n wie vom Server ausgewaehlt
#   # dh-bits  : DH Bits
#   # dh-param : ECDH Kurve

# dann können verschieden Algorithmen implementiert werden
### 1. o-saft wie jetzt
### 2. o-saft mit cipherraw wie jetzt
### 3. cipherraw mit unterschiedlicher Anzahl Ciphers, z.B.:
###      1, 8,9,15,16,17,32,64,48,49,127,128,129
### 4. von cipherraw den selected Cipher geben lassen

]; # @cipher_results

our %cfg = (
    'mename'        => "O-Saft ", # my name pretty printed
    'need_netdns'   => 0,       # used for better error message handling only
    'need_timelocal'=> 0,       # -"-
    # following initialized in _osaft_init()
    'me'            => "",
    'ARG0'          => "",
    'ARGV'          => [],      # arguments passed on command line
    'RC-ARGV'       => [],      # arguments read from RC-FILE (set in caller)
    'RC-FILE'       => "",      # our RC-FILE, search in pwd only!

   # config. key        default   description
   #------------------+---------+----------------------------------------------
    'try'           => 0,       # 1: do not execute openssl, just show
    'exec'          => 0,       # 1: if +exec command used
    'trace'         => 0,       # 1: trace yeast, 2=trace Net::SSLeay and Net::SSLinfo also
    'traceME'       => 0,       # 1: trace yeast only, but no modules
                                # -1: trace modules only, but not yeast
    'traceARG'      => 0,       # 1: trace yeast's argument processing
    'traceCMD'      => 0,       # 1: trace command processing
    'traceKEY'      => 0,       # 1: (trace) print yeast's internal variable names
    'traceTIME'     => 0,       # 1: (trace) print additiona time for benchmarking
    'linux_debug'   => 0,       # passed to Net::SSLeay::linux_debug
    'verbose'       => 0,       # used for --v
    'v_cipher'      => 0,       # used for --v-cipher
    'warning'       => 1,       # 1: print warnings; 0: don't print warnings
    'proxyhost'     => "",      # FQDN or IP of proxy to be used
    'proxyport'     => 0,       # port for proxy
    'proxyauth'     => "",      # authentication string used for proxy
    'proxyuser'     => "",      # username for proxy authentication (Basic or Digest Auth)
    'proxypass'     => "",      # password for proxy authentication (Basic or Digest Auth)
    'starttls'      => "",      # use STARTTLS if not empty
                                # protocol to be used with STARTTLS; default: SMTP
                                # valid protocols: SMTP, IMAP, IMAP2, POP3, FTPS, LDAP, RDP, XMPP
    'starttls_delay'=> 0,       # STARTTLS: time to wait in seconds (to slow down the requests)
    'starttls_phase'=> [],      # STARTTLS: Array for customized STARTTLS sequences
    'starttls_error'=> [],      # STARTTLS: Array for customized STARTTLS sequences error handling
    'slow_server_delay' => 0,   # time to wait in seconds after a connection via proxy or before starting STARTTLS sequence
    'connect_delay' => 0,       # time to wait in seconds for starting next cipher check
    'socket_reuse'  => 1,       # 0: close and reopen sockets when SSL connect fails
                                # 1: reuse existing sockets, even if SSL connect failed
    'enabled'       => 0,       # 1: only print enabled ciphers
    'disabled'      => 0,       # 1: only print disabled ciphers
    'nolocal'       => 0,
    'experimental'  => 0,       # 1: use experimental functionality
    'ignore_no_conn'=> 0,       # 1: ignore warnings if connection fails, check target anyway
    'uselwp'        => 0,       # 1: use perls LWP module for HTTP checks # TODO: NOT YET IMPLEMENTED
    'forcesni'      => 0,       # 1: do not check if SNI seems to be supported by Net::SSLeay
    'usesni'        => 1,       # 0: do not make connection in SNI mode;
                                # 3: test with and without SNI mode (used with +cipherraw only)
    'usedns'        => 1,       # 1: make DNS reverse lookup
    'usemx'         => 0,       # 1: make MX-Record DNS lookup
    'usehttp'       => 1,       # 1: make HTTP request
    'usealpn'       => 1,       # 0: do not use -alpn option for openssl
    'usenpn'        => 1,       # 0: do not use -nextprotoneg option for openssl
    'protos_next'   =>          # all names known for ALPN or NPN
                       'http/1.1,h2c,h2c-14,spdy/1,npn-spdy/2,spdy/2,spdy/3,spdy/3.1,spdy/4a2,spdy/4a4,grpc-exp,h2-14,h2-15,http/2.0,h2',
                                # even Net::SSLeay functions most likely use an
                                # array,  this is a string with comma-separated
                                # names as used by openssl
                                # Note: must not contain any white spaces!
    'protos_alpn'   => [],      # initially same as cfg{protos_next}, see _cfg_init()
    'protos_npn'    => [],      # "-"
    'use_reconnect' => 1,       # 0: do not use -reconnect option for openssl
    'use_extdebug'  => 1,       # 0: do not use -tlsextdebug option for openssl
    'slowly'        => 0,       # passed to Net::SSLeay::slowly
    'sni_name'      => "1",     # name to be used for SNI mode connection; hostname if empty
                                # NOTE: default=1 as this is behaviour for Net::SSLinfo < 1.85
    'use_sni_name'  => 0,       # 0: use hostname; 1: use name provided by --sni-name
    'sclient_opt'   => "",      # argument or option passed to openssl s_client command
    'no_cert'       => 0,       # 0: get data from certificate; 1, 2, do not get data
    'no_cert_txt'   => "",      # change default text if no data from cert retrieved
    'ca_depth'      => undef,   # depth of peer certificate verification verification
    'ca_crl'        => undef,   # URL where to find CRL file
    'ca_file'       => undef,   # PEM format file with CAs
    'ca_path'       => undef,   # path to directory with PEM files for CAs
                                # see Net::SSLinfo why undef as default
    'ca_paths'      => [qw(/etc/ssl/certs /usr/lib/certs /System/Library/OpenSSL)],
                                # common paths to PEM files for CAs
    'ca_files'      => [qw(ca-certificates.crt certificates.crt certs.pem)],
                                # common PEM filenames for CAs
    'openssl_env'   => undef,   # environment variable OPENSSL if defined
    'openssl_cnf'   => undef,   # full path with openssl's openssl.cnf
    'openssl_cnfs'  => [qw(/usr/lib/ssl/openssl.cnf /etc/ssl/openssl.cnf /System//Library/OpenSSL/openssl.cnf /usr/ssl/openssl.cnf)], # NOT YET USED
    'openssl_fips'  => undef,   # NOT YET USED
    'openssl_msg'   => "",      # '-msg': option needed for openssl versions older than 1.0.2 to get the dh_parameter
    'exitcode'      => 0,       # 1: exit with status code if any check is "no"
    'exitcode_checks'   => 1,   # 0: do not count "no" checks for --exitcode
    'exitcode_cipher'   => 1,   # 0: do not count any ciphers for --exitcode
    'exitcode_medium'   => 1,   # 0: do not count MEDIUM ciphers for --exitcode
    'exitcode_weak' => 1,       # 0: do not count  WEAK  ciphers for --exitcode
    'exitcode_low'  => 1,       # 0: do not count  LOW   ciphers for --exitcode
    'exitcode_pfs'  => 1,       # 0: do not count ciphers without PFS for --exitcode
    'exitcode_prot' => 1,       # 0: do not count protocols other than TLSv12 for --exitcode
    'exitcode_sizes'=> 1,       # 0: do not count size checks for --exitcode
    'ignorecase'    => 1,       # 1: compare some strings case insensitive
    'ignorenoreply' => 1,       # 1: treat "no reply" as hertabeat not enabled
    'shorttxt'      => 0,       # 1: use short label texts
    'version'       => [],      # contains the versions to be checked
    'versions'      =>          # all supported versions; SEE Note:%prot (in o-saft.pl)
                       # [reverse sort keys %prot], # do not use generic list 'cause we want special order
                       [qw(SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 TLSv13 DTLSv09 DTLSv1 DTLSv11 DTLSv12 DTLSv13)],
    'DTLS_versions' => [qw(DTLSv09 DTLSv1 DTLSv11 DTLSv12 DTLSv13)],
                                # temporary list 'cause DTLS not supported by openssl (6/2015)
    'ssl_lazy'      => 0,       # 1: lazy check for available SSL protocol functionality
    'SSLv2'         => 1,       # 1: check this SSL version
    'SSLv3'         => 1,       # 1:   "
    'TLSv1'         => 1,       # 1:   "
    'TLSv11'        => 1,       # 1:   "
    'TLSv12'        => 1,       # 1:   "
    'TLSv13'        => 1,       # 1:   "
                                # NOTE: DTLS currently (6/2015) disabled by default 'cause not supported by openssl
    'DTLSv09'       => 0,       # 1:   "
    'DTLSv1'        => 0,       # 1:   "
    'DTLSv11'       => 0,       # 1:   "
    'DTLSv12'       => 0,       # 1:   "
    'DTLSv13'       => 0,       # 1:   "
    'TLS1FF'        => 0,       # dummy for future use
    'DTLSfamily'    => 0,       # dummy for future use
    'nullssl2'      => 0,       # 1: complain if SSLv2 enabled but no ciphers accepted
    'cipher'        => [],      # ciphers we got with --cipher=
    'cipherpattern' => "ALL:NULL:eNULL:aNULL:LOW:EXP", # openssl pattern for all ciphers
                                # TODO: must be same as in Net::SSLinfo or used from there
    'ciphers'       => [],      # contains all ciphers to be tested
    'cipherrange'   => 'rfc',   # the range to be used from 'cipherranges'
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
        'yeast'     => "",      # internal list, computed later ...
                                # push(@all, @{$_}[0]) foreach (values %cipher_names);
        'rfc'       =>          # constants for ciphers defined in various RFCs
                       "0x03000000 .. 0x030000FF, 0x0300C000 .. 0x0300C0FF,
                        0x0300CC00 .. 0x0300CCFF, 0x0300FE00 .. 0x0300FFFF,
                       ",
        'shifted'   =>          # constants for ciphers defined in various RFCs shifted with an offset of 64 (=0x40) Bytes
                       "0x03000100 .. 0x0300013F,
                        0x03000000 .. 0x030000FF, 0x0300C000 .. 0x0300C0FF,
                        0x0300CC00 .. 0x0300CCFF, 0x0300FE00 .. 0x0300FFFF,
                       ",
        'long'      =>          # more lazy list of constants for cipher
                       "0x03000000 .. 0x030000FF, 0x0300C000 .. 0x0300FFFF,
                       ",
        'huge'      =>          # huge range of constants for cipher
                       "0x03000000 .. 0x0300FFFF,
                       ",
        'safe'      =>          # safe full range of constants for cipher
                                # because some network stack (NIC) will crash for 0x033xxxxx
                       "0x03000000 .. 0x032FFFFF,
                       ",
        'full'      =>          # full range of constants for cipher
                       "0x03000000 .. 0x03FFFFFF,
                       ",
# TODO:                 0x03000000,   0x03FFFFFF,   # used as return by microsoft testserver and also by SSL-honeypot (US)
        'SSLv2'     =>          # constants for ciphers according RFC for SSLv2
                       "0x02000000,   0x02010080, 0x02020080, 0x02030080, 0x02040080,
                        0x02050080,   0x02060040, 0x02060140, 0x020700C0, 0x020701C0,
                        0x02FF0810,   0x02FF0800, 0x02FFFFFF,
                        0x03000000 .. 0x03000002, 0x03000007 .. 0x0300002C, 0x030000FF,
                        0x0300FEE0,   0x0300FEE1, 0x0300FEFE, 0x0300FEFF,
                       ",
                       # 0x02FF0810,   0x02FF0800, 0x02FFFFFF,   # obsolete SSLv2 ciphers
                       # 0x0300FEE0,   0x0300FEE1, 0x0300FEFE, 0x0300FEFF, # obsolete FIPS ciphers
# TODO:                 0x02000000,   0x02FFFFFF,   # increment even only
# TODO:                 0x03000000,   0x03FFFFFF,   # increment  odd only
        'SSLv2_long'=>          # more lazy list of constants for ciphers for SSLv2
                       "0x02000000,   0x02010080, 0x02020080, 0x02030080, 0x02040080,
                        0x02050080,   0x02060040, 0x02060140, 0x020700C0, 0x020701C0,
                        0x02FF0810,   0x02FF0800, 0x02FFFFFF,
                        0x03000000 .. 0x0300002F, 0x030000FF,
                        0x0300FEE0,   0x0300FEE1, 0x0300FEFE, 0x0300FEFF,
                       ",
                       # 0x03000000 .. 0x0300002F, 0x030000FF,   # old SSLv3 ciphers
        'c0xx'      => "0x0300C000 .. 0x0300C0FF",  # constants for ciphers using ecc
        'ccxx'      => "0x0300CC00 .. 0x0300CCFF",  # constants for ciphers using ecc
        'ecc'       =>          # constants for ciphers using ecc
                       "0x0300C000 .. 0x0300C0FF,
                        0x0300CC00 .. 0x0300CCFF,
                       ",
    }, # cipherranges
    'cipher_dh'     => 0,       # 1: +cipher also prints DH parameters (default will be changed in future)
    'cipher_md5'    => 1,       # 0: +cipher does not use *-MD5 ciphers except for SSLv2
    'cipher_alpn'   => 1,       # 0: +cipher does not use ALPN
    'cipher_npn'    => 1,       # 0: +cipher does not use  NPN ($Net::SSLinfo::use_nextprot is for openssl only)
    'cipher_ecdh'   => 1,       # 0: +cipher does not use TLS curves extension
    'cipher_alpns'  => [],      # contains all protocols to be passed for +cipher checks
    'cipher_npns'   => [],      # contains all protocols to be passed for +cipher checks
    'ciphercurves'  => [],      # contains all curves to be passed for +cipher checks
    'ciphers-v'     => 0,       # as: openssl ciphers -v
    'ciphers-V'     => 0,       # as: openssl ciphers -V

   # following keys for commands, nameing scheme:
   #     do         - the list off all commands to be performed
   #     commands-* - internal list for various types of commands
   #     cmd-*      - list for "summary" commands, can be redifined by user
   #     need-*     - list of commands which need a speciphic check
   #
   # TODO: need to unify  cmd-* and need-* and regex->cmd-*;
   #       see also _need_* functions and "construct list for special commands"
   #       in o-saft.pl
   # config. key        list      description
   #------------------+---------+----------------------------------------------
    'do'            => [],      # commands to be performed
    'commands'      => [],      # contains all commands from %data, %checks and commands-INT
                                # will be constructed in main, see: construct list for special commands
    'commands-CMD'  => [],      # contains all cmd-* commands from below
    'commands-USR'  => [],      # contains all commands defined by user with
                                # option --cfg-cmd=* ; see _cfg_set()
    'commands-EXP'  => [        # experimental commands
                        qw(sloth),
                       ],
    'commands-NOTYET'=>[        # commands and checks NOT YET IMPLEMENTED
                        qw(zlib lzo open_pgp fallback closure order sgc scsv time),
                       ],
    'commands-INT'  => [        # add internal commands
                                # these have no key in %data or %checks
                        qw(
                         check cipher dump check_sni exec help info info--v http
                         quick list libversion sizes s_client version quit
                         sigkey bsi ev cipherraw cipher_dh cipher_default
                        ),
                                # internal (debugging) commands
                      # qw(options cert_type),  # will be seen with +info--v only
                                # keys not used as command
                        qw(cn_nosni valid-years valid-months valid-days valid-host)
                       ],
    'commands-HINT' => [        # checks which are NOT YET fully implemented
                                # these are mainly all commands for compliance
                                # see also: cmd-bsi
                        qw(rfc_7525 tr_02102+ tr_02102- tr_03116+ tr_03116-)
                       ],
    'cmd-beast'     => [qw(beast)],                 # commands for +beast
    'cmd-crime'     => [qw(crime)],                 # commands for +crime
    'cmd-drown'     => [qw(drown)],                 # commands for +drown
    'cmd-freak'     => [qw(freak)],                 # commands for +freak
    'cmd-lucky13'   => [qw(lucky13)],               # commands for +lucky13
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
                         lucky13 poodle rc4 sloth sweet32
                         fingerprint_hash fp_not_md5 sha2signature pub_encryption
                         pub_enc_known email serial subject dates verify heartbeat
                         expansion compression hostname hsts_sts crl
                         resumption renegotiation tr_02102+ tr_02102- rfc_7525
                       )],
    'cmd-ev'        => [qw(cn subject altname dv ev ev- ev+ ev_chars)], # commands for +ev
    'cmd-bsi'       => [        # commands for +bsi
                                # see also: commands-HINT
                        qw(after dates crl cipher_rc4 renegotiation
                           tr_02102+ tr_02102- tr_03116+ tr_03116- 
                       )],
    'cmd-pfs'       => [qw(cipher_pfs cipher_pfsall session_random)],   # commands for +pfs
    'cmd-sni'       => [qw(sni hostname)],          # commands for +sni
    'cmd-sni--v'    => [qw(sni cn altname verify_altname verify_hostname hostname wildhost wildcard)],
    'cmd-vulns'     => [        # commands for checking known vulnerabilities
                        qw(beast breach crime drown freak heartbleed logjam lucky13 poodle rc4 sloth sweet32 time hassslv2 hassslv3 cipher_pfs session_random)
                       #qw(resumption renegotiation) # die auch?
                       ],
    'cmd-prots'     => [        # commands for checking protocols
                        qw(hassslv2 hassslv3 hastls10 hastls11 hastls12 hastls13 hasalpn hasnpn session_protocol fallback_protocol alpn alpns npns next_protocols https_protocols http_protocols https_svc http_svc)
                       ],
    'ignore-out'    => [],      # commands (output) to be ignored, SEE Note:ignore-out
    'cmd-NL'        => [        # commands which need NL when printed
                                # they should be available with +info --v only 
                        qw(certificate extensions pem pubkey sigdump text chain chain_verify)
                       ],
                    # need-* lists used to improve performance
    'need-cipher'   => [        # commands which need +cipher
                        qw(check cipher cipher_dh cipher_strong
                         cipher_null cipher_adh cipher_cbc cipher_des cipher_edh
                         cipher_exp  cipher_rc4 cipher_pfs cipher_pfsall
                         beast crime time breach drown freak logjam lucky13 poodle rc4 sloth sweet32
                         tr_02102+ tr_02102- tr_03116+ tr_03116- rfc_7525
                         hassslv2 hassslv3 hastls10 hastls11 hastls12 hastls13
                       )],
                                # TODO: need simple check for protocols
    'need-default'  => [        # commands which need selected cipher
                        qw(check cipher cipher_pfs cipher_order cipher_strong cipher_default cipher_selected),
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
                         rfc_7525 rfc_6125_names rfc_2818_names
                       )],
    'need-checkalnp'=> [        # commands which need checkalpn()
                        qw(alpns alpn hasalpn npns npn hasnpn),
                       ],
    'need-checkbleed'   => [ qw(heartbleed) ],
    'need-check_dh' => [        # commands which need check_dh()
                        qw(logjam dh_512 dh_2048 ecdh_256 ecdh_512)
                       ],
    'need-checkdest'=> [        # commands which need checkprot()
                        qw(reversehost ip resumption renegotiation
                         session_protocol session_ticket session_random session_lifetime
                         krb5 psk_hint psk_identity srp heartbeat
                         cipher_selected cipher_pfs crime
                       )],
    'need-checkhttp'=> [qw(pkp_pins)],  # commands which need checkhttp(); more will be added in _init
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
                                # not usefull in this list: serial extension
                        qw(
                         fingerprint fingerprint_hash fingerprint_sha1 fingerprint_md5
                         sigkey_value pubkey_value modulus
                         master_key session_id session_ticket
                       )],      # fingerprint is special, see _ishexdata()
   #------------------+---------+----------------------------------------------

   # option key        default   description
   #------------------+---------+----------------------------------------------
    'opt-v'         => 0,       # 1 when option -v was given
    'opt-V'         => 0,       # 1 when option -V was given
    'format'        => "",      # empty means some slightly adapted values (no \s\n)
    'formats'       => [qw(csv html json ssv tab xml fullxml raw hex 0x esc)],
    'out_header'    => 0,       # print header lines in output
    'out_score'     => 0,       # print scoring; default for +check
    'out_hint'      => 1,       # 1: print hints; 0: don't print hints
    'out_hint_cipher'   => 1,   # 1: print hints for +cipher command
    'out_hint_check'=> 1,       # 1: print hints for +check commands
    'out_hint_info' => 1,       # 1: print hints for +info commands
    'tmplib'        => "/tmp/yeast-openssl/",   # temp. directory for openssl and its libraries
    'pass_options'  => "",      # options to be passeed thru to other programs
    'mx_domains'    => [],      # list of mx-domain:port to be processed
    'hosts'         => [],      # list of host:port to be processed
    'host'          => "",      # currently scanned host
    'ip'            => "",      # currently scanned host's IP (machine readable format)
    'IP'            => "",      # currently scanned host's IP (human readable, doted octed)
    'rhost'         => "",      # currently scanned host's reverse resolved name
    'DNS'           => "",      # currently scanned host's other IPs and names (DNS aliases)
    'port'          => 443,     # port for currently used connections
    'timeout'       => 2,       # default timeout in seconds for connections
                                # Note that some servers do not connect SSL within this time
                                #      this may result in ciphers marked as  "not supported"
                                #      it's recommended to set timeout to 3 or higher, which
                                #      results in a performance bottleneck, obviously
                                #  see 'sslerror' settings and options also
    'openssl'  =>   {  # configurations for various openssl functionality
       #'openssl'   => "",      # if set, full path of openssl executable
                                # same data structure as in Net::SSLinfo
                                # not all values used yet
        #--------------+--------+---------------------------------------------
        # key (=option) supported=1    warning message if option is missing
        #--------------+--------+---------------------------------------------
        '-alpn'         => [ 1,   "checks with ALPN disabled"],
        '-npn'          => [ 1,   "checks with NPN  disabled"],
        '-nextprotoneg' => [ 1,   "checks with NPN  disabled"], # alias for -npn
        '-reconnect'    => [ 1,   "checks with openssl reconnect disabled"],
        '-fallback_scsv'=> [ 1,   "checks for TLS_FALLBACK_SCSV wrong"],
        '-no_tlsext'    => [ 1,   "<<NOT YET USED>>"],
        '-no_ticket'    => [ 1,   "<<NOT YET USED>>"],
        '-serverinfo'   => [ 1,   "checks without TLS extension disabled"],
        '-servername'   => [ 1,   "checks with TLS extension SNI disabled"],
        '-serverpref'   => [ 1,   "<<NOT YET USED>>"],
        '-showcerts'    => [ 1,   "<<NOT YET USED>>"],
        '-curves'       => [ 1,   "using -curves disabled"],
        '-debug'        => [ 1,   "<<NOT YET USED>>"],
        '-bugs'         => [ 1,   "<<NOT YET USED>>"],
        '-key'          => [ 1,   "<<NOT YET USED>>"],
        '-msg'          => [ 1,   "using -msg disabled, DH paramaters missing or wrong"],
        '-psk'          => [ 1,   "PSK  missing or wrong"],
        '-psk_identity' => [ 1,   "PSK identity missing or wrong"],
        '-pause'        => [ 1,   "<<NOT YET USED>>"],
        '-proxy'        => [ 1,   "<<NOT YET USED>>"],
        '-state'        => [ 1,   "<<NOT YET USED>>"],
        '-status'       => [ 1,   "<<NOT YET USED>>"],
        '-sigalgs'      => [ 1,   "<<NOT YET USED>>"],
        '-client_sigalgs' => [ 1, "<<NOT YET USED>>"],
        '-tlsextdebug'    => [ 1, "TLS extension missing or wrong"],
        '-legacy_renegotiation' => [ 1, "<<NOT YET USED>>"],
        '-nbio_test'    => [ 1,   "<<NOT YET USED>>"],
        '-CAfile'       => [ 1,   "using -CAfile disabled"],
        '-CApath'       => [ 1,   "using -CApath disabled"],
        #--------------+--------+---------------------------------------------
    },
    'ssleay'   =>   {  # configurations for various Net::SSLeay functionality
                                # 1: if available (see _check_functions()) is default
        'openssl'   => 1,       # OPENSSL_VERSION_NUMBER()
        'get_alpn'  => 1,       # P_alpn_selected available()
        'get_npn'   => 1,       # P_next_proto_negotiated()
        'set_alpn'  => 1,       # CTX_set_alpn_protos()
        'set_npn'   => 1,       # CTX_set_next_proto_select_cb()
        'can_npn'   => 1,       # same as get_npn, just an alias
        'can_ecdh'  => 1,       # can_ecdh()
        'can_sni'   => 1,       # for openssl version > 0x01000000
        'can_ocsp'  => 1,       # OCSP_cert2ids
        'iosocket'  => 1,       # $IO::Socket::SSL::VERSION # TODO: wrong container
    },
    'ssl_error'     => 1,       # stop connecting to target after ssl-error-max failures
    'sslerror' =>   {  # configurations for TCP SSL protocol
        'timeout'   => 1,       # timeout to receive ssl-answer
        'max'       => 5,       # max. consecutive errors
        'total'     => 10,      # max. overall errors
                                # following are NOT YET fully implemented:
        'delay'     => 0,       # if > 0 continue trying to connect after this time
        'per_prot'  => 1,       # if > 0 detection and count are per SSL version
    },
    'sslhello' =>   {  # configurations for TCP SSL protocol (mainly used in Net::SSLhello)
        'timeout'   => 2,       # timeout to receive ssl-answer
        'retry'     => 2,       # number of retry when timeout
        'maxciphers'=> 32,      # number of ciphers sent in SSL3/TLS Client-Hello
        'usesignaturealg' => 1, # 1: use extension "signature algorithm"
        'useecc'    => 1,       # 1: use supported elliptic curves
        'useecpoint'=> 1,       # 1: use ec_point_formats extension
        'usereneg'  => 0,       # 1: secure renegotiation
        'double_reneg'  => 0,   # 0: do not send reneg_info extension if the cipher_spec already includes SCSV
                                #    "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" {0x00, 0xFF}
        'nodatanocipher'=> 1,   # 1: do not abort testing next cipher for some TLS intolerant Servers 'NoData or Timeout Equals to No Cipher'
    },
    'legacy'        => "simple",
    'legacys'       => [qw(cnark sslaudit sslcipher ssldiagnos sslscan ssltest
                        ssltest-g sslyze testsslserver thcsslcheck openssl
                        simple full compact quick key)],
                       # SSLAudit, THCSSLCheck, TestSSLServer are converted using lc()
    'showhost'      => 0,       # 1: prefix printed line with hostname
    'usr-args'      => [],      # list of all arguments --usr* (to be used in o-saft-usr.pm)
   #------------------+---------+----------------------------------------------
    'data'  => {       # data provided (mainly used for testing and debugging)
        'file_sclient'  => "",  # file containing data from "openssl s_client "
        'file_ciphers'  => "",  # file containing data from "openssl ciphers"
        'file_pem'      => "",  # file containing certificate(s) in PEM format
        'file_pcap'     => "",  # file containing data in PCAP format
                                # i.e. "openssl s_client -showcerts ..."
    }, # data
   #------------------+---------+----------------------------------------------
   #------------------+--------------------------------------------------------
    'regex' => {
        # RegEx for matching commands and options
        'cmd-http'  => '^h?(?:ttps?|sts)_',     # match keys for HTTP
        'cmd-hsts'  => '^h?sts',                # match keys for (H)STS
        'cmd-sizes' => '^(?:cnt|len)_',         # match keys for length, sizes etc.
        'cmd-cfg'   => '(?:cmd|checks?|data|info|hint|text|scores?)',# --cfg-* commands
        'commands-INT'  => '^(?:cn_nosni|valid-(?:year|month|day|host)s?)', # internal data only, no command
        'opt-empty' => '(?:[+]|--)(?:cmd|help|host|port|format|legacy|timeout|trace|openssl|(?:cipher|proxy|sep|starttls|exe|lib|ca-|cfg-|ssl-|usr-).*)',
                       # these options may have no value
                       # i.e.  --cmd=   ; this may occour in CGI mode

        # RegEx for matching SSL protocol keys in %data and %checks
        'SSLprot'   => '^(SSL|D?TLS)v[0-9]',    # match keys SSLv2, TLSv1, ...

        # RegEx for matching SSL protocol keys in %data and %checks
        # First some basic RegEx used later on, either in following RegEx or
        # as $cfg{'regex'}->{...}  itself.
        '_or-'      => '[\+_-]',
                       # tools use _ or - as separator character; + used in openssl
        'ADHorDHA'  => '(?:A(?:NON[_-])?DH|DH(?:A|[_-]ANON))[_-]',
                       # Anonymous DH has various acronyms:
                       #     ADH, ANON_DH, DHA, DH-ANON, DH_Anon, ...
        'RC4orARC4' => '(?:ARC(?:4|FOUR)|RC4)',
                       # RC4 has other names due to copyright problems:
                       #     ARC4, ARCFOUR, RC4
        '3DESorCBC3'=> '(?:3DES(?:[_-]EDE)[_-]CBC|DES[_-]CBC3)',
                       # Tripple DES is used as 3DES-CBC, 3DES-EDE-CBC, or DES-CBC3
        'DESor3DES' => '(?:[_-]3DES|DES[_-]_192)',
                       # Tripple DES is used as 3DES or DES_192
        'DHEorEDH'  => '(?:DHE|EDH)[_-]',
                       # DHE and EDH are 2 acronyms for the same thing
        'EC-DSA'    => 'EC(?:DHE|EDH)[_-]ECDSA',
        'EC-RSA'    => 'EC(?:DHE|EDH)[_-]RSA',
                       # ECDHE-RSA or ECDHE-ECDSA
        'EC'        => 'EC(?:DHE|EDH)[_-]',
        'EXPORT'    => 'EXP(?:ORT)?(?:40|56|1024)?[_-]',
                       # EXP, EXPORT, EXPORT40, EXP1024, EXPORT1024, ...
        'FRZorFZA'  => '(?:FORTEZZA|FRZ|FZA)[_-]',
                       # FORTEZZA has abbreviations FZA and FRZ
                       # unsure about FORTEZZA_KEA
        'SHA2'      => 'sha(?:2|224|256|384|512)',
                       # any SHA2, just sha2 is too lazy
        'AES-GCM'   => 'AES(?:128|256)[_-]GCM[_-]SHA(?:256|384|512)',
                       # any AES128-GCM or AES256-GCM
        'SSLorTLS'  => '^(?:SSL[23]?|TLS[12]?|PCT1?)[_-]',
                       # Numerous protocol prefixes are in use:
                       #     PTC, PCT1, SSL, SSL2, SSL3, TLS, TLS1, TLS2,
        'aliases'   => '(?:(?:DHE|DH[_-]ANON|DSS|RAS|STANDARD)[_-]|EXPORT_NONE?[_-]?XPORT|STRONG|UNENCRYPTED)',
                       # various variants for aliases to select cipher groups
        'compression'   =>'(?:DEFLATE|LZO)',    # if compression available
        'nocompression' =>'(?:NONE|NULL|^\s*$)',# if no compression available
        'encryption'    =>'(?:encryption|ecPublicKey)', # anything containing this string
        'encryption_ok' =>'(?:(?:(?:(?:md[245]|ripemd160|sha(?:1|224|256|384|512))with)?[rd]saencryption)|id-ecPublicKey)',
                       # well known strings to identify signature and public key encryption
                       # rsaencryption, dsaencryption, md[245]withrsaencryption, 
                       # ripemd160withrsa shaXXXwithrsaencryption
                       # id-ecPublicKey
        'encryption_no' =>'(?:rsa(?:ssapss)?|sha1withrsa|dsawithsha1?|dsa_with_sha256)',
                       # rsa, rsassapss, sha1withrsa, dsawithsha*, dsa_with_sha256
        'isIP'          => '(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
        'isDNS'         => '(?:[a-z0-9.-]+)',
        'isIDN'         => '(?:xn--)',
        'leftwild'      => '^\*(?:[a-z0-9.-]+)',
        'doublewild'    => '(?:[a-z0-9.-]+\*[a-z0-9-]+\*)', # x*x or x*.x*
        'invalidwild'   => '(?:\.\*\.)',            # no .*.
        'invalidIDN'    => '(?:xn--[a-z0-9-]*\*)',  # no * right of xn--
        'isSPDY3'       => '(?:spdy\/3)',           # match in protocols (NPN)
                       # TODO: lazy match as it matches spdy/3.1 also

        # RegEx containing pattern to identify vulnerable ciphers
            #
            # In a perfect (perl) world we can use negative lokups like
            #     (ABC)(?!XYZ)
            # which means: contains `ABC' but not `XYZ' where `XYZ' could be
            # to the right or left of `ABC'.
            # But in real world some perl implementations fail to match such
            # pattern correctly. Hence we use two pattern:  one for positive
            # match and second for the negative (not) match. Both patterns
            # must be used programatically.
            # Key 'TYPE' must match and key 'notTYPE' must not match.
        # The following RegEx define what is "vulnerable":
        'BEAST'     => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?.*?[_-]CBC',  # borrowed from 'Lucky13'. There may be another better RegEx.
#       'BREACH'    => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?',
        'FREAK'     => '^(?:SSL[23]?)?(?:EXP(?:ORT)?(?:40|56|1024)?[_-])',
                       # EXP? is same as regex{EXPORT} above
        'notCRIME'  => '(?:NONE|NULL|^\s*$)',   # same as nocompression (see above)
#       'TIME'      => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?',
        'Lucky13'   => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?.*?[_-]CBC',
        'Logjam'    => 'EXP(?:ORT)?(?:40|56|1024)?[_-]',    # match against cipher
                       # Logjam is same as regex{EXPORT} above
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
   #------------------+--------------------------------------------------------
    'hints' => {       # texts used for hints
	#   'key'   => "any string, may contain \t and \n",
        #
        # Key can be any string.  If key is same as a  valid command (without
        # leading +), such hints are printed automatically (see below).
        # Hint texts can be defined here or anywhere in the code, for example
        # right at the place where they are used. A definition somewhere else
        # in the code should look like:
        #   $cfg{'hints'}->{'your-key'} = "your text\nwith a newline";
        # This allows that the texts can be customised using the option:
        #   --cfg-hints=your-key="other text"
        # How automatic printing works:
        #   Hint texts can be defined for any valid command (see above). When
        #   results are printed,  print_check() and print_data()  will  auto-
        #   matically print such hint texts if any.
        # However, hint texts can be printed anywhere at anytime using:
        #   printhint('your-key'),
        # It is not recommended to use:
        #   print STR_HINT, "my text";
    }, # hints
   #------------------+--------------------------------------------------------
    'ourstr' => {
        # RegEx to match strings of our own output, see OUTPUT in o-saft-man.pm
        # first all that match a line at beginning:
        'error'     => qr(^\*\*ERR),            # see STR_ERROR
        'warning'   => qr(^\*\*WARN),           # see STR_WARN
        'hint'      => qr(^\!\!Hint),           # see STR_HINT
        'dbx'       => qr(^#dbx#),              # see STR_DBX
        'headline'  => qr(^={1,3} ),            # headlines
        'keyline'   => qr(^#\[),                # dataline prefixed with key
        'verbose'   => qr(^#[^[]),              # verbose output
        # matches somewhere in the line:
        'undef'     => qr(\<\<undef),           # see STR_UNDEF
        'yeast'     => qr(\<\<.*?\>\>),         # additional informations
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
        #    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384  (IE8 only)
        #    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA*
        #    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA*
        #    TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        #    TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        #    TLS_RSA_WITH_RC4_128_SHA
        #    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
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
    'openssl_option_map' => {   # map our internal option to openssl option; used our Net:SSL*
        # will be initialized from %prot
     },
    'openssl_version_map' => {  # map our internal option to openssl version (hex value); used our Net:SSL*
        # will be initialized from %prot
     },
    'done'      => {},          # defined in caller
   #------------------+---------+----------------------------------------------
); # %cfg

our %dbx = (    # save hardcoded settings (command lists, texts), and debugging data
                # used in o-saft-dbx.pm only
    'argv'      => undef,       # normal options and arguments
    'cfg'       => undef,       # config options and arguments
    'exe'       => undef,       # executable, library, environment
    'file'      => undef,       # read files
    'cmd-check' => undef,
    'cmd-http'  => undef,
    'cmd-info'  => undef,
    'cmd-quick' => undef,
); # %dbx


#_____________________________________________________________________________
#__________________________________________________________________ methods __|

=pod

=head2 get_cipher_suitename($cipher)

=head2 get_cipher_suiteconst($cipher)

=head2 get_cipher_suitealias($cipher)

Get information from internal C<%cipher_names> data structure.

=head2 get_cipher_sec($cipher)

=head2 get_cipher_ssl($cipher)

=head2 get_cipher_enc($cipher)

=head2 get_cipher_bits($cipher)

=head2 get_cipher_mac($cipher)

=head2 get_cipher_auth($cipher)

=head2 get_cipher_keyx($cipher)

=head2 get_cipher_score($cipher)

=head2 get_cipher_tags($cipher)

=head2 get_cipher_desc($cipher)

Get information from internal C<%cipher> data structure.

=cut

sub get_cipher_suitename { my $c=shift; return $cipher_names{$c}[0] if (defined $cipher_names{$c}[0]); return ""; }
sub get_cipher_suiteconst{ my $c=shift; return $cipher_names{$c}[1] if (defined $cipher_names{$c}[1]); return ""; }
sub get_cipher_suitealias{ my $c=shift; return $cipher_alias{$c}[0] if (defined $cipher_alias{$c}[0]); return ""; }

# some people prefer to use a getter function to get data from objects
# each function returns a spcific value (column) from the %cipher table
# see %ciphers_desc about description of the columns
# returns STR_UNDEF if requested cipher is missing
sub get_cipher_sec($)  { my $c=shift; return $ciphers{$c}[0] || "" if ((grep{/^$c/} %ciphers)>0); return STR_UNDEF; }
sub get_cipher_ssl($)  { my $c=shift; return $ciphers{$c}[1] || "" if ((grep{/^$c/} %ciphers)>0); return STR_UNDEF; }
sub get_cipher_enc($)  { my $c=shift; return $ciphers{$c}[2] || "" if ((grep{/^$c/} %ciphers)>0); return STR_UNDEF; }
sub get_cipher_bits($) { my $c=shift; return $ciphers{$c}[3] || "" if ((grep{/^$c/} %ciphers)>0); return STR_UNDEF; }
sub get_cipher_mac($)  { my $c=shift; return $ciphers{$c}[4] || "" if ((grep{/^$c/} %ciphers)>0); return STR_UNDEF; }
sub get_cipher_auth($) { my $c=shift; return $ciphers{$c}[5] || "" if ((grep{/^$c/} %ciphers)>0); return STR_UNDEF; }
sub get_cipher_keyx($) { my $c=shift; return $ciphers{$c}[6] || "" if ((grep{/^$c/} %ciphers)>0); return STR_UNDEF; }
sub get_cipher_score($){ my $c=shift; return $ciphers{$c}[7] || "" if ((grep{/^$c/} %ciphers)>0); return STR_UNDEF; }
sub get_cipher_tags($) { my $c=shift; return $ciphers{$c}[8] || "" if ((grep{/^$c/} %ciphers)>0); return STR_UNDEF; }
sub get_cipher_desc($) { my $c=shift;
    # get description for specified cipher from %ciphers
    if (! defined $ciphers{$c}) {
       _warn("016: undefined cipher description for '$c'"); # TODO: correct %ciphers
       return STR_UNDEF;
    }
    my @c = @{$ciphers{$c}};
    shift @c;
    return @c if ((grep{/^$c/} %ciphers)>0);
    return "";
}

=pod

=head2 get_cipher_hex($cipher)

Get cipher's hex key from C<%cipher_names> or C<%cipher_alias> data structure.

=head2 get_cipher_name($cipher)

Check if given C<%cipher> name is a known cipher.

=cut

sub get_cipher_hex($)  {
    # find hex key for cipher in %cipher_names or %cipher_alias
    # FIXME: need $ssl parameter because of duplicate names (SSLv3, TLSv19
    my $c = shift;
    foreach my $k (keys %cipher_names) { # database up to VERSION 14.07.14
        return $k if ((get_cipher_suitename($k) eq $c) or (get_cipher_suiteconst($k) eq $c));
    }
    foreach my $k (keys %cipher_alias) { # not yet found, check for alias
        return $k if ($cipher_alias{$k}[0] eq $c);
    }
    return "";
} # get_cipher_hex

sub get_cipher_name($) {
    # check if given cipher name is a known cipher
    # checks in %ciphers if nof found in %cipher_names
    # FIXME: need $ssl parameter because of duplicate names (SSLv3, TLSv19
    my $cipher  = shift;
    return $cipher if ((grep{/^$cipher/} %ciphers)>0);
    _trace("get_cipher_name: search $cipher");
    foreach my $k (keys %cipher_names) {
        my $suite = get_cipher_suitename($k);
        return $suite if ($cipher =~ m/$cipher_names{$k}[0]/);
        return $suite if (get_cipher_suiteconst($k) =~ /$cipher/);
    }
    # nothing found yet, try more lazy match
    foreach my $k (keys %cipher_names) {
        my $suite = get_cipher_suitename($k);
        if ($suite =~ m/$cipher/) {
            _warn("017: partial match for cipher name found '$cipher'");
            return $suite;
        }
    }
    return "";
} # get_cipher_name


=pod

=head2 get_openssl_version($cmd)

Call external $cmd (which is a full path for L<openssl|openssl>, usually) executable
to retrive its version. Returns version string.
=cut

sub get_openssl_version($) {
    # we do a simple call, no checks, should work on all platforms
    # get something like: OpenSSL 1.0.1k 8 Jan 2015
    my $cmd  = shift;
    my $data = qx($cmd version);
    chomp $data;
    _trace("get_openssl_version: $data");
    $data =~ s#^.*?(\d+(?:\.\d+)*).*$#$1#; # get version number without letters
    _trace("get_openssl_version()\t= $data");
    return $data;
} # get_openssl_version


=pod

=head2 get_dh_paramter($cipher, $data)

Parse output of `openssl -msg' (given in $data) and returns DH parameters.
Returns empty string if none found.
=cut

sub get_dh_paramter($$) {
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
    $data =~ s/[^0-9a-f_]//gi;    # remove all none hex characters and non seperator
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

    if ($msgType == 0x0C) { # is ServerKeyExchange
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
        # (according RFC2246/RFC5246: sections 7.4.3)
        $dh = Net::SSLhello::parseServerKeyExchange($keyExchange, $msgLen, $msgData);
    }

    chomp $dh;
    _trace("get_dh_paramter(){ ServerKeyExchange\t= $dh }");
    return $dh;
}; # get_dh_paramter

=pod

=head2 sort_cipher_names(@ciphers)

Sort given list of C<@ciphers> according their strength, most strongest first.
returns sorted list of ciphers.

C<@ciphers> is a list of cipher suite names. These names should be those used
by  openssl(1)  .
=cut

sub sort_cipher_names   {
    # cipher suites must be given as array
    # NOTE: the returned list may not be exactly sorted according the cipher's
    #       strength, just roughly
    # known insecure, i.e. CBC, DES, NULL, etc. ciphers are added at the end
    # all ciphers classified "insecure" are added to end of the result list,
    # these (insecure) ciphers are not sorted according their strength as it
    # doesn't make much sense to distinguish "more" or "less" insecure
    my @ciphers = @_;
    my @sorted  ;
    my @latest  ;
    my $cnt_in  = scalar @ciphers;  # number of passed ciphers; see check at end

my@a = @ciphers;

    # Algorithm:
    #  1. remove all known @insecure ciphers from given list
    #  2. start building new list with most @strength cipher first
    #  3. add previously remove @insecure ciphers to new list

    # define list of RegEx to match openssl cipher suite names
    # each RegEx could be seen as a  class of ciphers with the same strength
    # the list defines the strength in descending order, most strength first
    # NOTE the list may contain pattern, which actually do not match a valid
    # cipher suite name; doese't matter, but may avoid future adaptions, see
    # warning at end also

    my @insecure = (
        qw((?:RC[24]))  ,               # all RC2 and RC4
        qw((?:CBC|DES)) ,               # all CBC, DES, 3DES
        qw((?:DSS))     ,               # all DSS
        qw((?:MD[2345])),               # all MD
        qw(DH.?(?i:anon)) ,             # Anon needs to be caseless
        qw((?:NULL))    ,               # all NULL
    );
    my @strength = (
        qw(CECPQ1[_-].*?CHACHA)       ,
        qw(CECPQ1[_-].*?AES256.GCM)   ,
        qw((?:ECDHE|EECDH).*?CHACHA)  , # 1. all ecliptical curve, ephermeral, GCM
        qw((?:ECDHE|EECDH).*?512.GCM) , # .. sorts -ECDSA before -RSA
        qw((?:ECDHE|EECDH).*?384.GCM) ,
        qw((?:ECDHE|EECDH).*?256.GCM) ,
        qw((?:ECDHE|EECDH).*?128.GCM) ,
        qw((?:EDH|DHE).*?CHACHA)  ,     # 2. all ephermeral, GCM
        qw((?:EDH|DHE).*?512.GCM) ,     # .. sorts AES before CAMELLIA
        qw((?:EDH|DHE).*?384.GCM) ,
        qw((?:EDH|DHE).*?256.GCM) ,
        qw((?:EDH|DHE).*?128.GCM) ,
        qw(ECDH[_-].*?CHACHA)   ,       # 3. all ecliptical curve, GCM
        qw(ECDH[_-].*?512.GCM)  ,       # .. sorts -ECDSA before -RSA
        qw(ECDH[_-].*?384.GCM)  ,
        qw(ECDH[_-].*?256.GCM)  ,
        qw(ECDH[_-].*?128.GCM)  ,
        qw(ECDHE.*?CHACHA) ,            # 4. all remaining ecliptical curve, ephermeral
        qw(ECDHE.*?512) ,
        qw(ECDHE.*?384) ,
        qw(ECDHE.*?256) ,
        qw(ECDHE.*?128) ,
        qw(ECDH[_-].*?CHACHA),          # 5. all remaining ecliptical curve
        qw(ECDH[_-].*?512) ,
        qw(ECDH[_-].*?384) ,
        qw(ECDH[_-].*?256) ,
        qw(ECDH[_-].*?128) ,
        qw(AES) ,                       # 5. all AES
        qw(SRP) ,
        qw(PSK) ,
        qw((?:EDH|DHE).*?CHACHA) ,      # 6. all DH
        qw((?:EDH|DHE).*?512) ,
        qw((?:EDH|DHE).*?384) ,
        qw((?:EDH|DHE).*?256) ,
        qw((?:EDH|DHE).*?128) ,
        qw((?:EDH|DHE).*?(?:RSA|DSS)) ,
        qw(CAMELLIA) ,                  # 7. unknown strength
        qw((?:SEED|IDEA)) ,
        qw(RSA[_-]) ,                   # 8.
        qw(DH[_-])  ,
        qw(RC)      ,
        qw(EXP)     ,                   # 9. Export ...
        qw(AEC.*?256) ,                 # insecure
        qw(AEC.*?128) ,
        qw(AEC)     ,
        qw(ADH.*?256) ,                 # no encryption
        qw(ADH.*?128) ,
        qw(ADH)     ,
    );
    foreach my $rex (@insecure) {               # remove all known insecure suites
        _trace2("sort_cipher_names: insecure regex\t= $rex }");
        push(@latest, grep{ /$rex/} @ciphers);  # add matches to result
        @ciphers    = grep{!/$rex/} @ciphers;   # remove matches from original list
    }
    foreach my $rex (@strength) {               # sort according strength
        $rex = qr/^(?:(?:SSL|TLS)[_-])?$rex/;   # allow IANA constant names too
        _trace2("sort_cipher_names: strong regex\t= $rex }");
        push(@sorted, grep{ /$rex/} @ciphers);  # add matches to result
        @ciphers    = grep{!/$rex/} @ciphers;   # remove matches from original list
    }
    push(@sorted, @latest);                     # add insecure ciphers again
    my $cnt_out = scalar @sorted;
    if ($cnt_in != $cnt_out) {
        # print warning if above algorithm misses ciphers; uses perl's  warn()
        # instead of our _warn() to clearly inform the user that the code here
        # needs to be fixed
        warn STR_WARN . "015: missing ciphers in sorted list: $cnt_out < $cnt_in"; ## no critic qw(ErrorHandling::RequireCarping)
        #dbx# print "## ".@sorted . " # @ciphers";
    }
    @sorted = grep{!/^\s*$/} @sorted;           # remove empty names, if any ...
    return @sorted;
} # sort_cipher_names

# internal methods

sub _prot_init_value {
    #? initialize default values in %prot
    foreach my $ssl (keys %prot) {
        $prot{$ssl}->{'cnt'}            = 0;
        $prot{$ssl}->{'-?-'}            = 0;
        $prot{$ssl}->{'WEAK'}           = 0;
        $prot{$ssl}->{'LOW'}            = 0;
        $prot{$ssl}->{'MEDIUM'}         = 0;
        $prot{$ssl}->{'HIGH'}           = 0;
        $prot{$ssl}->{'protocol'}       = 0;
        $prot{$ssl}->{'ciphers_pfs'}    = [];
        $prot{$ssl}->{'cipher_pfs'}     = STR_UNDEF;
        $prot{$ssl}->{'default'}        = STR_UNDEF;
        $prot{$ssl}->{'cipher_strong'}  = STR_UNDEF;
        $prot{$ssl}->{'cipher_weak'}    = STR_UNDEF;
    }
    return;
} # _prot_init_value

sub _cfg_init   {
    #? initialize dynamic settings in %cfg, copy data from %prot
    $cfg{'openssl_option_map'}->{$_}  = $prot{$_}->{'opt'} foreach (keys %prot);
    $cfg{'openssl_version_map'}->{$_} = $prot{$_}->{'hex'} foreach (keys %prot);
    $cfg{'protos_alpn'} = [split(/,/, $cfg{'protos_next'})];
    $cfg{'protos_npn'}  = [split(/,/, $cfg{'protos_next'})];
    # initialize alternate protocols and curves for cipher checks
    $cfg{'cipher_alpns'}= [split(/,/, $cfg{'protos_next'})];
    $cfg{'cipher_npns'} = [split(/,/, $cfg{'protos_next'})];
    $cfg{'ciphercurves'}= [
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
        ];
    # incorporate some environment variables
    $cfg{'openssl_env'} = $ENV{'OPENSSL'}      if (defined $ENV{'OPENSSL'});
    $cfg{'openssl_cnf'} = $ENV{'OPENSSL_CONF'} if (defined $ENV{'OPENSSL_CONF'});
    $cfg{'openssl_fips'}= $ENV{'OPENSSL_FIPS'} if (defined $ENV{'OPENSSL_FIPS'});

    return;
} # _cfg_init

sub _cmd_init   {
    #? initialize dynamic settings in %cfg for commands
    foreach my $key (keys %cfg) {       # well-known "summary" commands
        push(@{$cfg{'commands-CMD'}}, $key) if ($key =~ m/^cmd-/);
    } 
    return;
} # _cmd_init

sub _dbx_init   {
    #? initialize settings for debugging
    $dbx{'cmd-check'} = $cfg{'cmd-check'};
    $dbx{'cmd-http'}  = $cfg{'cmd-http'};
    $dbx{'cmd-info'}  = $cfg{'cmd-info'};
    $dbx{'cmd-quick'} = $cfg{'cmd-quick'};
    push(@{$dbx{file}}, "osaft.pm");    # set myself
    return;
} # _dbx_init

sub _osaft_init {
    #? additional generic initializations for data structures
    my $me =  $0;       # done here to instead of package's "main" to avoid
       $me =~ s#.*[/\\]##;  # multiple variable definitions of $me
    $cfg{'me'}      = $me;
    $cfg{'RC-FILE'} = "./.$me";
    $cfg{'ARG0'}    = $0;
    $cfg{'ARGV'}    = [@ARGV];
    _prot_init_value(); # initallize WEAK, LOW, MEDIUM, HIGH, default, pfs, protocol
    _cfg_init();        # initallize dynamic data in %cfg
    _cmd_init();        # initallize dynamic commands in %cfg
    _dbx_init();        # initallize debugging data in %dbx
    foreach my $k (keys %data_oid) {
        $data_oid{$k}->{val} = "<<check error>>"; # set a default value
    }
    return;
}; # _osaft_init


=pod

=head2 osaft::printhint($cmd,@text)

Print hint for specified command, additionl text will be appended.

=head2 osaft::osaft_sleep($wait)

Wrapper to simulate "slee" with perl's select.
=cut

sub printhint   {   ## no critic qw(Subroutines::RequireArgUnpacking) # buggy perlcritic
    #? Print hint for specified command.
    my $cmd  = shift;
    my @args = @_;
    print STR_HINT, $cfg{'hints'}->{$cmd}, join(" ", @args) if (defined $cfg{'hints'}->{$cmd});
    return;
} # printhint

sub osaft_sleep {
    #? wrapper for IO::select
    my $wait = shift;
    select( undef, undef, undef, $wait);
    return;
} # osaft_sleep

sub osaft_done() {};    # dummy to check successful include

_osaft_init();          # complete initializations

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=head1 NOTES

It's often recommended not to export constants and variables from modules, see
for example  http://perldoc.perl.org/Exporter.html#Good-Practices . The main
purpose of this module is defining variables. Hence we export them.

=head1 SEE ALSO

# ...

=head1 AUTHOR

28-dec-15 Achim Hoffmann

=cut

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

# TODO: interanl wrappers for main's methods
#       they are defined after the  ## PACKAGE  mark to avoid errors in the
#       script generated by contrib/gen_standalone.sh
sub _trace(@)   { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _trace0(@)  { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _trace1(@)  { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _trace2(@)  { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _trace3(@)  { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _warn(@)    { ::_warn(@_);  return; }   ## no critic qw(Subroutines::RequireArgUnpacking)

unless (defined caller) {       # print myself or open connection
    printf("# %s %s\n", __PACKAGE__, $VERSION);
    if (eval {require POD::Perldoc;}) {
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

