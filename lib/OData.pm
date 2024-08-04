#!/usr/bin/perl -CADSio
## PACKAGE {

#!# Copyright (c) 2024, Achim Hoffmann
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package OData;
use strict;
use warnings;
use utf8;

# for description of "no critic" pragmas, please see  t/.perlcriticrc  and
# SEE Perl:perlcritic

## no critic qw(RegularExpressions::RequireExtendedFormatting)
## no critic qw(Variables::ProhibitPackageVars)

#_____________________________________________________________________________
#___________________________________________________ package initialisation __|

my  $SID_odata  =  "@(#) OData.pm 3.25 24/08/05 00:25:15";
our $VERSION    =  "24.06.24";

use Exporter qw(import);

BEGIN {
    # SEE Perl:@INC
    # SEE Perl:BEGIN perlcritic
    my $_path = $0;     $_path =~ s#[/\\][^/\\]*$##x;
    if (exists $ENV{'PWD'} and not (grep{/^$ENV{'PWD'}$/} @INC) ) {
        unshift(@INC, $ENV{'PWD'});
    }
    unshift(@INC, $_path)   if not (grep{/^$_path$/} @INC);
    unshift(@INC, "lib")    if not (grep{/^lib$/}    @INC);
    our @EXPORT_OK  = qw(
        %checks
        %data
        %data0
        %info
        %shorttexts
        %check_cert
        %check_conn
        %check_dest
        %check_http
        %check_size
    );
    # not exported
}

use OText       qw(%STR);
use OCfg        qw(%cfg %prot);
        # 7/2024 ah: full qualified variable $OCfg:: needed; reason unknown

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8


=head1 NAME

OData - common SSL/TLS-connection data for O-Saft and related tools


=head1 DESCRIPTION

Utility package for O-Saft (o-saft.pl and related tools).  It declares and
defines common  L</VARIABLES>  to be used in the calling tool.
All variables and methods are defined in the  OData  namespace.


=head1 SYNOPSIS

=over 2

=item use OData;            # from within perl code

=item OData.pm --help       # on command-line will print help

=item OData.pm --usage      # on command-line will show commands to print data

=back


=head1 OPTIONS

=over 4

=item --help

Print this text.

=item --usage

Print usage for COMMANDS of CLI mode.

=back


=head1 VARIABLES

=head3 %checks

Computed checks.

=head3 %check_cert

Collected and checked certificate data.

=head3 %check_conn

Collected and checked connection data.

=head3 %check_dest

Collected and checked target (connection) data.

=head3 %check_http

Collected HTTP and HTTPS data.

=head3 %check_size

Collected and checked length and count data.

=head3 %data

OData from connection and certificate details.

=head3 %data0

Same as %data with 'val' only. Contains values from first connection only.

=head3 %info

Same as %data with values only.

=head3 %shorttexts

=cut

#_____________________________________________________________________________
#________________________________________________ public (export) variables __|

# NOTE: do not change names of keys in %data and all %check_* as these keys
#       are used in output with --trace-key

# SEE Note:Data Structures
our %info   = (         # keys are identical to %data
    'alpn'          => "",
    'npn'           => "",
    'alpns'         => "",
    'npns'          => "",
);

our %data0  = ();       # same as %data but has 'val' only, no 'txt'
                        # contains values from first connection only

our %data   = (         # connection and certificate details
    # values from SSLinfo, will be processed in print_data()
    #----------------------+-------------------------------------------------------------+-----------------------------------
    # +command                    => value from SSLinfo::*()                               => label to be printed
    #----------------------+-------------------------------------------------------------+-----------------------------------
    'cn_nosni'          => {'val' => "",                                                  'txt' => "Certificate CN without SNI"},
    'pem'               => {'val' => sub { SSLinfo::pem(               $_[0], $_[1])}, 'txt' => "Certificate PEM"},
    'text'              => {'val' => sub { SSLinfo::text(              $_[0], $_[1])}, 'txt' => "Certificate PEM decoded"},
    'cn'                => {'val' => sub { SSLinfo::cn(                $_[0], $_[1])}, 'txt' => "Certificate Common Name"},
    'subject'           => {'val' => sub { SSLinfo::subject(           $_[0], $_[1])}, 'txt' => "Certificate Subject"},
    'issuer'            => {'val' => sub { SSLinfo::issuer(            $_[0], $_[1])}, 'txt' => "Certificate Issuer"},
    'altname'           => {'val' => sub { SSLinfo::altname(           $_[0], $_[1])}, 'txt' => "Certificate Subject's Alternate Names"},
    'cipher_selected'   => {'val' => sub { SSLinfo::selected(          $_[0], $_[1])}, 'txt' => "Selected Cipher"},  # SEE Note:Selected Cipher
    'ciphers_local'     => {'val' => sub { SSLinfo::cipher_openssl()                }, 'txt' => "Local SSLlib Ciphers"},
    'ciphers'           => {'val' => sub { return join(" ",  SSLinfo::ciphers($_[0], $_[1]))}, 'txt' => "Client Ciphers"},
    'dates'             => {'val' => sub { return join(" .. ", SSLinfo::dates($_[0], $_[1]))}, 'txt' => "Certificate Validity (date)"},
    'before'            => {'val' => sub { SSLinfo::before(            $_[0], $_[1])}, 'txt' => "Certificate valid since"},
    'after'             => {'val' => sub { SSLinfo::after(             $_[0], $_[1])}, 'txt' => "Certificate valid until"},
    'aux'               => {'val' => sub { SSLinfo::aux(               $_[0], $_[1])}, 'txt' => "Certificate Trust Information"},
    'email'             => {'val' => sub { SSLinfo::email(             $_[0], $_[1])}, 'txt' => "Certificate Email Addresses"},
    'pubkey'            => {'val' => sub { SSLinfo::pubkey(            $_[0], $_[1])}, 'txt' => "Certificate Public Key"},
    'pubkey_algorithm'  => {'val' => sub { SSLinfo::pubkey_algorithm(  $_[0], $_[1])}, 'txt' => "Certificate Public Key Algorithm"},
    'pubkey_value'      => {'val' => sub { __SSLinfo('pubkey_value',   $_[0], $_[1])}, 'txt' => "Certificate Public Key Value"},
    'modulus_len'       => {'val' => sub { SSLinfo::modulus_len(       $_[0], $_[1])}, 'txt' => "Certificate Public Key Length"},
    'modulus'           => {'val' => sub { SSLinfo::modulus(           $_[0], $_[1])}, 'txt' => "Certificate Public Key Modulus"},
    'modulus_exponent'  => {'val' => sub { SSLinfo::modulus_exponent(  $_[0], $_[1])}, 'txt' => "Certificate Public Key Exponent"},
    'serial'            => {'val' => sub { SSLinfo::serial(            $_[0], $_[1])}, 'txt' => "Certificate Serial Number"},
    'serial_hex'        => {'val' => sub { SSLinfo::serial_hex(        $_[0], $_[1])}, 'txt' => "Certificate Serial Number (hex)"},
    'serial_int'        => {'val' => sub { SSLinfo::serial_int(        $_[0], $_[1])}, 'txt' => "Certificate Serial Number (int)"},
    'certversion'       => {'val' => sub { SSLinfo::version(           $_[0], $_[1])}, 'txt' => "Certificate Version"},
    'sigdump'           => {'val' => sub { SSLinfo::sigdump(           $_[0], $_[1])}, 'txt' => "Certificate Signature (hexdump)"},
    'sigkey_len'        => {'val' => sub { SSLinfo::sigkey_len(        $_[0], $_[1])}, 'txt' => "Certificate Signature Key Length"},
    'signame'           => {'val' => sub { SSLinfo::signame(           $_[0], $_[1])}, 'txt' => "Certificate Signature Algorithm"},
    'sigkey_value'      => {'val' => sub { __SSLinfo('sigkey_value',       $_[0], $_[1])}, 'txt' => "Certificate Signature Key Value"},
    'trustout'          => {'val' => sub { SSLinfo::trustout(              $_[0], $_[1])}, 'txt' => "Certificate trusted"},
    'extensions'        => {'val' => sub { __SSLinfo('extensions',         $_[0], $_[1])}, 'txt' => "Certificate extensions"},
    'tlsextdebug'       => {'val' => sub { __SSLinfo('tlsextdebug',        $_[0], $_[1])}, 'txt' => "TLS extensions (debug)"},
    'tlsextensions'     => {'val' => sub { __SSLinfo('tlsextensions',      $_[0], $_[1])}, 'txt' => "TLS extensions"},
    'ext_authority'     => {'val' => sub { __SSLinfo('ext_authority',      $_[0], $_[1])}, 'txt' => "Certificate extensions Authority Information Access"},
    'ext_authorityid'   => {'val' => sub { __SSLinfo('ext_authorityid',    $_[0], $_[1])}, 'txt' => "Certificate extensions Authority key Identifier"},
    'ext_constraints'   => {'val' => sub { __SSLinfo('ext_constraints',    $_[0], $_[1])}, 'txt' => "Certificate extensions Basic Constraints"},
    'ext_cps'           => {'val' => sub { __SSLinfo('ext_cps',            $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies"},
    'ext_cps_cps'       => {'val' => sub { __SSLinfo('ext_cps_cps',        $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: CPS"},
    'ext_cps_policy'    => {'val' => sub { __SSLinfo('ext_cps_policy',     $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: Policy"},
    'ext_cps_notice'    => {'val' => sub { __SSLinfo('ext_cps_notice',     $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: User Notice"},
    'ext_crl'           => {'val' => sub { __SSLinfo('ext_crl',            $_[0], $_[1])}, 'txt' => "Certificate extensions CRL Distribution Points"},
    'ext_subjectkeyid'  => {'val' => sub { __SSLinfo('ext_subjectkeyid',   $_[0], $_[1])}, 'txt' => "Certificate extensions Subject Key Identifier"},
    'ext_keyusage'      => {'val' => sub { __SSLinfo('ext_keyusage',       $_[0], $_[1])}, 'txt' => "Certificate extensions Key Usage"},
    'ext_extkeyusage'   => {'val' => sub { __SSLinfo('ext_extkeyusage',    $_[0], $_[1])}, 'txt' => "Certificate extensions Extended Key Usage"},
    'ext_certtype'      => {'val' => sub { __SSLinfo('ext_certtype',       $_[0], $_[1])}, 'txt' => "Certificate extensions Netscape Cert Type"},
    'ext_issuer'        => {'val' => sub { __SSLinfo('ext_issuer',         $_[0], $_[1])}, 'txt' => "Certificate extensions Issuer Alternative Name"},
    'ocsp_uri'          => {'val' => sub { SSLinfo::ocsp_uri(              $_[0], $_[1])}, 'txt' => "Certificate OCSP Responder URL"},
    'ocspid'            => {'val' => sub { __SSLinfo('ocspid',             $_[0], $_[1])}, 'txt' => "Certificate OCSP Hashes"},
    'ocsp_subject_hash' => {'val' => sub { __SSLinfo('ocsp_subject_hash',  $_[0], $_[1])}, 'txt' => "Certificate OCSP Subject Hash"},
    'ocsp_public_hash'  => {'val' => sub { __SSLinfo('ocsp_public_hash',   $_[0], $_[1])}, 'txt' => "Certificate OCSP Public Key Hash"},
    'ocsp_response'     => {'val' => sub { SSLinfo::ocsp_response(         $_[0], $_[1])}, 'txt' => "Target's OCSP Response"},
    'ocsp_response_data'=> {'val' => sub { SSLinfo::ocsp_response_data(    $_[0], $_[1])}, 'txt' => "Target's OCSP Response Data"},
    'ocsp_response_status'=> {'val' => sub { SSLinfo::ocsp_response_status($_[0], $_[1])}, 'txt' => "Target's OCSP Response Status"},
    'ocsp_cert_status'  => {'val' => sub { SSLinfo::ocsp_cert_status(      $_[0], $_[1])}, 'txt' => "Target's OCSP Response Cert Status"},
    'ocsp_next_update'  => {'val' => sub { SSLinfo::ocsp_next_update(      $_[0], $_[1])}, 'txt' => "Target's OCSP Response Next Update"},
    'ocsp_this_update'  => {'val' => sub { SSLinfo::ocsp_this_update(      $_[0], $_[1])}, 'txt' => "Target's OCSP Response This Update"},
    'subject_hash'      => {'val' => sub { SSLinfo::subject_hash(          $_[0], $_[1])}, 'txt' => "Certificate Subject Name Hash"},
    'issuer_hash'       => {'val' => sub { SSLinfo::issuer_hash(           $_[0], $_[1])}, 'txt' => "Certificate Issuer Name Hash"},
    'selfsigned'        => {'val' => sub { SSLinfo::selfsigned(            $_[0], $_[1])}, 'txt' => "Certificate Validity (signature)"},
    'fingerprint_type'  => {'val' => sub { SSLinfo::fingerprint_type(      $_[0], $_[1])}, 'txt' => "Certificate Fingerprint Algorithm"},
    'fingerprint_hash'  => {'val' => sub { __SSLinfo('fingerprint_hash',   $_[0], $_[1])}, 'txt' => "Certificate Fingerprint Hash Value"},
    'fingerprint_sha2'  => {'val' => sub { __SSLinfo('fingerprint_sha2',   $_[0], $_[1])}, 'txt' => "Certificate Fingerprint SHA2"},
    'fingerprint_sha1'  => {'val' => sub { __SSLinfo('fingerprint_sha1',   $_[0], $_[1])}, 'txt' => "Certificate Fingerprint SHA1"},
    'fingerprint_md5'   => {'val' => sub { __SSLinfo('fingerprint_md5',    $_[0], $_[1])}, 'txt' => "Certificate Fingerprint  MD5"},
    'fingerprint'       => {'val' => sub { __SSLinfo('fingerprint',        $_[0], $_[1])}, 'txt' => "Certificate Fingerprint"},
    'cert_type'         => {'val' => sub { SSLinfo::cert_type(             $_[0], $_[1])}, 'txt' => "Certificate Type (bitmask)"},
    'sslversion'        => {'val' => sub { SSLinfo::SSLversion(            $_[0], $_[1])}, 'txt' => "Selected SSL Protocol"},
    'resumption'        => {'val' => sub { SSLinfo::resumption(            $_[0], $_[1])}, 'txt' => "Target supports Resumption"},
    'renegotiation'     => {'val' => sub { SSLinfo::renegotiation(         $_[0], $_[1])}, 'txt' => "Target supports Renegotiation"},
    'compression'       => {'val' => sub { SSLinfo::compression(           $_[0], $_[1])}, 'txt' => "Target supports Compression"},
    'expansion'         => {'val' => sub { SSLinfo::expansion(             $_[0], $_[1])}, 'txt' => "Target supports Expansion"},
    'krb5'              => {'val' => sub { SSLinfo::krb5(                  $_[0], $_[1])}, 'txt' => "Target supports Krb5"},
    'psk_hint'          => {'val' => sub { SSLinfo::psk_hint(              $_[0], $_[1])}, 'txt' => "Target supports PSK Identity Hint"},
    'psk_identity'      => {'val' => sub { SSLinfo::psk_identity(          $_[0], $_[1])}, 'txt' => "Target supports PSK"},
    'srp'               => {'val' => sub { SSLinfo::srp(                   $_[0], $_[1])}, 'txt' => "Target supports SRP"},
    'heartbeat'         => {'val' => sub { __SSLinfo('heartbeat',          $_[0], $_[1])}, 'txt' => "Target supports Heartbeat"},
    'master_secret'     => {'val' => sub { SSLinfo::master_secret(         $_[0], $_[1])}, 'txt' => "Target supports Extended Master Secret"},
#    master_secret  is alias for extended_master_secret, TLS 1.3 and later
    'next_protocols'    => {'val' => sub { SSLinfo::next_protocols(        $_[0], $_[1])}, 'txt' => "Target's advertised protocols"},
#   'alpn'              => {'val' => sub { SSLinfo::alpn(                  $_[0], $_[1])}, 'txt' => "Target's selected protocol (ALPN)"}, # old, pre 17.04.17 version
    'alpn'              => {'val' => sub { return $info{'alpn'};                        }, 'txt' => "Target's selected protocol (ALPN)"},
    'npn'               => {'val' => sub { return $info{'npn'};                         }, 'txt' => "Target's selected protocol  (NPN)"},
    'alpns'             => {'val' => sub { return $info{'alpns'};                       }, 'txt' => "Target's supported ALPNs"},
    'npns'              => {'val' => sub { return $info{'npns'};                        }, 'txt' => "Target's supported  NPNs"},
    'master_key'        => {'val' => sub { SSLinfo::master_key(            $_[0], $_[1])}, 'txt' => "Target's Master-Key"},
    'public_key_len'    => {'val' => sub { SSLinfo::public_key_len(        $_[0], $_[1])}, 'txt' => "Target's Server public key length"}, # value reported by openssl s_client -debug ...
    'session_id'        => {'val' => sub { SSLinfo::session_id(            $_[0], $_[1])}, 'txt' => "Target's Session-ID"},
    'session_id_ctx'    => {'val' => sub { SSLinfo::session_id_ctx(        $_[0], $_[1])}, 'txt' => "Target's Session-ID-ctx"},
    'session_protocol'  => {'val' => sub { SSLinfo::session_protocol(      $_[0], $_[1])}, 'txt' => "Target's selected SSL Protocol"},
    'session_ticket'    => {'val' => sub { SSLinfo::session_ticket(        $_[0], $_[1])}, 'txt' => "Target's TLS Session Ticket"},
    'session_lifetime'  => {'val' => sub { SSLinfo::session_lifetime(      $_[0], $_[1])}, 'txt' => "Target's TLS Session Ticket Lifetime"},
    'session_timeout'   => {'val' => sub { SSLinfo::session_timeout(       $_[0], $_[1])}, 'txt' => "Target's TLS Session Timeout"},
    'session_starttime' => {'val' => sub { SSLinfo::session_starttime(     $_[0], $_[1])}, 'txt' => "Target's TLS Session Start Time EPOCH"},
    'session_startdate' => {'val' => sub { SSLinfo::session_startdate(     $_[0], $_[1])}, 'txt' => "Target's TLS Session Start Time locale"},
    'dh_parameter'      => {'val' => sub { SSLinfo::dh_parameter(          $_[0], $_[1])}, 'txt' => "Target's DH Parameter"},
    'chain'             => {'val' => sub { SSLinfo::chain(                 $_[0], $_[1])}, 'txt' => "Certificate Chain"},
    'chain_verify'      => {'val' => sub { SSLinfo::chain_verify(          $_[0], $_[1])}, 'txt' => "CA Chain Verification (trace)"},
    'verify'            => {'val' => sub { SSLinfo::verify(                $_[0], $_[1])}, 'txt' => "Validity Certificate Chain"},
    'error_verify'      => {'val' => sub { SSLinfo::error_verify(          $_[0], $_[1])}, 'txt' => "CA Chain Verification error"},
    'error_depth'       => {'val' => sub { SSLinfo::error_depth(           $_[0], $_[1])}, 'txt' => "CA Chain Verification error in level"},
    'verify_altname'    => {'val' => sub { SSLinfo::verify_altname(        $_[0], $_[1])}, 'txt' => "Validity Alternate Names"},
    'verify_hostname'   => {'val' => sub { SSLinfo::verify_hostname(       $_[0], $_[1])}, 'txt' => "Validity Hostname"},
    'https_protocols'   => {'val' => sub { SSLinfo::https_protocols(       $_[0], $_[1])}, 'txt' => "HTTPS Alternate-Protocol"},
    'https_content_enc' => {'val' => sub { SSLinfo::https_content_enc(     $_[0], $_[1])}, 'txt' => "HTTPS Content-Encoding"},
    'https_transfer_enc'=> {'val' => sub { SSLinfo::https_transfer_enc(    $_[0], $_[1])}, 'txt' => "HTTPS Transfer-Encoding"},
    'https_svc'         => {'val' => sub { SSLinfo::https_svc(             $_[0], $_[1])}, 'txt' => "HTTPS Alt-Svc header"},
    'https_status'      => {'val' => sub { SSLinfo::https_status(          $_[0], $_[1])}, 'txt' => "HTTPS Status line"},
    'https_server'      => {'val' => sub { SSLinfo::https_server(          $_[0], $_[1])}, 'txt' => "HTTPS Server banner"},
    'https_location'    => {'val' => sub { SSLinfo::https_location(        $_[0], $_[1])}, 'txt' => "HTTPS Location header"},
    'https_refresh'     => {'val' => sub { SSLinfo::https_refresh(         $_[0], $_[1])}, 'txt' => "HTTPS Refresh header"},
    'https_alerts'      => {'val' => sub { SSLinfo::https_alerts(          $_[0], $_[1])}, 'txt' => "HTTPS Error alerts"},
    'https_pins'        => {'val' => sub { SSLinfo::https_pins(            $_[0], $_[1])}, 'txt' => "HTTPS Public-Key-Pins header"},
    'https_body'        => {'val' => sub { SSLinfo::https_body(            $_[0], $_[1])}, 'txt' => "HTTPS Body"},
    'https_sts'         => {'val' => sub { SSLinfo::https_sts(             $_[0], $_[1])}, 'txt' => "HTTPS STS header"},
    'hsts_httpequiv'    => {'val' => sub { SSLinfo::hsts_httpequiv(        $_[0], $_[1])}, 'txt' => "HTTPS STS in http-equiv"},
    'hsts_maxage'       => {'val' => sub { SSLinfo::hsts_maxage(           $_[0], $_[1])}, 'txt' => "HTTPS STS MaxAge"},
    'hsts_subdom'       => {'val' => sub { SSLinfo::hsts_subdom(           $_[0], $_[1])}, 'txt' => "HTTPS STS include sub-domains"},
    'hsts_preload'      => {'val' => sub { SSLinfo::hsts_preload(          $_[0], $_[1])}, 'txt' => "HTTPS STS preload"},
    'http_protocols'    => {'val' => sub { SSLinfo::http_protocols(        $_[0], $_[1])}, 'txt' => "HTTP Alternate-Protocol"},
    'http_svc'          => {'val' => sub { SSLinfo::http_svc(              $_[0], $_[1])}, 'txt' => "HTTP Alt-Svc header"},
    'http_status'       => {'val' => sub { SSLinfo::http_status(           $_[0], $_[1])}, 'txt' => "HTTP Status line"},
    'http_location'     => {'val' => sub { SSLinfo::http_location(         $_[0], $_[1])}, 'txt' => "HTTP Location header"},
    'http_refresh'      => {'val' => sub { SSLinfo::http_refresh(          $_[0], $_[1])}, 'txt' => "HTTP Refresh header"},
    'http_sts'          => {'val' => sub { SSLinfo::http_sts(              $_[0], $_[1])}, 'txt' => "HTTP STS header"},
    #----------------------+-------------------------------------------------------------+-----------------------------------
    'options'           => {'val' => sub { SSLinfo::options(               $_[0], $_[1])}, 'txt' => "internal used SSL options bitmask"},
    'fallback_protocol' => {'val' => sub { print('$prot{fallback_protocol}->{val} in _init');},     'txt' => "Target's fallback SSL Protocol"},
    #----------------------+-------------------------------------------------------------+-----------------------------------
    # following not printed by default, but can be used as command
#   'PROT'              => {'val' => sub { return $OCfg::prot{'PROT'}->{'default'}           }, 'txt' => "Target default PROT     cipher"},
    # all others will be added below
    #----------------------+-------------------------------------------------------------+-----------------------------------
    # following are used for checkdates() only, they must not be a command!
    # they are not printed with +info or +check; values are integer
    'valid_years'       => {'val' =>  0, 'txt' => "certificate validity in years"      },
    'valid_months'      => {'val' =>  0, 'txt' => "certificate validity in months"     },
    'valid_days'        => {'val' =>  0, 'txt' => "certificate validity in days"       },  # approx. value, accurate if < 30
    'valid_host'        => {'val' =>  0, 'txt' => "dummy used for printing DNS stuff"  },
    #----------------------+-------------------------------------------------------------+-----------------------------------
); # %data
# need s_client for: compression|expansion|selfsigned|chain|verify|resumption|renegotiation|next_protocols|
# need s_client for: krb5|psk_hint|psk_identity|master_secret|srp|master_key|public_key_len|session_id|session_id_ctx|session_protocol|session_ticket|session_lifetime|session_timeout|session_starttime|session_startdate

our %checks = (
    # key           =>  {val => "", txt => "label to be printed", score => 0, typ => "connection"},
    #
    # default for 'val' is "" (empty string), default for 'score' is 0
    # 'typ' is any of certificate, connection, destination, https, sizes
    # both will be set in sub _init_checks_val(), please see below

    # the default "" value means "check = ok/yes", otherwise: "check =failed/no"

); # %checks

our %check_cert = (  # certificate data
    #------------------+-----------------------------------------------------
    # key                     => label to be printed (description)
    #------------------+-----------------------------------------------------
    'verify'        => {'txt' => "Certificate chain validated"},
    'fp_not_md5'    => {'txt' => "Certificate Fingerprint is not MD5"},
    'dates'         => {'txt' => "Certificate is valid"},
    'expired'       => {'txt' => "Certificate is not expired"},
    'certfqdn'      => {'txt' => "Certificate is valid according given hostname"},
    'wildhost'      => {'txt' => "Certificate's wildcard does not match hostname"},
    'wildcard'      => {'txt' => "Certificate does not contain wildcards"},
    'rootcert'      => {'txt' => "Certificate is not root CA"},
    'selfsigned'    => {'txt' => "Certificate is not self-signed"},
    'dv'            => {'txt' => "Certificate Domain Validation (DV)"},
    'ev+'           => {'txt' => "Certificate strict Extended Validation (EV)"},
    'ev-'           => {'txt' => "Certificate lazy Extended Validation (EV)"},
    'ocsp_uri'      => {'txt' => "Certificate has OCSP Responder URL"},
    'cps'           => {'txt' => "Certificate has Certification Practice Statement"},
    'crl'           => {'txt' => "Certificate has CRL Distribution Points"},
    'zlib'          => {'txt' => "Certificate has (TLS extension) compression"},
    'lzo'           => {'txt' => "Certificate has (GnuTLS extension) compression"},
    'open_pgp'      => {'txt' => "Certificate has (TLS extension) authentication"},
    'ocsp_valid'    => {'txt' => "Certificate has valid OCSP URL"},
    'cps_valid'     => {'txt' => "Certificate has valid CPS URL"},
    'crl_valid'     => {'txt' => "Certificate has valid CRL URL"},
    'sernumber'     => {'txt' => "Certificate Serial Number size RFC 5280"},
    'constraints'   => {'txt' => "Certificate Basic Constraints is false"},
    'sha2signature' => {'txt' => "Certificate Private Key Signature SHA2"},
    'modulus_exp_1' => {'txt' => "Certificate Public Key Modulus Exponent <>1"},
    'modulus_size_oldssl' => {'txt' => "Certificate Public Key Modulus >16385 bits"},
    'modulus_exp_65537' =>{'txt'=> "Certificate Public Key Modulus Exponent =65537"},
    'modulus_exp_oldssl'=>{'txt'=> "Certificate Public Key Modulus Exponent >65537"},
    'pub_encryption'=> {'txt' => "Certificate Public Key with Encryption"},
    'pub_enc_known' => {'txt' => "Certificate Public Key Encryption known"},
    'sig_encryption'=> {'txt' => "Certificate Private Key with Encryption"},
    'sig_enc_known' => {'txt' => "Certificate Private Key Encryption known"},
    'rfc_6125_names'=> {'txt' => "Certificate Names compliant to RFC 6125"},
    'rfc_2818_names'=> {'txt' => "Certificate subjectAltNames compliant to RFC 2818"},
    # following checks in subjectAltName, CRL, OCSP, CN, O, U
    'nonprint'      => {'txt' => "Certificate does not contain non-printable characters"},
    'crnlnull'      => {'txt' => "Certificate does not contain CR, NL, NULL characters"},
    'ev_chars'      => {'txt' => "Certificate has no invalid characters in extensions"},
# TODO: SRP is a target feature but also named a `Certificate (TLS extension)'
#    'srp'           => {'txt' => "Certificate has (TLS extension) authentication"},
    #------------------+-----------------------------------------------------
    # extensions:
    #   KeyUsage:
    #     0 - digitalSignature
    #     1 - nonRepudiation
    #     2 - keyEncipherment
    #     3 - dataEncipherment
    #     4 - keyAgreement
    #     5 - keyCertSign      # indicates this is CA cert
    #     6 - cRLSign
    #     7 - encipherOnly
    #     8 - decipherOnly
    # verify, is-trusted: certificate must be trusted, not expired (after also)
    #  common name or altname matches given hostname
    #     1 - no chain of trust
    #     2 - not before
    #     4 - not after
    #     8 - hostname mismatch
    #    16 - revoked
    #    32 - bad common name
    #    64 - self-signed
    # possible problems with chains:
    #   - contains untrusted certificate
    #   - chain incomplete/not resolvable
    #   - chain too long (depth)
    #   - chain size too big
    #   - contains illegal characters
    # TODO: wee need an option to specify the the local certificate storage!
); # %check_cert

our %check_conn = (  # connection data
    #------------------+-----------------------------------------------------
#   'ip'            => {'txt' => "IP for given hostname "}, # 12/2019: no check implemented
    'reversehost'   => {'txt' => "Given hostname is same as reverse resolved hostname"},
    'hostname'      => {'txt' => "Connected hostname equals certificate's Subject"},
    'beast'         => {'txt' => "Connection is safe against BEAST attack (any cipher)"},
    'breach'        => {'txt' => "Connection is safe against BREACH attack"},
    'ccs'           => {'txt' => "Connection is safe against CCS Injection attack"},
    'crime'         => {'txt' => "Connection is safe against CRIME attack"},
    'drown'         => {'txt' => "Connection is safe against DROWN attack"},
    'time'          => {'txt' => "Connection is safe against TIME attack"},
    'freak'         => {'txt' => "Connection is safe against FREAK attack"},
    'heartbleed'    => {'txt' => "Connection is safe against Heartbleed attack"},
    'logjam'        => {'txt' => "Connection is safe against Logjam attack"},
    'lucky13'       => {'txt' => "Connection is safe against Lucky 13 attack"},
    'poodle'        => {'txt' => "Connection is safe against POODLE attack"},
    'rc4'           => {'txt' => "Connection is safe against RC4 attack"},
    'robot'         => {'txt' => "Connection is safe against ROBOT attack"},
    'sloth'         => {'txt' => "Connection is safe against SLOTH attack"},
    'sweet32'       => {'txt' => "Connection is safe against Sweet32 attack"},
    'sni'           => {'txt' => "Connection is not based on SNI"},
    #------------------+-----------------------------------------------------
); # %check_conn

our %check_dest = (  # target (connection) data
    #------------------+-----------------------------------------------------
    'sgc'           => {'txt' => "Target supports Server Gated Cryptography (SGC)"},
    'hassslv2'      => {'txt' => "Target does not support SSLv2"},
    'hassslv3'      => {'txt' => "Target does not support SSLv3"},      # POODLE
    'hastls10'      => {'txt' => "Target does not supports TLSv1"},
    'hastls11'      => {'txt' => "Target does not supports TLSv1.1"},
    'hastls10_old'  => {'txt' => "Target supports TLSv1"},  # until 23.04.23 version
    'hastls11_old'  => {'txt' => "Target supports TLSv1.1"},# until 23.04.23 version
    'hastls12'      => {'txt' => "Target supports TLSv1.2"},
    'hastls13'      => {'txt' => "Target supports TLSv1.3"},
    'hasdtls1'      => {'txt' => "Target supports DTLSv1"},
    'hasdtls12'     => {'txt' => "Target supports DTLSv1.2"},
    'hasdtls13'     => {'txt' => "Target supports DTLSv1.3"},
    'hasalpn'       => {'txt' => "Target supports ALPN"},
    'hasnpn'        => {'txt' => "Target supports  NPN"},
    'cipher_strong' => {'txt' => "Target selects strongest cipher"},
    'cipher_order'  => {'txt' => "Target does not honors client's cipher order"}, # NOT YET USED
    'cipher_weak'   => {'txt' => "Target does not accept weak cipher"},
    'cipher_null'   => {'txt' => "Target does not accept NULL ciphers"},
    'cipher_adh'    => {'txt' => "Target does not accept ADH ciphers"},
    'cipher_exp'    => {'txt' => "Target does not accept EXPORT ciphers"},
    'cipher_cbc'    => {'txt' => "Target does not accept CBC ciphers"},
    'cipher_des'    => {'txt' => "Target does not accept DES ciphers"},
    'cipher_rc4'    => {'txt' => "Target does not accept RC4 ciphers"},
    'cipher_edh'    => {'txt' => "Target supports EDH ciphers"},
    'cipher_pfs'    => {'txt' => "Target supports PFS (selected cipher)"},
    'cipher_pfsall' => {'txt' => "Target supports PFS (all ciphers)"},
    'closure'       => {'txt' => "Target understands TLS closure alerts"},
    'compression'   => {'txt' => "Target does not support Compression"},
    'fallback'      => {'txt' => "Target supports fallback from TLSv1.1"},
    'ism'           => {'txt' => "Target is ISM compliant (ciphers only)"},
    'pci'           => {'txt' => "Target is PCI compliant (ciphers only)"},
    'fips'          => {'txt' => "Target is FIPS-140 compliant"},
#   'nsab'          => {'txt' => "Target is NSA Suite B compliant"},
    'tr_02102+'     => {'txt' => "Target is strict TR-02102-2 compliant"},
    'tr_02102-'     => {'txt' => "Target is  lazy  TR-02102-2 compliant"},
    'tr_03116+'     => {'txt' => "Target is strict TR-03116-4 compliant"},
    'tr_03116-'     => {'txt' => "Target is  lazy  TR-03116-4 compliant"},
    'rfc_7525'      => {'txt' => "Target is RFC 7525 compliant"},
    'sstp'          => {'txt' => "Target does not support method SSTP"},
    'resumption'    => {'txt' => "Target supports Resumption"},
    'renegotiation' => {'txt' => "Target supports Secure Renegotiation"},
    'krb5'          => {'txt' => "Target supports Krb5"},
    'psk_hint'      => {'txt' => "Target supports PSK Identity Hint"},
    'psk_identity'  => {'txt' => "Target supports PSK"},
    'srp'           => {'txt' => "Target supports SRP"},
    'ocsp_stapling' => {'txt' => "Target supports OCSP Stapling"},
    'master_secret' => {'txt' => "Target supports Extended Master Secret"},
    'session_ticket'=> {'txt' => "Target supports TLS Session Ticket"}, # sometimes missing ...
    'session_lifetime'  =>{ 'txt'=> "Target TLS Session Ticket Lifetime"},
    'session_starttime' =>{ 'txt'=> "Target TLS Session Start Time match"},
    'session_random'=> {'txt' => "Target TLS Session Ticket is random"},
    'heartbeat'     => {'txt' => "Target does not support heartbeat extension"},
    'scsv'          => {'txt' => "Target does not support SCSV"},
    # following for information, checks not useful; see "# check target specials" in checkdest also
#    'master_key'    => {'txt' => "Target supports Master-Key"},
#    'session_id'    => {'txt' => "Target supports Session-ID"},
    'dh_512'        => {'txt' => "Target DH Parameter >= 512 bits"},
    'dh_2048'       => {'txt' => "Target DH Parameter >= 2048 bits"},
    'ecdh_256'      => {'txt' => "Target DH Parameter >= 256 bits (ECDH)"},
    'ecdh_512'      => {'txt' => "Target DH Parameter >= 512 bits (ECDH)"},
    #------------------+-----------------------------------------------------
); # %check_dest

our %check_size = (  # length and count data
    # counts and sizes are integer values, key mast have prefix (len|cnt)_
    #------------------+-----------------------------------------------------
    'len_pembase64' => {'txt' => "Certificate PEM (base64) size"},  # <(2048/8*6)
    'len_pembinary' => {'txt' => "Certificate PEM (binary) size"},  # < 2048
    'len_subject'   => {'txt' => "Certificate Subject size"},       # <  256
    'len_issuer'    => {'txt' => "Certificate Issuer size"},        # <  256
    'len_cps'       => {'txt' => "Certificate CPS size"},           # <  256
    'len_crl'       => {'txt' => "Certificate CRL size"},           # <  256
    'len_crl_data'  => {'txt' => "Certificate CRL data size"},
    'len_ocsp'      => {'txt' => "Certificate OCSP size"},          # <  256
    'len_oids'      => {'txt' => "Certificate OIDs size"},
    'len_publickey' => {'txt' => "Certificate Public Key size"},    # > 1024
    # \---> same as modulus_len
    'len_sigdump'   => {'txt' => "Certificate Signature Key size"} ,# > 1024
    'len_altname'   => {'txt' => "Certificate Subject Altname size"},
    'len_chain'     => {'txt' => "Certificate Chain size"},         # < 2048
    'len_sernumber' => {'txt' => "Certificate Serial Number size"}, # <=  20 octets
    'cnt_altname'   => {'txt' => "Certificate Subject Altname count"}, # == 0
    'cnt_wildcard'  => {'txt' => "Certificate Wildcards count"},    # == 0
    'cnt_chaindepth'=> {'txt' => "Certificate Chain Depth count"},  # == 1
    'cnt_ciphers'   => {'txt' => "Total number of checked ciphers"},# <> 0
    'cnt_totals'    => {'txt' => "Total number of accepted ciphers"},
    'cnt_checks_noo'=> {'txt' => "Total number of check results 'no(<<)'"},
    'cnt_checks_no' => {'txt' => "Total number of check results 'no'"},
    'cnt_checks_yes'=> {'txt' => "Total number of check results 'yes'"},
    'cnt_exitcode'  => {'txt' => "Total number of insecure checks"},# == 0
    #------------------+-----------------------------------------------------
# TODO: cnt_ciphers, len_chain, cnt_chaindepth
); # %check_size

our %check_http = (  # HTTP vs. HTTPS data
    # key must have prefix (hsts|sts); see $OCfg::cfg{'regex'}->{'cmd-http'}
    #------------------+-----------------------------------------------------
    'sts_maxage0d'  => {'txt' => "STS max-age not reset"},           # max-age=0 is bad
    'sts_maxage1d'  => {'txt' => "STS max-age less than one day"},   # weak
    'sts_maxage1m'  => {'txt' => "STS max-age less than one month"}, # low
    'sts_maxage1y'  => {'txt' => "STS max-age less than one year"},  # medium
    'sts_maxagexy'  => {'txt' => "STS max-age more than one year"},  # high
    'sts_maxage18'  => {'txt' => "STS max-age more than 18 weeks"},  #
    'sts_expired'   => {'txt' => "STS max-age < certificate's validity"},
    'hsts_sts'      => {'txt' => "Target sends STS header"},
    'sts_maxage'    => {'txt' => "Target sends STS header with proper max-age"},
    'sts_subdom'    => {'txt' => "Target sends STS header with includeSubdomain"},
    'sts_preload'   => {'txt' => "Target sends STS header with preload"},
    'hsts_is301'    => {'txt' => "Target redirects with status code 301"}, # RFC 6797 requirement
    'hsts_is30x'    => {'txt' => "Target redirects not with 30x status code"}, # other than 301, 304
    'hsts_fqdn'     => {'txt' => "Target redirect matches given host"},
    'http_https'    => {'txt' => "Target redirects HTTP to HTTPS"},
    'hsts_location' => {'txt' => "Target sends STS and no Location header"},
    'hsts_refresh'  => {'txt' => "Target sends STS and no Refresh header"},
    'hsts_redirect' => {'txt' => "Target redirects HTTP without STS header"},
    'hsts_samehost' => {'txt' => "Target redirects HTTP to HTTPS same host"},
    'hsts_ip'       => {'txt' => "Target does not send STS header for IP"},
    'hsts_httpequiv'=> {'txt' => "Target does not send STS in meta tag"},
    'https_pins'    => {'txt' => "Target sends Public-Key-Pins header"},
    #------------------+-----------------------------------------------------
); # %check_http

our %shorttexts = (
    #------------------+------------------------------------------------------
    # %check +check     short label text
    #------------------+------------------------------------------------------
    'ip'            => "IP for hostname",
    'DNS'           => "DNS for hostname",
    'reversehost'   => "Reverse hostname",
    'hostname'      => "Hostname equals Subject",
    'expired'       => "Not expired",
    'certfqdn'      => "Valid for hostname",
    'wildhost'      => "Wilcard for hostname",
    'wildcard'      => "No wildcards",
    'sni'           => "Not SNI based",
    'sernumber'     => "Size Serial Number",
    'sha2signature' => "Signature is SHA2",
    'rootcert'      => "Not root CA",
    'ocsp_uri'      => "OCSP URL",
    'ocsp_valid'    => "OCSP valid",
    'hastls10_old'  => "TLSv1",
    'hastls11_old'  => "TLSv1.1",
    'hassslv2'      => "No SSLv2",
    'hassslv3'      => "No SSLv3",
    'hastls10'      => "No TLSv1",
    'hastls11'      => "No TLSv1.1",
    'hastls12'      => "TLSv1.2",
    'hastls13'      => "TLSv1.3",
    'hasdtls1'      => "DTLSv1",
    'hasdtls12'     => "DTLSv1.2",
    'hasdtls13'     => "DTLSv1.3",
    'hasalpn'       => "Supports ALPN",
    'hasnpn'        => "Supports  NPN",
    'alpn'          => "Selected ALPN",
    'npn'           => "Selected  NPN",
    'alpns'         => "Supported ALPNs",
    'npns'          => "Supported  NPNs",
    'master_secret' => "Supports Extended Master Secret",
#   'master_secret' => "Supports EMS",
    'next_protocols'=> "(NPN) Protocols",
    'cipher_strong' => "Strongest cipher selected",
    'cipher_order'  => "Client's cipher order",
    'cipher_weak'   => "Weak cipher selected",
    'cipher_null'   => "No NULL ciphers",
    'cipher_adh'    => "No ADH ciphers",
    'cipher_exp'    => "No EXPORT ciphers",
    'cipher_cbc'    => "No CBC ciphers",
    'cipher_des'    => "No DES ciphers",
    'cipher_rc4'    => "No RC4 ciphers",
    'cipher_edh'    => "EDH ciphers",
    'cipher_pfs'    => "PFS (selected cipher)",
    'cipher_pfsall' => "PFS (all ciphers)",
    'sgc'           => "SGC supported",
    'cps'           => "CPS supported",
    'crl'           => "CRL supported",
    'cps_valid'     => "CPS valid",
    'crl_valid'     => "CRL valid",
    'dv'            => "DV supported",
    'ev+'           => "EV supported (strict)",
    'ev-'           => "EV supported (lazy)",
    'ev_chars'      => "No invalid characters in extensions",
    'beast'         => "Safe to BEAST (cipher)",
    'breach'        => "Safe to BREACH",
    'ccs'           => "Safe to CCS",
    'crime'         => "Safe to CRIME",
    'drown'         => "Safe to DROWN",
    'time'          => "Safe to TIME",
    'freak'         => "Safe to FREAK",
    'heartbleed'    => "Safe to Heartbleed",
    'lucky13'       => "Safe to Lucky 13",
    'logjam'        => "Safe to Logjam",
    'poodle'        => "Safe to POODLE",
    'rc4'           => "Safe to RC4 attack",
    'robot'         => "Safe to ROBOT",
    'sloth'         => "Safe to SLOTH",
    'sweet32'       => "Safe to Sweet32",
    'scsv'          => "SCSV not supported",
    'constraints'   => "Basic Constraints is false",
    'modulus_exp_1' => "Modulus Exponent <>1",
    'modulus_size_oldssl'  => "Modulus >16385 bits",
    'modulus_exp_65537' =>"Modulus Exponent =65537",
    'modulus_exp_oldssl'=>"Modulus Exponent >65537",
    'pub_encryption'=> "Public Key with Encryption",
    'pub_enc_known' => "Public Key Encryption known",
    'sig_encryption'=> "Private Key with Encryption",
    'sig_enc_known' => "Private Key Encryption known",
    'rfc_6125_names'=> "Names according RFC 6125",
    'rfc_2818_names'=> "subjectAltNames according RFC 2818",
    'closure'       => "TLS closure alerts",
    'fallback'      => "Fallback from TLSv1.1",
    'zlib'          => "ZLIB extension",
    'lzo'           => "GnuTLS extension",
    'open_pgp'      => "OpenPGP extension",
    'ism'           => "ISM compliant",
    'pci'           => "PCI compliant",
    'fips'          => "FIPS-140 compliant",
    'sstp'          => "SSTP",
#   'nsab'          => "NSA Suite B compliant",
    'tr_02102+'     => "TR-02102-2 compliant (strict)",
    'tr_02102-'     => "TR-02102-2 compliant (lazy)",
    'tr_03116+'     => "TR-03116-4 compliant (strict)",
    'tr_03116-'     => "TR-03116-4 compliant (lazy)",
    'rfc_7525'      => "RFC 7525 compliant",
    'resumption'    => "Resumption",
    'renegotiation' => "Renegotiation",     # NOTE: used in %data and %check_dest
    'hsts_sts'      => "STS header",
    'sts_maxage'    => "STS long max-age",
    'sts_maxage0d'  => "STS max-age not reset",
    'sts_maxage1d'  => "STS max-age < 1 day",
    'sts_maxage1m'  => "STS max-age < 1 month",
    'sts_maxage1y'  => "STS max-age < 1 year",
    'sts_maxagexy'  => "STS max-age > 1 year",
    'sts_maxage18'  => "STS max-age > 18 weeks",
    'sts_expired'   => "STS max-age < certificate's validity",
    'sts_subdom'    => "STS includeSubdomain",
    'sts_preload'   => "STS preload",
    'hsts_httpequiv'=> "STS not in meta tag",
    'hsts_ip'       => "STS header not for IP",
    'hsts_location' => "STS and Location header",
    'hsts_refresh'  => "STS and no Refresh header",
    'hsts_redirect' => "STS within redirects",
    'http_https'    => "Redirects HTTP",
    'hsts_fqdn'     => "Redirects to same host",
    'hsts_is301'    => "Redirects with 301",
    'hsts_is30x'    => "Redirects not with 30x",
    'https_pins'    => "Public-Key-Pins",
    'selfsigned'    => "Validity (signature)",
    'chain'         => "Certificate chain",
    'verify'        => "Chain verified",
    'chain_verify'  => "CA Chain trace",
    'error_verify'  => "CA Chain error",
    'error_depth'   => "CA Chain error in level",
    'nonprint'      => "No non-printables",
    'crnlnull'      => "No CR, NL, NULL",
    'compression'   => "Compression",
    'expansion'     => "Expansion",
    'krb5'          => "Krb5 Principal",
    'psk_hint'      => "PSK Identity Hint",
    'psk_identity'  => "PSK Identity",
    'ocsp_stapling' => "OCSP Stapling",
    'ocsp_response'     => "OCSP Response",
    'ocsp_response_data'=> "OCSP Response Data",
    'ocsp_response_status' => "OCSP Response Status",
    'ocsp_cert_status'  => "OCSP Response Cert Status",
    'ocsp_next_update'  => "OCSP Response Next Update",
    'ocsp_this_update'  => "OCSP Response This Update",
    'srp'               => "SRP Username",
    'master_key'        => "Master-Key",
    'public_key_len'    => "Server public key length",
    'session_id'        => "Session-ID",
    'session_id_ctx'    => "Session-ID-ctx",
    'session_protocol'  => "Selected SSL Protocol",
    'session_ticket'    => "TLS Session Ticket",
    'session_lifetime'  => "TLS Session Ticket Lifetime",
    'session_random'    => "TLS Session Ticket random",
    'session_timeout'   => "TLS Session Timeout",
    'session_startdate' => "TLS Session Start Time locale",
    'session_starttime' => "TLS Session Start Time EPOCH",
    'dh_parameter'  => "DH Parameter",
    'dh_512'        => "DH Parameter >= 512",
    'dh_2048'       => "DH Parameter >= 2048",
    'ecdh_256'      => "DH Parameter >= 256 (ECDH)",
    'ecdh_512'      => "DH Parameter >= 512 (ECDH)",
    'ext_authority' => "Authority Information Access",
    'ext_authorityid'=>"Authority key Identifier",
    'ext_constraints'=>"Basic Constraints",
    'ext_cps'       => "Certificate Policies",
    'ext_cps_cps'   => "Certificate Policies: CPS",
    'ext_cps_policy'=> "Certificate Policies: Policy",
    'ext_cps_notice'=> "Certificate Policies: User Notice",
    'ext_crl'       => "CRL Distribution Points",
    'ext_subjectkeyid'=>"Subject Key Identifier",
    'ext_keyusage'  => "Key Usage",
    'ext_extkeyusage'=>"Extended Key Usage",
    'ext_certtype'  => "Netscape Cert Type",
    'ext_issuer'    => "Issuer Alternative Name",
    'fallback_protocol' => "Fallback SSL Protocol",
    'len_pembase64' => "Size PEM (base64)",
    'len_pembinary' => "Size PEM (binary)",
    'len_subject'   => "Size subject",
    'len_issuer'    => "Size issuer",
    'len_cps'       => "Size CPS",
    'len_crl'       => "Size CRL",
    'len_crl_data'  => "Size CRL data",
    'len_ocsp'      => "Size OCSP",
    'len_oids'      => "Size OIDs",
    'len_altname'   => "Size altname",
    'len_publickey' => "Size pubkey",
    'len_sigdump'   => "Size signature key",
    'len_chain'     => "Size certificate chain",
    'len_sernumber' => "Size serial number",
    'cnt_altname'   => "Count altname",
    'cnt_wildcard'  => "Count wildcards",
    'cnt_chaindepth'=> "Count chain depth",
    'cnt_ciphers'   => "Checked ciphers",
    'cnt_totals'    => "Accepted ciphers",
    'cnt_checks_noo'=> "Checks 'no(<<)'",
    'cnt_checks_no' => "Checks 'no'",
    'cnt_checks_yes'=> "Checks 'yes'",
    #------------------+------------------------------------------------------
    # %data +command    short label text
    #------------------+------------------------------------------------------
    'pem'           => "PEM",
    'text'          => "PEM decoded",
    'cn'            => "Common Name",
    'subject'       => "Subject",
    'issuer'        => "Issuer",
    'altname'       => "Subject AltNames",
    'ciphers'       => "Client Ciphers",
    'ciphers_local' => "SSLlib Ciphers",
    'cipher_selected'   => "Selected Cipher",
    'dates'         => "Validity (date)",
    'before'        => "Valid since",
    'after'         => "Valid until",
    'tlsextdebug'   => "TLS Extensions (debug)",
    'tlsextensions' => "TLS Extensions",
    'extensions'    => "Extensions",
    'heartbeat'     => "Heartbeat",     # not really a `key', but an extension
    'aux'           => "Trust",
    'email'         => "Email",
    'pubkey'        => "Public Key",
    'pubkey_algorithm'  => "Public Key Algorithm",
    'pubkey_value'  => "Public Key Value",
    'modulus_len'   => "Public Key Length",
    'modulus'       => "Public Key Modulus",
    'modulus_exponent'  => "Public Key Exponent",
    'serial'        => "Serial Number",
    'serial_hex'    => "Serial Number (hex)",
    'serial_int'    => "Serial Number (int)",
    'certversion'   => "Certificate Version",
    'sslversion'    => "SSL Protocol",
    'signame'       => "Signature Algorithm",
    'sigdump'       => "Signature (hexdump)",
    'sigkey_len'    => "Signature Key Length",
    'sigkey_value'  => "Signature Key Value",
    'trustout'      => "Trusted",
    'ocspid'        => "OCSP Hashes",
    'ocsp_subject_hash' => "OCSP Subject Hash",
    'ocsp_public_hash'  => "OCSP Public Hash",
    'subject_hash'  => "Subject Hash",
    'issuer_hash'   => "Issuer Hash",
    'fp_not_md5'    => "Fingerprint not MD5",
    'cert_type'     => "Certificate Type (bitmask)",
    'verify_hostname'   => "Hostname valid",
    'verify_altname'    => "AltNames valid",
    'fingerprint_hash'  => "Fingerprint Hash",
    'fingerprint_type'  => "Fingerprint Algorithm",
    'fingerprint_sha2'  => "Fingerprint SHA2",
    'fingerprint_sha1'  => "Fingerprint SHA1",
    'fingerprint_md5'   => "Fingerprint  MD5",
    'fingerprint'       => "Fingerprint:",
    'https_protocols'   => "HTTPS Alternate-Protocol",
    'https_body'    => "HTTPS Body",
    'https_svc'     => "HTTPS Alt-Svc header",
    'https_status'  => "HTTPS Status line",
    'https_server'  => "HTTPS Server banner",
    'https_location'=> "HTTPS Location header",
    'https_alerts'  => "HTTPS Error alerts",
    'https_refresh' => "HTTPS Refresh header",
    'https_pins'    => "HTTPS Public-Key-Pins header",
    'https_sts'     => "HTTPS STS header",
    'hsts_maxage'   => "HTTPS STS MaxAge",
    'hsts_subdom'   => "HTTPS STS sub-domains",
    'hsts_preload'  => "HTTPS STS preload",
    'hsts_is301'    => "HTTP Status code is 301",
    'hsts_is30x'    => "HTTP Status code not 30x",
    'hsts_samehost' => "HTTP redirect to same host",
    'http_protocols'=> "HTTP Alternate-Protocol",
    'http_svc'      => "HTTP Alt-Svc header",
    'http_status'   => "HTTP Status line",
    'http_location' => "HTTP Location header",
    'http_refresh'  => "HTTP Refresh header",
    'http_sts'      => "HTTP STS header",
    'options'       => "internal SSL bitmask",
    #------------------+------------------------------------------------------
    # more texts dynamically, see "adding more shorttexts" below
); # %shorttexts

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

# SEE Perl:Undefined subroutine
*_warn    = sub { print(join(" ", "**WARNING:", @_), "\n"); return; } if not defined &_warn;
*_dbx     = sub { print(join(" ", "#dbx#"     , @_), "\n"); return; } if not defined &_dbx;

sub __SSLinfo   { ## no critic qw(Subroutines::ProhibitExcessComplexity)
    #? wrapper for SSLinfo::*() functions
    # SSLinfo::*() return raw data, depending on $OCfg::cfg{'format'}
    # these values will be converted to o-saft's preferred format
    my ($cmd, $host, $port) = @_;
    my $val = "<<__SSLinfo: unknown command: '$cmd'>>";
    my $ext = "";
    $val =  SSLinfo::fingerprint(      $host, $port) if ($cmd eq 'fingerprint');
    $val =  SSLinfo::fingerprint_hash( $host, $port) if ($cmd eq 'fingerprint_hash');
    $val =  SSLinfo::fingerprint_sha2( $host, $port) if ($cmd eq 'fingerprint_sha2');
    $val =  SSLinfo::fingerprint_sha1( $host, $port) if ($cmd eq 'fingerprint_sha1');
    $val =  SSLinfo::fingerprint_md5(  $host, $port) if ($cmd eq 'fingerprint_md5');
    $val =  SSLinfo::pubkey_value(     $host, $port) if ($cmd eq 'pubkey_value');
    $val =  SSLinfo::sigkey_value(     $host, $port) if ($cmd eq 'sigkey_value');
    $val =  SSLinfo::heartbeat(        $host, $port) if ($cmd eq 'heartbeat');
    $val =  SSLinfo::extensions(       $host, $port) if ($cmd =~ /^ext(?:ensions|_)/);
    $val =  SSLinfo::tlsextdebug(      $host, $port) if ($cmd eq 'tlsextdebug');
    if ($cmd eq 'tlsextensions') {
        $val =  SSLinfo::tlsextensions($host, $port);
        $val =~ s/^\s*//g;
        $val =~ s/([\n\r])/; /g;
    }
    # ::ocspid may return multiple lines, something like:
    #   Subject OCSP hash: 57F4D68F870A1698065F803BE9D967B1B2B9E491
    #   Public key OCSP hash: BF788D39424E219C62538F72701E1C87C4F667EA
    # it's also assumed that both lines are present
    if ($cmd =~ /ocspid/) {
        $val =  SSLinfo::ocspid($host, $port);
        $val =~ s/^\n?\s+//g;           # remove leading spaces
        $val =~ s/([\n\r])/; /g;        # remove newlines
    }
    if ($cmd =~ /ocsp_subject_hash/) {
        $val =  SSLinfo::ocspid($host, $port);
        $val =~ s/^[^:]+:\s*//;
        $val =~ s/.ublic[^:]+:\s*.*//;
    }
    if ($cmd =~ /ocsp_public_hash/) {
        $val =  SSLinfo::ocspid($host, $port);
        $val =~ s/^[^:]+:\s*//;
        $val =~ s/^[^:]+:\s*//;     # TODO: quick&dirty
    }
    if ($cmd =~ m/ext_/) {
        # all following are part of SSLinfo::extensions(), now extract parts
        # The extension section in the certificate starts with
        #    X509v3 extensions:
        # then each extension starts with a string prefixed by  X509v3
        # except following:
        #    Authority Information Access
        #    Netscape Cert Type
        #    CT Precertificate SCTs
        #
        # Example www.microsoft.com (03/2016)
        #    X509v3 extensions:
        #        X509v3 Subject Alternative Name:
        #            DNS:privacy.microsoft.com, DNS:www.microsoft.com, DNS:wwwqa.microsoft.com
        #        X509v3 Basic Constraints:
        #            CA:FALSE
        #        X509v3 Key Usage: critical
        #            Digital Signature, Key Encipherment
        #        X509v3 Extended Key Usage:
        #            TLS Web Server Authentication, TLS Web Client Authentication
        #        X509v3 Certificate Policies:
        #            Policy: 2.16.840.1.113733.1.7.23.6
        #              CPS: https://d.symcb.com/cps
        #              User Notice:
        #                Explicit Text: https://d.symcb.com/rpa
        #        X509v3 Authority Key Identifier:
        #            keyid:0159ABE7DD3A0B59A66463D6CF200757D591E76A
        #        X509v3 CRL Distribution Points:
        #            Full Name:
        #              URI:http://sr.symcb.com/sr.crl
        #        Authority Information Access:
        #            OCSP - URI:http://sr.symcd.com
        #            CA Issuers - URI:http://sr.symcb.com/sr.crt
        #        CT Precertificate SCTs:
        #            Signed Certificate Timestamp:
        #                Version   : v1(0)
        #                Log ID    : DDEB1D2B7A0D4FA6208B81AD8168707E:
        #                            2E8E9D01D55C888D3D11C4CDB6ECBECC
        #                Timestamp : Mar 24 212018.939 2016 GMT
        #                Extensions: none
        #                Signature : ecdsa-with-SHA256
        #                            304602210095B30A493A8E8B253004AD:
        #                            A971E0106BE0CC97B6FF2908FDDBBB3D:
        #                            B8CEBFFCF8022100F37AA34DE5BE38D8:
        #                            5A03EE8B3AAE451C0014A802C079AA34:
        #                            9C20BAF44C54CF36
        #            Signed Certificate Timestamp:
        #                Version   : v1(0)
        #                Log ID    : A4B90990B418581487BB13A2CC67700A:
        #                            3C359804F91BDFB8E377CD0EC80DDC10
        #                Timestamp : Mar 24 212018.983 2016 GMT
        #                Extensions: none
        #                Signature : ecdsa-with-SHA256
        #                            3046022100C877DC1DBBDA2FBC7E5E63:
        #                            60A7EAB31EED42066F91C724963EE0CE:
        #                            80C8EBCE8C022100D5865704F32487CF:
        #                            FF021F1C8A955303E496630CAE3C0F18:
        #                            B8CDDFD4798365FD
        #        ...
        #
        # Example microsoft.com
        #    X509v3 extensions:
        #        X509v3 Key Usage:
        #            Digital Signature, Key Encipherment, Data Encipherment
        #        X509v3 Extended Key Usage:
        #            TLS Web Server Authentication, TLS Web Client Authentication
        #        S/MIME Capabilities:
        #            0000 - 30 69 30 0e 06 08 2a 86-48 86 f7 0d 03   0i0...*.H....
        #            000d - 02 02 02 00 80 30 0e 06-08 2a 86 48 86   .....0...*.H.
        #            001a - f7 0d 03 04 02 02 00 80-30 0b 06 09 60   ........0...`
        #            0027 - 86 48 01 65 03 04 01 2a-30 0b 06 09 60   .H.e...*0...`
        #            0034 - 86 48 01 65 03 04 01 2d-30 0b 06 09 60   .H.e...-0...`
        #            0041 - 86 48 01 65 03 04 01 02-30 0b 06 09 60   .H.e....0...`
        #            004e - 86 48 01 65 03 04 01 05-30 07 06 05 2b   .H.e....0...+
        #            005b - 0e 03 02 07 30 0a 06 08-2a 86 48 86 f7   ....0...*.H..
        #            0068 - 0d 03 07                                 ...
        #        X509v3 Subject Key Identifier:
        #            84C60E3B0FA69BF6EE0640CB02041B5F59340F73
        #        X509v3 Authority Key Identifier:
        #            keyid:51AF24269CF468225780262B3B4662157B1ECCA5
        #        X509v3 CRL Distribution Points:
        #            Full Name:
        #              URI:http://mscrl.microsoft.com/pki/mscorp/crl/msitwww2.crl
        #              URI:http://crl.microsoft.com/pki/mscorp/crl/msitwww2.crl
        #        Authority Information Access:
        #            CA Issuers - URI:http://www.microsoft.com/pki/mscorp/msitwww2.crt
        #            OCSP - URI:http://ocsp.msocsp.com
        #        X509v3 Certificate Policies:
        #            Policy: 1.3.6.1.4.1.311.42.1
        #              CPS: http://www.microsoft.com/pki/mscorp/cps
        #        1.3.6.1.4.1.311.21.10:
        #            0000 - 30 18 30 0a 06 08 2b 06-01 05 05 07 03   0.0...+......
        #            000d - 01 30 0a 06 08 2b 06 01-05 05 07 03 02   .0...+.......
        #        ...
        #
        # Example bsi.bund.de (03/2016)
        #    X509v3 extensions:
        #        X509v3 Authority Key Identifier:
        #            keyid:5404296FA293C6903145C03DDE2BE20A6980925F
        #        X509v3 Key Usage: critical
        #            Digital Signature, Key Encipherment
        #        X509v3 Extended Key Usage:
        #            TLS Web Client Authentication, TLS Web Server Authentication
        #        X509v3 Subject Key Identifier:
        #            1BA42D9746798AE2AE91D60AA60BE40FAA8A299E
        #        X509v3 Certificate Policies:
        #            Policy: 1.3.6.1.4.1.7879.13.2
        #              CPS: http://www.telesec.de/serverpass/cps.html
        #            Policy: 2.23.140.1.2.2
        #        X509v3 CRL Distribution Points:
        #            Full Name:
        #              URI:http://crl.serverpass.telesec.de/rl/TeleSec_ServerPass_DE-2.crl
        #            Full Name:
        #              URI:ldap://ldap.serverpass.telesec.de/cn=TeleSec%20ServerPass%20DE-2,ou=T-Systems%20Trust%20Center,o=T-Systems%20International%20GmbH,c=de?certificateRevocationlist?base?certificateRevocationlist=*
        #        Authority Information Access:
        #            OCSP - URI:http://ocsp.serverpass.telesec.de/ocspr
        #            CA Issuers - URI:http://crl.serverpass.telesec.de/crt/TeleSec_ServerPass_DE-2.cer
        #            CA Issuers - URI:ldap://ldap.serverpass.telesec.de/cn=TeleSec%20ServerPass%20DE-2,ou=T-Systems%20Trust%20Center,o=T-Systems%20International%20GmbH,c=de?cACertificate
        #        X509v3 Basic Constraints: critical
        #            CA:FALSE
        #        X509v3 Subject Alternative Name:
        #            DNS:www.bsi.bund.de
        #
        # Example www.bsi.de (06/2016)
        #    X509v3 CRL Distribution Points:
        #
        #         Full Name:
        #           URI:http://crl.serverpass.telesec.de/rl/TeleSec_ServerPass_DE-2.crl
        #
        #         Full Name:
        #           URI:ldap://ldap.serverpass.telesec.de/cn=TeleSec%20ServerPass%20DE-2,ou=T-Systems%20Trust%20Center,o=T-Systems%20International%20GmbH,c=de?certificateRevocationlist?base?certificateRevocationlist=*
        #     Authority Information Access:
        #         OCSP - URI:http://ocsp.serverpass.telesec.de/ocspr
        #         CA Issuers - URI:http://crl.serverpass.telesec.de/crt/TeleSec_ServerPass_DE-2.cer
        #         CA Issuers - URI:ldap://ldap.serverpass.telesec.de/cn=TeleSec%20ServerPass%20DE-2,ou=T-Systems%20Trust%20Center,o=T-Systems%20International%20GmbH,c=de?cACertificate
        #
        # handled in RegEx below which matches next extension, if any.
        $val .= " X509";# add string to match last extension also
        my $rex = '\s*(.*?)(?:X509|Authority|Netscape|CT Precertificate).*';
            # FIXME: the RegEx should match OIDs also
            # FIXME: otherwise OID extensions are added as value to the
            #        preceding extension, see example above (4/2016)
        # TODO: replace following list of RegEx with a loop over the extensions
        $ext = $val;
        $val =~ s#.*?Authority Information Access:$rex#$1#ms    if ($cmd eq 'ext_authority');
        $val =~ s#.*?Authority Key Identifier:$rex#$1#ms        if ($cmd eq 'ext_authorityid');
        $val =~ s#.*?Basic Constraints:$rex#$1#ms               if ($cmd eq 'ext_constraints');
        $val =~ s#.*?Key Usage:$rex#$1#ms                       if ($cmd eq 'ext_keyusage');
        $val =~ s#.*?Subject Key Identifier:$rex#$1#ms          if ($cmd eq 'ext_subjectkeyid');
        $val =~ s#.*?Certificate Policies:$rex#$1#ms            if ($cmd =~ /ext_cps/);
        $val =~ s#.*?CPS\s*:\s*([^\s\n]*).*#$1#ms               if ($cmd eq 'ext_cps_cps');
        $val =~ s#.*?Policy\s*:\s*(.*?)(?:\n|CPS|User).*#$1#ims if ($cmd eq 'ext_cps_policy');
        $val =~ s#.*?User\s*Notice:\s*(.*?)(?:\n|CPS|Policy).*#$1#ims  if ($cmd eq 'ext_cps_notice');
        $val =~ s#.*?CRL Distribution Points:$rex#$1#ms         if ($cmd eq 'ext_crl');
        $val =~ s#.*?Extended Key Usage:$rex#$1#ms              if ($cmd eq 'ext_extkeyusage');
        $val =~ s#.*?Netscape Cert Type:$rex#$1#ms              if ($cmd eq 'ext_certtype');
        $val =~ s#.*?Issuer Alternative Name:$rex#$1#ms         if ($cmd eq 'ext_issuer');
        if ($cmd eq 'ext_crl') {
            $val =~ s#\s*Full Name:\s*##imsg;   # multiple occourances possible
            $val =~ s#(\s*URI\s*:)# #msg;
        }
        $val =  "" if ($ext eq $val);   # nothing changed, then expected pattern is missing
    }
# TODO: move code for formatting to print*()
    if ($cmd =~ /ext(?:ensions|debug|_)/) {
        # grrr, formatting extensions is special, take care for traps ...
        if ($OCfg::cfg{'format'} ne "raw") {
            $val =~ s/([0-9a-f]):([0-9a-f])/$1$2/ig; # remove : inside hex (quick&dirty)
            # it was quick&dirty, correct some failures
            $val =~ s/(keyid)/$1:/i;
            $val =~ s/(CA)(FALSE)/$1:$2/i;
            if ($cmd eq 'extensions') {
                # extensions are special as they contain multiple values
                # values are separated by emty lines
                $val =~ s/\n\n+/\n/g;   # remove empty lines
            } else {
                $val =~ s/\s\s+/ /g;    # remove multiple spaces
            }
        }
        return $val; # ready!
    }
# TODO: move code for formatting to print*()
    if ($OCfg::cfg{'format'} ne "raw") {
        $val =  "" if not defined $val; # avoid warnings
        $val =~ s/^\s+//g;      # remove leading spaces
        $val =~ s/\n\s+//g;     # remove trailing spaces
        $val =~ s/\n/ /g;
        $val =~ s/\s\s+/ /g;    # remove multiple spaces
        $val =~ s/([0-9a-f]):([0-9a-f])/$1$2/ig; # remove : inside hex (quick&dirty)
    }
    return $val;
} # __SSLinfo


#_____________________________________________________________________________
#__________________________________________________________________ methods __|

=pod

=head1 METHODS

None.

=cut

#_____________________________________________________________________________
#____________________________________________________ internal test methods __|

sub show    {
    #? dispatcher for various --test-data-* options to show information
    # output similar (but not identical) to lib/OMan::man_table()
    my $arg = shift;
    printf("= %%$arg\n");
    #if ('info' eq $arg)   { # not yet used
    #printf("%21s -\t%s\n", $_, $info{$_}->{txt}) foreach (sort(keys %info));
    #}
    if ('data' eq $arg)   {
        printf("%21s -\t%s\n", $_, $data{$_}->{txt})       foreach (sort keys %data);
    }
    if ('checks' eq $arg) {
        printf("%21s -\t%s\n", $_, $checks{$_}->{txt})     foreach (sort keys %checks);
    }
    if ('check_cert' eq $arg) {
        printf("%21s -\t%s\n", $_, $check_cert{$_}->{txt}) foreach (sort keys %check_cert);
    }
    if ('check_conn' eq $arg) {
        printf("%21s -\t%s\n", $_, $check_conn{$_}->{txt}) foreach (sort keys %check_conn);
    }
    if ('check_dest' eq $arg) {
        printf("%21s -\t%s\n", $_, $check_dest{$_}->{txt}) foreach (sort keys %check_dest);
    }
    if ('check_size' eq $arg) {
        printf("%21s -\t%s\n", $_, $check_size{$_}->{txt}) foreach (sort keys %check_size);
    }
    if ('check_http' eq $arg) {
        printf("%21s -\t%s\n", $_, $check_http{$_}->{txt}) foreach (sort keys %check_http);
    }
    if ($arg =~ m/shorttexts?$/) {
        printf("%21s -\t%s\n", $_, $shorttexts{$_})        foreach (sort keys %shorttexts);
    }
    return if ($arg =~ /check_/); # cert conn dest size http
    # some settings are done in o-saft.pl, which uses OMan::man_table(), hence ...
    print <<"EoHelp";

= Please use  o-saft.pl --help=$arg  for formated output.
EoHelp
    return;
} # show

#_____________________________________________________________________________
#___________________________________________________ initialisation methods __|

sub _init_checks_val    {
    # set all default check values here
    #trace("_init_checks_val() {");
    my %_text = ( # same as %main::text
        'undef'    => "<<undefined>>",
        'na_STS'   => "<<N/A as STS not set>>",
    );
    foreach my $key (keys %checks)     { $checks{$key}->{val} = ""; }
#### temporär, bis alle so gesetzt sind {
    foreach my $key (qw(heartbeat krb5 psk_hint psk_identity srp session_ticket session_lifetime)) {
        $checks{$key}->{val}    = $_text{'undef'};
    }
#### temporär }
    foreach my $key (keys %checks) {
        $checks{$key}->{val}    =  0 if ($key =~ m/$OCfg::cfg{'regex'}->{'cmd-sizes'}/);
        $checks{$key}->{val}    =  0 if ($key =~ m/$OCfg::cfg{'regex'}->{'SSLprot'}/);
    }
    # some special values %checks{'sts_maxage*'}
    $checks{'sts_maxage0d'}->{val}  =        1;
    $checks{'sts_maxage1d'}->{val}  =    86400; # day
    $checks{'sts_maxage1m'}->{val}  =  2592000; # month
    $checks{'sts_maxage1y'}->{val}  = 31536000; # year
    $checks{'sts_maxagexy'}->{val}  = 99999999;
    $checks{'sts_maxage18'}->{val}  = 10886400; # 18 weeks
    # if $data{'https_sts'}->{val}($host) is empty {
        foreach my $key (qw(
            sts_maxage sts_expired sts_preload sts_subdom
            hsts_location hsts_refresh hsts_fqdn hsts_samehost hsts_sts
        )) {
            $checks{$key}->{val}    = $_text{'na_STS'};
        }
    # }
    foreach my $key (@{$OCfg::cfg{'cmd-vulns'}}) {
        $checks{$key}->{val}        = $_text{'undef'};  # may be refined below
    }
    foreach my $key (qw(
        cipher_null cipher_adh cipher_exp cipher_cbc cipher_des cipher_rc4
        cipher_edh  cipher_pfs cipher_pfsall
        beast breach freak logjam lucky13 rc4 robot sloth sweet32
        ism pci fips tr_02102+ tr_02102- tr_03116+ tr_03116- rfc_7525
    )) {
        $checks{$key}->{val}        = "";
    }
    #trace("_init_checks_val() }");
    return;
} # _init_checks_val

sub _init   {
    #? initialise variables

    # construct %checks from %check_* and set 'typ'
    foreach my $key (keys %check_conn) { $checks{$key}->{txt} = $check_conn{$key}->{txt}; $checks{$key}->{typ} = 'connection'; }
    foreach my $key (keys %check_cert) { $checks{$key}->{txt} = $check_cert{$key}->{txt}; $checks{$key}->{typ} = 'certificate'; }
    foreach my $key (keys %check_dest) { $checks{$key}->{txt} = $check_dest{$key}->{txt}; $checks{$key}->{typ} = 'destination'; }
    foreach my $key (keys %check_size) { $checks{$key}->{txt} = $check_size{$key}->{txt}; $checks{$key}->{typ} = 'sizes'; }
    foreach my $key (keys %check_http) { $checks{$key}->{txt} = $check_http{$key}->{txt}; $checks{$key}->{typ} = 'https'; }
    _init_checks_val(); # initialise all checks{$key}->{val}
    # more data added to %checks after defining %cfg, see main

    # more initialisation for %data add keys from %prot to %data
    # add keys from %prot to %shorttext also
    $data{'fallback_protocol'}->{'val'} = sub { return $OCfg::prot{'fallback'}->{val}  };
    foreach my $ssl (keys %OCfg::prot) {
        my $key = lc($ssl); # keys in data are all lowercase (see: convert all +CMD)
        $data{$key}->{val} = sub {    return $OCfg::prot{$ssl}->{'default'}; };
        $data{$key}->{txt} = "Target default $OCfg::prot{$ssl}->{txt} cipher";
        $shorttexts{$key}  =        "Default $OCfg::prot{$ssl}->{txt} cipher";
    }

    return;
} # _init

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

sub _main   {
    my @argv = @_;
    push(@argv, "--help") if (0 > $#argv);
    my %usage = (
        '# commands to show internal data' => {
            'info'       => 'show %data',
            'data'       => 'show %data',
            'checks'     => 'show %checks',
            'check_cert' => 'show %check_cert',
            'check_conn' => 'show %check_conn',
            'check_http' => 'show %check_http',
            'check_dest' => 'show %check_dest',
            'check_size' => 'show %check_size',
            'shorttexts' => 'show %shorttexts',
        },
    );
    # got arguments, do something special
    while (my $arg = shift @argv) {
        if ($arg =~ m/^--?h(?:elp)?$/x) { OText::print_pod($0, __PACKAGE__, $SID_odata); exit 0; }
        if ($arg eq '--usage')          { OText::usage_show("", \%usage); exit 0; }
        # ----------------------------- options
#       if ($arg =~ m/^--(?:v|trace.?CMD)/i) { $VERBOSE++; next; }  # allow --v
        # ----------------------------- commands
        if ($arg =~ /^version$/x)        { print "$SID_odata\n";next; }
        if ($arg =~ /^[-+]?V(ERSION)?$/) { print "$VERSION\n";  next; }
        $arg =~ s/^--test[_.-]?//x; # allow short option without prefix --test
        if ($arg eq 'info') { $arg = "data"; }
        show($arg);
    }
    exit 0;
} # _main

sub done    {}; # dummy to check successful include

_init();

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=head1 SEE ALSO

# ...


=head1 VERSION

3.25 2024/08/05


=head1 AUTHOR

22-jun-22 Achim Hoffmann

=cut

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main(@ARGV) if (not defined caller);

1;

