#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) 2022, Achim Hoffmann
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package OSaft::Data;

use strict;
use warnings;

my  $SID_data   =  "@(#) Data.pm 1.8 22/11/04 00:33:50";
our $VERSION    =  "22.11.22";

BEGIN {
    # SEE Perl:@INC
    # SEE Perl:BEGIN perlcritic
    my $_me   = $0;     $_me   =~ s#.*[/\\]##x;
    my $_path = $0;     $_path =~ s#[/\\][^/\\]*$##x;
    unshift(@INC, $_path)   if (1 > (grep{/^$_path$/} @INC));
    unshift(@INC, "..")     if (1 > (grep{/^\.\.$/}   @INC));
    unshift(@INC, ".")      if (1 > (grep{/^\.$/}     @INC));
}

use OSaft::Text qw(print_pod);

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8


=head1 NAME

OSaft::Data -- common SSL/TLS-connection data for O-Saft and related tools


=head1 DESCRIPTION

Utility package for O-Saft (o-saft.pl and related tools).  It declares and
defines common  L</VARIABLES>  to be used in the calling tool.
All variables and methods are defined in the  OSaft::Data  namespace.


=head1 SYNOPSIS

=over 2

=item use OSaft::Data;          # in perl code

=item OSaft/Data.pm --help      # on command-line will print help

=back


=head1 OPTIONS

=over 4

=item --help

=back


=head1 VARIABLES

=over 4

=item %checks

Computed checks.

=item %check_cert

Collected and checked certificate data.

=item %check_conn

Collected and checked connection data.

=item %check_dest

Collected and checked target (connection) data.

=item %check_http

Collected HTTP and HTTPS data.

=item %check_size

Collected and checked length and count data.

=item %data

Data from connection and certificate details.

=item %data0

Same as %data with 'val' only. Contains values from first connection only.

=item %info

Same as %data with values only.

=item %shorttexts

=back

=cut

#_____________________________________________________________________________
#________________________________________________ public (export) variables __|

# SEE Perl:perlcritic
## no critic qw(Variables::ProhibitPackageVars)

use Exporter qw(import);
use base     qw(Exporter);
our @EXPORT_OK  = qw(
        %checks
        %check_cert
        %check_conn
        %check_dest
        %check_http
        %check_size
        %data
        %data0
        %info
        %shorttexts
        data_done
);

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
    # values from Net::SSLinfo, will be processed in print_data()
    #----------------------+-------------------------------------------------------------+-----------------------------------
    # +command                    => value from Net::SSLinfo::*()                               => label to be printed
    #----------------------+-------------------------------------------------------------+-----------------------------------
    'cn_nosni'          => {'val' => "",                                                  'txt' => "Certificate CN without SNI"},
    'pem'               => {'val' => sub { Net::SSLinfo::pem(             $_[0], $_[1])}, 'txt' => "Certificate PEM"},
    'text'              => {'val' => sub { Net::SSLinfo::text(            $_[0], $_[1])}, 'txt' => "Certificate PEM decoded"},
    'cn'                => {'val' => sub { Net::SSLinfo::cn(              $_[0], $_[1])}, 'txt' => "Certificate Common Name"},
    'subject'           => {'val' => sub { Net::SSLinfo::subject(         $_[0], $_[1])}, 'txt' => "Certificate Subject"},
    'issuer'            => {'val' => sub { Net::SSLinfo::issuer(          $_[0], $_[1])}, 'txt' => "Certificate Issuer"},
    'altname'           => {'val' => sub { Net::SSLinfo::altname(         $_[0], $_[1])}, 'txt' => "Certificate Subject's Alternate Names"},
    'cipher_selected'   => {'val' => sub { Net::SSLinfo::selected(        $_[0], $_[1])}, 'txt' => "Selected Cipher"},  # SEE Note:Selected Cipher
    'ciphers_local'     => {'val' => sub { Net::SSLinfo::cipher_openssl()              }, 'txt' => "Local SSLlib Ciphers"},
    'ciphers'           => {'val' => sub { join(" ",  Net::SSLinfo::ciphers($_[0], $_[1]))}, 'txt' => "Client Ciphers"},
    'dates'             => {'val' => sub { join(" .. ", Net::SSLinfo::dates($_[0], $_[1]))}, 'txt' => "Certificate Validity (date)"},
    'before'            => {'val' => sub { Net::SSLinfo::before(          $_[0], $_[1])}, 'txt' => "Certificate valid since"},
    'after'             => {'val' => sub { Net::SSLinfo::after(           $_[0], $_[1])}, 'txt' => "Certificate valid until"},
    'aux'               => {'val' => sub { Net::SSLinfo::aux(             $_[0], $_[1])}, 'txt' => "Certificate Trust Information"},
    'email'             => {'val' => sub { Net::SSLinfo::email(           $_[0], $_[1])}, 'txt' => "Certificate Email Addresses"},
    'pubkey'            => {'val' => sub { Net::SSLinfo::pubkey(          $_[0], $_[1])}, 'txt' => "Certificate Public Key"},
    'pubkey_algorithm'  => {'val' => sub { Net::SSLinfo::pubkey_algorithm($_[0], $_[1])}, 'txt' => "Certificate Public Key Algorithm"},
    'pubkey_value'      => {'val' => sub {  ::__SSLinfo('pubkey_value',   $_[0], $_[1])}, 'txt' => "Certificate Public Key Value"},
    'modulus_len'       => {'val' => sub { Net::SSLinfo::modulus_len(     $_[0], $_[1])}, 'txt' => "Certificate Public Key Length"},
    'modulus'           => {'val' => sub { Net::SSLinfo::modulus(         $_[0], $_[1])}, 'txt' => "Certificate Public Key Modulus"},
    'modulus_exponent'  => {'val' => sub { Net::SSLinfo::modulus_exponent($_[0], $_[1])}, 'txt' => "Certificate Public Key Exponent"},
    'serial'            => {'val' => sub { Net::SSLinfo::serial(          $_[0], $_[1])}, 'txt' => "Certificate Serial Number"},
    'serial_hex'        => {'val' => sub { Net::SSLinfo::serial_hex(      $_[0], $_[1])}, 'txt' => "Certificate Serial Number (hex)"},
    'serial_int'        => {'val' => sub { Net::SSLinfo::serial_int(      $_[0], $_[1])}, 'txt' => "Certificate Serial Number (int)"},
    'certversion'       => {'val' => sub { Net::SSLinfo::version(         $_[0], $_[1])}, 'txt' => "Certificate Version"},
    'sigdump'           => {'val' => sub { Net::SSLinfo::sigdump(         $_[0], $_[1])}, 'txt' => "Certificate Signature (hexdump)"},
    'sigkey_len'        => {'val' => sub { Net::SSLinfo::sigkey_len(      $_[0], $_[1])}, 'txt' => "Certificate Signature Key Length"},
    'signame'           => {'val' => sub { Net::SSLinfo::signame(         $_[0], $_[1])}, 'txt' => "Certificate Signature Algorithm"},
    'sigkey_value'      => {'val' => sub {  ::__SSLinfo('sigkey_value',   $_[0], $_[1])}, 'txt' => "Certificate Signature Key Value"},
    'trustout'          => {'val' => sub { Net::SSLinfo::trustout(        $_[0], $_[1])}, 'txt' => "Certificate trusted"},
    'extensions'        => {'val' => sub {  ::__SSLinfo('extensions',     $_[0], $_[1])}, 'txt' => "Certificate extensions"},
    'tlsextdebug'       => {'val' => sub {  ::__SSLinfo('tlsextdebug',    $_[0], $_[1])}, 'txt' => "TLS extensions (debug)"},
    'tlsextensions'     => {'val' => sub {  ::__SSLinfo('tlsextensions',  $_[0], $_[1])}, 'txt' => "TLS extensions"},
    'ext_authority'     => {'val' => sub {  ::__SSLinfo('ext_authority',  $_[0], $_[1])}, 'txt' => "Certificate extensions Authority Information Access"},
    'ext_authorityid'   => {'val' => sub {  ::__SSLinfo('ext_authorityid',  $_[0], $_[1])}, 'txt' => "Certificate extensions Authority key Identifier"},
    'ext_constraints'   => {'val' => sub {  ::__SSLinfo('ext_constraints',  $_[0], $_[1])}, 'txt' => "Certificate extensions Basic Constraints"},
    'ext_cps'           => {'val' => sub {  ::__SSLinfo('ext_cps',        $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies"},
    'ext_cps_cps'       => {'val' => sub {  ::__SSLinfo('ext_cps_cps',    $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: CPS"},
    'ext_cps_policy'    => {'val' => sub {  ::__SSLinfo('ext_cps_policy', $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: Policy"},
    'ext_cps_notice'    => {'val' => sub {  ::__SSLinfo('ext_cps_notice', $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: User Notice"},
    'ext_crl'           => {'val' => sub {  ::__SSLinfo('ext_crl',        $_[0], $_[1])}, 'txt' => "Certificate extensions CRL Distribution Points"},
    'ext_subjectkeyid'  => {'val' => sub {  ::__SSLinfo('ext_subjectkeyid', $_[0], $_[1])}, 'txt' => "Certificate extensions Subject Key Identifier"},
    'ext_keyusage'      => {'val' => sub {  ::__SSLinfo('ext_keyusage',   $_[0], $_[1])}, 'txt' => "Certificate extensions Key Usage"},
    'ext_extkeyusage'   => {'val' => sub {  ::__SSLinfo('ext_extkeyusage',  $_[0], $_[1])}, 'txt' => "Certificate extensions Extended Key Usage"},
    'ext_certtype'      => {'val' => sub {  ::__SSLinfo('ext_certtype',   $_[0], $_[1])}, 'txt' => "Certificate extensions Netscape Cert Type"},
    'ext_issuer'        => {'val' => sub {  ::__SSLinfo('ext_issuer',     $_[0], $_[1])}, 'txt' => "Certificate extensions Issuer Alternative Name"},
    'ocsp_uri'          => {'val' => sub { Net::SSLinfo::ocsp_uri(        $_[0], $_[1])}, 'txt' => "Certificate OCSP Responder URL"},
    'ocspid'            => {'val' => sub {  ::__SSLinfo('ocspid',         $_[0], $_[1])}, 'txt' => "Certificate OCSP Hashes"},
    'ocsp_subject_hash' => {'val' => sub {  ::__SSLinfo('ocsp_subject_hash',$_[0], $_[1])}, 'txt' => "Certificate OCSP Subject Hash"},
    'ocsp_public_hash'  => {'val' => sub {  ::__SSLinfo('ocsp_public_hash', $_[0], $_[1])}, 'txt' => "Certificate OCSP Public Key Hash"},
    'ocsp_response'     => {'val' => sub { Net::SSLinfo::ocsp_response(   $_[0], $_[1])}, 'txt' => "Target's OCSP Response"},
    'ocsp_response_data'=> {'val' => sub { Net::SSLinfo::ocsp_response_data(     $_[0], $_[1])}, 'txt' => "Target's OCSP Response Data"},
    'ocsp_response_status'=> {'val' => sub { Net::SSLinfo::ocsp_response_status( $_[0], $_[1])}, 'txt' => "Target's OCSP Response Status"},
    'ocsp_cert_status'  => {'val' => sub { Net::SSLinfo::ocsp_cert_status($_[0], $_[1])}, 'txt' => "Target's OCSP Response Cert Status"},
    'ocsp_next_update'  => {'val' => sub { Net::SSLinfo::ocsp_next_update($_[0], $_[1])}, 'txt' => "Target's OCSP Response Next Update"},
    'ocsp_this_update'  => {'val' => sub { Net::SSLinfo::ocsp_this_update($_[0], $_[1])}, 'txt' => "Target's OCSP Response This Update"},
    'subject_hash'      => {'val' => sub { Net::SSLinfo::subject_hash(    $_[0], $_[1])}, 'txt' => "Certificate Subject Name Hash"},
    'issuer_hash'       => {'val' => sub { Net::SSLinfo::issuer_hash(     $_[0], $_[1])}, 'txt' => "Certificate Issuer Name Hash"},
    'selfsigned'        => {'val' => sub { Net::SSLinfo::selfsigned(      $_[0], $_[1])}, 'txt' => "Certificate Validity (signature)"},
    'fingerprint_type'  => {'val' => sub { Net::SSLinfo::fingerprint_type($_[0], $_[1])}, 'txt' => "Certificate Fingerprint Algorithm"},
    'fingerprint_hash'  => {'val' => sub {  ::__SSLinfo('fingerprint_hash', $_[0], $_[1])}, 'txt' => "Certificate Fingerprint Hash Value"},
    'fingerprint_sha2'  => {'val' => sub {  ::__SSLinfo('fingerprint_sha2', $_[0], $_[1])}, 'txt' => "Certificate Fingerprint SHA2"},
    'fingerprint_sha1'  => {'val' => sub {  ::__SSLinfo('fingerprint_sha1', $_[0], $_[1])}, 'txt' => "Certificate Fingerprint SHA1"},
    'fingerprint_md5'   => {'val' => sub {  ::__SSLinfo('fingerprint_md5',  $_[0], $_[1])}, 'txt' => "Certificate Fingerprint  MD5"},
    'fingerprint'       => {'val' => sub {  ::__SSLinfo('fingerprint',      $_[0], $_[1])}, 'txt' => "Certificate Fingerprint"},
    'cert_type'         => {'val' => sub { Net::SSLinfo::cert_type(       $_[0], $_[1])}, 'txt' => "Certificate Type (bitmask)"},
    'sslversion'        => {'val' => sub { Net::SSLinfo::SSLversion(      $_[0], $_[1])}, 'txt' => "Selected SSL Protocol"},
    'resumption'        => {'val' => sub { Net::SSLinfo::resumption(      $_[0], $_[1])}, 'txt' => "Target supports Resumption"},
    'renegotiation'     => {'val' => sub { Net::SSLinfo::renegotiation(   $_[0], $_[1])}, 'txt' => "Target supports Renegotiation"},
    'compression'       => {'val' => sub { Net::SSLinfo::compression(     $_[0], $_[1])}, 'txt' => "Target supports Compression"},
    'expansion'         => {'val' => sub { Net::SSLinfo::expansion(       $_[0], $_[1])}, 'txt' => "Target supports Expansion"},
    'krb5'              => {'val' => sub { Net::SSLinfo::krb5(            $_[0], $_[1])}, 'txt' => "Target supports Krb5"},
    'psk_hint'          => {'val' => sub { Net::SSLinfo::psk_hint(        $_[0], $_[1])}, 'txt' => "Target supports PSK Identity Hint"},
    'psk_identity'      => {'val' => sub { Net::SSLinfo::psk_identity(    $_[0], $_[1])}, 'txt' => "Target supports PSK"},
    'srp'               => {'val' => sub { Net::SSLinfo::srp(             $_[0], $_[1])}, 'txt' => "Target supports SRP"},
    'heartbeat'         => {'val' => sub {   ::__SSLinfo('heartbeat',     $_[0], $_[1])}, 'txt' => "Target supports Heartbeat"},
    'master_secret'     => {'val' => sub { Net::SSLinfo::master_secret(   $_[0], $_[1])}, 'txt' => "Target supports Extended Master Secret"},
#    master_secret  is alias for extended_master_secret, TLS 1.3 and later
    'next_protocols'    => {'val' => sub { Net::SSLinfo::next_protocols(  $_[0], $_[1])}, 'txt' => "Target's advertised protocols"},
#   'alpn'              => {'val' => sub { Net::SSLinfo::alpn(            $_[0], $_[1])}, 'txt' => "Target's selected protocol (ALPN)"}, # old, pre 17.04.17 version
    'alpn'              => {'val' => sub { return $info{'alpn'};                       }, 'txt' => "Target's selected protocol (ALPN)"},
    'npn'               => {'val' => sub { return $info{'npn'};                        }, 'txt' => "Target's selected protocol  (NPN)"},
    'alpns'             => {'val' => sub { return $info{'alpns'};                      }, 'txt' => "Target's supported ALPNs"},
    'npns'              => {'val' => sub { return $info{'npns'};                       }, 'txt' => "Target's supported  NPNs"},
    'master_key'        => {'val' => sub { Net::SSLinfo::master_key(      $_[0], $_[1])}, 'txt' => "Target's Master-Key"},
    'public_key_len'    => {'val' => sub { Net::SSLinfo::public_key_len(  $_[0], $_[1])}, 'txt' => "Target's Server public key length"}, # value reported by openssl s_client -debug ...
    'session_id'        => {'val' => sub { Net::SSLinfo::session_id(      $_[0], $_[1])}, 'txt' => "Target's Session-ID"},
    'session_id_ctx'    => {'val' => sub { Net::SSLinfo::session_id_ctx(  $_[0], $_[1])}, 'txt' => "Target's Session-ID-ctx"},
    'session_protocol'  => {'val' => sub { Net::SSLinfo::session_protocol($_[0], $_[1])}, 'txt' => "Target's selected SSL Protocol"},
    'session_ticket'    => {'val' => sub { Net::SSLinfo::session_ticket(  $_[0], $_[1])}, 'txt' => "Target's TLS Session Ticket"},
    'session_lifetime'  => {'val' => sub { Net::SSLinfo::session_lifetime($_[0], $_[1])}, 'txt' => "Target's TLS Session Ticket Lifetime"},
    'session_timeout'   => {'val' => sub { Net::SSLinfo::session_timeout( $_[0], $_[1])}, 'txt' => "Target's TLS Session Timeout"},
    'session_starttime' => {'val' => sub { Net::SSLinfo::session_starttime($_[0],$_[1])}, 'txt' => "Target's TLS Session Start Time EPOCH"},
    'session_startdate' => {'val' => sub { Net::SSLinfo::session_startdate($_[0],$_[1])}, 'txt' => "Target's TLS Session Start Time locale"},
    'dh_parameter'      => {'val' => sub { Net::SSLinfo::dh_parameter(    $_[0], $_[1])}, 'txt' => "Target's DH Parameter"},
    'chain'             => {'val' => sub { Net::SSLinfo::chain(           $_[0], $_[1])}, 'txt' => "Certificate Chain"},
    'chain_verify'      => {'val' => sub { Net::SSLinfo::chain_verify(    $_[0], $_[1])}, 'txt' => "CA Chain Verification (trace)"},
    'verify'            => {'val' => sub { Net::SSLinfo::verify(          $_[0], $_[1])}, 'txt' => "Validity Certificate Chain"},
    'error_verify'      => {'val' => sub { Net::SSLinfo::error_verify(    $_[0], $_[1])}, 'txt' => "CA Chain Verification error"},
    'error_depth'       => {'val' => sub { Net::SSLinfo::error_depth(     $_[0], $_[1])}, 'txt' => "CA Chain Verification error in level"},
    'verify_altname'    => {'val' => sub { Net::SSLinfo::verify_altname(  $_[0], $_[1])}, 'txt' => "Validity Alternate Names"},
    'verify_hostname'   => {'val' => sub { Net::SSLinfo::verify_hostname( $_[0], $_[1])}, 'txt' => "Validity Hostname"},
    'https_protocols'   => {'val' => sub { Net::SSLinfo::https_protocols( $_[0], $_[1])}, 'txt' => "HTTPS Alternate-Protocol"},
    'https_svc'         => {'val' => sub { Net::SSLinfo::https_svc(       $_[0], $_[1])}, 'txt' => "HTTPS Alt-Svc header"},
    'https_status'      => {'val' => sub { Net::SSLinfo::https_status(    $_[0], $_[1])}, 'txt' => "HTTPS Status line"},
    'https_server'      => {'val' => sub { Net::SSLinfo::https_server(    $_[0], $_[1])}, 'txt' => "HTTPS Server banner"},
    'https_location'    => {'val' => sub { Net::SSLinfo::https_location(  $_[0], $_[1])}, 'txt' => "HTTPS Location header"},
    'https_refresh'     => {'val' => sub { Net::SSLinfo::https_refresh(   $_[0], $_[1])}, 'txt' => "HTTPS Refresh header"},
    'https_alerts'      => {'val' => sub { Net::SSLinfo::https_alerts(    $_[0], $_[1])}, 'txt' => "HTTPS Error alerts"},
    'https_pins'        => {'val' => sub { Net::SSLinfo::https_pins(      $_[0], $_[1])}, 'txt' => "HTTPS Public-Key-Pins header"},
    'https_body'        => {'val' => sub { Net::SSLinfo::https_body(      $_[0], $_[1])}, 'txt' => "HTTPS Body"},
    'https_sts'         => {'val' => sub { Net::SSLinfo::https_sts(       $_[0], $_[1])}, 'txt' => "HTTPS STS header"},
    'hsts_httpequiv'    => {'val' => sub { Net::SSLinfo::hsts_httpequiv(  $_[0], $_[1])}, 'txt' => "HTTPS STS in http-equiv"},
    'hsts_maxage'       => {'val' => sub { Net::SSLinfo::hsts_maxage(     $_[0], $_[1])}, 'txt' => "HTTPS STS MaxAge"},
    'hsts_subdom'       => {'val' => sub { Net::SSLinfo::hsts_subdom(     $_[0], $_[1])}, 'txt' => "HTTPS STS include sub-domains"},
    'hsts_preload'      => {'val' => sub { Net::SSLinfo::hsts_preload(    $_[0], $_[1])}, 'txt' => "HTTPS STS preload"},
    'http_protocols'    => {'val' => sub { Net::SSLinfo::http_protocols(  $_[0], $_[1])}, 'txt' => "HTTP Alternate-Protocol"},
    'http_svc'          => {'val' => sub { Net::SSLinfo::http_svc(        $_[0], $_[1])}, 'txt' => "HTTP Alt-Svc header"},
    'http_status'       => {'val' => sub { Net::SSLinfo::http_status(     $_[0], $_[1])}, 'txt' => "HTTP Status line"},
    'http_location'     => {'val' => sub { Net::SSLinfo::http_location(   $_[0], $_[1])}, 'txt' => "HTTP Location header"},
    'http_refresh'      => {'val' => sub { Net::SSLinfo::http_refresh(    $_[0], $_[1])}, 'txt' => "HTTP Refresh header"},
    'http_sts'          => {'val' => sub { Net::SSLinfo::http_sts(        $_[0], $_[1])}, 'txt' => "HTTP STS header"},
    #----------------------+-------------------------------------------------------------+-----------------------------------
    'options'           => {'val' => sub { Net::SSLinfo::options(         $_[0], $_[1])}, 'txt' => "internal used SSL options bitmask"},
    'fallback_protocol' => {'val' => sub { print('$prot{fallback}->{val} in _data_init');},'txt' => "Target's fallback SSL Protocol"},
    #----------------------+-------------------------------------------------------------+-----------------------------------
    # following not printed by default, but can be used as command
#   'PROT'              => {'val' => sub { return $prot{'PROT'}->{'default'}           }, 'txt' => "Target default PROT     cipher"},
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
    # both will be set in sub _init_all(), please see below

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
     # NOTE: following keys use mixed case letters, that's ok 'cause these
     #       checks are not called by their own commands; ugly hack ...
    #------------------+-----------------------------------------------------
); # %check_conn

our %check_dest = (  # target (connection) data
    #------------------+-----------------------------------------------------
    'sgc'           => {'txt' => "Target supports Server Gated Cryptography (SGC)"},
    'hassslv2'      => {'txt' => "Target does not support SSLv2"},
    'hassslv3'      => {'txt' => "Target does not support SSLv3"},      # POODLE
    'hastls10'      => {'txt' => "Target supports TLSv1"},
    'hastls11'      => {'txt' => "Target supports TLSv1.1"},
    'hastls12'      => {'txt' => "Target supports TLSv1.2"},
    'hastls13'      => {'txt' => "Target supports TLSv1.3"},
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
    'cnt_ciphers'   => {'txt' => "Total number of offered ciphers"},# <> 0
    'cnt_totals'    => {'txt' => "Total number of checked ciphers"},
    'cnt_checks_noo'=> {'txt' => "Total number of check results 'no(<<)'"},
    'cnt_checks_no' => {'txt' => "Total number of check results 'no'"},
    'cnt_checks_yes'=> {'txt' => "Total number of check results 'yes'"},
    'cnt_exitcode'  => {'txt' => "Total number of insecure checks"},# == 0
    #------------------+-----------------------------------------------------
# TODO: cnt_ciphers, len_chain, cnt_chaindepth
); # %check_size

our %check_http = (  # HTTP vs. HTTPS data
    # key must have prefix (hsts|sts); see $cfg{'regex'}->{'cmd-http'}
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
    'hassslv2'      => "No SSLv2",
    'hassslv3'      => "No SSLv3",
    'hastls10'      => "TLSv1",
    'hastls11'      => "TLSv1.1",
    'hastls12'      => "TLSv1.2",
    'hastls13'      => "TLSv1.3",
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
    'cnt_ciphers'   => "Count ciphers",
    'cnt_totals'    => "Checked ciphers",
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

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

=pod

=head1 METHODS

None.

=cut

#_____________________________________________________________________________
#____________________________________________________ internal test methods __|

sub show            {
    return;
} # show

#_____________________________________________________________________________
#___________________________________________________ initialisation methods __|

sub _data_init      {
    #? initialise variables

    # construct %checks from %check_* and set 'typ'
    foreach my $key (keys %check_conn) { $checks{$key}->{txt} = $check_conn{$key}->{txt}; $checks{$key}->{typ} = 'connection'; }
    foreach my $key (keys %check_cert) { $checks{$key}->{txt} = $check_cert{$key}->{txt}; $checks{$key}->{typ} = 'certificate'; }
    foreach my $key (keys %check_dest) { $checks{$key}->{txt} = $check_dest{$key}->{txt}; $checks{$key}->{typ} = 'destination'; }
    foreach my $key (keys %check_size) { $checks{$key}->{txt} = $check_size{$key}->{txt}; $checks{$key}->{typ} = 'sizes'; }
    foreach my $key (keys %check_http) { $checks{$key}->{txt} = $check_http{$key}->{txt}; $checks{$key}->{typ} = 'https'; }
    foreach my $key (keys %checks)     { $checks{$key}->{val} = ""; }
    # more data added to %checks after defining %cfg, see main

    # TODO: must be done in main:
    #$data{'fallback_protocol'}->{'val'} = sub { return $prot{'fallback'}->{val}  };
    ## add keys from %prot to %shorttext,
    #foreach my $ssl (keys %prot) {
    #    my $key = lc($ssl); # keys in data are all lowercase (see: convert all +CMD)
    #    $shorttexts{$key} = "Default $prot{$ssl}->{txt} cipher";
    #}

    return;
} # _data_init

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

sub _main_data      {
    my @argv = @_;
    push(@argv, "--help") if (0 > $#argv);
    binmode(STDOUT, ":unix:utf8"); ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    binmode(STDERR, ":unix:utf8"); ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    # got arguments, do something special
    while (my $arg = shift @argv) {
        print_pod($0, __PACKAGE__, $SID_data)   if ($arg =~ m/^--?h(?:elp)?$/x);
        # ----------------------------- options
#       if ($arg =~ m/^--(?:v|trace.?CMD)/i) { $VERBOSE++; next; }  # allow --v
        # ----------------------------- commands
        if ($arg =~ /^version$/)         { print "$SID_data\n"; next; }
        if ($arg =~ /^[-+]?V(ERSION)?$/) { print "$VERSION\n";  next; }
        if ($arg =~ m/^--(?:test[_.-]?)data/x) {
            $arg = "--test-data";
#?#            printf("#$0: direct testing not yet possible, please try:\n   o-saft.pl $arg\n");
        }
    }
    exit 0;
} # _main_data

sub data_done       {}; # dummy to check successful include

_data_init();

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=head1 SEE ALSO

# ...

=head1 VERSION

1.8 2022/11/04

=head1 AUTHOR

22-jun-22 Achim Hoffmann

=cut

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main_data(@ARGV) if (not defined caller);

1;

