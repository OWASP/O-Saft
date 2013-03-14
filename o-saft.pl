#!/usr/bin/perl

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
#!# Permits anyone the right to use and modify the software without limitations
#!# as long as proper  credits are given  and the original  and modified source
#!# code are included. Requires  that the final product, software derivate from
#!# the original  source or any  software  utilizing a GPL  component, such  as
#!# this, is also licensed under the same GPL license.
#!#############################################################################

#!# WARNING:
#!# This is no "academically" certified code, but written to be understood
#!# and modified by humans (you:) easily. Please see the proper section in
#!# the documentation  "Program Code"  at the end of this file if you want
#!# to improve the program.

# ToDo please see  =begin ToDo  in POD section

use strict;

my $SID     = "@(#) yeast.pl 1.86 13/03/14 07:55:16";
my $VERSION = "--is defined at end of this file, and I hate to write it twice--";
my @DATA    = <DATA>;
{ # perl is clever enough to extract it from itself ;-)
    $VERSION = join ('', @DATA);
    $VERSION =~ s/.*?\n@\(#\)\s*([^\n]*).*/$1/ms;
};

my $me      = $0; $me     =~ s#.*/##;
my $mepath  = $0; $mepath =~ s#/[^/]*$##;
   $mepath  = './' if ($mepath eq $me);
my $mename  = 'yeast ';
   $mename  = 'O-Saft' if ($me !~ /yeast/);

use IO::Socket::SSL; #  qw(debug2);
use IO::Socket::INET;

# quick&dirty checks
# -------------------------------------
if (!defined $Net::SSLeay::VERSION) { # Net::SSLeay auto-loaded by IO::Socket::SSL
    die "**ERROR: Net::SSLeay not found, useless use of yet another SSL tool";
    # ToDo: this is not really true, i.e. if we use openssl instead Net::SSLeay
}

if (! eval("require Net::SSLinfo;")) {
    # Net::SSLinfo may not be installed, try to find in program's directory
    push(@INC, $mepath);
    require Net::SSLinfo;
}

my @argv = @ARGV;
my $arg;

# CGI
# -------------------------------------
my $cgi    = 0;
if ($me =~/\.cgi$/) {
    # CGI mode is pretty simple: see {yeast,o-saft}.cgi
    die "**ERROR: CGI mode requires strict settings" if ($cgi !~ /--cgi=?/);
}

#!# set defaults
#!# -------------------------------------
#!# To make (programmer's) life simple, we try to avoid complex data structure,
#!# which are error-prone, by using a couple of global variables.
#!# As there are no plans to run this tool in threaded mode, this should be ok.
#!# Please see "Program Code" in the POD section too.
#!#
#!# Here's an overview of the used global variables:
#!#   @results        - where we store the results as:  'cipher' => 'yes|no'
#!#   %data           - labels and correspondig value (from Net::SSLinfo)
#!#   %check_cert     - collected and checked certificate data
#!#   %check_dest     - collected and checked target (connection) data
#!#   %check_conn     - collected and checked connection data
#!#   %check_size     - collected and checked length and count data
#!#   %check_http     - NOT YET IMPLEMENTED
#!#   %shorttexts     - same as %check_*, but short texts
#!#   %cmd            - configuration for external commands
#!#   %cfg            - configuration for commands and options
#!#   %text           - configuration for texts
#!#   %ciphers_desc   - description of %ciphers data structure
#!#   %ciphers        - our ciphers
#!#
#!# All %check_*  contain a default 'score' value of 10, see --set-score
#!# option how to chain that.

my $info = 0;       # set to 1 if +info or +sni_check was used
my @results = ();
my %data = (        # values will be processed in printtext()
    #!#----------------+-----------------------------------------------------------+-----------------------------------
    #!# +command                 value from Net::SSLinfo::*()                                label to be printed
    #!#----------------+-----------------------------------------------------------+-----------------------------------
    'cn_nossni'     => {'val' => '',                                                'txt' => "Certificate CN without SNI"},
    'certificate'   => {'val' => sub { Net::SSLinfo::pem(           $_[0], $_[1])}, 'txt' => "Certificate PEM:\n"},
    'pem'           => {'val' => sub { Net::SSLinfo::pem(           $_[0], $_[1])}, 'txt' => "Certificate PEM:\n"},
    'PEM'           => {'val' => sub { Net::SSLinfo::pem(           $_[0], $_[1])}, 'txt' => "Certificate PEM:\n"},
    'text'          => {'val' => sub { Net::SSLinfo::text(          $_[0], $_[1])}, 'txt' => "Certificate PEM decoded:\n"},
    'cn'            => {'val' => sub { Net::SSLinfo::cn(            $_[0], $_[1])}, 'txt' => "Certificate Common Name"},
    'commonName'    => {'val' => sub { Net::SSLinfo::cn(            $_[0], $_[1])}, 'txt' => "Certificate Common Name"},
    'subject'       => {'val' => sub { Net::SSLinfo::subject(       $_[0], $_[1])}, 'txt' => "Certificate Subject"},
    'subjectX509'   => {'val' => sub { Net::SSLinfo::subject(       $_[0], $_[1])}, 'txt' => "Certificate Subject"},
    'owner'         => {'val' => sub { Net::SSLinfo::subject(       $_[0], $_[1])}, 'txt' => "Certificate Subject"},
    'issuer'        => {'val' => sub { Net::SSLinfo::issuer(        $_[0], $_[1])}, 'txt' => "Certificate Issuer"},
    'issuerX509'    => {'val' => sub { Net::SSLinfo::issuer(        $_[0], $_[1])}, 'txt' => "Certificate Issuer"},
    'authority'     => {'val' => sub { Net::SSLinfo::issuer(        $_[0], $_[1])}, 'txt' => "Certificate Issuer"},
    'altname'       => {'val' => sub { Net::SSLinfo::altname(       $_[0], $_[1])}, 'txt' => "Certificate Subject's Alternate Names"},
    'default'       => {'val' => sub { Net::SSLinfo::default(       $_[0], $_[1])}, 'txt' => "Default Cipher"},
    'ciphers_openssl'=>{'val' => sub { $_[0] },                                     'txt' => "OpenSSL Ciphers"},
    'ciphers'       => {'val' => sub { join(" ",  Net::SSLinfo::ciphers($_[0], $_[1]))}, 'txt' => "Client Ciphers"},
    'dates'         => {'val' => sub { join(" .. ", Net::SSLinfo::dates($_[0], $_[1]))}, 'txt' => "Certificate Validity"},
    'valid'         => {'val' => sub { join(" .. ", Net::SSLinfo::dates($_[0], $_[1]))}, 'txt' => "Certificate Validity"},
    'before'        => {'val' => sub { Net::SSLinfo::before(        $_[0], $_[1])}, 'txt' => "Certificate valid since"},
    'after'         => {'val' => sub { Net::SSLinfo::after(         $_[0], $_[1])}, 'txt' => "Certificate valid until"},
    'expire'        => {'val' => sub { Net::SSLinfo::after(         $_[0], $_[1])}, 'txt' => "Certificate valid until"},
    'aux'           => {'val' => sub { Net::SSLinfo::aux(           $_[0], $_[1])}, 'txt' => "Certificate Trust Information"},
    'email'         => {'val' => sub { Net::SSLinfo::email(         $_[0], $_[1])}, 'txt' => "Certificate email addresses"},
    'pubkey'        => {'val' => sub { Net::SSLinfo::pubkey(        $_[0], $_[1])}, 'txt' => "Certificate Public Key:\n"},
    'pubkey_algorithm'=>{'val'=> sub { Net::SSLinfo::pubkey_algorithm($_[0],$_[1])},'txt' => "Certificate Public Key Algorithm"},
    'modulus_len'   => {'val' => sub { Net::SSLinfo::modulus_len(   $_[0], $_[1])}, 'txt' => "Certificate Public Key length"},
    'modulus'       => {'val' => sub { Net::SSLinfo::modulus(       $_[0], $_[1])}, 'txt' => "Certificate Public Key modulus"},
    'modulus_exponent'=>{'val'=> sub { Net::SSLinfo::modulus_exponent($_[0],$_[1])},'txt' => "Certificate Public Key exponent"},
    'serial'        => {'val' => sub { Net::SSLinfo::serial(        $_[0], $_[1])}, 'txt' => "Certificate Serial Number"},
    'sigdump'       => {'val' => sub { Net::SSLinfo::sigdump(       $_[0], $_[1])}, 'txt' => "Certificate Signature (hexdump):\n"},
    'signame'       => {'val' => sub { Net::SSLinfo::signame(       $_[0], $_[1])}, 'txt' => "Certificate Signature Algorithm"},
    'sigdump_len'   => {'val' => sub { Net::SSLinfo::sigdump_len(   $_[0], $_[1])}, 'txt' => "Certificate Signature Key length"},
    'trustout'      => {'val' => sub { Net::SSLinfo::trustout(      $_[0], $_[1])}, 'txt' => "Certificate trusted"},
#   'ocsp_uri'      => {'val' => sub { Net::SSLinfo::ocsp_uri(      $_[0], $_[1])}, 'txt' => "Certificate Authority Information Access:"},
#   'ocspid'        => {'val' => sub { Net::SSLinfo::ocspid(        $_[0], $_[1])}, 'txt' => "Certificate Authority Information Access ID:"},
    'ocsp_uri'      => {'val' => sub { Net::SSLinfo::ocsp_uri(      $_[0], $_[1])}, 'txt' => "Certificate OCSP Responder URL"},
    'ocspid'        => {'val' => sub { Net::SSLinfo::ocspid(        $_[0], $_[1])}, 'txt' => "Certificate OCSP subject, public key hash"},
    'subject_hash'  => {'val' => sub { Net::SSLinfo::subject_hash(  $_[0], $_[1])}, 'txt' => "Certificate Subject Name hash"},
    'issuer_hash'   => {'val' => sub { Net::SSLinfo::issuer_hash(   $_[0], $_[1])}, 'txt' => "Certificate Issuer Name hash"},
    'resumption'    => {'val' => sub { Net::SSLinfo::resumption(    $_[0], $_[1])}, 'txt' => "Target supports resumption"},
    'renegotiation' => {'val' => sub { Net::SSLinfo::renegotiation( $_[0], $_[1])}, 'txt' => "Target supports renegotiation"},
    'selfsigned'    => {'val' => sub { Net::SSLinfo::selfsigned(    $_[0], $_[1])}, 'txt' => "Certificate validity"},
    'compression'   => {'val' => sub { Net::SSLinfo::compression(   $_[0], $_[1])}, 'txt' => "Target supports compression"},
    'expansion'     => {'val' => sub { Net::SSLinfo::expansion(     $_[0], $_[1])}, 'txt' => "Target supports expansion"},
    'verify'        => {'val' => sub { Net::SSLinfo::verify(        $_[0], $_[1])}, 'txt' => "Validity Certificate Chain"},
    'verify_hostname'=>{'val' => sub { Net::SSLinfo::verify_hostname( $_[0],$_[1])},'txt' => "Validity Hostname"},
    'verify_altname'=> {'val' => sub { Net::SSLinfo::verify_altname(  $_[0],$_[1])},'txt' => "Validity Alternate Names"},
    'fingerprint_hash'=>{'val'=> sub { Net::SSLinfo::fingerprint_hash($_[0],$_[1])},'txt' => "Certificate Fingerprint Hash Value"},
    'fingerprint_sha1'=>{'val'=> sub { Net::SSLinfo::fingerprint_sha1($_[0],$_[1])},'txt' => "Certificate Fingerprint SHA1"},
    'fingerprint_md5' =>{'val'=> sub { Net::SSLinfo::fingerprint_md5( $_[0],$_[1])},'txt' => "Certificate Fingerprint  MD5"},
    'fingerprint_type'=>{'val'=> sub { Net::SSLinfo::fingerprint_type($_[0],$_[1])},'txt' => "Certificate Fingerprint Algorithm"},
    'fingerprint'   => {'val' => sub { Net::SSLinfo::fingerprint(   $_[0], $_[1])}, 'txt' => "Certificate Fingerprint"},
    'http_status'   => {'val' => sub { Net::SSLinfo::http_status(   $_[0], $_[1])}, 'txt' => "HTTP: Status line"},
    'http_server'   => {'val' => sub { Net::SSLinfo::http_server(   $_[0], $_[1])}, 'txt' => "HTTP: Server banner"},
    'http_location' => {'val' => sub { Net::SSLinfo::http_location( $_[0], $_[1])}, 'txt' => "HTTP: Location header"},
    'http_refresh'  => {'val' => sub { Net::SSLinfo::http_refresh(  $_[0], $_[1])}, 'txt' => "HTTP: Refresh header"},
    'http_alerts'   => {'val' => sub { Net::SSLinfo::http_alerts(   $_[0], $_[1])}, 'txt' => "HTTP: Error alerts"},
    'http_alerts'   => {'val' => sub { Net::SSLinfo::http_alerts(   $_[0], $_[1])}, 'txt' => "HTTP: Error alerts"},
    'hsts'          => {'val' => sub { Net::SSLinfo::hsts(          $_[0], $_[1])}, 'txt' => "HTTP: STS header"},
    'hsts_maxage'   => {'val' => sub { Net::SSLinfo::hsts_maxage(   $_[0], $_[1])}, 'txt' => "HTTP: STS MaxAge"},
    'hsts_subdom'   => {'val' => sub { Net::SSLinfo::hsts_subdom(   $_[0], $_[1])}, 'txt' => "HTTP: STS include sub-domains"},
    'hsts_pins'     => {'val' => sub { Net::SSLinfo::hsts_pins(     $_[0], $_[1])}, 'txt' => "HTTP: STS pins"},
    #------------------+---------------------------------------+-------------------------------------------------------
); # %data
# need s_client for: compression|expansion|selfsigned|verify|resumption|renegotiation|

my %check_cert = (
    #
    # default val is '' (empty string) for all following
    # (default is 0 if check not yet implemented)
    #  the default value means "check = ok/yes", otherwise: "check =failed/no"
    #------------------+-----------+------------------------------------------
    # +check            value                 label to be printed (description)
    #------------------+-----------+------------------------------------------
    'verify'        => {'val' =>'', 'txt' => "Certificate chain validated"},
    'fp_not_MD5'    => {'val' =>'', 'txt' => "Certificate Fingerprint is not MD5"},
    'expired'       => {'val' => 0, 'txt' => "Certificate is not expired"},
    'hostname'      => {'val' => 0, 'txt' => "Certificate is valid according given hostname"},
    'wildhost'      => {'val' =>'', 'txt' => "Certificate's wilcard does not match hostname"},
    'wildcard'      => {'val' =>'', 'txt' => "Certificate does not contain wildcards"},
    'rootcert'      => {'val' =>'', 'txt' => "Certificate is not root CA"},
    'selfsigned'    => {'val' =>'', 'txt' => "Certificate is not self-signed"},
    'OCSP'          => {'val' =>'', 'txt' => "Certificate has OCSP Responder URL"},
    'CRL'           => {'val' => 0, 'txt' => "Certificate has CRL Distribution Points"},
    'EV'            => {'val' => 0, 'txt' => "Certificate has Extended Validation (EV)"},
    'ZLIB'          => {'val' => 0, 'txt' => "Certificate has (TLS extension) compression"},
    'LZO'           => {'val' => 0, 'txt' => "Certificate has (GnuTLS extension) compression"},
    'SRP'           => {'val' => 0, 'txt' => "Certificate has (TLS extension) authentication"},
    'OpenPGP'       => {'val' => 0, 'txt' => "Certificate has (TLS extension) authentication"},
    # following checks in subjectAltName, CRL, OCSP, CN, O, U
    'nonprint'      => {'val' => 0, 'txt' => "Certificate contains non-printable characters"},
    'crnlnull'      => {'val' => 0, 'txt' => "Certificate contains CR, NL, NULL characters"},
    #------------------+-----------+------------------------------------------
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
    # ToDo: wee need an option to specify the the local certificate storage!
); # %check_cert
$check_cert{$_}->{score} = 10 foreach (keys %check_cert);
my %check_dest = (
    #------------------+-----------+------------------------------------------
    'SGC'           => {'val' => 0, 'txt' => "Target supports Server Gated Cryptography (SGC)"},
    'hasSSLv2'      => {'val' =>'', 'txt' => "Target supports only safe protocols (no SSL 2.0)"},
    'EDH'           => {'val' =>'', 'txt' => "Target does not accepts EDH ciphers"},
    'NULL'          => {'val' =>'', 'txt' => "Target does not accepts NULL ciphers"},
    'EXPORT'        => {'val' =>'', 'txt' => "Target does not accepts EXPORT ciphers"},
    'closure'       => {'val' => 0, 'txt' => "Target understands TLS closure alerts"},
    'fallback'      => {'val' => 0, 'txt' => "Target supports fallback from TLSv1.1"},
    'order'         => {'val' => 0, 'txt' => "Target honors client's cipher order"},
    'ISM'           => {'val' =>'', 'txt' => "Target supports ISM compliant ciphers"},
    'PCI'           => {'val' =>'', 'txt' => "Target supports PCI compliant ciphers"},
    'FIPS'          => {'val' =>'', 'txt' => "Target supports FIPS-140 compliant ciphers"},
    'resumption'    => {'val' =>'', 'txt' => "Target supports resumption"},
    'renegotiation' => {'val' =>'', 'txt' => "Target supports renegotiation"},
    #------------------+-----------+------------------------------------------
); # %check_dest
$check_dest{$_}->{score} = 10 foreach (keys %check_dest);
my %check_conn = (
    'IP'            => {'val' =>'', 'txt' => "IP for given hostname "},
    'reversehost'   => {'val' =>'', 'txt' => "Given hostname is same as reverse resolved hostname"},
    'hostname'      => {'val' =>'', 'txt' => "Connected hostname matches certificate's subject"},
    'BEAST-default' => {'val' =>'', 'txt' => "Connection is safe against BEAST attack (default cipher)"},
    'BEAST'         => {'val' =>'', 'txt' => "Connection is safe against BEAST attack (any cipher)"},
    'CRIME'         => {'val' => 0, 'txt' => "Connection is safe against CRIME attack"},
    'SNI'           => {'val' =>'', 'txt' => "Connection is not based on SNI"},
    'default'       => {'val' =>'', 'txt' => "Default cipher for "},
    'totals'        => {'val' => 0, 'txt' => "Total number of checked ciphers"},
     # counter for accepted ciphers, 0 if not supported
    'SSLv2'         => {'val' => 0, 'txt' => "Supported ciphers for SSLv2 (total)"},
    'SSLv3'         => {'val' => 0, 'txt' => "Supported ciphers for SSLv3 (total)"},
    'TLSv1'         => {'val' => 0, 'txt' => "Supported ciphers for TLSv1 (total)"},
    'TLSv11'        => {'val' => 0, 'txt' => "Supported ciphers for TLSv11 (total)"},
    'TLSv12'        => {'val' => 0, 'txt' => "Supported ciphers for TLSv12 (total)"},
    # counter for this type of cipher
    'SSLv2-LOW'     => {'val' => 0, 'txt' => "Supported   LOW   security ciphers"},
    'SSLv2-WEAK'    => {'val' => 0, 'txt' => "Supported  WEAK   security ciphers"},
    'SSLv2-HIGH'    => {'val' => 0, 'txt' => "Supported  HIGH   security ciphers"},
    'SSLv2-MEDIUM'  => {'val' => 0, 'txt' => "Supported MEDIUM  security ciphers"},
    'SSLv2--?-'     => {'val' => 0, 'txt' => "Supported unknown security ciphers"},
    'SSLv3-LOW'     => {'val' => 0, 'txt' => "Supported   LOW   security ciphers"},
    'SSLv3-WEAK'    => {'val' => 0, 'txt' => "Supported  WEAK   security ciphers"},
    'SSLv3-HIGH'    => {'val' => 0, 'txt' => "Supported  HIGH   security ciphers"},
    'SSLv3-MEDIUM'  => {'val' => 0, 'txt' => "Supported MEDIUM  security ciphers"},
    'SSLv3--?-'     => {'val' => 0, 'txt' => "Supported unknown security ciphers"},
    'TLSv1-LOW'     => {'val' => 0, 'txt' => "Supported   LOW   security ciphers"},
    'TLSv1-WEAK'    => {'val' => 0, 'txt' => "Supported  WEAK   security ciphers"},
    'TLSv1-HIGH'    => {'val' => 0, 'txt' => "Supported  HIGH   security ciphers"},
    'TLSv1-MEDIUM'  => {'val' => 0, 'txt' => "Supported MEDIUM  security ciphers"},
    'TLSv1--?-'     => {'val' => 0, 'txt' => "Supported unknown security ciphers"},
    'TLSv11-LOW'    => {'val' => 0, 'txt' => "Supported   LOW   security ciphers"},
    'TLSv11-WEAK'   => {'val' => 0, 'txt' => "Supported  WEAK   security ciphers"},
    'TLSv11-HIGH'   => {'val' => 0, 'txt' => "Supported  HIGH   security ciphers"},
    'TLSv11-MEDIUM' => {'val' => 0, 'txt' => "Supported MEDIUM  security ciphers"},
    'TLSv11--?-'    => {'val' => 0, 'txt' => "Supported unknown security ciphers"},
    'TLSv12-LOW'    => {'val' => 0, 'txt' => "Supported   LOW   security ciphers"},
    'TLSv12-WEAK'   => {'val' => 0, 'txt' => "Supported  WEAK   security ciphers"},
    'TLSv12-HIGH'   => {'val' => 0, 'txt' => "Supported  HIGH   security ciphers"},
    'TLSv12-MEDIUM' => {'val' => 0, 'txt' => "Supported MEDIUM  security ciphers"},
    'TLSv12--?-'    => {'val' => 0, 'txt' => "Supported unknown security ciphers"},
); # %check_conn
# set score
$check_conn{$_}->{score} = 10 foreach (keys %check_conn);
$check_conn{'TLSv1-HIGH'}->{score}  = 0;
$check_conn{'TLSv11-HIGH'}->{score} = 0;
$check_conn{'TLSv12-HIGH'}->{score} = 0;
foreach (keys %check_conn) {
    $check_conn{$_}->{score} = 90 if (m/WEAK/i);
    $check_conn{$_}->{score} = 30 if (m/LOW/i);
    $check_conn{$_}->{score} = 10 if (m/MEDIUM/i);
}

my %check_size = (
    # counts and sizes are integer values, key mast have prefix (len|cnt)_
    #------------------+-----------+------------------------------------------
    'len_pembase64' => {'val' => 0, 'txt' => "Size: Certificate PEM (base64)"}, # <(2048/8*6)
    'len_pembinary' => {'val' => 0, 'txt' => "Size: Certificate PEM (binary)"}, # < 2048
    'len_subject'   => {'val' => 0, 'txt' => "Size: Certificate subject"},      # <  256
    'len_issuer'    => {'val' => 0, 'txt' => "Size: Certificate subject"},      # <  256
    'len_CPS'       => {'val' => 0, 'txt' => "Size: Certificate CPS"},          # <  256
    'len_CRL'       => {'val' => 0, 'txt' => "Size: Certificate CRL"},          # <  256
    'len_CRL_data'  => {'val' => 0, 'txt' => "Size: Certificate CRL data"},
    'len_OCSP'      => {'val' => 0, 'txt' => "Size: Certificate OCSP"},         # <  256
    'len_OIDs'      => {'val' => 0, 'txt' => "Size: Certificate OIDs"},
    'len_publickey' => {'val' => 0, 'txt' => "Size: Certificate public key"},   # > 1024
    'len_sigdump'   => {'val' => 0, 'txt' => "Size: Certificate signature key"},# > 1024
    'len_altname'   => {'val' => 0, 'txt' => "Size: Certificate subject altname"},
    'len_chain'     => {'val' => 0, 'txt' => "Size: Certificate Chain size"},   # < 2048
    'cnt_altname'   => {'val' => 0, 'txt' => "Count: Certificate subject altname"}, # == 0
    'cnt_wildcard'  => {'val' => 0, 'txt' => "Count: Certificate wildcards"},   # == 0
    'cnt_chaindepth'=> {'val' => 0, 'txt' => "Count: Certificate Chain Depth"}, # == 1
    'cnt_ciphers'   => {'val' => 0, 'txt' => "Count: Offered Ciphers"},         # <> 0
    #------------------+-----------+------------------------------------------
# ToDo: cnt_ciphers, len_chain, cnt_chaindepth
); # %check_size
$check_size{$_}->{score} = 10 foreach (keys %check_size);
my %check_http = (
    'http_status'   => {'val' => '', 'txt' => "HTTP: Status line"},
    'http_banner'   => {'val' => '', 'txt' => "HTTP: Server banner"},
    'http_alerts'   => {'val' => '', 'txt' => "HTTP: Error alerts"},
    'hsts'          => {'val' => '', 'txt' => "HTTP: STS header"},
    'hsts_maxage'   => {'val' => '', 'txt' => "HTTP: STS MaxAge"},
    'hsts_subdom'   => {'val' => '', 'txt' => "HTTP: STS includes sub-domains"},
    'hsts_pins'     => {'val' => '', 'txt' => "HTTP: STS pins"},
); # %check_http
$check_http{$_}->{score} = 10 foreach (keys %check_http);
my %data_oid = ( # ToDo: nothing YET IMPLEMENTED
#   '1.3.6.1'                   => {iso(1) org(3) dod(6) iana(1)}
    '1.3.6.1'                   => {'val' => '', 'txt' => "Internet OID"},
    '1.3.6.1.5.5.7.3.1'         => {'val' => '', 'txt' => "Server Authentication"},
    '1.3.6.1.5.5.7.3.2'         => {'val' => '', 'txt' => "Client Authentication"},
    '1.3.6.1.5.5.7.3.3'         => {'val' => '', 'txt' => "Code Signing"},
    '1.3.6.1.5.5.7.3.4'         => {'val' => '', 'txt' => "Email Protection"},
    '1.3.6.1.5.5.7.3.5'         => {'val' => '', 'txt' => "IPSec end system"},
    '1.3.6.1.5.5.7.3.6'         => {'val' => '', 'txt' => "IPSec tunnel"},
    '1.3.6.1.5.5.7.3.7'         => {'val' => '', 'txt' => "IPSec user"},
    '1.3.6.1.5.5.7.3.8'         => {'val' => '', 'txt' => "Timestamping"},
    '1.3.6.1.4.1.311.10.3.3'    => {'val' => '', 'txt' => "Microsoft Server Gated Crypto"},
    '2.16.840.1.113730.4.1'     => {'val' => '', 'txt' => "Netscape SGC"},
); # %data_oid
my %shorttexts = (
    #------------------+------------------------------------------------------
    # %check +check     short label text
    #------------------+------------------------------------------------------
    # Note: key must be same string as used in %ciphers[ssl] {
    'SSLv2'         => "Ciphers (SSLv2)",
    'SSLv3'         => "Ciphers (SSLv3)",
    'TLSv1'         => "Ciphers (TLSv1)",
    'TLSv11'        => "Ciphers (TLSv11)",
    'TLSv12'        => "Ciphers (TLSv12)",
    #}
    'TLSv1-HIGH'    => "Ciphers HIGH",
    'default'       => "Default Cipher ",
    'IP'            => "IP for hostname",
    'reversehost'   => "Reverse hostname",
    'expired'       => "Not expired",
    'hostname'      => "Valid for hostname",
    'wildhost'      => "Wilcard for hostname",
    'wildcard'      => "No wildcards",
    'SNI'           => "Not SNI based",
    'rootcert'      => "Not root CA",
    'OCSP'          => "OCSP supported",
    'hasSSLv2'      => "No SSL 2.0",
    'EDH'           => "No EDH ciphers",
    'NULL'          => "No NULL ciphers",
    'EXPORT'        => "No EXPORT ciphers",
    'SGC'           => "SGC supported",
    'CRL'           => "CRL supported",
    'EV'            => "EV supported",
    'BEAST-default' => "Default cipher safe to BEAST",
    'BEAST'         => "Supported cipher safe to BEAST",
    'CRIME'         => "Safe to CRIME",
    'closure'       => "TLS closure alerts",
    'fallback'      => "Fallback from TLSv1.1",
    'ZLIB'          => "ZLIB extension",
    'LZO'           => "GnuTLS extension",
    'SRP'           => "SRP extension",
    'OpenPGP'       => "OpenPGP extension",
    'order'         => "Client's cipher order",
    'ISM'           => "ISM compliant",
    'PCI'           => "PCI compliant",
    'FIPS'          => "FIPS-140 compliant",
    'resumption'    => "Resumption",
    'renegotiation' => "Renegotiation",
    'selfsigned'    => "self-signed",
    'verify'        => "Chain",
    'nonprint'      => "non-printables",
    'crnlnull'      => "CR, NL, NULL",
    'compression'   => "Compression",
    'expansion'     => "Expansion",
    'len_pembase64' => "Size PEM (base64)",
    'len_pembinary' => "Size PEM (binary)",
    'len_subject'   => "Size subject",
    'len_issuer'    => "Size subject",
    'len_CPS'       => "Size CPS",
    'len_CRL'       => "Size CRL",
    'len_CRL_data'  => "Size CRL data",
    'len_OCSP'      => "Size CRL",
    'len_OIDs'      => "Size OIDs",
    'len_altname'   => "Size altname",
    'len_publickey' => "Size pubkey",
    'len_sigdump'   => "Size signature key",
    'cnt_altname'   => "Count altname",
    'cnt_wildcard'  => "Count wildcards",
    #------------------+------------------------------------------------------
    # %data +command    short label text
    #------------------+------------------------------------------------------
    'certificate'   => "PEM",
    'pem'           => "PEM",
    'PEM'           => "PEM",
    'text'          => "PEM decoded",
    'cn'            => "Common Name (CN)",
    'commonName'    => "Common Name (CN)",
    'subject'       => "Subject",
    'subjectX509'   => "Subject",
    'owner'         => "Subject",
    'issuer'        => "Issuer",
    'issuerX509'    => "Issuer",
    'authority'     => "Issuer",
    'altname'       => "Subject AltNames",
    'ciphers'       => "Client Ciphers",
    'default'       => "Default Cipher",
    'ciphers_openssl'   => "OpenSSL Ciphers",
    'dates'         => "Validity",
    'valid'         => "Validity",
    'before'        => "Valid since",
    'after'         => "Valid until",
    'expire'        => "Valid until",
    'aux'           => "Trust",
    'email'         => "email",
    'pubkey'        => "Public Key",
    'pubkey_algorithm'  => "Public Key Algorithm",
    'modulus_len'   => "Public Key length",
    'modulus'       => "Public Key modulus",
    'modulus_exponent'  => "Public Key exponent",
    'serial'        => "Serial Number",
    'signame'       => "Signature Algorithm",
    'sigdump'       => "Signature (hexdump)",
    'sigdump_len'   => "Signature key length",
    'trustout'      => "Trusted",
    'ocsp_uri'      => "OCSP URL",
    'ocspid'        => "OCSP hashs",
    'subject_hash'  => "Subject hash",
    'issuer_hash'   => "Issuer hash",
    'fp_not_MD5'    => "Fingerprint not MD5",
    'verify_hostname'   => "Hostname valid",
    'verify_altname'    => "AltNames valid",
    'fingerprint_hash'  => "Fingerprint Hash Value",
    'fingerprint_type'  => "Fingerprint Algorithm",
    'fingerprint_sha1'  => "Fingerprint SHA1",
    'fingerprint_md5'   => "Fingerprint  MD5",
    'fingerprint'       => "Fingerprint:",
    'http_status'   => "HTTP: Status line",
    'http_server'   => "HTTP: Server banner",
    'http_alerts'   => "HTTP: Error alerts",
    'http_location' => "HTTP: Location header",
    'http_refresh'  => "HTTP: Refresh header",
    'hsts'          => "HTTP: STS header",
    'hsts_maxage'   => "HTTP: STS MaxAge",
    'hsts_subdom'   => "HTTP: STS sub-domains",
    'hsts_pins'     => "HTTP: STS pins",
    #------------------+------------------------------------------------------
); # %shorttexts
my %score = (
    #------------------+-------------+----------------------------------------
    'check_dest'    => {'val' => 100, 'txt' => "Target checks"},
    'check_conn'    => {'val' => 100, 'txt' => "SSL connection checks"},
    'check_ciph'    => {'val' => 100, 'txt' => "Ciphers checks"},
    'check_cert'    => {'val' => 100, 'txt' => "Certificate checks"},
    'check_size'    => {'val' => '' , 'txt' => "Certificate sizes checks"},
    'check_http'    => {'val' => '' , 'txt' => "HTTP(S) checks"},
    #------------------+-------------+----------------------------------------
); # %score
my %cmd = (
    'is_set'        => undef,   # undef indicates not yet initialized
    'timeout'       => "timeout",   # to terminate shell processes (timeout 1)
    'openssl'       => "openssl",   # OpenSSL
    'libs'          => "",      # where to find libssl.so and libcrypto.so
    'path'          => "",      # where to find openssl executable
    'extopenssl'    => 1,       # use external openssl; default yes, except on Win32
    'extsclient'    => 1,       # use openssl s_client; default yes, except on Win32
    'envlibvar'     => "LD_LIBRARY_PATH",       # name of environment variable
);
my %cfg = (
    'try'           => 0,
    'trace'         => 0,       # 1=trace yeast, 2=trace Net::SSLeay and Net::SSLinfo also
    'verbose'       => 0,
    'enabled'       => 0,       # 1: only print enabled
    'disabled'      => 0,       # 1: only print disabled
    'nolocal'       => 0,
    'usehttp'       => 1,       # 1: make HTTP request
    'uselwp'        => 0,       # 1: use perls LWP module for HTTP checks
    'usesni'        => 1,       # 0: do not make connection in SNI mode
    'no_cert'       => 0,       # 0: get data from certificate; 1, 2, do not get data
    'no_cert_txt'   => "",      # change default text if no data from cert retrived
    'ignorecase'    => 1,       # 1: compare some strings case insensitive
    'short'         => 0,       # 1: use short label texts
    'version'       => [],      # contains the versions to be checked
    'versions'      => [qw( SSLv2 SSLv3 TLSv1 TLSv11 TLSv12)],
                                # Note: must be same string as used in %ciphers[ssl]
                                # ToDo: DTLS09, DTLS10
    'SSLv2'         => 1,       # 1: check this SSL version; default 1
    'SSLv3'         => 1,       # 1: check this SSL version; default 1
    'TLSv1'         => 1,       # 1: check this SSL version; default 1
    'TLSv11'        => 0,       # 1: check this SSL version; default 0
    'TLSv12'        => 0,       # 1: check this SSL version; default 0
    'DTLS09'        => 0,       # 1: check this SSL version; default 0
    'DTLS10'        => 0,       # 1: check this SSL version; default 0
    'nullssl2'      => 0,       # 1: complain if SSLv2 enabled but no ciphers accepted
    'do'            => [],      # the commands to be performed, any of commands
    'exec'          => 0,       # 1: if +exec command used
    'command'       => "",
    'commands'      => [qw(ciphers list version libversion exec info info--v check help dump sizes
                        beast cipher renegotiation resumption selfsigned s_client sni sni_check check_sni
                        cn commonName 
                        certificate pem text issuer subject altname after before expire chain valid
                        fingerprint fingerprint_hash fingerprint_md5 fingerprint_sha1 fingerprint_type
                        email serial signame sigdump sigdump_len extensions aux subject_hash issuer_hash trustout
                        pubkey pubkey_algorithm modulus modulus_len modulus_exponent
                        issuerX509 subjectX509
                        default verify verify_altname verify_hostname
                        http_status http_server http_alerts hsts hsts_maxage hsts_subdom http_location http_refresh http_pins
                        )],
    'sni--v'        => [qw(sni cn altname verify_altname verify_hostname hostname wildhost wildcard)],
    'info'          => [qw(
                        cn subject issuer altname before after chain
                        fingerprint fingerprint_hash fingerprint_sha1 fingerprint_md5 fingerprint_type
                        email serial signame sigdump_len extensions aux trustout ocsp_uri ocspid
                        pubkey_algorithm modulus modulus_len modulus_exponent
                        expansion compression selfsigned verify verify_altname verify_hostname
                        default ciphers
                        beast renegotiation resumption
                        http_status http_server http_alerts hsts hsts_maxage hsts_subdom http_location http_refresh http_pins
                        )],     # information provided for +info
    'info--v'       => [qw(
                        certificate text cn subject issuer altname before after dates chain
                        fingerprint fingerprint_hash fingerprint_sha1 fingerprint_md5 fingerprint_type
                        email serial signame sigdump_len extensions aux trustout ocsp_uri ocspid
                        pubkey pubkey_algorithm modulus modulus_len modulus_exponent
                        expansion compression selfsigned verify verify_altname verify_hostname
                        dump
                        default ciphers
                        beast renegotiation resumption
                        http_status http_server http_alerts hsts hsts_maxage hsts_subdom http_location http_refresh http_pins
                        )],     # information provided for +info --v
    'format'        => "tab",
    'formats'       => [qw(csv html json ssv tab xml fullxml)],
    'tmplib'        => "/tmp/yeast-openssl/",   # temp. directory for openssl and its libraries
    'lang'          => "de",    # output language
    'langs'         => [qw(de en)],
    'pass_options'  => "",      # options to be passeed thru to other programs
    'hosts'         => [],
    'host'          => "",      # currently scanned host
    'ip'            => "",      # currently scanned host's IP
    'IP'            => "",      # IP human redable (doted octed)
    'rhost'         => "",      # reverse resolved name of currently scanned host
    'port'          => 443,     # default port for connections
    'timeout'       => 1,       # default timeout in seconds for connections
                                # NOTE that some servers do not connect SSL within this time
                                #      this may result in ciphers marked as  "not supported"
                                #      it's recommended to set timeout to 3 or higher, which
                                #      results in a performance bottleneck, obviously
    'openssl'       => "ssleay",
    'openssls'      => [qw(ssleay local x86_32 x86_64 x86Mac arch)],
    'legacy'        => "simple",
    'legacys'       => [qw(cnark simple sslaudit sslcipher ssldiagnos sslscan
                        ssltest ssltest-g sslyze full compact)],
    'showhost'      => 0,       # 1: prefix printed line with hostname
    'compliance' => {           # Regex containing pattern for allowed ciphers
        'ISM'       => 'NULL|^ADH-|DES-CBC-|MD5|RC', # No NULL cipher, No Null Auth, No single DES, No MD5, No RC ciphers
        'PCI'       => 'NULL|^ADH-|DES-CBC-|^EXP-',  # No NULL cipher, No Null Auth, No single DES, No Export encryption
        'FIPS-140'  => 'IDEA|RC4|MD5',  # TLSv1, 3DES, AES, no IDEA, no RC4, no MD5
        'FIPS-140-2'=> '',      # ToDo:
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
    },
    'cipher'        => "yeast", # which ciphers to be used # <------------------------
); # %cfg
my %ciphers_desc = (    # description of following %ciphers table
    'head'                  => [qw(  sec  ssl   enc  bits mac  auth  keyx   score  tags)],
                            # abbrevations used by openssl:
                            # SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2
                            # Kx=  key exchange (DH is diffie-hellman)
                            # Au=  authentication
                            # Enc= encryption with bit size
                            # Mac= mac encryption algorithm
    'text'                  => [ # full description of each column in 'ciphers' below
        'Security',         # LOW, MEDIUM, HIGH as reported by openssl 0.9.8
                            # WEAK as reported by openssl 0.9.8 as EXPORT
                            # weak unqualified by openssl or know vulnerable
                            # Note: weak includes NONE (no security at all)
                            #
                            # all following informations as reported by openssl 0.9.8
        'Protocol Version', # SSLv2, SSLv3, TLSv1, TLSv11, TLSv12
                            # NOTE all SSLv3 are also TLSv1, TLSv11, TLSv12
                            # (cross-checked with sslaudit.ini)
                            # ToDo: DTLS0.9, DTLS1.0
        'Encryption Algorithm', # Nine, AES, DES, 3DES, RC4, RC2, SEED
        'Key Size',         # in bits
        'MAC Algorithm',    # MD5, SHA1
        'Authentication',   # None, DSS, RSA
        'Key Exchange',     # DH, ECDH, RSA
                            # last column is a : separated list (only export from openssl)
                            # different versions of openssl report  ECDH or ECDH/ECDSA
        'score',            # score value as defined in sslaudit.ini (0, 20, 80, 100)
                            # additionally following sores are used:
                            #   2: have been 20 in sslaudit.ini
                            #   1: assumed weak security
                            #  11: unknown, assumed weak security
                            #  81: unknown, assumed MEDIUM security
                            #  91: unknown, assumed HIGH security
        'tags',             # export  as reported by openssl 0.9.8
                            # OSX     on Mac OS X only
        ],
); # %ciphers_desc
my %ciphers = (
        #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,
        #'head'                 => [qw(  sec  ssl   enc  bits mac  auth  keyx    score tags)],
        #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,
        #'ADH-AES128-SHA'        => [qw(  HIGH SSLv3 AES   128 SHA1 None  DH         11 "")],
        #'ADH-AES256-SHA'        => [qw(  HIGH SSLv3 AES   256 SHA1 None  DH         11 "")],
        #'ADH-DES-CBC3-SHA'      => [qw(  HIGH SSLv3 3DES  168 SHA1 None  DH         11 "")],
        #'ADH-DES-CBC-SHA'       => [qw(   LOW SSLv3 DES    56 SHA1 None  DH         11 "")],
        #'ADH-RC4-MD5'           => [qw(MEDIUM SSLv3 RC4   128 MD5  None  DH         11 "")],
        #'ADH-SEED-SHA'          => [qw(MEDIUM SSLv3 SEED  128 SHA1 None  DH         11 "")],
        #   above use anonymous DH and hence are vulnerable to MiTM attacks
        #   see openssl's `man ciphers' for details (eNULL and aNULL)
        #   so they are qualified   weak  here instead of the definition
        #   in  `openssl ciphers -v HIGH'
        #--------
        # values  -?-  are unknown yet
        #!#---------------------------+------+-----+----+----+----+-----+--------+----+--------,
        #!# 'head'              => [qw(  sec  ssl   enc  bits mac  auth  keyx    score tags)],
        #!#---------------------------+------+-----+----+----+----+-----+--------+----+--------,
        'ADH-AES128-SHA'        => [qw(  weak SSLv3 AES   128 SHA1 None  DH          0 :)],
        'ADH-AES256-SHA'        => [qw(  weak SSLv3 AES   256 SHA1 None  DH          0 :)],
        'ADH-DES-CBC3-SHA'      => [qw(  weak SSLv3 3DES  168 SHA1 None  DH          0 :)],
        'ADH-DES-CBC-SHA'       => [qw(  weak SSLv3 DES    56 SHA1 None  DH          0 :)],
        'ADH-RC4-MD5'           => [qw(  weak SSLv3 RC4   128 MD5  None  DH          0 :)], # openssl: MEDIUM
        'ADH-SEED-SHA'          => [qw(  weak SSLv3 SEED  128 SHA1 None  DH          0 OSX)], # openssl: MEDIUM
        #
        'AECDH-AES128-SHA'      => [qw(  weak SSLv3 AES   128 SHA1 None  ECDH       11 :)],
        'AECDH-AES256-SHA'      => [qw(  weak SSLv3 AES   256 SHA1 None  ECDH       11 :)],
        'AECDH-DES-CBC3-SHA'    => [qw(  weak SSLv3 3DES  168 SHA1 None  ECDH       11 :)],
        'AECDH-NULL-SHA'        => [qw(  weak SSLv3 None    0 SHA1 None  ECDH        0 :)],
        'AECDH-RC4-SHA'         => [qw(  weak SSLv3 RC4   128 SHA1 None  ECDH       11 :)], # openssl: MEDIUM
        'AES128-SHA'            => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   RSA        80 :)],
        'AES256-SHA'            => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   RSA       100 :)],
        'DES-CBC3-MD5'          => [qw(  HIGH SSLv2 3DES  168 MD5  RSA   RSA        80 :)],
        'DES-CBC3-SHA'          => [qw(  HIGH SSLv3 3DES  168 SHA1 RSA   RSA        80 :)],
        'DES-CBC-MD5'           => [qw(   LOW SSLv2 DES    56 MD5  RSA   RSA        20 :)],
        'DES-CBC-SHA'           => [qw(   LOW SSLv3 DES    56 SHA1 RSA   RSA        20 :)],
        'DH-DSS-AES128-SHA'     => [qw(  high -?-   AES   128 SHA1 DSS   DH         11 :)], #
        'DH-DSS-AES256-SHA'     => [qw(  high -?-   AES   256 SHA1 DSS   DH         11 :)], #
        'DH-RSA-AES128-SHA'     => [qw(  high -?-   AES   128 SHA1 RSA   DH         11 :)], #
        'DH-RSA-AES256-SHA'     => [qw(  high -?-   AES   256 SHA1 RSA   DH         11 :)], #
        'DHE-DSS-AES128-SHA'    => [qw(  HIGH SSLv3 AES   128 SHA1 DSS   DH         80 :)],
        'DHE-DSS-AES256-SHA'    => [qw(  HIGH SSLv3 AES   256 SHA1 DSS   DH        100 :)],
        'DHE-DSS-RC4-SHA'       => [qw(  high SSLv3 RC4   -?- SHA1 DSS   DH         80 :)],
        'DHE-DSS-SEED-SHA'      => [qw(MEDIUM SSLv3 SEED  128 SHA1 DSS   DH         81 OSX)],
        'DHE-RSA-AES128-SHA'    => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   DH         80 :)],
        'DHE-RSA-AES256-SHA'    => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   DH        100 :)],
        'DHE-RSA-SEED-SHA'      => [qw(MEDIUM SSLv3 SEED  128 SHA1 RSA   DH         81 OSX)],
        'ECDH-ECDSA-AES128-SHA' => [qw(  high SSLv3 AES   128 SHA1 ECDSA ECDH       11 :)], #
        'ECDH-ECDSA-AES256-SHA' => [qw(  high SSLv3 AES   256 SHA1 ECDSA ECDH       11 :)], #
        'ECDH-ECDSA-DES-CBC3-SHA'=>[qw(   -?- SSLv3 3DES  168 SHA1 ECDSA ECDH/ECDSA 11 :)], # (from openssl-1.0.0d)
        'ECDH-ECDSA-RC4-SHA'    => [qw(MEDIUM SSLv3 RC4   128 SHA1 ECDSA ECDH/ECDSA 81 :)], # (from openssl-1.0.0d)
        'ECDH-ECDSA-NULL-SHA'   => [qw(  weak SSLv3 None    0 SHA1 ECDSA ECDH/ECDSA 11 :)], # (from openssl-1.0.0d)
        'ECDH-RSA-AES128-SHA'   => [qw(  -?-  SSLv3 AES   128 SHA1 RSA   ECDH       11 :)], #
        'ECDH-RSA-AES256-SHA'   => [qw(  -?-  SSLv3 AES   256 SHA1 RSA   ECDH       11 :)], #
        'ECDH-RSA-DES-CBC3-SHA' => [qw(  -?-  SSLv3 3DES  168 SHA1 RSA   ECDH       11 :)], #
        'ECDH-RSA-RC4-SHA'      => [qw(MEDIUM SSLv3 RC4   128 SHA1 RSA   ECDH       81 :)], #
        'ECDH-RSA-NULL-SHA'     => [qw(  weak SSLv3 None    0 SHA1 RSA   ECDH       11 :)], # (from openssl-1.0.0d)
        'ECDHE-ECDSA-AES128-SHA'=> [qw(  high SSLv3 AES   128 SHA1 ECDSA ECDH       11 :)], #
        'ECDHE-ECDSA-AES256-SHA'=> [qw(  high SSLv3 AES   256 SHA1 ECDSA ECDH       11 :)], #
        'ECDHE-ECDSA-DES-CBC3-SHA'=> [qw( -?- SSLv3 3DES  168 SHA1 ECDSA ECDH       11 :)], #
        'ECDHE-ECDSA-NULL-SHA'  => [qw(  weak SSLv3 None    0 SHA1 ECDSA ECDH       11 :)], #
        'ECDHE-ECDSA-RC4-SHA'   => [qw(MEDIUM SSLv3 RC4   128 SHA1 ECDSA ECDH       81 :)], #
        'ECDHE-RSA-AES128-SHA'  => [qw(  -?-  SSLv3 AES   128 SHA1 RSA   ECDH       11 :)], #
        'ECDHE-RSA-AES256-SHA'  => [qw(  -?-  SSLv3 AES   256 SHA1 RSA   ECDH       11 :)], #
        'ECDHE-RSA-DES-CBC3-SHA'=> [qw(  -?-  SSLv3 3DES  168 SHA1 RSA   ECDH       11 :)], #
        'ECDHE-RSA-RC4-SHA'     => [qw(MEDIUM SSLv3 RC4   128 SHA1 RSA   ECDH       81 :)], #
        'ECDHE-RSA-NULL-SHA'    => [qw(  weak SSLv3 None    0 SHA1 RSA   ECDH       11 :)], #
        'EDH-DSS-AES128-SHA'    => [qw(  high SSLv3 AES   128 SHA1 DSS   DHE        91 :)], # (from RSA BSAFE SSL-C) same as DHE-DSS-AES128-SHA?
        'EDH-DSS-AES256-SHA'    => [qw(  high SSLv3 AES   256 SHA1 DSS   DHE       100 :)], # (from RSA BSAFE SSL-C) same as DHE-DSS-AES256-SHA?
        'EDH-DSS-DES-CBC3-SHA'  => [qw(  HIGH SSLv3 3DES  168 SHA1 DSS   DH         80 :)],
        'EDH-DSS-DES-CBC-SHA'   => [qw(   LOW SSLv3 DES    56 SHA1 DSS   DH          1 :)],
        'EDH-DSS-RC4-SHA'       => [qw(  high SSLv3 RC4   128 SHA1 DSS   DHE       100 :)], # (from RSA BSAFE SSL-C) same as DHE-DSS-RC4-SHA?
        'EDH-RSA-AES128-SHA'    => [qw(  high SSLv3 AES   128 SHA1 RSA   DHE        80 :)], # (from RSA BSAFE SSL-C) same as DHE-RSA-AES128-SHA?
        'EDH-RSA-AES256-SHA'    => [qw(  high SSLv3 AES   256 SHA1 RSA   DHE       100 :)], # (from RSA BSAFE SSL-C) same as DHE-RSA-AES256-SHA?
        'EDH-RSA-DES-CBC3-SHA'  => [qw(  HIGH SSLv3 3DES  168 SHA1 RSA   DH         80 :)],
        'EDH-RSA-DES-CBC-SHA'   => [qw(   LOW SSLv3 DES    56 SHA1 RSA   DH         20 :)],
        'EXP-ADH-DES-CBC-SHA'   => [qw(  WEAK SSLv3 DES    40 SHA1 None  DH(512)     0 export)],
        'EXP-ADH-RC4-MD5'       => [qw(  WEAK SSLv3 RC4    40 MD5  None  DH(512)     0 export)],
        'EXP-DES-CBC-SHA'       => [qw(  WEAK SSLv3 DES    40 SHA1 RSA   RSA(512)    2 export)],
        'EXP-EDH-DSS-DES-CBC-SHA'=>[qw(  WEAK SSLv3 DES    40 SHA1 DSS   DH(512)     2 export)],
        'EXP-EDH-RSA-DES-CBC-SHA'=>[qw(  WEAK SSLv3 DES    40 SHA1 RSA   DH(512)     2 export)],
        'EXP-RC2-CBC-MD5'       => [qw(  WEAK SSLv2 RC2    40 MD5  RSA   RSA(512)    2 export)],
        'EXP-RC2-CBC-MD5'       => [qw(  WEAK SSLv3 RC2    40 MD5  RSA   RSA(512)    2 export)],
        'EXP-RC2-MD5'           => [qw(  WEAK SSLv2 RC2    40 MD5  RSA   RSA(512)    2 export)],
        'EXP-RC4-MD5'           => [qw(  WEAK SSLv2 RC4    40 MD5  RSA   RSA(512)    2 export)],
        'EXP-RC4-MD5'           => [qw(  WEAK SSLv3 RC4    40 MD5  RSA   RSA(512)    2 export)],
        'EXP-DES-56-SHA'        => [qw(  weak SSLv3 DES    56 SHA  RSA   RSA         2 :)], # (from RSA BSAFE SSL-C) same as EXP1024-DES-CBC-SHA?
        'EXP-EDH-DSS-DES-56-SHA'=> [qw(  weak SSLv3 DES    56 SHA  DSS   DHE         2 :)], # (from RSA BSAFE SSL-C) same as EXP1024-DHE-DSS-DES-CBC-SHA?
        'EXP-EDH-DSS-RC4-56-SHA'=> [qw(  weak SSLv3 RC4    56 SHA  DSS   DHE         2 :)], # (from RSA BSAFE SSL-C)
        'EXP-RC4-64-MD5'        => [qw(  weak SSLv3 RC4    64 MD5  DSS   RSA         2 :)], # (from RSA BSAFE SSL-C)
        'EXP-RC4-56-SHA'        => [qw(  weak SSLv3 RC4    56 SHA  DSS   RSA         2 :)], # (from RSA BSAFE SSL-C) same as EXP1024-RC4-SHA?
        'EXP1024-DES-CBC-SHA'   => [qw(  weak -?-   DES    56 SHA  RSA   RSA         2 :)], #
        'EXP1024-DHE-DSS-DES-CBC-SHA' => [qw(weak -?- DES  56 SHA  DSS   RSA         2 :)], #
        'EXP1024-RC2-CBC-MD5'   => [qw(  -?-  -?-   RC2    56 MD5  -?-   -?-         1 :)], #
        'EXP1024-RC4-MD5'       => [qw(  weak -?-   RC4    56 MD5  -?-   -?-         1 :)], #
        'EXP1024-RC4-SHA'       => [qw(  weak SSLv3 RC4    56 SHA  RSA   -?-         2 :)], #
        'IDEA-CBC-MD5'          => [qw(MEDIUM SSLv2 IDEA  128 MD5  RSA   RSA        80 :)], #
        'IDEA-CBC-SHA'          => [qw(MEDIUM SSLv2 IDEA  128 SHA  RSA   RSA        80 :)], #
        'NULL-MD5'              => [qw(  weak SSLv3 None    0 MD5  RSA   RSA         0 :)],
        'NULL-SHA'              => [qw(  weak SSLv3 None    0 SHA1 RSA   RSA         0 :)],
        'PSK-3DES-EDE-CBC-SHA'  => [qw(  -?-  SSLv3 3DES  168 SHA  PSK   PSK         1 :)], #
        'PSK-AES128-CBC-SHA'    => [qw(  -?-  SSLv3 AES   128 SHA  PSK   PSK         1 :)], #
        'PSK-AES256-CBC-SHA'    => [qw(  -?-  SSLv3 AES   256 SHA  PSK   PSK         1 :)], #
        'PSK-RC4-SHA'           => [qw(MEDIUM SSLv3 RC4   128 SHA  PSK   PSK         1 :)], #
        'RC2-CBC-MD5'           => [qw(MEDIUM SSLv2 RC2   128 MD5  RSA   RSA        11 :)],
        'RC2-MD5'               => [qw(MEDIUM SSLv2 RC2   128 MD5  RSA   RSA        80 :)],
        'RC4-MD5'               => [qw(MEDIUM SSLv2 RC4   128 MD5  RSA   RSA        80 :)],
        'RC4-MD5'               => [qw(MEDIUM SSLv3 RC4   128 MD5  RSA   RSA        80 :)],
        'RC4-SHA'               => [qw(MEDIUM SSLv3 RC4   128 SHA1 RSA   RSA        80 :)],
        'SEED-SHA'              => [qw(MEDIUM SSLv3 SEED  128 SHA1 RSA   RSA        11 OSX)],
        #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,
        'ADH-CAMELLIA128-SHA'   => [qw(  weak SSLv3 CAMELLIA  128 SHA1 None  DH      0 :)], #openssl: HIGH
        'ADH-CAMELLIA256-SHA'   => [qw(  weak SSLv3 CAMELLIA  256 SHA1 None  DH      0 :)], #openssl: HIGH
        'CAMELLIA128-SHA'       => [qw(  HIGH SSLv3 CAMELLIA  128 SHA1 RSA   RSA    80 :)], #
        'CAMELLIA256-SHA'       => [qw(  HIGH SSLv3 CAMELLIA  256 SHA1 RSA   RSA   100 :)], #
        'DHE-DSS-CAMELLIA128-SHA'=>[qw(  HIGH SSLv3 CAMELLIA  128 SHA1 DSS   DH     80 :)], #
        'DHE-DSS-CAMELLIA256-SHA'=>[qw(  HIGH SSLv3 CAMELLIA  256 SHA1 DSS   DH    100 :)], #
        'DHE-RSA-CAMELLIA128-SHA'=>[qw(  HIGH SSLv3 CAMELLIA  128 SHA1 RSA   DH     80 :)], #
        'DHE-RSA-CAMELLIA256-SHA'=>[qw(  HIGH SSLv3 CAMELLIA  256 SHA1 RSA   DH    100 :)], #
        'GOST94-GOST89-GOST89'  => [qw(  -?-  SSLv3 -?-   -?- -?-  -?-   -?-         1 :)], #
        'GOST2001-GOST89-GOST89'=> [qw(  -?-  SSLv3 -?-   -?- -?-  -?-   -?-         1 :)], #
        'GOST94-NULL-GOST94'    => [qw(  -?-  SSLv3 -?-   -?- -?-  -?-   -?-         1 :)], #
        'GOST2001-NULL-GOST94'  => [qw(  -?-  SSLv3 -?-   -?- -?-  -?-   -?-         1 :)], #
        #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,
        'EDH-DSS-CBC-SHA'       => [qw(  weak SSLv3 DES   -?- SHA1 DSS   DH         20 :)], # probably typo in sslaudit.ini
        #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,

        # from openssl-1.0.1c
        #!#-----------------------------------+------+-----+------+---+------+-----+--------+----+--------,
        #!# 'head'                      => [qw(  sec  ssl   enc   bits mac    auth  keyx    score tags)],
        #!#-----------------------------------+------+-----+------+---+------+-----+--------+----+--------,
        'SRP-AES-128-CBC-SHA'           => [qw(   -?- SSLv3 AES    128 SHA1   None  SRP        11 :)], # openssl: HIGH
        'SRP-AES-256-CBC-SHA'           => [qw(   -?- SSLv3 AES    256 SHA1   None  SRP        11 :)], # openssl: HIGH
        'SRP-DSS-3DES-EDE-CBC-SHA'      => [qw(  HIGH SSLv3 3DES   168 SHA1   DSS   SRP        11 :)],
        'SRP-DSS-AES-128-CBC-SHA'       => [qw(  HIGH SSLv3 AES    128 SHA1   DSS   SRP        11 :)],
        'SRP-DSS-AES-256-CBC-SHA'       => [qw(  HIGH SSLv3 AES    256 SHA1   DSS   SRP        11 :)],
        'SRP-RSA-3DES-EDE-CBC-SHA'      => [qw(  HIGH SSLv3 3DES   168 SHA1   RSA   SRP        11 :)],
        'SRP-RSA-AES-128-CBC-SHA'       => [qw(  HIGH SSLv3 AES    128 SHA1   RSA   SRP        11 :)],
        'SRP-RSA-AES-256-CBC-SHA'       => [qw(  HIGH SSLv3 AES    256 SHA1   RSA   SRP        11 :)],
        'SRP-3DES-EDE-CBC-SHA'          => [qw(   -?- SSLv3 3DES   168 SHA1   None  SRP        11 :)], # openssl: HIGH

#       'AECDH-AES256-SHA'              => [qw(  weak SSLv3 AES   256 SHA1 None  ECDH       11 :)],

        'ADH-AES128-SHA256'             => [qw(  -?- TLSv12 AES    128 SHA256 None  DH         11 :)], # openssl: HIGH
        'ADH-AES128-GCM-SHA256'         => [qw(  -?- TLSv12 AESGCM 128 AEAD   None  DH         11 :)], # openssl: HIGH
        'ADH-AES256-GCM-SHA384'         => [qw(  -?- TLSv12 AESGCM 256 AEAD   None  DH         11 :)], # openssl: HIGH
        'ADH-AES256-SHA256'             => [qw(  -?- TLSv12 AES    256 SHA256 None  DH         11 :)], # openssl: HIGH
        'AES128-GCM-SHA256'             => [qw( high TLSv12 AESGCM 128 AEAD   RSA   RSA        11 :)],
        'AES128-SHA256'                 => [qw( high TLSv12 AES    128 SHA256 RSA   RSA        11 :)],
        'AES256-GCM-SHA384'             => [qw( high TLSv12 AESGCM 256 AEAD   RSA   RSA        11 :)],
        'AES256-SHA256'                 => [qw( high TLSv12 AES    256 SHA256 RSA   RSA        11 :)],
        'DHE-DSS-AES128-GCM-SHA256'     => [qw( high TLSv12 AESGCM 128 AEAD   DSS   DH         11 :)],
        'DHE-DSS-AES128-SHA256'         => [qw( high TLSv12 AES    128 SHA256 DSS   DH         11 :)],
        'DHE-DSS-AES256-GCM-SHA384'     => [qw( high TLSv12 AESGCM 256 AEAD   DSS   DH         11 :)],
        'DHE-DSS-AES256-SHA256'         => [qw( high TLSv12 AES    256 SHA256 DSS   DH         11 :)],
        'DHE-RSA-AES128-GCM-SHA256'     => [qw( high TLSv12 AESGCM 128 AEAD   RSA   DH         11 :)],
        'DHE-RSA-AES128-SHA256'         => [qw( high TLSv12 AES    128 SHA256 RSA   DH         11 :)],
        'DHE-RSA-AES256-GCM-SHA384'     => [qw( high TLSv12 AESGCM 256 AEAD   RSA   DH         11 :)],
        'DHE-RSA-AES256-SHA256'         => [qw( high TLSv12 AES    256 SHA256 RSA   DH         11 :)],
        'ECDH-ECDSA-AES128-GCM-SHA256'  => [qw( high TLSv12 AESGCM 128 AEAD   ECDH  ECDH/ECDSA 11 :)],
        'ECDH-ECDSA-AES128-SHA256'      => [qw( high TLSv12 AES    128 SHA256 ECDH  ECDH/ECDSA 11 :)], # (from openssl-1.9.1c) same as ECDH-ECDSA-AES128-SHA?
        'ECDH-ECDSA-AES256-GCM-SHA384'  => [qw( high TLSv12 AESGCM 256 AEAD   ECDH  ECDH/ECDSA 11 :)],
        'ECDH-ECDSA-AES256-SHA384'      => [qw( high TLSv12 AES    256 SHA384 ECDH  ECDH/ECDSA 11 :)], # (from openssl-1.9.1c) same as ECDH-ECDSA-AES256-SHA?
        'ECDHE-ECDSA-AES128-GCM-SHA256' => [qw( high TLSv12 AESGCM 128 AEAD   ECDSA ECDH       11 :)],
        'ECDHE-ECDSA-AES128-SHA256'     => [qw( high TLSv12 AES    128 SHA256 ECDSA ECDH       11 :)],
        'ECDHE-ECDSA-AES256-GCM-SHA384' => [qw( high TLSv12 AESGCM 256 AEAD   ECDSA ECDH       11 :)],
        'ECDHE-ECDSA-AES256-SHA384'     => [qw( high TLSv12 AES    256 SHA384 ECDSA ECDH       11 :)],
        'ECDHE-RSA-AES128-GCM-SHA256'   => [qw( high TLSv12 AESGCM 128 AEAD   RSA   ECDH       11 :)],
        'ECDHE-RSA-AES128-SHA256'       => [qw( high TLSv12 AES    128 SHA256 RSA   ECDH       11 :)],
        'ECDHE-RSA-AES256-GCM-SHA384'   => [qw( high TLSv12 AESGCM 256 AEAD   RSA   ECDH       11 :)],
        'ECDHE-RSA-AES256-SHA384'       => [qw( high TLSv12 AES    256 SHA384 RSA   ECDH       11 :)],
        'ECDH-RSA-AES128-GCM-SHA256'    => [qw( high TLSv12 AESGCM 128 AEAD   ECDH  ECDH/ECDSA 11 :)],
        'ECDH-RSA-AES128-SHA256'        => [qw( high TLSv12 AES    128 SHA256 ECDH  ECDH/ECDSA 11 :)],
        'ECDH-RSA-AES256-GCM-SHA384'    => [qw( high TLSv12 AESGCM 256 AEAD   ECDH  ECDH/ECDSA 11 :)],
        'ECDH-RSA-AES256-SHA384'        => [qw( high TLSv12 AES    256 SHA384 ECDH  ECDH/ECDSA 11 :)],
        'NULL-SHA256'                   => [qw( weak TLSv12 None     0 SHA256 RSA   RSA         0 :)],
        #-------------------------------------+------+-----+------+---+------+-----+--------+----+--------,

    # === openssl ===
    # above table (roughly) generated with:
    #   openssl ciphers -v ALL:eNULL:aNULL | sort \
    #   | awk '{e=$7;printf("\t%26s => [%s, %s, %s, %s, %s, %s, %s],\n",$1,$2,substr($5,5),substr($5,index($5,"(")+1),substr($6,5),substr($4,4),substr($3,4),e)}'
    # or better
    #   | awk '{q="'"'"'";a=sprintf("%s%c",$1,q);e=$7;printf("\t%c%-26s => [qw( -?-\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t13 :)],\n",q,a,$2,substr($5,5),substr($5,index($5,"(")+1),substr($6,5),substr($4,4),substr($3,4),e)}'
    # === openssl 0.9.8o ===
    # above table (roughly) generated with:
    #   openssl ciphers -v ALL:eNULL:aNULL | sort
    #
    # Note: some openssl (0.9.8o on Ubuntu 11.10) fail to list ciphers with
    #    openssl ciphers -ssl2 -v

    # === openssl-x86_64 1.0.0d ===
    # *CAMELLIA*, PSK*
    # different results:
    #   ECDH-ECDSA-AES128-SHA   SSLv3 Kx=ECDH/ECDSA Au=ECDH Enc=AES(128)  Mac=SHA1
    #   ECDH-ECDSA-AES256-SHA   SSLv3 Kx=ECDH/ECDSA Au=ECDH Enc=AES(256)  Mac=SHA1
    #   ECDH-ECDSA-DES-CBC3-SHA SSLv3 Kx=ECDH/ECDSA Au=ECDH Enc=3DES(168) Mac=SHA1
    #   ECDH-ECDSA-RC4-SHA      SSLv3 Kx=ECDH/ECDSA Au=ECDH Enc=RC4(128)  Mac=SHA1
    #   ECDH-RSA-NULL-SHA       SSLv3 Kx=ECDH/RSA   Au=ECDH Enc=None      Mac=SHA1
    #   ECDH-ECDSA-NULL-SHA     SSLv3 Kx=ECDH/ECDSA Au=ECDH Enc=None      Mac=SHA1

); # %ciphers

my %text = (
    'separator' => ":",# separator character between label and value
    'legacy' => {      #--------------+------------------------+---------------------
        #header     => # not implemented  supported               unsupported
        #              #----------------+------------------------+---------------------
        'compact'   => { 'not' => '-',   'yes' => "yes",         'no' => "no" },
        'simple'    => { 'not' => '-?-', 'yes' => "yes",         'no' => "no" },
        'full'      => { 'not' => '-?-', 'yes' => "Yes",         'no' => "No" },
        #              #----------------+------------------------+---------------------
        # following keys are roughly the names of the tool they are used
        #              #----------------+------------------------+---------------------
        'sslaudit'  => { 'not' => '-?-', 'yes' => "successfull", 'no' => "unsuccessfull" },
        'sslcipher' => { 'not' => '-?-', 'yes' => "ENABLED",     'no' => "DISABLED" },
        'ssldiagnos'=> { 'not' => '-?-', 'yes' => "CONNECT_OK CERT_OK", 'no' => "FAILED" },
        'sslscan'   => { 'not' => '-?-', 'yes' => "Accepted",    'no' => "Rejected" },
        'ssltest'   => { 'not' => '-?-', 'yes' => "Enabled",     'no' => "Disabled" },
        'ssltest-g' => { 'not' => '-?-', 'yes' => "Enabled",     'no' => "Disabled" },
        'sslyze'    => { 'not' => '-?-', 'yes' => "%s",          'no' => "SSL Alert" },
        #              #----------------+------------------------+---------------------
        #                -?- means "not implemented"
        # all other text used in headers titles, etc. are defined in the
        # corresponding print functions:
        #     printtitle, printheader, printfooter, printdefault, printtotals
    },
    'de' => {
        'head'      => "Cipher(Schlüssel) Sicherheit angeboten Risiko",
        'unknown'   => "unbekannt",
        'weak'      => "schwach",
        'strong'    => "stark",
        'very'      => "sehr stark",
        'yes'       => "ja",
        'no'        => "nein",
        'na'        => "N/A",
        'ok'        => "keins",
        'low'       => "niedrig",
        'med'       => "mittel",
        'high'      => "hoch",
        'none'      => "-/-",
        'provided'  => "# Schlüssel angeboten von ",
        'default'   => "# Default Schlüssel angeboten für ",
        },
    'en' => {
        'head'      => "Cipher Security offered Risk",
        'unknown'   => "unknown",
        'weak'      => "weak",
        'strong'    => "strong",
        'very'      => "very_strong",
        'yes'       => "yes",
        'no'        => "no",
        'na'        => "N/A",
        'ok'        => "none",
        'low'       => "low",
        'med'       => "medium",
        'high'      => "high",
        'provided'  => "# Ciphers provided by ",
        'default'   => "# Default ciphers provided for ",
        },

    # short list of used terms and acronyms, always incomplete ...
    'glossar' => {
        'AAD'       => 'additional authenticated data',
        'ADH'       => 'Anonymous Diffie-Hellman',
        'Adler32'   => 'hash function',
        'AEAD'      => 'Authenticated Encryption with Additional Data',
        'AES'       => 'Advanced Encryption Standard',
        'AIA'       => 'Authority Information Access',
        'AKID'      => 'Authority Key IDentifier',
        'ARC4'      => 'Alleged RC4 (see RC4)',
        'ARCFOUR'   => 'alias for ARC4',
        'ASN'       => 'Autonomous System Number',
        'ASN.1'     => 'Abstract Syntax Notation One',
        'BEAST'     => 'Browser Exploit Against SSL/TLS',
        'BER'       => 'Basic Encoding Rules',
        'Blowfish'  => 'symmetric block cipher',
        'CAMELLIA'  => 'Encryption algorithm by Mitsubishi and NTT',
        'CAST-128'  => 'Carlisle Adams and Stafford Tavares, block cipher',
        'CAST5'     => 'alias for CAST-128',
        'CAST-256'  => 'Carlisle Adams and Stafford Tavares, block cipher',
        'CAST6'     => 'alias for CAST-256',
        'cipher suite'  => 'cipher suite is a named combination of authentication, encryption, and message authentication code algorithms',
        'CA'        => 'Certificate Authority',
        'CBC'       => 'Cyclic Block Chaining',
        'CBC '      => 'Cipher Block Chaining (sometimes)',
        'CBC  '     => 'Ciplier Block Chaining (sometimes)',
        #   ^^-- spaces to make key unique
        'CCM'       => 'CBC-MAC Mode',
        'CDP'       => 'CRL Distribution Points',
        'CEK'       => 'Content Encryption Key',
        'CFB'       => 'Cipher Feedback',
        'CFB3'      => 'Cipher Feedback',
        'CFBx'      => 'Cipher Feedback x bit mode',
        'CHAP'      => 'Challenge Handshake Authentication Protocol',
        'CMAC'      => 'block cipher algorithm',
        'CMP'       => 'X509 Certificate Management Protocol',
        'CMS'       => 'Cryptographic Message Syntax',
        'CMVP'      => 'Cryptographic Module Validation Program (NIST)',
        'CN'        => 'Common Name',
        'CPS'       => 'Certification Practice Statement',
        'CRC'       => 'Cyclic Redundancy Check',
        'CRIME'     => ' Exploit SSL/TLS ',
        'CRL'       => 'Certificate Revocation List',
        'CSP'       => 'Certificate Service Provider',
        'CSP '      => 'Critical Security Parameter (used in FIPS 140-2)',
        'CSR'       => 'Certificate Signing Request',
        'CTS'       => 'Cipher Text Stealing',
        'DER'       => 'Distinguished Encoding Rules',
        'DES'       => 'Data Encryption Standard',
        'DESede'    => 'alias for 3DES (? java only?',
        '3DES'      => 'Tripple DES (168 bits)',
        '3DES-EDE'  => 'alias for 3DES',
        '3TDEA'     => 'Tripple DES (168 bits)',
        '2TDEA'     => 'Double DES (112 bits)',
        'D5'        => "Verhoeff's Dihedral Group D5 Check",
        'DEA'       => 'Data Encryption Algorithm (sometimes a synonym for DES)',
        'DECIPHER'  => 'synonym for decryption',
        'DER'       => 'Distinguished Encoding Rules',
        'DH'        => 'Diffie-Hellman',
        'DHE'       => 'Diffie-Hellman ephemeral',
        'DPA'       => 'Dynamic Passcode Authentication (see CAP)',
        'DSA'       => 'Digital Signature Algorithm',
        'DSS'       => 'Digital Signature Standard',
        'DTLS'      => 'Datagram TLS',
        'DTLSv1'    => 'Datagram TLS 1.0',
        'DV'        => "Domain Validation",
        'DV-SSL'    => "Domain Validated Certificate",
        'EAP'       => 'Extensible Authentication Protocol',
        'EAP-PSK'   => 'Extensible Authentication Protocol using a Pre-Shared Key',
        'EC'        => 'Elliptic Curve',
        'ECB'       => 'Electronic Codebook (Mode)',
        'ECC'       => 'Elliptic Curve Cryptography',
        'ECDH'      => 'Elliptic Curve Diffie-Hellman',
        'ECDHE'     => 'Ephemeral ECDH',
        'ECDSA'     => 'Elliptic Curve Digital Signature Algorithm',
        'ECMQV'     => 'Elliptic Curve Menezes-Qu-Vanstone',
        'EDE'       => 'Encryption-Decryption-Encryption',
        'EDH'       => 'Ephemeral Diffie-Hellman',
        'ENCIPHER'  => 'synonym for encryption',
        'ESP'       => 'Encapsulating Security Payload',
        'EV'        => 'Extended Validation',
        'EV-SSL'    => "Extended Validation Certificate",
        'FEAL'      => 'Fast Data Encryption Algorithm',
        'FIPS'      => 'Federal Information Processing Standard',
        'FIPS46-2'  => 'FIPS Data Encryption Standard (DES)',
        'FIPS73'    => 'FIPS Guidelines for Security of Computer Applications',
        'FIPS140-2' => 'FIPS Security Requirements for Cryptographic Modules',
        'FIPS140-3' => 'proposed revision of FIPS 140-2',
        'FIPS180-3' => 'FIPS Secure Hash Standard',
        'FIPS186-3' => 'FIPS Digital Signature Standard (DSS)',
        'FIPS197'   => 'FIPS Advanced Encryption Standard (AES)',
        'FIPS198-1' => 'FIPS The Keyed-Hash Message Authentication Code (HMAC)',
        'FQDN'      => 'Fully-qualified Domain Name',
        'FZA'       => 'FORTEZZA',
        'GCM'       => 'Galois/Counter Mode (block cipher mode)',
        'GOST'      => 'Gossudarstwenny Standard',
        'HAVAL'     => 'one-way hashing',
        'HAS-160'   => 'hash function',
        'HAS-V'     => 'hash function',
        'HMAC'      => 'keyed-Hash Message Authentication Code',
        'HSTS'      => 'HTTP Strict Transport Security',
        'HTOP'      => 'HMAC-Based One-Time Password',
        'IDEA'      => 'International Data Encryption Algorithm',
        'IV'        => 'Initialization Vector',
        'JSSE'      => 'Java Secure Socket Extension',
        'KEA'       => 'Key Exchange Algorithm (alias for FORTEZZA-KEA)',
        'KEK'       => 'Key Encryption Key',
        'MARS'      => '',
        'MAC'       => 'Message Authentication Code',
        'MEK'       => 'Message Encryption Key',
        'MD2'       => 'Message Digest 2',
        'MD4'       => 'Message Digest 4',
        'MD5'       => 'Message Digest 5',
        'MISTY1'    => 'block cipher algorithm',
        'NTLM'      => 'NT Lan Manager. Microsoft Windows challenge-response authentication method.',
        'NPN'       => 'Next Protocol Negotiation',
        'NULL'      => 'no encryption',
        'OAEP'      => 'Optimal Asymmetric Encryption Padding',
        'OFB'       => 'Output Feedback',
        'OFBx'      => 'Output Feedback x bit mode',
        'OID'       => 'Object Identifier',
        'OTP'       => 'One Time Pad',
        'OCSP'      => 'Online Certificate Status Protocol',
        'OCSP stapling' => 'formerly known as: TLS Certificate Status Request',
        'OV'        => "Organisation Validation",
        'OV-SSL'    => "Organisational Validated Certificate",
        'P12'       => 'see PKCS#12',
        'P7B'       => 'see PKCS#7',
        'PAKE'      => 'Password Authenticated Key Exchange',
        'PBE'       => 'Password Based Encryption',
        'PCBC'      => 'Propagating Cipher Block Chaining',
        'PEM'       => 'Privacy Enhanced Mail',
        'PFS'       => 'Perfect Forward Secrecy',
        'PFX'       => 'see PKCS#12',
#       'PFX'       => 'Personal Information Exchange', # just for info
        'PII'       => 'Personally Identifiable Information',
        'PKCS'      => 'Public Key Cryptography Standards',
        'PKCS1'     => 'PKCS #1: RSA Encryption Standard',
        'PKCS6'     => 'PKCS #6: RSA Extended Certificate Syntax Standard',
        'PKCS7'     => 'PKCS #7: RSA Cryptographic Message Syntax Standard',
        'PKCS8'     => 'PKCS #8: RSA Private-Key Information Syntax Standard',
        'PKCS12'    => 'PKCS #12: RSA Personal Information Exchange Syntax Standard (public + private key)',
        'PKI'       => 'Public Key Infrastructure',
        'PKIX'      => 'Internet Public Key Infrastructure Using X.509',
        'PRF'       => 'pseudo-random function',
        'PSK'       => 'Pre-shared Key',
        'Rabbit'    => 'stream cipher algorithm',
        'Radix-64'  => 'alias for Base-64',
        'RC2'       => 'Rivest Cipher 2, block cipher by Ron Rivest',
        'RC4'       => "Rivest Cipher 4, stream cipher (aka Ron's Code)",
        'RC5'       => 'Rivest Cipher 5, block cipher',
        'RC6'       => 'Rivest Cipher 6',
        'RCSU'      => "Reuters' Compression Scheme for Unicode (aka SCSU)",
        'Rijndael'  => 'symmetric block cipher algorithm',
        'RIPEMD'    => 'RACE Integrity Primitives Evaluation Message Digest',
        'ROT-13'    => 'see XOR',
        'RTP'       => 'Real-time Transport Protocol',
        'RSA'       => 'public key cryptographic algorithm',
        'RSS-14'    => 'Reduced Space Symbology, see GS1',
        'RTN'       => 'Routing transit number',
        'SAFER'     => 'Secure And Fast Encryption Routine, block cipher',
        'SAM'       => 'syriac abbreviation mark',
        'SAN'       => 'Subject Alternate Name',
        'SBCS'      => 'single-byte character set',
        'SCEP'      => 'Simple Certificate Enrollment Protocol',
        'SCSU'      => 'Standard Compression Scheme for Unicode (compressed UTF-16)',
        'SCVP'      => 'Server-Based Certificate Validation Protocol',
        'SEED'      => '128-bit Symmetric Block Cipher',
        'Serpent'   => 'symmetric key block cipher',
        'SGC'       => 'Server-Gated Cryptography',
        'SHA'       => 'Secure Hash Algorithm',
        'SHA-0'     => 'Secure Hash Algorithm (insecure version before 1995)',
        'SHA-1'     => 'Secure Hash Algorithm (since 1995)',
        'SHA-2'     => 'Secure Hash Algorithm (since 2002)',
        'SHA-224'   => 'Secure Hash Algorithm (224 bit)',
        'SHA-256'   => 'Secure Hash Algorithm (256 bit)',
        'SHA-384'   => 'Secure Hash Algorithm (384 bit)',
        'SHA-512'   => 'Secure Hash Algorithm (512 bit)',
        'SHA1'      => 'alias for SHA-1 (160 bit)',
        'SHA2'      => 'alias for SHA-2 (224, 256, 384 or 512 bit)',
        'SHS'       => 'Secure Hash Standard',
        'Skein'     => 'hash function',
        'Skipjack'  => 'encryption algorithm specified as part of the Fortezza',
        'Snefu'     => 'hash function',
        'SNI'       => 'Server Name Indication',
        'SPDY'      => "Google's application-layer protocol an top of SSL",
        'Square'    => 'block cipher',
        'SRP'       => 'Secure Remote Password protocol',
        'SRTP'      => 'Secure RTP',
        'SSL'       => 'Secure Sockets Layer',
        'SSLv2'     => 'Secure Sockets Layer Version 2',
        'SSLv3'     => 'Secure Sockets Layer Version 3',
        'SSPI'      => 'Security Support Provider Interface',
        'SST'       => 'Serialized Certificate Store format',
        'TEA'       => 'Tiny Encryption Algorithm',
        'TEK'       => 'Traffic Encryption Key',
        'Tiger'     => 'hash function',
        'Threefish' => 'hash function',
        'TLS'       => 'Transport Layer Security',
        'TLSv1'     => 'Transport Layer Security version 1',
        'TSK'       => 'Transmission Security Key',
        'TTP'       => 'trusted Third Party',
        'Twofish'   => 'symmetric key block cipher',
        'UC'        => 'Unified Communications (SSL Certificate using SAN)',
        'UCC'       => 'Unified Communications Certificate (rarley used)',
        'WHIRLPOOL' => 'hash function',
        'X.680'     => 'X.680: ASN.1',
        'X.509'     => 'X.509: The Directory - Authentication Framework',
        'X680'      => 'X.680: ASN.1',
        'X509'      => 'X.509: The Directory - Authentication Framework',
        'XKMS'      => 'XML Key Management Specification',
        'XMLSIG'    => 'XML-Signature Syntax and Processing',
        'XTEA'      => 'extended Tiny Encryption Algorithm',
        'XUDA'      => 'Xcert Universal Database API',
        'XXTEA'     => 'enhanced/corrected Tiny Encryption Algorithm',
        'ZLIB'      => 'Lossless compression file format',
    },
    'mnemonic'      => {
        'example'   => 'TLS_DHE_DSS_WITH_3DES-EDE-CBC_SHA',
        'description'=> 'TLS Version _ key establishment algorithm _ digital signature algorithm _ WITH _ confidentility algorithm _ hash function' ,
        'explain'   => 'TLS Version1 _ Ephermeral DH key agreement _ DSS which implies DSA _ WITH _ 3DES encryption in CBC mode _ SHA for HMAC'
    },
    # RFC 2412: OAKLEY Key Determination Protocol (PFS)
    # RFC 2818: ? (Namenspruefung)
    # RFC 2712: TLSKRB: Addition of Kerberos Cipher Suites to Transport Layer Security (TLS)
    # RFC 3268:  TLSAES: Advanced Encryption Standard (AES) Ciphersuites for Transport Layer Security (TLS)
    # RFC 5081: TLSPGP: Using OpenPGP Keys for Transport Layer Security (TLS) Authentication
    # RFC 4279:  TLSPSK: Pre-Shared Key Ciphersuites for Transport Layer Security (TLS)
    # RFC 4492:  TLSECC: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
    # RFC 3749: TLS Compression Method 
    # RFC 2246:  TLS Version 1
    # RFC 3268:  TLS Version 1 AES
    # RFC 4132:  TLS Version 1 Camellia
    # RFC 4162: TLS Version 1 SEED
    # RFC 4346:  TLS Version 1.1
    # RFC 5246:  TLS Version 1.2
    # RFC 3546: TLS Extensions
    # RFC 4366: TLS Extensions
    #               ?AKID - authority key identifier?
    #               Server name Indication (SNI): server_name
    #               Maximum Fragment Length Negotiation: max_fragment_length
    #               Client Certificate URLs: client_certificate_url
    #               Trusted CA Indication: trusted_ca_keys
    #               Truncated HMAC: truncated_hmac
    #               Certificate Status Request (i.e. OCSP stapling): status_request
    #               Error Alerts
    # RFC 5764: TLS Extensions SRTP
    # RFC 4366: OCSP stapling (http://en.wikipedia.org/wiki/OCSP_stapling)
    # RFC 6066: OCSP stapling (http://en.wikipedia.org/wiki/OCSP_stapling)
    # RFC 6066: TLS Extensions: Extension Definitions
    #                PkiPath
    # RFC 4749: TLS Compression Methods
    # RFC 5077: TLS session resumption
    # RFC 4347: DTLS Datagram TLS
    # RFC 6460: ?
    # RFC 6125: Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS)
    # RFC 4210: X509 PKI Certificate Management Protocol (CMP)
    # RFC 3739: x509 PKI Qualified Certificates Profile
    # RFC 4158: X509 PKI Certification Path Building
    # RFC 5055: Server-Based Certificate Validation Protocol (SCVP)
    # RFC 2560: Online Certificate Status Protocol (OCSP)
    # RFC 5019: simplified RFC 2560
    # RFC 4387: X509 PKI Operational Protocols: Certificate Store Access via HTTP

    # AIA  : {http://www.startssl.com/certs/sub.class4.server.ca.crt}
    # CDP  : {http://www.startssl.com/crt4-crl.crl, http://crl.startssl.com/crt4-crl.crl}
    # OCSP : http://ocsp.startssl.com/sub/class4/server/ca
    # cat some.crl | openssl crl -text -inform der -noout
    # OCSP response "3" (TLS 1.3) ==> certifcate gueltig
    # HSTS : http://tools.ietf.org/html/draft-hodges-strict-transport-sec-02
    #        https://www.owasp.org/index.php/HTTP_Strict_Transport_Security
    #        Strict-Transport-Security: max-age=16070400; includeSubDomains
    #        Apache config:
    #             Header set Strict-Transport-Security "max-age=16070400; includeSubDomains"
    # SNI apache: http://wiki.apache.org/httpd/NameBasedSSLVHostsWithSNI
    #        SSLStrictSNIVHostCheck, which controls whether to allow non SNI clients to access a name-based virtual host. 
    #        when client provided the hostname using SNI, the new environment variable SSL_TLS_SNI

); # %text

$cmd{'extopenssl'} = 0 if ($^O =~ m/MSWin32/); # tooooo slow on Windows
$cmd{'extsclient'} = 0 if ($^O =~ m/MSWin32/); # tooooo slow on Windows

# inernal functions
# -------------------------------------
# check functions for array members and hash keys
sub _is_hashkey($$)    { my $is=shift; my @in=keys %{$_[0]}; return grep({$_ eq $is} @in); }
sub _is_member($$)     { my $is=shift; my @in=@{$_[0]};      return grep({$_ eq $is} @in); }
sub _is_do($)          { my $is=shift;                       return _is_member(   $is, \@{$cfg{'do'}}); }
sub _is_command($)     { my $is=shift;                       return _is_member(   $is, \@{$cfg{'commands'}}); }
sub _match_member($$)  { my $is=shift; my @in=@{$_[0]};      return grep(    /^$is/, @in); }
sub _match_do($)       { my $is=shift;                       return _match_member($is, \@{$cfg{'do'}}); }
sub _match_command($)  { my $is=shift;                       return _match_member($is, \@{$cfg{'commands'}}); }

# some people prefer to use a getter function to get data from objects
# each function returns a spcific value (column) from the %cipher table
# see %%ciphers_desc about description of the columns
sub get_cipher_sec($)  { my $c=$_[0]; return $ciphers{$c}[0] if (grep(/^$c/, %ciphers)>0); return ''; }
sub get_cipher_ssl($)  { my $c=$_[0]; return $ciphers{$c}[1] if (grep(/^$c/, %ciphers)>0); return ''; }
sub get_cipher_enc($)  { my $c=$_[0]; return $ciphers{$c}[2] if (grep(/^$c/, %ciphers)>0); return ''; }
sub get_cipher_bits($) { my $c=$_[0]; return $ciphers{$c}[3] if (grep(/^$c/, %ciphers)>0); return ''; }
sub get_cipher_mac($)  { my $c=$_[0]; return $ciphers{$c}[4] if (grep(/^$c/, %ciphers)>0); return ''; }
sub get_cipher_auth($) { my $c=$_[0]; return $ciphers{$c}[5] if (grep(/^$c/, %ciphers)>0); return ''; }
sub get_cipher_keyx($) { my $c=$_[0]; return $ciphers{$c}[6] if (grep(/^$c/, %ciphers)>0); return ''; }
sub get_cipher_score($){ my $c=$_[0]; return $ciphers{$c}[7] if (grep(/^$c/, %ciphers)>0); return ''; }
sub get_cipher_tags($) { my $c=$_[0]; return $ciphers{$c}[8] if (grep(/^$c/, %ciphers)>0); return ''; }
sub get_cipher_desc($) { my $c=$_[0]; my @c = @{$ciphers{$c}}; shift @c; return @c if (grep(/^$c/, %ciphers)>0); return ''; }

# some debug functions
sub _error    { local $\ = "\n"; print "**ERROR: " . @_; }
sub _yeast($) { local $\ = "\n"; print "#" . $mename . ": " . $_[0]; }
sub _trace($) { print "#" . $mename . "::" . $_[0] if ($cfg{'trace'} > 0); }

sub _setcmd() {
    # check for external commands and initialize %cmd if necessary
    return if (defined $cmd{'is_set'});
    my $_openssl = $cmd{'openssl'};        # just for better readability
    my $_timeout = $cmd{'timeout'};
    $cmd{'is_set'} = 1;
    # check if we have timeout and openssl program
    `$_timeout --version 2>&1` or $_timeout = '';   # without leading \, lazy
    `$_openssl version   2>&1` or $_openssl = '';   # may fail on Windows :-(
     $_timeout .= ' 1' if ($_timeout ne '');
    if ($^O !~ m/MSWin32/) {
        # Windows is too stupid for secure program calls
        $_timeout = '\\' .  $_timeout if (($_timeout ne '') and ($_timeout !~ /\//));
        $_openssl = '\\' .  $_openssl if (($_openssl ne '') and ($_openssl !~ /\//));
        _trace("_setcmd MSWin32");
    }
    print "**WARNING: no timeout command found, expect some long network timeouts (>2 min)\n" if ($_timeout eq '');
    $cmd{'openssl'} = $_openssl;
    $cmd{'timeout'} = $_timeout;
    _trace("_setcmd timeout: $_timeout");
    _trace("_setcmd openssl: $_openssl");
} # _setcmd


# scan options and arguments
# -------------------------------------
my $typ = 'host';
while ($#argv >= 0) {
    $arg = shift @argv;
    _yeast("ARG: $arg") if ($cfg{'verbose'} == 4);
    # When used as CGI we need some special checks:
    #   - remove trailing = for all options except (see below)
    #   - ignore --cgi option
    #   - ignore empty arguments
    #   - argumets for --command may miss a leading +, which will be added
    #
    if ($arg !~ /([+]|--)(cmd|host|port|exe|lib|cipher|format|legacy|timeout|url)=/) {
        $arg =~ s/=+$//;                    # remove trailing = (for CGI mode)
    }
    # First check for option or command.
    # Options may have an argument, either as seperate word or as part of the
    # option parameter itself: --opt=argument .
    # Such an argument is handled at end of loop using $typ,  the default  is
    # $typ='host'  which means we expect a hostname argument. Any other value
    # for  $typ will be set in the corresponding option after the argument is
    # parsed (see $typ at end of loop), $typ will be reset to 'host' again.
    # Note: the sequence must be:
    #   1. check for options (as they may have arguments)
    #   2. check for commands (as they all start with '+' and we don't expect
    #      any argument starting with '+')
    #   3. check argument (otherwise relooped before)
    #   finally discard unknown options silently
    #
    # Following checks use exact matches with 'eq' or regex matches with '=~'

    #{ options
    #!# You may read the lines as table with colums like:
    #!#--------+------------------------+----------------------+----------------
    #!#           argument to check       what to do             what to do next
    #!#--------+------------------------+----------------------+----------------
    if ($arg eq  '--http')              { $cfg{'usehttp'}++;     next; } # must be before --help
    if ($arg =~ m/^--no[_-]?http$/)     { $cfg{'usehttp'}   = 0; next; }
    if ($arg =~ m/^--h(?:elp)?=?(.*)$/) { printhelp($2);         exit 0; } # allow --h --help --h=*
    if ($arg =~ m/^\+help=?(.*)$/)      { printhelp($2);         exit 0; } # allow +help +help=*
    if ($arg =~ m/^(--|\+)ab(?:br|k)=?$/){printabbr();           exit 0; }
    if ($arg =~ m/^(--|\+)todo=?$/i)    { printtodo();           exit 0; }
    # some options are for compatibility with other programs
    #   example: -tls1 -tlsv1 --tlsv1 --tls1_1 --tlsv1_1 --tls11
    if ($arg eq  '--n')                 { $cfg{'try'}       = 1; next; }
    if ($arg =~ /^--v(erbose)?$/)       { $cfg{'verbose'}++; $info = 1; next; }
    if ($arg eq  '--trace')             { $cfg{'trace'}++;       next; }
    if ($arg eq  '--trace--')           { $cfg{'trace'}     = -1;next; } # special internal tracing
    # options form other programs for compatibility
    if ($arg =~ /^--?no[_-]failed$/)    { $cfg{'disabled'}  = 0; next; } # sslscan
    if ($arg eq  '--hide_rejected_ciphers'){$cfg{'disabled'}= 0; next; }
#   if ($arg eq  '--insecure')          { $cfg{'no_failed'} = 0; next; } # ToDo to be tested
    if ($arg eq  '--version')           { $arg = '+version';           }
    # options form other programs which we treat as command; see Options vs. Commands also
    if ($arg eq  '--list')              { $arg = '+list';              } # no next!
    if ($arg eq  '--chain')             { $arg = '+chain';             } # as these
    if ($arg eq  '--cipher')            { $arg = '+cipher';            } # should
    if ($arg eq  '--default')           { $arg = '+default';           } # become
    if ($arg eq  '--fingerprint')       { $arg = '+fingerprint';       } # commands
    if ($arg =~ /^--resum(ption)?$/)    { $arg = '+resumption';        } # ..
    if ($arg =~ /^--reneg(otiation)?/)  { $arg = '+renegotiation';     } # ..
    # our (and some compatibility) options
    if ($arg eq  '--regular')           { $cfg{'usehttp'}++;     next; } # sslyze
    if ($arg eq  '--lwp')               { $cfg{'uselwp'}    = 1; next; }
    if ($arg eq  '--sni')               { $cfg{'usesni'}    = 1; next; }
    if ($arg =~ /^--no[_-]?sni/)        { $cfg{'usesni'}    = 0; next; }
    if ($arg =~ /^--no[_-]?cert$/)      { $cfg{'no_cert'}++;     next; }
    if ($arg =~ /^--no[_-]?ignorecase$/){ $cfg{'ignorecase'}= 0; next; }
    if ($arg =~ /^--ignorecase$/)       { $cfg{'ignorecase'}= 1; next; }
    if ($arg eq  '--short')             { $cfg{'short'}     = 1; next; }
    if ($arg eq  '--openssl')           { $cmd{'extopenssl'}= 1; next; }
    if ($arg =~ /^--no[_-]?openssl/)    { $cmd{'extopenssl'}= 0; next; }
    if ($arg =~ /^--s_?client/)         { $cmd{'extsclient'}= 1; next; }
    if ($arg =~ /^--?sslv?2$/i)         { $cfg{'SSLv2'}     = 1; next; } # allow case insensitive
    if ($arg =~ /^--?sslv?3$/i)         { $cfg{'SSLv3'}     = 1; next; } # ..
    if ($arg =~ /^--?tlsv?1$/i)         { $cfg{'TLSv1'}     = 1; next; } # ..
    if ($arg =~ /^--?tlsv?1[-_.]?1$/i)  { $cfg{'TLSv11'}    = 1; next; } # allow ._- separator
    if ($arg =~ /^--?tlsv?1[-_.]?2$/i)  { $cfg{'TLSv12'}    = 1; next; } # ..
    if ($arg =~ /^--dtlsv?0[-_.]?9$/i)  { $cfg{'DTLS09'}    = 1; next; } # ..
    if ($arg =~ /^--dtlsv?1[-_.]?0$/i)  { $cfg{'DTLS10'}    = 1; next; } # ..
    if ($arg =~ /^--no[_-]?sslv?2$/i)   { $cfg{'SSLv2'}     = 0; next; } # allow _- separator
    if ($arg =~ /^--no[_-]?sslv?3$/i)   { $cfg{'SSLv3'}     = 0; next; } # ..
    if ($arg =~ /^--no[_-]?tlsv?1$/i)   { $cfg{'TLSv1'}     = 0; next; } # ..
    if ($arg =~ /^--no[_-]?tlsv?11$/i)  { $cfg{'TLSv11'}    = 0; next; } # ..
    if ($arg =~ /^--no[_-]?tlsv?12$/i)  { $cfg{'TLSv12'}    = 0; next; } # ..
    if ($arg =~ /^--no[_-]?dtlsv?09$/i) { $cfg{'DTLS09'}    = 0; next; } # ..
    if ($arg =~ /^--no[_-]?dtlsv?10$/i) { $cfg{'DTLS10'}    = 0; next; } # ..
    if ($arg =~ /^--nullsslv?2$/i)      { $cfg{'nullssl2'}  = 1; next; } # ..
    if ($arg eq  '--enabled')           { $cfg{'enabled'}   = 1; next; }
    if ($arg eq  '--disabled')          { $cfg{'disabled'}  = 1; next; }
    if ($arg eq  '--local')             { $cfg{'nolocal'}   = 1; next; }
    if ($arg eq  '--showhost')          { $cfg{'showhost'}++;    next; }
    if ($arg =~ /^-?-h(?:ost)?$/)       { $typ = 'host';         next; } # --h already catched above
    if ($arg =~ /^-?-h(?:ost)?=(.*)/)   { $typ = 'host';    $arg = $1; } # no next
    if ($arg =~ /^-?-p(?:ort)?$/)       { $typ = 'port';         next; }
    if ($arg =~ /^-?-p(?:ort)?=(.*)/)   { $typ = 'port';    $arg = $1; } # no next
    if ($arg =~ /^--exe$/)              { $typ = 'exe';          next; }
    if ($arg =~ /^--exe=(.*)/)          { $typ = 'exe';     $arg = $1; } # no next
    if ($arg =~ /^--lib$/)              { $typ = 'lib';          next; }
    if ($arg =~ /^--lib=(.*)/)          { $typ = 'lib';     $arg = $1; } # no next
    if ($arg =~ /^--cipher$/)           { $typ = 'cipher';       next; }
    if ($arg =~ /^--cipher=(.*)/)       { $typ = 'cipher';  $arg = $1; } # no next
    if ($arg =~ /^--format$/)           { $typ = 'format';       next; }
    if ($arg =~ /^--format=(.*)/)       { $typ = 'format';  $arg = $1; } # no next
    if ($arg =~ /^--legacy$/)           { $typ = 'legacy';       next; }
    if ($arg =~ /^--legacy=(.*)/)       { $typ = 'legacy';  $arg = $1; } # no next
    if ($arg =~ /^--sep(?:arator)?$/)   { $typ = 'sep';          next; }
    if ($arg =~ /^--sep(?:arator)?=(.*)/){$typ = 'sep';     $arg = $1; } # no next
    if ($arg =~ /^--set[_-]?score$/)    { $typ = 'score';        next; }
    if ($arg =~ /^--set[_-]?score=(.*)/){ $typ = 'score';   $arg = $1; } # no next
    if ($arg =~ /^--timeout$/)          { $typ = 'timeout';      next; }
    if ($arg =~ /^--timeout$/)          { $typ = 'timeout';      next; }
    if ($arg =~ /^--timeout=(.*)/)      { $typ = 'timeout'; $arg = $1; } # no next
    if ($arg =~ /^--openssl=(.*)/)      { $typ = 'openssl'; $arg = $1; $cmd{'extopenssl'}= 1; } # no next
    if ($arg =~ /^--no[_-]?cert[_-]?te?xt$/)    { $typ = 'ctxt'; next; }
    if ($arg =~ /^--no[_-]?cert[_-]?te?xt=(.*)/){ $typ = 'ctxt'; $arg = $1; } # no next
    if ($arg =~ /^--(fips|ism|pci)$/i)  { next; } # silently ignored
    if ($arg =~ /^-(H|s|url|u|U|x)/)    { next; } # silently ignored
    #} +---------+----------------------+----------------------+----------------

    #{ commands
    if ($arg =~ /^\+info/)  { $info = 1; }  # needed 'cause +info converts to list of commands
    # You may read the lines as table with colums like:
    #  +---------+----------+----------------------------------+----------------
    #   argument to check     what to do                         what to do next
    #  +---------+----------+----------------------------------+----------------
    if ($arg =~ /^--cmd=\+?(.*)/){ $arg = '# CGI ';   $arg = '+' . $1; } # no next
    if ($arg =~ /^--cgi=?/) { $arg = '# for CGI mode; ignore';   next; }
    if ($arg eq  '+info')   { @{$cfg{'do'}} = @{$cfg{'info'}};   next; } # +info is just a list of all other commands
    if ($arg eq  '+info--v'){ @{$cfg{'do'}} = @{$cfg{'info--v'}};next; } # like +info ...
    if ($arg eq  '+check')  { @{$cfg{'do'}} = 'check';          ;next; }
    if ($arg eq  '+check_sni'
     or $arg eq  '+sni_check') {
                   $info = 1; @{$cfg{'do'}} = @{$cfg{'sni--v'}}; next; }
    if ($arg =~ /^\+(.*)/)  { # got a command
        my $val = $1;
        _yeast("args: command= $val") if ($cfg{'trace'} == 4);
        next if ($arg =~ m/^\+\s*$/);  # ignore empty arguments; for CGI mode
        if ($val =~ m/^exec$/i) {      # +exec is special
            $cfg{'exec'} = 1;
            next;
        }
        if (_is_member($val, \@{$cfg{'commands'}}) == 1) {
            push(@{$cfg{'do'}}, $val);
        } else {
            warn("**WARNING: unknown command '$val' ignored");
        }
        next;
    }
    #} +---------+----------+----------------------------------+----------------

    next if ($arg =~ /^\s*$/);  # ignore empty arguments; for CGI mode

    #{ option arguments
    #dbx# print "#dbx# typ: $typ :: ARG: $arg\n";
    #  +---------+----------+------------------------------+--------------------
    #   argument to process   what to do                    expect next argument
    #  +---------+----------+------------------------------+--------------------
    if ($typ eq 'openssl')  { $cmd{'openssl'} = $arg;       $typ = 'host'; next; }
    if ($typ eq 'exe')      { $cmd{'path'}    = $arg;       $typ = 'host'; next; }
    if ($typ eq 'lib')      { $cmd{'libs'}    = $arg;       $typ = 'host'; next; }
    if ($typ eq 'sep')      { $text{'separator'} = $arg;    $typ = 'host'; next; }
    if ($typ eq 'timeout')  { $cfg{'timeout'} = $arg;       $typ = 'host'; next; }
    if ($typ eq 'cipher')   { $cfg{'cipher'}  = $arg;       $typ = 'host'; next; }
    if ($typ eq 'format')   { $typ = "** TBD **";           $typ = 'host'; next; }
    if ($typ eq 'score')    { set_score($arg);              $typ = 'host'; next; }
    if ($typ eq 'ctxt')     { $cfg{'no_cert_txt'} = $arg;   $typ = 'host'; next; }
    if ($typ eq 'port')     { $cfg{'port'}    = $arg;       $typ = 'host'; next; }
    if ($typ eq 'host')     {
        # allow URL   http://f.q.d.n:42/aa*foo=bar:23/
        my $port = $arg;
        if ($arg =~ m#.*?:\d+#) {                  # got a port too
            $port =~ s#(?:[^/]+/+)?([^/]*).*#$1#;  # match host:port
            $port =~ s#[^:]*:(\d+).*#$1#;
            $cfg{'port'} = $port;
            _yeast("port: $port") if ($cfg{'trace'} > 0);
        }
        $arg =~ s#(?:[^/]+/+)?([^/]*).*#$1#;
        $arg =~ s#:(\d+)##;
        push(@{$cfg{'hosts'}}, $arg);
        _yeast("host: $arg") if ($cfg{'trace'} > 0);
        $typ = 'host';
        next;
    }
    if ($typ eq 'legacy')   {
        $arg = 'sslcipher' if ($arg eq 'ssl-cipher-check'); # alias
        if (1 == grep(/^$arg$/, @{$cfg{'legacys'}})) {
            $cfg{'legacy'} = $arg;
        } else {
            warn("**WARNING: unknown legacy '$arg'; ignored");
        }
        $typ = 'host';
        next;
    }
    #} +---------+----------+------------------------------+--------------------

} # while

# set defaults for Net::SSLinfo
# -------------------------------------
$Net::SSLinfo::trace       = $cfg{'trace'} if ($cfg{'trace'} > 0);
$Net::SSLinfo::use_openssl = $cmd{'extopenssl'};
$Net::SSLinfo::use_sclient = $cmd{'extsclient'};
$Net::SSLinfo::openssl     = $cmd{'openssl'};
$Net::SSLinfo::use_http    = $cfg{'usehttp'};
$Net::SSLinfo::use_SNI     = $cfg{'usesni'};
$Net::SSLinfo::timeout_sec = $cfg{'timeout'};
$Net::SSLinfo::no_cert     = $cfg{'no_cert'};
$Net::SSLinfo::no_cert_txt = $cfg{'no_cert_txt'};
$Net::SSLinfo::ignore_case = $cfg{'ignore_case'};

# call with other libraries
# -------------------------------------
if ($cfg{'trace'} == 4) {
    _yeast("args: exec= $cfg{'exec'}");
    _yeast("args: commands= " . join(' ', @{$cfg{'do'}}));
}
# NOTE: this must be the very first action/command
if ($cfg{'exec'} == 0) {
    # as all shared libraries used by perl modules are already loaded when
    # this program executes, we need to set PATH and LD_LIBRARY_PATH befor
    # being called
    # so we call ourself with proper set environment variables again
    if (($cmd{'path'} ne '') or ($cmd{'libs'} ne '')) {
        local $\ = "\n";
        $ENV{PATH} = $cmd{'path'} . ':' . $ENV{PATH};
        $ENV{$cmd{envlibvar}} = $cmd{'libs'};
        if ($cfg{'trace'} > 0) {
            _yeast("exec: envlibvar= $cmd{envlibvar}");
            _yeast("exec: $cmd{envlibvar}= $ENV{$cmd{envlibvar}}");
            _yeast("exec: PATH= $ENV{PATH}");
        }
        _trace("exec: $0 +exec " . join(" ", @ARGV));
        exec $0, '+exec', @ARGV;
    }
}

# set additional defaults if missing
# -------------------------------------
push(@{$cfg{'do'}}, 'cipher') if ($#{$cfg{'do'}} < 0); # command
foreach my $version (@{$cfg{'versions'}}) {
    next if ($cfg{$version} == 0);
    $cfg{$version} = 0; # reset to simplify further checks
    # ToDo: DTLS09, DTLS10
    if ($version =~ /^(SSLv2|SSLv3|TLSv1)$/) {
        $typ = eval("Net::SSLeay::SSLv2_method()") if ($version eq 'SSLv2');
        $typ = eval("Net::SSLeay::SSLv3_method()") if ($version eq 'SSLv3');
        $typ = eval("Net::SSLeay::TLSv1_method()") if ($version eq 'TLSv1');
        # ugly eval, but that's the simplest (only?) way to check if required
        # functionality is available; we could try  Net::SSLeay::CTX_v2_new()
        # and similar calls also, but that requires eval too
        # if a version like SSLv2 is not supported, perl bails out with error
        # like:        Can't locate auto/Net/SSLeay/CTX_v2_new.al in @INC ...
        if (defined $typ) {
            push(@{$cfg{'version'}}, $version);
            $cfg{$version} = 1;
        } else {# eval failed ..
            print "**WARNING: SSL version '$version' not supported by openssl; ignored"; # if ($cfg{'verbose'} > 0);
        }
    } else {    # SSL versions not supported by Net::SSLeay <= 1.51 (Jan/2013)
        warn("**WARNING: unsupported SSL version '$version'; ignored");
    }
}

local $\ = "\n";

if ($cfg{'trace'} > 0) {
    @{$cfg{'do'}} = @{$cfg{'info--v'}} if (@{$cfg{'do'}} eq @{$cfg{'info'}});
    _yeast("      verbose= $cfg{'verbose'}");
    _yeast("        trace= $cfg{'trace'}");
    _yeast(" cmd->timeout= $cmd{'timeout'}");
    _yeast(" cmd->openssl= $cmd{'openssl'}");
    _yeast("  use_openssl= $cmd{'extopenssl'}");
    _yeast("      use_SNI= $Net::SSLinfo::use_SNI");
    _yeast("      targets= " . join(' ', @{$cfg{'hosts'}}));
    foreach my $key (qw(port format legacy openssl cipher usehttp)) {
        printf("#%s: %13s= %s\n", $mename, $key, $cfg{$key});
    }
    _yeast("      version= " . join(' ', @{$cfg{'version'}}));
    _yeast("     commands= " . join(' ', @{$cfg{'do'}}));
    _yeast('');
}

# main: do the work
# -------------------------------------
# first all commands which do not make a connection
if (_is_do('version')) {
    printversion();
    exit 0;
}
if (_is_do('libversion')) {
    printopenssl();
    exit 0;
}

if (_is_do('list')) {
    _trace(" +list");
    my $have_cipher = 0;
    my $miss_cipher = 0;
    my $ciphers     = '';
       $ciphers     = Net::SSLinfo::cipher_local() if ($cfg{'verbose'} > 0);
    print "# List $0 ciphers ...\n";
    print "#Cipher\t" . join("\t", @{$ciphers_desc{'text'}}) . "\n";
    printf("%-31s %s\n", "# cipher", join("\t", @{$ciphers_desc{'head'}}));
    printf("#%s%s\n", ('-' x 30), ('+-------' x 9));
    foreach my $cipher (sort keys %ciphers) {
### ToDo {
        my $can = ' ';
        if ($cfg{'verbose'} > 0) {
            #my $can = (1 == grep(/^$cipher$/, split(':', $ciphers))) ? ' ' : '-';
            #my @g = scalar grep({$_ eq $cipher} split(':', $ciphers));
            #print "G: $cipher " . join",",@g ."\n";
            if (0 >= grep({$_ eq $cipher} split(':', $ciphers))) {
                $can = '#';
                $miss_cipher++;
            } else {
                $have_cipher++;
            }
## above not yet working proper 'cause grep() returns more than one match
##
# # convert array to a hash with the array elements as the hash keys and the values are simply 1
#  my %hash = map {$_ => 1} @array;
#
#  # check if the hash contains $match
#  if (defined $hash{$match}) {
#      print "found it\n";
#  }
#
### ToDo }
        }
        printf("%s %-29s %s\n", $can, $cipher, join("\t", @{$ciphers{$cipher}}));
    }
    printf("#%s%s\n", ('-' x 30), ('+-------' x 9));
    if ($cfg{'verbose'} > 0) {
        my @miss = ();
        foreach my $cipher (split(':', $ciphers)) {
## 10sep: meldet AECDH-NULL-SHA als fehlend
            push(@miss, $cipher) if (! defined $ciphers{$cipher});
        }
        print "\n# Ciphers marked with # above are not supported by local SSL implementation.\n";
        print "Ciphers in $mename:        ", join(':', keys %ciphers);
        print "Supported Ciphers:        ", $have_cipher;
        print "Unsupported Ciphers:      ", $miss_cipher;
        print "Testable Ciphers:         ", scalar split(':', $ciphers);
        print "Ciphers missing in $mename:", $#miss, "  ", join(' ', @miss);
        print "Ciphers (from local ssl): ", $ciphers;
            # ToDo: there may be more "Testable" than "Supported" ciphers
    }
}

if (_is_do('ciphers')) {
    _trace(" +ciphers");
    if ($#{$cfg{'hosts'}} < 0) {    # no target given, try to use openssl
        print "**WARNING: no target given, try to get cipher list from openssl" if ($cfg{'verbose'} > 0);
        printtext($cfg{'legacy'}, 'ciphers_openssl', Net::SSLinfo::cipher_local());
        exit 0;                     # other commands do not make sense without a target
    }
}

if ($cfg{'short'} > 0) {            # reconfigure texts
    foreach my $key (keys %data) { $data{$key}->{'txt'} = $shorttexts{$key}; }
}

# now commands which do make a connection

# run the appropriate SSL tests for each host
foreach my $host (@{$cfg{'hosts'}}) {
    _trace(" (" . ($host||'') . "," . ($cfg{'port'}||'') . ")");
    print "# Target: $host:$cfg{'port'}\n" if ($cfg{'verbose'} > 0);
    my $ip = gethostbyname($host);
    my $cn = '';
    $cfg{'host'}        = $host;
    $cfg{'ip'}          = $ip;
    $cfg{'IP'}          = join('.', unpack('W4', $ip));
    $cfg{'rhost'}       = gethostbyaddr($ip, AF_INET);
    $cfg{'rhost'}       = '<gethostbyaddr() failed>' if ($? != 0);
    $check_conn{'reversehost'}->{val}   = $cfg{'rhost'};
    $check_conn{'IP'}->{val} = $cfg{'IP'};
    if ($cfg{'usesni'} != 0) {      # following check useful with SNI only
        $Net::SSLinfo::use_SNI     = 0;
        $data{'cn_nossni'}->{val}  = $data{'commonName'}->{val}($host, $cfg{'port'});
        Net::SSLinfo::do_ssl_close($host, $cfg{'port'});
        $Net::SSLinfo::use_SNI     = $cfg{'usesni'};
        _trace(" cn_nossni: $data{'cn_nossni'}->{val}");
    }

    # Check if there is something listening on $host:$port

        # use Net::SSLinfo::do_ssl_open() instead of IO::Socket::INET->new()
        # to check the connection (hostname and port)
        # as side effect we get the local cipher list
    my $ciphers = Net::SSLinfo::ciphers($host, $cfg{'port'});
    my $err     = Net::SSLinfo::errors( $host, $cfg{'port'});
    if ($err !~ /^\s*$/) {
        print "# " . $err if ($cfg{'verbose'} > 0);
        warn("**WARNING: Can't make a connection to $host:$cfg{'port'}; target ignored");
        goto CLOSE_SSL;
    }

    if ($cfg{'cipher'} ne 'yeast') {  # default setting: use all supported
        if ($cfg{'cipher'} =~ m/(NULL|COMP|DEF|HIG|MED|LOW|PORT| |:|@|!|\+)/) {
            _trace(" cipher match: $cfg{'cipher'}");
            Net::SSLinfo::do_ssl_close($host, $cfg{'port'}); # close from previous call
            # ToDo: Net::SSLinfo::set_cipher_list('SSLv3', $cfg{'cipher'});
            #       $ciphers = Net::SSLinfo::ciphers($host, $cfg{'port'});
            # ToDo: 'cause Net::SSLeay::set_cipher_list() returns Segmentation fault
            # we need to use Net::SSLinfo::do_open_ssl(), see Net::SSLinfo.pm
            Net::SSLinfo::do_ssl_open( $host, $cfg{'port'}, $cfg{'cipher'});
            $ciphers = Net::SSLinfo::cipher_local($host, $cfg{'port'});
            Net::SSLinfo::do_ssl_close($host, $cfg{'port'});
            _yeast(" ciphers: $ciphers") if ($cfg{'trace'} > 0);
        }
    }

    if (_is_do('dump')) {
        _trace(" +dump");
        if ($cfg{'trace'} > 1) {   # requires: --v --trace --trace
            _trace(' ############################################################ %SSLinfo');
            print Net::SSLinfo::dump();
        }
        printdump($cfg{'legacy'}, $host, $cfg{'port'});
    }

    if (($info == 1) or _is_do('check')) {
        _trace(" +info");
        printruler();
        printcheck($cfg{'legacy'}, 'Given hostname',            $host);
        printcheck($cfg{'legacy'}, 'Reverse resolved hostname', $cfg{'rhost'});
        printcheck($cfg{'legacy'}, 'IP for given hostname',     $cfg{'IP'});
        printruler();
    }

    # check ciphers manually (required for +check also)
    if (_is_do('cipher') or _is_do('check')) {
        _trace(" +cipher");
        foreach my $version (@{$cfg{'version'}}) {
            # TODo: single cipher check: grep for cipher in %{$ciphers}
            @results = ();
            #dbx# print "#dbx# $version # ", keys %{$ciphers} ; #sort keys %hash; # exit;
            printtitle($cfg{'legacy'}, $version, join(':', $host, $cfg{'port'}));
            checkciphers($version, $host, $cfg{'port'}, $ciphers, \%ciphers);
            printciphers($version, $host, @results);
            foreach (qw(LOW WEAK MEDIUM HIGH -?-)) {
                my $key = $version . '-' . $_;
                if ($check_conn{$key}->{val} != 0) {
                $score{'check_ciph'}->{val} -= _getscore($key, 'egal', \%check_conn);
                #$score{'check_conn'}->{val} -= _getscore($key, 'egal', \%check_conn);
                }
            }
        }
    }

    if (_is_do('check')) {
        _trace(" +check");
        printruler();
        print "**WARNING: no openssl, some checks are missing" if (($^O =~ m/MSWin32/) and ($cmd{'extopenssl'} == 0));
        checkssl($host, $cfg{'port'});
        printruler();
        printscore();
        printruler();
        goto CLOSE_SSL;
    }

    if (_is_do('sizes')) {
        _trace(" +sizes");
        checksizes($host, $cfg{'port'});
        #goto CLOSE_SSL;
    }

    if (_is_do('sni')) {
        _trace(" +sni");
        checksni($host, $cfg{'port'});
    }

# ToDo: HTTP checks for hsts*
# max-age=0   ==> Reset, sehr schlecht!
# max-age=86400  ==> 1 Tag, sehr schlecht
# max-age=2592000  ==> 30 Tage, schlecht
# max-age=31536000  ==> 365 Tage, ausreichend
# pins= ==> fingerprint des Zertifikats, wenn leer, dann Reset
# Achtung: pruefen ob STS auch beit http:// gesetzt, sehr schlecht, da MiTM-Angriff moeglich

    if (_is_do('s_client')) { # for debugging only
        _trace(" +s_client");
        print "#{\n", Net::SSLinfo::s_client($_[0], $_[1]), "\n#}";
    }

    $cfg{'showhost'} = 0 if (($info == 1) and ($cfg{'showhost'} < 2)); # does not make for +info, but giving option twice ...

    # now do all other required checks using %data
    local $\ = "\n";
    foreach my $label (@{$cfg{'do'}}) {
# ToDo: Spezialbehandlung fuer: fingerprint, verify, altname
        next if ($label =~ m/^(exec|cipher|check)$/); # already done or done later
        _trace(" do: " . $label) if ($cfg{'trace'} > 1);
        printtext($cfg{'legacy'}, $label, $host);
    }
    goto CLOSE_SSL if ($info == 1);

    # now do all other required checks using %check_cert
    foreach my $label (@{$cfg{'do'}}) {
        next if (1 !=_is_hashkey($label, \%check_cert));
        _trace(" do: " . $label) if ($cfg{'trace'} > 1);
        printcheck($cfg{'legacy'}, $check_cert{$label}->{txt}, _setvalue($check_cert{$label}->{val}));# _setvalue
    }

    CLOSE_SSL:
    Net::SSLinfo::do_ssl_close($host, $cfg{'port'});
    _trace(" done: $host");

} # foreach host

exit 0; # main


# check functions
# -------------------------------------
sub _setvalue($)       { return ($_[0] eq '') ? 'yes' : 'no (' . $_[0] . ')'; }
    # return 'yes' if given value is empty, return 'no' otherwise
sub _isbeast($)        { return ($_[0] =~ /(RC4)/) ? '' : $_[0] . ' '; }
    # return given cipher if vulnerable to BEAST attack, empty string otherwise
# ToDo: more checks, see: http://www.bolet.org/TestSSLServer/
sub _iscrime($)        { return 0; }
# ToDo: for checks, see: http://www.bolet.org/TestSSLServer/
sub _getscore($$$)     {
    # return 0 if given value is empty, otherwise score to given key
    my $key     = shift;
    my $value   = shift;
    my $hashref = shift;# list of checks
    my %hash    = %$hashref;
    return 0 if ($value eq '');
    _trace("_getscore: $key : '$value' = ". $hash{$key}->{score});
    return $hash{$key}->{score};
}

sub checkciphers($$$$$) {
    # test target if geven ciphers are accepted, results stored in global @results
    # NOTE that verbose output is printed directly (hence preceeds results)
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my $ciphers = shift;# ciphers to be checked
    my $hashref = shift;# our list of ciphers
    my %hash    = %$hashref;
    my $verbose = $cfg{'verbose'};
                        # verbose==2 : print remotly checked ciphers
                        # verbose==3 : print processed ciphers
                        # verbose==4 : print how cipher is processed
    local   $|  = 1;    # do not buffer (for verbosity)
    my $skip    = 0;

    printf("# checkciphers: ") if ($cfg{'verbose'} == 2);
    # ToDo: change logic of following loop
    #     now we loop over *our* ciphers which misses ciphers available in
    #     the local SSL implementation (if there are more)
    foreach my $c (sort {$hash{$a} cmp $hash{$b}} keys %hash) {
        printf("# checkciphers: $c\n") if ($cfg{'verbose'} == 3);
        printf("# checkciphers: $c\t") if ($cfg{'verbose'} == 4);
# ToDo:  cipher not supported by local SSL implementation
        #    if (!$cfg{'nolocal'}) {
        #        $skip++;
        #        next;
        #    }
        #    #printline($cfg{'legacy'}, $c, 'not') if (!$cfg{'disabled'}); # ToDo: print with --v only
        #    push(@results, [$c, 'not']);
        if (0 >= grep(/^$c$/, split(/[ :]/, $ciphers))) {
            # cipher not to be checked
            printf("skip\n") if ($cfg{'verbose'} == 4);
            next;
        }
        printf(" $c")     if ($cfg{'verbose'} == 2);
        printf("check\n") if ($cfg{'verbose'} == 4);
        #dbx# print "#dbx# H: $host , $cfg{'host'} \n";
        my $sslsocket = IO::Socket::SSL->new(
            PeerAddr        => $host,
            PeerPort        => $port,
            Proto           => 'tcp',
            Timeout         => $cfg{'timeout'},
        #   SSL_hostname    => $host,   # for SNI
            SSL_version     => $ssl,
            SSL_cipher_list => $c
            #SSL_honor_cipher_order => 1
            #
            # if $c not supported locally (part of $ciphers)
            # then new() should fail
            # ToDo: get error if failed
# SSL_verify_mode
#              This option sets the verification mode for the peer certificate.
#              The default (0x00) does no authentication.  You may combine 0x01
#              (verify peer), 0x02 (fail verification if no peer certificate
#              exists; ignored for clients), and 0x04 (verify client once) to
#              change the default.
# 
## use IO::Socket::SSL;
## my $GLOBAL_CONTEXT_ARGS = new IO::Socket::SSL::GLOBAL_CONTEXT_ARGS (
##    'SSL_verify_mode' => 0x02,
##    'SSL_ca_path' => '/root/ca/'); 
##
        );
        #dbx# printf("#dbx# E: %s\n", $sslsocket->opened()); # nok
        if (!$sslsocket) {  # connect failed, cipher not accepted
            #dbx# print "#dbx#\t$c\t$hash{$c}  -- $ssl  # unsupported";
            push(@results, [$c, 'no']);
        } else {            # connect succeded, cipher accepted
            $check_conn{$ssl}->{val}++;
            push(@results, [$c, 'yes']);

            # check weak ciphers
            $check_dest{'NULL'}->{val}  .= ' ' . $c if ($c =~ /NULL/);
            $check_dest{'EDH'}->{val}   .= ' ' . $c if ($c =~ /EDH/);
            $check_dest{'EXPORT'}->{val}.= ' ' . $c if ($c =~ /EXP/);
            # check compliance
            $check_dest{'ISM'}->{val}   .= ' ' . $c if ($c =~ /$cfg{'compliance'}->{'ISM'}/);
            $check_dest{'PCI'}->{val}   .= ' ' . $c if ($c =~ /$cfg{'compliance'}->{'PCI'}/);
            $check_dest{'FIPS'}->{val}  .= ' ' . $c if ($c =~ /$cfg{'compliance'}->{'FIPS-140'}/);
            $check_dest{'FIPS'}->{val}  .= ' ' . $c if ($c !~ /(3DES|AES)/);
            # check attacks
            $check_conn{'BEAST'}->{val} .= _isbeast($c) if ($ssl =~ /(SSLv3|TLSv1)/);
            # counters
            my $risk = get_cipher_sec($c);
            $check_conn{$ssl . '--?-'}->{val}++     if ($risk =~ /-\?-/);
            $check_conn{$ssl . '-LOW'}->{val}++     if ($risk =~ /LOW/i);
            $check_conn{$ssl . '-WEAK'}->{val}++    if ($risk =~ /WEAK/i);
            $check_conn{$ssl . '-HIGH'}->{val}++    if ($risk =~ /HIGH/i);
            $check_conn{$ssl . '-MEDIUM'}->{val}++  if ($risk =~ /MEDIUM/i);

#nok# print Net::SSL::ExpireDate($sslsocket);
# see: http://search.cpan.org/~mikem/Net-SSLeay-1.48/lib/Net/SSLeay.pod
# see: http://search.cpan.org/~sullr/IO-Socket-SSL-1.76/SSL.pm

            $sslsocket->close(SSL_ctx_free => 1);
        }
    } # foreach %hash
    print "\n" if ($verbose > 1);

} # checkciphers

sub _checksni($$) {
    # check if given FQDN needs to use SNI; sets $check_conn{'SNI'}, $check_cert{'hostname'}
    my $host    = shift;
    my $port    = shift;
    if ($cfg{'usesni'} == 1) {      # useless check for --no-sni
        if ($data{'cn_nossni'}->{val} eq $host) {
            $check_conn{'SNI'}->{val} = '';
        } else {
            $check_conn{'SNI'}->{val} = $data{'cn_nossni'}->{val};
        }
    }
    # $check_cert{'hostname'} and $check_conn{'hostname'} are similar
    if ($data{'commonName'}->{val}($host) eq $host) {
        $check_cert{'hostname'}->{val} = '';
        $check_conn{'hostname'}->{val} = '';
    } else {
        $check_cert{'hostname'}->{val} = $data{'cn_nossni'}->{val}; #$host;
        $check_conn{'hostname'}->{val} = $host; # $data{'cn_nossni'}->{val}
    }
} # _checksni

sub _getwilds($$) {
    # compute usage of wildcard in CN and subjectAltname
    my $host    = shift;
    my $port    = shift;
    my ($value, $regex);
    foreach $value (split(' ', $data{'altname'}->{val}($host))) {
            $value =~ s/.*://;      # strip prefix
        if ($value =~ m/\*/) {
            $check_cert{'wildcard'}->{val} .= ' ' . $value;
            ($regex = $value) =~ s/[*]/.*/;   # make regex (miss dots is ok)
            $check_cert{'wildhost'}->{val}  = $value if ($host =~ m/$regex/);
            $check_size{'cnt_wildcard'}->{val}++;
        }
        $check_size{'cnt_altname'}->{val}++;
        $check_size{'len_altname'}->{val} = length($value) + 1; # count number of characters + type (int)
    }
    # checking for SNI does not work here 'cause it destroys %data
} # _getwilds

sub _getsizes($$) {
    # compute some lengths and count from certificate values, sets %check_size, %check_cert
    my $host    = shift;
    my $port    = shift;
    my ($value, $regex);

    # wildcards (and some sizes)
    _getwilds($host, $port);

    $check_cert{'OCSP'}->{val}     = '' if ($data{'ocsp_uri'}->{val}($host) ne '');
    $check_cert{'rootcert'}->{val} = '' if ($data{'subject'}->{val}($host) eq $data{'issuer'}->{val}($host));
    # ToDo: more checks necessary:
    #    KeyUsage field must set keyCertSign and/or the BasicConstraints field has the CA attribute set TRUE.

    #$check_cert{'nonprint'}      =
    #$check_cert{'crnlnull'}      =
    # sizes
    $value =  $data{'PEM'}->{val}($host);
    $check_size{'len_pembase64'}->{val} = length($value);
    $value =~ s/(----.+----\n)//g;
    chomp $value;
    $check_size{'len_pembinary'}->{val} = length($value) / 8 * 6;
    $check_size{'len_subject'}->{val}   = length($data{'subject'}->{val}($host));
    $check_size{'len_issuer'}->{val}    = length($data{'issuer'}->{val}($host));
    #$check_size{'len_CPS'}->{val}       = length($data{'CPS'}->{val}($host));
    #$check_size{'len_CRL'}->{val}       = length($data{'CRL'}->{val}($host));
    #$check_size{'len_CRL_data'}->{val}  = length($data{'CRL'}->{val}($host));
    $check_size{'len_OCSP'}->{val}      = length($data{'ocsp_uri'}->{val}($host));
    #$check_size{'len_OIDs'}->{val}      = length($data{'OIDs'}->{val}($host));
    $check_size{'len_publickey'}->{val} = $data{'modulus_len'}->{val}($host);
    $check_size{'len_sigdump'}->{val}   = $data{'sigdump_len'}->{val}($host);

} # _getsizes

sub checksni($$) {
    # check and print SNI usage
    my $host    = shift;
    my $port    = shift;
    my $value   = '';
    _checksni($host, $port);
    foreach my $label (qw(SNI hostname)) {
        _printkey($label) if ($cfg{'trace'} == -1);
        $value = $check_conn{$label}->{val};
        $value = _setvalue($value);
        printcheck($cfg{'legacy'}, $check_conn{$label}->{txt}, $value);
    }
} # checksni

sub checksizes($$) {
    # check and print certificate lengths and counts
    my $host    = shift;
    my $port    = shift;
    _getsizes($host, $port);
    printsizes($cfg{'legacy'});
} # checksizes

sub checkssl($$) {
    # print SSL checks
    my $host    = shift;
    my $port    = shift;
    my $ciphers = shift;

# ToDo: needs to be modularized
    my $ssl;
    my ($label, $cipher, $value, $regex);

    if ($cfg{'short'} > 0) {
        foreach my $key (keys %check_cert) { $check_cert{$key}->{'txt'} = $shorttexts{$key}; }
        foreach my $key (keys %check_dest) { $check_dest{$key}->{'txt'} = $shorttexts{$key}; }
        foreach my $key (keys %check_conn) { $check_conn{$key}->{'txt'} = $shorttexts{$key}; }
        foreach my $key (keys %check_size) { $check_size{$key}->{'txt'} = $shorttexts{$key}; }
    }

    print "\nPerformed checks:\n";

    # compliance checks are be done in checkciphers() except FIPS
    # done in checkciphers(): NULL, EDH, EXPORT, ISM, PCI, FIPS, BEAST
# ToDo: PCI no SSLv2; trusted certificate; DH 1024+
    foreach $ssl (qw(SSLv2 SSLv3)) { $check_dest{'FIPS'}->{val} .= ' ' . $ssl if ($check_conn{$ssl}->{val} != 0); }
    if ($cfg{'SSLv2'} == 0) {
        $check_dest{'hasSSLv2'}->{val}   = '<test disabled>' if ($cfg{'SSLv2'} == 0);
    } else {
        $check_dest{'hasSSLv2'}->{val}   = '!' if ($cfg{'nullssl2'} == 1); # SSLv2 enabled, but no ciphers
    }

    # SNI, wildcards and some sizes
    _getsizes($host, $port);
    # check for SNI
    _checksni($host, $port);

    foreach $label (qw(resumption renegotiation)) {
        $value = $data{$label}->{val}($host);
        $check_dest{$label}->{val}   = $value if ($value eq '');
    }
    if ($cfg{'verbose'} > 0) { # ToDo
        foreach $label (qw(verify selfsigned)) {
#ah# print "#### $label : $value #";
            $value = $data{$label}->{val}($host);
            $check_cert{$label}->{val}   = $value if ($value eq '');
#            $score{'check_cert'}->{val} -= _getscore($label, $value, \%check_cert);
        }
    }
    $check_cert{'selfsigned'}->{val} = $data{'selfsigned'}->{val}($host);
    $check_cert{'fp_not_MD5'}->{val} = $data{'fingerprint'} if ('MD5' eq $data{'fingerprint'});
    $check_conn{'reversehost'}->{val}= $cfg{'rhost'}        if ($host ne $cfg{'rhost'});

    # print default cipher and check if safe against BEAST
    print '# @cfg{version} ' . '#' if ($cfg{'trace'} == -1); # .'#' is dirty hack to avoid bug in yeast2o-saft.sh
    foreach $ssl (@{$cfg{'versions'}}) {
        next if ($cfg{$ssl} == 0); # see eval("Net::SSLeay::SSLv2_method()") above
        $value  = $check_conn{$ssl}->{val};
        $cipher = get_default($host, $port, $ssl);
        if (($value == 0) && ($cipher eq '')) {
            $value = '(protocol probably supported, but no ciphers accepted)';
            # _getscore() below fails for this (see with --trace) 'cause there
            # is no entry %check_conn{'SSLv2-'} ; that's ok
        } else {
            $value = $cipher . ' ' . get_cipher_sec($cipher);
        }
        # the score can be found in %check_conn, where the key must be computed
        #  name of key = $ssl . '-' . sec;  # something like: SSLv3-HIGH
        # as _getscore() returns 0 if given value is empty, we always pass a value
        $score{'check_conn'}->{val} -= _getscore(($ssl . '-' . get_cipher_sec($cipher)), $value, \%check_conn);
        _printkey($ssl) if ($cfg{'trace'} == -1);
        printcheck($cfg{'legacy'}, $check_conn{default}->{txt} . $ssl, $value);
        if ($ssl =~ /(SSLv3|TLSv1)/) {
            if (_isbeast($cipher) ne '') {
                $check_conn{'BEAST-default'}->{val} .= $ssl . ':' . $cipher . ' ';
            }
        }
    }
    print '# %check_cert #' if ($cfg{'trace'} == -1);
    $cfg{'no_cert_txt'} = ' ' if ($cfg{'no_cert_txt'} eq ''); # ToDo: quick&dirty to avoid "yes" results
    foreach $label (sort keys %check_cert) {
        $value = $check_cert{$label}->{val};
        next if ($value eq 0);                      # NOT YET IMPLEMEMNTED
        $value = $cfg{'no_cert_txt'} if ($cfg{'no_cert'} != 0);
        $score{'check_cert'}->{val} -= _getscore($label, $value, \%check_cert);
        _printkey($label) if ($cfg{'trace'} == -1);
        printcheck($cfg{'legacy'}, $check_cert{$label}->{txt}, _setvalue($value));
    }
    print '# %check_dest #' if ($cfg{'trace'} == -1);
    foreach $label (sort keys %check_dest) {
        next if ($label =~ /^\s*$/);                # lazy programming :)
        $value = $check_dest{$label}->{val};
        next if ($value eq 0);                      # NOT YET IMPLEMEMNTED
        $score{'check_dest'}->{val} -= _getscore($label, $value, \%check_dest);
        _printkey($label) if ($cfg{'trace'} == -1);
        printcheck($cfg{'legacy'}, $check_dest{$label}->{txt}, _setvalue($value));
    }
    print '# %check_conn #' if ($cfg{'trace'} == -1);
    foreach $label (sort (keys %check_conn)) {
        next if ($label =~ /^\s*$/);                # lazy programming :)
        next if ($label =~ /^(SSLv|TLSv|default|IP)/); # already printed
        next if (($label eq 'hostname') and ($cfg{'no_cert'} != 0));
        $value = $check_conn{$label}->{val};
        next if ($value eq 0);                      # NOT YET IMPLEMEMNTED
        $score{'check_conn'}->{val} -= _getscore($label, $value, \%check_conn);
        _printkey($label) if ($cfg{'trace'} == -1);
        if ($label eq 'BEAST') {                    # check is special
            if (! _is_do('cipher') && ! _is_do('check')) {
                $value = "(check possible in conjunction with `+cipher' only)";
                printcheck($cfg{'legacy'}, $check_conn{$label}->{txt}, $value) if ($cfg{'verbose'} > 0);
                next;
            }
        }
        printcheck($cfg{'legacy'}, $check_conn{$label}->{txt}, _setvalue($value));
    }
    if ($cfg{'verbose'} > 0) {
        print "**WARNING: can't print certificate sizes without a certificate (--no-cert)" if ($cfg{'no_cert'} != 0);
    }
    printsizes($cfg{'legacy'}) if ($cfg{'no_cert'} == 0);

    if ($cfg{'verbose'} > 0) {
        print "\n# NOT YET completed checks:\n";

# ToDo: folgendes durch sinnvollen Check ersetzten {
        foreach $label (qw(verify_hostname verify_altname verify valid fingerprint modulus_len sigdump_len)) {
            #_printkey($label) if ($cfg{'trace'} == -1); # not necessary, done in printtext()
            printtext($cfg{'legacy'}, $label, $host);
# ToDo: nicht sinnvoll wenn $cfg{'no_cert'} != 0
        }
    }
#}

# ToDo
#   if (_is_do('verify')) {
#       print '';
#       print "Hostname validity:       "      . Net::SSLinfo::verify_hostname($host, $cfg{'port'});
#       print "Alternate name validity: "      . Net::SSLinfo::verify_altname($host, $cfg{'port'});
#   }
#
#   if (_is_do('altname')) {
#       print '';
#       print "Certificate AltNames:    "      . Net::SSLinfo::altname($host, $cfg{'port'});
#       print "Alternate name validity: "      . Net::SSLinfo::verify_altname($host, $cfg{'port'});
#   }

} #checkssl

sub get_default($$$) {
    # return default cipher from target (or local ssl if no target given)
    my $cipher = '';
    _trace(" get_default(" . ($_[0]||'') . "," . ($_[1]||'') . "," . ($_[2]||'') . ")");
    my $sslsocket = IO::Socket::SSL->new(
        PeerAddr        => $_[0],
        PeerPort        => $_[1],
        Proto           => 'tcp',
        Timeout         => $cfg{'timeout'},
        SSL_version     => $_[2],
        );
    if ($sslsocket) {
        $cipher = $sslsocket->get_cipher();
        $sslsocket->close(SSL_ctx_free => 1);
    } else {
    }
    return $cipher;
} # get_default

sub set_score($) {
    # set given value as 'score' in %check_* hash
    # if given value is a file, read settings from that file
    # otherwise given value must be KEY=VALUE format;
    my $score = shift;
    if (-f "$score") {  # got a valid file, read from that file
        _trace(" set_score: read " . $score . "\n");
        #
        # formal of each line in file must be:
        #    anthing following (and inclusing) a hash is a comment and ignored
        #    empty line are ignored
        #    setiings mut be in format:  key=value
        #       where white spaces are allowed arround =
        my $line ='';
	open(FID, $score) || warn("**WARNING: cannot open '$score': $! ; ignored");
        while ($line = <FID>) {
            chomp $line;
            $line =~ s/\s*#.*$//;       # remove trailing comments
            next if ($line =~ m/^\s*$/);# ignore empty lines
            if ($line !~ m/^[a-zA-Z0-9_?=\s-]*$/) {
                warn("**WARNING: invalid score value '$line'; ignored");
                next;
            }
            $line =~ s/[^a-zA-Z0-9_?=-]*//g;
            _trace(" set_score: set " . $line . "\n");
            set_score($line);
        }
	close(FID);
	return;
    } # read file
    my ($key, $val) = split('=', $score);
    _trace(" set_score(key=" . $key . ", score=" . $val . ").\n");
    if ($val !~ m/^(\d\d?|100)$/) { # allow 0 .. 100
        warn("**WARNING: invalid score value '$val'; ignored");
        return;
    }
    # we try $key in all hashes, if they are not unique they are set all
    # invalid keys are silently ignored
    $check_dest{$key}->{score} = $val if ($check_dest{$key});
    $check_conn{$key}->{score} = $val if ($check_conn{$key});
    $check_cert{$key}->{score} = $val if ($check_cert{$key});
    $check_size{$key}->{score} = $val if ($check_size{$key});
    $check_http{$key}->{score} = $val if ($check_http{$key});
} # set_score

# print functions
# -------------------------------------
sub _dump($$) {
    my ($label, $value) = @_;
        $label =~ s/\n//g;
        $label = sprintf("%s %s", $label, '_' x (75 -length($label)));
        printf("#{ %s\n\t%s\n#}\n", $label, $value);
        # using curly prackets 'cause they most likely are not part og any data
} # _dump
sub dumpdata()    { printdump(@_); }
sub _printkey($)  { printf("#%-16s# ", '[' . join(' ',@_) . ']'); }
sub _printhost($) { printf("%s%s", $_[0], $text{'separator'}) if ($cfg{'showhost'} > 0); }
sub printruler()  { print '-'x39, '+' . '-'x35; }
sub printdump($$) {
    # just dumps internal database %data and %check_*
    my ($legacy, $host, $port) = @_;   # NOT IMPLEMENTED
    print '######################################################################### %data';
    foreach my $key (keys %data) {
        next if ($key =~ m/(cn|PEM|pem|x509|authority|dates|expire)/); # ignore aliases
        _dump($data{$key}->{txt}, $data{$key}->{val}($host));
    }
    print '######################################################################## %check';
    foreach my $key (keys %check_conn) { _dump($check_conn{$key}->{txt}, $check_conn{$key}->{val}); }
    foreach my $key (keys %check_cert) { _dump($check_cert{$key}->{txt}, $check_cert{$key}->{val}); }
    foreach my $key (keys %check_dest) { _dump($check_dest{$key}->{txt}, $check_dest{$key}->{val}); }
} # printdump

sub printscore() {
    # print calculated scores
    print "Scoring (max value 100):";
    foreach my $key (keys %score) {
        printcheck($cfg{'legacy'}, $score{$key}->{txt}, $score{$key}->{val});
    }
} # printscore

sub printtext($$) {
    # print given label and text according given legacy format
    my ($legacy, $label, $host, $port) = @_;   # host and port are optional
    if (1 != grep(/^$label$/, keys %data)) {   # silently ignore unknown labels
        warn("**WARNING: unknown label '$label'; ignored") if ($cfg{'verbose'} > 2); # seems to be a programming error
        return;
    }
    _printkey($label) if ($cfg{'trace'} == -1);
    _printhost($host);
    my $val = $data{$label}->{val}($host);
    # { always pretty print
        if ($label =~ m/X509$/) {
            $label =~ s/X509$//;
            $val = $data{$label}->{val}($host);
            $val =~ s#/([^=]*)#\n   ($1)#g;
            $val =~ s#=#\t#g;
            printf("\n%s%s%s\n", $data{$label}->{txt}, $text{'separator'}, $val);
            return;
        }
    # }
    if ($legacy eq 'compact') {
        $val   =~ s#[\n\r]#; #g;
        $label = $data{$label}->{txt};
        $label =~ s#[\n]##g;
        printf("%s%s%s\n", $label, $text{'separator'}, $val);
        return;
    }
    if ($legacy eq 'full') {    # do some pretty printing
        if ($label =~ m/(subject|owner)/)    { $val =~ s#/#, #g; $val =~ s#^, ##g;   }
        if ($label =~ m/(issuer|authority)/) { $val =~ s#/#, #g; $val =~ s#^, ##g;   }
        if ($label =~ m/(serial|modulus)/)   { $val =~ s#(..)#$1:#g; $val =~ s#:$##; }
        if ($label =~ m/(^altname)/)         { $val =~ s#^ ##;   $val =~ s# #\n\t#g; }
        if ($label =~ m/(fingerprint)$/)     {
            $label = 'fingerprint_type';
            printf("\n%s%s\n\t%s%s\n", $data{$label}->{txt}, $text{'separator'}, $data{$label}->{val}($host));
            $label = 'fingerprint_hash';
            printf("\n%s%s\n\t%s%s\n", $data{$label}->{txt}, $text{'separator'}, $data{$label}->{val}($host));
            $label = 'fingerprint_sha1';
            printf("\n%s%s\n\t%s%s\n", $data{$label}->{txt}, $text{'separator'}, $data{$label}->{val}($host));
            $label = 'fingerprint_md5';
            printf("\n%s%s\n\t%s%s\n", $data{$label}->{txt}, $text{'separator'}, $data{$label}->{val}($host));
            return;
        }
        printf("\n%s%s\n\t%s%s\n", $data{$label}->{txt}, $text{'separator'}, $val);
    } else {
        printf("%-32s\t%s\n", $data{$label}->{txt} . $text{'separator'}, $val);
    }
} # printtext

sub printtitle($$$) {
    # print title according given legacy format
    my $legacy  = shift;
    my $ssl     = shift;
    my $host    = shift;
    my $txt     = "Checking $ssl Ciphers on $host ..."; # often used
    local    $\ = "\n";
    if ($legacy eq 'sslyze')    {
        my $txt = " SCAN RESULTS FOR " . $host . " - " . $cfg{'IP'};
        print "$txt";
        print " " . "-" x length($txt);
    }
    if ($legacy eq 'sslaudit')  {} # no title
    if ($legacy eq 'sslcipher') { print "Testing $host ..."; }
    if ($legacy eq 'ssldiagnos'){
        print
            "----------------TEST INFO---------------------------\n",
            "[*] Target IP: $cfg{'IP'}\n",
            "[*] Target Hostname: $host\n",
            "[*] Target port: $cfg{'port'}\n",
            "----------------------------------------------------\n";
    }
    if ($legacy eq 'sslscan')   { print "Testing SSL server $host"; }
    if ($legacy eq 'ssltest')   { print $txt; }
    if ($legacy eq 'ssltest-g') { print $txt; }
    if ($legacy eq 'compact')   {}
    if ($legacy eq 'simple')    { print $txt; }
    if ($legacy eq 'full')      { print $txt; }
} # printtitle

sub printheader($) {
    # print header line according given legacy format
    my $legacy  = shift;
    if ($legacy eq 'sslyze')    {}
    if ($legacy eq 'sslaudit')  {}
    if ($legacy eq 'sslcipher') {}
    if ($legacy eq 'ssldiagnos'){}
    if ($legacy eq 'sslscan')   { print "\n  Supported Server Cipher(s):"; }
    if ($legacy eq 'ssltest')   { printf("   %s, %s (%s)\n",  'Cipher', 'Enc, bits, Auth, MAC, Keyx', 'supported'); }
    if ($legacy eq 'ssltest-g') { printf("%s;%s;%s;%s\n", 'compliant', 'host:port', 'protocol', 'cipher', 'description'); }
    if ($legacy eq 'compact')   {}
    if ($legacy eq 'simple')    { printf("    %-15s\t%s\t%s\n", 'Cipher', 'supported', 'Security'); }
    if ($legacy eq 'full')      {
        # host:port protocol    supported   cipher    compliant security    description
        printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", 'host:port', 'Protocol', 'supported', 'Cipher', 'compliant', 'Security', 'Description');
    }
} # printheader

sub printfooter($) {
    # print footer line according given legacy format
    my $legacy  = shift;
    if ($legacy eq 'sslyze')    { print "\n SCAN COMPLETED IN ...\n"; }
    if ($legacy eq 'sslaudit')  {}
    if ($legacy eq 'sslcipher') {}
    if ($legacy eq 'ssldiagnos'){}
    if ($legacy eq 'sslscan')   {}
    if ($legacy eq 'ssltest')   {}
    if ($legacy eq 'ssltest-g') {}
    if ($legacy eq 'simple')    {}
    if ($legacy eq 'compact')   {}
    if ($legacy eq 'full')      {}
} # printfooter

sub printdefault($$) {
    # print default cipher according given legacy format
    my $legacy  = shift;
    my $host    = shift;
    if ($legacy eq 'sslyze')    { print "\n\n      Preferred Cipher Suites:"; }
    if ($legacy eq 'sslaudit')  {} # ToDo: cipher name should be DEFAULT
    if ($legacy eq 'sslcipher') {}
    if ($legacy eq 'ssldiagnos'){}
    if ($legacy eq 'sslscan')   { print "\n  Preferred Server Cipher(s):"; }
    if ($legacy eq 'ssltest')   {}
    if ($legacy eq 'ssltest-g') {}
    if ($legacy eq 'simple')    {}
    if ($legacy eq 'compact')   {}
    if ($legacy eq 'full')      {}
    printline($cfg{'legacy'}, $data{default}->{val}($host), 'yes');
} # printdefault

sub printtotals($$) {
    # print total number of ciphers supported according given legacy format
    my $legacy  = shift;
    my $ssl     = shift;
    my $key     = '';
    if ($legacy eq 'ssldiagnos') {
        print "\n-= SUMMARY =-\n";
        printf("Weak:         %s\n", $check_conn{$ssl . '-WEAK'}->{val});
        printf("Intermediate: %s\n", $check_conn{$ssl . '-MEDIUM'}->{val}); # MEDIUM
        printf("Strong:       %s\n", $check_conn{$ssl . '-HIGH'}->{val});   # HIGH
    }
    if ($legacy =~ /(full|simple)/) {
        foreach (qw(LOW WEAK MEDIUM HIGH -?-)) {
            $key = $ssl . '-' . $_;
            _printkey($key) if ($cfg{'trace'} == -1);
            printcheck($legacy, $check_conn{$key}->{txt}, $check_conn{$key}->{val});
        }
        _printkey($ssl) if ($cfg{'trace'} == -1);
        printcheck($legacy, $check_conn{$ssl}->{txt}, $check_conn{$ssl}->{val});
    }
} # printtotals

sub printline($$$) {
    # print cipher check result according given legacy format
    my $legacy  = shift;
    my $cipher  = shift;
    my $support = shift;
    # variables for better (human) readability
    my $bit  = get_cipher_bits($cipher);
    my $sec  = get_cipher_sec($cipher);
    my $ssl  = get_cipher_ssl($cipher);
    my $desc =  join(" ", get_cipher_desc($cipher));
    my $yesno= $text{'legacy'}->{$legacy}->{$support};
    if ( $legacy eq 'sslyze')   {
        if ($support eq 'yes') {
            $support = sprintf("%4s bits", $bit) if ($support eq 'yes');
        } else {
            $support = $yesno;
        }
        printf("\t%-24s\t%s\n", $cipher, $support);
    }
    if ( $legacy eq 'sslaudit') {
        # SSLv2 - DES-CBC-SHA - unsuccessfull
        # SSLv3 - DES-CBC3-SHA - successfull - 80
        printf("%s - %s - %s\n", $ssl, $cipher, $yesno);
    }
    if ( $legacy eq 'sslcipher') {
        #   TLSv1:EDH-RSA-DES-CBC3-SHA - ENABLED - STRONG 168 bits
        #   SSLv3:DHE-RSA-AES128-SHA - DISABLED - STRONG 128 bits
        $sec = 'INTERMEDIATE:' if ($sec =~ /LOW/i);
        $sec = 'STRONG'        if ($sec =~ /high/i);
        $sec = 'WEAK'          if ($sec =~ /weak/i);
        printf("   %s:%s - %s - %s %s bits\n", $ssl, $cipher, $yesno, $sec, $bit);
    }
    if ( $legacy eq 'ssldiagnos') {
        # [+] Testing WEAK: SSL 2, DES-CBC3-MD5 (168 bits) ... FAILED
        # [+] Testing STRONG: SSL 3, AES256-SHA (256 bits) ... CONNECT_OK CERT_OK
        $sec = ($sec =~ /high/i) ? 'STRONG' : 'WEAK';
        printf("[+] Testing %s: %s, %s (%s bits) ... %s\n", $sec, $ssl, $cipher, $bit, $yesno);
    }
    if ( $legacy eq 'sslscan') {
        #    Rejected  SSLv3  256 bits  ADH-AES256-SHA
        #    Accepted  SSLv3  128 bits  AES128-SHA
        $bit = sprintf("%3s bits", $bit);
        printf("    %s  %s  %s  %s\n", $yesno, $ssl, $bit, $cipher);

    }
    if ( $legacy eq 'ssltest') {
        # cipher, description, (supported)
        my @arr = @{$ciphers{$cipher}};
        pop(@arr);  # remove last value: tags
        pop(@arr);  # remove last value: score
        shift @arr; # remove 1'st value: security
        shift @arr; # remove 2'nd value: ssl
        $arr[1] .= ' bits';
        $arr[2] .= ' MAC';
        $arr[3] .= ' Auth';
        $arr[4] .= ' Kx';
        my $tmp = $arr[2]; $arr[2] = $arr[3]; $arr[3] = $tmp;
        printf("   %s, %s (%s)\n",  $cipher, join (', ', @arr), $yesno);
    }
    if ( $legacy eq 'ssltest-g') {
        # compliant;host:port;protocol;cipher;description
        printf("%s;%s;%s;%s\n", 'C', $cfg{'host'} . ':' . $cfg{'port'}, $sec, $cipher, $desc);
        # 'C' needs to be checked first
    }
    if ( $legacy eq 'simple')   {
        printf("    %-28s\t%s\t%s\n", $cipher, $yesno, $sec);
    }
    if ( $legacy eq 'compact')   {
        printf("%s %s %s\n", $cipher, $yesno, $sec);
    }
    if ( $legacy eq 'full') {
        # host:port protocol    supported   cipher    compliant security    description
        $desc =  join("\t", get_cipher_desc($cipher));
        $desc =~ s/\s*:\s*$//;
        printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
            $cfg{'host'} . ':' . $cfg{'port'},
            $ssl,
            $yesno,
            $cipher,
            '-?-',
            $sec,
            $desc
        );
    }
} # printline

sub _is_print($$$) {
    # return 1 if parameter indicate printing
    my $enabled = shift;
    my $print_disabled = shift;
    my $print_enabled  = shift;
    return 1 if ($print_disabled == $print_enabled);
    return 1 if ($print_disabled && ($enabled eq 'no' ));
    return 1 if ($print_enabled  && ($enabled eq 'yes'));
    return 0;
} # _is_print

sub printciphers($$@) {
    # print all cipher check results according given legacy format
    my $ssl     = shift;
    my $host    = shift;
    my @results = @_;
    my $print   = 0; # default: do not print
    my $c       = '';
    local    $\ = "\n";
    printheader( $cfg{'legacy'});
    printdefault($cfg{'legacy'}, $host) if ($cfg{'legacy'} eq 'sslaudit');

    if ($cfg{'legacy'} eq 'sslyze') {
        print "\n  * $ssl Cipher Suites :";
        printdefault($cfg{'legacy'}, $host);
        print "";
        print "\n      Accepted Cipher Suites:";
        foreach $c (@results) {
            $print = _is_print (${$c}[1], $cfg{'disabled'}, $cfg{'enabled'});
            printline($cfg{'legacy'}, ${$c}[0], ${$c}[1]) if ($print);
        }
        print "";
        print "\n      Rejected Cipher Suites:";
        foreach $c (@results) {
            $print = _is_print (${$c}[1], $cfg{'disabled'}, $cfg{'enabled'});
            printline($cfg{'legacy'}, ${$c}[0], ${$c}[1]) if ($print);
        }
    } else {
        foreach $c (@results) {
            $print = _is_print (${$c}[1], $cfg{'disabled'}, $cfg{'enabled'});
            printline($cfg{'legacy'}, ${$c}[0], ${$c}[1]) if ($print);
        }
    }
    printdefault($cfg{'legacy'}, $host) if ($cfg{'legacy'} eq 'sslscan');
    printtotals( $cfg{'legacy'}, $ssl);
    printcheck(  $cfg{'legacy'}, $check_conn{'totals'}->{txt}, $#results) if ($cfg{'verbose'} > 0);
    printfooter( $cfg{'legacy'});
} # printciphers

sub printversion() {
    # print program and module versions
    local $\ = "\n";
    print '# Path = ' . $mepath if ($cfg{'verbose'} > 1);
    print '# @INC = ' . join(" ", @INC) . "\n" if ($cfg{'verbose'} > 0);
    print "    $0 $VERSION";
    print "    " . Net::SSLinfo::do_openssl('version', '', '', '');
    # get a quick overview also
    print "Required (and used) Modules:";
    print "    IPC::System::Simple  $IPC::System::Simple::VERSION";
    print "    IO::Socket::INET     $IO::Socket::INET::VERSION";
    print "    IO::Socket::SSL      $IO::Socket::SSL::VERSION";
    print "    Net::SSLeay          $Net::SSLeay::VERSION";
    print "    Net::SSLinfo         $Net::SSLinfo::VERSION";
    my $m;
    if ($cfg{'verbose'} > 0) {
        print "\nLoaded Modules:";
        foreach $m (sort keys %INC) {
            printf("    %-22s %6s %s\n", $m, $INC{$m});
        }
        print "\nLoaded Module Versions:";
        no strict qw(refs); # avoid: Can't use string ("AutoLoader::") as a HASH ref while "strict refs" in use
        foreach $m (sort keys %main:: ) {
            next if $m !~ /::/;
            printf("    %-22s %6s %s\n", $m, ${$$m{'VERSION'}}, $INC{$m});
        }
    }
} # printversion

sub printopenssl() {
    # print openssl version
    print Net::SSLinfo::do_openssl('version', '', '', '');
} # printopenssl

sub printcheck($$$) {
    # print label and result of check
    my $legacy  = shift;
    my $label   = shift;
    my $value   = shift;
    if ( $legacy eq 'full')   {
        printf("%s\n", $label . $text{'separator'});
        printf("\t%s\n", $value) if (defined $value);
        return;
    }
    if ( $legacy eq 'compact')   {
        printf("%s", $label . $text{'separator'});
        printf("%s\n", $value) if (defined $value);
    } else {
        printf("%-36s", $label . $text{'separator'});
        printf("\t%s\n", $value) if (defined $value);
    }
} # printcheck

sub printsizes($) {
    # print label and result for sizes
    my $legacy = shift;
    my ($label, $value);
    foreach $label (sort keys %check_size) {
        _printkey($label) if ($cfg{'trace'} == -1);
        $value = '';
        $value = ' bytes' if ($label =~ /^(len)/);
        $value = ' bits'  if ($label =~ /^(len_publickey|len_sigdump)/);
# ToDo: $score{'check_size'}->{val} -= _getscore($label, $value, \%check_size);
        printcheck($legacy, $check_size{$label}->{txt}, $check_size{$label}->{val} . $value);
    }
} # printsizes

sub printhelp($) {
    # print program's help
    # if parameter is not empty, print brief list of specified label
    my $label   = shift;
    local $\;
    $\ = "\n";
    print "# help: $label .\n" if ($cfg{'verbose'} > 0);
    if ($label =~ m/^(cmd|command)s?/)  { print "# $mename commands:\t+" . join(" +", @{$cfg{'commands'}}); exit; }
    if ($label =~ m/^(legacy)s?/)       { print "# $mename legacy values:\t" . join(" ", @{$cfg{'legacys'}}); exit; }
    if ($label =~ m/^compliance/)       { print "# $mename compliance values:\t" . join(" ", keys %{$cfg{'compliance'}}); exit; }
    if ($label =~ m/^(check|score)$/) {
        my $key   = "";
        my $score = "";
        print "# $mename " . $score{'check_dest'}->{txt} . ":";
        foreach $key (sort keys %check_dest) {
            $score = "=" . $check_dest{$key}->{score} if ($label eq 'score');
            printf("%18s%s\t# %s\n", $key, $score, $check_dest{$key}->{txt});
        }
        $score = "";
        print "# $mename " . $score{'check_conn'}->{txt} . ":";
        foreach $key (sort keys %check_conn) {
            $score = "=" . $check_conn{$key}->{score} if ($label eq 'score');
            printf("%18s%s\t# %s\n", $key, $score, $check_conn{$key}->{txt});
        }
        $score = "";
        print "# $mename " . $score{'check_cert'}->{txt} . ":";
        foreach $key (sort keys %check_cert) {
            $score = "=" . $check_cert{$key}->{score} if ($label eq 'score');
            printf("%18s%s\t# %s\n", $key, $score, $check_cert{$key}->{txt});
        }
        $score = "";
        print "# $mename " . $score{'check_size'}->{txt} . ":";
        foreach $key (sort keys %check_size) {
            $score = "=" . $check_size{$key}->{score} if ($label eq 'score');
            printf("%18s%s\t# %s\n", $key, $score, $check_size{$key}->{txt});
        }
        $score = "";
        print "# $mename " . $score{'check_http'}->{txt} . ":";
        foreach $key (sort keys %check_http) {
            $score = "=" . $check_http{$key}->{score} if ($label eq 'score');
            printf("%18s%s\t# %s\n", $key, $score, $check_http{$key}->{txt});
        }
        exit;
    }
    if ($label =~ m/score/) {
        print "# $mename score values:\n";
    }
    if ($cfg{'verbose'} > 1) { printhist(); exit; }
    if ($cfg{'verbose'} < 1) { # we can test poor man's POD with --v
        if (eval("require POD::Perldoc;")) {
            # pod2usage( -verbose => 1 )
            exit( Pod::Perldoc->run(args=>[$0]) );
        }
        if (`perldoc -V`) {
            # may return:  You need to install the perl-doc package to use this program.
            exec "perldoc $0"; # scary ...
        }
        print "\n# no perldoc and no Pod::Perldoc, try poor man's POD ...\n";
    }
    # go on if exec fails or --v was given
    my $skip  = 0;
    my $ident = "        ";
    foreach (@DATA) {
        $ident = "        ";
        next if (/__DATA__$/);
        next if (/^\s*$/);
        next if (/^=(cut|pod|for).*/);
        last if (/=end ToDo/);      # quick&dirty fix 18jan13 (@DATA contains script at end)
        s/^=end\s*/  {$skip = 0;}/e && next;
        s/^=begin\s*/{$skip = 1;}/e && next;
        next if ($skip != 0);
        s/\$0/$0/g;
        print "\n" if m/^=head3\s/; # ToDo: does not work with \n in substitute below
        s/^=head1\s*/{$ident="\n"}/e;
        s/^=head2\s*/{$ident="\n  "}/e;
        s/^=head3\s*/{$ident="    "}/e;
        s/^=over\s*(\d*)//;
        s/^=back/{$ident="    "}/e;
        print "" if m/^=item\s/;
        s/^=item\s*(.*)/$1/;
        s/[BICL]<([^>]*)>/"$1"/g;
        print $ident, $_;
    }
} # printhelp

sub printhist() {
    my $egg = join ('', @DATA);
    $egg =~ s{.*?=begin\s+--v --v(.*?)=end\s+--v.*}{$1}ms;
    print scalar reverse $egg;
} # printhist

sub printtodo() {
    # print program's ToDo
    my $txt = join ('', @DATA);
    $txt =~ s{.*?=begin\s+ToDo[^\n]*(.*?)=end\s+ToDo.*}{$1}ms;
    print $txt;
} # printtodo

sub printabbr() {
    # print abbrevations, acronyms used in SSL world
    printf "#%14s - %s\n", 'Abbrevation', 'Description';
    printf "#" . '-'x15 . '+' . '-'x60 . "\n";
    printf( "%15s - %s\n", do{(my $a=$_)=~s/ *$//;$a}, $text{'glossar'}->{$_}) foreach (sort keys %{$text{'glossar'}});
} # printabbr

__END__
__DATA__

=pod

=head1 NAME

o-saft.pl - OWASP SSL audit for testers

=head1 DESCRIPTION

This tools lists  information about remote target's  SSL  certificate
and tests the remote target according given list of ciphers.

=head1 SYNOPSIS

$0 [COMMANDS ..] [OPTIONS ..] target [target target ...]

Where  [COMMANDS]  and  [OPTIONS]  are described below  and  C<target>
is a hostname either as full qualified domain name or as IP. Multiple
commands and targets are possible.

=head1 QUICKSTART

Before we go into the details of the purpose and usage,  here are the
most often used examples:

=over

=item Show supported (enabled) ciphers of target:

    $0 +cipher --enabled example.tld

=item Show details of certificate and connection of target:

    $0 +info example.tld

=item Check certificate, ciphers and SSL connection of target:

    $0 +check example.tld

=back

For more special test cases, see  B<COMMANDS>  and  B<OPTIONS>  section
below.

=head1 RESULTS

For the results,  we have to distinguish those returned by  I<+cipher>
command  and those from all other tests and checks like  I<+check>  or
I<+info>  command.

=head3 +cipher

    The cipher checks will return one line for each tested cipher. It
    contains at least the cipher name,  "yes"  or  "no"  wether it is
    supported or not, and a security qualification. It may look like:
        AES256-SHA       yes    HIGH
        NULL-SHA         no     weak

    Depending on the used  "--legacy=*"  option the format may differ
    and also contain more information.  For details see  "--legacy=*"
    option below.

    The text for security qualifications are mainly those returned by
    openssl (version 0.9.8): LOW, MEDIUM, HIGH and WEAK.
    The same texts but with all lower case characters are used if the
    qualification was adapted herein.

=head3 +check

    These tests return a line with a label describing the test  and a
    test result for it.  The  idea is to report  "yes"  if the result
    is considered "secure" and report the reason why it is considered
    insecure otherwise.

    Note that there are tests where  the reuslt sounds confusing when
    first viewed, like for www.wi.ld:
        Certificate is valid according given hostname:  no (*.wi.ld)
        Certificate's wilcard does not match hostname:  yes
    This can for example occour with:
        Certificate Common Name:                *.wi.ld
        Certificate Subject's Alternate Names:  DNS:www.wi.ld

    Please check the result with the  "+info"  command also to verify
    if the check sounds resonable.

=head3 +info

    The test result contains  detailed information.  The labels there
    are mainly the same as for the  "+check"  command.

=head1 COMMANDS

There are commands for various tests according the  SSL connection to
the target.

All commands are preceded by a  I<+>  to easily distinguish from other
arguments and options. However, some  I<--OPT>  options are treated as
commands for historical reason or compatibility to other programs.

The Most important commands are (in alphabetical order):

=head3 +check +cipher +info +list +sni +sni_check +version

A list of all available commands will be printed with

    $0 --help=commands

=begin comment

    Nach  =head3  sollten die Paragraphen eingerueckt sein,  das kann
    (perl)pod aber nicht.  Darum verwenden wir  "verbatime paragraph"
    und verzichten auf spezielle POD-Auszeichnungen.

=end comment

=head2 Commands for information about this tool

=head3 +ciphers

    Show ciphers offerd by local SSL implentation and by target.

    Note that SSL requires a successful connection to the target.  If
    no target is given, we try to get the list using "openssl(1)".

=head3 +list

    Show all ciphers  knwon by this tool.  This includes cryptogrphic
    details of the cipher and some internal details about the rating.

    Use "--v" option to show more details.

=head3 +abbr +abk

    Show common abbrevation used in the world of security.

=head3 +version

    Show program's and used perl modules' version, then exit.

    Use "--v" option to show more details.

=head3 +libversion

    Show version of openssl.

=head3 +todo

    Show known problems and bugs.

=head2 Commands to check SSL details

    Check for SSL connection in  SNI mode and if given  FQDN  matches
    certificate's subject.

=head3 +check

    Check the SSL connection for security issues. This is the same as
     "+info +cipher +sizes --sslv2 --sslv3 --tls1"
    but also gives some kind of rating for security issues if any.

    The rating is mainly based on the information given in
        http://ssllabs.com/.....

    Note that this command cannot be combined with other commands.

=head3 +info

    Overview of most important details of the SSL connection.

=head3 +info--v

    Overview of all details of the SSL connection. This is a shortcut
    for all commands listed below but not including "+cipher".

    This command is intended for debuuging  as it prints some details
    from the used  Net::SSLinfo  module.

=head3 +sni

    Check for Server Name Indication (SNI) usage.

=head3 +sni_check +check_sni

    Check for Server Name Indication (SNI) usage and validity of all
    names (CN, subjectAltName, FQDN, etc.).

=head3 +sizes

    Check length, size and count of some values in the certificate.

=head3 +s_client

    Dump data retrived from  "openssl s_client ..."  call.  Should be
    used for debugging only.

=head3 +dump

    Dumps internal data for SSL connection and target certificate.
    This is mainly for debugging and should not be used together with
    other commands (except "+cipher").
    Each key-value pair is enclosed in "#{" and "#}" .

    Using "--trace --trace" dumps data of  Net::SSLinfo  too.

=head3 +exec

    Command used internally when requested to use other libraries.
    This command should not be used directly.


=head2 Commands to test target's ciphers

=head3 +cipher

    Check target for ciphers, either all ciphers or ciphers specified
    with "-cipher=*" option.

    Note that ciphers not supported by the local SSL implentation are
    not checked by default, use "--local" option for that.

=head2 Commands to test SSL connection to target

=head3 +beast

    Check if target accepts ciphers vulnerable to BEAST attack.

=head3 +renegotiation

    Tests the target's support for client-initiated renegotiations.

=head3 +resumption

    Tests if the target supports session resumption (RFC 5077).

=head2 Commands to show details of the target's certificate

The names of these commands are mainly adopted to  openssl's commands
(see "openssl cipher", "openssl x509").
All these commands just show  a single detail which is also available
with the I<+text> command.

=head3 +after, +valid

    Show date until certificate is valid.

=head3 +altname

    Show certificate's subject alternate name (SAN).

=head3 +aux

    Show certificate's trust information.

=head3 +before

    Show date since certificate is valid.

=head3 +cn, +commonName

    Show certificate's common name (CN).

=head3 +certificate

    Show certificate's PEM and text.

=head3 +email

    Show certificate's email address.

=head3 +expire

    Show certificate's expire date (alias for "+after").

=head3 +extensions

    Show certificate's X509V3 extensions.

=head3 +fingerprint

    Show certificate fingerprint's algorithm and hash value.

=head3 +issuer, +authority

    Show certificate's issuer name.

=head3 +modulus

    Show certificate public key's modulus.

=head3 +pem

    Show certificate as PEM.

=head3 +pubkey

    Show certificate's public key.

=head3 +sigdump

    Show hexadecimal dump of the certificate signature.

=head3 +signame

    Show certificate's signature algorithm.

=head3 +subject, +owner

    Show certificate's subject name.

=head3 +fingerprint_md5

    Show certificate  MD5 fingerprint (with Net::SSLeay >= 1.49 only)

=head3 +fingerprint_sha1

    Show certificate SHA1 fingerprint (with Net::SSLeay >= 1.49 only)

=head2 More commands to show details of the target's certificate

Following command are not available using L<openssl(1)>  (version 0.9.x)
directly but only herein.

=head3 +fingerprint_type

    Show certificate fingerprint's algorithm.

=head3 +fingerprint_hash

    Show certificate fingerprint's hash value.

=head3 +modulus_len

    Show certificate public key's length (in bits).

=head3 +modulus_exponent

    Show certificate public key's modulus exponent.

=head3 +pubkey_algorithm

    Show certificate public key's algorithm.

=head3 +serial

    Show certificate's serial number.

=head3 +text

    Show certificate as text.

=head3 +trustout

    Verify if certificate is trusted.

=begin comment

=head3 +verify

    Verify if given hostname matches target's certificate.

=end comment

=head1 OPTIONS

=head2 General options

=head3 --h --help

  WYSIWYG

=head3 --help=commands

  Show available commands.

=head3 --help=checks

  Show available checks.

=head3 --help=legacy

  Show possible legacy formats (used as value for  "--legacy=KEY"  option).

=head3 --help=compliance

  Show available compliance checks.

=head3 --help=score

  Show score value for each check.
  Value is printed in format to be used for  "--set-score KEY=VAL"  option.

  Note that the sequence of options is important. Use the options "--trace"
  and/or  ""--set-score KEY=VAL"  before  "--help=score".

=head3 --n

  Do not execute, just show commands (only useful in conjunction with
  using openssl).

=head3 --v --verbose

  Print more information about checks.

  Note that this option should be first otherwise some debug messages
  may be missing.

=head3 --v --v

  Print remotly checked ciphers.

=head3 --v --v --v

  Print processed ciphers.

=head3 --v --v --v --v

  Print checked ciphers and checks.

=head3 --trace

  Print more debugging messages.

=head3 --trace --trace

  Print more debugging messages and pass "trace=2" to Net::SSLeay and
  Net::SSLinfo.

=head3 --trace --trace --trace

  Print more debugging messages and pass "trace=3" to Net::SSLeay and
  Net::SSLinfo.

=head3 --trace --trace --trace --trace

  Print processing of all command line arguments.

=head3 --trace--

  Print some internal variable names in debugging messages.

=head2 --trace vs. --v

While  I<--v>  is used to print more data,  I<--trace> is used to print
more information about internal data such as  procedure names  and/or
variable names and program flow.

=head2 Options for SSL tool

=head3 --s_client

  Use  "openssl s_slient ..." call to retrieve more informations from
  the SSL connection.  This is disabled by default on Windows because
  of performance problems. Without this option following informations
  are missing on Windows:
      compression, expansion, renegotiation, resumption,
      selfsigned, verify
  See "Net::SSLinfo" for details.

=head3 --no-openssl

  Do not use external "openssl" tool to retrieve informations. Use of
  "openssl" is disabled by default on Windows.
  Note that this results in some missing informations.

=head3 --openssl=TOOL

  TOOL      can be a path to openssl executable;  default: openssl

=begin comment

  ssleay:   use installed SSLeay library for perl
  local:    use installed openssl (found via PATH envrionment variable)
            Note that this disables use of SSLeay
  x86_32:   use  ** NOT YET IMPLEMENTED **
  x86_64:   use  ** NOT YET IMPLEMENTED **
  x86Mac:   use  ** NOT YET IMPLEMENTED **
  arch:     use  ** NOT YET IMPLEMENTED **

=end comment

=head3 --exe=PATH

  PATH      is a full path where to find openssl.

=head3 --lib=PATH

  PATH      is a full path where to find libssl.so and libcrypto.so

  See "HACKER's INFO" below for a detailed description how it works.

=head3 --envlibvar=NAME

  NAME  is the name of the environment variable containing additional
  paths for searching dynamic shared libraries.
  Default is LD_LIBRARY_PATH .

  Check your system for the proper name, i.e.:
      DYLD_LIBRARY_PATH, LIBPATH, RPATH, SHLIB_PATH .

=head2 Options for SSL connection to target

=head3 --cipher=CIPHER

  CIPHER    can be any string accpeted by openssl or following:

  yeast     use all ciphers from list defined herein, see "+list"

Default is  C<ALL:NULL:eNULL:aNULL:LOW>  as specified in Net::SSLinfo.

=head3 --local

  It does not make much sense trying a connection with a cipher which
  is  not supported  by the local SSL implementation. Hence these are
  silently ignored by default.
  With this option we try to use such ciphers also.

=head3 --ssl2, --sslv2

=head3 --ssl3, --sslv3

=head3 --tls1, --tlsv1

=head3 --tls11, --tlsv11

=head3 --tls12, --tlsv12

  Tests ciphers for this SSL version.
  Note that these options are discarded for  "+check"  command.

=head3 --nullsslv2

  This option forces to assume that  SSLV2 enabled even if no ciphers
  accepted.

  The target server may accept connections with  SSLv2  but not allow
  any cipher. Some checks verify if  SSLv2  is enabled at all,  which
  then would result in a failed test.
  The default behaviour is to assume that  SSLv2 is not enabled if no
  ciphers are accepted.

=head3 --http

  Make a HTTP request if cipher is supported.

  If used twice debugging will be enabled using  environment variable
  HTTPS_DEBUG .

=head3 --no-http

  Do not make HTTP request.

=head3 --sni

  Make SSL connection in SNI mode.

=head3 --no-sni

  Do not make SSL connection in SNI mode (default: SNI mode).

=head3 --no-cert

  Do not get data from target's certificate, return empty string.

=head3 --no-cert --no-cert

  Do not get data from target's certificate, return Net::SSLinfo.pm's
  default string.

=head3 --no-cert-text

  Set string to be returned from  "Net::SSLinfo.pm" if no certificate
  data is collected due to use of "--no-cert".

=head2 Options for checks and results

Options used for  I<+check>  command:

=head3 --enabled

  Only print result for ciphers accepted by target.

=head3 --disabled

  Only print result for ciphers not accepted by target.

=head3 --ignorecase

  Checks are done case insensitive.

=head3 --no-ignorecase

  Checks are done case sensitive. Default: case insensitive.
  Currently only checks according CN, alternate names in the target's
  certificate compared to the given hostname are effected.

=head3 --set-score KEY=SCORE

  Set the score value  "SCORE"  for the check specified by  "KEY".
  All score values are set to 10 by default. Values "0" .. "100"  are
  allowed.

  If  "KEY=SCORE"  is a filename, values are read from that file.
  To generate a sample file, simply use:

    $0 --help=score

  For deatils how soring works, please see  SCORING  section.

=head2 Options for output format

=head3 --short

  Use short less descriptive text labels for  "+check"   and  "+info"
  command.

=head3 --legacy=TOOL

  For compatibility with other tools,  the output format used for the
  result of the  "+check" command can be adjusted to mimic the format
  of other SSL testing tools.

  The argument to the "--legacy=TOOL"  option is the name of the tool
  to be simulated.

  Following TOOLs are supported:

    sslaudit:     format of output similar to  sslaudit
    sslcipher:    format of output similar to  ssl-cipher-check
    ssldiagnos:   format of output similar to  ssldiagnos
    sslscan:      format of output similar to  sslscan
    ssltest:      format of output similar to  ssltest
    ssltestg:     format of output similar to  ssltest -g
    ssltest-g:    format of output similar to  ssltest -g
    sslyze:       format of output similar to  sslyze
    ssl-cipher-check:    same as sslcipher:

  Note that these legacy formats only apply to the checked ciphers.
  Other texts like headers and footers are adapted slightly.

  Please don't expect identical output as the TOOL, it's a best guess
  and should be parsable in a very similar way.

  TOOL may also be one of follwoing internal formats:

    compact:      mainly avoid tabs and spaces
                  format is as follows
                    Some Label:<-- anthing right of colon is data
    full:         pretty print: each label in its  own line, followed
                  by data in next line prepended by tab character
                  (useful for "+info" only)


=begin comment

**NOT YET IMPLEMENTED**

=head3 --de

  Deutsche Texte ausgeben. (Betrifft nicht die Texte bei "--legacy" Ausgaben).

=head3 --en

  Print English texts.

=head3 --format=F

=head3 --format F

  csv       print result for cipher test as comma separated list
  ssv       print result for cipher test as semicolon separated list
  tab       print result for cipher test as TAB separated list
  txt       print result for cipher test as simple line with spaces
  html      print result for cipher test HTML formated (HTML fragment)
  json      print result for cipher test JSON formated
  xml       print result for cipher test XML formated (XML fragment)
  fullhtml  print result for cipher test HTML formated (complete HTML)
  fullxml   print result for cipher test XML formated (complete XML)

  The "--format" option is ignored if "--legacy" is used.

=end comment

=head3 --separator=CHAR --sep=CHAR

  Character (or string) CHAR will be used as separator between labels
  and values of the printed results. Default is  :

=head3 --showhost

  Prefix each printed line with the given hostname (target).

  Note that this option does not apply to the commands:
   +check +cipher +info +sni +sni_check

=begin comment

  However, it applies partially if used twice.

=end comment

=head2 Options for compatibility with other programs

Please see other programs for detailed description (if not obvious:).
Note that only the long form options are accepted  as most short form
options are ambigious.

=over 4

=item --insecure        (cnark.pl)

=item --hide_rejected_ciphers (sslyze)

=item --no-failed       (sslscan)

=item --regular         (sslyze)

=item --reneg           (sslyze)

=item --resum           (sslyze)

=item --timeout=SEC     (sslyze)

=item -H, -s, --timeout, -u, -url, -U, -x

=back

  These options are silently ignored.

=head2 Options vs. Commands

For comptibility with other programs and lazy users, some options are
silently taken as commands, means that  I<--THIS>  becomes  I<+THIS> .

=over 4

=item --help

=item --abbr

=item --todo

=item --chain

=item --default

=item --fingerprint

=item --list

=item --version

=back

Take care that this behaviour may be removed in future versions as it
conflicts with those options and commands which actually exist, like:

=over 4

=item --sni  vs.  +sni

=back

=head1 SCORING

The scoring is implemented for following different values:

=over 4

=item Target checks

=item SSL connection checks

=item Ciphers checks

=item Certificate checks

=item Certificate sizes checks

=item HTTP(S) checks

=back

the max. value for each is  100  and will be decremented by the score
defined for each check (see  I<--help=score>) if that check fails.

Each check has a default score of  10. This value can be chaged using
the  I<--set-score>  option.

=head1 LIMITATIONS

Port as specified with I<--port> options is the same for all targets.

If the specified targets accepts connections but does not speak  SSL,
the connection will be closed after the system's TCP/IP-timeout. This
script will hang (about 2-3 minutes).

The used L<timeout(1)> command cannot be defined with a full path like
L<openssl(1)> can with the I<--openssl=path/to/openssl>.

Checking the target for supported ciphers may return that a cipher is
not supported by the server  misleadingly.  Reason is most likely  an
improper timeout for the connection.

=head2 Poor Systems

On Windows usage of L<openssl(1)> is disabled by default due to various
performance problems. It needs to be enabled with I<--openssl> option.

On Windows the usage of "openssl s_client" needs to be enabled using
I<--s_client> option.

On Windows it's a pane to specify the path for I<--openssl=..> option.
Variants are:

=over 4

=item --openssl=/path/to/openssl.exe

=item --openssl=X:/path/to/openssl.exe

=item --openssl=\path\to\openssl.exe

=item --openssl=X:\path\to\openssl.exe

=item --openssl=\\path\\to\\openssl.exe

=item --openssl=X:\\path\\to\\openssl.exe

=back

You have to fiddle around to find the proper one.

=head1 WHY?

Why a new tool for checking SSL  when there already exist a dozens or
more in 2012? Some (but not all) reasons are:

=over

=item - lack of tests of unusual ciphers

=item - different results returned for the same check on same target

=item - missing functionality (checks) according modern SSL/TLS

=item - lack of tests of unusual (SSL, certificate) configurations

=item - new advanced features (CRL, OCSP, EV) not supported

=item - (mainly) missing feasability to add own tests

=back

Other  reasons or problems  are that they are either binary and hence
not portable to other (newer) platforms.

=begin comment

Or, if written in perl, they mainly use L<Net::SSLeay(1)> or 
L<IO::Socket::SSL(1)> which lacks CRL and OCSP and EV checkings.

=end comment

=head1 DEPENDENCIES

=over

=item L<IO::Socket::SSL(1)>

=item L<IO::Socket::INET(1)>

=item L<Net::SSLeay(1)>

=item L<Net::SSLinfo(1)>

=back


=head1 SEE ALSO

L<openssl(1)>, L<Net::SSLeay(1)>, L<Net::SSLinfo(1)>, L<timeout(1)>

http://www.openssl.org/docs/apps/ciphers.html

L<IO::Socket::SSL(1)>, L<IO::Socket::INET(1)>

=head1 HACKER's INFO

We support following options, which are all identical, for lazy users
and for compatibility with other programs:

    --port PORT
    --port=PORT
    --p PORT
    --p=PORT
    -p PORT
    -p=PORT

This applies to all such options, I<--port> is just an example.

Following syntax is supported also:

    $0 http://some.tld other.tld:3889/some/path?a=b

Note that only the hostname and the port are used from an URL. When a
port is given in an URL and a I<--port> option, the order of them will
identify which port is used: last one wins.

=head2 Using private libssl.so and libcrypt.so

For all  cryptographic functionality  the libraries  installed on the
system will be used.  This is in particular perl's  Net:SSLeay module
and the openssl executable.

It is possible to provide your own libraries, if the  perl module and
the executable are  linked using  dynamic shared objects  (aka shared
library, position independent code).

On most systems these libraries are loaded at startup of the program.
The runtime loader uses a preconfigured list of directories  where to
find these libraries. Also most systems provide a special environment
variable to specify  additional paths  to directories where to search
for libraries, for example the  LD_LIBRARY_PATH environment variable.
This is the default environment variable used herein.  If your system
uses  another name it must be specified with the  I<--envlibvar=NAME>
option, where  NAME  is the name of the environment variable.

=head3 Caveats

Depending on your system, and the used modules and executabes, it can
be tricky to replace the configured shared libraries with own ones.
Reasons are:
  a) the linked library name contains a version number,
  b) the linked library uses a fixed path,
  c) the linked library is searched at a predefined path,
  d) the executable checks the library version when loaded.

Only the first one a) can be circumvented.  The last one d) can often
be ignored as it only prints a warning or error message.

To circumvent the "name with verion number" problem try following:

=over

=item 1. use ldd (or a similar tool) to get the names used by openssl:

  ldd /usr/bin/openssl

which returns something like:

  libssl.so.0.9.8 => /lib/libssl.so.0.9.8 (0x00007f940cb6d000)
  libcrypto.so.0.9.8 => /lib/libcrypto.so.0.9.8 (0x00007f940c7de000)
  libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f940c5d9000)
  libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f940c3c1000)
  libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f940c02c000)
  /lib64/ld-linux-x86-64.so.2 (0x00007f940cdea000)

Here only the first two libraries are important.  Both,  libcrypto.so
and libssl.so  need to be version "0.9.8" (in this example).

=item 2. create a directory for your libraries, i.e.:

  mkdir /tmp/dada

=item 3. place your libraries there, assuming they are:

  /tmp/dada/libssl.so.1.42
  /tmp/dada/libcrypto.so.1.42

=item 4. create symbolic links in that directory:

  ln -s libssl.so.1.42    libssl.so.0.9.8
  ln -s libcrypto.so.1.42 libcrypto.so.0.9.8

=item 5. test program with following option:

  $0 +libversion --lib=/tmp/dada
  $0 +list --v   --lib=/tmp/dada

  or:

  $0 +libversion --lib=/tmp/dada -exe=/path/to-openssl
  $0 +list --v   --lib=/tmp/dada -exe=/path/to-openssl

=item 6. start program with your options, i.e.:

  $0 --lib=/tmp/dada +ciphers

=back

This works if L<openssl(1)> uses the same shared libraries as
L<Net:SSLeay(1)>, which most likely is the case.

It's tested with Unix/Linux only. It may work on other platforms also
if they support such an environment variable and the installed
L<Net::SSLeay(1)>  and L<openssl(1)>  are linked using dynamic shared
objects.

Depending on the compile time settings and/or the location of the used
tool or lib, a warning like follows my occour:

  WARNING: can't open config file: /path/to-openssl/ssl/openssl.cnf

This warning can be ignored, usually.

=head3 Cumbersome Approach

A more cumbersome approach to call  this program is to set  following
environment variables in your shell:

  PATH=/tmp/dada-1.42/apps:$PATH
  LD_LIBRARY_PATH=/tmp/dada-1.42

=head3 Windows Caveats

I.g. the used libraries on Windows are libeay32.dll and ssleay32.dll.
The I<--lib> option is not yet tested on Windows systems.

Windows also supports the LD_LIBRARY_PATH environment variable. If it
does not work as expected with that variable, it might be possible to
place the libs in the same directory as the  corresponding executable
(which is found by the PATH environment variable).

=for comment openssl.exe 1.0.0e needs: libeay32.dll, ssleay32.dll

=head2 Using CGI mode

The script can be usesed as CGI application. Output is the same as in
common CLI mode, using  'Content-Type:text/plain'.  Keep in mind that
the used modules like  L<Net::SSLeay>  will write some  debug messages
on STDERR instead STDOUT. Therefore multiple  I<--v> and/or  I<--trace>
options behave slightly different.

Some options are disabled in CGI mode  because they are dangerous  or
don't make any sense.

=head3 WARNING

  There are  no  input data validation checks implemented herein. All 
  input data is url-decoded once and then used verbatime.
  More advanced checks must be done outside before calling this tool.

=begin comment

The only code necessary for CGI mode is encapsulated at the beginning,
see C<if ($me =~/\.cgi$/){ ... }>. Beside some minor additional regex
matches (mainly removing trailing  C<=> and empty arguments) no other
code is needed. 

=head2 Program Code

Most functions use global variables (even if they are defined in main
with `my'). These variables are mainly: @DATA, @results, %cmd, %data,
%cfg, %check_*, %ciphers, %text.

All C<print*()> functions write on STDOUT directly. They are slightly
prepared  for using texts from the configuration (%cfg, %check_*), so
these texts can be adapted easily.

The  code  mainly uses  'text enclosed in single quotes'  for program
internal strings such as hash keys, and uses "double quoted" text for
texts being printed. However, exceptions if obviously necessary ;-)
Reason is mainly to make seaching texts a bit easyer.

The code is most likely not thread-safe. Anyway, we don't use them.

=end comment

=head2 Debugging, Tracing

Following  options and commands  are useful for hunting problems with
SSL connections and/or this tool. Note that some options can be given
multiple times to increase amount of listed information. Also keep in
mind that it's best to specify  I<--v>  as very first argument.

=head3 Commands

=over 4

=item +dump

=item +libversion

=item +s_client

=item +todo

=item +version

=back

=head3 Options

=over 4

=item --v

=item --trace

=item --trace--

=back


=head1 EXAMPLES

($0 in all following examples is the name of the tool)

=head2 General

    $0 +cipher example.tld
    $0 +info   example.tld
    $0 +check  example.tld
    $0 +list
    $0 +list --v
    $0 +certificate example.tld
    $0 +fingerprint example.tld 444
    $0 +expire +valid example.tld

=head2 Some specials

=over

=item Check for Server Name Indication (SNI) usage only

    $0 +sni example.tld

=item Check for SNI and print certificate's subject and altname

    $0 +sni +cn +altname example.tld

=item Check for all SNI, certificate's subject and altname issues

    $0 +sni_check example.tld

=item Only print supported (enabled) ciphers:

    $0 +cipher --disabled example.tld

=item Only print unsupported (disabled) ciphers:

    $0 +cipher --enabled example.tld

=item Test for a specific ciphers:

    $0 +cipher --cipher=ADH-AES256-SHA example.tld

=item Test all ciphers, even if not supported by local SSL implementation:

    $0 +cipher --local example.tld

=item Test using a private libssl.so, libcrypto.so and openssl:

    $0 +cipher --lib=/foo/bar-1.42--exe=/foo/bar-1.42/apps some.tld

=back

=head2 Special for hunting problems with connections etc.

=over

=item Simple tracing

    $0 +cn   some.tld --trace
    $0 +info some.tld --trace

=item A bit more tracing

    $0 +cn   some.tld --trace --trace

=item Show internal variable names in output

    $0 +info some.tld --trace--

=item Show warnings, if any

    $0 +info some.tld --v --v --v

=item Show values retrieved from target certificate directly

    $0 +info some.tld --no_cert --no_cert --no_cert-text=Value-from-Certificate

=back

=for following lines may contain trailing space, which are requiered

=begin --v --v

.raw nerobeg
sretset rof tidua LSS PSAWO  -  "tfaS-O"   
retseT r¼Ãf tiduA LSS PSAWO  -  "tfaS-O"   
 nnawdnegri nnad sib ,elieW enie sad gnig oS
..wsu ,"haey-lss" ,"agoy-lss" :etsiL red fua dnats -ret¤Ãps reibŸÃieW
eretiew  raap nie-  nohcs se tnha rhi  ,ehcuS eid nnageb os ,nebegrev
 nohcs dnis nemaN ednessap eleiV  .guneg 'giffirg`  thcin reba sad raw
gnuhciltneff¶ÃreV enie r¼ÃF  .noisrevsgnulkciwtnE red emaN  red tsi saD
. loot LSS rehtona tey -  "lp.tsaey"   :resseb nohcs tsi
sad ,aha ,tsaey -- efeH -- reibŸÃieW .thcin sad tgnilk srednoseb ,ajan
eigeRnegiE ni resworB LSS nie redeiw  -  "lp.reibssiew"   
:ehan gal se ,nedrew emaN 'regithcir` nie hcod nnad se etssum
hcan dnu hcaN  .edruw nefforteg setsre sla "y" sad liew ,"lp.y" :eman
-ietaD nie snetsednim  ,reh emaN nie etssum sE .slooT seseid pytotorP
retsre nie nohcs hcua nnad dnatsne iebad ,tetsokeg reibŸÃieW eleiv dnu
nednutS eginie nnad hcim tah esylanA eiD .)dnis hcon remmi dnu( neraw
nedeihcsrev rhes esiewliet eis muraw ,nednifuzsuareh dnu nehetsrev uz
)noitpO "*=ycagel--"  eheis( slooT-tseT-LSS reredna releiv essinbegrE
nehcildeihcsretnu eid hcusreV mieb  dnatstne looT  meseid uz eedI eiD

)-: ti dnatsrednu :laog txeN .eno neddih eht ,ti tog uoY

=end --v

=head1 ATTRIBUTION

Based on ideas (in alphabetical order) of:
   cnark.pl, SSLAudit.pl sslscan, ssltest.pl, sslyze.py

=for comment: VERSION string must start with @(#) at beginning of a line

=head1 VERSION

@(#) 13.03.13

=head1 AUTHOR

31. July 2012 Achim Hoffmann (at) sicsec de

=begin ToDo # no POD syntax here!

TODO

  * useSNI funktioniert nicht sauber in Net::SSLinfo, Einstieg siehe 
    # following check useful with SNI only

  * complete +http checks (see %check_http also)

  * implement +chain (see Net::SSLinfo.pm implement verify* also)

  * +beast
    dazu muss eigene Check-Route gemacht werden, da Protokoll und
    Cipher pro Protokoll geprueft werden (so wie z.Zt. in checks() )

  * implement +crime, +renegotiation und +resumption as command

  * check() Rest implementieren (siehe check{XXX}->{val} == 0
          SSL_honor_cipher_order => 1

  * use Net::SSLeay 1.42 as fallback, because 1.49 causes problems at
    some sites (connect() fails).

  * (nicht wichtig, aber sauber programmieren)
    get_default(): Net::SSLinfo::default() benutzen
    _yeast() und _trace() vereinheitlichen
  
  * --cipher=RC4  funktioniert mit openssl, aber nicht hier
    (wontfix; nur Shortcuts LOW|MEDIUM|HIGH|+ usw. unterstützt)

  * Net::SSLinfo.pm implement verify*

  * Net::SSLinfo.pm Net::SSLeay::ctrl()  sometimes fails, but doesn't
    return error message

  * Net::SSLinfo.pm Net::SSLeay::set_cipher_list() Segmentation fault
    (with Net::SSLeay 1.49 and newer)

  * Net::SSLinfo.pm Net::SSLeay::get_cipher_bits() Segmentation fault

=end ToDo

=cut
