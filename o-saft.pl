#!/usr/bin/perl -w

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

#!# WARNING:
#!# This is no "academically" certified code,  but written to be understood and
#!# modified by humans (you:) easily.  Please see the documentation  in section
#!# "Program Code" at the end of this file if you want to improve the program.

# ToDo please see  =begin ToDo  in POD section

use strict;

my  $SID    = "@(#) yeast.pl 1.218 14/02/01 12:39:23";
my  @DATA   = <DATA>;
our $VERSION= "--is defined at end of this file, and I hate to write it twice--";
{ # perl is clever enough to extract it from itself ;-)
    $VERSION= join ("", @DATA);
    $VERSION=~ s/.*?\n@\(#\)\s*([^\n]*).*/$1/ms;
};

our $me     = $0; $me     =~ s#.*/##;
our $mepath = $0; $mepath =~ s#/[^/]*$##;
    $mepath = "./" if ($mepath eq $me);
our $mename = "yeast  ";
    $mename = "O-Saft " if ($me !~ /yeast/);

binmode(STDOUT, ":unix");
binmode(STDERR, ":unix");

use IO::Socket::SSL; #  qw(debug2);
use IO::Socket::INET;

# README if any
# -------------------------------------
open(RC, '<', "o-saft-README") && do { print <RC>; close(RC); exit 0; };

# CGI
# -------------------------------------
my $cgi  = 0;
if ($me =~/\.cgi$/) {
    # CGI mode is pretty simple: see {yeast,o-saft}.cgi
    #   code removed here!
    die "**ERROR: CGI mode requires strict settings" if ($cgi !~ /--cgi=?/);
    $cgi = 1;
}

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

sub _print_read($$) { printf("=== reading %s from  %s ===\n", @_) if(grep(/(:?--no.?header)/i, @ARGV) <= 0); }
        # $cfg{'out_header'} not yet available, see LIMITATIONS also

my $arg = "";
# array to collect data fordebugging, they are global!
our @dbxarg;    # normal options and arguments
our @dbxcfg;    # config options and arguments
our @dbxexe;    # executable, library, environment
our @dbxfile;   # read files

# read file with user source, if any
# -------------------------------------
my @usr = grep(/--(?:use?r)/, @ARGV);   # must have --usr option
if (($#usr >= 0) and ($cgi == 0)) {
    $arg =  "./o-saft-usr.pm";
    if (! -e $arg) {
        $arg = join("/", $mepath, $arg);# try to find it in installation directory
    }
}
if (-e $arg) {
    push(@dbxfile, $arg);
    _print_read("user file", $arg) if(grep(/(:?--no.?header)/i, @ARGV) <= 0);
    require $arg;
} else {
    sub usr_pre_file()  {}; # dummy stub, see o-saft-usr.pm
    sub usr_pre_args()  {}; #  "
    sub usr_pre_exec()  {}; #  "
    sub usr_pre_cipher(){}; #  "
    sub usr_pre_main()  {}; #  "
    sub usr_pre_host()  {}; #  "
    sub usr_pre_info()  {}; #  "
    sub usr_pre_open()  {}; #  "
    sub usr_pre_cmds()  {}; #  "
    sub usr_pre_data()  {}; #  "
    sub usr_pre_print() {}; #  "
    sub usr_pre_next()  {}; #  "
    sub usr_pre_exit()  {}; #  "
}


my @argv = grep(/--trace.?arg/, @ARGV);# preserve --tracearg option

usr_pre_file();

# read .rc-file if any
# -------------------------------------
my @rc_argv = "";
$arg = "./.$me";
open(RC, '<', "./.$me") && do {
    push(@dbxfile, $arg);
    _print_read("options", $arg) if ($cgi == 0);
    @rc_argv = grep(!/\s*#[^\r\n]*/, <RC>); # remove comment lines
    @rc_argv = grep(s/[\r\n]//, @rc_argv);  # remove newlines
    close(RC);
    push(@argv, @rc_argv);
    #dbx# _dbx ".RC: " . join(" ", @rc_argv) . "\n";
};

push(@argv, @ARGV);
#dbx# _dbx "ARG: " . join(" ", @argv);

# read file with source for trace and verbose, if any
# -------------------------------------
my @dbx = grep(/--(?:trace|v$|yeast)/, @argv);  # option can be in .rc-file, hence @argv
if (($#dbx >= 0) and ($cgi == 0)) {
    $arg =  "./o-saft-dbx.pm";
    $arg =  $dbx[0] if ($dbx[0] =~ m#/#);
    $arg =~ s#[^=]+=##; # --trace=./myfile.pl
    if (! -e $arg) {
        warn "**WARNING: '$arg' not found";
        $arg = join("/", $mepath, $arg);    # try to find it in installation directory
        die  "**ERROR: '$!' '$arg'; exit" unless (-e $arg);
        # no need to continue if required file does not exist
        # Note: if $mepath or $0 is a symbolic link, above checks fail
        #       we don't fix that! Workaround: install file in ./
    }
    push(@dbxfile, $arg);
    _print_read("trace file", $arg) if(grep(/(:?--no.?header)/i, @argv) <= 0);
        # allow --no-header in RC-FILE also
    require $arg;   # `our' variables are available there
}

# initialize defaults
#!# set defaults
#!# -------------------------------------
#!# To make (programmer's) life simple, we try to avoid complex data structure,
#!# which are error-prone, by using a couple of global variables.
#!# As there are no plans to run this tool in threaded mode, this should be ok.
#!# Please see "Program Code" in the POD section too.
#!#
#!# Here's an overview of the used global variables:
#!#   @results        - where we store the results as:  'cipher' => "yes|no"
#!#   %data           - labels and correspondig value (from Net::SSLinfo)
#!#   %checks         - collected and checked certificate data
#!#                     collected and checked target (connection) data
#!#                     collected and checked connection data
#!#                     collected and checked length and count data
#!#                     HTTP vs HTTPS checks
#!#   %shorttexts     - same as %checks, but short texts
#!#   %cmd            - configuration for external commands
#!#   %cfg            - configuration for commands and options
#!#   %text           - configuration for message texts
#!#   %scores         - scoring values
#!#   %ciphers_desc   - description of %ciphers data structure
#!#   %ciphers        - our ciphers
#!#   %cipher_names   - (hash)map of cipher constant-names to names
#!#
#!# All %check_*  contain a default 'score' value of 10, see --cfg_score
#!# option how to change that.

# Note: all keys in data and check_* must be unique 'cause of shorttexts!!

#
# Note according perlish programming style:
#     references to $arr->{'val') are most often simplified as $arr->{val)
#     same applies to 'txt', 'typ' and 'score'

my ($key,$sec,$ssl);# some temporary variables used in main
my $host    = "";   # the host currently processed in main
my $port    = "";   # the port currently used in main
my $legacy  = "";   # the legacy mode used in main
my $verbose = 0;    # verbose mode used in main
   # above host, port, legacy and verbose are just shortcuts for corresponding
   # values in $cfg{}, used for better human readability
my $info    = 0;    # set to 1 if +info  or +sni_check was used
my $check   = 0;    # set to 1 if +check was used
my $quick   = 0;    # set to 1 if +quick was used
my @results = ();   # list of checked ciphers: [SSL-Version, ciper suite name, yes|no]
our %data   = (     # values from Net::SSLinfo, will be processed in print_data()
    #!#----------------+-----------------------------------------------------------+-----------------------------------
    #!# +command                 value from Net::SSLinfo::*()                                label to be printed
    #!#----------------+-----------------------------------------------------------+-----------------------------------
    'cn_nosni'      => {'val' => "",                                                'txt' => "Certificate CN without SNI"},
    'pem'           => {'val' => sub { Net::SSLinfo::pem(           $_[0], $_[1])}, 'txt' => "Certificate PEM"},
    'text'          => {'val' => sub { Net::SSLinfo::text(          $_[0], $_[1])}, 'txt' => "Certificate PEM decoded"},
    'cn'            => {'val' => sub { Net::SSLinfo::cn(            $_[0], $_[1])}, 'txt' => "Certificate Common Name"},
    'subject'       => {'val' => sub { Net::SSLinfo::subject(       $_[0], $_[1])}, 'txt' => "Certificate Subject"},
    'issuer'        => {'val' => sub { Net::SSLinfo::issuer(        $_[0], $_[1])}, 'txt' => "Certificate Issuer"},
    'altname'       => {'val' => sub { Net::SSLinfo::altname(       $_[0], $_[1])}, 'txt' => "Certificate Subject's Alternate Names"},
    'default'       => {'val' => sub { Net::SSLinfo::default(       $_[0], $_[1])}, 'txt' => "Default Cipher"},
    'ciphers_openssl'=>{'val' => sub { $_[0] },                                     'txt' => "OpenSSL Ciphers"},
    'ciphers'       => {'val' => sub { join(" ",  Net::SSLinfo::ciphers($_[0], $_[1]))}, 'txt' => "Client Ciphers"},
    'dates'         => {'val' => sub { join(" .. ", Net::SSLinfo::dates($_[0], $_[1]))}, 'txt' => "Certificate Validity (date)"},
    'before'        => {'val' => sub { Net::SSLinfo::before(        $_[0], $_[1])}, 'txt' => "Certificate valid since"},
    'after'         => {'val' => sub { Net::SSLinfo::after(         $_[0], $_[1])}, 'txt' => "Certificate valid until"},
    'aux'           => {'val' => sub { Net::SSLinfo::aux(           $_[0], $_[1])}, 'txt' => "Certificate Trust Information"},
    'email'         => {'val' => sub { Net::SSLinfo::email(         $_[0], $_[1])}, 'txt' => "Certificate Email Addresses"},
    'pubkey'        => {'val' => sub { Net::SSLinfo::pubkey(        $_[0], $_[1])}, 'txt' => "Certificate Public Key"},
    'pubkey_algorithm'=>{'val'=> sub { Net::SSLinfo::pubkey_algorithm($_[0],$_[1])},'txt' => "Certificate Public Key Algorithm"},
    'pubkey_value'  => {'val' => sub {    __SSLinfo('pubkey_value', $_[0], $_[1])}, 'txt' => "Certificate Public Key Value"},
    'modulus_len'   => {'val' => sub { Net::SSLinfo::modulus_len(   $_[0], $_[1])}, 'txt' => "Certificate Public Key Length"},
    'modulus'       => {'val' => sub { Net::SSLinfo::modulus(       $_[0], $_[1])}, 'txt' => "Certificate Public Key Modulus"},
    'modulus_exponent'=>{'val'=> sub { Net::SSLinfo::modulus_exponent($_[0],$_[1])},'txt' => "Certificate Public Key Exponent"},
    'serial'        => {'val' => sub { Net::SSLinfo::serial(        $_[0], $_[1])}, 'txt' => "Certificate Serial Number"},
    'certversion'   => {'val' => sub { Net::SSLinfo::version(       $_[0], $_[1])}, 'txt' => "Certificate Version"},
    'sigdump'       => {'val' => sub { Net::SSLinfo::sigdump(       $_[0], $_[1])}, 'txt' => "Certificate Signature (hexdump)"},
    'sigkey_len'    => {'val' => sub { Net::SSLinfo::sigkey_len(    $_[0], $_[1])}, 'txt' => "Certificate Signature Key Length"},
    'signame'       => {'val' => sub { Net::SSLinfo::signame(       $_[0], $_[1])}, 'txt' => "Certificate Signature Algorithm"},
    'sigkey_value'  => {'val' => sub {    __SSLinfo('sigkey_value', $_[0], $_[1])}, 'txt' => "Certificate Signature Key Value"},
    'trustout'      => {'val' => sub { Net::SSLinfo::trustout(      $_[0], $_[1])}, 'txt' => "Certificate trusted"},
    'extensions'    => {'val' => sub { __SSLinfo('extensions',      $_[0], $_[1])}, 'txt' => "Certificate extensions"},
    'ext_authority' => {'val' => sub { __SSLinfo('ext_authority',   $_[0], $_[1])}, 'txt' => "Certificate extensions Authority Information Access"},
    'ext_authorityid'=>{'val' => sub { __SSLinfo('ext_authorityid', $_[0], $_[1])}, 'txt' => "Certificate extensions Authority key Identifier"},
    'ext_constrains'=> {'val' => sub { __SSLinfo('ext_constrains',  $_[0], $_[1])}, 'txt' => "Certificate extensions Basic Constraints"},
    'ext_cps'       => {'val' => sub { __SSLinfo('ext_cps',         $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies"},
    'ext_cps_policy'=> {'val' => sub { __SSLinfo('ext_cps_policy',  $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: Policy"},
    'ext_subjectkeyid'=>{'val'=> sub { __SSLinfo('ext_subjectkeyid',$_[0], $_[1])}, 'txt' => "Certificate extensions Subject Key Identifier"},
    'ext_cps_cps'   => {'val' => sub { __SSLinfo('ext_cps_cps',     $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: CPS"},
    'ext_crl'       => {'val' => sub { __SSLinfo('ext_crl',         $_[0], $_[1])}, 'txt' => "Certificate extensions CRL Distribution Points"},
    'ext_crl_crl'   => {'val' => sub { __SSLinfo('ext_crl_crL',     $_[0], $_[1])}, 'txt' => "Certificate extensions CRL Distribution Points: Full Name"},
    'ext_keyusage'  => {'val' => sub { __SSLinfo('ext_keyusage',    $_[0], $_[1])}, 'txt' => "Certificate extensions Key Usage"},
    'ext_extkeyusage'=>{'val' => sub { __SSLinfo('ext_extkeyusage', $_[0], $_[1])}, 'txt' => "Certificate extensions Extended Key Usage"},
    'ext_certtype'  => {'val' => sub { __SSLinfo('ext_certtype',    $_[0], $_[1])}, 'txt' => "Certificate extensions Netscape Cert Type"},
    'ext_issuer'    => {'val' => sub { __SSLinfo('ext_issuer',      $_[0], $_[1])}, 'txt' => "Certificate extensions Issuer Alternative Name"},
    'ocsp_uri'      => {'val' => sub { Net::SSLinfo::ocsp_uri(      $_[0], $_[1])}, 'txt' => "Certificate OCSP Responder URL"},
    'ocspid'        => {'val' => sub { Net::SSLinfo::ocspid(        $_[0], $_[1])}, 'txt' => "Certificate OCSP subject, public key hash"},
    'subject_hash'  => {'val' => sub { Net::SSLinfo::subject_hash(  $_[0], $_[1])}, 'txt' => "Certificate Subject Name hash"},
    'issuer_hash'   => {'val' => sub { Net::SSLinfo::issuer_hash(   $_[0], $_[1])}, 'txt' => "Certificate Issuer Name hash"},
    'selfsigned'    => {'val' => sub { Net::SSLinfo::selfsigned(    $_[0], $_[1])}, 'txt' => "Certificate Validity (signature)"},
    'fingerprint_type'=>{'val'=> sub { Net::SSLinfo::fingerprint_type($_[0],$_[1])},'txt' => "Certificate Fingerprint Algorithm"},
    'fingerprint_hash'=>{'val'=> sub { __SSLinfo('fingerprint_hash',$_[0], $_[1])}, 'txt' => "Certificate Fingerprint Hash Value"},
    'fingerprint_sha1'=>{'val'=> sub { __SSLinfo('fingerprint_sha1',$_[0], $_[1])}, 'txt' => "Certificate Fingerprint SHA1"},
    'fingerprint_md5' =>{'val'=> sub { __SSLinfo('fingerprint_md5', $_[0], $_[1])}, 'txt' => "Certificate Fingerprint  MD5"},
    'fingerprint'   => {'val' => sub { __SSLinfo('fingerprint',     $_[0], $_[1])}, 'txt' => "Certificate Fingerprint"},
    'cert_type'     => {'val' => sub { Net::SSLinfo::cert_type(     $_[0], $_[1])}, 'txt' => "Certificate Type (bitmask)"},
    'sslversion'    => {'val' => sub { Net::SSLinfo::SSLversion(    $_[0], $_[1])}, 'txt' => "Selected SSL Protocol"},
    'resumption'    => {'val' => sub { Net::SSLinfo::resumption(    $_[0], $_[1])}, 'txt' => "Target supports resumption"},
    'renegotiation' => {'val' => sub { Net::SSLinfo::renegotiation( $_[0], $_[1])}, 'txt' => "Target supports renegotiation"},
    'compression'   => {'val' => sub { Net::SSLinfo::compression(   $_[0], $_[1])}, 'txt' => "Target supports compression"},
    'expansion'     => {'val' => sub { Net::SSLinfo::expansion(     $_[0], $_[1])}, 'txt' => "Target supports expansion"},
    'krb5'          => {'val' => sub { Net::SSLinfo::krb5(          $_[0], $_[1])}, 'txt' => "Target supports Krb5"},
    'psk_hint'      => {'val' => sub { Net::SSLinfo::psk_hint(      $_[0], $_[1])}, 'txt' => "Target supports PSK identity hint"},
    'psk_identity'  => {'val' => sub { Net::SSLinfo::psk_identity(  $_[0], $_[1])}, 'txt' => "Target supports PSK"},
    'srp'           => {'val' => sub { Net::SSLinfo::srp(           $_[0], $_[1])}, 'txt' => "Target supports SRP"},
    'protocols'     => {'val' => sub { Net::SSLinfo::protocols(     $_[0], $_[1])}, 'txt' => "Target supported protocols"},
    'master_key'    => {'val' => sub { Net::SSLinfo::master_key(    $_[0], $_[1])}, 'txt' => "Target's Master-Key"},
    'session_id'    => {'val' => sub { Net::SSLinfo::session_id(    $_[0], $_[1])}, 'txt' => "Target's Session-ID"},
    'session_ticket'=> {'val' => sub { Net::SSLinfo::session_ticket($_[0], $_[1])}, 'txt' => "Target's TLS Session Ticket"},
    'chain'         => {'val' => sub { Net::SSLinfo::chain(         $_[0], $_[1])}, 'txt' => "Certificate Chain"},
    'chain_verify'  => {'val' => sub { Net::SSLinfo::chain_verify(  $_[0], $_[1])}, 'txt' => "CA Chain Verification (trace)"},
    'verify'        => {'val' => sub { Net::SSLinfo::verify(        $_[0], $_[1])}, 'txt' => "Validity Certificate Chain"},
    'error_verify'  => {'val' => sub { Net::SSLinfo::error_verify(  $_[0], $_[1])}, 'txt' => "CA Chain Verification error"},
    'error_depth'   => {'val' => sub { Net::SSLinfo::error_depth(   $_[0], $_[1])}, 'txt' => "CA Chain Verification error in level"},
    'verify_altname'=> {'val' => sub { Net::SSLinfo::verify_altname($_[0], $_[1])}, 'txt' => "Validity Alternate Names"},
    'verify_hostname'=>{'val' => sub { Net::SSLinfo::verify_hostname( $_[0],$_[1])},'txt' => "Validity Hostname"},
    'https_status'  => {'val' => sub { Net::SSLinfo::https_status(  $_[0], $_[1])}, 'txt' => "HTTPS Status line"},
    'https_server'  => {'val' => sub { Net::SSLinfo::https_server(  $_[0], $_[1])}, 'txt' => "HTTPS Server banner"},
    'https_location'=> {'val' => sub { Net::SSLinfo::https_location($_[0], $_[1])}, 'txt' => "HTTPS Location header"},
    'https_refresh' => {'val' => sub { Net::SSLinfo::https_refresh( $_[0], $_[1])}, 'txt' => "HTTPS Refresh header"},
    'https_alerts'  => {'val' => sub { Net::SSLinfo::https_alerts(  $_[0], $_[1])}, 'txt' => "HTTPS Error alerts"},
    'https_pins'    => {'val' => sub { Net::SSLinfo::https_pins(    $_[0], $_[1])}, 'txt' => "HTTPS Public Key Pins"},
    'https_sts'     => {'val' => sub { Net::SSLinfo::https_sts(     $_[0], $_[1])}, 'txt' => "HTTPS STS header"},
    'hsts_maxage'   => {'val' => sub { Net::SSLinfo::hsts_maxage(   $_[0], $_[1])}, 'txt' => "HTTPS STS MaxAge"},
    'hsts_subdom'   => {'val' => sub { Net::SSLinfo::hsts_subdom(   $_[0], $_[1])}, 'txt' => "HTTPS STS include sub-domains"},
    'http_status'   => {'val' => sub { Net::SSLinfo::http_status(   $_[0], $_[1])}, 'txt' => "HTTP Status line"},
    'http_location' => {'val' => sub { Net::SSLinfo::http_location( $_[0], $_[1])}, 'txt' => "HTTP Location header"},
    'http_refresh'  => {'val' => sub { Net::SSLinfo::http_refresh(  $_[0], $_[1])}, 'txt' => "HTTP Refresh header"},
    'http_sts'      => {'val' => sub { Net::SSLinfo::http_sts(      $_[0], $_[1])}, 'txt' => "HTTP STS header"},
    #------------------+---------------------------------------+-------------------------------------------------------
    'options'       => {'val' => sub { Net::SSLinfo::options(       $_[0], $_[1])}, 'txt' => "<<internal>> used SSL options bitmask"},
    # following are used for checkdates() only, they must not be a command!
    # they are not printed with +info or +check; values are integer
    'valid-years'   => {'val' =>  0, 'txt' => "certificate validity in years"},
    'valid-months'  => {'val' =>  0, 'txt' => "certificate validity in months"},
    'valid-days'    => {'val' =>  0, 'txt' => "certificate validity in days"},   # approx. value, accurate if < 30
); # %data
# need s_client for: compression|expansion|selfsigned|chain|verify|resumption|renegotiation|protocols|
# need s_client for: krb5|psk_hint|psk_identity|srp|master_key|session_id|session_ticket|

our %checks = (
    # key           =>  {val => "", txt => "label to be printed", score => 0, typ => "connection"},
    #
    # default for 'val' is "" (empty string), default for 'score' is 0
    # 'typ' is any of certificate, connection, destination, https, sizes
    # both will be set in sub _init_all(), please see below

    # the default value means "check = ok/yes", otherwise: "check =failed/no"

); # %checks

my %check_cert = (
    # collected and checked certificate data
    #------------------+-----------------------------------------------------
    # key               label to be printed (description)
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
    'ocsp'          => {'txt' => "Certificate has OCSP Responder URL"},
    'cps'           => {'txt' => "Certificate has Certification Practice Statement"},
    'crl'           => {'txt' => "Certificate has CRL Distribution Points"},
    'zlib'          => {'txt' => "Certificate has (TLS extension) compression"},
    'lzo'           => {'txt' => "Certificate has (GnuTLS extension) compression"},
    'open_pgp'      => {'txt' => "Certificate has (TLS extension) authentication"},
    'sernumber'     => {'txt' => "Certificate Serial Number size RFC5280"},
    # following checks in subjectAltName, CRL, OCSP, CN, O, U
    'nonprint'      => {'txt' => "Certificate contains non-printable characters"},
    'crnlnull'      => {'txt' => "Certificate contains CR, NL, NULL characters"},
    'ev-chars'      => {'txt' => "Certificate has no invalid characters in extensions"},
# ToDo: SRP is a target feature but also named a `Certificate (TLS extension)'
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
    # ToDo: wee need an option to specify the the local certificate storage!
); # %check_cert

my %check_conn = (
    # collected and checked connection data
    #------------------+-----------------------------------------------------
    'ip'            => {'txt' => "IP for given hostname "},
    'reversehost'   => {'txt' => "Given hostname is same as reverse resolved hostname"},
    'hostname'      => {'txt' => "Connected hostname matches certificate's subject"},
    'beast-default' => {'txt' => "Connection is safe against BEAST attack (default cipher)"},
    'beast'         => {'txt' => "Connection is safe against BEAST attack (any cipher)"},
    'breach'        => {'txt' => "Connection is safe against BREACH attack"},
    'crime'         => {'txt' => "Connection is safe against CRIME attack"},
    'time'          => {'txt' => "Connection is safe against TIME attack"},
    'sni'           => {'txt' => "Connection is not based on SNI"},
    'default'       => {'txt' => "Default cipher for "},   # used for @cfg{version} only
     # counter for accepted ciphers, 0 if not supported
    'SSLv2'         => {'txt' => "Supported ciphers for SSLv2 (total)"},
    'SSLv3'         => {'txt' => "Supported ciphers for SSLv3 (total)"},
    'TLSv1'         => {'txt' => "Supported ciphers for TLSv1 (total)"},
    'TLSv11'        => {'txt' => "Supported ciphers for TLSv11 (total)"},
    'TLSv12'        => {'txt' => "Supported ciphers for TLSv12 (total)"},
    'DTLSv1'        => {'txt' => "Supported ciphers for DTLSv1 (total)"},
    # counter for this type of cipher
    'SSLv2-LOW'     => {'txt' => "Supported   LOW   security ciphers"},
    'SSLv2-WEAK'    => {'txt' => "Supported  WEAK   security ciphers"},
    'SSLv2-HIGH'    => {'txt' => "Supported  HIGH   security ciphers"},
    'SSLv2-MEDIUM'  => {'txt' => "Supported MEDIUM  security ciphers"},
    'SSLv2--?-'     => {'txt' => "Supported unknown security ciphers"},
    'SSLv3-LOW'     => {'txt' => "Supported   LOW   security ciphers"},
    'SSLv3-WEAK'    => {'txt' => "Supported  WEAK   security ciphers"},
    'SSLv3-HIGH'    => {'txt' => "Supported  HIGH   security ciphers"},
    'SSLv3-MEDIUM'  => {'txt' => "Supported MEDIUM  security ciphers"},
    'SSLv3--?-'     => {'txt' => "Supported unknown security ciphers"},
    'TLSv1-LOW'     => {'txt' => "Supported   LOW   security ciphers"},
    'TLSv1-WEAK'    => {'txt' => "Supported  WEAK   security ciphers"},
    'TLSv1-HIGH'    => {'txt' => "Supported  HIGH   security ciphers"},
    'TLSv1-MEDIUM'  => {'txt' => "Supported MEDIUM  security ciphers"},
    'TLSv1--?-'     => {'txt' => "Supported unknown security ciphers"},
    'TLSv11-LOW'    => {'txt' => "Supported   LOW   security ciphers"},
    'TLSv11-WEAK'   => {'txt' => "Supported  WEAK   security ciphers"},
    'TLSv11-HIGH'   => {'txt' => "Supported  HIGH   security ciphers"},
    'TLSv11-MEDIUM' => {'txt' => "Supported MEDIUM  security ciphers"},
    'TLSv11--?-'    => {'txt' => "Supported unknown security ciphers"},
    'TLSv12-LOW'    => {'txt' => "Supported   LOW   security ciphers"},
    'TLSv12-WEAK'   => {'txt' => "Supported  WEAK   security ciphers"},
    'TLSv12-HIGH'   => {'txt' => "Supported  HIGH   security ciphers"},
    'TLSv12-MEDIUM' => {'txt' => "Supported MEDIUM  security ciphers"},
    'TLSv12--?-'    => {'txt' => "Supported unknown security ciphers"},
    'DTLSv1-LOW'    => {'txt' => "Supported   LOW   security ciphers"},
    'DTLSv1-WEAK'   => {'txt' => "Supported  WEAK   security ciphers"},
    'DTLSv1-HIGH'   => {'txt' => "Supported  HIGH   security ciphers"},
    'DTLSv1-MEDIUM' => {'txt' => "Supported MEDIUM  security ciphers"},
    'DTLSv1--?-'    => {'txt' => "Supported unknown security ciphers"},
    #------------------+-----------------------------------------------------
); # %check_conn

my %check_dest = (
    # collected and checked target (connection) data
    #------------------+-----------------------------------------------------
    'sgc'           => {'txt' => "Target supports Server Gated Cryptography (SGC)"},
    'hasSSLv2'      => {'txt' => "Target supports only safe protocols (no SSL 2.0)"},
    'edh'           => {'txt' => "Target supports EDH ciphers"},
    'adh'           => {'txt' => "Target does not accepts ADH ciphers"},
    'null'          => {'txt' => "Target does not accepts NULL ciphers"},
    'export'        => {'txt' => "Target does not accepts EXPORT ciphers"},
    'rc4'           => {'txt' => "Target does not accepts RC4 ciphers"},
    'closure'       => {'txt' => "Target understands TLS closure alerts"},
    'fallback'      => {'txt' => "Target supports fallback from TLSv1.1"},
    'order'         => {'txt' => "Target honors client's cipher order"},
    'ism'           => {'txt' => "Target supports ISM compliant ciphers"},
    'pci'           => {'txt' => "Target supports PCI compliant ciphers"},
    'fips'          => {'txt' => "Target supports FIPS-140 compliant ciphers"},
    'tr-02102'      => {'txt' => "Target supports TR-02102-2 compliant ciphers"},
    'bsi-tr-02102+' => {'txt' => "Target is strict BSI TR-02102-2 compliant"},
    'bsi-tr-02102-' => {'txt' => "Target is  lazy  BSI TR-02102-2 compliant"},
    'resumption'    => {'txt' => "Target supports resumption"},
    'renegotiation' => {'txt' => "Target supports renegotiation"},
    'pfs'           => {'txt' => "Target supports forward secrecy (PFS)"},
    'krb5'          => {'txt' => "Target supports Krb5"},
    'psk_hint'      => {'txt' => "Target supports PSK identity hint"},
    'psk_identity'  => {'txt' => "Target supports PSK"},
    'srp'           => {'txt' => "Target supports SRP"},
    'session_ticket'=> {'txt' => "Target supports TLS Session Ticket"}, # sometimes missing ...
    # following for information, checks not useful; see "# check target specials" in checkdest also
#    'master_key'    => {'txt' => "Target supports Master-Key"},
#    'session_id'    => {'txt' => "Target supports Session-ID"},
    #------------------+-----------------------------------------------------
); # %check_dest

my %check_size = (
    # collected and checked length and count data
    # counts and sizes are integer values, key mast have prefix (len|cnt)_
    #------------------+-----------------------------------------------------
    'len_pembase64' => {'txt' => "Certificate PEM (base64) size"},  # <(2048/8*6)
    'len_pembinary' => {'txt' => "Certificate PEM (binary) size"},  # < 2048
    'len_subject'   => {'txt' => "Certificate Subject size"},       # <  256
    'len_issuer'    => {'txt' => "Certificate Issuer size"},        # <  256
    'len_CPS'       => {'txt' => "Certificate CPS size"},           # <  256
    'len_CRL'       => {'txt' => "Certificate CRL size"},           # <  256
    'len_CRL_data'  => {'txt' => "Certificate CRL data size"},
    'len_OCSP'      => {'txt' => "Certificate OCSP size"},          # <  256
    'len_OIDs'      => {'txt' => "Certificate OIDs size"},
    'len_publickey' => {'txt' => "Certificate Public Key size"},    # > 1024
    'len_sigdump'   => {'txt' => "Certificate Signature Key size"} ,# > 1024
    'len_altname'   => {'txt' => "Certificate Subject Altname size"},
    'len_chain'     => {'txt' => "Certificate Chain size"},         # < 2048
    'len_sernumber' => {'txt' => "Certificate Serial Number size"}, # <=  20 octets
    'cnt_altname'   => {'txt' => "Certificate Subject Altname count"}, # == 0
    'cnt_wildcard'  => {'txt' => "Certificate Wildcards count"},    # == 0
    'cnt_chaindepth'=> {'txt' => "Certificate Chain Depth count"},  # == 1
    'cnt_ciphers'   => {'txt' => "Number of offered ciphers"},      # <> 0
    'cnt_totals'    => {'txt' => "Total number of checked ciphers"},
    #------------------+-----------------------------------------------------
# ToDo: cnt_ciphers, len_chain, cnt_chaindepth
); # %check_size

my %check_http = (
    # HTTP vs HTTPS checks
    # score are absolute values here, they are set to 100 if attribute is found
    # key must have prefix (hsts|sts); see $cfg{'regex'}->{'cmd-http'}
    #------------------+-----------------------------------------------------
    'sts_maxage0d'  => {'txt' => "STS max-age not set"},             # very weak
    'sts_maxage1d'  => {'txt' => "STS max-age less than one day"},   # weak
    'sts_maxage1m'  => {'txt' => "STS max-age less than one month"}, # low
    'sts_maxage1y'  => {'txt' => "STS max-age less than one year"},  # medium
    'sts_maxagexy'  => {'txt' => "STS max-age more than one year"},  # high
    'hsts_sts'      => {'txt' => "Target sends STS header"},
    'sts_maxage'    => {'txt' => "Target sends STS header with proper max-age"},
    'sts_subdom'    => {'txt' => "Target sends STS header with includeSubdomain"},
    'hsts_is301'    => {'txt' => "Target redirects with status code 301"}, # RFC6797 requirement
    'hsts_is30x'    => {'txt' => "Target redirects not with 30x status code"}, # other than 301, 304
    'hsts_fqdn'     => {'txt' => "Target redirect matches given host"},
    'http_https'    => {'txt' => "Target redirects HTTP to HTTPS"},
    'hsts_location' => {'txt' => "Target sends STS and no Location header"},
    'hsts_refresh'  => {'txt' => "Target sends STS and no Refresh header"},
    'hsts_redirect' => {'txt' => "Target redirects HTTP without STS header"},
    'pkp_pins'      => {'txt' => "Target sends Public Key Pins header"},
    #------------------+-----------------------------------------------------
); # %check_http

# now construct %checks from %check_* and set 'typ'
foreach $key (keys %check_conn) { $checks{$key}->{txt} = $check_conn{$key}->{txt}; $checks{$key}->{typ} = 'connection'; }
foreach $key (keys %check_cert) { $checks{$key}->{txt} = $check_cert{$key}->{txt}; $checks{$key}->{typ} = 'certificate'; }
foreach $key (keys %check_dest) { $checks{$key}->{txt} = $check_dest{$key}->{txt}; $checks{$key}->{typ} = 'destination'; }
foreach $key (keys %check_size) { $checks{$key}->{txt} = $check_size{$key}->{txt}; $checks{$key}->{typ} = 'sizes'; }
foreach $key (keys %check_http) { $checks{$key}->{txt} = $check_http{$key}->{txt}; $checks{$key}->{typ} = 'https'; }

our %data_oid = ( # ToDo: nothing YET IMPLEMENTED except for EV
        # ToDo: generate this table using Net::SSLeay functions like:
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
    '1.3.6.1.5.5.7.1.1'         => {'txt' => "Authority Information Access"}, # authorityInfoAccess
    '1.3.6.1.5.5.7.1.12'        => {'txt' => "<<undef>>"},
    '1.3.6.1.5.5.7.1.14'        => {'txt' => "Proxy Certification Information"},
    '1.3.6.1.5.5.7.3.1'         => {'txt' => "Server Authentication"},
    '1.3.6.1.5.5.7.3.2'         => {'txt' => "Client Authentication"},
    '1.3.6.1.5.5.7.3.3'         => {'txt' => "Code Signing"},
    '1.3.6.1.5.5.7.3.4'         => {'txt' => "Email Protection"},
    '1.3.6.1.5.5.7.3.5'         => {'txt' => "IPSec end system"},
    '1.3.6.1.5.5.7.3.6'         => {'txt' => "IPSec tunnel"},
    '1.3.6.1.5.5.7.3.7'         => {'txt' => "IPSec user"},
    '1.3.6.1.5.5.7.3.8'         => {'txt' => "Timestamping"},
    '1.3.6.1.4.1.11129.2.5.1'   => {'txt' => "<<undef>>"}, # Certificate Policy?
    '1.3.6.1.4.1.14370.1.6'     => {'txt' => "<<undef>>"}, # Certificate Policy?
    '1.3.6.1.4.1.311.10.3.3'    => {'txt' => "Microsoft Server Gated Crypto"},
    '1.3.6.1.4.1.311.10.11'     => {'txt' => "Microsoft Server: EV additional Attributes"},
    '1.3.6.1.4.1.311.10.11.11'  => {'txt' => "Microsoft Server: EV ??friendly name??"},
    '1.3.6.1.4.1.311.10.11.83'  => {'txt' => "Microsoft Server: EV ??root program??"},
    '1.3.6.1.4.1.4146.1.10'     => {'txt' => "<<undef>>"}, # Certificate Policy?
    '2.16.840.1.113730.4.1'     => {'txt' => "Netscape SGC"},
    '1.2.840.113549.1.1.1'      => {'txt' => "SubjectPublicKeyInfo"}, # ???
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
    '2.16.840.1.113733.1.7.23.6'=> {'txt' => "<<undef>>"}, # Certificate Policy?
    '2.16.840.1.113733.1.7.48.1'=> {'txt' => "<<undef>>"}, # Certificate Policy?
    '2.16.840.1.113733.1.7.54'  => {'txt' => "<<undef>>"}, # Certificate Policy?
    '0.9.2342.19200300.100.1.3' => {'txt' => "subject:mail"},
); # %data_oid
$data_oid{$_}->{val} = "<<check error>>" foreach (keys %data_oid);

our %shorttexts = (
    #------------------+------------------------------------------------------
    # %check +check     short label text
    #------------------+------------------------------------------------------
    # Note: key must be same string as used in %ciphers[ssl] {
    'SSLv2'         => "Ciphers (SSLv2)",
    'SSLv3'         => "Ciphers (SSLv3)",
    'TLSv1'         => "Ciphers (TLSv1)",
    'TLSv11'        => "Ciphers (TLSv11)",
    'TLSv12'        => "Ciphers (TLSv12)",
    'DTLSv1'        => "Ciphers (DTLSv1)",
    #}
    'TLSv1-HIGH'    => "Ciphers HIGH",
    'ip'            => "IP for hostname",
    'DNS'           => "DNS for hostname",
    'reversehost'   => "Reverse hostname",
    'hostname'      => "Hostname matches Subject",
    'expired'       => "Not expired",
    'certfqdn'      => "Valid for hostname",
    'wildhost'      => "Wilcard for hostname",
    'wildcard'      => "No wildcards",
    'sni'           => "Not SNI based",
    'sernumber'     => "Serial Number size (RFC5280)",
    'rootcert'      => "Not root CA",
    'ocsp'          => "OCSP supported",
    'hasSSLv2'      => "No SSL 2.0",
    'adh'           => "No ADH ciphers",
    'edh'           => "EDH ciphers",
    'null'          => "No NULL ciphers",
    'export'        => "No EXPORT ciphers",
    'rc4'           => "No RC4 ciphers",
    'sgc'           => "SGC supported",
    'cps'           => "CPS supported",
    'crl'           => "CRL supported",
    'dv'            => "DV supported",
    'ev+'           => "Strict EV supported",
    'ev-'           => "Lazy EV supported",
    'ev-chars'      => "NO invalid characters in extensions",
    'beast-default' => "Default cipher safe to BEAST",
    'beast'         => "Supported cipher safe to BEAST",
    'breach'        => "Safe to BREACH",
    'crime'         => "Safe to CRIME",
    'time'          => "Safe to TIME",
    'closure'       => "TLS closure alerts",
    'fallback'      => "Fallback from TLSv1.1",
    'zlib'          => "ZLIB extension",
    'lzo'           => "GnuTLS extension",
    'open_pgp'      => "OpenPGP extension",
    'order'         => "Client's cipher order",
    'ism'           => "ISM compliant",
    'pci'           => "PCI compliant",
    'pfs'           => "PFS supported",
    'fips'          => "FIPS-140 compliant",
    'tr-02102'      => "TR-02102-2 compliant",
    'bsi-tr-02102+' => "Strict BSI TR-02102-2 compliant",
    'bsi-tr-02102-' => "Lazy BSI TR-02102-2 compliant",
    'resumption'    => "Resumption",
    'renegotiation' => "Renegotiation",
    'hsts_sts'      => "STS header",
    'sts_maxage'    => "STS long max-age",
    'sts_subdom'    => "STS includeSubdomain",
    'hsts_location' => "STS and Location header",
    'hsts_refresh'  => "STS and no Refresh header",
    'hsts_redirect' => "Redirects without STS",
    'http_https'    => "Redirects HTTP",
    'hsts_fqdn'     => "Redirects to same host",
    'hsts_is301'    => "Redirects with 301",
    'hsts_is30x'    => "Redirects not with 30x",
    'pkp_pins'      => "Public Key Pins",
    'selfsigned'    => "Validity (signature)",
    'chain'         => "Certificate chain",
    'chain_verify'  => "CA Chain trace",
    'verify'        => "Chain verified",
    'error_verify'  => "CA Chain error",
    'error_depth'   => "CA Chain error in level",
    'nonprint'      => "non-printables",
    'crnlnull'      => "CR, NL, NULL",
    'compression'   => "Compression",
    'expansion'     => "Expansion",
    'krb5'          => "Krb5 Principal",
    'psk_hint'      => "PSK identity hint",
    'psk_identity'  => "PSK identity",
    'srp'           => "SRP username",
    'protocols'     => "Protocols",
    'master_key'    => "Master-Key",
    'session_id'    => "Session-ID",
    'session_ticket'=> "TLS Session Ticket",
    'len_pembase64' => "Size PEM (base64)",
    'len_pembinary' => "Size PEM (binary)",
    'len_subject'   => "Size subject",
    'len_issuer'    => "Size issuer",
    'len_CPS'       => "Size CPS",
    'len_CRL'       => "Size CRL",
    'len_CRL_data'  => "Size CRL data",
    'len_OCSP'      => "Size OCSP",
    'len_OIDs'      => "Size OIDs",
    'len_altname'   => "Size altname",
    'len_publickey' => "Size pubkey",
    'len_sigdump'   => "Size signature key",
    'len_chain'     => "Size certificate chain",
    'cnt_altname'   => "Count altname",
    'cnt_wildcard'  => "Count wildcards",
    'cnt_chaindepth'=> "Count chain depth",
    'cnt_ciphers'   => "Count ciphers",
    'cnt_totals'    => "Checked ciphers",
    #------------------+------------------------------------------------------
    # %data +command    short label text
    #------------------+------------------------------------------------------
    'pem'           => "PEM",
    'text'          => "PEM decoded",
    'cn'            => "Common Name (CN)",
    'subject'       => "Subject",
    'issuer'        => "Issuer",
    'altname'       => "Subject AltNames",
    'ciphers'       => "Client Ciphers",
    'default'       => "Default Cipher",
    'ciphers_openssl'   => "OpenSSL Ciphers",
    'dates'         => "Validity (date)",
    'before'        => "Valid since",
    'after'         => "Valid until",
    'extensions'    => "Extensions",
    'aux'           => "Trust",
    'email'         => "Email",
    'pubkey'        => "Public Key",
    'pubkey_algorithm'  => "Public Key Algorithm",
    'pubkey_value'  => "Public Key Value",
    'modulus_len'   => "Public Key length",
    'modulus'       => "Public Key modulus",
    'modulus_exponent'  => "Public Key exponent",
    'serial'        => "Serial Number",
    'certversion'   => "Certificate Version",
    'sslversion'    => "SSL protocol",
    'signame'       => "Signature Algorithm",
    'sigdump'       => "Signature (hexdump)",
    'sigkey_len'    => "Signature key length",
    'sigkey_value'  => "Signature key value",
    'trustout'      => "Trusted",
    'ocsp_uri'      => "OCSP URL",
    'ocspid'        => "OCSP hash",
    'subject_hash'  => "Subject hash",
    'issuer_hash'   => "Issuer hash",
    'fp_not_md5'    => "Fingerprint not MD5",
    'verify_hostname'   => "Hostname valid",
    'verify_altname'    => "AltNames valid",
    'fingerprint_hash'  => "Fingerprint Hash",
    'fingerprint_type'  => "Fingerprint Algorithm",
    'fingerprint_sha1'  => "Fingerprint SHA1",
    'fingerprint_md5'   => "Fingerprint  MD5",
    'fingerprint'       => "Fingerprint:",
    'https_status'  => "HTTPS Status line",
    'https_server'  => "HTTPS Server banner",
    'https_alerts'  => "HTTPS Error alerts",
    'https_refresh' => "HTTPS Refresh header",
    'https_pins'    => "HTTPS Public Key Pins",
    'https_sts'     => "HTTPS STS header",
    'hsts_maxage'   => "HTTPS STS MaxAge",
    'hsts_subdom'   => "HTTPS STS sub-domains",
    'hsts_is301'    => "HTTP Status code is 301",
    'hsts_is30x'    => "HTTP Status code not 30x",
    'http_status'   => "HTTP Status line",
    'http_location' => "HTTP Location header",
    'http_refresh'  => "HTTP Refresh header",
    'http_sts'      => "HTTP STS header",
    #------------------+------------------------------------------------------
    # more texts dynamically, see "adding more shorttexts" below
); # %shorttexts
my %scores = (
    # keys starting with 'check_' are for total values
    # all other keys are for individual score values
    #------------------+-------------+----------------------------------------
    'check_conn'    => {'val' => 100, 'txt' => "SSL connection checks"},
    'check_ciph'    => {'val' => 100, 'txt' => "Ciphers checks"},
    'check_cert'    => {'val' => 100, 'txt' => "Certificate checks"},
    'check_dest'    => {'val' => 100, 'txt' => "Target checks"},
    'check_http'    => {'val' => 100, 'txt' => "HTTP(S) checks"},
    'check_size'    => {'val' => 100, 'txt' => "Certificate sizes checks"},
    'checks'        => {'val' => 100, 'txt' => "Total scoring"},
    #------------------+-------------+----------------------------------------
    # sorting according key name
); # %scores

my %score_ssllabs = (
    # SSL Server Rating Guide:
    #------------------+------------+---------------+-------------------------
    'check_prot'    => {'val' =>  0, 'score' => 0.3, 'txt' => "Protocol support"},        # 30%
    'check_keyx'    => {'val' =>  0, 'score' => 0.3, 'txt' => "Key exchange support"},    # 30%
    'check_ciph'    => {'val' =>  0, 'score' => 0.4, 'txt' => "Cipher strength support"}, # 40%
    # 'score' is a factor here; 'val' will be the score 0..100

    # Letter grade translation
    #                                           Grade  Numerical Score
    #------------------------------------------+------+---------------
    'A' => {'val' => 0, 'score' => 80, 'txt' => "A"}, # score >= 80
    'B' => {'val' => 0, 'score' => 65, 'txt' => "B"}, # score >= 65
    'C' => {'val' => 0, 'score' => 50, 'txt' => "C"}, # score >= 50
    'D' => {'val' => 0, 'score' => 35, 'txt' => "D"}, # score >= 35
    'E' => {'val' => 0, 'score' => 20, 'txt' => "E"}, # score >= 20
    'F' => {'val' => 0, 'score' => 20, 'txt' => "F"}, # score >= 20
     # 'val' is not used above!

    # Protocol support rating guide
    # Protocol                                  Score          Protocol
    #------------------------------------------+-----+------------------
    'SSLv2'         => {'val' =>  0, 'score' =>  20, 'txt' => "SSL 2.0"}, #  20%
    'SSLv2'         => {'val' =>  0, 'score' =>  80, 'txt' => "SSL 3.0"}, #  80%
    'TLSv1'         => {'val' =>  0, 'score' =>  90, 'txt' => "TLS 1.0"}, #  90%
    'TLSv11'        => {'val' =>  0, 'score' =>  95, 'txt' => "TLS 1.1"}, #  95%
    'TLSv12'        => {'val' =>  0, 'score' => 100, 'txt' => "TLS 1.2"}, # 100%
    'DTLSv1'        => {'val' =>  0, 'score' => 100, 'txt' => "DTLS 1.0"},# 100%
    # 'txt' is not used here!
    #
    #    ( best protocol + worst protocol ) / 2

    # Key exchange rating guide
    #                                           Score          Key exchange aspect                              # Score
    #------------------------------------------+-----+----------------------------------------------------------+------
    'key_debian'    => {'val' =>  0, 'score' =>   0, 'txt' => "Weak key (Debian OpenSSL flaw)"},                #   0%
    'key_anonx'     => {'val' =>  0, 'score' =>   0, 'txt' => "Anonymous key exchange (no authentication)"},    #   0%
    'key_512'       => {'val' =>  0, 'score' =>  20, 'txt' => "Key length < 512 bits"},                         #  20%
    'key_export'    => {'val' =>  0, 'score' =>  40, 'txt' => "Exportable key exchange (limited to 512 bits)"}, #  40%
    'key_1024'      => {'val' =>  0, 'score' =>  40, 'txt' => "Key length < 1024 bits (e.g., 512)"},            #  40%
    'key_2048'      => {'val' =>  0, 'score' =>  80, 'txt' => "Key length < 2048 bits (e.g., 1024)"},           #  80%
    'key_4096'      => {'val' =>  0, 'score' =>  90, 'txt' => "Key length < 4096 bits (e.g., 2048)"},           #  90%
    'key_good'      => {'val' =>  0, 'score' => 100, 'txt' => "Key length >= 4096 bits (e.g., 4096)"},          # 100%
    #
    #
    # Cipher strength rating guide
    #                                           Score          Cipher strength                # Score
    #------------------------------------------+-----+----------------------------------------+------
    'ciph_0'        => {'val' =>  0, 'score' =>   0, 'txt' => "0 bits (no encryption)"},      #   0%
    'ciph_128'      => {'val' =>  0, 'score' =>   0, 'txt' => "< 128 bits (e.g., 40, 56)"},   #  20%
    'ciph_256'      => {'val' =>  0, 'score' =>   0, 'txt' => "< 256 bits (e.g., 128, 168)"}, #  80%
    'ciph_512'      => {'val' =>  0, 'score' =>   0, 'txt' => ">= 256 bits (e.g., 256)"},     # 100%
    #
    #    ( strongest cipher + weakest cipher ) / 2
    #
); # %score_ssllabs

my %info_gnutls = ( # NOT YET USED
   # extracted from http://www.gnutls.org/manual/gnutls.html
   #     security   parameter   ECC key
   #       bits       size       size    security    description
   #     ----------+-----------+--------+-----------+------------------
   'I' => "<72      <1008      <160      INSECURE    Considered to be insecure",
   'W' => "72        1008       160      WEAK        Short term protection against small organizations",
   'L' => "80        1248       160      LOW         Very short term protection against agencies",
   'l' => "96        1776       192      LEGACY      Legacy standard level",
   'M' => "112       2432       224      NORMAL      Medium-term protection",
   'H' => "128       3248       256      HIGH        Long term protection",
   'S' => "256       15424      512      ULTRA       Foreseeable future",
); # %info_gnutls

our %cmd = (
    'timeout'       => "timeout",   # to terminate shell processes (timeout 1)
    'openssl'       => "openssl",   # OpenSSL
    'libs'          => [],      # where to find libssl.so and libcrypto.so
    'path'          => [],      # where to find openssl executable
    'extopenssl'    => 1,       # 1: use external openssl; default yes, except on Win32
    'extsclient'    => 1,       # 1: use openssl s_client; default yes, except on Win32
    'extciphers'    => 0,       # 1: use openssl s_client -cipher for connection check 
    'envlibvar'     => "LD_LIBRARY_PATH",       # name of environment variable
    'call'          => [],      # list of special (internal) function calls
                                # see --call=METHOD option in description below
);

our %cfg = (
   # config. key        default   description
   #------------------+---------+----------------------------------------------
	#	#	#	#
    'try'           => 0,       # 1: do not execute openssl, just show
    'exec'          => 0,       # 1: if +exec command used
    'trace'         => 0,       # 1: trace yeast, 2=trace Net::SSLeay and Net::SSLinfo also
    'traceARG'      => 0,       # 1: trace yeast's argument processing
    'traceCMD'      => 0,       # 1: trace command processing
    'traceKEY'      => 0,       # 1: (trace) print yeast's internal variable names
    'verbose'       => 0,       # used for --v
    'enabled'       => 0,       # 1: only print enabled ciphers
    'disabled'      => 0,       # 1: only print disabled ciphers
    'nolocal'       => 0,
    'usedns'        => 1,       # 1: make DNS reverse lookup
    'usehttp'       => 1,       # 1: make HTTP request
    'uselwp'        => 0,       # 1: use perls LWP module for HTTP checks # ToDo: NOT YET IMPLEMENTED
    'usesni'        => 1,       # 0: do not make connection in SNI mode;
    'no_cert'       => 0,       # 0: get data from certificate; 1, 2, do not get data
    'no_cert_txt'   => "",      # change default text if no data from cert retrieved
    'ca_depth'      => undef,   # depth of peer certificate verification verification
    'ca_crl'        => undef,   # URL where to find CRL file
    'ca_file'       => undef,   # PEM format file with CAs
    'ca_path'       => undef,   # path to directory with PEM files for CAs
                                # see Net::SSLinfo why undef as default
    'ca_paths'      => [qw(/etc/ssl/certs /usr/lib/certs /System/Library/OpenSSL)],
    'ca_files'      => [qw(ca-certificates.crt certificates.crt certs.pem)],
    'ignorecase'    => 1,       # 1: compare some strings case insensitive
    'shorttxt'      => 0,       # 1: use short label texts
    'version'       => [],      # contains the versions to be checked
    'versions'      => [qw(SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 DTLSv1)],
                                # NOTE: must be same string as used in %ciphers[ssl]
                                # NOTE: must be same string as used in Net::SSLinfo %_SSLmap
                                # ToDo: DTLSv0.9
    'SSLv2'         => 1,       # 1: check this SSL version
    'SSLv3'         => 1,       # 1:   "
    'TLSv1'         => 1,       # 1:   "
    'TLSv11'        => 1,       # 1:   "
    'TLSv12'        => 1,       # 1:   "
    'DTLSv9'        => 0,       # 1:   "
    'DTLSv1'        => 1,       # 1:   "
    'nullssl2'      => 0,       # 1: complain if SSLv2 enabled but no ciphers accepted
    'cipher'        => "yeast", # which ciphers to be used
    'cipherpattern' => "ALL:NULL:eNULL:aNULL:LOW:EXP", # openssl pattern for all ciphers
                                # ToDo: must be same as in Net::SSLinfo or used from there
    'ciphers'       => [],      # contains all ciphers to be tested
    'do'            => [],      # the commands to be performed, any of commands
    'commands'      => [],      # contains all commands, constructed below
    'cmd-intern'    => [        # add internal commands
                    # these have no key in %data or %checks
                       qw(
                        check cipher dump check_sni exec help info info--v http
                        quick list libversion sizes s_client version
                        sigkey bsi ev
                       ),
                    # add special commands for certificate extensions
                    # they are alredy part of extension (see above) and hence
                    # there'se no need to be part of +info or individual use
                       qw(
                        ext_authority ext_authorityid ext_constrains ext_certtype
                        ext_cps ext_cps_policy ext_cps_cps ext_subjectkeyid 
                        ext_crl ext_crl_crl ext_keyusage ext_extkeyusage
                        ext_issuer
                       ),
                    # internal (debugging or experimental) commands
                      # qw(options cert_type),   # will bee seen with +info--v only
                    # keys not used as command
                       qw(cn_nosni valid-years valid-months valid-days)
                       ],
    'cmd-NL'        => [        # commands which need NL when printed
                                # they should be available with +info --v only 
                       qw(certificate extensions pem pubkey sigdump text chain chain_verify)
                       ],
    'cmd-NOT_YET'   => [        # commands and checks NOT YET IMPLEMENTED
                       qw(
                        zlib lzo open_pgp nonprint crnlnull
                        fallback closure order sgc time
                       )],
    'cmd-beast'     => [qw(beast beast-default)],       # commands for +beast
    'cmd-crime'     => [qw(crime)],                     # commands for +crime
    'cmd-http'      => [],      # commands for +http, computed below
    'cmd-info'      => [],      # commands for +info, simply anything from %data
    'cmd-info--v'   => [],      # commands for +info --v
    'cmd-check'     => [],      # commands for +check, simply anything from %checks
    'cmd-sizes'     => [],      # commands for +sizes
    'cmd-quick'     => [        # commands for +quick
                       qw(
                        default cipher fingerprint_hash fp_not_md5 email serial
                        subject dates verify expansion compression hostname
                        beast beast-default crime export rc4 pfs crl
                        resumption renegotiation tr-02102 bsi-tr-02102+ bsi-tr-02102- hsts_sts
                       )],
    'cmd-ev'        => [qw(cn subject altname dv ev ev- ev+ ev-chars)], # commands for +ev
    'cmd-bsi'       => [qw(after dates crl rc4 renegotiation tr-02102 bsi-tr-02102+ bsi-tr-02102-)], # commands for +bsi
    'cmd-sni'       => [qw(sni hostname)],          # commands for +sni
    'cmd-sni--v'    => [qw(sni cn altname verify_altname verify_hostname hostname wildhost wildcard)],
    'need_cipher'   => [        # list of commands which need +cipher
                       qw(check beast crime time breach pfs rc4 bsi default cipher)],
    'need_checkssl' => [        # list of commands which need checkssl()
                       qw(check beast crime time breach pfs rc4 bsi default ev+ ev-)],
    'data_hex'      => [        # list of data values which are in hex values
                                # used in conjunction with --format=hex
                       qw(
                        fingerprint fingerprint_hash fingerprint_sha1 fingerprint_md5
                        serial sigkey_value pubkey_value modulus
                        master_key session_id session_ticket extension
                       )],      # fingerprint is special, see _ishexdata()

    'format'        => "",      # empty means some slightly adapted values (no \s\n)
    'formats'       => [qw(csv html json ssv tab xml fullxml raw hex)],
    'out_header'    => 0,       # print header lines in output
    'out_score'     => 0,       # print scoring; default for +check
    'tmplib'        => "/tmp/yeast-openssl/",   # temp. directory for openssl and its libraries
    'lang'          => "de",    # output language
    'langs'         => [qw(de en)],
    'pass_options'  => "",      # options to be passeed thru to other programs
    'hosts'         => [],      # list of hosts:port to be processed
    'host'          => "",      # currently scanned host
    'ip'            => "",      # currently scanned host's IP
    'IP'            => "",      # currently scanned host's IP (human readable, doted octed)
    'rhost'         => "",      # currently scanned host's reverse resolved name
    'DNS'           => "",      # currently scanned host's other IPs and names (DNS aliases)
    'port'          => 443,     # port for currently used connections
    'timeout'       => 2,       # default timeout in seconds for connections
                                # NOTE that some servers do not connect SSL within this time
                                #      this may result in ciphers marked as  "not supported"
                                #      it's recommended to set timeout to 3 or higher, which
                                #      results in a performance bottleneck, obviously
    'legacy'        => "simple",
    'legacys'       => [qw(cnark simple sslaudit sslcipher ssldiagnos sslscan
                        ssltest ssltest-g sslyze testsslserver full compact quick)],
    'showhost'      => 0,       # 1: prefix printed line with hostname
   #------------------+---------+----------------------------------------------
    'regex' => {
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
        'EC-RSA'    => 'EC(?:DHE|EDH)[_-]RSA',
        'EC-DSA'    => 'EC(?:DHE|EDH)[_-]ECDSA',
                       # ECDHE-RSA or ECDHE-ECDSA
        'EXPORT'    => 'EXP(?:ORT)?(?:40|56|1024)?[_-]',
                       # EXP, EXPORT, EXPORT40, EXP1024, EXPORT1024, ...
        'FRZorFZA'  => '(?:FORTEZZA|FRZ|FZA)[_-]',
                       # FORTEZZA has abbreviations FZA and FRZ
                       # unsure about FORTEZZA_KEA
        'SSLorTLS'  => '^(?:SSL[23]?|TLS[12]?|PCT1?)[_-]',
                       # Numerous protocol prefixes are in use:
                       #     PTC, PCT1, SSL, SSL2, SSL3, TLS, TLS1, TLS2,
        'aliases'   => '(?:(?:DHE|DH[_-]ANON|DSS|RAS|STANDARD)[_-]|EXPORT_NONE?[_-]?XPORT|STRONG|UNENCRYPTED)',
                       # various variants for aliases to select cipher groups
        'compression'   =>'(?:DEFLATE|LZO)',    # if compression available
        'nocompression' =>'(?:NONE|NULL|^\s*$)',# if no compression available

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
        'BEAST'     => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?(?:ARC(?:4|FOUR)|RC4)',
#       'BREACH'    => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?',
        'notCRIME'  => '(?:NONE|NULL|^\s*$)',   # same as nocompression (see above)
#       'TIME'      => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?',
#       'Lucky13'   => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?',
        # The following RegEx define what is "not vulnerable":
        'PFS'       => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?((?:EC)?DHE|EDH)[_-]',

        'TR-02102'  => '(?:DHE|EDH)[_-](?:PSK|(?:EC)?(?:[DR]S[AS]))[_-]',
                       # ECDHE_ECDSA | ECDHE_RSA | DHE_DSS | DHE_RSA
                       # ECDHE_ECRSA, ECDHE_ECDSS or DHE_DSA does not exists, hence lazy regex above
        'notTR-02102'     => '[_-]SHA$',
                       # ciphers with SHA1 hash are not allowed
        'TR-02102-noPFS'  => '(?:EC)?DH)[_-](?:EC)?(?:[DR]S[AS])[_-]',
                       # if PFS not possible, see TR-02102-2 3.2.1
        '1.3.6.1.5.5.7.1.1'  =>  '(?:1\.3\.6\.1\.5\.5\.7\.1\.1|authorityInfoAccess)',

        # Regex containing pattern for compliance checks
        # The following RegEx define what is "not compliant":
        'notISM'    => '(?:NULL|A(?:NON[_-])?DH|DH(?:A|[_-]ANON)[_-]|(?:^DES|[_-]DES)[_-]CBC[_-]|MD5|RC)',
        'notPCI'    => '(?:NULL|(?:A(?:NON[_-])?DH|DH(?:A|[_-]ANON)|(?:^DES|[_-]DES)[_-]CBC|EXP(?:ORT)?(?:40|56|1024)?)[_-])',
        'notFIPS-140'=>'(?:(?:ARC(?:4|FOUR)|RC4)|MD5|IDEA)',
        'FIPS-140'  => '(?:(?:3DES(?:[_-]EDE)[_-]CBC|DES[_-]CBC3)|AES)', # these are compiant

        # Regex for checking EV-SSL
        # they should matching:   /key=value/other-key=other-value
        '2.5.4.10'  => '(?:2\.5\.4\.10|organizationName|O)',
        '2.5.4.11'  => '(?:2\.5\.4\.1?|organizationalUnitName|OU)',
        '2.5.4.15'  => '(?:2\.5\.4\.15|businessCategory)',
        '2.5.4.3'   => '(?:2\.5\.4\.3|commonName|CN)',
        '2.5.4.5'   => '(?:2\.5\.4\.5|serialNumber)',
        '2.5.4.6'   => '(?:2\.5\.4\.6|countryName|C)',
        '2.5.4.7'   => '(?:2\.5\.4\.7|localityName|L)',
        '2.5.4.8'   => '(?:2\.5\.4\.8|stateOrProvinceName|SP|ST)', # ToDo: is ST a bug?
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

        # Regex for matching commands
        'cmd-http'  => '^h?(?:ttps?|sts)_',    # match keys for HTTP
        'cmd-sizes' => '^(?:cnt|len)_',        # match keys for length, sizes etc.
        'cmd-intern'=> '^(?:cn_nosni|valid-(?:year|month|day)s)', # internal data only, no command

        # Regex for matching SSL protocol keys in %data and %checks
        'SSLprot'   => '^(SSL|D?TLS)v[0-9]',   # match keys SSLv2, TLSv1-LOW, ...

    }, # regex
    'compliance' => {           # description of RegEx above for compliance checks
        'TR-02102'  => "no RC4, only eclipic curve, only SHA256 or SHA384, need CRL and AIA, no wildcards, and verifications ...",
        'ISM'       => "no NULL cipher, no Anonymous Auth, no single DES, no MD5, no RC ciphers",
        'PCI'       => "no NULL cipher, no Anonymous Auth, no single DES, no Export encryption, DH > 1023",
        'FIPS-140'  => "must be TLSv1 or 3DES or AES, no IDEA, no RC4, no MD5",
        'FIPS-140-2'=> "-- NOT YET IMPLEMENTED --",      # ToDo:
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
    },
    'openssl_option_map' => {   # map our internal option to openssl option
        'SSLv2'     => "-ssl2",
        'SSLv3'     => "-ssl3",
        'TLSv1'     => "-tls1",
        'TLSv11'    => "-tls1_1",
        'TLSv12'    => "-tls1_2",
        'DTLSv1'    => "-dtls1",
     },
    'done' => {                 # internal administration
        'hosts'     => 0,
        'dbxfile'   => 0,
        'rc-file'   => 0,
        'init_all'  => 0,
         # all following need to be reset for each host
        'checkciphers'  => 0,   # not used, as it's called multiple times
        'checkdefault'  => 0,
        'check02102'=> 0,
        'checkdates'=> 0,
        'checksizes'=> 0,
        'checkcert' => 0,
        'checkdest' => 0,
        'checkhttp' => 0,
        'checksni'  => 0,
        'checkssl'  => 0,
        'checkdv'   => 0,
        'checkev'   => 0,
    },
); # %cfg

# construct list for special commands: 'cmd-*'
sub _is_intern($);      # perl avoid: main::_is_member() called too early to check prototype
sub _is_member($$);     #   "
my $old = "";
my $rex = join("|", @{$cfg{'versions'}});   # these are data only, not commands
foreach $key (sort {uc($a) cmp uc($b)} keys %data, keys %checks, @{$cfg{'cmd-intern'}}) {
    next if ($key eq $old); # unique
    $old = $key;
    push(@{$cfg{'commands'}},  $key) if ($key !~ m/^($rex)/);
    push(@{$cfg{'cmd-http'}},  $key) if ($key =~ m/$cfg{'regex'}->{'cmd-http'}/i);
    push(@{$cfg{'cmd-sizes'}}, $key) if ($key =~ m/$cfg{'regex'}->{'cmd-sizes'}/);
}
push(@{$cfg{'cmd-check'}}, $_) foreach (keys %checks);
push(@{$cfg{'cmd-info--v'}}, 'dump');       # more information
foreach $key (keys %data) {
    push(@{$cfg{'cmd-info--v'}}, $key);
    next if (_is_intern($key) > 0);         # ignore aliases
    next if ($key =~ m/^(ciphers)/   and $verbose == 0); # Client ciphers are less important
    next if ($key =~ m/^modulus$/    and $verbose == 0); # same values as 'pubkey_value'
    push(@{$cfg{'cmd-info'}},    $key);
}
push(@{$cfg{'cmd-info--v'}}, 'info--v');

# adding more shorttexts
foreach my $ssl (@{$cfg{'versions'}}) {
    foreach $sec (qw(LOW WEAK HIGH MEDIUM -?-)) {
        #------------------+------------------------------------------------------
        # %checks           short label text
        #------------------+------------------------------------------------------
        $shorttexts{$ssl . '-' . $sec} = $sec . " (total)";
    }
}

my %ciphers_desc = (    # description of following %ciphers table
    'head'          => [qw(  sec  ssl   enc  bits mac  auth  keyx   score  tags)],
                            # abbreviations used by openssl:
                            # SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2
                            # Kx=  key exchange (DH is diffie-hellman)
                            # Au=  authentication
                            # Enc= encryption with bit size
                            # Mac= mac encryption algorithm
    'text'          => [ # full description of each column in 'ciphers' below
        'Security',         # LOW, MEDIUM, HIGH as reported by openssl 0.9.8
                            # WEAK as reported by openssl 0.9.8 as EXPORT
                            # weak unqualified by openssl or know vulnerable
                            # Note: weak includes NONE (no security at all)
                            #
                            # all following informations as reported by openssl 0.9.8
        'Protocol Version', # SSLv2, SSLv3, TLSv1, TLSv11, TLSv12, DTLS0.9, DTLS1.0
                            # Note: all SSLv3 are also TLSv1, TLSv11, TLSv12
                            # (cross-checked with sslaudit.ini)
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
        'DHE-DSS-RC4-SHA'       => [qw(  high SSLv3 RC4   128 SHA1 DSS   DH         80 :)], # FIXME: degrade this also?
        'DHE-DSS-SEED-SHA'      => [qw(MEDIUM SSLv3 SEED  128 SHA1 DSS   DH         81 OSX)],
        'DHE-RSA-AES128-SHA'    => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   DH         80 :)],
        'DHE-RSA-AES256-SHA'    => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   DH        100 :)],
        'DHE-RSA-SEED-SHA'      => [qw(MEDIUM SSLv3 SEED  128 SHA1 RSA   DH         81 OSX)],
        'ECDH-ECDSA-AES128-SHA' => [qw(  high SSLv3 AES   128 SHA1 ECDSA ECDH       11 :)], #
        'ECDH-ECDSA-AES256-SHA' => [qw(  high SSLv3 AES   256 SHA1 ECDSA ECDH       11 :)], #
        'ECDH-ECDSA-DES-CBC3-SHA'=>[qw(  HIGH SSLv3 3DES  168 SHA1 ECDSA ECDH/ECDSA 11 :)], # (from openssl-1.0.0d)
       #'ECDH-ECDSA-RC4-SHA'    => [qw(MEDIUM SSLv3 RC4   128 SHA1 ECDSA ECDH/ECDSA 81 :)], # (from openssl-1.0.0d)
        'ECDH-ECDSA-RC4-SHA'    => [qw(  weak SSLv3 RC4   128 SHA1 ECDSA ECDH/ECDSA 81 :)], # (from openssl-1.0.0d)
        'ECDH-ECDSA-NULL-SHA'   => [qw(  weak SSLv3 None    0 SHA1 ECDSA ECDH/ECDSA 11 :)], # (from openssl-1.0.0d)
        'ECDH-RSA-AES128-SHA'   => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   ECDH       11 :)], #
        'ECDH-RSA-AES256-SHA'   => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   ECDH       11 :)], #
        'ECDH-RSA-DES-CBC3-SHA' => [qw(  HIGH SSLv3 3DES  168 SHA1 RSA   ECDH       11 :)], #
       #'ECDH-RSA-RC4-SHA'      => [qw(MEDIUM SSLv3 RC4   128 SHA1 RSA   ECDH       81 :)], #
        'ECDH-RSA-RC4-SHA'      => [qw(  weak SSLv3 RC4   128 SHA1 RSA   ECDH       81 :)], #
        'ECDH-RSA-NULL-SHA'     => [qw(  weak SSLv3 None    0 SHA1 RSA   ECDH       11 :)], # (from openssl-1.0.0d)
        'ECDHE-ECDSA-AES128-SHA'=> [qw(  high SSLv3 AES   128 SHA1 ECDSA ECDH       11 :)], #
        'ECDHE-ECDSA-AES256-SHA'=> [qw(  high SSLv3 AES   256 SHA1 ECDSA ECDH       11 :)], #
        'ECDHE-ECDSA-DES-CBC3-SHA'=> [qw(HIGH SSLv3 3DES  168 SHA1 ECDSA ECDH       11 :)], #
        'ECDHE-ECDSA-NULL-SHA'  => [qw(  weak SSLv3 None    0 SHA1 ECDSA ECDH       11 :)], #
       #'ECDHE-ECDSA-RC4-SHA'   => [qw(MEDIUM SSLv3 RC4   128 SHA1 ECDSA ECDH       81 :)], #
        'ECDHE-ECDSA-RC4-SHA'   => [qw(  weak SSLv3 RC4   128 SHA1 ECDSA ECDH       81 :)], #
        'ECDHE-RSA-AES128-SHA'  => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   ECDH       11 :)], #
        'ECDHE-RSA-AES256-SHA'  => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   ECDH       11 :)], #
        'ECDHE-RSA-DES-CBC3-SHA'=> [qw(  HIGH SSLv3 3DES  168 SHA1 RSA   ECDH       11 :)], #
       #'ECDHE-RSA-RC4-SHA'     => [qw(MEDIUM SSLv3 RC4   128 SHA1 RSA   ECDH       81 :)], #
        'ECDHE-RSA-RC4-SHA'     => [qw(  weak SSLv3 RC4   128 SHA1 RSA   ECDH       81 :)], #
        'ECDHE-RSA-NULL-SHA'    => [qw(  weak SSLv3 None    0 SHA1 RSA   ECDH       11 :)], #
        'EDH-DSS-AES128-SHA'    => [qw(  high SSLv3 AES   128 SHA1 DSS   DHE        91 :)], # (from RSA BSAFE SSL-C) same as DHE-DSS-AES128-SHA?
        'EDH-DSS-AES256-SHA'    => [qw(  high SSLv3 AES   256 SHA1 DSS   DHE       100 :)], # (from RSA BSAFE SSL-C) same as DHE-DSS-AES256-SHA?
        'EDH-DSS-DES-CBC3-SHA'  => [qw(  HIGH SSLv3 3DES  168 SHA1 DSS   DH         80 :)],
        'EDH-DSS-DES-CBC-SHA'   => [qw(   LOW SSLv3 DES    56 SHA1 DSS   DH          1 :)],
       #'EDH-DSS-RC4-SHA'       => [qw(  high SSLv3 RC4   128 SHA1 DSS   DHE       100 :)], # (from RSA BSAFE SSL-C) same as DHE-DSS-RC4-SHA?
        'EDH-DSS-RC4-SHA'       => [qw(  weak SSLv3 RC4   128 SHA1 DSS   DHE       100 :)], # (from RSA BSAFE SSL-C) same as DHE-DSS-RC4-SHA?
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
        'EXP1024-RC2-CBC-MD5'   => [qw(  weak -?-   RC2    56 MD5  -?-   -?-         1 :)], #
        'EXP1024-RC4-MD5'       => [qw(  weak -?-   RC4    56 MD5  -?-   -?-         1 :)], #
        'EXP1024-RC4-SHA'       => [qw(  weak SSLv3 RC4    56 SHA  RSA   -?-         2 :)], #
        'IDEA-CBC-MD5'          => [qw(MEDIUM SSLv2 IDEA  128 MD5  RSA   RSA        80 :)], #
        'IDEA-CBC-SHA'          => [qw(MEDIUM SSLv2 IDEA  128 SHA  RSA   RSA        80 :)], #
        'NULL-MD5'              => [qw(  weak SSLv3 None    0 MD5  RSA   RSA         0 :)],
        'NULL-SHA'              => [qw(  weak SSLv3 None    0 SHA1 RSA   RSA         0 :)],
        'PSK-3DES-EDE-CBC-SHA'  => [qw(  HIGH SSLv3 3DES  168 SHA  PSK   PSK         1 :)], #
        'PSK-AES128-CBC-SHA'    => [qw(  HIGH SSLv3 AES   128 SHA  PSK   PSK         1 :)], #
        'PSK-AES256-CBC-SHA'    => [qw(  HIGH SSLv3 AES   256 SHA  PSK   PSK         1 :)], #
        'PSK-RC4-SHA'           => [qw(MEDIUM SSLv3 RC4   128 SHA  PSK   PSK         1 :)], #
        'RC2-CBC-MD5'           => [qw(MEDIUM SSLv2 RC2   128 MD5  RSA   RSA        11 :)],
        'RC2-MD5'               => [qw(MEDIUM SSLv2 RC2   128 MD5  RSA   RSA        80 :)],
        'RC4-MD5'               => [qw(MEDIUM SSLv2 RC4   128 MD5  RSA   RSA        80 :)],
       #'RC4-MD5'               => [qw(MEDIUM SSLv3 RC4   128 MD5  RSA   RSA        80 :)],
       #'RC4-SHA'               => [qw(MEDIUM SSLv3 RC4   128 SHA1 RSA   RSA        80 :)],
        'RC4-MD5'               => [qw(  weak SSLv3 RC4   128 MD5  RSA   RSA        80 :)],
        'RC4-SHA'               => [qw(  weak SSLv3 RC4   128 SHA1 RSA   RSA        80 :)],
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

my %cipher_names = (
    # ADH_DES_192_CBC_SHA      # alias: DH_anon_WITH_3DES_EDE_CBC_SHA
    # ADH_DES_40_CBC_SHA       # alias: DH_anon_EXPORT_WITH_DES40_CBC_SHA
    # ADH_DES_64_CBC_SHA       # alias: DH_anon_WITH_DES_CBC_SHA
    # ADH_RC4_40_MD5           # alias: DH_anon_EXPORT_WITH_RC4_40_MD5
    # DHE_RSA_WITH_AES_128_SHA # alias: DHE_RSA_WITH_AES_128_CBC_SHA
    # DHE_RSA_WITH_AES_256_SHA # alias: DHE_RSA_WITH_AES_256_CBC_SHA
    #
    # from openssl-1.0.1c (generated by openssl_h-to-perl_hash)
    #!#----------------------------------------+-------------+--------------------+
    #!# cipher suite value                  => [   constant   cipher names        ],
    #!#----------------------------------------+-------------+--------------------+
    'ADH_DES_192_CBC_SHA'                   => [qw(0x0300001B ADH-DES-CBC3-SHA)],
    'ADH_DES_40_CBC_SHA'                    => [qw(0x03000019 EXP-ADH-DES-CBC-SHA)],
    'ADH_DES_64_CBC_SHA'                    => [qw(0x0300001A ADH-DES-CBC-SHA)],
    'ADH_RC4_128_MD5'                       => [qw(0x03000018 ADH-RC4-MD5)],
    'ADH_RC4_40_MD5'                        => [qw(0x03000017 EXP-ADH-RC4-MD5)],
    'ADH_WITH_AES_128_GCM_SHA256'           => [qw(0x030000A6 ADH-AES128-GCM-SHA256)],
    'ADH_WITH_AES_128_SHA'                  => [qw(0x03000034 ADH-AES128-SHA)],
    'ADH_WITH_AES_128_SHA256'               => [qw(0x0300006C ADH-AES128-SHA256)],
    'ADH_WITH_AES_256_GCM_SHA384'           => [qw(0x030000A7 ADH-AES256-GCM-SHA384)],
    'ADH_WITH_AES_256_SHA'                  => [qw(0x0300003A ADH-AES256-SHA)],
    'ADH_WITH_AES_256_SHA256'               => [qw(0x0300006D ADH-AES256-SHA256)],
    'ADH_WITH_CAMELLIA_128_CBC_SHA'         => [qw(0x03000046 ADH-CAMELLIA128-SHA)],
    'ADH_WITH_CAMELLIA_256_CBC_SHA'         => [qw(0x03000089 ADH-CAMELLIA256-SHA)],
    'ADH_WITH_SEED_SHA'                     => [qw(0x0300009B ADH-SEED-SHA)],
    'DES_192_EDE3_CBC_WITH_MD5'             => [qw(0x020700c0 DES-CBC3-MD5)],
    'DES_192_EDE3_CBC_WITH_SHA'             => [qw(0x020701c0 DES-CBC3-SHA)],
    'DES_64_CBC_WITH_MD5'                   => [qw(0x02060040 DES-CBC-MD5)],
    'DES_64_CBC_WITH_SHA'                   => [qw(0x02060140 DES-CBC-SHA)],
    'DES_64_CFB64_WITH_MD5_1'               => [qw(0x02ff0800 DES-CFB-M1)],
    'DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA'   => [qw(0x03000063 EXP1024-DHE-DSS-DES-CBC-SHA)],
    'DHE_DSS_EXPORT1024_WITH_RC4_56_SHA'    => [qw(0x03000065 EXP1024-DHE-DSS-RC4-SHA)],
    'DHE_DSS_WITH_AES_128_GCM_SHA256'       => [qw(0x030000A2 DHE-DSS-AES128-GCM-SHA256)],
    'DHE_DSS_WITH_AES_128_SHA'              => [qw(0x03000032 DHE-DSS-AES128-SHA)],
    'DHE_DSS_WITH_AES_128_SHA256'           => [qw(0x03000040 DHE-DSS-AES128-SHA256)],
    'DHE_DSS_WITH_AES_256_GCM_SHA384'       => [qw(0x030000A3 DHE-DSS-AES256-GCM-SHA384)],
    'DHE_DSS_WITH_AES_256_SHA'              => [qw(0x03000038 DHE-DSS-AES256-SHA)],
    'DHE_DSS_WITH_AES_256_SHA256'           => [qw(0x0300006A DHE-DSS-AES256-SHA256)],
    'DHE_DSS_WITH_CAMELLIA_128_CBC_SHA'     => [qw(0x03000044 DHE-DSS-CAMELLIA128-SHA)],
    'DHE_DSS_WITH_CAMELLIA_256_CBC_SHA'     => [qw(0x03000087 DHE-DSS-CAMELLIA256-SHA)],
    'DHE_DSS_WITH_RC4_128_SHA'              => [qw(0x03000066 DHE-DSS-RC4-SHA)],
    'DHE_DSS_WITH_SEED_SHA'                 => [qw(0x03000099 DHE-DSS-SEED-SHA)],
    'DHE_RSA_WITH_AES_128_GCM_SHA256'       => [qw(0x0300009E DHE-RSA-AES128-GCM-SHA256)],
    'DHE_RSA_WITH_AES_128_SHA'              => [qw(0x03000033 DHE-RSA-AES128-SHA)],
    'DHE_RSA_WITH_AES_128_SHA256'           => [qw(0x03000067 DHE-RSA-AES128-SHA256)],
    'DHE_RSA_WITH_AES_256_GCM_SHA384'       => [qw(0x0300009F DHE-RSA-AES256-GCM-SHA384)],
    'DHE_RSA_WITH_AES_256_SHA'              => [qw(0x03000039 DHE-RSA-AES256-SHA)],
    'DHE_RSA_WITH_AES_256_SHA256'           => [qw(0x0300006B DHE-RSA-AES256-SHA256)],
    'DHE_RSA_WITH_CAMELLIA_128_CBC_SHA'     => [qw(0x03000045 DHE-RSA-CAMELLIA128-SHA)],
    'DHE_RSA_WITH_CAMELLIA_256_CBC_SHA'     => [qw(0x03000088 DHE-RSA-CAMELLIA256-SHA)],
    'DHE_RSA_WITH_SEED_SHA'                 => [qw(0x0300009A DHE-RSA-SEED-SHA)],
    'DH_DSS_DES_192_CBC3_SHA'               => [qw(0x0300000D DH-DSS-DES-CBC3-SHA)],
    'DH_DSS_DES_40_CBC_SHA'                 => [qw(0x0300000B EXP-DH-DSS-DES-CBC-SHA)],
    'DH_DSS_DES_64_CBC_SHA'                 => [qw(0x0300000C DH-DSS-DES-CBC-SHA)],
    'DH_DSS_WITH_AES_128_GCM_SHA256'        => [qw(0x030000A4 DH-DSS-AES128-GCM-SHA256)],
    'DH_DSS_WITH_AES_128_SHA'               => [qw(0x03000030 DH-DSS-AES128-SHA)],
    'DH_DSS_WITH_AES_128_SHA256'            => [qw(0x0300003E DH-DSS-AES128-SHA256)],
    'DH_DSS_WITH_AES_256_GCM_SHA384'        => [qw(0x030000A5 DH-DSS-AES256-GCM-SHA384)],
    'DH_DSS_WITH_AES_256_SHA'               => [qw(0x03000036 DH-DSS-AES256-SHA)],
    'DH_DSS_WITH_AES_256_SHA256'            => [qw(0x03000068 DH-DSS-AES256-SHA256)],
    'DH_DSS_WITH_CAMELLIA_128_CBC_SHA'      => [qw(0x03000042 DH-DSS-CAMELLIA128-SHA)],
    'DH_DSS_WITH_CAMELLIA_256_CBC_SHA'      => [qw(0x03000085 DH-DSS-CAMELLIA256-SHA)],
    'DH_DSS_WITH_SEED_SHA'                  => [qw(0x03000097 DH-DSS-SEED-SHA)],
    'DH_RSA_DES_192_CBC3_SHA'               => [qw(0x03000010 DH-RSA-DES-CBC3-SHA)],
    'DH_RSA_DES_40_CBC_SHA'                 => [qw(0x0300000E EXP-DH-RSA-DES-CBC-SHA)],
    'DH_RSA_DES_64_CBC_SHA'                 => [qw(0x0300000F DH-RSA-DES-CBC-SHA)],
    'DH_RSA_WITH_AES_128_GCM_SHA256'        => [qw(0x030000A0 DH-RSA-AES128-GCM-SHA256)],
    'DH_RSA_WITH_AES_128_SHA'               => [qw(0x03000031 DH-RSA-AES128-SHA)],
    'DH_RSA_WITH_AES_128_SHA256'            => [qw(0x0300003F DH-RSA-AES128-SHA256)],
    'DH_RSA_WITH_AES_256_GCM_SHA384'        => [qw(0x030000A1 DH-RSA-AES256-GCM-SHA384)],
    'DH_RSA_WITH_AES_256_SHA'               => [qw(0x03000037 DH-RSA-AES256-SHA)],
    'DH_RSA_WITH_AES_256_SHA256'            => [qw(0x03000069 DH-RSA-AES256-SHA256)],
    'DH_RSA_WITH_CAMELLIA_128_CBC_SHA'      => [qw(0x03000043 DH-RSA-CAMELLIA128-SHA)],
    'DH_RSA_WITH_CAMELLIA_256_CBC_SHA'      => [qw(0x03000086 DH-RSA-CAMELLIA256-SHA)],
    'DH_RSA_WITH_SEED_SHA'                  => [qw(0x03000098 DH-RSA-SEED-SHA)],
    'ECDHE_ECDSA_WITH_AES_128_CBC_SHA'      => [qw(0x0300C009 ECDHE-ECDSA-AES128-SHA)],
    'ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'   => [qw(0x0300C02B ECDHE-ECDSA-AES128-GCM-SHA256)],
    'ECDHE_ECDSA_WITH_AES_128_SHA256'       => [qw(0x0300C023 ECDHE-ECDSA-AES128-SHA256)],
    'ECDHE_ECDSA_WITH_AES_256_CBC_SHA'      => [qw(0x0300C00A ECDHE-ECDSA-AES256-SHA)],
    'ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'   => [qw(0x0300C02C ECDHE-ECDSA-AES256-GCM-SHA384)],
    'ECDHE_ECDSA_WITH_AES_256_SHA384'       => [qw(0x0300C024 ECDHE-ECDSA-AES256-SHA384)],
    'ECDHE_ECDSA_WITH_DES_192_CBC3_SHA'     => [qw(0x0300C008 ECDHE-ECDSA-DES-CBC3-SHA)],
    'ECDHE_ECDSA_WITH_NULL_SHA'             => [qw(0x0300C006 ECDHE-ECDSA-NULL-SHA)],
    'ECDHE_ECDSA_WITH_RC4_128_SHA'          => [qw(0x0300C007 ECDHE-ECDSA-RC4-SHA)],
    'ECDHE_RSA_WITH_AES_128_CBC_SHA'        => [qw(0x0300C013 ECDHE-RSA-AES128-SHA)],
    'ECDHE_RSA_WITH_AES_128_GCM_SHA256'     => [qw(0x0300C02F ECDHE-RSA-AES128-GCM-SHA256)],
    'ECDHE_RSA_WITH_AES_128_SHA256'         => [qw(0x0300C027 ECDHE-RSA-AES128-SHA256)],
    'ECDHE_RSA_WITH_AES_256_CBC_SHA'        => [qw(0x0300C014 ECDHE-RSA-AES256-SHA)],
    'ECDHE_RSA_WITH_AES_256_GCM_SHA384'     => [qw(0x0300C030 ECDHE-RSA-AES256-GCM-SHA384)],
    'ECDHE_RSA_WITH_AES_256_SHA384'         => [qw(0x0300C028 ECDHE-RSA-AES256-SHA384)],
    'ECDHE_RSA_WITH_DES_192_CBC3_SHA'       => [qw(0x0300C012 ECDHE-RSA-DES-CBC3-SHA)],
    'ECDHE_RSA_WITH_NULL_SHA'               => [qw(0x0300C010 ECDHE-RSA-NULL-SHA)],
    'ECDHE_RSA_WITH_RC4_128_SHA'            => [qw(0x0300C011 ECDHE-RSA-RC4-SHA)],
    'ECDH_ECDSA_WITH_AES_128_CBC_SHA'       => [qw(0x0300C004 ECDH-ECDSA-AES128-SHA)],
    'ECDH_ECDSA_WITH_AES_128_GCM_SHA256'    => [qw(0x0300C02D ECDH-ECDSA-AES128-GCM-SHA256)],
    'ECDH_ECDSA_WITH_AES_128_SHA256'        => [qw(0x0300C025 ECDH-ECDSA-AES128-SHA256)],
    'ECDH_ECDSA_WITH_AES_256_CBC_SHA'       => [qw(0x0300C005 ECDH-ECDSA-AES256-SHA)],
    'ECDH_ECDSA_WITH_AES_256_GCM_SHA384'    => [qw(0x0300C02E ECDH-ECDSA-AES256-GCM-SHA384)],
    'ECDH_ECDSA_WITH_AES_256_SHA384'        => [qw(0x0300C026 ECDH-ECDSA-AES256-SHA384)],
    'ECDH_ECDSA_WITH_DES_192_CBC3_SHA'      => [qw(0x0300C003 ECDH-ECDSA-DES-CBC3-SHA)],
    'ECDH_ECDSA_WITH_NULL_SHA'              => [qw(0x0300C001 ECDH-ECDSA-NULL-SHA)],
    'ECDH_ECDSA_WITH_RC4_128_SHA'           => [qw(0x0300C002 ECDH-ECDSA-RC4-SHA)],
    'ECDH_RSA_WITH_AES_128_CBC_SHA'         => [qw(0x0300C00E ECDH-RSA-AES128-SHA)],
    'ECDH_RSA_WITH_AES_128_GCM_SHA256'      => [qw(0x0300C031 ECDH-RSA-AES128-GCM-SHA256)],
    'ECDH_RSA_WITH_AES_128_SHA256'          => [qw(0x0300C029 ECDH-RSA-AES128-SHA256)],
    'ECDH_RSA_WITH_AES_256_CBC_SHA'         => [qw(0x0300C00F ECDH-RSA-AES256-SHA)],
    'ECDH_RSA_WITH_AES_256_GCM_SHA384'      => [qw(0x0300C032 ECDH-RSA-AES256-GCM-SHA384)],
    'ECDH_RSA_WITH_AES_256_SHA384'          => [qw(0x0300C02A ECDH-RSA-AES256-SHA384)],
    'ECDH_RSA_WITH_DES_192_CBC3_SHA'        => [qw(0x0300C00D ECDH-RSA-DES-CBC3-SHA)],
    'ECDH_RSA_WITH_NULL_SHA'                => [qw(0x0300C00B ECDH-RSA-NULL-SHA)],
    'ECDH_RSA_WITH_RC4_128_SHA'             => [qw(0x0300C00C ECDH-RSA-RC4-SHA)],
    'ECDH_anon_WITH_AES_128_CBC_SHA'        => [qw(0x0300C018 AECDH-AES128-SHA)],
    'ECDH_anon_WITH_AES_256_CBC_SHA'        => [qw(0x0300C019 AECDH-AES256-SHA)],
    'ECDH_anon_WITH_DES_192_CBC3_SHA'       => [qw(0x0300C017 AECDH-DES-CBC3-SHA)],
    'ECDH_anon_WITH_NULL_SHA'               => [qw(0x0300C015 AECDH-NULL-SHA)],
    'ECDH_anon_WITH_RC4_128_SHA'            => [qw(0x0300C016 AECDH-RC4-SHA)],
    'EDH_DSS_DES_192_CBC3_SHA'              => [qw(0x03000013 EDH-DSS-DES-CBC3-SHA)],
    'EDH_DSS_DES_40_CBC_SHA'                => [qw(0x03000011 EXP-EDH-DSS-DES-CBC-SHA)],
    'EDH_DSS_DES_64_CBC_SHA'                => [qw(0x03000012 EDH-DSS-DES-CBC-SHA)],
    'EDH_RSA_DES_192_CBC3_SHA'              => [qw(0x03000016 EDH-RSA-DES-CBC3-SHA)],
    'EDH_RSA_DES_40_CBC_SHA'                => [qw(0x03000014 EXP-EDH-RSA-DES-CBC-SHA)],
    'EDH_RSA_DES_64_CBC_SHA'                => [qw(0x03000015 EDH-RSA-DES-CBC-SHA)],
    'FZA_DMS_FZA_SHA'                       => [qw(0x0300001D FZA-FZA-CBC-SHA)],
    'FZA_DMS_NULL_SHA'                      => [qw(0x0300001C FZA-NULL-SHA)],
    'FZA_DMS_RC4_SHA'                       => [qw(0x0300001E FZA-RC4-SHA)],
    'IDEA_128_CBC_WITH_MD5'                 => [qw(0x02050080 IDEA-CBC-MD5)],
    'KRB5_DES_192_CBC3_MD5'                 => [qw(0x03000023 KRB5-DES-CBC3-MD5)],
    'KRB5_DES_192_CBC3_SHA'                 => [qw(0x0300001F KRB5-DES-CBC3-SHA)],
    'KRB5_DES_40_CBC_MD5'                   => [qw(0x03000029 EXP-KRB5-DES-CBC-MD5)],
    'KRB5_DES_40_CBC_SHA'                   => [qw(0x03000026 EXP-KRB5-DES-CBC-SHA)],
    'KRB5_DES_64_CBC_MD5'                   => [qw(0x03000022 KRB5-DES-CBC-MD5)],
    'KRB5_DES_64_CBC_SHA'                   => [qw(0x0300001E KRB5-DES-CBC-SHA)],
    'KRB5_IDEA_128_CBC_MD5'                 => [qw(0x03000025 KRB5-IDEA-CBC-MD5)],
    'KRB5_IDEA_128_CBC_SHA'                 => [qw(0x03000021 KRB5-IDEA-CBC-SHA)],
    'KRB5_RC2_40_CBC_MD5'                   => [qw(0x0300002A EXP-KRB5-RC2-CBC-MD5)],
    'KRB5_RC2_40_CBC_SHA'                   => [qw(0x03000027 EXP-KRB5-RC2-CBC-SHA)],
    'KRB5_RC4_128_MD5'                      => [qw(0x03000024 KRB5-RC4-MD5)],
    'KRB5_RC4_128_SHA'                      => [qw(0x03000020 KRB5-RC4-SHA)],
    'KRB5_RC4_40_MD5'                       => [qw(0x0300002B EXP-KRB5-RC4-MD5)],
    'KRB5_RC4_40_SHA'                       => [qw(0x03000028 EXP-KRB5-RC4-SHA)],
    'NULL'                                  => [qw(0x02ff0810 NULL)],
    'NULL_WITH_MD5'                         => [qw(0x02000000 NULL-MD5)],
    'PSK_WITH_3DES_EDE_CBC_SHA'             => [qw(0x0300008B PSK-3DES-EDE-CBC-SHA)],
    'PSK_WITH_AES_128_CBC_SHA'              => [qw(0x0300008C PSK-AES128-CBC-SHA)],
    'PSK_WITH_AES_256_CBC_SHA'              => [qw(0x0300008D PSK-AES256-CBC-SHA)],
    'PSK_WITH_RC4_128_SHA'                  => [qw(0x0300008A PSK-RC4-SHA)],
    'RC2_128_CBC_EXPORT40_WITH_MD5'         => [qw(0x02040080 EXP-RC2-CBC-MD5)],
    'RC2_128_CBC_WITH_MD5'                  => [qw(0x02030080 RC2-CBC-MD5)],
    'RC4_128_EXPORT40_WITH_MD5'             => [qw(0x02020080 EXP-RC4-MD5)],
    'RC4_128_WITH_MD5'                      => [qw(0x02010080 RC4-MD5)],
    'RC4_64_WITH_MD5'                       => [qw(0x02080080 RC4-64-MD5)],
    'RSA_DES_192_CBC3_SHA'                  => [qw(0x0300000A DES-CBC3-SHA)],
    'RSA_DES_40_CBC_SHA'                    => [qw(0x03000008 EXP-DES-CBC-SHA)],
    'RSA_DES_64_CBC_SHA'                    => [qw(0x03000009 DES-CBC-SHA)],
    'RSA_EXPORT1024_WITH_DES_CBC_SHA'       => [qw(0x03000062 EXP1024-DES-CBC-SHA)],
    'RSA_EXPORT1024_WITH_RC2_CBC_56_MD5'    => [qw(0x03000061 EXP1024-RC2-CBC-MD5)],
    'RSA_EXPORT1024_WITH_RC4_56_MD5'        => [qw(0x03000060 EXP1024-RC4-MD5)],
    'RSA_EXPORT1024_WITH_RC4_56_SHA'        => [qw(0x03000064 EXP1024-RC4-SHA)],
    'RSA_IDEA_128_SHA'                      => [qw(0x03000007 IDEA-CBC-SHA)],
    'RSA_NULL_MD5'                          => [qw(0x03000001 NULL-MD5)],
    'RSA_NULL_SHA'                          => [qw(0x03000002 NULL-SHA)],
    'RSA_RC2_40_MD5'                        => [qw(0x03000006 EXP-RC2-CBC-MD5)],
    'RSA_RC4_128_MD5'                       => [qw(0x03000004 RC4-MD5)],
    'RSA_RC4_128_SHA'                       => [qw(0x03000005 RC4-SHA)],
    'RSA_RC4_40_MD5'                        => [qw(0x03000003 EXP-RC4-MD5)],
    'RSA_WITH_AES_128_GCM_SHA256'           => [qw(0x0300009C AES128-GCM-SHA256)],
    'RSA_WITH_AES_128_SHA'                  => [qw(0x0300002F AES128-SHA)],
    'RSA_WITH_AES_128_SHA256'               => [qw(0x0300003C AES128-SHA256)],
    'RSA_WITH_AES_256_GCM_SHA384'           => [qw(0x0300009D AES256-GCM-SHA384)],
    'RSA_WITH_AES_256_SHA'                  => [qw(0x03000035 AES256-SHA)],
    'RSA_WITH_AES_256_SHA256'               => [qw(0x0300003D AES256-SHA256)],
    'RSA_WITH_CAMELLIA_128_CBC_SHA'         => [qw(0x03000041 CAMELLIA128-SHA)],
    'RSA_WITH_CAMELLIA_256_CBC_SHA'         => [qw(0x03000084 CAMELLIA256-SHA)],
    'RSA_WITH_NULL_SHA256'                  => [qw(0x0300003B NULL-SHA256)],
    'RSA_WITH_SEED_SHA'                     => [qw(0x03000096 SEED-SHA)],
#   'SCSV'                                  => [qw(0x030000FF )],
    'SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA'     => [qw(0x0300C01C SRP-DSS-3DES-EDE-CBC-SHA)],
    'SRP_SHA_DSS_WITH_AES_128_CBC_SHA'      => [qw(0x0300C01F SRP-DSS-AES-128-CBC-SHA)],
    'SRP_SHA_DSS_WITH_AES_256_CBC_SHA'      => [qw(0x0300C022 SRP-DSS-AES-256-CBC-SHA)],
    'SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA'     => [qw(0x0300C01B SRP-RSA-3DES-EDE-CBC-SHA)],
    'SRP_SHA_RSA_WITH_AES_128_CBC_SHA'      => [qw(0x0300C01E SRP-RSA-AES-128-CBC-SHA)],
    'SRP_SHA_RSA_WITH_AES_256_CBC_SHA'      => [qw(0x0300C021 SRP-RSA-AES-256-CBC-SHA)],
    'SRP_SHA_WITH_3DES_EDE_CBC_SHA'         => [qw(0x0300C01A SRP-3DES-EDE-CBC-SHA)],
    'SRP_SHA_WITH_AES_128_CBC_SHA'          => [qw(0x0300C01D SRP-AES-128-CBC-SHA)],
    'SRP_SHA_WITH_AES_256_CBC_SHA'          => [qw(0x0300C020 SRP-AES-256-CBC-SHA)],
    #!#----------------------------------------+-------------+--------------------+
); # %cipher_names

my %text = (
    'separator' => ":",# separator character between label and value
    # texts may be redefined
    'undef'         => "<<undefined>>",
    'response'      => "<<response>>",
    'protocol'      => "<<protocol probably supported, but no ciphers accepted>>",
    'need-cipher'   => "<<check possible in conjunction with `+cipher' only>>",
    'no-STS'        => "<<N/A as STS not set>>",
    'no-dns'        => "<<N/A as --no-dns in use>>",
    'no-cert'       => "<<N/A as --no-cert in use>>",
    'no-http'       => "<<N/A as --no-http in use>>",
    'disabled'      => "<<test disabled>>",
    'miss-RSA'      => " <<missing ECDHE-RSA-* cipher>>",
    'miss-ECDSA'    => " <<missing ECDHE-ECDSA-* cipher>>",
    'EV-miss'       => " <<missing @@>>",
    'EV-large'      => " <<too large @@>>",
    'EV-subject-CN' => " <<missmatch: subject CN= and commonName>>",
    'EV-subject-host'=>" <<missmatch: subject CN= and given hostname>>",
    'no-reneg'      => " <<secure renegotiation not supported>>",
    'cert-dates'    => " <<invalid certificate date>>",
    'cert-valid'    => " <<certificate validity to large @@>>",
    'cert-chars'    => " <<invalid charcters in @@>>",
    'wildcards'     => " <<uses wildcards:",
    'gethost'       => " <<gethostbyaddr() failed>>",
    'out-target'    => "\n==== Target: @@ ====\n",
    'out-ciphers'   => "\n=== Ciphers: Checking @@ ===",
    'out-infos'     => "\n=== Informations ===",
    'out-scoring'   => "\n=== Scoring Results ===",
    'out-checks'    => "\n=== Performed Checks ===",
    'out-list'      => "=== List @@ Ciphers ===",
    'out-summary'   => "== Ciphers: Summary @@ ==",
    # hostname texts
    'host-host'     => "Given hostname",
    'host-IP'       => "IP for given hostname",
    'host-rhost'    => "Reverse resolved hostname",
    'host-DNS'      => "DNS entries for given hostname",
    # misc texts
    'cipher'        => "Cipher",
    'support'       => "supported",
    'security'      => "Security",
    'desc'          => "Description",
    'desc-check'    => "Check Result (yes is considered good)",
    'desc-info'     => "Value",
    'desc-score'    => "Score (max value 100)",

    # texts used for legacy mode; DO NOT CHANGE!
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
        'sslcipher' => { 'not' => '-?-', 'yes' => "ENABLED",     'no' => "DISABLED"  },
        'ssldiagnos'=> { 'not' => '-?-', 'yes' => "CONNECT_OK CERT_OK", 'no' => "FAILED" },
        'sslscan'   => { 'not' => '-?-', 'yes' => "Accepted",    'no' => "Rejected"  },
        'ssltest'   => { 'not' => '-?-', 'yes' => "Enabled",     'no' => "Disabled"  },
        'ssltest-g' => { 'not' => '-?-', 'yes' => "Enabled",     'no' => "Disabled"  },
        'sslyze'    => { 'not' => '-?-', 'yes' => "%s",          'no' => "SSL Alert" },
        'testsslserver'=>{'not'=> '-?-', 'yes' => "",            'no' => ""          },
        #              #----------------+------------------------+---------------------
        #                -?- means "not implemented"
        # all other text used in headers titles, etc. are defined in the
        # corresponding print functions:
        #     printtitle, print_cipherhead, printfooter, print_cipherdefault, print_ciphertotals
    },
    # Note: all other legacy texts are hardcoded, as there is no need to change them!

    # short list of used terms and acronyms, always incomplete ...
    'glossar' => {
        'AA'        => "Attribute Authority",
        'AAD'       => "additional authenticated data",
        'ADH'       => "Anonymous Diffie-Hellman",
        'Adler32'   => "hash function",
        'AEAD'      => "Authenticated Encryption with Additional Data",
        'AECDHE'    => "Anonymous Ephemeral ECDH",
        'AES'       => "Advanced Encryption Standard",
        'AIA'       => "Authority Information Access (certificate extension)",
        'AKID'      => "Authority Key IDentifier",
        'ARC4'      => "Alleged RC4 (see RC4)",
        'ARCFOUR'   => "alias for ARC4",
        'ASN'       => "Autonomous System Number",
        'ASN.1'     => "Abstract Syntax Notation One",
        'BDH'       => "Bilinear Diffie-Hellman",
        'BEAST'     => "Browser Exploit Against SSL/TLS",
        'BER'       => "Basic Encoding Rules",
        'Blowfish'  => "symmetric block cipher",
        'BREACH'    => "Browser Reconnaissance & Exfiltration via Adaptive Compression of Hypertext (a variant of CRIME)",
                    #   http://www.breachattack.com/
        'CAMELLIA'  => "Encryption algorithm by Mitsubishi and NTT",
        'CAST-128'  => "Carlisle Adams and Stafford Tavares, block cipher",
        'CAST5'     => "alias for CAST-128",
        'CAST-256'  => "Carlisle Adams and Stafford Tavares, block cipher",
        'CAST6'     => "alias for CAST-256",
        'cipher suite'  => "cipher suite is a named combination of authentication, encryption, and message authentication code algorithms",
        'CA'        => "Certificate Authority (aka root CA)",
        'CBC'       => "Cyclic Block Chaining",
        'CBC '      => "Cipher Block Chaining (sometimes)",
        'CBC  '     => "Ciplier Block Chaining (sometimes)",
        #   ^^-- spaces to make key unique
        'CCM'       => "CBC-MAC Mode",
        'CCS'       => "Change Cipher Spec (protocol)",
        'CDH'       => "?  Diffie-Hellman",
        'CDP'       => "CRL Distribution Points",
        'CEK'       => "Content Encryption Key",
        'CFB'       => "Cipher Feedback",
        'CFB3'      => "Cipher Feedback",
        'CFBx'      => "Cipher Feedback x bit mode",
        'CHAP'      => "Challenge Handshake Authentication Protocol",
        'CKA'       => "", # PKCS#11
        'CKK'       => "", # PKCS#11
        'CKM'       => "", # PKCS#11
        'CMAC'      => "Cipher-based MAC",
        'CMP'       => "X509 Certificate Management Protocol",
        'CMS'       => "Cryptographic Message Syntax",
        'CMVP'      => "Cryptographic Module Validation Program (NIST)",
        'CN'        => "Common Name",
        'CP'        => "Certificate Policy (certificate extension)",
        'CPD'       => "Certificate Policy Definitions",
        'CPS'       => "Certification Practice Statement",
        'CRC'       => "Cyclic Redundancy Check",
        'CRIME'     => "Compression Ratio Info-leak Made Easy (Exploit SSL/TLS)",
        'CRL'       => "Certificate Revocation List",
        'CSP'       => "Certificate Service Provider",
        'CSP '      => "Critical Security Parameter (used in FIPS 140-2)",
        'CSR'       => "Certificate Signing Request",
        'CP'        => "Certificate Transparency",
        'CTL'       => "Certificate Trust Line",
        'CTR'       => "Counter Mode (sometimes: CM; block cipher mode)",
        'CTS'       => "Cipher Text Stealing",
        'CWC'       => "CWC Mode (Carter-Wegman + CTR mode; block cipher mode)",
        'DDH'       => "?discrete? Diffie-Hellman",
        'DER'       => "Distinguished Encoding Rules",
        'DES'       => "Data Encryption Standard",
        'DESede'    => "alias for 3DES ?java only?",
        '3DES'      => "Tripple DES (168 bits)",
        '3DES-EDE'  => "alias for 3DES",
        '3TDEA'     => "Three-key  Tripple DEA (sometimes: Tripple DES; 168 bits)",
        '2TDEA'     => "Double-key Tripple DEA (sometimes: Double DES; 112 bits)",
        'D5'        => "Verhoeff's Dihedral Group D5 Check",
        'DANE'      => "DNS-based Authentication of Named Entities",
        'DDH'       => "Decisional Diffie-Hellman (Problem)",
        'DEA'       => "Data Encryption Algorithm (sometimes a synonym for DES)",
        'DECIPHER'  => "synonym for decryption",
        'DER'       => "Distinguished Encoding Rules",
        'DH'        => "Diffie-Hellman",
        'DHE'       => "Diffie-Hellman ephemeral", # historic acronym, often used, mainly in openssl
        'DLIES'     => "Discrete Logarithm Integrated Encryption Scheme",
        'DPA'       => "Dynamic Passcode Authentication (see CAP)",
        'DRBG'      => "Deterministic Random Bit Generator",
        'DSA'       => "Digital Signature Algorithm",
        'DSS'       => "Digital Signature Standard",
        'DTLS'      => "Datagram TLS",
        'DTLSv1'    => "Datagram TLS 1.0",
        'DV'        => "Domain Validation",
        'DV-SSL'    => "Domain Validated Certificate",
        'EAP'       => "Extensible Authentication Protocol",
        'EAP-PSK'   => "Extensible Authentication Protocol using a Pre-Shared Key",
        'EAX'       => "EAX Mode (block cipher mode)",
        'EAXprime'  => "alias for EAX Mode",
        'EC'        => "Elliptic Curve",
        'ECB'       => "Electronic Code Book (Mode)",
        'ECC'       => "Elliptic Curve Cryptography",
        'ECDH'      => "Elliptic Curve Diffie-Hellman",
        'ECDHE'     => "Ephemeral ECDH",
        'ECDSA'     => "Elliptic Curve Digital Signature Algorithm",
        'ECGDSA'    => "Elliptic Curve ??? DSA",
        'ECIES'     => "Elliptic Curve Integrated Encryption Scheme",
        'ECKA'      => "Elliptic Curve Key Agreement",
        'ECKA-EG'   => "Elliptic Curve Key Agreement of ElGamal Type",
        'ECKDSA'    => "Elliptic Curve ??? DSA",
        'ECMQV'     => "Elliptic Curve Menezes-Qu-Vanstone",
        'EDE'       => "Encryption-Decryption-Encryption",
        'EDH'       => "Ephemeral Diffie-Hellman", # official acronym
        'ElGamal'   => "asymmetric block cipher",
        'ENCIPHER'  => "synonym for encryption",
        'ESP'       => "Encapsulating Security Payload",
        'EV'        => "Extended Validation",
        'EV-SSL'    => "Extended Validation Certificate",
        'FEAL'      => "Fast Data Encryption Algorithm",
        'FFC'       => "Finite Field Cryptography",
        'FIPS'      => "Federal Information Processing Standard",
        'FIPS46-2'  => "FIPS Data Encryption Standard (DES)",
        'FIPS73'    => "FIPS Guidelines for Security of Computer Applications",
        'FIPS140-2' => "FIPS Security Requirements for Cryptographic Modules",
        'FIPS140-3' => "proposed revision of FIPS 140-2",
        'FIPS180-3' => "FIPS Secure Hash Standard",
        'FIPS186-3' => "FIPS Digital Signature Standard (DSS)",
        'FIPS197'   => "FIPS Advanced Encryption Standard (AES)",
        'FIPS198-1' => "FIPS The Keyed-Hash Message Authentication Code (HMAC)",
        'FQDN'      => "Fully-qualified Domain Name",
        'FZA'       => "FORTEZZA",
        'G-DES'     => "??? DES",
        'GCM'       => "Galois/Counter Mode (block cipher mode)",
        'GHASH'     => "Hash funtion used in GCM",
        'GMAC'      => "MAC for GCM",
        'GOST'      => "Gossudarstwenny Standard",
        'Grainv1'   => "stream cipher (64 bit IV)",
        'Grainv128' => "stream cipher (96 bit IV)",
        'HAVAL'     => "one-way hashing",
        'HAS-160'   => "hash function",
        'HAS-V'     => "hash function",
        'HC128'     => "stream cipher",
        'HC256'     => "stream cipher",
        'HIBE'      => "hierarchical identity-based encryption",
        'HMAC'      => "keyed-Hash Message Authentication Code",
        'HMQV'      => "h? Menezes-Qu-Vanstone",
        'HSM'       => "Hardware Security Module",
        'HSTS'      => "HTTP Strict Transport Security",
        'HTOP'      => "HMAC-Based One-Time Password",
        'IAPM'      => "Integrity Aware Parallelizable Mode (block cipher mode of operation)",
        'ICM'       => "Integer Counter Mode (alias for CTR)",
        'IDEA'      => "International Data Encryption Algorithm",
        'IFC'       => "Integer Factorization Cryptography",
        'ISAKMP'    => "Internet Security Association and Key Management Protocol",
        'IV'        => "Initialization Vector",
        'JSSE'      => "Java Secure Socket Extension",
        'KEA'       => "Key Exchange Algorithm (alias for FORTEZZA-KEA)",
        'KEK'       => "Key Encryption Key",
        'KSK'       => "Key Signing Key", # DNSSEC
        'Lucky 13'  => "Break SSL/TLS Protocol",
        'MARS'      => "",
        'MAC'       => "Message Authentication Code",
        'MEK'       => "Message Encryption Key",
        'MD2'       => "Message Digest 2",
        'MD4'       => "Message Digest 4",
        'MD5'       => "Message Digest 5",
        'MISTY1'    => "block cipher algorithm",
        'MQV'       => "Menezes-Qu-Vanstone (authentecated key agreement",
        'NTLM'      => "NT Lan Manager. Microsoft Windows challenge-response authentication method.",
        'NPN'       => "Next Protocol Negotiation",
        'Neokeon'   => "symmetric block cipher algorithm",
        'NSS'       => "Network Security Services",
        'NULL'      => "no encryption",
        'OAEP'      => "Optimal Asymmetric Encryption Padding",
        'OFB'       => "Output Feedback",
        'OCB'       => "Offset Codebook Mode (block cipher mode of operation)",
        'OFBx'      => "Output Feedback x bit mode",
        'OID'       => "Object Identifier",
        'OTP'       => "One Time Pad",
        'OCSP'      => "Online Certificate Status Protocol",
        'OCSP stapling' => "formerly known as: TLS Certificate Status Request",
        'OMAC'      => "One-Key CMAC, aka CBC-MAC",
        'OMAC1'     => "same as CMAC",
        'OV'        => "Organisational Validation",
        'OV-SSL'    => "Organisational Validated Certificate",
        'P12'       => "see PKCS#12",
        'P7B'       => "see PKCS#7",
        'PACE'      => "Password Authenticated Connection Establishment",
        'PAKE'      => "Password Authenticated Key Exchange",
        'PBE'       => "Password Based Encryption",
        'PC'        => "Policy Constraints (certificate extension)",
        'PCBC'      => "Propagating Cipher Block Chaining",
        'PEM'       => "Privacy Enhanced Mail",
        'PFS'       => "Perfect Forward Secrecy",
        'PFX'       => "see PKCS#12",
#       'PFX'       => "Personal Information Exchange", # just for info
        'PII'       => "Personally Identifiable Information",
        'PKCS'      => "Public Key Cryptography Standards",
        'PKCS1'     => "PKCS #1: RSA Encryption Standard",
        'PKCS6'     => "PKCS #6: RSA Extended Certificate Syntax Standard",
        'PKCS7'     => "PKCS #7: RSA Cryptographic Message Syntax Standard",
        'PKCS8'     => "PKCS #8: RSA Private-Key Information Syntax Standard",
        'PKCS11'    => "PKCS #11: RSA Cryptographic Token Interface Standard (keys in hardware devices, cards)",
        'PKCS12'    => "PKCS #12: RSA Personal Information Exchange Syntax Standard (public + private key stored in files)",
        'PKI'       => "Public Key Infrastructure",
        'PKIX'      => "Internet Public Key Infrastructure Using X.509",
        'PM'        => "Policy Mappings (certificate extension)",
        'PMAC'      => "Parallelizable MAC",
        'Poly1305-AES'  => "MAC (by D. Bernstein)",
        'POP'       => "Proof of Possession",
        'PRF'       => "pseudo-random function",
        'PSK'       => "Pre-shared Key",
        'RA'        => "Registration Authority (aka Registration CA)",
        'Rabbit'    => "stream cipher algorithm",
        'RADIUS'    => "Remote Authentication Dial-In User Service",
        'Radix-64'  => "alias for Base-64",
        'RBG'       => "Random Bit Generator",
        'RC2'       => "Rivest Cipher 2, block cipher by Ron Rivest",
        'RC4'       => "Rivest Cipher 4, stream cipher (aka Ron's Code)",
        'RC5'       => "Rivest Cipher 5, block cipher (32 bit word)",
        'RC5-64'    => "Rivest Cipher 5, block cipher (64 bit word)",
        'RC6'       => "Rivest Cipher 6",
        'RCSU'      => "Reuters' Compression Scheme for Unicode (aka SCSU)",
        'Rijndael'  => "symmetric block cipher algorithm",
        'RIPEMD'    => "RACE Integrity Primitives Evaluation Message Digest",
        'RNG'       => "Random Number Generator",
        'ROT-13'    => "see XOR",
        'RTP'       => "Real-time Transport Protocol",
        'RSA'       => "Rivest Sharmir Adelman (public key cryptographic algorithm)",
        'RSS-14'    => "Reduced Space Symbology, see GS1",
        'RTN'       => "Routing transit number",
        'SA'        => "Subordinate Authority (aka Subordinate CA)",
        'SAFER'     => "Secure And Fast Encryption Routine, block cipher",
        'Salsa20'   => "stream cipher",
        'SAM'       => "syriac abbreviation mark",
        'SAN'       => "Subject Alternate Name",
        'SBCS'      => "single-byte character set",
        'SCEP'      => "Simple Certificate Enrollment Protocol",
        'SCSU'      => "Standard Compression Scheme for Unicode (compressed UTF-16)",
        'SCVP'      => "Server-Based Certificate Validation Protocol",
        'SDES'      => "Security Description Protokol",
        'SEED'      => "128-bit Symmetric Block Cipher",
        'Serpent'   => "symmetric key block cipher",
        'SGC'       => "Server-Gated Cryptography",
        'SHA'       => "Secure Hash Algorithm",
        'SHA-0'     => "Secure Hash Algorithm (insecure version before 1995)",
        'SHA-1'     => "Secure Hash Algorithm (since 1995)",
        'SHA-2'     => "Secure Hash Algorithm (since 2002)",
        'SHA-224'   => "Secure Hash Algorithm (224 bit)",
        'SHA-256'   => "Secure Hash Algorithm (256 bit)",
        'SHA-384'   => "Secure Hash Algorithm (384 bit)",
        'SHA-512'   => "Secure Hash Algorithm (512 bit)",
        'SHA1'      => "alias for SHA-1 (160 bit)",
        'SHA2'      => "alias for SHA-2 (224, 256, 384 or 512 bit)",
        'SHS'       => "Secure Hash Standard",
        'SIA'       => "Subject Information Access (certificate extension)",
        'SIC'       => "Segmented Integer Counter (alias for CTR)",
        'Skein'     => "hash function",
        'SKID'      => "subject key ID (certificate extension)",
        'Skipjack'  => "encryption algorithm specified as part of the Fortezza",
        'Snefu'     => "hash function",
        'SNI'       => "Server Name Indication",
        'SPDY'      => "Google's application-layer protocol an top of SSL",
        'Square'    => "block cipher",
        'SRP'       => "Secure Remote Password protocol",
        'SRTP'      => "Secure RTP",
        'SSL'       => "Secure Sockets Layer",
        'SSLv2'     => "Secure Sockets Layer Version 2",
        'SSLv3'     => "Secure Sockets Layer Version 3",
        'SSPI'      => "Security Support Provider Interface",
        'SST'       => "Serialized Certificate Store format",
        'TCB'       => "Trusted Computing Base",
        'TDEA'      => "Tripple DEA",
        'TEA'       => "Tiny Encryption Algorithm",
        'TEK'       => "Traffic Encryption Key",
        'Tiger'     => "hash function",
        'TIME'      => "Timing Info-leak Made Easy (Exploit SSL/TLS)",
#        'TIME'      => "A Perfect CRIME? TIME Will Tell",
        'Threefish' => "hash function",
        'TR-02102'  => "Technische Richtlinie 02102 (des BSI)",
        'TSP'       => "trust-Management Service Provider",
        'TLS'       => "Transport Layer Security",
        'TLSA'      => "TLS Trus Anchors",
        'TLSv1'     => "Transport Layer Security version 1",
        'TSK'       => "Transmission Security Key",
        'TTP'       => "trusted Third Party",
        'Twofish'   => "symmetric key block cipher",
        'UC'        => "Unified Communications (SSL Certificate using SAN)",
        'UCC'       => "Unified Communications Certificate (rarley used)",
        'UMAC'      => "Universal hashing MAC",
        'VMAC'      => "Universal hashing MAC (variant of UMAC?)",
        'VMPC'      => "stream cipher",
        'WHIRLPOOL' => "hash function",
        'X.680'     => "X.680: ASN.1",
        'X.509'     => "X.509: The Directory - Authentication Framework",
        'X680'      => "X.680: ASN.1",
        'X509'      => "X.509: The Directory - Authentication Framework",
        'XCBC'      => "variant of CMAC",
        'XKMS'      => "XML Key Management Specification",
        'XMLSIG'    => "XML-Signature Syntax and Processing",
        'XTEA'      => "extended Tiny Encryption Algorithm",
        'XUDA'      => "Xcert Universal Database API",
        'XXTEA'     => "enhanced/corrected Tiny Encryption Algorithm",
        'ZLIB'      => "Lossless compression file format",
        'ZSK'       => "Zone Signing Key", # DNSSEC
    },
    'mnemonic'      => { # NOT YET USED
        'example'   => "TLS_DHE_DSS_WITH_3DES-EDE-CBC_SHA",
        'description'=> "TLS Version _ key establishment algorithm _ digital signature algorithm _ WITH _ confidentility algorithm _ hash function",
        'explain'   => "TLS Version1 _ Ephemeral DH key agreement _ DSS which implies DSA _ WITH _ 3DES encryption in CBC mode _ SHA for HMAC"
    },
    # RFC 2412: OAKLEY Key Determination Protocol (PFS - Perfect Forward Secrec')
    #           alle *DH* sind im Prinzip PFS.
    #           wird manchmal zusaetzlich mit DHE bezeichnet, wobei E für ephemeral
    #           also flüchtige, vergängliche Schlüssel steht
    #           D.H. ECDHE_* und DHE_* an den Anfang der Cipherliste stellen, z.B.
    #                TLS_ECDHE_RSA_WITH_RC4_128_SHA
    #                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    #                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    #                TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA 
    #           http://en.wikipedia.org/wiki/Perfect_forward_secrecy
    # RFC 2818: ? (Namenspruefung)
    # RFC 2712: TLSKRB: Addition of Kerberos Cipher Suites to Transport Layer Security (TLS)
    # RFC 2986: PKCS#10
    # RFC 5967: PKCS#10
    # RFC 3268:  TLSAES: Advanced Encryption Standard (AES) Ciphersuites for Transport Layer Security (TLS)
    # RFC 5081: TLSPGP: Using OpenPGP Keys for Transport Layer Security (TLS) Authentication
    # RFC 4279:  TLSPSK: Pre-Shared Key Ciphersuites for Transport Layer Security (TLS)
    # RFC 4492:  TLSECC: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
    # RFC 3749: TLS Compression Method http://tools.ietf.org/html/rfc3749
    # RFC 3943: TLS Protocol Compression Using Lempel-Ziv-Stac (LZS) http://tools.ietf.org/html/rfc3943
    # RFC 2246:  TLS Version 1
    # RFC 3268:  TLS Version 1 AES
    # RFC 4132:  TLS Version 1 Camellia
    # RFC 4162: TLS Version 1 SEED
    # RFC 4346:  TLS Version 1.1
    # RFC 5246:  TLS Version 1.2  http://tools.ietf.org/html/rfc5346
    # RFC 3546: TLS Extensions
    # RFC 4366: TLS Extensions
    #               AKID - authority key identifier
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
    # RFC 2246: TLS protocol version 1.0 http://tools.ietf.org/html/rfc2246,
    # RFC 6101: SSL protocol version 3.0 http://tools.ietf.org/html/rfc6101,
    # RFC 6460: ?
    # RFC 6125: Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS)
    # RFC 4210: X509 PKI Certificate Management Protocol (CMP)
    # RFC 3739: x509 PKI Qualified Certificates Profile; EU Directive 1999/93/EC
    # RFC 4158: X509 PKI Certification Path Building
    # RFC 5055: Server-Based Certificate Validation Protocol (SCVP)
    # RFC 2560: Online Certificate Status Protocol (OCSP)
    # RFC 5019: simplified RFC 2560
    # RFC 4387: X509 PKI Operational Protocols: Certificate Store Access via HTTP
    # RFC 5746: TLS Renegotiation Indication Extension http://tools.ietf.org/html/rfc5746,

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
    # TLS session resumption problem with session ticket
    #        see https://www.imperialviolet.org/2011/11/22/forwardsecret.html
    #        "Since the session ticket contains the state of the session, and
    #         thus keys that can decrypt the session, it too must be protected
    #         by ephemeral keys. But, in order for session resumption to be
    #         effective, the keys protecting the session ticket have to be kept
    #         around for a certain amount of time: the idea of session resumption
    #         is that you can resume the session in the future, and you can't
    #         do that if the server can't decrypt the ticket!
    #         So the ephemeral, session ticket keys have to be distributed to
    #         all the frontend machines, without being written to any kind of
    #         persistent storage, and frequently rotated."
    #        see also https://www.imperialviolet.org/2013/06/27/botchingpfs.html

    # just for information, some configuration options in Firefox
    'firefox' => { # NOT YET USED
        'browser.cache.disk_cache_ssl'        => "En-/Disable caching of SSL pages",        # false
        'security.enable_tls_session_tickets' => "En-/Disable Session Ticket extension",    # false
        'security.ssl.allow_unrestricted_renego_everywhere__temporarily_available_pref' =>"",# false
        'security.ssl.renego_unrestricted_hosts' => '??', # Liste
        'security.ssl.require_safe_negotiation'  => "",   # true
        'security.ssl.treat_unsafe_negotiation_as_broken' => "", # true
        'security.ssl.warn_missing_rfc5746'      => "",   # true
        'pfs.datasource.url' => '??', #
        'browser.identity.ssl_domain_display'    => "coloured non EV-SSL Certificates", # true
        },
    'IE' => { # NOT YET USED
        'HKLM\\...' => "sequence of ciphers", #
        },

); # %text

$cmd{'extopenssl'} = 0 if ($^O =~ m/MSWin32/); # tooooo slow on Windows
$cmd{'extsclient'} = 0 if ($^O =~ m/MSWin32/); # tooooo slow on Windows
$cfg{'done'}->{'dbxfile'}++ if ($#dbx > 0);
$cfg{'done'}->{'rc-file'}++ if ($#rc_argv > 0);

# save hardcoded settings (command lists, texts); used in o-saft-dbx.pm
our %org = (
    'cmd-check' => $cfg{'cmd-check'},
    'cmd-http'  => $cfg{'cmd-http'},
    'cmd-info'  => $cfg{'cmd-info'},
    'cmd-quick' => $cfg{'cmd-quick'},
    #'text'      => { %text }, no need for 'glossar' here
); # %org

#_init_all();  # call delayed to prevent warning of prototype check with -w

# internal functions
# -------------------------------------
sub _dprint   { local $\ = "\n"; print "#dbx# ", join(" ", @_); }
sub _dbx      { _dprint(@_); } # alias for _dprint

# debug functions are defined in o-saft-dbx.pm and loaded on demand
sub _yeast_init()  {}
sub _yeast_exit()  {}
sub _yeast_args()  {}
sub _yeast_data()  {}
sub _yeast($) {}
sub _y_ARG    {}
sub _y_CMD    {}
sub _v_print  {}
sub _v2print  {}
sub _v3print  {}
sub _v4print  {}
sub _vprintme {}
sub _trace($) {}
# if --trace-arg given
sub _trace_1arr($) {}

sub _initchecks_score()  {
    # set all default score values here
    $checks{$_}->{score} = 10 foreach (keys %checks);
    # some special values %checks{'sts_maxage*'}
    $checks{'sts_maxage0d'}->{score} =   0; # very weak
    $checks{'sts_maxage1d'}->{score} =  10; # weak
    $checks{'sts_maxage1m'}->{score} =  20; # low
    $checks{'sts_maxage1y'}->{score} =  70; # medium
    $checks{'sts_maxagexy'}->{score} = 100; # high
    $checks{'TLSv1-HIGH'}  ->{score} =   0;
    $checks{'TLSv11-HIGH'} ->{score} =   0;
    $checks{'TLSv12-HIGH'} ->{score} =   0;
    $checks{'DTLSv1-HIGH'} ->{score} =   0;
    foreach (keys %checks) {
        $checks{$_}->{score} = 90 if (m/WEAK/i);
        $checks{$_}->{score} = 30 if (m/LOW/i);
        $checks{$_}->{score} = 10 if (m/MEDIUM/i);
    }
} # _initchecks_score

sub _initchecks_val()  {
    # set all default score values here
    $checks{$_}->{val}   = "" foreach (keys %checks);
    # some special values %checks{'sts_maxage*'}
    $checks{'sts_maxage0d'}->{val} =        0;
    $checks{'sts_maxage1d'}->{val} =    86400;  # day
    $checks{'sts_maxage1m'}->{val} =  2592000;  # month
    $checks{'sts_maxage1y'}->{val} = 31536000;  # year
    $checks{'sts_maxagexy'}->{val} = 99999999;
    foreach (keys %checks) {
        $checks{$_}->{val}   =  0 if (m/$cfg{'regex'}->{'cmd-sizes'}/);
        $checks{$_}->{val}   =  0 if (m/$cfg{'regex'}->{'SSLprot'}/);
    }
} # _initchecks_val

sub _init_all()  {
    # set all default score values here
    $cfg{'done'}->{'init_all'}++;
    _trace("_init_all()");
    _initchecks_score();
    _initchecks_val();
} # _init_all
_init_all();   # initialize defaults in %checks (score, val)

sub _resetchecks() {
    # reset values
    foreach (keys %{$cfg{'done'}}) {
        next if (!m/^check/);  # only reset check*
        $cfg{'done'}->{$_} = 0;
    }
    _initchecks_val();
}

sub _find_cipher_name($) {
    # check if given cipher name is a known cipher
    # checks in %cipher_names if nof found in %ciphers
    my $cipher  = shift;
    return $cipher if (grep(/^$cipher/, %ciphers)>0);
    _trace("_find_cipher_name: search $cipher");
    foreach (keys %cipher_names) {
        return $cipher_names{$_}[1] if ($cipher =~ m/$_/);
        return $cipher_names{$_}[1] if ($cipher_names{$_}[0] =~ /$cipher/);
    }
    # nothing found yet, try more lazy match
    foreach (keys %cipher_names) {
        if ($_ =~ m/$cipher/) {
            warn("**WARNING: partial match for cipher name found '$cipher'");
            return $cipher_names{$_}[1];
        }
    }
    return "";
} # _find_cipher_name

sub _prot_cipher($$)   { return " " . join(":", @_); }
    # return string consisting of given parameters separated by : and prefixed with a space
    # (mainly used to concatenate SSL Version and cipher suite name)

sub _getscore($$$)     {
    # return score value from given hash; 0 if given value is empty, otherwise score to given key
    my $key     = shift;
    my $value   = shift || "";
    my $hashref = shift;# list of checks
    my %hash    = %$hashref;
    return 0 if ($value eq "");
    my $score   = $hash{$key}->{score} || 0;
    _trace("_getscore: $key : '$value' = ". $score);
    return $score;
} # _getscore

sub _cfg_set($$) {
    # set value in configuration %checks, %text
    # $typ must be any of: CFG-text, CFG-score, CFG-cmd-*
    # if given value is a file, read settings from that file
    # otherwise given value must be KEY=VALUE format;
    my $typ = shift;    # type of config value to be set
    my $arg = shift;    # KEY=VAL or filename
    my ($key, $val);
    no warnings qw(prototype); # avoid: main::_cfg_set() called too early to check prototype at ...
    _trace(" _cfg_set($typ, ){");
    if ($typ !~ m/^CFG-(cmd|checks?|data|text|scores?)$/) {
        warn("**WARNING: unknown configuration key '$typ'; ignored");
        goto _CFG_RETURN;
    }
    if (($arg =~ m|^[a-zA-Z0-9,._+#()\/-]+|) and (-f "$arg")) { # read from file
        # we're picky about valid filenames: only characters, digits and some
        # special chars (this should work on all platforms)
        if ($cgi == 0) {
            warn("**WARNING: configuration files are not read in CGI mode; ignored");
            return;
        }
        _trace(" _cfg_set: read $arg \n");
        my $line ="";
        open(FID, $arg) && do {
            push(@dbxfile, $arg);
            _print_read("configuration", $arg) if($cfg{'out_header'} > 0);
            while ($line = <FID>) {
                #
                # format of each line in file must be:
                #    Lines starting with  =  are comments and ignored.
                #    Anthing following (and including) a hash is a comment
                #    and ignored. Empty lines are ignored.
                #    Settings must be in format:  key=value
                #       where white spaces are allowed arround =
                chomp $line;
                $line =~ s/\s*#.*$// if ($typ !~ m/^CFG-text/i);
                    # remove trailing comments, but CFG-text may contain #
                next if ($line =~ m/^\s*=/);# ignore our header lines (since 13.12.11)
                next if ($line =~ m/^\s*$/);# ignore empty lines
                _trace(" _cfg_set: set " . $line . "\n");
                _cfg_set($typ, $line);
            }
            close(FID);
            goto _CFG_RETURN;
        };
        warn("**WARNING: cannot open '$arg': $! ; ignored");
        return;
    } # read file

    ($key, $val) = split(/=/, $arg, 2); # left of first = is key
    $key =~ s/[^a-zA-Z0-9_?=+-]*//g;    # strict sanatize key

    if ($typ eq 'CFG-cmd') {            # set new list of commands $arg
        $typ = 'cmd-' . $key ;# the command to be set, i.e. cmd-http, cmd-sni, ...
        _trace(" _cfg_set(KEY=$key, CMD=$val)\n");
        @{$cfg{$typ}} = ();
        push(@{$cfg{$typ}}, split(/\s+/, $val));
        foreach $key (@{$cfg{$typ}}) {  # check for mis-spelled commands
            next if (_is_hashkey($key, \%checks) > 0);
            next if (_is_hashkey($key, \%data) > 0);
            next if (_is_intern( $key) > 0);
            next if (_is_member( $key, \@{$cfg{'cmd-NL'}}) > 0);
            warn("**WARNING: unknown command '$key' for '$typ'; ignored");
        }
    }

    # invalid keys are silently ignored (perl is that clever:)

    if ($typ eq 'CFG-score') {          # set new score value
        _trace(" _cfg_set(KEY=$key, SCORE=$val)\n");
        if ($val !~ m/^(\d\d?|100)$/) { # allow 0 .. 100
            warn("**WARNING: invalid score value '$val'; ignored");
            goto _CFG_RETURN;
        }
        $checks{$key}->{score} = $val if ($checks{$key});
    }

    if ($typ =~ /^CFG-(checks?|data|scores|text)/) {
        $val =~ s/(\\n)/\n/g;
        $val =~ s/(\\r)/\r/g;
        $val =~ s/(\\t)/\t/g;
        _trace(" _cfg_set(KEY=$key, LABEL=$val).\n");
        $checks{$key}->{txt} = $val if ($typ =~ /^CFG-check/);
        $data{$key}  ->{txt} = $val if ($typ =~ /^CFG-data/);
        $text{$key}          = $val if ($typ =~ /^CFG-text/);
        $scores{$key}->{txt} = $val if ($typ =~ /^CFG-scores/);
        $scores{$key}->{txt} = $val if ($key =~ m/^check_/); # contribution to lazy usage
    }

    _CFG_RETURN:
    _trace(" _cfg_set }");
    return;
} # _cfg_set

# check functions for array members and hash keys
sub __SSLinfo($$$) {
    # wrapper for Net::SSLinfo::*() functions
    # Net::SSLinfo::*() return raw data, depending on $cfg{'format'}
    # these values will be converted to o-saft's preferred format
    my $cmd = shift;
    my $val = "<<__SSLinfo: unknown command: '$cmd'>>";
    $val =  Net::SSLinfo::fingerprint(      $_[0], $_[1]) if ($cmd eq 'fingerprint');
    $val =  Net::SSLinfo::fingerprint_hash( $_[0], $_[1]) if ($cmd eq 'fingerprint_hash');
    $val =  Net::SSLinfo::fingerprint_sha1( $_[0], $_[1]) if ($cmd eq 'fingerprint_sha1');
    $val =  Net::SSLinfo::fingerprint_md5(  $_[0], $_[1]) if ($cmd eq 'fingerprint_md5');
    $val =  Net::SSLinfo::pubkey_value(     $_[0], $_[1]) if ($cmd eq 'pubkey_value');
    $val =  Net::SSLinfo::sigkey_value(     $_[0], $_[1]) if ($cmd eq 'sigkey_value');
    $val =  Net::SSLinfo::extensions(       $_[0], $_[1]) if ($cmd =~ /ext(?:ensions|_)/);
    if ($cmd =~ m/ext_/) {
        # all following ar part of Net::SSLinfo::extensions(), now extract parts
        # The extension section in the certificate starts with
        #    X509v3 extensions:
        # then each extension starts with a string prefixed by  X509v3
        # except following:
        #    Authority Information Access
        #    Netscape Cert Type
        # these are handled in regex below which matches next extension, if any.
        $val .= " X509";# add string to match last extenion also
        my $rex = '\s*(.*?)(?:X509|Authority|Netscape).*';
        my $ext = $val;
        $val =~ s#.*?Authority Information Access:$rex#$1#ms    if ($cmd eq 'ext_authority');
        $val =~ s#.*?Authority Key Identifier:$rex#$1#ms        if ($cmd eq 'ext_authorityid');
        $val =~ s#.*?Basic Constraints:$rex#$1#ms               if ($cmd eq 'ext_constrains');
        $val =~ s#.*?Key Usage:$rex#$1#ms                       if ($cmd eq 'ext_keyusage');
        $val =~ s#.*?Subject Key Identifier:$rex#$1#ms          if ($cmd eq 'ext_subjectkeyid');
        $val =~ s#.*?Certificate Policies:$rex#$1#ms            if ($cmd =~ /ext_cps/);
        $val =~ s#.*?CPS\s*:\s*([^\s\n]*).*#$1#ms               if ($cmd eq 'ext_cps_cps');
        $val =~ s#.*?Policy\s*:\s*(.*?)(?:CPS|User).*#$1#ims    if ($cmd eq 'ext_cps_policy');
        $val =~ s#.*?CRL Distribution Points:$rex#$1#ms         if ($cmd =~ /ext_crl/);
        $val =~ s#.*?Extended Key Usage:$rex#$1#ms              if ($cmd eq 'ext_extkeyusage');
        $val =~ s#.*?Netscape Cert Type:$rex#$1#ms              if ($cmd eq 'ext_certtype');
        $val =~ s#.*?Issuer Alternative Name:$rex#$1#ms         if ($cmd eq 'ext_issuer');
        #$val =~ s#.*?(URI\s*:.*)#$1#ms                          if ($cmd eq 'ext_crl_crl');
# ToDo: previous fails, reason unknown
        $val =  "" if ($ext eq $val);    # nothing changed, then expected pattern is missing
    }
    if ($cmd =~ /ext(?:ensions|_)/) {
        # grrr, formatting extensions is special, take care for traps ...
        if ($cfg{'format'} ne "raw") {
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
    if ($cfg{'format'} ne "raw") {
        $val =  "" if (!defined $val);  # avoid warnings
        $val =~ s/\n\s+//g; # remove trailing spaces
        $val =~ s/\n/ /g;
        $val =~ s/\s\s+//g; # remove multiple spaces
        $val =~ s/([0-9a-f]):([0-9a-f])/$1$2/ig; # remove : inside hex (quick&dirty)
    }
    return $val;
}; # __SSLinfo

sub _subst($$)         { my $is=shift; $is=~s/@@/$_[0]/;  return $is; }
    # return given text with '@@' replaced by given value
sub _need_cipher()     { my $is=join("|", @{$cfg{'do'}}); return grep(/^($is)$/,  @{$cfg{'need_cipher'}}); }
    # returns >0 if any of the given commands ($cfg{'do'}) is listed in $cfg{'need_cipher'}
sub _need_checkssl()   { my $is=join("|", @{$cfg{'do'}}); return grep(/^($is)$/,  @{$cfg{'need_checkssl'}}); }
    # returns >0 if any of the given commands ($cfg{'do'}) is listed in $cfg{'need_checkssl'}
sub _is_hashkey($$)    { my $is=shift; return grep({lc($is) eq lc($_)} keys %{$_[0]}); }
sub _is_member($$)     { my $is=shift; return grep({lc($is) eq lc($_)}      @{$_[0]}); }
sub _is_do($)          { my $is=shift; return _is_member($is, \@{$cfg{'do'}}); }
sub _is_intern($)      { my $is=shift; return _is_member($is, \@{$cfg{'cmd-intern'}}); }
sub _is_hexdata($)     { my $is=shift; return _is_member($is, \@{$cfg{'data_hex'}});   }
sub _is_call($)        { my $is=shift; return _is_member($is, \@{$cmd{'call'}}); }
    # returns >0 if any of the given string is listed in $cfg{*}

# some people prefer to use a getter function to get data from objects
# each function returns a spcific value (column) from the %cipher table
# see %ciphers_desc about description of the columns
sub get_cipher_sec($)  { my $c=$_[0]; return $ciphers{$c}[0] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_ssl($)  { my $c=$_[0]; return $ciphers{$c}[1] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_enc($)  { my $c=$_[0]; return $ciphers{$c}[2] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_bits($) { my $c=$_[0]; return $ciphers{$c}[3] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_mac($)  { my $c=$_[0]; return $ciphers{$c}[4] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_auth($) { my $c=$_[0]; return $ciphers{$c}[5] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_keyx($) { my $c=$_[0]; return $ciphers{$c}[6] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_score($){ my $c=$_[0]; return $ciphers{$c}[7] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_tags($) { my $c=$_[0]; return $ciphers{$c}[8] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_desc($) { my $c=$_[0]; my @c = @{$ciphers{$c}}; shift @c; return @c if (grep(/^$c/, %ciphers)>0); return ""; }

# check functions
# -------------------------------------
sub _setvalue($){ return ($_[0] eq "") ? 'yes' : 'no (' . $_[0] . ')'; }
    # return 'yes' if given value is empty, return 'no' otherwise
sub _isbeast($$){
    # return given cipher if vulnerable to BEAST attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return ""      if ($ssl    !~ /(SSLv3|TLSv11?)/); # SSLv2 and TLSv1.2 not vulnerable to BEAST
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'BEAST'}/);
    return "";
} # _isbeast
#sub _isbreach($)       { return "NOT YET IMPLEMEMNTED"; }
sub _isbreach($){
    return 0;
# ToDo: checks
    # To be vulnerable, a web application must:
    #      Be served from a server that uses HTTP-level compression
    #      Reflect user-input in HTTP response bodies
    #      Reflect a secret (such as a CSRF token) in HTTP response bodies
    #      *  agnostic to the version of TLS/SSL
    #      *  does not require TLS-layer compression
    #      *  works against any cipher suite
    #      *  can be executed in under a minute
}
sub _iscrime($) { return ($_[0] =~ /$cfg{'regex'}->{'nocompression'}/) ? "" : $_[0] . " "; }
    # return compression if available, empty string otherwise
sub _istime($)  { return 0; } # ToDo: checks
sub _ispfs($$)  {
    # return given cipher if it does not support forward secret connections (PFS)
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    eq "SSLv2"); # PFS not possible with SSLv2
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'PFS'}/);
    return "";
} # _ispfs
sub _isrc4($) { return ($_[0] =~ /$cfg{'regex'}->{'RC4'}/) ? $_[0] . " " : ""; }
    # return given cipher if it is RC4
sub _istr02102($$) {
    # return given cipher if it is not TR-02102 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'EXPORT'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notTR-02102'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'TR-02102'}/);
# FIXME: check for SHA1 missing, which is a lazy accept, see TR-02102-2 3.2.2
    return "";
} # _istr02102
sub _isfips($$) {
    # return given cipher if it is not FIPS-140 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    ne "TLSv1");
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notFIPS-140'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'FIPS-140'}/);
    return "";
} # _isfips
sub _ispci($$)  {
    # return given cipher if it is not PCI compliant, empty string otherwise
# ToDo: DH 1024+ is PCI compliant
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    eq "SSLv2"); # SSLv2 is not PCI compliant
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notPCI'}/);
    return "";
} # _ispci

sub _usesocket($$$$) {
    # return 1 if cipher accepted by SSL connection
    # note that this is used to check for supported ciphers only, hence no
    # need for sophisticated options in new()
    my ($ssl, $host, $port, $ciphers) = @_;
    _trace("_usesocket(..., $ciphers)");
    my $sslsocket = IO::Socket::SSL->new(
        PeerAddr        => $host,
        PeerPort        => $port,
        Proto           => "tcp",
        Timeout         => $cfg{'timeout'},
    #   SSL_hostname    => $host,# for SNI
        SSL_verify_mode => 0x0,  # SSL_VERIFY_NONE => Net::SSLeay::VERIFY_NONE(); # 0
        SSL_ca_file     => undef,# see man IO::Socket::SSL
        SSL_ca_path     => undef,#  "
        SSL_version     => $ssl, # default is SSLv23
        SSL_cipher_list => $ciphers
    );
# ToDo: IO::Socket::SSL::get_cipher($sslsocket);  does not work
    if ($sslsocket) {  # connect failed, cipher not accepted
        $sslsocket->close(SSL_ctx_free => 1);
        return 1;
    }
    return 0;
} # _usesocket

sub _useopenssl($$$$) {
    # return 1 if cipher accepted by SSL connection
    my ($ssl, $host, $port, $ciphers) = @_;
    _trace("_useopenssl($ssl, ..., $ciphers)");
    $ssl = $cfg{'openssl_option_map'}->{$ssl};
    my $data = Net::SSLinfo::do_openssl("s_client $ssl -cipher $ciphers -connect", $host, $port);
    # we may get for success:
    #   New, TLSv1/SSLv3, Cipher is DES-CBC3-SHA
    _trace("_useopenssl data #{ $data }") if ($cfg{'trace'} > 1);
    return 1 if ($data =~ m#New, [A-Za-z0-9/.,-]+ Cipher is#);
    # grrrr, it's a pain that openssl changes error messages for each version
    # we may get any of following errors:
    #   TIME:error:140790E5:SSL routines:SSL23_WRITE:ssl handshake failure:.\ssl\s23_lib.c:177:
    #   New, (NONE), Cipher is (NONE)
    #   connect:errno=11004
    #   TIME:error:14077410:SSL routines:SSL23_GET_SERVER_HELLO:sslv3 alert handshake failure:s23_clnt.c:602:
    #   TIME:error:140740B5:SSL routines:SSL23_CLIENT_HELLO:no ciphers available:s23_clnt.c:367:
    # if SSL version not supported (by openssl):
    #   29153:error:140A90C4:SSL routines:SSL_CTX_new:null ssl method passed:ssl_lib.c:1453:
    # openssl 1.0.1e :
    #   # unknown messages: 139693193549472:error:1407F0E5:SSL routines:SSL2_WRITE:ssl handshake failure:s2_pkt.c:429:
    #   error setting cipher list
    #   139912973481632:error:1410D0B9:SSL routines:SSL_CTX_set_cipher_list:no cipher match:ssl_lib.c:1314:
    return 0 if ($data =~ m#New,.*?Cipher is .?NONE#);
    return 0 if ($data =~ m#SSL routines.*(?:handshake failure|null ssl method passed|no ciphers? (?:available|match))#);
    if ($data =~ m#^\s*$#) {
        warn("**WARNING: empty result from openssl; ignored");
    } else {
        warn("**WARNING: unknown result from openssl; ignored");
    }
    _trace("_useopenssl #{ $data }");
    print "**Hint: use options like: --v --trace --timeout=42";
    return 0;
} # _useopenssl

sub _get_default($$$) {
    # return default cipher from target (or local ssl if no target given)
    my $cipher = "";
    $cfg{'done'}->{'checkdefault'}++;
    _trace(" _get_default(" . ($_[0]||"") . "," . ($_[1]||"") . "," . ($_[2]||"") . ")");
    my $sslsocket = IO::Socket::SSL->new(
        PeerAddr        => $_[0],
        PeerPort        => $_[1],
        Proto           => "tcp",
        Timeout         => $cfg{'timeout'},
        SSL_version     => $_[2],
        );
    if ($sslsocket) {
        $cipher = $sslsocket->get_cipher();
        $sslsocket->close(SSL_ctx_free => 1);
    } else {
    }
    return $cipher;
} # _get_default

sub checkcipher($$) {
    #? test given cipher and add result to %check_* value
    my ($ssl, $c) = @_;
    my $risk = get_cipher_sec($c);
    # following checks add the "not compliant" or vulnerable ciphers

    # check weak ciphers
    $checks{'null'}->{val}      .= _prot_cipher($ssl, $c) if ($c =~ /NULL/);
    $checks{'adh'}->{val}       .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'ADHorDHA'}/);
    $checks{'edh'}->{val}       .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'DHEorEDH'}/);
    $checks{'export'}->{val}    .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'EXPORT'}/);
    $checks{'rc4'}->{val}       .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'RC4orARC4'}/);
    # check compliance
    $checks{'ism'}->{val}       .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'notISM'}/);
    $checks{'pci'}->{val}       .= _prot_cipher($ssl, $c) if ("" ne _ispci($ssl, $c));
    $checks{'fips'}->{val}      .= _prot_cipher($ssl, $c) if ("" ne _isfips($ssl, $c));
    $checks{'tr-02102'}->{val}  .= _prot_cipher($ssl, $c) if ("" ne _istr02102($ssl, $c));
    # check attacks
    $checks{'beast'}->{val}     .= _prot_cipher($ssl, $c) if ("" ne _isbeast($ssl, $c));
    $checks{'breach'}->{val}    .= _prot_cipher($ssl, $c) if ("" ne _isbreach($c));
    # counters
    $checks{$ssl . '--?-'}->{val}++     if ($risk =~ /-\?-/); # private marker
    $checks{$ssl . '-LOW'}->{val}++     if ($risk =~ /LOW/i);
    $checks{$ssl . '-WEAK'}->{val}++    if ($risk =~ /WEAK/i);
    $checks{$ssl . '-HIGH'}->{val}++    if ($risk =~ /HIGH/i);
    $checks{$ssl . '-MEDIUM'}->{val}++  if ($risk =~ /MEDIUM/i);
} # checkcipher

sub checkciphers($$$$$) {
    #? test target if given ciphers are accepted, results stored in global @results
    # NOTE that verbose output is printed directly (hence preceeds results)
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my $ciphers = shift;# ciphers to be checked
    my $hashref = shift;# our list of ciphers
    my %hash    = %$hashref;
    #no# $cfg{'done'}->{'checkciphers'}++;
    #no# return if ($cfg{'done'}->{'checkciphers'} > 1);
    _trace("checkciphers($ssl, .., $ciphers) {");
    my $verbose = $cfg{'verbose'};
                    # verbose==2 : _v2print() print remotely checked ciphers
                    # verbose==3 : _v3print() print processed ciphers
                    # verbose==4 : _v4print() print how cipher is processed
    local   $|  = 1;    # do not buffer (for verbosity)
    my $skip    = 0;
    my $hasecdsa= 0;    # ECDHE-ECDSA is mandatory for TR-02102-2, see 3.2.3
    my $hasrsa  = 0;    # ECDHE-RSA   is mandatory for TR-02102-2, see 3.2.3

    _v2print("check cipher $ssl: ");
    # ToDo: change logic of following loop
    #     now we loop over *our* ciphers which misses ciphers available in
    #     the local SSL implementation (if there are more)
    _y_CMD("  use socket ..")  if (0 == $cmd{'extciphers'});
    _y_CMD("  use openssl ..") if (1 == $cmd{'extciphers'});
    foreach my $c (sort {$hash{$a} cmp $hash{$b}} keys %hash) {
        _v3print("check cipher $ssl: $c");
        _v4print("check cipher $ssl: $c\t");
# ToDo:  cipher not supported by local SSL implementation
        #    if (!$cfg{'nolocal'}) {
        #        $skip++;
        #        next;
        #    }
        #    #print_cipherline($cfg{'legacy'}, $c, 'not') if (!$cfg{'disabled'}); # print with --v only
        #    push(@results, [$ssl, $c, 'not']);
        #

        if (0 >= grep(/^$c$/, split(/[ :]/, $ciphers))) {
            # cipher not to be checked
            _v4print("skip\n");
            #printf("skip\n") if ($verbose == 4);
            next;
        }
        printf(" $c")     if ($verbose == 2); # don't want _v2print() here
        _v4print("check\n");
        #dbx# _dbx "H: $host , $cfg{'host'} \n";
        my $supported = 0;

        #if (1 == _is_call('cipher-socket')) {
        if (0 == $cmd{'extciphers'}) {
            $supported = _usesocket( $ssl, $host, $port, $c);
        } else { # force openssl
            $supported = _useopenssl($ssl, $host, $port, $c);
        }
        if (0 == $supported) {
            #dbx# _dbx "\t$c\t$hash{$c}  -- $ssl  # connect failed, cipher unsupported";
            push(@results, [$ssl, $c, 'no']);
        } else {
            $checks{$ssl}->{val}++; # cipher accepted
            push(@results, [$ssl, $c, 'yes']);
            checkcipher($ssl, $c);
        }
        $hasrsa  = 1 if ($c =~ /$cfg{'regex'}->{'EC-RSA'}/);
        $hasecdsa= 1 if ($c =~ /$cfg{'regex'}->{'EC-DSA'}/);
    } # foreach %hash
    _v2print("\n");
    $checks{'edh'}->{val} = "" if ($checks{'edh'}->{val} ne ""); # good if we have them
    # TR-02102-2, see 3.2.3
    if ($checks{$ssl}->{val} > 0) { # check do not make sense if there're no ciphers
        $checks{'tr-02102'}->{val} .=_prot_cipher($ssl, $text{'miss-RSA'})   if ($hasrsa != 1);
        $checks{'tr-02102'}->{val} .=_prot_cipher($ssl, $text{'miss-ECDSA'}) if ($hasecdsa != 1);
    }
    $checks{'cnt_totals'}->{val} +=
            $checks{$ssl . '--?-'}->{val}  +
            $checks{$ssl . '-LOW'}->{val}  +
            $checks{$ssl . '-WEAK'}->{val} +
            $checks{$ssl . '-HIGH'}->{val} +
            $checks{$ssl . '-MEDIUM'}->{val};

    _trace(" checkciphers }");
} # checkciphers

sub checkdates($$) {
    # check validation of certificate's before and after date
    my ($host, $port) = @_;
    $cfg{'done'}->{'checkdates'}++;
    return if ($cfg{'done'}->{'checkdates'} > 1);
       #
       # Note about calculating dates:
       # calculation should be done without using additional perl modules like
       # Time::Local, Date::Calc, Date::Manip, ...
       # Hence we convert the date given by the certificate's before and after
       # value to the format  YYYYMMDD. The format given in the certificate is
       # always GMT and in fixed form:  MMM DD hh:mm:ss YYYY GMT. So a split()
       # gives year and day as integer. Just the month is a string, which need
       # to be converted to an integer using the map() funtion on @mon array.
       # The same format is used for the current date given by gmtime(), but
       # convertion is much simpler as no strings exist here.
    my @now = gmtime(time);
    my $now = sprintf("%4d%02d%02d ", $now[5]+1900, $now[4]+1, $now[3]);
    my @mon = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my $m   = 0;
    my @since = split(/ +/, $data{'before'}->{val}($host));
    my @until = split(/ +/, $data{'after'} ->{val}($host));
    my $s_mon = 0; my $u_mon = 0;
       map({$m++; $s_mon=$m if/$since[0]/} @mon); $m = 0;
       map({$m++; $u_mon=$m if/$until[0]/} @mon); $m = 0;
    my $start = sprintf("%s%02s%02s", $since[3], $s_mon, $since[1]);
    my $end   = sprintf("%s%02s%02s", $until[3], $u_mon, $until[1]);
    # end date magic, do checks ..
    $checks{'dates'}->{val}     =          $data{'before'}->{val}($host) if ($now < $start);
    $checks{'dates'}->{val}    .= " .. " . $data{'after'} ->{val}($host) if ($now > $end);
    $checks{'expired'}->{val}   =          $data{'after'} ->{val}($host) if ($now > $end);
    $data{'valid-years'}->{val}     = ($until[3]       -  $since[3]);
    $data{'valid-months'}->{val}    = ($until[3] * 12) - ($since[3] * 12) + $u_mon - $s_mon;
    $data{'valid-days'}->{val}      = ($data{'valid-years'}->{val}  *  5) + ($data{'valid-months'}->{val} * 30); # approximately
    $data{'valid-days'}->{val}      = ($until[1] - $since[1]) if ($data{'valid-days'}->{val} < 60); # more accurate
    _trace("checkdates: start, now, end: : $start, $now, $end");
    _trace("checkdates: valid:       " . $checks{'dates'}->{val});
    _trace("checkdates: valid-years: " . $data{'valid-years'}->{val});
    _trace("checkdates: valid-month: " . $data{'valid-months'}->{val} . "  = ($until[3]*12) - ($since[3]*12) + $u_mon - $s_mon");
    _trace("checkdates: valid-days:  " . $data{'valid-days'}->{val}   . "  = (" . $data{'valid-years'}->{val} . "*5) + (" . $data{'valid-months'}->{val} . "*30)");
} # checkdates

sub _getwilds($$) {
    # compute usage of wildcard in CN and subjectAltname
    my ($host, $port) = @_;
    my ($value, $regex);
    foreach $value (split(" ", $data{'altname'}->{val}($host))) {
            $value =~ s/.*://;      # strip prefix
        if ($value =~ m/\*/) {
            $checks{'wildcard'}->{val} .= " " . $value;
            ($regex = $value) =~ s/[*]/.*/;   # make regex (miss dots is ok)
            $checks{'wildhost'}->{val}  = $value if ($host =~ m/$regex/);
            $checks{'cnt_wildcard'}->{val}++;
        }
        $checks{'cnt_altname'}->{val}++;
        $checks{'len_altname'}->{val} = length($value) + 1; # count number of characters + type (int)
    }
    # checking for SNI does not work here 'cause it destroys %data
} # _getwilds

sub checkcert($$) {
    #? check certificate settings
    my ($host, $port) = @_;
    my ($value, $label, $subject, $txt);
    $cfg{'done'}->{'checkcert'}++;
    return if ($cfg{'done'}->{'checkcert'} > 1);

    # wildcards (and some sizes)
    _getwilds($host, $port);
    # $checks{'certfqdn'}->{val} ... done in checksni()

    $checks{'rootcert'}->{val}  = $data{'issuer'}->{val}($host) if ($data{'subject'}->{val}($host) eq $data{'issuer'}->{val}($host));
    #dbx# _dbx "S " .$data{'subject'}->{val}($host);
    #dbx# _dbx "S " .$data{'issuer'}->{val}($host);

    $checks{'ocsp'}->{val}      = " " if ($data{'ocsp_uri'}->{val}($host) eq "");
    $checks{'cps'}->{val}       = " " if ($data{'ext_cps'}->{val}($host) eq "");
    $checks{'crl'}->{val}       = " " if ($data{'ext_crl'}->{val}($host) eq "");
    # ToDo: more checks necessary:
    #    KeyUsage field must set keyCertSign and/or the BasicConstraints field has the CA attribute set TRUE.

    #$checks{'nonprint'}      =
    #$checks{'crnlnull'}      =

    # certificate
    if ($cfg{'verbose'} > 0) { # ToDo
        foreach $label (qw(verify selfsigned)) {
            #dbx# _dbx "$label : $value #";
            $value = $data{$label}->{val}($host);
            $checks{$label}->{val}   = $value if ($value eq "");

# FIXME:  $data{'verify'} $data{'error_verify'} $data{'error_depth'}
#   if (_is_do('verify')) {
#       print "";
#       print "Hostname validity:       "      . Net::SSLinfo::verify_hostname($host, $port);
#       print "Alternate name validity: "      . Net::SSLinfo::verify_altname($host, $port);
#   }
#
#   if (_is_do('altname')) {
#       print "";
#       print "Certificate AltNames:    "      . Net::SSLinfo::altname($host, $port);
#       print "Alternate name validity: "      . Net::SSLinfo::verify_altname($host, $port);
#   }
        }
    }
    $checks{'selfsigned'}->{val} = $data{'selfsigned'}->{val}($host);
    $checks{'fp_not_md5'}->{val} = $data{'fingerprint'} if ('MD5' eq $data{'fingerprint'});

    # valid characters (most likely only relevant for EV)
    #_dbx "EV: regex:" . $cfg{'regex'}->{'notEV-chars'};
    foreach $label (qw(cn subject altname extensions ext_crl ocsp_uri)) { # CRL
        # also (should already be part of others): CN, O, U
        $subject =  $data{$label}->{val}($host);
        $subject =~ s#[\r\n]##g;         # CR and NL ar most likely added by openssl
        if ($subject =~ m#$cfg{'regex'}->{'notEV-chars'}#) {
            $txt = _subst($text{'cert-chars'}, $label);
            $checks{'ev-chars'}->{val} .= $txt;
            $checks{'ev+'}->{val}      .= $txt;
            $checks{'ev-'}->{val}      .= $txt;
            $checks{'dv'}->{val}       .= $txt;
             if ($cfg{'verbose'} > 0) {
                 $subject =~ s#($cfg{'regex'}->{'EV-chars'}+)##msg;
                 _v2print("EV:  wrong characters in $label: $subject" . "\n");
             }
        }
    }

# ToDo: check: serialNumber: Positive number up to a maximum of 20 octets.
# ToDo: check: Signature: Must be the same OID as that defined in SignatureAlgorithm below.
# ToDo: check: Version
# ToDo: check: validity (aka dates)
# ToDo: check: Issuer
#        Only CN=, C=, ST=, O=, OU= and serialNumber= must be supported the rest are optional 
# ToDo: check: Subject
#        The subject field can be empty in which case the entity being authenticated is defined in the subjectAltName.

} # checkcert

sub checksni($$) {
    #? check if given FQDN needs to use SNI
    # sets $checks{'sni'}, $checks{'certfqdn'}
    my ($host, $port) = @_;
    $cfg{'done'}->{'checksni'}++;
    return if ($cfg{'done'}->{'checksni'} > 1);
    if ($cfg{'usesni'} == 1) {      # useless check for --no-sni
        if ($data{'cn_nosni'}->{val} eq $host) {
            $checks{'sni'}->{val}   = "";
        } else {
            $checks{'sni'}->{val}   = $data{'cn_nosni'}->{val};
        }
    }
    # $checks{'certfqdn'} and $checks{'hostname'} are similar
    if ($data{'cn'}->{val}($host) eq $host) {
        $checks{'certfqdn'}->{val}  = "";
        $checks{'hostname'}->{val}  = "";
    } else {
        $checks{'certfqdn'}->{val}  = $data{'cn_nosni'}->{val} . " <> " . $host;
        $checks{'hostname'}->{val}  = $host . " <> " . $data{'cn_nosni'}->{val};
    }
} # checksni

sub checksizes($$) {
    #? compute some lengths and count from certificate values
    # sets %checks
    my ($host, $port) = @_;
    my $value;
    $cfg{'done'}->{'checksizes'}++;
    return if ($cfg{'done'}->{'checksizes'} > 1);

    checkcert($host, $port) if ($cfg{'no_cert'} == 0); # in case we missed it before
    $value =  $data{'pem'}->{val}($host);
    $checks{'len_pembase64'}->{val} = length($value);
    $value =~ s/(----.+----\n)//g;
    chomp $value;
    $checks{'len_pembinary'}->{val} = sprintf("%d", length($value) / 8 * 6) + 1; # simple round()
    $checks{'len_subject'}->{val}   = length($data{'subject'}->{val}($host));
    $checks{'len_issuer'}->{val}    = length($data{'issuer'}->{val}($host));
    $checks{'len_CPS'}->{val}       = length($data{'ext_cps'}->{val}($host));
    $checks{'len_CRL'}->{val}       = length($data{'ext_crl'}->{val}($host));
    #$checks{'len_CRL_data'}->{val}  = length($data{'crl'}->{val}($host));
    $checks{'len_OCSP'}->{val}      = length($data{'ocsp_uri'}->{val}($host));
    #$checks{'len_OIDs'}->{val}      = length($data{'OIDs'}->{val}($host));
    $checks{'len_sernumber'}->{val} = int(length($data{'serial'}->{val}($host)) / 2); # value are hex octets
    $value = $data{'modulus_len'}->{val}($host);
    $checks{'len_publickey'}->{val} = (($value =~ m/^\s*$/) ? 0 : $value); # missing without openssl
    $value = $data{'sigkey_len'}->{val}($host);
    $checks{'len_sigdump'}->{val}   = (($value =~ m/^\s*$/) ? 0 : $value); # missing without openssl
    $value = 0 if($value =~ m/^\s*$/); # if value is empty, we might get: Argument "" isn't numeric in int
    $checks{'sernumber'}->{val}     = " " if ($value > 20);
} # checksizes

sub check02102($$) {
    #? check if target is compliant to BSI TR-02102-2
    # assumes that checkssl() already done
    my ($host, $port) = @_;
    $cfg{'done'}->{'check02102'}++;
    return if ($cfg{'done'}->{'check02102'} > 1);
    my $txt = "";
    #
    # description (see CHECK in pod below) ...
    # lines starting with #! are headlines from TR-02102-2

    # All checks according ciphers already done in checkciphers() and stored
    # in $checks{'tr-02102'}. We need to do checks according certificate and
    # protocol and fill other %checks values according requirements.

    #! TR-02102-2 3.2.1 Empfohlene Cipher Suites
    #! TR-02102-2 3.2.2 Übergangsregelungen
    #! TR-02102-2 3.2.3 Mindestanforderungen für Interoperabilität
    $checks{'bsi-tr-02102+'}->{val} = $checks{'tr-02102'}->{val}; # cipher checks are already done
    $checks{'bsi-tr-02102-'}->{val} = $checks{'tr-02102'}->{val}; # .. for lazy check, ciphers are enough

    #! TR-02102-2 3.3 Session Renegotation
    $checks{'bsi-tr-02102+'}->{val}.= $text{'no-reneg'}   if ($checks{'renegotiation'}->{val} ne "");

    #! TR-02102-2 3.4 Zertifikate und Zertifikatsverifikation
    $txt = _subst($text{'cert-valid'}, $data{'valid-years'}->{val});
    $checks{'bsi-tr-02102+'}->{val}.= $txt                if ($data{'valid-years'}->{val}  > 3);
    $checks{'bsi-tr-02102+'}->{val}.= $text{'cert-dates'} if ($checks{'dates'}->{val} ne "");
    $checks{'bsi-tr-02102+'}->{val}.= _subst($text{'EV-miss'}, 'CRL')  if ($checks{'crl'}->{val}   ne "");
    $checks{'bsi-tr-02102+'}->{val}.= _subst($text{'EV-miss'}, 'AIA')  if ($data{'ext_authority'}->{val}($host)  eq "");
    $checks{'bsi-tr-02102+'}->{val}.= _subst($text{'EV-miss'}, 'OCSP') if ($data{'ocsp_uri'}->{val}($host)  eq "");
    $checks{'bsi-tr-02102+'}->{val}.= $text{'wildcards'} . $checks{'wildcard'}->{val} .">>" if ($checks{'wildcard'}->{val} ne "");

    #! TR-02102-2 3.5 Domainparameter und Schlüssellängen
# FIXME:

    #! TR-02102-2 3.6 Schlüsselspeicherung
    #! TR-02102-2 3.7 Umgang mit Ephemeralschlüsseln
    #! TR-02102-2 3.8 Zufallszahlen
        # these checks are not possible from remote

    # FIXME: certificate (chain) validation check
    # ToDo: cipher bit length check

} # check02102

sub checkdv($$) {
    #? check if certificate is DV-SSL
    my ($host, $port) = @_;
    $cfg{'done'}->{'checkdv'}++;
    return if ($cfg{'done'}->{'checkdv'} > 1);
    #
    # DV certificates must have:
    #    CN= value in either the subject or subjectAltName
    #    C=, ST=, L=, OU= or O= should be either blank or contain appropriate
    #        text such as "not valid".  # ToDo: match $cfg{'regex'}->{'EV-empty'}
    # ToDo: reference missing

    my $cn      = $data{'cn'}->{val}($host);
    my $subject = $data{'subject'}->{val}($host);
    my $altname = $data{'altname'}->{val}($host); # space-separated values
    my $oid     = '2.5.4.3';                      # /CN= or commonName
    my $txt     = "";

       # following checks work like:
       #   for each check add descriptive failture text (from %text)
       #   to $checks{'dv'}->{val} if check fails

    # required CN=
    if ($cn =~ m/^\s*$/) {
        $checks{'dv'}->{val} .= _subst($text{'EV-miss'}, "Common Name");
        return; # .. as all other checks will fail too now
    }

    # CN= in subject or subjectAltname
    if (($subject !~ m#/$cfg{'regex'}->{$oid}=([^/\n]*)#)
    and ($altname !~ m#/$cfg{'regex'}->{$oid}=([^\s\n]*)#)) {
        $checks{'dv'}->{val} .= _subst($text{'EV-miss'}, $data_oid{$oid}->{txt});
        return; # .. as ..
    }
    $txt = $1;  # $1 is matched FQDN

# ToDo: %data_oid not yet used
    $data_oid{$oid}->{val} = $txt if ($txt !~ m/^\s*$/);
    $data_oid{$oid}->{val} = $cn  if ($cn  !~ m/^\s*$/);

    # there's no rule that CN's value must match the hostname, somehow ..
    # we check at least if subject or subjectAltname match hostname
    if ($txt ne $cn) {  # mismatch
        $checks{'dv'}->{val} .= $text{'EV-subject-CN'};
    }
    if ($txt ne $host) {# mismatch
        if (0 >= grep(/^DNS:$host$/, split(/[\s]/, $altname))) {
            $checks{'dv'}->{val} .= $text{'EV-subject-host'};
        }
    }

} # checkdv

sub checkev($$) {
    #? check if certificate is EV-SSL
    my ($host, $port) = @_;
    $cfg{'done'}->{'checkev'}++;
    return if ($cfg{'done'}->{'checkev'} > 1);
    #
    # most information must be provided in `subject' field
    # unfortunately the specification is a bit vague which X509  keywords
    # must be used, hence we use RegEx to math the keyword assigned value
    #
    # { According EV Certificate Guidelines - Version 1.0 https://www.cabforum.org/contents.html
    # == Required ==
    # Organization name:   subject:organizationName (OID 2.5.4.10 )
    # Business Category:   subject:businessCategory (OID 2.5.4.15)
    # Domain name:         subject:commonName (OID 2.5.4.3) or SubjectAlternativeName:dNSName
    #     This field MUST contain one of the following strings in UTF-8
    #     English: 'V1.0, Clause 5.(b)', 'V1.0, Clause 5.(c)' or 'V1.0, Clause 5.(d)',
    #     depending whether the Subject qualifies under the terms of Section 5b, 5c, or
    #     5d of the Guidelines, respectively.
    # Jurisdiction of Incorporation or Registration:
    #     Locality:        subject:jurisdictionOfIncorporationLocalityName (OID 1.3.6.1.4.1.311.60.2.1.1)
    #     State or Province:subject:jurisdictionOfIncorporationStateOrProvinceName (OID 1.3.6.1.4.1.311.60.2.1.2) 
    #     Country:         subject:jurisdictionOfIncorporationCountryName (OID 1.3.6.1.4.1.311.60.2.1.3)
    # Registration Number: subject:serialNumber (OID 2.5.4.5) 
    # Physical Address of Place of Business
    #     City or town:    subject:localityName (OID 2.5.4.7)
    #     State or province: subject:stateOrProvinceName (OID 2.5.4.8)
    #     Number & street: subject:streetAddress (OID 2.5.4.9)
    # 
    # Maximum Validity Period  27 months (recommended: EV Subscriber certificate 12 months)
    # 
    # == Optional ==
    # Physical Address of Place of Business
    #     Country:         subject:countryName (OID 2.5.4.6)
    #     Postal code:     subject:postalCode (OID 2.5.4.17)
    # Compliance with European Union Qualified Certificates Standard In addition,
    # CAs MAY include a qcStatements extension per RFC 3739. The OID for
    #                      qcStatements:qcStatement:statementId is 1.3.6.1.4.1.311.60.2.1
    #
    # }
    # Issuer Domain Component: issuer:domainComponent (OID 0.9.2342.19200300.100.1.25)
    #
    # See also: http://www.evsslcertificate.com
    #
    my $oid     = "";
    my $subject = $data{'subject'}->{val}($host);
    my $cn      = $data{'cn'}->{val}($host);
    my $alt     = $data{'altname'}->{val}($host);
    my $txt     = "";
    my $key     = "";

       # following checks work like:
       #   for each check add descriptive failture text (from %text)
       #   to $checks{'ev+'}->{val} if check fails

    checkdv($host, $port);
    $checks{'ev+'}->{val} = $checks{'dv'}->{val}; # wrong for DV then wrong for EV too

    # required OID
    foreach $oid (qw(
        1.3.6.1.4.1.311.60.2.1.1   1.3.6.1.4.1.311.60.2.1.3
        2.5.4.5    2.5.4.7   2.5.4.10   2.5.4.15
        )) {
        if ($subject =~ m#/$cfg{'regex'}->{$oid}=([^/\n]*)#) {
            $data_oid{$oid}->{val} = $1;
            _v2print("EV: " . $cfg{'regex'}->{$oid} . " = $1\n");
            #dbx# _dbx "L:$oid: $1";
        } else {
            _v2print("EV: " . _subst($text{'EV-miss'}, $cfg{'regex'}->{$oid}) . "; required\n");
            $txt = _subst($text{'EV-miss'}, $data_oid{$oid}->{txt});
            $checks{'ev+'}->{val} .= $txt;
            $checks{'ev-'}->{val} .= $txt;
        }
    }
    $oid = '1.3.6.1.4.1.311.60.2.1.2'; # or /ST=
    if ($subject !~ m#/$cfg{'regex'}->{$oid}=([^/\n]*)#) {
        $txt = _subst($text{'EV-miss'}, $data_oid{$oid}->{txt});
        $checks{'ev+'}->{val} .= $txt;
        $oid = '2.5.4.8'; # or /ST=
        if ($subject =~ m#/$cfg{'regex'}->{'2.5.4.8'}=([^/\n]*)#) {
            $data_oid{$oid}->{val} = $1;
        } else {
            $checks{'ev-'}->{val} .= $txt;
            _v2print("EV: " . _subst($text{'EV-miss'}, $cfg{'regex'}->{$oid}) . "; required\n");
        }
    }
    $oid = '2.5.4.9'; # may be missing
    if ($subject !~ m#/$cfg{'regex'}->{$oid}=([^/\n]*)#) {
        $txt = _subst($text{'EV-miss'}, $data_oid{$oid}->{txt});
        $checks{'ev+'}->{val} .= $txt;
        _v2print("EV: " . $cfg{'regex'}->{$oid} . " = missing+\n");
        _v2print("EV: " . _subst($text{'EV-miss'}, $cfg{'regex'}->{$oid}) . "; required\n");
    }
    # optional OID
    foreach $oid (qw(2.5.4.6 2.5.4.17)) {
    }
    if (64 < length($data_oid{'2.5.4.10'}->{val})) {
        $txt = _subst($text{'EV-large'}, "64 < " . $data_oid{$oid}->{txt});
        $checks{'ev+'}->{val} .= $txt;
        _v2print("EV: " . $txt . "\n");
    }
    # validity <27 months
    if ($data{'valid-months'}->{val} > 27) {
        $txt = _subst($text{'cert-valid'}, "27 < " . $data{'valid-months'}->{val});
        $checks{'ev+'}->{val} .= $txt;
        _v2print("EV: " . $txt . "\n");
    }
    # valid characters already don in checkcert()

    # ToDo: wildcard no, SAN yes
    # ToDo: cipher 2048 bit?
    # ToDo: potential dangerous OID: '1.3.6.1.4.1.311.60.1.1'
    # ToDo: Scoring: 100 EV+SGC; 80 EV; 70 EV-; 50 OV; 30 DV
} # checkev

sub checkroot($$) {
    #? check if certificate is root CA
    my ($host, $port) = @_;
    $cfg{'done'}->{'checkroot'}++;
    return if ($cfg{'done'}->{'checkroot'} > 1);

# some texts from: http://www.zytrax.com/tech/survival/ssl.html
# The term Certificate Authority is defined as being an entity which signs
# certificates in which the following are true:
#   * the issuer and subject fields are the same,
#   * the KeyUsage field has keyCertSign set
#   * and/or the basicConstraints field has the cA attribute set TRUE.
# Typically, in chained certificates the root CA certificate is the topmost
# in the chain but RFC 4210 defines a 'root CA' to be any issuer for which
# the end-entity, for example, the browser has a certificate which was obtained
# by a trusted out-of-band process. Since final authority for issuing any
# certificate rest with this CA the terms and conditions of any intermediate
# certificate may be modified by this entity.
#
# Subordinate Authority:
# may be marked as CAs (the extension BasicContraints will be present and cA will be set True)
#
# Intermediate Authority (a.k.a. Intermediate CA):
# Imprecise term occasionally used to define an entity which creates an
# intermediate certificate and could thus encompass an RA or a subordinate CA.
#
# Cross certificates (a.k.a. Chain or Bridge certificate):
# A cross-certificate is one in which the subject and the issuer are not the
# same but in both cases they are CAs (BasicConstraints extension is present and has cA set True).
#
# Intermediate certificates (a.k.a. Chain certificates):
# Imprecise term applied to any certificate which is not signed by a root CA.
# The term chain in this context is meaningless (but sounds complicated and
# expensive) and simply indicates that the certificate forms part of a chain.
#
# Qualified certificates: Defined in RFC 3739
# the term Qualified certificates relates to personal certificates (rather than
# server certificates) and references the European Directive on Electronic Signature (1999/93/EC)
# see check02102() above
#
# Multi-host certificates (aka wildcard certificates)
#
# EV Certificates (a.k.a. Extended Certificates): Extended Validation (EV)
# certificates are distinguished by the presence of the CertificatePolicies
# extension containg a registered OID in the policyIdentifier field. 
# see checkev() above
#
#

# RFC 3280
#  4.2.1.10  Basic Constraints
#    X509v3 Basic Constraints:
#        cA:FALSE
#        pathLenConstraint  INTEGER (0..MAX) OPTIONAL }
# RFC 4158

} # checkroot

sub checkdest($$) {
    #? check anything related to target and connection
    my ($host, $port) = @_;
    my $ciphers = shift;
    my ($key, $value, $ssl, $cipher);
    $cfg{'done'}->{'checkdest'}++;
    return if ($cfg{'done'}->{'checkdest'} > 1);

    checksni($host, $port);     # set checks according hostname
    $checks{'reversehost'}->{val}   = $host . " <> " . $cfg{'rhost'} if ($cfg{'rhost'} ne $host);
    $checks{'reversehost'}->{val}   = $text{'no-dns'}   if ($cfg{'usedns'} <= 0);
    $checks{'ip'}->{val}            = $cfg{'IP'};
    if ($cfg{'SSLv2'} == 0) {
        $checks{'hasSSLv2'}->{val}  = $text{'disabled'} if ($cfg{'SSLv2'} == 0);
    } else {
        $checks{'hasSSLv2'}->{val}  = '!' if ($cfg{'nullssl2'} == 1); # SSLv2 enabled, but no ciphers
    }

    # check default cipher
    foreach $ssl (@{$cfg{'versions'}}) {
        next if ($cfg{$ssl} == 0);
        $value  = $checks{$ssl}->{val};
        $cipher = _get_default($host, $port, $ssl);
        if (($value == 0) && ($cipher eq "")) {
            $value = $text{'protocol'};
            # _getscore() below fails for this (see with --trace) 'cause there
            # is no entry %checks{'SSLv2-'} ; that's ok
        } else {
            $value = $cipher . " " . get_cipher_sec($cipher);
        }
        $checks{$ssl}->{val} = $value;
        $checks{'beast-default'}->{val} .= _prot_cipher($ssl, $cipher) if ("" ne _isbeast($ssl, $cipher));
        $checks{'pfs'}->{val}           .= _prot_cipher($ssl, $cipher) if ("" ne _ispfs($ssl, $cipher));
    }

    # vulnerabilities
    $checks{'crime'}->{val} = _iscrime($data{'compression'}->{val}($host));
    foreach $key (qw(resumption renegotiation)) {
        $value = $data{$key}->{val}($host);
        $checks{$key}->{val} = " " if ($value eq "");
    }
    #     Secure Renegotiation IS NOT supported
    $value = $data{'renegotiation'}->{val}($host);
    $checks{'renegotiation'}->{val} = $value if ($value =~ m/ IS NOT /i);
    $value = $data{'resumption'}->{val}($host);
    $checks{'resumption'}->{val}    = $value if ($value !~ m/^Reused/);

    # check target specials
    foreach $key (qw(krb5 psk_hint psk_identity srp session_ticket)) { # master_key session_id: see %check_dest above also
        $value = $data{$key}->{val}($host);
        $checks{$key}->{val} = " " if ($value eq "");
        # if supported we have a value
	# ToDo: see ZLIB also (seems to be wrong currently)
    }
} # checkdest

sub checkhttp($$) {
    #? HTTP(S) checks
    my ($host, $port) = @_;
    my $key = "";
    _y_CMD("checkhttp() " . $cfg{'done'}->{'checkhttp'});
    $cfg{'done'}->{'checkhttp'}++;
    return if ($cfg{'done'}->{'checkhttp'} > 1);

    # collect informations
    my $no = " "; # use a variable to make assignments below more human readable
    my $http_sts      = $data{'http_sts'}     ->{val}($host) || ""; # value may be undefined, avoid perl error
    my $http_location = $data{'http_location'}->{val}($host) || ""; #  "
    my $hsts_maxage   = $data{'hsts_maxage'}  ->{val}($host) || -1;
    my $hsts_fqdn     = $http_location;
       $hsts_fqdn     =~ s|^(?:https:)?//([^/]*)|$1|i; # get FQDN even without https:

    $checks{'hsts_is301'}->{val} = $data{'http_status'}->{val}($host) if ($data{'http_status'}->{val}($host) !~ /301/); # RFC6797 requirement
    $checks{'hsts_is30x'}->{val} = $data{'http_status'}->{val}($host) if ($data{'http_status'}->{val}($host) =~ /30[0235678]/); # not 301 or 304
    # perform checks
    $checks{'http_https'}->{val} = $no if ($http_location eq "");  # HTTP Location is there
    $checks{'hsts_redirect'}->{val} = $data{'https_sts'}->{val}($host) if ($http_sts ne ""); 
    if ($data{'https_sts'}->{val}($host) ne "") {
        $checks{'hsts_location'}->{val} = $data{'https_location'}->{val}($host) if ($data{'https_location'}->{val}($host) ne "");
        $checks{'hsts_refresh'} ->{val} = $data{'https_refresh'} ->{val}($host) if ($data{'https_refresh'} ->{val}($host) ne "");
        $checks{'hsts_fqdn'}    ->{val} = $hsts_fqdn   if ($http_location !~ m|^https://$host|i);
        $checks{'hsts_sts'}     ->{val} = $no if ($data{'https_sts'}  ->{val}($host) eq "");
        $checks{'sts_subdom'}   ->{val} = $no if ($data{'hsts_subdom'}->{val}($host) eq "");
        $checks{'sts_maxage'}   ->{val} = $hsts_maxage if (($hsts_maxage > $checks{'sts_maxage1m'}->{val}) or ($hsts_maxage < 1));
        $checks{'sts_maxage'}   ->{val}.= " = " . int($hsts_maxage / $checks{'sts_maxage1d'}->{val}) . " days" if ($checks{'sts_maxage'}->{val} ne ""); # pretty print
        $checks{'sts_maxagexy'} ->{val} = ($hsts_maxage > $checks{'sts_maxagexy'}->{val}) ? "" : "< ".$checks{'sts_maxagexy'}->{val};
        # other sts_maxage* are done below as they change {val}
    } else {
        $checks{'sts_maxagexy'} ->{val} = $text{'no-STS'};
        foreach $key (qw(hsts_location hsts_refresh hsts_fqdn hsts_sts sts_subdom sts_maxage)) {
            $checks{$key}->{val}    = $text{'no-STS'};
        }
    }
    $checks{'hsts_fqdn'}->{val} = "<<N/A>>" if ($http_location eq "");   # useless if no redirect
    $checks{'pkp_pins'} ->{val} = $no if ($data{'https_pins'}->{val}($host) eq "");
# ToDo: pins= ==> fingerprint des Zertifikats

    # NOTE: following sequence is important!
    foreach $key (qw(sts_maxage1y sts_maxage1m sts_maxage1d sts_maxage0d)) {
        if ($data{'https_sts'}->{val}($host) ne "") {
            $checks{'sts_maxage'}->{score} = $checks{$key}->{score} if ($hsts_maxage < $checks{$key}->{val});
            $checks{$key}->{val}    = ($hsts_maxage < $checks{$key}->{val}) ? "" : "> ".$checks{$key}->{val};
        } else {
            $checks{$key}->{val}    = $text{'no-STS'};
            $checks{$key}->{score}  = 0;
        }
    }
} # checkhttp

sub checkssl($$) {
    #? SSL checks
    my ($host, $port) = @_;
    my $ciphers = shift;
    my $key;
    $cfg{'done'}->{'checkssl'}++;
    return if ($cfg{'done'}->{'checkssl'} > 1);

    $cfg{'no_cert_txt'} = $text{'no-cert'} if ($cfg{'no_cert_txt'} eq ""); # avoid "yes" results
    if ($cfg{'no_cert'} == 0) {
        # all checks based on certificate can't be done if there was no cert, obviously
        checkcert( $host, $port);   # SNI, wildcards and certificate
        checkdates($host, $port);   # check certificate dates (since, until, exired)
        checkdv(   $host, $port);   # check for DV
        checkev(   $host, $port);   # check for EV
        check02102($host, $port);   # check for BSI TR-02102-2
        checksni(  $host, $port);   # check for SNI
        checksizes($host, $port);   # some sizes
    } else {
        $cfg{'done'}->{'checksni'}++;  # avoid checking again
        $cfg{'done'}->{'checkdates'}++;# "
        $cfg{'done'}->{'checksizes'}++;# "
        $cfg{'done'}->{'check02102'}++;# "
        $cfg{'done'}->{'checkdv'}++;   # "
        $cfg{'done'}->{'checkev'}++;   # "
        foreach $key (sort keys %checks) { # anything related to certs need special setting
            $checks{$key}->{val} = $cfg{'no_cert_txt'} if (_is_member($key, \@{$cfg{'check_cert'}}));
        }
        $checks{'hostname'}->{val} = $cfg{'no_cert_txt'};
        $checks{'bsi-tr-02102+'}->{val} = $cfg{'no_cert_txt'};
        $checks{'bsi-tr-02102-'}->{val} = $cfg{'no_cert_txt'};
    }

    if ($cfg{'usehttp'} == 1) {
        checkhttp( $host, $port);
    } else {
        $cfg{'done'}->{'checkhttp'}++;
        foreach $key (sort keys %checks) {
            $checks{$key}->{val} = $text{'no-http'} if (_is_member($key, \@{$cfg{'cmd-http'}}));
        }
    }
    # some checks accoring ciphers and compliance are done in checkciphers()
    # and check02102(); some more are done in checkhttp()
    # now do remaining for %checks
    checkdest( $host, $port);

# ToDo: folgende Checks implementieren
    foreach $key (qw(verify_hostname verify_altname verify dates fingerprint)) {
# ToDo: nicht sinnvoll wenn $cfg{'no_cert'} > 0
    }

} # checkssl

sub scoring($$) {
    #? compute scoring of all checks; sets values in %scores
    my ($host, $port) = @_;
    my ($key, $value);

    # http
    #  some scores are set in checkhttp()
    my $http_location = $data{'http_location'}->{val}($host) || "";
    $scores{'check_http'}->{val}    = 100;
    $checks{'hsts_fqdn'}->{score}   = 0 if ($http_location eq "");

    foreach $key (sort keys %checks) {
        next if ($key =~ m/^(ip|reversehost)/); # not scored
        next if ($key =~ m/^(sts_)/);           # needs special handlicg
        next if ($key =~ m/^(closure|fallback|cps|krb5|lzo|open_pgp|order|pkp_pins|psk_|rootcert|srp|zlib)/); # FIXME: not yet scored
        next if ($key =~ m/^TLSv1[12]/);  # FIXME:
        $value = $checks{$key}->{val};
        # ToDo: go through @results
#ToDo   foreach $sec (qw(LOW WEAK MEDIUM HIGH -?-)) {
#ToDo       # keys in %checks look like 'SSLv2-LOW', 'TLSv11-HIGH', etc.
#ToDo       $key = $ssl . '-' . $sec;
#ToDo       if ($checks{$key}->{val} != 0) {    # if set, decrement score
#ToDo           $scores{'check_ciph'}->{val} -= _getscore($key, 'egal', \%checks);
#ToDo printf "%20s: %4s %s\n", $key, $scores{'check_ciph'}->{val}, _getscore($key, 'egal', \%checks);
#ToDo       }
#ToDo   }
        $scores{'check_size'}->{val} -= _getscore($key, $value, \%checks) if($checks{$key}->{typ} eq "sizes");
#       $scores{'check_ciph'}->{val} -= _getscore($key, $value, \%checks) if($checks{$key}->{typ} eq "cipher");
        $scores{'check_http'}->{val} -= _getscore($key, $value, \%checks) if($checks{$key}->{typ} eq "https"); # done above
        $scores{'check_cert'}->{val} -= _getscore($key, $value, \%checks) if($checks{$key}->{typ} eq "certificate");
        $scores{'check_conn'}->{val} -= _getscore($key, $value, \%checks) if($checks{$key}->{typ} eq "connection");
        $scores{'check_dest'}->{val} -= _getscore($key, $value, \%checks) if($checks{$key}->{typ} eq "destination");
#_dbx "$key " . $checks{$key}->{val} if($checks{$key}->{typ} eq "connection");
#_dbx "score certificate $key : ".$checks{$key}->{val}." - ". $checks{$key}->{score}." = ".$scores{'check_cert'}->{val} if($checks{$key}->{typ} eq "certificate");
#_dbx "score connection  $key : ".$checks{$key}->{val}." - ". $checks{$key}->{score}." = ".$scores{'check_conn'}->{val} if($checks{$key}->{typ} eq "connection");
#_dbx "score destination $key : ".$checks{$key}->{val}." - ". $checks{$key}->{score}." = ".$scores{'check_dest'}->{val} if($checks{$key}->{typ} eq "destination");
#_dbx "score http/https  $key : ".$checks{$key}->{val}." - ". $checks{$key}->{score}." = ".$scores{'check_http'}->{val} if($checks{$key}->{typ} eq "https");
    }
} # scoring

# print functions
# -------------------------------------
sub print_host_key($$) {
    #? print hostname if --showhost given; print key if --tracekey given
    my ($host, $key) = @_;
    printf("%s%s", $_[0], $text{'separator'}) if ($cfg{'showhost'} > 0);
    printf("#[%-18s", $key . ']' . $text{'separator'}) if ($cfg{'traceKEY'} > 0);
}

sub _dump($$) {
    my ($label, $value) = @_;
        $label =~ s/\n//g;
        $label = sprintf("%s %s", $label, '_' x (75 -length($label)));
    $value = "" if (!defined $value); # value parameter is optional
    printf("#{ %s\n\t%s\n#}\n", $label, $value);
    # using curly prackets 'cause they most likely are not part of any data
} # _dump
sub printdump($$$) {
    #? just dumps internal database %data and %check_*
    my ($legacy, $host, $port) = @_;   # NOT IMPLEMENTED
    my $key;
    print '######################################################################### %data';
    foreach $key (keys %data) {
        next if (_is_intern($key) > 0);  # ignore aliases
        _dump($data{$key}->{txt}, $data{$key}->{val}($host));
    }
    print '######################################################################## %check';
    foreach $key (keys %checks) { _dump($checks{$key}->{txt}, $checks{$key}->{val}); }
} # printdump
sub printruler()  { print "=" . '-'x38, "+" . '-'x35 if ($cfg{'out_header'} > 0); }
sub printheader   {
    #? print title line and table haeder line if second argument given
    my ($txt, $desc, $rest) = @_;
    return if ($cfg{'out_header'} <= 0);
    print $txt;
    return if ($desc =~ m/^ *$/); # title only if no more arguments
    printf("= %-37s %s\n", $text{'desc'}, $desc);
    printruler();
} # printheader

sub print_data($$$) {
    # print given label and text from %data according given legacy format
    my ($legacy, $label, $host, $port) = @_;   # port is optional
    if (_is_hashkey($label, \%data) < 1) {     # silently ignore unknown labels
        warn("**WARNING: unknown label '$label'; ignored"); # seems to be a programming error
        return;
    }
    print_host_key($host, $label);
    my $val = $data{$label}->{val}($host) || "";
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
    if ((1 eq _is_hexdata($label)) && ($val !~ m/^\s*$/)) { # check for empty $val to avoid warnings with -w
        # pubkey_value may look like:
        #   Subject Public Key Info:Public Key Algorithm: rsaEncryptionPublic-Key: (2048 bit)Modulus=00c11b:...
        # where we want to convert the key value only but not its prefix
        # hence the final : is converted to =
        # (seems to happen on Windows only; reason yet unknown)
        $val =~ s/([Mm]odulus):/$1=/; #
        my ($k, $v) = split("=", $val);
        if (defined $v) {       # i.e SHA Fingerprint=
            $k .= "=";
        } else {
            $v  = $k;
            $k  = "";
        }
        $v   =~ s#(..)#$1:#g, $v =~ s#:$## if ($cfg{'format'} eq "hex");
        $val = $k . $v;
    }
    $val = "\n" . $val if (_is_member($label, \@{$cfg{'cmd-NL'}}) > 0); # multiline data
    if ($legacy eq 'compact') {
        $val   =~ s#[\n\r]#; #g;
        $label = $data{$label}->{txt};
        $label =~ s#[\n]##g;
        printf("%s%s%s\n", $label, $text{'separator'}, $val);
        return;
    }
    if ($legacy eq 'quick') {
        $label = $data{$label}->{txt};
        printf("%s%s%s\n", $label, $text{'separator'}, $val);
        return;
    }
    if ($legacy eq 'full') {    # do some pretty printing
        if ($label =~ m/(^altname)/) { $val =~ s#^ ##;     $val =~ s# #\n\t#g; }
        if ($label =~ m/(subject)/)  { $val =~ s#/#\n\t#g; $val =~ s#^\n\t##m; }
        if ($label =~ m/(issuer)/)   { $val =~ s#/#\n\t#g; $val =~ s#^\n\t##m; }
        if ($label =~ m/(serial|modulus|sigkey_value)/) {
                                       $val =~ s#(..)#$1:#g; $val =~ s#:$##; }
        if ($label =~ m/(pubkey_algorithm|signame)/) {
            $val =~ s#(with)# $1 #ig;
            $val =~ s#(encryption)# $1 #ig;
         }
        printf("\n%s%s\n\t%s\n", $data{$label}->{txt},  $text{'separator'}, $val); # comma!
    } else {
        printf("%-32s\t%s\n",      $data{$label}->{txt} . $text{'separator'}, $val); # dot!
    }
} # print_data

sub _print_line($$$) {
    #? print label and result of check
    my ($legacy, $label, $value) = @_;
    if ($legacy eq 'full')   {
        printf("%s\n", $label . $text{'separator'});
        printf("\t%s\n", $value) if (defined $value);
        return;
    }
    if ($legacy =~ m/(compact|quick)/) {
        printf("%s", $label . $text{'separator'});
        printf("%s", $value) if (defined $value);
    } else {
        printf("%-36s", $label . $text{'separator'});
        printf("\t%s", $value) if (defined $value);
    }
    printf("\n");
} # _print_line

sub print_line($$$$$) {
    #? print label and value
    my ($legacy, $host, $key, $label, $value) = @_;
    print_host_key($host, $key);
    _print_line($legacy, $label, $value);
} # print_line

sub print_check($$$$) {
    #? print label and result of check
    my ($legacy, $host, $label, $value) = @_;
    print_host_key($host, $label);
    $value = $checks{$label}->{val} if (!defined $value);
    $label = $checks{$label}->{txt};
    _print_line($legacy, $label, $value);
} # print_check

sub print_cipherline($$$$$$) {
    #? print cipher check result according given legacy format
    my ($legacy, $ssl, $host, $port, $cipher, $support) = @_;
    # variables for better (human) readability
    my $bit  = get_cipher_bits($cipher);
    my $sec  = get_cipher_sec($cipher);
#   my $ssl  = get_cipher_ssl($cipher);
    my $desc =  join(" ", get_cipher_desc($cipher));
    my $yesno= $text{'legacy'}->{$legacy}->{$support};
    if ($legacy eq 'sslyze')   {
        if ($support eq 'yes') {
            $support = sprintf("%4s bits", $bit) if ($support eq 'yes');
        } else {
            $support = $yesno;
        }
        printf("\t%-24s\t%s\n", $cipher, $support);
    }
    if ($legacy eq 'sslaudit') {
        # SSLv2 - DES-CBC-SHA - unsuccessfull
        # SSLv3 - DES-CBC3-SHA - successfull - 80
        printf("%s - %s - %s\n", $ssl, $cipher, $yesno);
    }
    if ($legacy eq 'sslcipher') {
        #   TLSv1:EDH-RSA-DES-CBC3-SHA - ENABLED - STRONG 168 bits
        #   SSLv3:DHE-RSA-AES128-SHA - DISABLED - STRONG 128 bits
        $sec = 'INTERMEDIATE:' if ($sec =~ /LOW/i);
        $sec = 'STRONG'        if ($sec =~ /high/i);
        $sec = 'WEAK'          if ($sec =~ /weak/i);
        printf("   %s:%s - %s - %s %s bits\n", $ssl, $cipher, $yesno, $sec, $bit);
    }
    if ($legacy eq 'ssldiagnos') {
        # [+] Testing WEAK: SSL 2, DES-CBC3-MD5 (168 bits) ... FAILED
        # [+] Testing STRONG: SSL 3, AES256-SHA (256 bits) ... CONNECT_OK CERT_OK
        $sec = ($sec =~ /high/i) ? 'STRONG' : 'WEAK';
        printf("[+] Testing %s: %s, %s (%s bits) ... %s\n", $sec, $ssl, $cipher, $bit, $yesno);
    }
    if ($legacy eq 'sslscan') {
        #    Rejected  SSLv3  256 bits  ADH-AES256-SHA
        #    Accepted  SSLv3  128 bits  AES128-SHA
        $bit = sprintf("%3s bits", $bit);
        printf("    %s  %s  %s  %s\n", $yesno, $ssl, $bit, $cipher);
    }
    if ($legacy eq 'ssltest') {
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
        printf("   %s, %s (%s)\n",  $cipher, join (", ", @arr), $yesno);
    }
    if ($legacy =~ m/compact|full|quick|simple/) { # only our own formats
        print_host_key($host, 'cipher');
    }
        # compliant;host:port;protocol;cipher;description
    if ($legacy eq 'ssltest-g') { printf("%s;%s;%s;%s\n", 'C', $host . ":" . $port, $sec, $cipher, $desc); } # 'C' needs to be checked first
    if ($legacy eq 'quick')     { printf("    %-28s\t(%s)\t%s\n", $cipher, $bit,   $sec); }
    if ($legacy eq 'simple')    { printf("    %-28s\t%s\t%s\n",   $cipher, $yesno, $sec); }
    if ($legacy eq 'compact')   { printf("%s %s %s\n",            $cipher, $yesno, $sec); }
    if ($legacy eq 'testsslserver') { printf("    %s\n", $cipher); }
    if ($legacy eq 'full') {
        # host:port protocol    supported   cipher    compliant security    description
        $desc =  join("\t", get_cipher_desc($cipher));
        $desc =~ s/\s*:\s*$//;
        printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $host . ':' . $port, $ssl, $yesno, $cipher, '-?-', $sec, $desc);
    }
} # print_cipherline

sub print_cipherruler   { print "=   " . "-"x35 . "+-------+-------" if ($cfg{'out_header'} > 0); }
sub print_cipherhead($) {
    #? print header line according given legacy format
    my $legacy  = shift;
    if ($legacy eq 'sslscan')   { print "\n  Supported Server Cipher(s):"; }
    if ($legacy eq 'ssltest')   { printf("   %s, %s (%s)\n",  'Cipher', 'Enc, bits, Auth, MAC, Keyx', 'supported'); }
    if ($legacy eq 'ssltest-g') { printf("%s;%s;%s;%s\n", 'compliant', 'host:port', 'protocol', 'cipher', 'description'); }
    if ($legacy eq 'simple')    { printf("=   %-34s%s\t%s\n", $text{'cipher'}, $text{'support'}, $text{'security'});
                                  print_cipherruler(); }
    if ($legacy eq 'full')      {
        # host:port protocol    supported   cipher    compliant security    description
        printf("= %s\t%s\t%s\t%s\t%s\t%s\t%s\n", 'host:port', 'Prot.', 'supp.', $text{'cipher'}, 'compliant', $text{'security'}, $text{'desc'});
    }
    # all others are empty, no need to do anything
} # print_cipherhead

sub print_cipherdefault($$$$) {
    #? print default cipher according given legacy format
    my ($legacy, $ssl, $host, $port) = @_;
    my $yesno   = 'yes';
    if ($legacy eq 'sslyze')    { print "\n\n      Preferred Cipher Suites:"; }
    if ($legacy eq 'sslaudit')  {} # ToDo: cipher name should be DEFAULT
    if ($legacy eq 'sslscan')   { print "\n  Preferred Server Cipher(s):"; $yesno = "";}
    # all others are empty, no need to do anything
    print_cipherline($legacy, $ssl, $host, $port, $data{'default'}->{val}($host), $yesno);
} # print_cipherdefault

sub print_ciphertotals($$$$) {
    #? print total number of ciphers supported for SSL version according given legacy format
    my ($legacy, $ssl, $host, $port) = @_;
    my ($key, $sec);
    if ($legacy eq 'ssldiagnos') {
        print "\n-= SUMMARY =-\n";
        printf("Weak:         %s\n", $checks{$ssl . '-WEAK'}->{val});
        printf("Intermediate: %s\n", $checks{$ssl . '-MEDIUM'}->{val}); # MEDIUM
        printf("Strong:       %s\n", $checks{$ssl . '-HIGH'}->{val});   # HIGH
    }
    if ($legacy =~ /(full|compact|simple|quick)/) {
        printheader(_subst($text{'out-summary'}, $ssl), "");
        _trace_1arr('%checks');
        foreach $sec (qw(LOW WEAK MEDIUM HIGH -?-)) {
            $key = $ssl . '-' . $sec;
            print_check($legacy, $host, $key, undef);
        }
        print_check($legacy, $host, $key, undef);
    }
} # print_ciphertotals

sub printtitle($$$$) {
    #? print title according given legacy format
    my ($legacy, $ssl, $host, $port) = @_;
    my $txt     = _subst($text{'out-ciphers'}, $ssl);
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
            "[*] Target port: $port\n",
            "----------------------------------------------------\n";
    }
    if ($legacy eq 'sslscan')   { $host =~ s/;/ on port /; print "Testing SSL server $host\n"; }
    if ($legacy eq 'ssltest')   { print "Checking for Supported $ssl Ciphers on $host..."; }
    if ($legacy eq 'ssltest-g') { print "Checking for Supported $ssl Ciphers on $host..."; }
    if ($legacy eq 'testsslserver') { print "Supported cipher suites (ORDER IS NOT SIGNIFICANT):\n  " . $ssl; }
    if ($legacy eq 'compact')   { print "Checking $ssl Ciphers ..."; }
    if ($legacy eq 'quick')     { printheader($txt, ""); }
    if ($legacy eq 'simple')    { printheader($txt, ""); }
    if ($legacy eq 'full')      { printheader($txt, ""); }
} # printtitle

sub printfooter($) {
    #? print footer line according given legacy format
    my $legacy  = shift;
    if ($legacy eq 'sslyze')    { print "\n\n SCAN COMPLETED IN ...\n"; }
    # all others are empty, no need to do anything
} # printfooter

sub _is_print($$$) {
    #? return 1 if parameter indicate printing
    my $enabled = shift;
    my $print_disabled = shift;
    my $print_enabled  = shift;
    return 1 if ($print_disabled == $print_enabled);
    return 1 if ($print_disabled && ($enabled eq 'no' ));
    return 1 if ($print_enabled  && ($enabled eq 'yes'));
    return 0;
} # _is_print

sub _print_results($$$@) {
    #? print all ciphers from @results if match $ssl and $yesno
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my $yesno   = shift; # only print these results, all if empty
    my @results = @_;
    my $print   = 0; # default: do not print
    my $c       = "";
    local    $\ = "\n";
    foreach $c (@results) {
        next if  (${$c}[0] ne $ssl);
        next if ((${$c}[2] ne $yesno) and ($yesno ne ""));
        $print = _is_print(${$c}[2], $cfg{'disabled'}, $cfg{'enabled'});
        print_cipherline($cfg{'legacy'}, $ssl, $host, $port, ${$c}[1], ${$c}[2]) if ($print ==1);
    }
} # _print_results

sub printciphers($$$$$@) {
    #? print all cipher check results according given legacy format
    my $legacy  = shift;
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my $count   = shift; # print title line if 0
    my @results = @_;
    local    $\ = "\n";
    print_cipherhead( $legacy) if (($cfg{'out_header'}>0) && ($count == 0));
    print_cipherdefault($legacy, $ssl, $host, $port) if ($legacy eq 'sslaudit');

    if ($legacy ne 'sslyze') {
        _print_results($ssl, $host, $port, "", @results);
        print_cipherruler() if ($legacy eq 'simple');
    } else {
        print "\n  * $ssl Cipher Suites :";
        print_cipherdefault($legacy, $ssl, $host, $port);
        if (($cfg{'enabled'} == 1) or ($cfg{'disabled'} == $cfg{'enabled'})) {
            print "\n      Accepted Cipher Suites:";
            _print_results($ssl, $host, $port, "yes", @results);
        }
        if (($cfg{'disabled'} == 1) or ($cfg{'disabled'} == $cfg{'enabled'})) {
            print "\n      Rejected Cipher Suites:";
            _print_results($ssl, $host, $port, "no", @results);
        }
    }
    print_ciphertotals($legacy, $ssl, $host, $port);
    print_check($legacy, $host, 'cnt_totals', $#results) if ($cfg{'verbose'} > 0);
    printfooter($legacy);
} # printciphers

sub print_size($$$) {
    #? print label and result for length, count, size, ...
    my ($legacy, $host, $label) = @_;
    my $value = "";
    $value = " bytes" if ($label =~ /^(len)/);
    $value = " bits"  if ($label =~ /^(len_publickey|len_sigdump)/);
    print_check($legacy, $host, $label, $checks{$label}->{val} . $value);
} # print_size

sub printdata($$) {
    #? print information stored in %data
    my ($legacy, $host) = @_;
    my $key  = "";
    local $\ = "\n";
    printheader($text{'out-infos'}, $text{'desc-info'});
    _trace_1arr('%data');
    foreach $key (@{$cfg{'do'}}) {
        next if (_is_member( $key, \@{$cfg{'cmd-NOT_YET'}}) > 0);
        next if (_is_hashkey($key, \%data) < 1);
        # special handling vor +info--v
        if (_is_do('info--v') > 0) {
            next if ($key eq 'info--v');
            next if ($key =~ m/$cfg{'regex'}->{'cmd-intern'}/i);
        } else {
            next if (_is_intern( $key) > 0);
        }
        _y_CMD("(%data)   +" . $key);
        if (_is_member( $key, \@{$cfg{'cmd-NL'}}) > 0) {
            # for +info print multine data only if --v given
            # if command given explizitely, i.e. +text, print
            next if ((_is_do('info') > 0) and ($cfg{'verbose'} <= 0));
        }
        if ($cfg{'format'} eq "raw") {  # should be the only place where format=raw counts
            print $data{$key}->{val}($host);;
        } else {
            print_data($legacy, $key, $host);
        }
    }
} # printdata

sub printchecks($$) {
    #? print results stored in %checks
    my ($legacy, $host) = @_;
    my $key  = "";
    local $\ = "\n";
    printheader($text{'out-checks'}, $text{'desc-check'});
    if (_is_do('default')) {            # values are special
        _trace_1arr('@cfg{version}');
        foreach $key (@{$cfg{'versions'}}) {
            next if ($cfg{$key} == 0);  # this version not checked, see eval("Net::SSLeay::SSLv2_method()") above
            print_line($legacy, $host, 'default', $checks{'default'}->{txt} . $key, $checks{$key}->{val});
        }
    }
    _trace_1arr('%checks');
    print "**WARNING: can't print certificate sizes without a certificate (--no-cert)" if ($cfg{'no_cert'} > 0);
    foreach $key (@{$cfg{'do'}}) {
        next if (_is_member( $key, \@{$cfg{'cmd-NOT_YET'}}) > 0);
        next if (_is_hashkey($key, \%checks) < 1);
        next if (_is_intern( $key) > 0);# ignore aliases
        next if ($key =~ m/$cfg{'regex'}->{'SSLprot'}/); # these counters are already printed
        next if ($key eq 'default');    # used for @cfg{version} only
        _y_CMD("(%checks) +" . $key);
        if ($key eq 'beast') {          # check is special
            if (! _is_do('cipher') && ($check <= 0)) {
                print_check($legacy, $host, $key, $text{'need-cipher'}) if ($cfg{'verbose'} > 0);
                next;
            }
        }
        if ($key =~ /$cfg{'regex'}->{'cmd-sizes'}/) { # sizes are special
            print_size($legacy, $host, $key) if ($cfg{'no_cert'} <= 0);
        } else {
            print_check($legacy, $host, $key, _setvalue($checks{$key}->{val}));
        }
    }
} # printchecks

# print functions for help and information
# -------------------------------------

sub printversion() {
    #? print program and module versions
    local $\ = "\n";
    print '# Path = ' . $mepath if ($cfg{'verbose'} > 1);
    print '# @INC = ' . join(" ", @INC) . "\n" if ($cfg{'verbose'} > 0);
    print "    $0 $VERSION";
    print "    " . Net::SSLinfo::do_openssl('version', "", "", "");
    # get a quick overview also
    print "Required (and used) Modules:";
    print "    IO::Socket::INET     $IO::Socket::INET::VERSION";
    print "    IO::Socket::SSL      $IO::Socket::SSL::VERSION";
    print "    Net::SSLeay          $Net::SSLeay::VERSION";
    print "    Net::SSLinfo         $Net::SSLinfo::VERSION";
    my ($m, $d, %p);
    if ($cfg{'verbose'} > 0) {
        print "\nLoaded Modules:";
        foreach $m (sort keys %INC) {
            printf("    %-22s %6s\n", $m, $INC{$m});
            $d = $INC{$m}; $d =~ s#$m$##; $p{$d} = 1;
        }
        print "\nLoaded Module Versions:";
        no strict 'refs';   # avoid: Can't use string ("AutoLoader::") as a HASH ref while "strict refs" in use
        foreach $m (sort keys %main:: ) {
            next if $m !~ /::/;
            $d = "?";       # beat the "Use of uninitialized value" dragon
            $d = ${$$m{'VERSION'}} if (defined ${$$m{'VERSION'}});
            printf("    %-22s %6s\n", $m, $d);
        }
    }
    return if ($^O =~ m/MSWin32/); # not Windows
    if ($cfg{'verbose'} > 1) {
        print "\nUsed Shared Objects:";
        # quick&dirty, don't want to use ::Find module
        foreach $d (sort keys %p) {
             next if ($d =~ m/^\s*$/);
             print "# find $d -name SSLeay.so\\* -o -name libssl.so\\* -o -name libcrypto.so\\*";
             print   `find $d -name SSLeay.so\\* -o -name libssl.so\\* -o -name libcrypto.so\\*`;
        }
    }
} # printversion

sub printopenssl() {
    #? print openssl version
    print Net::SSLinfo::do_openssl('version', "", "", "");
} # printopenssl

sub printcipherlist() {
    #? print all our ciphers
    _trace(" +list");
    my $have_cipher = 0;
    my $miss_cipher = 0;
    my $ciphers     = "";
       $ciphers     = Net::SSLinfo::cipher_local() if ($cfg{'verbose'} > 0);
    my $cipher      = "";
    printheader(_subst($text{'out-list'}, $0), "");
    printheader("= Cipher\t" . join("\t", @{$ciphers_desc{'text'}}) . "\n", "");
    printf("%-31s %s\n", "= cipher", join("\t", @{$ciphers_desc{'head'}}));
    printf("=%s%s\n", ('-' x 30), ('+-------' x 9));
    foreach $cipher (sort keys %ciphers) {
### ToDo {
        my $can = " ";
        if ($cfg{'verbose'} > 0) {
            #my $can = (1 == grep(/^$cipher$/, split(":", $ciphers))) ? " " : "-";
            #my @g = scalar grep({$_ eq $cipher} split(':', $ciphers));
            #print "G: $cipher " . join",",@g ."\n";
            if (0 >= grep({$_ eq $cipher} split(":", $ciphers))) {
                $can = "#";
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
    printf("=%s%s\n", ("-" x 30), ("+-------" x 9));
    if ($cfg{'verbose'} > 0) {
        my @miss = ();
        foreach $cipher (split(':', $ciphers)) {
            push(@miss, $cipher) if (! defined $ciphers{$cipher});
        }
        print "\n# Ciphers marked with # above are not supported by local SSL implementation.\n";
        print "Ciphers in $mename:        ", join(":", keys %ciphers);
        print "Supported Ciphers:        ", $have_cipher;
        print "Unsupported Ciphers:      ", $miss_cipher;
        print "Testable Ciphers:         ", scalar @{[split(":", $ciphers)]}; # @{[...]} to avoid Use of implicit split to @_ is deprecated at 
        print "Ciphers missing in $mename:", $#miss, "  ", join(" ", @miss);
        print "Ciphers (from local ssl): ", $ciphers;
            # ToDo: there may be more "Testable" than "Supported" ciphers
    }
} # printcipherlist

sub _print_head($$) { printf("=%14s | %s\n", @_); printf("=%s+%s\n", '-'x15, '-'x60); }
sub _print_opt($$$) { printf("%16s%s%s\n", @_); }
sub _print_cmd($$)  { printf("     +%-14s\t%s\n", @_); }
sub _print_cfg($$$$){
    # print line in configuration format
    my ($typ, $key, $sep, $txt) = @_;
    $txt =  '"' . $txt . '"' if ($typ =~ m/^cfg/);
    $key =  "--$typ=$key"    if ($typ =~ m/^cfg/);
    _print_opt($key, $sep, $txt);
}

sub printtable($) {
    #? print data from hash in tabular form, $typ denotes hash
    my $typ = shift;
    my %types = (
        # typ        header left    separator  header right
        #-----------+---------------+-------+-------------------------------
        'score' => ["key",           "=",    "SCORE\t# Description"],
        'regex' => ["key",           " => ", " Regular Expressions used internally"],
        'abbr'  => ["Abbrevation",   " - ",  "Description"],
        'intern'=> ["Command",       "    ", " list of commands"],
        'compl' => ["Compliance",    " - ",  "brief description of performed checks"],
        'data'  => ["key",    "=",   "text"],
        'check' => ["key",    "=",   "text"],
        'text'  => ["key",    "=",   "text"],
        'cfg_check' =>["N/A", "=",   "N/A"],
        'cfg_data'  =>["N/A", "=",   "N/A"],
        'cfg_text'  =>["N/A", "=",   "N/A"],
    );
    my ($key, $txt);
    my $sep = $types{$typ}->[1];
    _print_head($types{$typ}->[0], $types{$typ}->[2]) if ($typ !~ m/^cfg/);
    if ($typ eq 'abbr')  { _print_opt(do{(my $a=$_)=~s/ *$//;$a}, $sep, $text{'glossar'}->{$_}) foreach (sort keys %{$text{'glossar'}}); }
    if ($typ eq 'regex') { _print_opt($_, $sep, $cfg{'regex'}->{$_}) foreach (sort keys %{$cfg{'regex'}}); }
    if ($typ eq 'compl') { _print_opt($_, $sep, $cfg{'compliance'}->{$_}) foreach (sort keys %{$cfg{'compliance'}}); }
    if ($typ eq 'score') { _print_opt($_, $sep .  $checks{$_}->{score}, "\t# " . $checks{$_}->{txt}) foreach (sort keys %checks); }
    if ($typ eq 'intern') {
        foreach $key (sort keys %cfg) {
            next if ($key eq 'cmd-intern'); # don't list myself
            next if ($key !~ m/^cmd-(.*)/);
            _print_opt("cmd-" . $1, $sep, "+" . join(" +", @{$cfg{$key}}));
        }
    }
    if ($typ =~ m/check/) {
        foreach $key (sort keys %checks) {
            $txt =  $checks{$key}->{txt};
            _print_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/data/) {
        foreach $key (sort keys %data) {
            $txt =  $data{$key}->{txt};
            _print_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/text/) {
        foreach $key (sort keys %text) {
            next if (ref($text{$key}) ne ""); # skip except string
            $txt =  $text{$key};
            $txt =~ s/(\n)/\\n/g;
            $txt =~ s/(\r)/\\r/g;
            $txt =~ s/(\t)/\\t/g;
            _print_cfg($typ, $key, $sep, $txt);
        }
        print "
= Format is:  KEY=TEXT ; NL, CR and TAB are printed as \\n, \\r and \\t
= The string  @@  inside texts is used as placeholder.
= (Don't be confused about multiple  =  as they are part of  TEXT.)
    " if ($typ !~ m/^cfg/);
    }
} # printtable

sub printcommands() {
    #? print program's help about commands
    # we do not use POD, as most texts are already in %data and %checks
    my $key;
    print "\n   Summary and internal commands";
    foreach $key (@{$cfg{'commands'}}) {
        _print_cmd($key, "") if (_is_intern($key) > 0);
    }
    print "
   Commands to show target, connection and certificate details

        The names of these commands are mainly adopted to  openssl's commands
        (see \"openssl cipher\", \"openssl x509\").
        All these commands just show  a single detail which is also available
        with the  +text  command.
";
    foreach $key (@{$cfg{'commands'}}) {
        next if (_is_intern($key) > 0);
        next if (_is_hashkey($key, \%data) <= 0);
        _print_cmd($key, $data{$key}->{txt});
    }
    print "
   Commands for checks

        Commands to show results of performed checks.
";
    foreach $key (@{$cfg{'commands'}}) {
        next if (_is_intern($key) > 0);
        next if (_is_hashkey($key, \%checks) <= 0);
        next if ($key =~ m/$cfg{'regex'}->{'SSLprot'}/);
        _print_cmd($key, $checks{$key}->{txt});
    }
} # printcommands

sub printhist() {
    my $egg = join ("", @DATA);
    $egg =~ s{.*?=begin\s+--v --v(.*?)=end\s+--v.*}{$1}ms;
    print scalar reverse $egg;
} # printhist

sub printhelp($) {
    #? print program's help
    # if parameter is not empty, print brief list of specified label
    my $label   = shift || ""; # || to avoid uninitialized value
    local $\;
    $\ = "\n";
    _vprintme();
    _v_print("help: $label");
    if ($label =~ m/^cmd$/i)            { print "# $mename commands:\t+"        . join(" +", @{$cfg{'commands'}}); exit; }
    if ($label =~ m/^(legacy)s?/i)      { print "# $mename legacy values:\t"    . join(" ",  @{$cfg{'legacys'}});  exit; }
    if ($label =~ m/^commands?/i){ printcommands();  exit; }
    if ($label =~ m/^(abbr|compl|intern|regex|score|data|check|text)(?:iance)?s?$/i) { printtable(lc($1)); exit; }
    if ($label =~ m/^(?:cfg[_-])?(check|data|text)s?(?:[_-]cfg)?$/i) { printtable('cfg_'.lc($1)); exit; }
        # we allow:  text-cfg, text_cfg, cfg-text and cfg_text so that
        # we can simply switch from  --help=text  and/or  --cfg_text=*

    # no special help, print full one
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
    _v_print("poor man's POD ...");
    $\ = "";
    my $skip  = 0;
    my $ident = "        ";
    foreach (@DATA) {
        $ident = "        ";
        next if (/__DATA__$/);
        next if (/^\s*$/);
        next if (/^=(cut|pod|for|encoding).*/);
        last if (/=end ToDo/);      # quick&dirty fix 18jan13 (@DATA contains script at end)
        s/^=end\s*/  {$skip = 0;}/e && next;
        s/^=begin\s*/{$skip = 1;}/e && next;
        next if ($skip != 0);
        s/\$0(?![>"])/$mename/g;    # negative lookahead: keep "$0" and C<$0>
        print "\n" if m/^=head3\s/; # quick&dirty: does not work with \n in substitute below
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

sub printtodo() {
    #? print program's ToDo
    my $txt = join ("", @DATA);
    my $label = "";
    _vprintme();
    $txt =~ s{.*?=begin\s+ToDo[^\n]*(.*?)=end\s+ToDo.*}{$1}ms;
    print $txt;
    $\   =  "\n";
    print "  NOT YET IMPLEMENTED";
    foreach $label (sort keys %checks) {
        next if (_is_member($label, \@{$cfg{'cmd-NOT_YET'}}) <= 0);
        print "  " . $checks{$label}->{txt};
    }
} # printtodo

# end sub

usr_pre_args();

# scan options and arguments
# -------------------------------------
my $typ = 'HOST';
while ($#argv >= 0) {
    $arg = shift @argv;
    _y_ARG($arg);
    push(@dbxarg, $arg) if (($arg !~ m/^--cfg_/) && (($arg =~ m/^[+-]/) || ($typ ne "HOST")));
    push(@dbxcfg, $arg) if  ($arg =~ m/^--cfg_/);    # both aprox. match are sufficient for debugging
    # When used as CGI we need some special checks:
    #   - remove trailing = for all options except (see below)
    #   - ignore --cgi option
    #   - ignore empty arguments
    #   - arguments for --command may miss a leading +, which will be added
    #
    if ($arg !~ /([+]|--)(cmd|host|port|exe|lib|cipher|format|legacy|timeout|url)=/) {
        $arg =~ s/=+$//;                    # remove trailing = (for CGI mode)
    }
    # First check for option or command.
    # Options may have an argument, either as separate word or as part of the
    # option parameter itself: --opt=argument .
    # Such an argument is handled at end of loop using $typ,  the default  is
    # $typ='HOST'  which means we expect a hostname argument. Any other value
    # for  $typ will be set in the corresponding option after the argument is
    # parsed (see $typ at end of loop), $typ will be reset to 'HOST' again.
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
    if ($arg eq   '--http')             { $cfg{'usehttp'}++;     next; } # must be before --help
    if ($arg =~ m/^--no[_-]?http$/)     { $cfg{'usehttp'}   = 0; next; }
    if ($arg =~ m/^--h(?:elp)?(?:=(.*))?$/) { printhelp($1);     exit 0; } # allow --h --help --h=*
    if ($arg =~ m/^\+help=?(.*)$/)          { printhelp($1);     exit 0; } # allow +help +help=*
    if ($arg =~ m/^(--|\+)ab(?:br|k)=?$/)   { printtable('abbr');exit 0; }
    if ($arg =~ m/^(--|\+)glossar$/)        { printtable('abbr');exit 0; }
    if ($arg =~ m/^(--|\+)todo=?$/i)        { printtodo();       exit 0; }
    # options for trace and debug
    if ($arg =~ /^--yeast(.*)/)         { _yeast_data();         exit 0; } # debugging
   #if ($arg =~ /^--v(erbose)?$/)       { $cfg{'verbose'}++; $info = 1; next; }
    if ($arg =~ /^--v(erbose)?$/)       { $cfg{'verbose'}++;     next; }
    if ($arg eq  '--n')                 { $cfg{'try'}       = 1; next; }
    if ($arg eq  '--trace')             { $cfg{'trace'}++;       next; }
    if ($arg =~ /^--trace(--|[_-]?arg)/){ $cfg{'traceARG'}++;    next; } # special internal tracing
    if ($arg =~ /^--trace([_-]?cmd)/)   { $cfg{'traceCMD'}++;    next; } # ..
    if ($arg =~ /^--trace(@|[_-]?key)/) { $cfg{'traceKEY'}++;    next; } # ..
    if ($arg =~ /^--trace=(.*)/)        { $typ = 'TRACE';   $arg = $1; } # no next
    # options form other programs for compatibility
    if ($arg =~ /^--?no[_-]failed$/)    { $cfg{'enabled'}   = 0; next; } # sslscan
    if ($arg eq  '--hide_rejected_ciphers'){$cfg{'disabled'}= 0; next; } # ssltest.pl
    if ($arg eq  '--http_get')          { $cfg{'usehttp'}++;     next; } # ssltest.pl
    if ($arg eq  '--version')           { $arg = '+version';           }
    # options form other programs which we treat as command; see Options vs. Commands also
    if ($arg eq  '--list')              { $arg = '+list';              } # no next!
    if ($arg eq  '--chain')             { $arg = '+chain';             } # as these
    if ($arg eq  '--cipher')            { $arg = '+cipher';            } # should
    if ($arg eq  '--default')           { $arg = '+default';           } # become
    if ($arg eq  '--fingerprint')       { $arg = '+fingerprint';       } # commands
    if ($arg =~ /^--resum(ption)?$/)    { $arg = '+resumption';        } # ..
    if ($arg =~ /^--reneg(otiation)?/)  { $arg = '+renegotiation';     } # ..
    # options to handle external openssl
    if ($arg eq  '--openssl')           { $cmd{'extopenssl'}= 1; next; }
    if ($arg =~ /^--force[_-]openssl/)  { $cmd{'extciphers'}= 1; next; }
    if ($arg =~ /^--no[_-]?openssl/)    { $cmd{'extopenssl'}= 0; next; }
    if ($arg =~ /^--s_?client/)         { $cmd{'extsclient'}++;  next; }
    # some options are for compatibility with other programs
    #   example: -tls1 -tlsv1 --tlsv1 --tls1_1 --tlsv1_1 --tls11
    if ($arg eq  '--regular')           { $cfg{'usehttp'}++;     next; } # sslyze
    if ($arg eq  '--lwp')               { $cfg{'uselwp'}    = 1; next; }
    if ($arg eq  '--sni')               { $cfg{'usesni'}    = 1; next; }
    if ($arg =~ /^--no[_-]?sni/)        { $cfg{'usesni'}    = 0; next; }
    if ($arg =~ /^--no[_-]?cert$/)      { $cfg{'no_cert'}++;     next; }
    if ($arg =~ /^--no[_-]?ignorecase$/){ $cfg{'ignorecase'}= 0; next; }
    if ($arg =~ /^--ignorecase$/)       { $cfg{'ignorecase'}= 1; next; }
    if ($arg eq  '--short')             { $cfg{'shorttxt'}  = 1; next; }
    if ($arg eq  '--score')             { $cfg{'out_score'} = 1; next; }
    if ($arg =~ /^--no[_-]?score$/)     { $cfg{'out_score'} = 0; next; }
    if ($arg eq  '--header')            { $cfg{'out_header'}= 1; next; }
    if ($arg =~ /^--no[_-]?header$/)    { $cfg{'out_header'}= 0; push(@ARGV, "--no-header"); next; } # push() is ugly hack to preserve option even from rc-file
    if ($arg =~ /^--?sslv?2$/i)         { $cfg{'SSLv2'}     = 1; next; } # allow case insensitive
    if ($arg =~ /^--?sslv?3$/i)         { $cfg{'SSLv3'}     = 1; next; } # ..
    if ($arg =~ /^--?tlsv?1$/i)         { $cfg{'TLSv1'}     = 1; next; } # ..
    if ($arg =~ /^--?tlsv?1[-_.]?1$/i)  { $cfg{'TLSv11'}    = 1; next; } # allow ._- separator
    if ($arg =~ /^--?tlsv?1[-_.]?2$/i)  { $cfg{'TLSv12'}    = 1; next; } # ..
    if ($arg =~ /^--dtlsv?0[-_.]?9$/i)  { $cfg{'DTLSv9'}    = 1; next; } # ..
    if ($arg =~ /^--dtlsv?1[-_.]?0?$/i) { $cfg{'DTLSv1'}    = 1; next; } # ..
    if ($arg =~ /^--no[_-]?sslv?2$/i)   { $cfg{'SSLv2'}     = 0; next; } # allow _- separator
    if ($arg =~ /^--no[_-]?sslv?3$/i)   { $cfg{'SSLv3'}     = 0; next; } # ..
    if ($arg =~ /^--no[_-]?tlsv?1$/i)   { $cfg{'TLSv1'}     = 0; next; } # ..
    if ($arg =~ /^--no[_-]?tlsv?11$/i)  { $cfg{'TLSv11'}    = 0; next; } # ..
    if ($arg =~ /^--no[_-]?tlsv?12$/i)  { $cfg{'TLSv12'}    = 0; next; } # ..
    if ($arg =~ /^--no[_-]?dtlsv?09$/i) { $cfg{'DTLSv9'}    = 0; next; } # ..
    if ($arg =~ /^--no[_-]?dtlsv?10?$/i){ $cfg{'DTLSv1'}    = 0; next; } # ..
    if ($arg =~ /^--nullsslv?2$/i)      { $cfg{'nullssl2'}  = 1; next; } # ..
    if ($arg =~ /^--no[_-]?dns/)        { $cfg{'usedns'}    = 0; next; }
    if ($arg eq  '--dns')               { $cfg{'usedns'}    = 1; next; }
    if ($arg eq  '--enabled')           { $cfg{'enabled'}   = 1; next; }
    if ($arg eq  '--disabled')          { $cfg{'disabled'}  = 1; next; }
    if ($arg eq  '--local')             { $cfg{'nolocal'}   = 1; next; }
    if ($arg eq  '--showhost')          { $cfg{'showhost'}++;    next; }
    if ($arg eq  '-printavailable')     { $cfg{'enabled'}   = 1; next; } # ssldiagnos
    if ($arg =~ /^-?-h(?:ost)?$/)       { $typ = 'HOST';         next; } # --h already catched above
    if ($arg =~ /^-?-h(?:ost)?=(.*)/)   { $typ = 'HOST';    $arg = $1; } # no next
    if ($arg =~ /^-?-p(?:ort)?$/)       { $typ = 'PORT';         next; }
    if ($arg =~ /^-?-p(?:ort)?=(.*)/)   { $typ = 'PORT';    $arg = $1; } # no next
    if ($arg =~ /^--exe(?:[_-]?path)?$/){ $typ = 'EXE';          next; }
    if ($arg =~ /^--exe(?:[_-]?path)?=(.*)/){ $typ = 'EXE'; $arg = $1; } # no next
    if ($arg =~ /^--lib(?:[_-]?path)?$/){ $typ = 'LIB';          next; }
    if ($arg =~ /^--lib(?:[_-]?path)?=(.*)/){ $typ = 'LIB'; $arg = $1; } # no next
    if ($arg =~ /^--envlibvar$/)        { $typ = 'ENV';          next; }
    if ($arg =~ /^--envlibvar=(.*)/)    { $typ = 'ENV';     $arg = $1; } # no next
    if ($arg =~ /^--call$/)             { $typ = 'CALL';         next; }
    if ($arg =~ /^--call=(.*)/)         { $typ = 'CALL';    $arg = $1; } # no next
    if ($arg =~ /^--cipher$/)           { $typ = 'CIPHER';       next; }
    if ($arg =~ /^--cipher=(.*)/)       { $typ = 'CIPHER';  $arg = $1; } # no next
    if ($arg =~ /^--format$/)           { $typ = 'FORMAT';       next; }
    if ($arg =~ /^--format=(.*)/)       { $typ = 'FORMAT';  $arg = $1; } # no next
    if ($arg =~ /^--legacy$/)           { $typ = 'LEGACY';       next; }
    if ($arg =~ /^--legacy=(.*)/)       { $typ = 'LEGACY';  $arg = $1; } # no next
    if ($arg =~ /^--sep(?:arator)?$/)   { $typ = 'SEP';          next; }
    if ($arg =~ /^--sep(?:arator)?=(.*)/){$typ = 'SEP';     $arg = $1; } # no next
    if ($arg =~ /^--tab$/)          { $text{'separator'} = "\t"; next; } # TAB character
    if ($arg =~ /^--timeout$/)          { $typ = 'TIMEOUT';      next; }
    if ($arg =~ /^--timeout=(.*)/)      { $typ = 'TIMEOUT'; $arg = $1; } # no next
    if ($arg eq  '-interval')           { $typ = 'TIMEOUT';      next; } # ssldiagnos
    if ($arg =~ /^--openssl=(.*)/)      { $typ = 'OPENSSL'; $arg = $1; $cmd{'extopenssl'}= 1; } # no next
    if ($arg =~ /^--no[_-]?cert[_-]?te?xt$/)    { $typ = 'CTXT'; next; }
    if ($arg =~ /^--no[_-]?cert[_-]?te?xt=(.*)/){ $typ = 'CTXT'; $arg = $1; } # no next
    if ($arg =~ /^--cfg[_-](cmd|score|text)-([^=]*)=(.*)/){              # warn if old syntax; must be first --cfg* check!
        $typ = 'CFG-'.$1; $arg = $2 . "=" . $3;   # convert to new syntax
        print("**WARNING: old (pre 13.12.12) syntax '--cfg_$1-$2'; converted to '--cfg_$1=$2'; please consider changing your files\n");
        # no next;
    }
    if ($arg =~ /^--cfg[_-]([^=]*)$/)   { $typ = 'CFG-'.$1;      next; }
    if ($arg =~ /^--cfg[_-]([^=]*)=(.*)/){$typ = 'CFG-'.$1; $arg = $2; } # no next
    if ($arg =~ /^--ca[_-]?depth/i)     { $typ = 'CADEPTH';      next; }
    if ($arg =~ /^--ca[_-]?depth=(.*)/i){ $typ = 'CADEPTH'; $arg = $1; } # no next
    if ($arg =~ /^--ca[_-]?(?:cert(?:ificate)?|file)$/i)    { $typ = 'CAFILE';       next; } # curl, openssl, wget, ...
    if ($arg =~ /^--ca[_-]?(?:cert(?:ificate)?|file)=(.*)/i){ $typ = 'CAFILE';  $arg = $1; } # no next
    if ($arg =~ /^--ca[_-]?(?:directory|path)$/i)           { $typ = 'CAPATH';       next; } # curl, openssl, wget, ...
    if ($arg =~ /^--ca[_-]?(?:directory|path)=(.*)/i)       { $typ = 'CAPATH';  $arg = $1; } # no next
    if ($arg =~ /^--win[_-]?CR/i)       { binmode(STDOUT, ':crlf'); binmode(STDERR, ':crlf'); next; }
    if ($arg =~ /^--(fips|ism|pci)$/i)  { next; } # silently ignored
    if ($arg =~ /^-(H|r|s|t|url|u|U|x)/){ next; } #  "
    if ($arg =~ /^-(connect)/)          { next; } #  "
    if ($arg eq  '--insecure')          { next; } #  "
    if ($arg =~ /^--use?r$/)            { next; } # ignore, nothing to do
    if ($arg =~ /^--set[_-]?score=(.*)/){ # option used until 13.12.11
        warn("**WARNING: --set-score=* obsolte, please use --cfg_score=*; ignored");
        next;
    }
    #} +---------+----------------------+----------------------+----------------

    if ($typ =~ m/^CFG/)    { _cfg_set($typ, $arg);         $typ = 'HOST'; next; }
        # option arguments for configuration must be checked first as $arg
        # may contain strings matching in commands section right below

    #{ commands
    _y_ARG("command? $arg");
    if ($arg =~ /^--cmd=\+?(.*)/){ $arg = '# CGI '; $arg = '+' . $1; } # no next
        # in CGI mode commands need to be passed with --cmd=* option
    if ($arg eq  '+info')   { $info  = 1; } # needed 'cause +info and ..
    if ($arg eq  '+quick')  { $quick = 1; } # .. +quick convert to list of commands
    if ($arg eq  '+check')  { $check = 1; $cfg{'out_score'} = 1; } #
    # You may read the lines as table with colums like:
    #  +---------+--------------------+-----------------------+-----------------
    #   argument to check               aliased to (no next!) # traditional name
    #  +---------+--------------------+-----------------------+-----------------
    if ($arg =~ /^\+commonName/i)     { $arg = '+cn';      }
    if ($arg =~ /^\+cert(ificate)?$/i){ $arg = '+pem';     }  # PEM
    if ($arg =~ /^\+subjectX509/i)    { $arg = '+subject'; }  # subject
    if ($arg eq  '+owner')            { $arg = '+subject'; }  # subject
    if ($arg eq  '+authority')        { $arg = '+issuer';  }  # issuer
    if ($arg =~ /^\+issuerX509/i)     { $arg = '+issuer';  }  # issuer
    if ($arg eq  '+expire')           { $arg = '+after';   }
    if ($arg eq  '+sts')              { $arg = '+hsts';    }
    if ($arg eq  '+sigkey')           { $arg = '+sigdump'; }  # sigdump
    if ($arg eq  '+sigkey_algorithm') { $arg = '+signame'; }  # signame
    if ($arg =~ /^\+sni[_-]?check$/)  { $arg = '+check_sni';}
    if ($arg =~ /^\+check[_-]?sni$/)  { $arg = '+check_sni';}
    #  +---------+--------------------+------------------------+----------------
    #   argument to check     what to do                         what to do next
    #  +---------+----------+----------------------------------+----------------
    if ($arg =~ /^--cgi=?/) { $arg = '# for CGI mode; ignore';       next; }
    if ($arg eq  '+info')   { @{$cfg{'do'}} = (@{$cfg{'cmd-info'}},    'info'); next; }
    if ($arg eq  '+info--v'){ @{$cfg{'do'}} = (@{$cfg{'cmd-info--v'}}, 'info'); next; } # like +info ...
    if ($arg eq  '+quick')  { @{$cfg{'do'}} = (@{$cfg{'cmd-quick'}},  'quick'); next; }
    if ($arg eq  '+check')  { @{$cfg{'do'}} = (@{$cfg{'cmd-check'}},  'check'); next; }
    if ($arg eq '+check_sni'){@{$cfg{'do'}} = @{$cfg{'cmd-sni--v'}}; $info = 1; next; }
    if ($arg =~ /^\+(.*)/)  { # got a command
        my $val = $1;
        _y_ARG("command= $val");
        next if ($arg =~ m/^\+\s*$/);  # ignore empty arguments; for CGI mode
        if ($val =~ m/^exec$/i) {      # +exec is special
            $cfg{'exec'} = 1;
            next;
        }
        if ($val =~ /^beast/i){ push(@{$cfg{'do'}}, @{$cfg{'cmd-beast'}}); next; }
        if ($val =~ /^crime/i){ push(@{$cfg{'do'}}, @{$cfg{'cmd-crime'}}); next; }
        if ($val =~ /^sizes/i){ push(@{$cfg{'do'}}, @{$cfg{'cmd-sizes'}}); next; }
        if ($val =~ /^http/i) { push(@{$cfg{'do'}}, @{$cfg{'cmd-http'}});  next; }
        if ($val =~ /^sni/i)  { push(@{$cfg{'do'}}, @{$cfg{'cmd-sni'}});   next; }
        if ($val =~ /^ev$/i)  { push(@{$cfg{'do'}}, @{$cfg{'cmd-ev'}});    next; }
        if ($val =~ /^(bsi|TR-?02102)/i)  { push(@{$cfg{'do'}}, @{$cfg{'cmd-bsi'}});   next; }
        $val = lc($val);               # be greedy to allow +BEAST, +CRIME, etc.
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
    _y_ARG("argument? $arg, typ= $typ");
    push(@dbxexe, join("=", $typ, $arg)) if ($typ =~ m/OPENSSL|ENV|EXE|LIB/);
    #  +---------+----------+------------------------------+--------------------
    #   argument to process   what to do                    expect next argument
    #  +---------+----------+------------------------------+--------------------
    if ($typ eq 'ENV')      { $cmd{'envlibvar'} = $arg;     $typ = 'HOST'; next; }
    if ($typ eq 'OPENSSL')  { $cmd{'openssl'}   = $arg;     $typ = 'HOST'; next; }
    if ($typ eq 'EXE')      { push(@{$cmd{'path'}}, $arg);  $typ = 'HOST'; next; }
    if ($typ eq 'LIB')      { push(@{$cmd{'libs'}}, $arg);  $typ = 'HOST'; next; }
    if ($typ eq 'CALL')     { push(@{$cmd{'call'}}, $arg);  $typ = 'HOST'; next; }
    if ($typ eq 'SEP')      { $text{'separator'}= $arg;     $typ = 'HOST'; next; }
    if ($typ eq 'TIMEOUT')  { $cfg{'timeout'}   = $arg;     $typ = 'HOST'; next; }
    if ($typ eq 'CIPHER')   { $cfg{'cipher'}    = $arg;     $typ = 'HOST'; next; }
    if ($typ eq 'CTXT')     { $cfg{'no_cert_txt'}= $arg;    $typ = 'HOST'; next; }
    if ($typ eq 'CAFILE')   { $cfg{'ca_file'}   = $arg;     $typ = 'HOST'; next; }
    if ($typ eq 'CAPATH')   { $cfg{'ca_path'}   = $arg;     $typ = 'HOST'; next; }
    if ($typ eq 'CADEPTH')  { $cfg{'ca_depth'}  = $arg;     $typ = 'HOST'; next; }
    if ($typ eq 'PORT')     { $cfg{'port'}      = $arg;     $typ = 'HOST'; next; }
    if ($typ eq 'HOST')     {
        #  ------+----------+------------------------------+--------------------
        # allow URL   http://f.q.d.n:42/aa*foo=bar:23/
        $port = $arg;
        if ($port =~ m#.*?:\d+#) {                 # got a port too
            $port =~ s#(?:[^/]+/+)?([^/]*).*#$1#;  # match host:port
            $port =~ s#[^:]*:(\d+).*#$1#;
            _y_ARG("port: $port");
        } else { # use previous port
            $port = $cfg{'port'};
        }
        $arg =~ s#(?:[^/]+/+)?([^/]*).*#$1#;       # extract host from URL
        $arg =~ s#:(\d+)##;
        push(@{$cfg{'hosts'}}, $arg . ":" . $port);
        _yeast("host: $arg") if ($cfg{'trace'} > 0);
    }
    if ($typ eq 'LEGACY')   {
        $arg = 'sslcipher' if ($arg eq 'ssl-cipher-check'); # alias
        if (1 == grep(/^$arg$/, @{$cfg{'legacys'}})) {
            $cfg{'legacy'} = $arg;
        } else {
            warn("**WARNING: unknown legacy '$arg'; ignored");
        }
    }
    if ($typ eq 'FORMAT')   {
        if (1 == grep(/^$arg$/, @{$cfg{'formats'}})) {
            $cfg{'format'} = $arg;
        } else {
            warn("**WARNING: unknown format '$arg'; ignored");
        }
    }
    if ($typ eq 'TRACE')    {
        $cfg{'traceARG'}++   if ($arg =~ m#arg#i);
        $cfg{'traceCMD'}++   if ($arg =~ m#cmd#i);
        $cfg{'traceKEY'}++   if ($arg =~ m#key#i);
        $cfg{'trace'} = $arg if ($arg =~ m#\d+#i);
    }
    _y_ARG("argument= $arg");
    $typ = 'HOST';              # expect host as next argument
    #}

} # while
$verbose = $cfg{'verbose'};

_yeast_args();
_vprintme();

# set defaults for Net::SSLinfo
# -------------------------------------
{
    no warnings qw(once); # avoid: Name "Net::SSLinfo::trace" used only once: possible typo at ./yeast.pl line 
    $Net::SSLinfo::trace       = $cfg{'trace'} if ($cfg{'trace'} > 0);
    $Net::SSLinfo::use_openssl = $cmd{'extopenssl'};
    $Net::SSLinfo::use_sclient = $cmd{'extsclient'};
    $Net::SSLinfo::openssl     = $cmd{'openssl'};
    $Net::SSLinfo::use_http    = $cfg{'usehttp'};
    $Net::SSLinfo::use_SNI     = $cfg{'usesni'};
    $Net::SSLinfo::timeout_sec = $cfg{'timeout'};
    $Net::SSLinfo::no_cert     = $cfg{'no_cert'};
    $Net::SSLinfo::no_cert_txt = $cfg{'no_cert_txt'};
    $Net::SSLinfo::ignore_case = $cfg{'ignorecase'};
    $Net::SSLinfo::ca_crl      = $cfg{'ca_crl'};
    $Net::SSLinfo::ca_file     = $cfg{'ca_file'};
    $Net::SSLinfo::ca_path     = $cfg{'ca_path'};
    $Net::SSLinfo::ca_depth    = $cfg{'ca_depth'};
}
if ('cipher' eq join("", @{$cfg{'do'}})) {
    $Net::SSLinfo::use_http    = 0; # if only +cipher given don't use http 'cause it may cause erros
}

usr_pre_exec();

# call with other libraries
# -------------------------------------
_y_ARG("exec? $cfg{'exec'}");
# NOTE: this must be the very first action/command
if ($cfg{'exec'} == 0) {
    # as all shared libraries used by perl modules are already loaded when
    # this program executes, we need to set PATH and LD_LIBRARY_PATH before
    # being called
    # so we call ourself with proper set environment variables again
    if (($#{$cmd{'path'}} + $#{$cmd{'libs'}}) > -2) {
        _y_CMD("exec command " . join(" ", @{$cfg{'do'}}));
        my $chr = ($ENV{PATH} =~ m/;/) ? ";" : ":"; # set separator character (lazy)
        my $lib = $ENV{$cmd{envlibvar}};            # save existing LD_LIBRARY_PATH
        local $\ = "\n";
        $ENV{PATH} = join($chr, @{$cmd{'path'}}, $ENV{PATH})  if ($#{$cmd{'path'}} >= 0);
        $ENV{$cmd{envlibvar}}  = join($chr, @{$cmd{'libs'}})  if ($#{$cmd{'libs'}} >= 0);
        $ENV{$cmd{envlibvar}} .= $chr . $lib if ($lib);
        if ($verbose > 0) {
            _yeast("exec: envlibvar= $cmd{envlibvar}");
            _yeast("exec: $cmd{envlibvar}= " . ($ENV{$cmd{envlibvar}} || "")); # ENV may not exist
            _yeast("exec: PATH= $ENV{PATH}");
        }
        _yeast("exec: $0 +exec " . join(" ", @ARGV));
        _yeast("################################################") if (($cfg{'traceARG'} + $cfg{'traceCMD'}) > 0);
        exec $0, '+exec', @ARGV;
    }
}

# set additional defaults if missing
# -------------------------------------
$cfg{'out_header'}  = 1 if(0 => $verbose); # verbose uses headers
$cfg{'out_header'}  = 1 if(0 => grep(/\+(check|info|quick|cipher)$/, @ARGV)); # see --header
$cfg{'out_header'}  = 0 if(0 => grep(/--no.?header/, @ARGV)); # can be set in rc-file!
$quick = 1 if ($cfg{'legacy'} eq 'testsslserver');
if ($quick == 1) {
    $cfg{'enabled'} = 1;
    $cfg{'shorttxt'}= 1;
}
$text{'separator'}  = "\t"    if ($cfg{'legacy'} eq "quick");

push(@{$cfg{'do'}}, 'cipher') if ($#{$cfg{'do'}} < 0); # command
foreach $ssl (@{$cfg{'versions'}}) {
    next if ($cfg{$ssl} == 0);
    $cfg{$ssl} = 0; # reset to simplify further checks
    # ToDo: DTLSv9
    if ($ssl =~ /$cfg{'regex'}->{'SSLprot'}/) {
        # { DISABLED-CHECK (starting with VERSION 14.01.23)
            # some versions of Net::SSLeay seem not to support the methods for
            # all SSL versions even the underlying library supports it
            # hence the check (see below) is disabled for now
            push(@{$cfg{'version'}}, $ssl);
            $cfg{$ssl} = 1;
            next;
        # DISABLED-CHECK }
        # ToDO: enable checks again
        $typ = eval("Net::SSLeay::SSLv2_method()")   if ($ssl eq 'SSLv2');
        $typ = eval("Net::SSLeay::SSLv3_method()")   if ($ssl eq 'SSLv3');
        $typ = eval("Net::SSLeay::TLSv1_method()")   if ($ssl eq 'TLSv1');
        $typ = eval("Net::SSLeay::TLSv1_1_method()") if ($ssl eq 'TLSv11');
        $typ = eval("Net::SSLeay::TLSv1_2_method()") if ($ssl eq 'TLSv12');
        $typ = eval("Net::SSLeay::DTLSv1_method()")  if ($ssl eq 'DTLSv1');
        # ugly eval, but that's the simplest (only?) way to check if required
        # functionality is available; we could try  Net::SSLeay::CTX_v2_new()
        # and similar calls also, but that requires eval too
        # if a version like SSLv2 is not supported, perl bails out with error
        # like:        Can't locate auto/Net/SSLeay/CTX_v2_new.al in @INC ...
        if (defined $typ) {
            push(@{$cfg{'version'}}, $ssl);
            $cfg{$ssl} = 1;
        } else {# eval failed ..
            print "**WARNING: SSL version '$ssl' not supported by openssl; ignored\n";
        }
        # ToDo: geht nicht: Net::SSLeay::SSLv23_method();
    } else {    # SSL versions not supported by Net::SSLeay <= 1.51 (Jan/2013)
        warn("**WARNING: unsupported SSL version '$ssl'; ignored");
    }
}

if ($cfg{'shorttxt'} > 0) {     # reconfigure texts
    foreach $key (keys %data)   { $data{$key}  ->{'txt'} = $shorttexts{$key}; }
    foreach $key (keys %checks) { $checks{$key}->{'txt'} = $shorttexts{$key}; }
}

local $\ = "\n";

if (($cfg{'trace'} + $cfg{'verbose'}) >  0) {
    @{$cfg{'do'}} = @{$cfg{'cmd-info--v'}} if (@{$cfg{'do'}} eq @{$cfg{'cmd-info'}});
    _yeast_init();
}

usr_pre_cipher();

# get list of ciphers
my $ciphers = "";
if (_need_cipher() > 0) {
    _y_CMD("  get cipher list ..");
    my $pattern = $cfg{'cipherpattern'};# default pattern
       $pattern = $cfg{'cipher'} if ($cfg{'cipher'} ne 'yeast');# default setting: use all supported
    _trace("cipher pattern= $pattern");
    if ($cmd{'extciphers'} == 1) {
        $ciphers = Net::SSLinfo::cipher_local($pattern);
    } else {
        $ciphers = Net::SSLinfo::cipher_list( $pattern);
    }
    if ($ciphers =~ /^\s*$/) {  # empty list, try openssl and local list
        print "**WARNING: given pattern '$pattern' did not return cipher list";
        _y_CMD("  get cipher list using openssl ..");
        $ciphers = Net::SSLinfo::cipher_local($pattern);
        if ($ciphers =~ /^\s*$/) {  # empty list, try openssl and local list
            #if ($pattern =~ m/(NULL|COMP|DEF|HIG|MED|LOW|PORT|:|@|!|\+)/) {
            #    _trace(" cipher match: $pattern");
            #} else {
            #    _trace(" cipher privat: $pattern");
_dbx "\n########### fix this place (empty cipher list) ########\n";
# ToDo: #10jan14: reimplement this check when %ciphers has a new structure
            #10jan14    my ($c, $new);
            #10jan14    my $new_list = "";
            #10jan14    foreach $c (split(" ", $pattern)) {
            #10jan14        $new = _find_cipher_name($c);
            #10jan14        if ($new =~ m/^\s*$/) {
            #10jan14            if ($c !~ m/[A-Z0-9:+!-]+/) {
            #10jan14                # does also not match any special key accepted by openssl
            #10jan14                warn("**WARNING: unknown cipher name '$c'; ignored");
            #10jan14                next;
            #10jan14            }
            #10jan14        }
            #10jan14        $new_list = $new . " ";
            #10jan14    }
            #10jan14    $ciphers = $new_list;
            #}
            #_yeast(" ciphers: $ciphers") if ($cfg{'trace'} > 0);
        }
    }
    if ($ciphers =~ /^\s*$/) {
        print "Errors: " . Net::SSLinfo::errors();
        die("**ERROR: no ciphers found; may happen with openssl pre 1.0.0 according given pattern");
    }
    $ciphers =~ s/:/ /g;        # internal format are words separated by spaces
    push(@{$cfg{'ciphers'}}, split(" ", $ciphers));  # NOT YET USED
}
    _v_print("cipher list: $ciphers");

usr_pre_main();

# main: do the work
# -------------------------------------
# first all commands which do not make a connection
printversion(),    exit 0   if (_is_do('version'));
printopenssl(),    exit 0   if (_is_do('libversion'));
printcipherlist(), exit 0   if (_is_do('list'));

$legacy = $cfg{'legacy'};

# now commands which do make a connection
usr_pre_host();

# run the appropriate SSL tests for each host (ugly code down here):
$port = ($cfg{'port'}||"");     # defensive programming
foreach $host (@{$cfg{'hosts'}}) {
    if ($host =~ m#.*?:\d+#) { 
       ($host, $port) = split(":", $host);
        $cfg{'port'}  = $port;  #
        $cfg{'host'}  = $host;
    }
    _y_CMD("host{ " . ($host||"") . ":" . $port);
    _resetchecks();
    printheader(_subst($text{'out-target'}, "$host:$port"), "");

    # prepare DNS stuff
    #  gethostbyname() and gethostbyaddr() set $? on error, needs to be reset!
    my $rhost = "";
    my $fail  = '<<gethostbyaddr() failed>>';
    $? = 0;
    $cfg{'host'}        = $host;
    $cfg{'ip'}          = gethostbyname($host); # primary IP as identified by given hostname
    if (!defined $cfg{'ip'}) {
        warn("**WARNING: Can't get IP for host '$host'; ignored");
        _y_CMD("host}");
        next; # otherwise all following fails
    }
    $cfg{'IP'}          = join(".", unpack("W4", $cfg{'ip'}));
    if ($cfg{'usedns'} == 1) {  # following settings only with --dns
        $cfg{'rhost'}   = gethostbyaddr($cfg{'ip'}, AF_INET);
        $cfg{'rhost'}   = $fail if ($? != 0);
    }
    $? = 0;
    if ($cfg{'usedns'} == 1) {
        my ($fqdn, $aliases, $addrtype, $length, @ips) = gethostbyname($host);
        my $i = 0;
        foreach my $ip (@ips) {
            $? = 0;
            $rhost  = gethostbyaddr($ip, AF_INET);
            $rhost  = $fail if ($? != 0);
            $cfg{'DNS'} .= join(".", unpack("W4", $cfg{'ip'})) . " " . $rhost . "; ";
            #dbx# printf "[%s] = %s\t%s\n", $i, join(".",unpack("W4",$ip)), $rhost;
        }
        warn("**WARNING: Can't do DNS reverse lookup: for $host: $fail; ignored") if ($cfg{'rhost'} =~ m/gethostbyaddr/);
    }
    $? = 0;

    # print DNS stuff
    if (($info + $check) > 0) {
        _y_CMD("+info || +check");
        if ($legacy =~ /(full|compact|simple)/) {
            printruler();
            print_line($legacy, $host, 'host-host', $text{'host-host'}, $host);
            print_line($legacy, $host, 'host-IP',   $text{'host-IP'}, $cfg{'IP'});
            if ($cfg{'usedns'} == 1) {
                print_line($legacy, $host, 'host-rhost', $text{'host-rhost'}, $cfg{'rhost'});
                print_line($legacy, $host, 'host-DNS',   $text{'host-DNS'},   $cfg{'DNS'});
            }
            printruler();
        }
    }

    usr_pre_info();

    # check if SNI supported
        # to do this, we need a clean SSL connection with SNI disabled
        # see SSL_CTRL_SET_TLSEXT_HOSTNAME in NET::SSLinfo
        # finally we close the connection to be clean for all other tests
    if ($cfg{'usesni'} != 0) {      # useful with SNI only
        _trace(" cn_nosni: {");
        $Net::SSLinfo::use_SNI  = 0;
        if (defined Net::SSLinfo::do_ssl_open($host, $port, (join(" ", @{$cfg{'version'}})), $ciphers)) {
            $data{'cn_nosni'}->{val}= $data{'cn'}->{val}($host, $port);
            Net::SSLinfo::do_ssl_close($host, $port);
        }
        $Net::SSLinfo::use_SNI  = $cfg{'usesni'};
        _trace(" cn_nosni: $data{'cn_nosni'}->{val}  }");
    }

    usr_pre_open();

    # Check if there is something listening on $host:$port
        # use Net::SSLinfo::do_ssl_open() instead of IO::Socket::INET->new()
        # to check the connection (hostname and port)
    if (!defined Net::SSLinfo::do_ssl_open($host, $port, (join(" ", @{$cfg{'version'}})), $ciphers)) {
        my $err     = Net::SSLinfo::errors( $host, $port);
        if ($err !~ /^\s*$/) {
            _v_print($err);
            warn("**WARNING: Can't make a connection to $host:$port; target ignored");
            goto CLOSE_SSL;
        }
    }

    usr_pre_cmds();

    if (_is_do('dump')) {
        _y_CMD("+dump");
        if ($cfg{'trace'} > 1) {   # requires: --v --trace --trace
            _trace(' ############################################################ %SSLinfo');
            print Net::SSLinfo::dump();
        }
        printdump($legacy, $host, $port);
    }

    if (_need_cipher() > 0) {
        _y_CMD("  need_cipher ..");
        @results = ();          # new list for every host
        $checks{'cnt_totals'}->{val} = 0;
        foreach $ssl (@{$cfg{'version'}}) {
            checkciphers($ssl, $host, $port, $ciphers, \%ciphers);
        }
     }

    usr_pre_data();

    # check ciphers manually (required for +check also)
    if (_is_do('cipher') or $check > 0) {
        _y_CMD("+cipher");
        _trace(" ciphers: $ciphers");
        # ToDo: for legacy==testsslserver we need a summary line like:
        #      Supported versions: SSLv3 TLSv1.0
        my $_printtitle = 0;    # count title lines
        foreach $ssl (@{$cfg{'version'}}) {
            # ToDo: single cipher check: grep for cipher in %{$ciphers}
            #dbx# _dbx "$ssl # ", keys %{$ciphers} ; #sort keys %hash;
            $_printtitle++;
            if (($legacy ne "sslscan") or ($_printtitle <= 1)) {
                printtitle($legacy, $ssl, $host, $port);
            }
            printciphers($legacy, $ssl, $host, $port, ($legacy eq "sslscan")?($_printtitle):0, @results);
        }
        foreach $ssl (@{$cfg{'version'}}) {
            print_cipherdefault($legacy, $ssl, $host, $port) if ($legacy eq 'sslscan');
        }
        printruler() if ($quick == 0);
        printheader("\n" . _subst($text{'out-summary'}, ""), "");
        foreach $ssl (@{$cfg{'version'}}) {
            print_check($legacy, $host, $ssl, undef);
        }
        printruler() if ($quick == 0);
    }

    goto CLOSE_SSL if ((_is_do('cipher') > 0) and ($quick == 0));

    if (_need_checkssl() > 0) {
        _y_CMD("  need_checkssl ..");
        _trace(" checkssl {");
        checkssl( $host, $port);
        _trace(" checkssl }");
     }

    checkhttp( $host, $port); # may be already done in checkssl()
    checksni(  $host, $port); #  "
    checksizes($host, $port); #  "
    checkdv(   $host, $port); #  "
    checkdest( $host, $port);

    usr_pre_print();

    if ($check > 0) {
        _y_CMD("+check");
        print "**WARNING: no openssl, some checks are missing" if (($^O =~ m/MSWin32/) and ($cmd{'extopenssl'} == 0));
    }

    # for debugging only
    if (_is_do('s_client')) { _y_CMD("+s_client"); print "#{\n", Net::SSLinfo::s_client($host, $port), "\n#}"; }
    _y_CMD("do=".join(" ",@{$cfg{'do'}}));

    # print all required data and checks
    printdata(  $legacy, $host) if ($check == 0); # not for +check
    printchecks($legacy, $host) if ($info  == 0); # not for +info

    if ($cfg{'out_score'} > 0) { # no output for +info also
        scoring($host, $port);
        # simple rounding in perl: $rounded = int($float + 0.5)
        $scores{'checks'}->{val} = int(
            ((
              $scores{'check_cert'}->{val}
            + $scores{'check_conn'}->{val}
            + $scores{'check_dest'}->{val}
            + $scores{'check_http'}->{val}
            ) / 4 ) + 0.5);
        printheader($text{'out-scoring'}, $text{'desc-score'});
        _trace_1arr('%scores');
        foreach $key (sort keys %scores) {
            next if ($key !~ m/^check_/); # print totals only
            print_line($legacy, $host, $key, $scores{$key}->{txt}, $scores{$key}->{val});
        }
        print_line($legacy, $host, 'checks', $scores{'checks'}->{txt}, $scores{'checks'}->{val});
        printruler();
        if (($cfg{'traceKEY'} > 0) && ($verbose > 0)) {
            printtable('score');
            printruler();
        }
    }

    CLOSE_SSL:
    _y_CMD("host}");
    Net::SSLinfo::do_ssl_close($host, $port);
    _trace(" done: $host");
    $cfg{'done'}->{'hosts'}++;

    usr_pre_next();

} # foreach host

usr_pre_exit();

_yeast_exit();

exit 0; # main

__END__
__DATA__

=pod

=encoding utf8

=head1 NAME

o-saft.pl - OWASP SSL audit for testers
            OWASP SSL advanced forensic tool

=head1 DESCRIPTION

This tools lists  information about remote target's  SSL  certificate
and tests the remote target according given list of ciphers.

Note:  Throughout this description  C<$0>  is used as an alias for the
       program name  C<o-saft.pl> .

=head1 SYNOPSIS

$0 [COMMANDS ..] [OPTIONS ..] target [target target ...]

Where  [COMMANDS]  and  [OPTIONS]  are described below  and  C<target>
is a hostname either as full qualified domain name or as IP address.
Multiple commands and targets may be combined.

All  commands  and  options  can also be specified in a  rc-file, see
B<RC-FILE>  below.

=head1 QUICKSTART

Before going into  a detailed description  of the  purpose and usage,
here are some examples of the most common use cases:

=over

=item Show supported (enabled) ciphers of target:

    $0 +cipher --enabled example.tld

=item Show details of certificate and connection of target:

    $0 +info example.tld

=item Check certificate, ciphers and SSL connection of target:

    $0 +check example.tld

=back

For more specialised test cases, refer to the B<COMMANDS> and B<OPTIONS>
sections below.

=head1 WHY?

Why a new tool for checking SSL security and configuration when there
are already a dozen or more such tools in existence (circa 2012)?
Currently available tools suffer from some or all of following issues:

=over

=item * lack of tests of unusual ciphers

=item * lack of tests of unusual SSL certificate configurations

=item * may return different results for the same checks on a given target

=item * missing tests for modern SSL/TLS functionality

=item * missing tests for specific, known SSL/TLS vulnerabilities

=item * no support for newer, advanced, features e.g. CRL, OCSP, EV

=item * limited capability to create your own customised tests

=back

Other  reasons or problems  are that they are either binary and hence
not portable to other (newer) platforms.

In contrast to (all?) most other tools,  including openssl, it can be
used to `ask simple questions' like `does target support STS' just by
calling:

    $0 +cipher +hsts_sts example.tld

For more, please see  B<EXAMPLES>  section below.

=begin comment

Or, if written in perl, they mainly use L<Net::SSLeay(1)> or 
L<IO::Socket::SSL(1)> which lacks CRL and OCSP and EV checkings.

=end comment

=head1 RESULTS

For the results,  we have to distinguish those returned by  I<+cipher>
command  and those from all other tests and checks like  I<+check>  or
I<+info>  command.

=head3 +cipher

    The cipher checks will return one line for each tested cipher. It
    contains at least the cipher name,  "yes"  or  "no"  whether it's
    supported or not, and a security qualification. It may look like:
        AES256-SHA       yes    HIGH
        NULL-SHA         no     weak

    Depending on the used  "--legacy=*"  option the format may differ
    and also contain more information.  For details see  "--legacy=*"
    option below.

    The text for security qualifications are mainly those returned by
    openssl (version 1.0.1): LOW, MEDIUM, HIGH and WEAK.
    The same texts but with all lower case characters are used if the
    qualification was adapted herein.

=head3 +check

    These tests return a line with a label describing the test  and a
    test result for it.  The  idea is to report  "yes"  if the result
    is considered "secure" and report the reason why it is considered
    insecure otherwise. Example of a check considered secure:
        Label of the performed check:           yes
    Example of a check considered insecure:
        Label of the performed check:           no (reason why)

    Note that there are tests where the results appear confusing when
    first viewed, like for www.wi.ld:
        Certificate is valid according given hostname:  no (*.wi.ld)
        Certificate's wildcard does not match hostname: yes
    This can for example occur with:
        Certificate Common Name:                *.wi.ld
        Certificate Subject's Alternate Names:  DNS:www.wi.ld

    Please check the result with the  "+info"  command also to verify
    if the check sounds reasonable.

=head3 +info

    The test result contains  detailed information.  The labels there
    are mainly the same as for the  "+check"  command.

All output is designed to make it easily parsable by  postprocessors.
Please see  B<OUTPUT>  section below for details.

=head1 COMMANDS

There are commands for various tests according the  SSL connection to
the target, the targets certificate and the used ciphers.

All commands are preceded by a  C<+>  to easily distinguish from other
arguments and options. However, some  I<--OPT>  options are treated as
commands for historical reason or compatibility to other programs.

The Most important commands are (in alphabetical order):

=head3 +check +cipher +info +http +list +quick +sni +sni_check +version

A list of all available commands will be printed with

    $0 --help=cmd

The summary and internal commands return requested information or the
results of checks. These are described below.
The description of all other commands will be printed with

    $0 --help=commands

=begin comment

    Nach  =head3  sollten die Paragraphen eingerueckt sein,  das kann
    (perl)pod aber nicht.  Darum verwenden wir  "verbatime paragraph"
    und verzichten auf spezielle POD-Auszeichnungen.

=end comment

=head2 Commands for information about this tool

All these commands will exit after execution (cannot be used together
with other commands).

=head3 +ciphers

    Show ciphers offerd by local SSL implementation and by target.

    Note that SSL requires a successful connection to the target.  If
    no target is given, we try to get the list using "openssl(1)".

=head3 +list

    Show all ciphers  known by this tool.  This includes cryptogrphic
    details of the cipher and some internal details about the rating.

    Use "--v" option to show more details.

=head3 +abbr +abk

    Show common abbreviation used in the world of security.

=head3 +version

    Show version information for both the program and the Perl modules
    that it uses, then exit.

    Use "--v" option to show more details.

=head3 +libversion

    Show version of openssl.

=head3 +todo

    Show known problems and bugs.

=head2 Commands to check SSL details

=begin comment wozu-dieser-text

    Check for SSL connection in  SNI mode and if given  FQDN  matches
    certificate's subject.

=end comment

    Following (summary, internal) commands  are simply a shortcut for
    a list of other commands. For details of the list use:

        $0 --help=intern

=head3 +check

    Check the SSL connection for security issues. This is the same as
     "+info +cipher +sizes --sslv2 --sslv3 --tls1"
    but also gives some kind of scoring for security issues if any.

=begin comment

    The rating is mainly based on the information given in
        http://ssllabs.com/.....

=end comment

=head3 +http

    Perform HTTP checks (like STS, redirects etc.).

=head3 +info

    Overview of most important details of the SSL connection.

    Use "--v" option to show details also, which span multiple lines.

=head3 +info--v

    Overview of all details of the SSL connection. This is a shortcut
    for all commands listed below but not including "+cipher".

    This command is intended for debugging  as it prints some details
    from the used  Net::SSLinfo  module.

=head3 +quick

    Quick overview of checks. Implies "--enabled"  and  "--short".

=head3 +sni

    Check for Server Name Indication (SNI) usage.

=head3 +sni_check +check_sni

    Check for  Server Name Indication (SNI) usage and validity of all
    names (CN, subjectAltName, FQDN, etc.).

=head3 +bsi

    Various checks according BSI TR-02102-2 compliance.

=head3 +ev

    Various checks according certificate's extended Validation (EV).

=head3 +sizes

    Check length, size and count of some values in the certificate.

=head3 +s_client

    Dump data retrieved from  "openssl s_client ..."  call. Should be
    used for debugging only.
    It can be used just like openssl itself, for example:
        "openssl s_client -connect host:443 -no_sslv2"

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

    Note that ciphers  not supported  by the local SSL implementation
    are not checked by default, use "--local" option for that.

=head2 Commands to test SSL connection to target

Please see:

    $0 --help=commands

=head2 Commands to show details of the target's certificate

Please see:

    $0 --help=commands

=head1 OPTIONS

All options are written in lowercase. Words written in all capital in
the description here is text provided by the user.

=head2 General options

=head3 --h

=head3 --help

  WYSIWYG

  Note: The documentation is written  with perl's POD format and uses
        perl's POD module to print it.  Unfortunately  the first line
        written by  POD  is:
            "User Contributed Perl Documentation"
        which may be a bit misleading because all descriptions of the
        documentation belong to this tool itself.

=head3 --help=cmd

  Show available commands.

=head3 --help=commands

  Show available commands with short description.

=head3 --help=checks

  Show available checks.

=head3 --help=legacy

  Show possible legacy formats (used as value in  "--legacy=KEY").

=head3 --help=compliance

  Show available compliance checks.

=head3 --help=intern

  Show internal commands.

=head3 --help=score

  Show score value for each check.
  Value is printed in format to be used for  "--cfg_score=KEY=SCORE".

  Note that the  sequence  of options  is important.  Use the options
  "--trace"  and/or  "--cfg_score=KEY=SCORE"  before  "--help=score".

=head3 --help=text

  Show texts used in various messages.

=head3 --help=text-cfg

  Show texts used in various messages ready for use in in  RC-FILE or
  as option.

=head3 --help=regex

  Show regular expressions used internally.

=head3 --dns

  Do DNS lookups to map given hostname to IP, do a reverse lookup.

=head3 --no-dns

  Do not make DNS lookups.
  Note  that the corresponding IP and reverse hostname may be missing
  in some messages then.

=head3 --host=HOST

  Specify HOST as target to be checked. Legacy option.

=head3 --port=PORT

  Specify target's PORT to be used. Legacy option.

=head3 --host=HOST and --port=PORT and HOST:PORT and HOST

  When giving more than one HOST argument,  the sequence of the given
  HOST argument and the given  --port=PORT  and the given --host=HOST
  options are important.
  The rule how ports and hosts are mapped is as folollows:
      HOST:PORT arguments are uses as is (connection to HOST on PORT)
      only HOST is given, then previous specified --port=PORT is used
  Note that URLs are treated as HOST:PORT, if they contain a port.
  Example:
      $0 +cmd host-1 --port 23 host-2 host-3:42 host-4
  will connect to:
      host-1:443
      host-2:23
      host-3:42
      host-4:23

=head2 Options for SSL tool

=head3 --s_client

  Use  "openssl s_slient ..." call to retrieve more informations from
  the SSL connection.  This is disabled by default on Windows because
  of performance problems. Without this option following informations
  are missing on Windows:
      compression, expansion, renegotiation, resumption,
      selfsigned, verify, chain, protocols
  See "Net::SSLinfo" for details.

  If used together with "--trace", s_client data will also be printed
  in debug output of "Net::SSLinfo".

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

=head3 --force-openssl

  Use openssl to check for supported ciphers;  default: IO::Socket

  This option forces to use  "openssl s_slient -connect CIPHER .." to
  check if a cipher is supported by the remote target. This is useful
  if the "--lib=PATH" option doesn't work (for example due to changes
  of the API or other incompatibilities).

=end comment

=head3 --exe-path=PATH --exe=PATH

  PATH      is a full path where to find openssl.

=head3 --lib-path=PATH --lib=PATH

  PATH      is a full path where to find libssl.so and libcrypto.so

  See "HACKER's INFO" below for a detailed description how it works.

=head3 --envlibvar=NAME

  NAME  is the name of the environment variable containing additional
  paths for searching dynamic shared libraries.
  Default is LD_LIBRARY_PATH .

  Check your system for the proper name, i.e.:
      DYLD_LIBRARY_PATH, LIBPATH, RPATH, SHLIB_PATH .

=head3 --call=METHOD

  METHOD    method to be used for specific functionality

  Available methods:
      info-socket    use internal socket for retrieving informations
      info-openssl   use external openssl for retrieving informations
      info-user      use usr_getinfo() for retrieving informations
      cipher-socket  use internal socket to ckeck for ciphers
      cipher-openssl use external openssl to ckeck for ciphers
      cipher-user    use usr_getciphers() to ckeck for ciphers
  
  Method names starting with:
      info-   are responsible for retrieving  informations  about the
              SSL connection and the target certificate (i.g. what is
              provided by  +info  command)
      cipher- are responsible to connect to the target and test if it
              supports the specified ciphers (i.g. what is needed for
              +cipher  command)
      check-  are responsible for performing the checks (i.e. what is
              shown with  +check  command)
      score-  are responsible to compute the score based on the check
              results
  
  The second part of the name denotes which kind of method too call:
      socket    the internal functionality with sockets is used
      openssl   the exteranl openssl executable is used
      user      the external special function, as specified in user's
                o-saft-usr.pl,  is used.

  Example:
      --call=cipher-openssl
  will use the external  openssl  executable to check  the target for
  supported ciphers.

  Default settings are:
      --call=info-socket --call=cipher-socket --call=check-socket

  Just for curiosity, instead of using:

      $0 --call=info-user --call=cipher-user --call=check-user \
         --call=score-user ...

  consider to use your own script like:

      #!/usr/bin/env perl
      usr_getinfo();usr_getciphers();usr_checkciphers();usr_score();

  :-))

=head2 Options for SSL connection to target

=head3 --cipher=CIPHER

  CIPHER    can be any string accepeted by openssl or following:

  yeast     use all ciphers from list defined herein, see "+list"

  Beside the cipher names accepted by openssl, CIPHER can be the name
  of the constant or the (hex) value as defined in openssl's files.
  Currently supported are the names and constants of openssl 1.0.1c .
  Example:
      --cipher=DHE_DSS_WITH_RC4_128_SHA
      --cipher=0x03000066
      --cipher=66
  will be mapped to   DHE-DSS-RC4-SHA

  Note: if more than one cipher matches, just one will be selected.

  Default is "ALL:NULL:eNULL:aNULL:LOW" as specified in Net::SSLinfo.

=head3 --local

  It does not make much sense trying a connection with a cipher which
  is  not supported  by the local SSL implementation. Hence these are
  silently ignored by default.
  With this option we try to use such ciphers also.

  Option reserved for future use ...

=head3 --SSL

=head3 --no-SSL

  SSL       can be any of:  ssl, ssl2, ssl3, sslv2, sslv3, tls1,
      tls1, tls11, tls1.1, tls1-1, tlsv1, tlsv11, tlsv1.1, tlsv1-1
      (and similar variants for tlsv1.2).
  For example  "--tls1"  "--tlsv1"  "--tlsv1_1"  are all the same.

  ("--SSL" variants):    Test ciphers for this SSL/TLS version.
  ("--no-SSL" variants): Don't test ciphers for this SSL/TLS version.

=head3 --nullsslv2

  This option  forces  to assume that  SSLv2  is enabled  even if the
  target does not accept any ciphers.

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
  default string (see  "--no-cert-text TEXT"  option).

=head3 --no-cert-text TEXT

  Set  TEXT  to be returned from  "Net::SSLinfo.pm" if no certificate
  data is collected due to use of  "--no-cert".

=head3 --ca-depth INT

  Check certificate chain to depth  INT (like openssl's -verify).

=head3 --ca-file FILE

  Use  FILE  with bundle of CAs to verify target's certificate chain.

=head3 --ca-path DIR

  Use  DIR  where to find CA certificates in PEM format.

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

=head2 Options for output format

=head3 --short

  Use short less descriptive text labels for  "+check"   and  "+info"
  command.

=head3 --legacy=TOOL

  For compatibility with other tools,  the output format used for the
  result of the "+cipher" command can be adjusted to mimic the format
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
    testsslserver:format of output similar to  TestSSLServer.jar

  Note that these legacy formats only apply to  output of the checked
  ciphers. Other texts like headers and footers are adapted slightly.

  Please don't expect identical output as the TOOL, it's a best guess
  and should be parsable in a very similar way.

  TOOL may also be set to any of following internally defined values:

    compact:      mainly avoid tabs and spaces
                  format is as follows
                    Some Label:<-- anything right of colon is data
    full:         pretty print: each label in its  own line, followed
                  by data in next line prepended by tab character
                  (useful for "+info" only)
    quick:        use tab as separator; print ciphers with bit length
                  ("--tab" not necessary)
    simple:       default format

=head3 --format=FORM

  FORM may be one of follwoing:

    raw           print raw data as passed from Net::SSLinfo
                  Note: all data is printed as is, without additional
                  label or formatting.  It is recommended to use this
                  option in conjunction with exactly one command.
                  Otherwise the user needs to know how to `read'  the
                  printed data.
    hex           convert some data to hex: 2 bytes separated by :

=head3 --header

  Print formatting header.  Default for  "+check", "+info", "+quick".
  and  "+cipher"  only.

=head3 --no-header

  Do not print formatting header.
  Usefull if raw output should be passed to other programs.

=head3 --score

  Print scoring results. Default for  "+check".

=head3 --no-score

  Do not print scoring results.

=head3 --separator=CHAR

=head3 --sep=CHAR

  CHAR      will be used as separator between  label and value of the
      printed results. Default is  :

=head3 --tab

  TAB character (0x09, \t)  will be used  as separator between  label
      and value of the printed results.
  As label and value are already separated by a  TAB  character, this
  options is only useful in conjunction with the   "--legacy=compact"
  option.

=head3 --showhost

  Prefix each printed line with the given hostname (target).
  The hostname will be followed by the separator character.

=begin comment

  However, it applies partially if used twice for  +info.

=end comment

=head3 --win-CR

  Print windows-Style with CR LF as end of line. Default is NL only.

=head2 Options for compatibility with other programs

Please see other programs for detailed description (if not obvious:).
Note that only the long form options are accepted  as most short form
options are ambiguous.

=over 4

=item * --capath DIR      (curl)           same as I<--ca-path DIR>

=item * --CApath=DIR      (openssl)        same as I<--ca-path DIR>

=item * --ca-directory=DIR        (wget)   same as I<--ca-path DIR>

=item * --cacert FILE     (curl)           same as I<--ca-file DIR>

=item * --CAfile=FILE     (openssl)        same as I<--ca-file DIR>

=item * --ca-certificate=FILE     (wget)   same as I<--ca-path DIR>

=item * --hide_rejected_ciphers (sslyze)   same as I<--disabled>

=item * --http_get        (ssldiagnos)     same as I<--http>

=item * --no-failed       (sslscan)        same as I<--disabled>

=item * --regular         (sslyze)         same as I<--http>

=item * --reneg           (sslyze)         same as I<+renegotiation>

=item * --resum           (sslyze)         same as I<+resumtion>

=item * -h, -h=HOST       (various tools)  same as I<--host HOST>

=item * -p, -p=PORT       (various tools)  same as I<--port PORT>

=item * -noSSL                             same as I<--no-SSL>

=item * -no_SSL                            same as I<--no-SSL>

  For definition of  "SSL"  see  "--SSL"  and  "--no-SSL"  above.

=item * --insecure        (cnark.pl)       ignored

=item * --ism, --pci -x   (ssltest.pl)     ignored

=item * --timeout, --grep (ssltest.pl)     ignored

=item * -r,  -s,  -t      (ssltest.pl)     ignored

=item * -connect, --fips, -H, -u, -url, -U ignored

=back

=head2 Options for customization

  For general descriptions please see  CUSTOMIZATION  section below.

=head3 --cfg_cmd=CMD=LIST

  Redefine list of commands. Sets  %cfg{cmd-CMD}  to  LIST.  Commands
  are written without the leading  "+".
  CMD       can be any of:  bsi, check, http, info, quick, sni, sizes
  Example:
      --cfg_cmd=sni=sni hostname

  To get a list of commands and their settings, use:

      $0 --help=intern

  Main purpose is to reduce list of commands or print them sorted.

=head3 --cfg_score=KEY=SCORE

  Redefine value for scoring. Sets  %checks{KEY}{score}  to  SCORE.
  Most score values are set to 10 by default. Values "0" .. "100" are
  allowed.

  To get a list of current score settings, use:

      $0 --help=score

  For deatils how scoring works, please see  SCORING  section.

  Use the  "--trace-key"  option for the  "+info"  and/or  "+check"
  command to get the values for  KEY.

=head3 --cfg_checks=KEY=TEXT --cfg_data=KEY=TEXT

  Redefine texts used for labels in output. Sets  %data{KEY}{txt}  or
  %checks{KEY}{txt}  to  TEXT.

  To get a list of preconfigured labels, use:

      $0 --help=cfg_checks
      $0 --help=cfg_data

=head3 --cfg_text=KEY=TEXT

  Redefine general texts used in output. Sets  %text{KEY}  to  TEXT.

  To get a list of preconfigured texts, use:

      $0 --help=cfg_text

  Note that \n, \r and \t are replaced by the corresponding character
  when read from RC-FILE.

=head3 --call=METHOD

  See  L<Options for SSL tool>

=head3 --usr

  Execute functions defined in  o-saft-usr.pm.

=head2 Options for tracing and debugging

=head3 --n

  Do not execute, just show commands (only useful in conjunction with
  using openssl).

=head3 --v

=head3 --verbose

  Print more information about checks.

  Note that this option should be first otherwise some debug messages
  are missing.

=head3 --v --v

  Print remotely checked ciphers.

=head3 --v --v --v

  Print remotely checked ciphers one per line.

=head3 --v --v --v --v

  Print processed ciphers (check, skip, etc.).

=head3 --trace

  Print debugging messages.

=head3 --trace --trace

  Print more debugging messages and pass "trace=2" to Net::SSLeay and
  Net::SSLinfo.

=head3 --trace --trace --trace

  Print more debugging messages and pass "trace=3" to Net::SSLeay and
  Net::SSLinfo.

=head3 --trace --trace --trace --trace

  Print processing of all command line arguments.

=head3 --trace--

=head3 --trace-arg

  Print command line argument processing.

=for comment cannot use --trace=  'cause = will be removed (CGI mode)

=head3 --trace-cmd

  Trace execution of command processing (those given as  +*).

=head3 --trace@

=head3 --trace-key

  Print some internal variable names in output texts (labels).
  Variable names are prefixed to printed line and enclosed in  # .
  Example without --trace-key :
      Certificate Serial Number:          deadbeef

  Example with    --trace-key :
      #serial#          Certificate Serial Number:          deadbeef

=head3 --trace=VALUE

=over 4

=item * --trace=1                          same as I<--trace>

=item * --trace=2                          same as I<--trace> I<--trace>

=item * --trace=arg                        same as I<--trace-arg>

=item * --trace=cmd                        same as I<--trace-cmd>

=item * --trace=key                        same as I<--trace-key>

=back

=head3 --trace=FILE

  Use FILE instead of the default rc-file (.o-saft.pl, see RC-FILE).

=head2 --trace vs. --v

While  I<--v>  is used to print more data, I<--trace> is used to print
more information about internal data such as  procedure names and/or
variable names and program flow.

=head2 Options vs. Commands

For compatibility with other programs and lazy users, some arguments
looking like options are silently taken as commands. This means that
I<--THIS>  becomes  I<+THIS>  then. These options are:

=over 4

=item * --help

=item * --abbr

=item * --todo

=item * --chain

=item * --default

=item * --fingerprint

=item * --list

=item * --version

=back

Take care that this behaviour may be removed in future versions as it
conflicts with those options and commands which actually exist, like:

=over 4

=item --sni  vs.  +sni

=back

=head1 LAZY SYNOPSIS

We support following options, which are all identical, for lazy users
and for compatibility with other programs.

=head2 Option Variants

    --port PORT
    --port=PORT

This applies to most such options,  I<--port>  is just an example.
When used in the RC-FILE, the I<--OPTION=VALUE> variant must be used.

=for comment does not apply to --trace option

=head2 Option Names

Dash  C<->  and/or  underscore  C<_>  in option names are optional.
    --no-dns
    --no_dns
    --nodns

This applies to all such options, I<--no-dns> is just an example.

=head2 Targets

Following syntax is supported also:

    $0 http://some.tld other.tld:3889/some/path?a=b

Note that only the hostname and the port are used from an URL.

=head2 Options vs. Commands

See  B<Options vs. Commands>  in  B<OPTIONS>  section above

=head1 CHECKS

All SSL related check performed by the tool will be described here in
the near future (Any help appreciated ...).

=head2 General Checks

Lookup the IP of the given hostname (FQDN), and then tries to reverse
resolve the FQDN again.

=head2 SSL Ciphers

Check which ciphers are supported by target. Please see B<RESULTS> for
details of this check.

=head2 SSL Connection

=head2 SSL Vulnerabilities

=head3 ADH

Check if ciphers for anonymous key exchange are supported: ADH|DHA .
Such key exchanges can be sniffed.

=head3 EDH

Check if ephemeral ciphers are supported: DHE|EDH .
They are necessary to support Perfect Forward Secrecy (PFS).

=head3 BEAST

Currently (2014) only a simple check is used: only RC4 ciphers used.
Which is any cipher with RC4, ARC4 or ARCFOUR.
TLSv1.2 checks are not yet implemented.

=head3 CRIME

Connection is vulnerable if target supports SSL-level compression.

=head3 Lucky 13

NOT YET IMPLEMENTED

=head3 RC4

Check if RC4 ciphers are supported.
They are assumed to be broken.

=head3 PFS

Currently (2014) only a simple check is used: only DHE ciphers used.
Which is any cipher with DHE or ECDHE. SSLv2 does not support PFS.
TLSv1.2 checks are not yet implemented.

=head2 Target (server) Configuration and Support

=head2 Target (server) Certificate

=head3 Root CA

Provided certificate by target should not be a Root CA.

=head3 Self-signed Certificate

Certificate should not be self-signed.

=head3 IP in CommonName or subjectAltname (RFC6125)

NOT YET IMPLEMENTED

=head3 OCSP, CRL, CPS

Certificate should contain URL for OCSP and CRL.

=head3 Sizes and Lengths of Certificate Settings

=over 4

=item Serial Number <= 20 octets (RFC5280, 4.1.2.2.  Serial Number)

=back

...

=head3 DV-SSL - Domain Validation Certificate

The Certificate must provide:

=over 4

=item * Common Name C</CN=> field

=item * Common Name C</CN=> in C<subject>  or C<subjectAltname> field

=item * Domain name in I<commonName> or C<altname> field

=back

=head3 EV-SSL - Extended Validation Certificate

This check is performed according the requirements defined by the CA/
Browser Forum  https://www.cabforum.org/contents.html .
The Certificate must provide:

=over 4

=item * DV - Domain Validation Certificate (see above)

=item * Organization name C</O=> Cn I<subject> field

=item * Organization name must be less to 64 characters

=item * Business Category C</businessCategory=> in C<subject> field

=item * Registration Number C</serialNumber=> in C<subject> field

=item * Address of Place of Business in C<subject> field

Required are: C</C=>, C</ST=>, C</L=>

Optional are: C</street=>, C</postalCode=>

=item * Validation period does not exceed 27 month

=back

See  LIMITATIONS  also.

=head2 Target (server) HTTP(S) Support

=head3 STS header

Using STS is no perfect security.  While the very first request using
http: is always prone to a MiTM attack, MiTM is possible to following
requests again, if STS is not well implemented on the server.

=over 4

=item * Request with http: should be redirected to https:

=item * Redirects should use status code 301 (even others will work)

=item * Redirect's Location header must contain schema https:

=item * Redirect's Location header must redirect to same FQDN

=item * Redirect may use Refresh instead of Location header (not RFC6797)

=item * Redirects from HTTP must not contain STS header

=item * Answer from redirected page (HTTPS) must contain STS header

=item * STS header must contain includeSubDirectoy directive

=item * STS header max-age should be less than 1 month

=back

=head3 Publix Key Pins header

TBD - to be described ...

=head2 Compliances

=head3 FIPS-140

=head3 ISM

=head3 PCI

=head3 BSI TR-02102

Checks if connection and ciphers are compliant according TR-02102-2,
see https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen
/TechnischeRichtlinien/TR02102/BSI-TR-02102-2_pdf.pdf?__blob=publicationFile

(following headlines are taken from there)

=for comment above link written in 2 lines, otherwise perldoc complains:
=for comment "<standard input>:1450: warning [p 12, 2.2i]: can't break line"

=over 4

=item 3.2.1 Empfohlene Cipher Suites

=item 3.2.2 Übergangsregelungen

    RC4 allowed temporary for TLS 1.0. Only if  TLS 1.1  and  TLS 1.2
    cannot be supported.

=item 3.2.3 Mindestanforderungen für Interoperabilität

    Must at least support: ECDHE-ECDSA-* and ECDHE-RSA-*

=item 3.3 Session Renegotation

    Only server-side (secure) renegotiation allowed (see RFC5280).

=item 3.4 Zertifikate und Zertifikatsverifikation

    Must have "CRLDistributionPoint" or "AuthorityInfoAccess".

    MUST have "OCSP URL".

    "PrivateKeyUsage" must not exceed three years for certificate and
    must not exceed five years for CA certificates.

    "Subject",  "CommonName"  and  "SubjectAltName"  must not contain
    a wildcard.

    Certificate itself must be valid according dates if validity.
    Note that  the validity check relies on the years provided by the
    certificate's  "before"  and  "after"  values only. For example a
    certificate valid  from Jan 2013 to Mar 2016  is considered valid
    even the validity is more than three years.

    All certificates in the chain must be valid.
    **NOT YET IMPLEMENTED**

    Above conditions are not required for lazy checks.

=item 3.5 Domainparameter und Schlüssellängen

    **NOT YET IMPLEMENTED**

=begin comment

+--------------+---------------+--------
		Minimale
 Algorithmus	Schlüssellänge	Verwendung bis
+--------------+---------------+--------
 Signaturschlüssel für Zertifikate und Schlüsseleinigung
   ECDSA	224 Bit	2015
   ECDSA	250 Bit	2019+
     DSS	2000 Bit3	2019+
     RSA	2000 Bit3	2019+
 Statische Diffie-Hellman Schlüssel
    ECDH	224 Bit	2015
    ECDH	250 Bit	2019+
     DH	2000 Bit	2019+
 Ephemerale Diffie-Hellman Schlüssel
    ECDH	224 Bit	2015
    ECDH	250 Bit	2019+
      DH	2000 Bit	2019+
+--------------+---------------+--------

=end comment

=item 3.6 Schlüsselspeicherung

    This requirement is not testable from remote.

=item 3.7 Umgang mit Ephemeralschlüsseln

    This requirement is not testable from remote.

=item 3.8 Zufallszahlen

    This requirement is not testable from remote.

=back

=head1 SCORING

Coming soon ...

=head1 OUTPUT

All output is designed to make it  easily parsable by postprocessors.
Following rules are used:

=over 4

=item * Lines for formatting or header lines start with C<=>.

=item * Lines for verbosity or tracing start with C<#>.

=item * Errors and warnings start with C<**>.

=item * Empty lines are comments ;-)

=item * Label texts end with a separation character; default is  C<:>.

=item * Label and value for all checks are separated by  at least one  TAB
character.

=item * Texts for additional information are enclosed in  C<<<>  and  ">>".

=item * C<N/A> is used when no proper informations was found or provided.

    Replace  C<N/A> by whatever you think is adequate:  No answer,
    Not available,  Not applicable,  ...

=back

When used in  I<--legacy=full>  or I<--legacy=simple>  mode, the output
may contain formatting lines for better (human) readability.

=head2 Postprocessing Output

It is recommended to use the  I<--legacy=quick>  option, if the output
should be postprocessed, as it omits the default separation character
(C<:> , see above) and just uses on single tab character (0x09, \t  or
TAB) to separate the label text from the text of the result. Example:
        Label of the performed checkTABresult


=head1 CUSTOMIZATION

This tools can be customized as follows:

=over 4

=item Using command line options

    This is a simple way to redefine  specific settings.  Please  see
    CONFIGURATION OPTIONS  below.

=item Using Configuration file

    A configuration file can contain multiple configuration settings.
    Syntax is simply  KEY=VALUE. Please see CONFIGURATION FILE below.

=item Using resource files

    A resource file can contain multiple command line options. Syntax
    is the same as for command line options iteself.  Each  directory
    may contain its own resource file. Please see  RC-FILE  below.

=item Using debugging files

    These files are --nomen est omen-- used for debugging purposes.
    However, they can be (mis-)used to redefine all settings too.
    Please see  DEBUG-FILE  below.

=item Using user specified code

    This file contains  user specified  program code.  It can also be
    (mis-)used to redefine all settings. Please see USER-FILE  below.

=back

Customization is done by redefining values in internal data structure
which are:  %cfg,  %data,  %checks,  %text,  %scores .

Unless used in  DEBUG-FILE  or  USER_FILE,  there is  no need to know
these internal data structures or the names of variables; the options
will set the  proper values.  The key names being part of the option,
are printed in output with the  I<--trace-key>  option.

I.g. texts (values) of keys in  %data are those used in output of the
"Informations" section. Texts of keys in  %checks are used for output
in "Performed Checks" section.  And texts of keys in  %text  are used
for additional information lines or texts (mainly beginning with C<=>).

=head3 Configuration File vs. RC-FILE vs. DEBUG-FILE

=over 4

=item CONFIGURATION FILE

    Configuration Files must be specified with one of the   "--cfg_*"
    options. The specified file can be a valid path. Please note that
    only the characters:  a-zA-Z_0-9,.\/()-  are allowed as pathname.
    Syntax in configuration file is:  'KEY=VALUE'  where 'KEY' is any
    key as used in internal data structure.
    the keys in output).

=item RC-FILE

    Resource files are searched for and used automatically. They will
    be searched for in the local (current working) directory only.
    Syntax in resource file is: "--cfg_CFG=KEY=VALUE" as described in
    OPTIONS  section. 'CFG' is any of:  cmd,  check,  data,  text  or
    score. where  'KEY'  is any key from internal data structure.

=item DEBUG-FILE

    Debug files are searched for and used automatically. They will be
    searched for in the current working or installation directory.
    Syntax in these files is perl code.  Perl's  'require'  directive
    is used to include these files.

=item USER-FILE

    The user program file is included only if the  "--usr" option was
    used. It will be be searched for in the current working directory
    or the installation directory.

=back

=head2 CONFIGURATION OPTIONS

Configuration options are used to redefine  texts and labels or score
settings used in output. The options are:

=over 4

=item --cfg_cmd=KEY=LIST

=item --cfg_score=KEY=SCORE

=item --cfg_checks=KEY=TEXT

=item --cfg_data=KEY=TEXT

=item --cfg_text=KEY=TEXT

=back

Here  C<KEY> is the key used in the internal data structure and C<TEXT>
is the value to be set for this key.  Note that  unknown keys will be
ignored silently.

If  C<KEY=TEXT>  is an exiting filename,  all lines from that file are
read and set. For details see  B<CONFIGURATION FILE>  below.

=head2 CONFIGURATION FILE

Note that the file can contain  C<KEY=TEXT>  pairs for the kind of the
configuration as given by the  I<--cfg_CONF>  option.

For example when used  with  C<--cfg_text=file> only values for  %text
will be set, when used  with  C<--cfg_data=file> only values for %data
will be set, and so on.  C<KEY>  is not used when  C<KEY=TEXT>  is  an
existing filename. Though, it's recommended to use a non-existing key,
for example: I<--cfg-text=my_file=some/path/to/private/file> .

=head2 RC-FILE

A  rc-file  can contain any of the commands and options valid for the
tool itself. The syntax for them is the same as on command line. Each
command or option must be in a single line. Any empty or comment line
will be ignored. Comment lines start with  C<#>  or  C<=>.

Note that options with arguments must be used as  C<KEY=VALUE>.

All commands and options given on command line will  overwrite  those
found in the rc-file.

The rc-file will be searched for in the working directory only.

The name of the rc-file is the name of the program file prefixed by a
C<.>,  for example:  C<.o-saft.pl>.

=head2 DEBUG-FILE

All debugging functionality is defined in L<o-saft-dbx.pm>, which will
be searched for in the current working directory  or the installation
directory of the tool. For Details see  L<DEBUG>  below.

=head2 USER-FILE

All functions defined in  L<o-saft-usr.pm>  are called when the option
I<--usr>  was given. The functions are defined as empty stub, any code
can be inserted as need.  Please see  L<perldoc o-saft-usr.pm>  to see
when and how these functions are called.

=head1 CIPHER NAMES

While the SSL/TLS protocol uses integer numbers to identify  ciphers,
almost all tools use some kind of  `human readable'  texts for cipher
names. 

These numbers (which are most likely written  as hex values in source
code and documentations) are the only true identifier, and we have to
rely on the tools that they use the proper integers.

As such integer or hex numbers are difficult to handle by humans,  we
decided to use human readable texts. Unfortunately no common standard
exists how to construct the names and map them to the correct number.
Some, but by far not all, oddities are described in L<Name Rodeo>.

The rules for specifying cipher names are:

=over 4

=item 1. textual names as defined by IANA (see [IANA])

=item 2. mapping of names and numbers as defined by IANA (see [IANA])

=item 3. C<->  and  C<_>  are treated the same

=item 4. abbreviations are allowed, as long as they are unique

=item 5. beside IANA, openssl's cipher names are preferred

=item 6. name variants are supported, as long as they are unique

=item 7. hex numbers can be used

=back

[IANA]    http://www.iana.org/assignments/tls-parameters/tls-parameters.txt September 2013

[openssl] ... openssl 1.0.1

If in any doubt, use  I<+list --v>  to get an idea about the mapping.
Use  I<--help=regex>  to see which regex  are used to handle all these
variants herein.

Mind the traps and dragons with cipher names and what number they are
actually mapped. In particular when  I<--lib>, I<--exe> or I<--openssl>
options are in use. Always use these options with I<+list> command too.

=head2 Name Rodeo

As said above, the  SSL/TLS protocol uses integer numbers to identify
ciphers, but almost all tools use some kind of  human readable  texts
for cipher names. 

For example the cipher commonly known as C<DES-CBC3-SHA> is identified
by C<0x020701c0> (in openssl) and has C<SSL2_DES_192_EDE3_CBC_WITH_SHA>
as constant name. A definition is missing in IANA, but there is 
C<TLS_RSA_WITH_3DES_EDE_CBC_SHA> .
It's each tool's responsibility to map the human readable cipher name
to the correct (hex, integer) identifier.

For example Firefox uses  C<dhe_dss_des_ede3_sha>,  which is what?

Furthermore, there are different acronyms for the same thing in use.
For example  C<DHE>  and  C<EDH>  both mean C<Ephemeral Diffie-Hellman>.
Comments in the openssl sources mention this. And for curiosity these
sources use both in cypher names but allow only  C<EDH> as shortcut in
openssl's `ciphers'  command.

Next example is  C<ADH>  which is also known as  C<DH_anon> or C<DHAnon>
or  C<DHA>  or  <ANON_DH>. 

You think this is enough? Then have a look how many acronyms are used
for  `Tripple DES'.

Compared to above, the interchangeable use of  C<->  vs.  C<_> in human
readable cipher names is just a very simple one. However, see openssl
again what following means (returns):
    openssl ciphers -v RC4-MD5
    openssl ciphers -v RC4+MD5
    openssl ciphers -v RC4:-MD5
    openssl ciphers -v RC4:!MD5
    openssl ciphers -v RC4!MD5

Looking at all these oddities, it would be nice to have a common unique
naming scheme for cipher names. We have not.  As the SSL/TLS protocol
just uses a number, it would be natural to use the number as uniq key
for all cipher names, at least as key in our internal sources.

Unfortunately, the assignment of ciphers to numbers  changed over the
years, which means that the same number refers to a  different cipher
depending on the standard, and/or tool, or version of a tool you use.

As a result, we cannot use human readable cipher names as  identifier
(aka unique key), as there are  to many aliases  for the same cipher.
And also the number  cannot be used  as unique key, as a key may have
multiple ciphers assigned.

=head1 KNOWN PROBLEMS

=head2 Segmentation fault

Sometimes  the program terminates with a  `Segmentation fault'.  This
mainly happens if the target does not return certificate information.
If so, the  I<--no-cert>  option may help.

=head2 **WARNING: empty result from openssl; ignored at ...

This most likely occurs when the  provided cipher is  not accepted by
the server, or the server expects client certificates.

=head2 **WARNING: unknown result from openssl; ignored at ...

This most likely occurs when the  openssl  executable is used with a
very slow connection. Typically the reason is a connection timeout.
Try to use  I<--timout=SEC>  option.
To get more information, use  I<--v> I<--v>  and/or  I<--trace>  also.

=head2 Use of uninitialized value $headers in split ... do_httpx2.al)

The warning message (like follows or similar):

Use of uninitialized value $headers in split at blib/lib/Net/SSLeay.pm
(autosplit into blib/lib/auto/Net/SSLeay/do_httpx2.al) line 1290.

occurs if the target refused a connection on port 80. 
This is considered a bug in L<Net::SSLeay>.
Workaround to get rid of this message: use  I<--no-http>  option.

=head2 invalid SSL_version specified at ....

This error may occur on systems where SSL's DTLSv1 is not supported.
The full message looks like:

invalid SSL_version specified at C:/programs/perl/perl/vendor/lib/IO/Socket/SSL.

Workaround: use  I<--no-dtlsv1>  option.

=head2 Performance Problems

There are various reasons when the program responds slow, or seems to
hang. Beside the problems described below performance issues are most
likely a target-side problem. Most common reasons are:

=over 4

=item a) DNS resolver problems

Try with  I<--no-dns>

=item b) target does not accept connections for https

Try with  I<--no-http>

=item c) target's certificate is not valid

Try with  I<--no-cert>

=item d) target expects that the client provides a client certificate

No option provided yet ...

=item e) target does not handle Server Name Indication (SNI)

Try with  I<--no-sni>

Try to use following options to narrow down the cause of the problem:

=item use of external openssl executable

Use  I<--no-openssl> 

=back

Other options which may help to get closer to the problem's cause:
I<--timeout=SEC>,  I<--trace>,  I<--trace=cmd>  


=head1 LIMITATIONS

=head2 Commands

Some commands cannot be used together with others, for example:
I<+list>,  I<+libversion>,  I<+version>,  I<+check>,  I<+help>.
 
I<+quick>  should not be used together with other commands, it returns
strange output then.

I<+protocols>  requires  L<openssl(1)> with support for "-nextprotoneg"
option. Otherwise the value will be empty.

=head2 Options

The characters C<+> and C<=> cannot be used for I<--separator> option.

Following strings should not be used in any value for options:
  C<+check>, C<+info>, C<+quick>, C<--header>
as they my trigger the  -I<--header>  option unintentional.

The used L<timeout(1)> command cannot be defined with a full path like
L<openssl(1)>  can with the  I<--openssl=path/to/openssl>.

=head2 Broken pipe

This error message most likely means that the connection to specified
was not possible (firewall or whatever reason).

=head2 Target Certificate Chain Verification

The systems default capabilities i.e. libssl.so, openssl, are used to
verify the target's certificate chain.  Unfortunately various systems
have implemented different  approaches and rules how identify and how
to report a successful verification.  As a consequence  this tool can
only return the  same information about the chain verification as the
used underlying tools.  If that information is trustworthy depends on
how trustworthy the tools are.

These limitations apply to following commands:

=over 4

=item I<+verify>

=item I<+selfsigned>

=back

Following commands and options are useful to get more information:

=over 4

=item I<+chain_verify>, I<+verify>, I<+error_verify>, I<+chain>, I<+s_client>

=item I<--ca-file>, I<--ca-path>, I<--ca-depth>

=back

=head2 User Provided Files

Please note that there cannot be any guarantee that the code provided
in the  DEBUG-FILE L<o-saft-usr.pm>  or  USER-FILE  L<o-saft-usr.pm> 
will work flawless. Obviously this is the user's responsibility.

=head2 Problems and Errors

Checking the target for supported ciphers may return that a cipher is
not supported by the server  misleadingly.  Reason is most likely  an
improper timeout for the connection. See  I<--timeout=SEC>  option.

If the specified targets accepts connections but does not speak  SSL,
the connection will be closed after the system's TCP/IP-timeout. This
script will hang (about 2-3 minutes).

If reverse DNS lookup fails, an error message is returned as hostname,
like:  C<<<gethostbyaddr() failed>>>.
Workaround to get rid of this message: use  I<--no-dns>  option.

All checks for EV are solely based on the information provided by the
certificate.

=head2 Poor Systems

Use of  L<openssl(1)> is disabled by default on Windows due to various
performance problems. It needs to be enabled with I<--openssl> option.

On Windows the usage of  "openssl s_client" needs to be enabled using
I<--s_client> option.

On Windows it's a pain to specify the path for I<--openssl=..> option.
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

=head1 DEPENDENCIES

=over

=item L<IO::Socket::SSL(1)>

=item L<IO::Socket::INET(1)>

=item L<Net::SSLeay(1)>

=item L<Net::SSLinfo(1)>

=back

=head2 Additional Files used if requested

=over

=item L<.o-saft.pl>

=item L<o-saft-dbx.pm>

=item L<o-saft-usr.pm>

=item L<o-saft-README>

=back

=head1 SEE ALSO

L<openssl(1)>, L<Net::SSLeay(1)>, L<Net::SSLinfo(1)>, L<timeout(1)>

http://www.openssl.org/docs/apps/ciphers.html

L<IO::Socket::SSL(1)>, L<IO::Socket::INET(1)>

=head1 HACKER's INFO

=head2 Using private libssl.so and libcrypt.so

For all  cryptographic functionality  the libraries  installed on the
system will be used. This is in particular perl's  Net:SSLeay module,
the system's  libssl.so and libcrypt.so  and the openssl executable.

It is possible to provide your own libraries, if the  perl module and
the executable are  linked using  dynamic shared objects  (aka shared
library, position independent code).
The appropriate option is  I<--lib=PATH>  .

On most systems these libraries are loaded at startup of the program.
The runtime loader uses a preconfigured list of directories  where to
find these libraries. Also most systems provide a special environment
variable to specify  additional paths  to directories where to search
for libraries, for example the  LD_LIBRARY_PATH environment variable.
This is the default environment variable used herein.  If your system
uses  another name it must be specified with the  I<--envlibvar=NAME>
option, where  NAME  is the name of the environment variable.

=head2 Understanding  I<--exe=PATH>, I<--lib=PATH>, I<--openssl=FILE>

If any of I<--exe=PATH> or I<--lib=PATH> is provided, the pragram calls
(C<exec>) itself recursively with all given options, except the option
itself. The environment variables  C<LD_LIBRARY_PATH>  and C<PATH>  are
set before executing as follows:

=over 4

=item prepend  C<PATH>  with all values given with  I<--exe=PATH> 

=item prepend  C<LD_LIBRARY_PATH>  with all values given with  I<--lib=PATH> 

=back

This is exactly, what L<Cumbersome Approach> below describes. So these
option simply provide a shortcut for that.

Note that I<--openssl=FILE> is a full path to the L<openssl> executable
and will not be changed.  However, if it is a relative path, it might
be searched for using the previously set  C<PATH>  (see above).

Note that  C<LD_LIBRARY_PATH>  is the default.  It can be changed with
the  I<--envlibvar=NAME>  option.

=head2 Caveats

Depending on your system and the used modules and executables, it can
be tricky to replace the configured shared libraries with own ones.
Reasons are:
  a) the linked library name contains a version number,
  b) the linked library uses a fixed path,
  c) the linked library is searched at a predefined path,
  d) the executable checks the library version when loaded.

Only the first one a) can be circumvented.  The last one d) can often
be ignored as it only prints a warning or error message.

To circumvent the "name with version number" problem try following:

=over

=item 1. use L<ldd> (or a similar tool) to get the names used by L<openssl>:

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

Depending on  compile time settings  and/or  the location of the used
tool or lib, a warning like following my occur:

  WARNING: can't open config file: /path/to-openssl/ssl/openssl.cnf

This warning can be ignored, usually.

=head3 Cumbersome Approach

A more cumbersome approach to call  this program is to set  following
environment variables in your shell:

  PATH=/tmp/dada-1.42/apps:$PATH
  LD_LIBRARY_PATH=/tmp/dada-1.42

=head3 Windows Caveats

I.g. the used libraries on Windows are libeay32.dll and ssleay32.dll.

Windows also supports the LD_LIBRARY_PATH environment variable. If it
does not work as expected with that variable, it might be possible to
place the libs in the same directory as the  corresponding executable
(which is found by the PATH environment variable).

=for comment openssl.exe 1.0.0e needs: libeay32.dll, ssleay32.dll

=head2 Using CGI mode

This script can be used as  CGI application. Output is the same as in
common CLI mode, using  'Content-Type:text/plain'.  Keep in mind that
the used modules like  L<Net::SSLeay>  will write some debug messages
on STDERR instead STDOUT. Therefore multiple  I<--v> and/or  I<--trace>
options behave slightly different.

No additional external files like  B<RC-FILE> or B<DEBUG-FILE> are read
in CGI mode; they are silently ignored.
Some options are disabled in CGI mode  because they are dangerous  or
don't make any sense.

=head3 WARNING

  There are  no  input data validation checks implemented herein. All 
  input data is url-decoded once and then used verbatim.
  More advanced checks must be done outside before calling this tool.

=begin comment

The only code necessary for CGI mode is encapsulated at the beginning,
see  C<if ($me =~/\.cgi$/){ ... }>. Beside some minor additional regex
matches (mainly removing trailing  C<=> and empty arguments) no other
code is needed. 

=end comment

=head2 Using user specified code

There are some functions called within the program flow, which can be
filled with any perl code.  Empty stubs of the functions are prepared
in  L<o-saft-usr.pm>.  See also  B<USER-FILE>.

=head2 SECURITY

This tool is designed to be used by people doing security or forensic
analyses. Hence no malicious input is expected.

There are no special security checks implemented. Some parameters are
roughly sanatised according unwanted characters.  In particular there
are no checks according any kind of code injection.

Please see  B<WARNING> above if used in CGI mode. It's not recommended
to run this tool in CGI mode. You have been warned!

=for comment Program Code below is not shown with +help

=begin comment

=head2 Program Code

=head3 General

Perl's  `die()'  is used whenever an unrecoverable error occurs.  The
message printed will always start with `**ERROR: '.
Warnings are printed using perl's  `warn()'  function and the message
always begins with `**WARNING: '.

All C<print*()> functions write on STDOUT directly. They are slightly
prepared for using texts from  the configuration (%cfg, %checks),  so
these texts can be adapted easily (either with  OPTIONS  or in code).

The  code  mainly uses  'text enclosed in single quotes'  for program
internal strings such as hash keys, and uses "double quoted" text for
texts being printed. However, exceptions if obviously necessary ;-)
Strings used for RegEx are always enclosed in single quotes.
Reason is mainly to make searching texts a bit easyer.

The code flow mainly uses postfix conditions, means the if-conditions
are written right of the command to be executed. This is done to make
the code better readable (not disturbed by conditions).

While  Net::SSLinfo  uses  L<Net::SSLeay(1)>,  o-saft.pl  itself uses
only  L<IO::Socket::SSL(1)>. This is done 'cause we need some special
features here. However,  L<IO::Socket::SSL(1)>  uses  L<Net::SSLeay(1)>  
anyways.

The code is most likely not thread-safe. Anyway, we don't use them.

For debugging the code the  I<--trace>  option can be used.  See  DEBUG
section below for more details. Be prepared for a lot of output!

=head3 Comments

Following comments are used in the code:

=over 4

=item # ToDo:   - parts not working perfect, needs to be changed

=item # FIXME:  - program code known to be buggy, needs to be fixed

=back

=head3 Variables

Most functions use global variables (even if they are defined in main
with `my'). These variables are mainly: @DATA, @results, %cmd, %data,
%cfg, %checks, %ciphers, %text.

Variables defined with `our' are can be used in  L<o-saft-dbx.pm>  and
L<o-saft-dbx.pm> .

For a detailed description of the used variables, please refer to the
text starting at the line  C<#!# set defaults>.


=head3 Sub Names

Some rules used for function names:

=over 4

=item check*

    Functions which perform some checks

=item print*

    Functions which print results.

=item get_*

    Functions to get a value from internal ciphers data structure.

=item _<function_name>

    Some kind of helper functions .

=item _trace* _y*

    Print information when  "--trace"  is in use.

=item _v*print

    Print information when  "--v"  is in use.

=back

Function (sub) definitions are followed by a short description, which
is just one line right after the  C<sub>  line. Such lines always start
with  C<#?>  (see below how to get an overview).

=head3 Code information

Examples to get an overview of perl functions (sub):

   egrep '^(sub|\s*#\?)' $0

Same a little bit formatted:

   perl -lane 'sub p($$){printf("%-24s\t%s\n",@_);} \
     ($F[0]=~/^#/)&&do{$_=~s/^\s*#\??/-/;p($s,$_)if($s ne "");$s="";}; \
     ($F[0]=~/^sub/)&&do{p($s,"")if($s ne "");$s=$F[1];}' \
     $0

Following to get perl's variables for checks:

  $0 +check localhost --trace-key \
  | awk -F'#' '($2~/^ /){a=$2;gsub(" ","",a);next}(NF>1){printf"%s{%s}\n",a,$2}' \
  | tr '%' '$'

=head3 Debugging, Tracing

Most functionality for trace, debug or verbose output is encapsulated
in functions (see B<Sub Names> above). These functions are defined as
empty stubs herein.  The  real  definitions  are in  L<o-saft-dbx.pm>,
which is loaded on demand when either any  I<--trace*>  or  I<--v>  option
is specified. As long as these options are not used  o-saft.pl  works
without  L<o-saft-dbx.pm>.

Note: in contrast to the name of the RC-file, the name  o-saft-dbx.pm
is hard-coded.

=end comment

=head1 DEBUG

=head2 Debugging, Tracing

Following  options and commands  are useful for hunting problems with
SSL connections and/or this tool. Note that some options can be given
multiple times to increase amount of listed information. Also keep in
mind that it's best to specify  I<--v>  as very first argument.

Note that the file  L<o-saft-dbx.pm>  is required, if any  I<--trace*>
or  I<--v>  option is used.

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

=item --v--

=item --trace

=item --trace-arg

=item --trace-cmd

=item --trace-key

=back

Empty or undefined strings are written as  "<<undefined>>"  in texts.
Some parameters, in particular those of  HTTP responses,  are written
as  "<<response>>".  Long parameter lists are abbreviated with "...".


=head3 Output

When using  I<--v>  and/or  I<--trace>  options, additional output will
be prefixed with a  C<#>  (mainly as first, left-most character.
Following formats are used:

=over 4

=item #<space>

    Addition text for verbosity ("--v" options).

=item #[variable name]<TAB>

    Internal variable name ("--trace-key" options).

=item #o-saft.pl::

=item #Net::SSLinfo::

    Trace information for "--trace"  options.

=item #{

    Trace information from  "NET::SSLinfo"  for  "--trace"  options.
    These are data lines in the format:   #{ variable name : value #}
    Note that  `value'  here can span multiple lines and ends with #}

=back

=head1 EXAMPLES

($0 in all following examples is the name of the tool)

=head2 General

    $0 +cipher some.tld
    $0 +info   some.tld
    $0 +check  some.tld
    $0 +quick  some.tld
    $0 +help=commands
    $0 +list
    $0 +list --v
    $0 +certificate  some.tld
    $0 +fingerprint  some.tld 444
    $0 +after +dates some.tld

=head2 Some specials

=over

=item Get an idea how messages look like

    $0 +check --cipher=RC4 some.tld

=item Check for Server Name Indication (SNI) usage only

    $0 +sni some.tld

=item Check for SNI and print certificate's subject and altname

    $0 +sni +cn +altname some.tld

=item Check for all SNI, certificate's subject and altname issues

    $0 +sni_check some.tld

=item Only print supported ciphers

    $0 +cipher --enabled some.tld

=item Only print unsupported ciphers

    $0 +cipher --disabled some.tld

=item Test for a specific ciphers

    $0 +cipher --cipher=ADH-AES256-SHA some.tld

=for comment =item Test all ciphers, even if not supported by local SSL implementation

=for comment     $0 +cipher --local some.tld

=item Test using a private libssl.so, libcrypto.so and openssl

    $0 +cipher --lib=/foo/bar-1.42 --exe=/foo/bar-1.42/apps some.tld

=item Test using a private openssl

    $0 +cipher --openssl=/foo/bar-1.42/openssl some.tld

=item Test using a private openssl also for testing supported ciphers

    $0 +cipher --openssl=/foo/bar-1.42/openssl --force-openssl some.tld

=item Show current score settings

    $0 --help=score

=item Change a single score setting

    $0 --cfg_score=http_https=42   +check some.tld 

=item Use your private score settings from a file

    $0 --help=score > magic.score
    # edit as needed: magic.score
    $0 --cfg_score    magic.score  +check some.tld

=item Use your private texts in output

    $0 +check some.tld --cfg_text=desc="my special description"

=item Use your private texts from RC-FILE

    $0 --help=cfg_text >> .o-saft.pl
    # edit as needed:     .o-saft.pl
    $0 +check some.tld

=item Generate simple parsable output

    $0 --legacy=quick --no-header +info  some.tld
    $0 --legacy=quick --no-header +check some.tld
    $0 --legacy=quick --no-header --trace-key +info  some.tld
    $0 --legacy=quick --no-header --trace-key +check some.tld

=item Generate simple parsable output for multiple hosts

    $0 --legacy=quick --no-header --trace-key --showhost +check some.tld other.tld

=item Just for curiosity

    $0 some.tld +fingerprint --format=raw
    $0 some.tld +certificate --format=raw | openssl x509 -noout -fingerprint

=back

=head2 Special for hunting problems with connections etc.

=over

=item Show command line argument processing

    $0 +info some.tld --trace-arg

=item Simple tracing

    $0 +cn   some.tld --trace
    $0 +info some.tld --trace

=item A bit more tracing

    $0 +cn   some.tld --trace --trace

=item Show internal variable names in output

    $0 +info some.tld --trace-key

=item List checked ciphers

    $0 +cipher some.tld --v --v

=item List checked ciphers one per line

    $0 +cipher some.tld --v --v -v

=item Show processing of ciphers

    $0 +cipher some.tld --v --v --v -v

=item Show values retrieved from target certificate directly

    $0 +info some.tld --no-cert --no-cert --no-cert-text=Value-from-Certificate

=item Show certificate CA verifications

    $0 some.tld +chain_verify +verify +error_verify +chain

=item Avoid most performance and timeout problems

    $0 +info some.tld --no-cert --no-dns --no-http --no-openssl --no-sni

=back

=for following lines may contain trailing space, which are requiered

=begin --v --v


.raw nerobeg
sretset rof tidua LSS PSAWO  -  "tfaS-O"   
retseT reuf tiduA LSS PSAWO  -  "tfaS-O"   
 nnawdnegri nnad sib ,elieW enie sad gnig oS
..wsu ,"haey-lss" ,"agoy-lss" :etsiL red fua dnats -reteaps reibssieW
eretiew  raap nie-  nohcs se tnha nam  ,ehcuS eid nnageb os ,nebegrev
nohcs dnis nemaN ednessap eleiV  .guneg 'giffirg`  thcin reba sad raw
gnuhciltneffeoreV enie reuF .noisrevsgnulkciwtnE red emaN red tsi saD
. loot LSS rehtona tey -  "lp.tsaey"   :resseb nohcs tsi sad
,aha ,tsaey -- efeH -- reibssieW -- .thcin sad tgnilk srednoseb ,ajan
eigeRnegiE nI resworB lSS nIE redeiW  -  "lp.reibssiew"   
:ehan gal se ,nedrew emaN 'regithcir` nie hcod nnad se etssum
hcan dnu hcaN  .edruw nefforteg setsre sla "y" sad liew ,"lp.y" :eman
-ietaD nie snetsednim  ,reh emaN nie etssum sE .slooT seseid pytotorP
retsre nie  nohcs hcua  dnatstne iebaD  .tetsokeg reibssieW eleiv dnu
nednutS eginie nnad hcim tah esylanA eiD .)dnis hcon remmi dnu( neraw
nedeihcsrev rhes esiewliet eis muraw ,nednifuzsuareh dnu nehetsrev uz
)noitpO "*=ycagel--"  eheis( slooT-tseT-LSS reredna releiv essinbegrE
nehcildeihcsretnu eid hcusreV mieb  dnatstne looT  meseid uz eedI eiD

)-: ti dnatsrednu :laog txeN .eno neddih eht ,ti tog uoY

=end --v

=head1 ATTRIBUTION

Based on ideas (in alphabetical order) of:
   cnark.pl, SSLAudit.pl sslscan, ssltest.pl, sslyze.py

O-Saft - OWASP SSL advanced forensic tool
   Thanks to Gregor Kuznik for this title.

For re-writing some docs in proper English, thanks to Robb Watson.

=for comment: VERSION string must start with @(#) at beginning of a line

=head1 VERSION

@(#) 14.01.27

=head1 AUTHOR

31. July 2012 Achim Hoffmann (at) sicsec de

=begin ToDo # no POD syntax here!

TODO

  * missing checks
    ** SSL_honor_cipher_order => 1
    ** implement TLSv1.2 checks
    ** IP in CommonName or subjectAltname (RFC6125)
    ** checkcert(): KeyUsage, keyCertSign, BasicConstraints
    ** DV and EV miss some minor checks; see checkdv() and checkev()

  * verify CA chain:
    ** Net::SSLinfo.pm implement verify*
    ** implement +check_chain (see Net::SSLinfo.pm implement verify* also)
    ** implement +ca = +verify +chain +rootcert +expired +fingerprint

  * scoring
    ** implement score for PFS; lower score if not all ciphers support PFS

  * vulnerabilities
    ** complete TIME, BREACH check
    ** implement check for Lucky 13
    ** is DHE-DSS-RC4-SHA also weak?
    ** BEAST more checks, see: http://www.bolet.org/TestSSLServer/

  * Net::SSLeay
    ** Net::SSLinfo.pm Net::SSLeay::ctrl()  sometimes fails, but doesn't
       return error message
    ** Net::SSLeay::CTX_clear_options()
       Need to check the difference between the  SSL_OP_LEGACY_SERVER_CONNECT  and
       SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;  see also SSL_clear_options().
       see https://www.openssl.org/docs/ssl/SSL_CTX_set_options.html

  * Windows
    ** Unicode:
       try: cmd /K chcp 65001
       or:  chcp 65001
       or:  reg add hklm\system\currentcontrolset\control\nls\codepage -v oemcp -d 65001

  * internal
    ** make a clear concept how to handle +CMD whether they report
       checks or informations (aka %data vs. %check_*)
       currently (2014) each single command returns all values
    ** complete +http checks (see %checks also)
       improve score for these checks
       make clear usage of score from %checks
    ** client certificates not yet implemented in _usesocket() _useopenssl(),
       see t.client-cert.txt
    ** (nicht wichtig, aber sauber programmieren)
       _get_default(): Net::SSLinfo::default() benutzen

=end ToDo

not necessary
