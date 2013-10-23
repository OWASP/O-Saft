#! /usr/bin/perl -w

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

package Net::SSLinfo;

use strict;
use constant {
    SSLINFO     => 'Net::SSLinfo',
    SSLINFO_ERR => '#Net::SSLinfo::errors:',
    SID         => '@(#) Net::SSLinfo.pm 1.50 13/10/23 22:42:15',
};

######################################################## public documentation #
# Documentaion starts here, so we can use the inline documentation for our
# functions also and it will be extracted automatically by POD tools.  All
# public functions will be prefixed with a POD description.

=pod

=head1 NAME

Net::SSLinfo -- perl extension for SSL certificates

=head1 SYNOPSIS

    use Net::SSLinfo;
    print join("\n",
        PEM("www.example.com",443),
        dates(),
        default()
        ciphers()
        );
    do_ssl_close("www.example.com",443);

=head1 DESCRIPTION

This module is an extension to Net::SSLeay to provide information according
a SSL connection to a specific server.

The purpose is to give as much as possible information to the user (caller)
according the specified server aka hostname without struggling with the
internals of SSL as needed by Net::SSLeay.

=head1 RETURN VALUES

All methods return a string on success, empty string otherwise.

=head1 DEBUGGING

Simple tracing can be activated with C<$Net::SSLinfo:trace=1>.

C<$Net::SSLinfo:trace=2> or C<$Net::SSLinfo:trace=3> will be passed to
C<$Net::SSLeay::trace>.

Debugging of low level SSL can be enabled by setting C<$Net::SSLeay::trace>,
see L<Net::SSLeay> for details.

In trace messages empty or undefined strings are writtens as "<<undefined>>".

=head1 VARIABLES

Following variables are supported:

=over

=item $Net::SSLinfo::openssl

Path for openssl executable to be used; default: openssl

=item $Net::SSLinfo::timeout

Path for timeout executable to be used; default: timeout

=item $Net::SSLinfo::use_openssl

More informations according the  SSL connection and  the certificate,
additional to that of Net::SSLeay, can be retrived using the  openssl
executable. If set to "1" openssl will be used also; default: 1

If disabled, the values returned value will be: #

=item $Net::SSLinfo::use_sclient

Some informations according the  SSL connection and the certificate,
can only be retrived using  "openssl s_client ...".   Unfortunatelly
the use may result in a  performance penulty  on some systems and so
it can be disabled with "0"; default: 1

If disabled, the values returned will be: #

=item $Net::SSLinfo::use_SNI

If set to "1", the specified hostname will be used for SNI. This is needed
if there're multiple SSL hostnames on the same IP address.  If no hostname 
given, the hostname from PeerAddr will be used.  This will fail if only an 
IP was given.
If set to "0" no SNI will be used. This can be used to check if the target
supports SNI; default: 1

=item $Net::SSLinfo::use_http

If set to "1", make a simple  HTTP request on the open  SSL connection and
parse the response for additional SSL/TLS related information (for example
Strict-Transport-Security header); default: 1

=item $Net::SSLinfo::no_cert

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
string defined in  "$Net::SSLinfo::no_cert_txt".

=item $Net::SSLinfo::no_cert_txt

String to be used if "$Net::SSLinfo::no_cert" is set.
Default is (same as openssl): "unable to load certificate"

=back

=head1 EXAMPLES

See SYNOPSIS above.

=head1 LIMITATIONS

This module is not thread-save as it only supports one internal object for
socket handles. However, it will work if all threads use the same hostname.

Some data is collected using an external openssl executable. The output of
this executable is used to find proper information. Hence some data may be
missing or detected wrong due to different output formats of openssl.
If in doubt use "$Net::SSLinfo::use_openssl = 0" to disable openssl usage.

=head1 KNOWN PROBLEMS

Net::SSLeay::X509_get_subject_name()   from version 1.49 sometimes crashes
with segmentation fault.

Error message like:
  panic: sv_setpvn called with negative strlen at Net/SSLinfo.pm line 552,
     <DATA> line 1384.

Reason most likely Net::SSLeay Version (version<1.49) which doesn't define
C<Net::SSLeay::X509_NAME_get_text_by_NID()>.

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

############################################################## initialization #

# forward declarations
sub do_ssl_open($$);
sub do_ssl_close($$);
sub do_openssl($$$);

use vars   qw($VERSION @ISA @EXPORT @EXPORT_OK $HAVE_XS);

BEGIN {

require Exporter;
    $VERSION   = '13.10.22';
    @ISA       = qw(Exporter);
    @EXPORT    = qw(
        dump
        do_ssl_open
        do_ssl_close
        do_openssl
        set_cipher_list
        errors
        PEM
        pem
        text
        fingerprint
        fingerprint_hash
        fingerprint_text
        fingerprint_type
        fingerprint_sha1
        fingerprint_md5
        email
        serial
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
        trustout
        ocsp_uri
        ocspid
        before
        after
        dates
        issuer
        subject
        default
        ciphers
        cipher_list
        cipher_local
        cn
        commonname
        altname
        authority
        owner
        certificate
        version
        keysize
        keyusage
        https_status
        https_server
        https_alerts
        https_location
        https_refresh
        http_status
        http_location
        http_refresh
        http_sts
        hsts
        hsts_maxage
        hsts_subdom
        hsts_pins
        verify_hostname
        verify_altname
        verify_alias
        verify
        compression
        expansion
        krb5
        psk_hint
        psk_identity
        srp
        master_key
        session_id
        session_ticket
        renegotiation
        resumption
        selfsigned
        s_client
        error
    );
    # insert above in vi with:
    # :r !sed -ne 's/^sub \([a-zA-Z][^ (]*\).*/\t\t\1/p' %

    $HAVE_XS = eval { 
        local $SIG{'__DIE__'} = 'DEFAULT';
        eval {
            require XSLoader;
            XSLoader::load('Net::SSLinfo', $VERSION);
            1;
        } or do {
            require DynaLoader;
            push @ISA, 'DynaLoader';
            bootstrap Net::SSLinfo $VERSION;
            1;
        };

    } ? 1 : 0;
} # BEGIN

use Socket;
use Net::SSLeay;
    Net::SSLeay::load_error_strings();
    Net::SSLeay::SSLeay_add_ssl_algorithms();   # Important!
    Net::SSLeay::randomize();
$Net::SSLinfo::timeout     = 'timeout'; # timeout executable
$Net::SSLinfo::openssl     = 'openssl'; # openssl executable
$Net::SSLinfo::use_openssl = 1; # 1 use installed openssl executable
$Net::SSLinfo::use_sclient = 1; # 1 use openssl s_client ...
$Net::SSLinfo::use_SNI     = 1; # 1 use SNI to connect to target
$Net::SSLinfo::use_http    = 1; # 1 make HTTP request and retrive additional data
$Net::SSLinfo::no_cert     = 0; # 0 collect data from target's certificate
                                # 1 don't collect data from target's certificate
                                #   return empty string
                                # 2 don't collect data from target's certificate
                                #   return string $Net::SSLinfo::no_cert_txt
$Net::SSLinfo::no_cert_txt = 'unable to load certificate'; # same as openssl
$Net::SSLinfo::ignore_case = 1; # 1 match hostname, CN case insensitive
$Net::SSLinfo::timeout_sec = 3; # time in seconds for timeout executable
$Net::SSLinfo::trace       = 0; # 1=simple debugging Net::SSLinfo
                                # 2=trace     including $Net::SSLeay::trace=2
                                # 3=dump data including $Net::SSLeay::trace=3
my $trace    = $Net::SSLinfo::trace;

sub _settrace {
    $trace = $Net::SSLinfo::trace;          # set global variable
    $Net::SSLeay::trace = $trace if ($trace > 1);
        # must set $Net::SSLeay::trace here again as $Net::SSLinfo::trace
        # might unset when Net::SSLinfo called initially;
}

sub _trace { local $\ = "\n"; print '#' . SSLINFO . '::' . $_[0] if ($trace > 0); }

# define some shortcuts to avoid $Net::SSLinfo::*
my $_echo    = '';              # dangerous if aliased or wrong one found
my $_timeout = undef;
my $_openssl = undef;

sub _setcmd() {
    #? check for external commands and initialize if necessary
    return if (defined $_timeout);  # lazy check
    `$Net::SSLinfo::timeout --version 2>&1` and $_timeout = "$Net::SSLinfo::timeout $Net::SSLinfo::timeout_sec"; # without leading \, lazy
    `$Net::SSLinfo::openssl version   2>&1` and $_openssl = $Net::SSLinfo::openssl;
    #dbx# print "#_setcmd using: " . `which openssl`;
    if ($^O !~ m/MSWin32/) {
        # Windows is too stupid for secure program calls
        $_timeout = '\\' .  $_timeout if (($_timeout ne '') and ($_timeout !~ /\//));
        $_openssl = '\\' .  $_openssl if (($_openssl ne '') and ($_openssl !~ /\//));
        $_echo    = '\\' .  $_echo;
    }
} # _setcmd

##################################################### internal data structure #

my %_SSLinfo = ( # our internal data structure
    'key'       => 'value',     # description
    #-------------+-------------+---------------------------------------------
    'host'      => '',          # hostname (FQDN) or IP as given by user
    'addr'      => undef,       # raw INET IP for hostname (FQDN)
    'ip'        => '',          # human readable IP for hostname (FQDN)
    'port'      => 443,         # port as given by user (default 443)
    'ssl'       => undef,       # handle for Net::SSLeay
    'ctx'       => undef,       # handle for Net::SSLeay::CTX_new()
    'errors'    => [],          # stack for errors, if any
    'cipherlist'=> 'ALL:NULL:eNULL:aNULL:LOW', # we want to test really all ciphers available
    # now store the data we get from above handles
    'version'   => '',
    'verify_cnt'=> 0,           # Net::SSLeay::set_verify() call counter
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
    'ciphers'           => [],  # list of ciphers offered by local SSL implementation
    # all following are available when calling  openssl only
    's_client'          => '',  # data we get from `openssl s_client -connect ...'
    'ciphers_openssl'   => '',  # list of ciphers returned by openssl executable
    'subject_hash'      => '',  #
    'issuer_hash'       => '',  #
    'aux'               => '',  #
    'pubkey'            => '',  # certificates public key
    'pubkey_algorithm'  => '',  # certificates public key algorithm
    'pubkey_value'      => '',  # certificates public key value (same as modulus)
    'signame'           => '',  #
    'sigdump'           => '',  # algorithm and value of signature key
    'sigkey_len'        => '',  # bit length  of signature key
    'sigkey_value'      => '',  # value       of signature key
    'extensions'        => '',  #
    'email'             => '',  # the email address(es)
    'serial'            => '',  # the serial number
    'modulus'           => '',  # the modulus of the public key
    'modulus_len'       => '',  # bit length  of the public key
    'modulus_exponent'  => '',  # exponent    of the public key
    'fingerprint_text'  => '',  # the fingerprint text
    'fingerprint_type'  => '',  # just the fingerprint hash algorithm
    'fingerprint_hash'  => '',  # the fingerprint hash value
    'fingerprint_sha1'  => '',  # SHA1 fingerprint (if available)
    'fingerprint_md5'   => '',  # MD5  fingerprint (if available)
    'default'           => '',  # default cipher offered by server
    # all following need output from "openssl s_client ..."
    #   as it may be missing in s_client, we set the default to " "
    #   which means `not there'
    'verify'            => "",  # certificate chain verification
    'renegotiation'     => "",  # renegotiation supported
    'resumption'        => "",  # resumption supported
    'selfsigned'        => "",  # self-signed certificate
    'compression'       => "",  # compression supported
    'expansion'         => "",  # expansion supported
    'krb5'              => "",  # Krb Principal
    'psk_hint'          => "",  # PSK identity hint
    'psk_identity'      => "",  # PSK identity
    'srp'               => "",  # SRP username
    'master_key'        => "",  # Master-Key
    'session_id'        => "",  # Session-ID
    'session_ticket'    => "",  # TLS session ticket
    # following from HTTP request
    'http_status'       => '',  # HTTPS response (aka status) line
    'http_server'       => '',  # HTTPS Server header
    'http_alerts'       => '',  # HTTPS Alerts send by server
    'http_location'     => '',  # HTTPS Location header send by server
    'http_refresh'      => '',  # HTTPS Refresh header send by server
    'http_status'       => '',  # HTTP response (aka status) line
    'http_location'     => '',  # HTTP Location header send by server
    'http_refresh'      => '',  # HTTP Refresh header send by server
    'http_sts'          => '',  # HTTP Strict-Transport-Security header send by server (whish is very bad)
    'hsts'              => '',  # complete STS header
    'hsts_maxage'       => '',  # max-age attribute of STS header
    'hsts_subdom'       => '',  # includeSubDomains attribute of STS header
    'hsts_pins'         => '',  # pins attribute of STS header
); # %_SSLinfo

sub _SSLinfo_reset() {  # reset %_SSLinfo, for internal use only
    #? reset internal data structure
    foreach my $key (keys %_SSLinfo) {
        $_SSLinfo{$key}     = '';
    }
    # some are special
    $_SSLinfo{'key'}        = 'value';
    $_SSLinfo{'ctx'}        = undef;
    $_SSLinfo{'ssl'}        = undef;
    $_SSLinfo{'addr'}       = undef;
    $_SSLinfo{'port'}       = 443;
    $_SSLinfo{'errors'}     = [];
    $_SSLinfo{'ciphers'}    = [];
    $_SSLinfo{'cipherlist'} = 'ALL:NULL:eNULL:aNULL:LOW';
    $_SSLinfo{'verify_cnt'} = 0;
    $_SSLinfo{'ciphers_openssl'} = '';
} # _SSLinfo_reset

sub _dump($$$) { return sprintf("#{ %-12s:%s%s #}\n", $_[0], $_[1], ($_[2] || "<<undefined>>")); }
    # my ($label, $separator, $value) = @_;
sub dump() {
    #? return internal data structure
    my $data = '';
    if ($Net::SSLinfo::use_sclient > 1) {
        $data .= _dump('s_client', " ", $_SSLinfo{'s_client'});
    } else {
        $data .= _dump('s_client', " ", "#### please set 'Net::SSLinfo::use_sclient > 1' dump s_client data also ###");
    }
    $data .= _dump('PEM',     " ", $_SSLinfo{'PEM'});
    $data .= _dump('text',    " ", $_SSLinfo{'text'});
    $data .= _dump('ciphers', " ", join(" ", @{$_SSLinfo{'ciphers'}}));
    foreach my $key (keys %_SSLinfo) {
        next if ($key =~ m/ciphers|errors|PEM|text|fingerprint_|s_client/); # handled special
        $data .= _dump($key, " ", $_SSLinfo{$key});
    }
    foreach my $key (keys %_SSLinfo) {
        next if ($key !~ m/fingerprint_/);
        $data .= _dump($key, " ", $_SSLinfo{$key});
    }
    $data .= _dump('errors',  "\n", join("\n ** ", @{$_SSLinfo{'errors'}}));
    return $data;
} # dump

########################################################## internal functions #

sub _SSLinfo_get($$$) {
    # get specified value from %_SSLinfo, first parameter 'key' is mandatory
    my ($key, $host, $port) = @_;
    _settrace();
    _trace("_SSLinfo_get('$key'," . ($host||'') . "," . ($port||'') . ")");
    if ($key eq 'ciphers_openssl') { # always there, no need to connect target
        _setcmd();
        _trace("_SSLinfo_get: openssl ciphers $_SSLinfo{'cipherlist'}") if ($trace > 1);
        $_SSLinfo{'ciphers_openssl'} = do_openssl("ciphers $_SSLinfo{'cipherlist'}", '', '');
        chomp $_SSLinfo{'ciphers_openssl'};
        return $_SSLinfo{'ciphers_openssl'};
    }
    if ($key eq 'errors') { # always there, no need to connect target
        #src = Net::SSLeay::ERR_peek_error;      # just returns number
        #src = Net::SSLeay::ERR_peek_last_error; # should work since openssl 0.9.7
        return wantarray ? @{$_SSLinfo{$key}} : join("\n", @{$_SSLinfo{$key}});
    }
    return '' if !defined do_ssl_open($host, $port);
    if ($key eq 'ciphers') { # special handling
        return wantarray ? @{$_SSLinfo{$key}} : join(' ', @{$_SSLinfo{$key}});
        return wantarray ? @{$_SSLinfo{$key}} : join(':', @{$_SSLinfo{$key}}); # if we want `openssl ciphers' format
    }
    if ($key eq 'dates') {
        return ( $_SSLinfo{'before'}, $_SSLinfo{'after'});
    }
    _trace("_SSLinfo_get '$key'=" . ($_SSLinfo{$key} || ""));
    return (grep(/^$key$/, keys %_SSLinfo)) ? $_SSLinfo{$key} : '';
} # _SSLinfo_get

#
# general internal functions
#

sub _check_host($) {
    #? convert hostname to IP and store in $_SSLinfo{'host'}, returns 1 on success
    my $host = shift;
    _trace("_check_host($host)");
    $host  = $_SSLinfo{'host'} unless defined $host;
    my $ip = undef;
    if($ip = gethostbyname($host)) {
        $_SSLinfo{'host'} = $host;
        $_SSLinfo{'addr'} = $ip;
        $_SSLinfo{'ip'}   = join('.', unpack('W4', $ip));
    }
    _trace("_check_host $_SSLinfo{'host'} $_SSLinfo{'ip'} .");
    return (defined $ip) ? 1 : undef;
}

sub _check_port($) {
    #? convert port name to number and store in $_SSLinfo{'port'}, returns 1 on success
    my $port = shift;
    _trace("_check_port($port)");
    $port  = $_SSLinfo{'port'} unless defined $port;
    $port  = getservbyname($port, 'tcp') unless $port =~ /^\d+$/;
    $_SSLinfo{'port'} = $port if (defined $port);
    _trace("_check_port $port .");
    return (defined $port) ? 1 : undef;
}

sub _ssleay_get($$) {
    #? get specified value from SSLeay certificate
        # wrapper to get data provided by certificate
        # note that all these function may produce "segmentation fault" or alike if
        # the target does not have/use a certificate but allows connection with SSL
    my ($key, $x509) = @_;
    _settrace();
    _trace("_ssleay_get('$key', x509)");
    if ($Net::SSLinfo::no_cert != 0) {
            _trace("_ssleay_get 'use_cert' $Net::SSLinfo::no_cert .");
        return $Net::SSLinfo::no_cert_txt if ($Net::SSLinfo::no_cert == 2);
        return '';
    }

    return Net::SSLeay::X509_get_fingerprint(    $x509,  'md5') if ($key eq 'md5');
    return Net::SSLeay::X509_get_fingerprint(    $x509, 'sha1') if ($key eq 'sha1');

    return Net::SSLeay::X509_NAME_oneline(        Net::SSLeay::X509_get_subject_name($x509)) if($key eq 'subject');
    return Net::SSLeay::X509_NAME_oneline(        Net::SSLeay::X509_get_issuer_name( $x509)) if($key eq 'issuer');
    return Net::SSLeay::P_ASN1_UTCTIME_put2string(Net::SSLeay::X509_get_notBefore(   $x509)) if($key eq 'before');
    return Net::SSLeay::P_ASN1_UTCTIME_put2string(Net::SSLeay::X509_get_notAfter(    $x509)) if($key eq 'after');
    # constants like NID_CommonName from openssl/objects.h (1.0.0*)
    return Net::SSLeay::X509_NAME_get_text_by_NID( Net::SSLeay::X509_get_subject_name($x509), &Net::SSLeay::NID_commonName) if($key eq 'cn');

    # ToDo: following most likely do not work
    #     Net::SSLeay::NID_key_usage             = 83
    #     Net::SSLeay::NID_basic_constraints     = 87
    #     Net::SSLeay::NID_certificate_policies  = 89
    #     Net::SSLeay::NID_uniqueIdentifier      = 102
    #     Net::SSLeay::NID_serialNumber          = 105
    return Net::SSLeay::X509_NAME_get_text_by_NID(Net::SSLeay::X509_get_subject_name($x509), &Net::SSLeay::NID_serialNumber) if ($key eq 'policies');

    # X509_get_subjectAltNames returns array of (type, string)
    # type: 1 = email, 2 = DNS, 6 = URI, 7 = IPADD, 0 = othername
    if ($key eq 'altname') {
        my $ret = '';
        my @altnames = Net::SSLeay::X509_get_subjectAltNames($x509);
        while (@altnames) {             # construct string like openssl
            my ($type, $name) = splice(@altnames, 0, 2);
            $type = 'DNS'           if ($type eq '2');
            $type = 'URI'           if ($type eq '6');
            $type = 'IPADD'         if ($type eq '7');
            $name = '<unsupported>' if ($type eq '0');
            $type = 'othername'     if ($type eq '0');
            $type = 'email'         if ($type eq '1');
            # all other types are used as is, so we see what's missing
            $ret .= ' ' . join(':', $type, $name);
        }
        return $ret;
    }
    _trace("_ssleay_get '' .");  # or warn "**WARNING: wrong key '$key' given; ignored";
    return '';
} # _ssleay_get

sub _header_get($$) {
    #? get value for specified header from given HTTP response; empty if not exists
    my $head    = shift;   # header to search for
    my $response= shift; # response where to serach
    my $value   = '';
    _trace("__header_get('$head', <<response>>)");
    if ($response =~ m/[\r\n]$head\s*:/i) {
        $value  =  $response;
        $value  =~ s/.*?[\r\n]$head\s*:\s*([^\r\n]*).*$/$1/ims;
    }
    return $value;
} # _header_get

sub _openssl_MS($$$$) {
    #? wrapper to call external openssl executable on windows
    my $mode = shift;   # must be openssl command
    my $host = shift;   # '' if not used
    my $port = shift;   # '' if not used
    my $text = shift;   # text to be piped to openssl
    my $data ='';
    return '' if ($^O !~ m/MSWin32/);

    _trace("_openssl_MS($mode, $host, $port)");
    $host .= ':' if ($port ne '');
    $text = '""' if (!defined $text);
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
    _trace("_openssl_MS $mode $host$port: cmd.exe /D /C /S $tmp") if ($trace > 1);
    TRY: {
        open( T, '>', $tmp)                or {$err = $!} and last;
        print T "$text | $_openssl $mode $host$port 2>&1";
        close T;
        #dbx# print `cat $tmp`;
        $src = 'cmd.exe';
        ($data =  `cmd.exe /D /S /C $tmp`) or {$err = $!} and last;
        $src = 'unlink';
        unlink  $tmp                       or {$err = $!} and last;
         $data =~ s#^[^)]*[^\r\n]*.##s;          # remove cmd.exe's output
         $data =~ s#WARN.*?openssl.cnf[\r\n]##;  # remove WARNINGs
        _trace("_openssl_MS $mode $host$port : $data #") if ($trace > 1);
    }
    if ($err ne '') {
        $text = "_openssl_MS() failed calling $src: $err";
        _trace($text) if ($trace > 1);
        push(@{$_SSLinfo{'errors'}}, $text);
        return '';
    }
    return $data;
} # _openssl_MS

sub _openssl_x509($$) {
    #? call external openssl executable to retrive more data from PEM
    my $pem  = shift;
    my $mode = shift;   # must be one of openssl x509's options
    my $data = '';
    _trace("_openssl_x509($mode,...).");
    _setcmd();
    if ($_openssl eq '') {
        _trace("_openssl_x509($mode): WARNING: no openssl") if ($trace > 1);
        return '#';
    }

    #if ($mode =~ m/^-(text|email|modulus|serial|fingerprint|subject_hash|trustout)$/) {
    #   # supported by openssl's x509 (0.9.8 and higher)
    #}
    if ($mode =~ m/^-?(version|pubkey|signame|sigdump|aux|extensions)$/) {
        # openssl works the other way arround:
        #   define as -certopt what should *not* be printed
        # hence we use a list with all those no_* options and remove that one
        # which should be printed
        my $m =  'no_' . $mode;
        $mode =  '-text -certopt no_header,no_version,no_serial,no_signame,no_validity,no_subject,no_issuer,no_pubkey,no_sigdump,no_aux,no_extensions,ext_default,ext_dump';
            # ca_default   not used as it's already in $_SSLinfo{'text'}
        $mode =~ s/$m//;
        $mode =~ s/,,/,/;  # need to remove , also, otherwise we get everything
    }
    $mode = 'x509 -noout ' . $mode;
    _trace("_openssl_x509(openssl $mode).") if ($trace > 1);
    if ($^O !~ m/MSWin32/) {
        $data = `echo '$pem' | $_openssl $mode 2>&1`;
    } else { # it's sooooo simple, except on Windows :-(
        $data = _openssl_MS($mode, '', '', $pem);
    }
    chomp $data;
    $data =~ s/\s*$//;  # be sure ...
    #dbx# print "#3 $data \n#3";
    return $data;
} # _openssl_x509

############################################################ public functions #
#
# for perldoc we need at least one space between ( and ) if used in a =head2
# line, otherwise it will be formatted wrong

=pod

=head2 do_ssl_open( $host,$port[,$cipherlist])

Opens new SSL connection with Net::SSLeay.
If C<$cipherlist> is missing or empty, default C<ALL:NULL:eNULL:aNULL:LOW> will be used.

Returns array with $ssl object and $ctx object.

This method is called automatically by all other functions, hence no need to
call it directly.
=cut

# from openssl/x509_vfy.h
sub _X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT () { 18 }
sub _FLAGS_ALLOW_SELFSIGNED () { 0x00000001 }

sub do_ssl_open($$) {
    my ($host, $port, $cipher) = @_;
    $cipher = "" if (!defined $cipher); # cipher parameter is optional
    _settrace();
    _trace("do_ssl_open(" . ($host||'') . "," . ($port||'') . "," . ($cipher||'') . ")");
    goto finished if (defined $_SSLinfo{'ssl'});
    #_SSLinfo_reset(); # <== does not work yet as it clears everything

    if ($cipher =~ m/^\s*$/) {
        $cipher = $_SSLinfo{'cipherlist'} if ($cipher =~ /^\s*$/);
    } else {
        $_SSLinfo{'cipherlist'} = $cipher;
    }
    _trace("do_ssl_open cipherlist: $_SSLinfo{'cipherlist'}");
    my $src;         # reason why something failed
    my $err = "";    # error string from sub-system, if any
    my $ssl = undef;
    my $dum;         # used to avoid warnings with perl's -w

# ToDo: proxy settings work in HTTP mode only
##Net::SSLeay::set_proxy('some.tld', 84, 'z00', 'pass');
##print "#ERR: $!";
##

    TRY: {
        $src = '_check_host(' . $host . ')'; if (!defined _check_host($host)) { last; }
        $src = '_check_port(' . $port . ')'; if (!defined _check_port($port)) { last; }
        $src = 'socket()';
                socket( S, &AF_INET, &SOCK_STREAM, 0)     or {$err = $!} and last;
        $src = 'connect()';
        $dum=()=connect(S, sockaddr_in($_SSLinfo{'port'}, $_SSLinfo{'addr'})) or {$err = $!} and last;
        select(S); $| = 1; select(STDOUT);  # Eliminate STDIO buffering

        # connection open, lets do SSL
        my $ctx;
        ($ctx = Net::SSLeay::CTX_new()) or {$src = 'Net::SSLeay::CTX_new()'} and last;
            # ToDo: not sure if CTX_new() can fail
        Net::SSLeay::CTX_set_verify($ctx, &Net::SSLeay::VERIFY_PEER, \&_check_peer);
            # ToDo: not sure if CTX_set_verify() can fail
######
            # SSL_version     => 'SSLv2', 'SSLv3', or 'TLSv1'
            # SSL_cipher_list => ALL:NULL:eNULL:aNULL:LOW  COMPLEMENTOFALL
#           # SSL_cipher_list => $_SSLinfo{'cipherlist'},
            # SSL_check_crl   => true (verify CRL in local SSL_ca_path)
            # SSL_honor_cipher_order  => true (cipher order provided by client)

             # ToDo: setting verify options not yet tested
# use constant SSL_VERIFY_NONE => Net::SSLeay::VERIFY_NONE();
# use constant SSL_VERIFY_PEER => Net::SSLeay::VERIFY_PEER();
# use constant SSL_VERIFY_FAIL_IF_NO_PEER_CERT => Net::SSLeay::VERIFY_FAIL_IF_NO_PEER_CERT();
# use constant SSL_VERIFY_CLIENT_ONCE => Net::SSLeay::VERIFY_CLIENT_ONCE();
            # SSL_verify_mode => # 0x00, 0x01 (verify peer), 0x02 (fails if no cert), 0x04 (verify client)

#

             # ToDo: setting more options not yet tested
        #Net::SSLeay::CTX_set_options($ctx, (Net::SSLeay::OP_NO_SSLv3() | Net::SSLeay::OP_NO_TLSv1()));
        #Net::SSLeay::OP_NO_TLSv1()) liefert unter Windows Speicherfehler

        # my $tls_options = Net::SSLeay::OP_NO_SSLv2() | Net::SSLeay::OP_NO_SSLv3();
        # 
        # my $fileno = fileno($sock);
        # my $ctx = Net::SSLeay::CTX_v23_new();
        # return { error => "SSL context init failed: $!" } unless $ctx;
        # Net::SSLeay::CTX_set_options($ctx, $tls_options) # returns new options bitmask
        #         or return { error => "SSL context option set failed: $!" };
    # 
# fuer Client-Cert siehe smtp_tls_cert.pl
######
######
                #Net::SSLeay::CTX_set_options($ctx, (Net::SSLeay::OP_CIPHER_SERVER_PREFERENCE));
                #Net::SSLeay::CTX_set_options($ctx, (Net::SSLeay::OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION));
######

        $src = 'Net::SSLeay::CTX_set_options()';
                Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL);
            # ToDo: not sure if CTX_set_options() can fail
        $src = 'Net::SSLeay::new()';
        ($ssl=  Net::SSLeay::new($ctx))                   or {$err = $!} and last;
            # ToDo: not sure if new() can fail
        $src = 'Net::SSLeay::set_fd()';
                Net::SSLeay::set_fd($ssl, fileno(S))      or {$err = $!} and last;
        if (!   Net::SSLeay::set_cipher_list($ssl, $cipher)) {
            $err = $!;
            $src = 'Net::SSLeay::set_cipher_list(' . $cipher . ')';
            last;
        }

#ah #ToDo: print "# SNI $Net::SSLinfo::use_SNI";
        if ($Net::SSLinfo::use_SNI == 1) {
            _trace("do_ssl_open: SNI");
            # use constant SSL_CTRL_SET_TLSEXT_HOSTNAME => 55
            # use constant TLSEXT_NAMETYPE_host_name    => 0
            $src = 'Net::SSLeay::ctrl()';
            Net::SSLeay::ctrl($ssl, 55, 0, $host)         or {$err = $!} and last;
#ah #ToDo: above sometimes fails but does not return errors, reason yet unknown
        }
        # following may call _check_peer()
        if (Net::SSLeay::connect($ssl) <= 0) {  # something failed
            $err = $!;
            $src = 'Net::SSLeay::connect()';
            last;
        }

        # SSL established, lets get informations
        # ToDo: starting from here implement error checks
        $src ='Net::SSLeay::get_peer_certificate()';
        my $x509= Net::SSLeay::get_peer_certificate($ssl);
        $_SSLinfo{'ctx'}        = $ctx;
        $_SSLinfo{'ssl'}        = $ssl;
        $_SSLinfo{'x509'}       = $x509;
        my $i   = 0;
        my $c   = '';
        push(@{$_SSLinfo{'ciphers'}}, $c) while ($c = Net::SSLeay::get_cipher_list($ssl, $i++));
        $_SSLinfo{'default'}    = Net::SSLeay::get_cipher($ssl);
        #$_SSLinfo{'bits'}       = Net::SSLeay::get_cipher_bits($ssl, $x509); # ToDo: Segmentation fault
        $_SSLinfo{'certificate'}= Net::SSLeay::dump_peer_certificate($ssl);  # same as issuer + subject
        $_SSLinfo{'PEM'}        = Net::SSLeay::PEM_get_string_X509($x509) || "";
            # 'PEM' set empty for example when $Net::SSLinfo::no_cert is in use
            # this inhibits warnings inside perl (see  NO Certificate  below)
        $_SSLinfo{'subject'}    = _ssleay_get('subject', $x509);
        $_SSLinfo{'issuer'}     = _ssleay_get('issuer',  $x509);
        $_SSLinfo{'before'}     = _ssleay_get('before',  $x509);
        $_SSLinfo{'after'}      = _ssleay_get('after',   $x509);
        if (1.33 <= $Net::SSLeay::VERSION) {# condition stolen from IO::Socket::SSL,
            $_SSLinfo{'altname'}= _ssleay_get('altname', $x509);
        } else {
            warn "you need at least Net::SSLeay version 1.33 for getting subjectAltNames";
        }
        if (1.30 <= $Net::SSLeay::VERSION) {# condition stolen from IO::Socket::SSL
            $_SSLinfo{'cn'}     = _ssleay_get('cn', $x509);
            $_SSLinfo{'cn'}     =~ s{\0$}{};    # work around Bug in Net::SSLeay <1.33 (from IO::Socket::SSL)
        } else {
            warn "you need at least Net::SSLeay version 1.30 for getting commonName";
        }
        
        $_SSLinfo{'policies'}   = _ssleay_get('policies', $x509);

        # used by IO::Socket::SSL, allow for compatibility and lazy user
        #      owner commonName cn subject issuer authority subjectAltNames
        #      alias: owner == subject, issuer == authority, commonName == cn
        $_SSLinfo{'commonName'} = $_SSLinfo{'cn'};
        $_SSLinfo{'authority'}  = $_SSLinfo{'issuer'};
        $_SSLinfo{'owner'}      = $_SSLinfo{'subject'};

        if (1.45 <= $Net::SSLeay::VERSION) {
            $_SSLinfo{'fingerprint_md5'} = _ssleay_get('md5',  $x509);
            $_SSLinfo{'fingerprint_sha1'}= _ssleay_get('sha1', $x509);
        } else {
            $_SSLinfo{'fingerprint_md5'} = '';
            $_SSLinfo{'fingerprint_sha1'}= '';
        }

        # following not working
        #$_SSLinfo{'signatureAl'}= $ssl->peer_certificate('SignatureAlgorithm') || '';
        #$_SSLinfo{'NPN'}        = $ssl->next_proto_negotiated()             || '';

        if ($Net::SSLinfo::use_http > 0) {
            _trace("do_ssl_open HTTPS {");
            #dbx# $host .= 'x';
            my $response = '';
            my $request  = "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n";
            $src = 'Net::SSLeay::write()';
            Net::SSLeay::write($ssl, $request) or {$err = $!} and last;
            $response = Net::SSLeay::read($ssl);
            $_SSLinfo{'https_status'}   =  $response;
            $_SSLinfo{'https_status'}   =~ s/[\r\n].*$//ms; # get very first line
            $_SSLinfo{'https_server'}   =  _header_get('Server',   $response);
            $_SSLinfo{'https_location'} =  _header_get('Location', $response);
            $_SSLinfo{'https_refresh'}  =  _header_get('Refresh',  $response);
            $_SSLinfo{'hsts'}           =  _header_get('Strict-Transport-Security', $response);
            $_SSLinfo{'hsts_maxage'}    =  $_SSLinfo{'hsts'};
            $_SSLinfo{'hsts_maxage'}    =~ s/.*?max-age=([^;" ]*).*/$1/i;
            $_SSLinfo{'hsts_subdom'}    = 'includeSubDomains' if ($_SSLinfo{'hsts'} =~ m/includeSubDomains/i);
            $_SSLinfo{'hsts_pins'}      =  $_SSLinfo{'hsts'}  if ($_SSLinfo{'hsts'} =~ m/pins=/i);
            $_SSLinfo{'hsts_pins'}      =~ s/.*?pins=([^;" ]*).*/$1/i;
# ToDo:     $_SSLinfo{'hsts_alerts'}    =~ s/.*?((?:alert|error|warning)[^\r\n]*).*/$1/i;
            _trace("\n$response \n# do_ssl_open HTTPS }");
            _trace("do_ssl_open HTTP {");
            my %headers;
            ($response, $_SSLinfo{'http_status'}, %headers) = Net::SSLeay::get_http($host, 80, '/',
                 Net::SSLeay::make_headers('Connection' => 'close', 'Host' => $host)
            );
            # ToDo: not tested if following grep() catches multiple occourances
            $_SSLinfo{'http_location'}  =  $headers{(grep(/^Location$/i, keys %headers))[0] || ""};
            $_SSLinfo{'http_refresh'}   =  $headers{(grep(/^Refresh$/i,  keys %headers))[0] || ""};
            $_SSLinfo{'http_sts'}       =  $headers{(grep(/^Strict-Transport-Security$/i, keys %headers))[0] || ""};
            _trace("\n$response \n# do_ssl_open HTTP }");
        }

        if ($Net::SSLinfo::use_openssl == 0) {
            # calling external openssl is a performance penulty
            # it would be better to manually parse $_SSLinfo{'text'} but that
            # needs to be adapted to changes of openssl's output then
            _trace("do_ssl_open() without openssl done.");
            goto finished;
        }
        # NO Certificate {
        # We get following data using openssl executable.
        # There is no need  to check  $Net::SSLinfo::no_cert  as openssl is
        # clever enough to return following strings if the cert is missing:
        #         unable to load certificate
        # If we use  'if (defined $_SSLinfo{'PEM'}) {'  instead of an empty
        # $_SSLinfo{'PEM'}  (see initial setting above),  then  all values
        # would contain an empty string instead of the the openssl warning:
        #         unable to load certificate
        my $fingerprint                 = _openssl_x509($_SSLinfo{'PEM'}, '-fingerprint');
        chomp $fingerprint;
        $_SSLinfo{'fingerprint_text'}   = $fingerprint;
        $_SSLinfo{'fingerprint'}        = $fingerprint; #alias
       ($_SSLinfo{'fingerprint_type'},  $_SSLinfo{'fingerprint_hash'}) = split('=', $fingerprint);
        $_SSLinfo{'fingerprint_type'}   =~ s/(^[^\s]*).*/$1/;
        $_SSLinfo{'fingerprint_hash'}   = "" if (!defined $_SSLinfo{'fingerprint_hash'});

        $_SSLinfo{'text'}               = _openssl_x509($_SSLinfo{'PEM'}, '-text');
        $_SSLinfo{'modulus'}            = _openssl_x509($_SSLinfo{'PEM'}, '-modulus');
        $_SSLinfo{'serial'}             = _openssl_x509($_SSLinfo{'PEM'}, '-serial');
        $_SSLinfo{'email'}              = _openssl_x509($_SSLinfo{'PEM'}, '-email');
        $_SSLinfo{'subject_hash'}       = _openssl_x509($_SSLinfo{'PEM'}, '-subject_hash');
        $_SSLinfo{'issuer_hash'}        = _openssl_x509($_SSLinfo{'PEM'}, '-issuer_hash');
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
       ($_SSLinfo{'pubkey_value'}       =  $_SSLinfo{'pubkey'})  =~ s/^.*?Modulus ([^\r\n]*)//si;
        $_SSLinfo{'pubkey_value'}       =~ s/Exponent.*//si;
        $_SSLinfo{'modulus_exponent'}   =  $_SSLinfo{'pubkey'};
        $_SSLinfo{'modulus_exponent'}   =~ s/^.*?Exponent: (.*)$/$1/si;
        $_SSLinfo{'modulus'}            =~ s/^[^=]*=//i;
        $_SSLinfo{'serial'}             =~ s/^[^=]*=//i;
        $_SSLinfo{'signame'}            =~ s/^[^:]*: //i;
        $_SSLinfo{'modulus_len'}        =  4 * length($_SSLinfo{'modulus'});
            # Note: modulus is hex value where 2 characters are 8 bit
        $_SSLinfo{'sigkey_len'}         =  $_SSLinfo{'sigkey_value'};
        $_SSLinfo{'sigkey_len'}         =~ s/[\s\n]//g;
        $_SSLinfo{'sigkey_len'}         =~ s/[:]//g;
        $_SSLinfo{'sigkey_len'}         =  4 * length($_SSLinfo{'sigkey_len'});
        chomp $_SSLinfo{'fingerprint_hash'};
        chomp $_SSLinfo{'modulus'};
        chomp $_SSLinfo{'pubkey'};
        chomp $_SSLinfo{'serial'};
        chomp $_SSLinfo{'signame'};
        # NO Certificate }

        $_SSLinfo{'s_client'}       = do_openssl('s_client', $host, $port);
        
            # from s_client:
            #    Protocol  : TLSv1
            #    Session-ID: 322193A0D243EDD1C07BA0B2E68D1044CDB06AF0306B67836558276E8E70655C
            #    Session-ID-ctx: 
            #    Master-Key: EAC0900291A1E5B73242C3C1F5DDCD4BAA7D9F8F4BC6E640562654B51E024143E5403716F9BF74672AF3703283456403
            #    Key-Arg   : None
            #    Krb5 Principal: None
            #    PSK identity: None
            #    PSK identity hint: None
            #    SRP username: None
            #    Compression: zlib compression
            #    Expansion: zlib compression
        my %match_map = (
            # %_SSLinfo key       string to match in s_client
            'session_id'       => "Session-ID:",
            'master_key'       => "Master-Key:",
            'krb5'             => "Krb5 Principal:",
            'psk_identity'     => "PSK identity:",
            'psk_hint'         => "PSK identity hint:",
            'srp'              => "SRP username:",
            'compression'      => "Compression:",
            'expansion'        => "Expansion:",
            #'session_ticket'   => "TLS session ticket:",
            #'renegotiation'    => "Renegotiation".
        );
        my $d    = "";
        my $data = $_SSLinfo{'s_client'};
            # Note: as openssl s_client is called with -resume, the retrived
            # data may contain output of s_client up to 5 times
            # it's not ensured that all 5 data sets are identical, hence
            # we need to check them all -at least the last one-
            # Unfortunately all following checks us akk 5 data sets.
        foreach my $key (keys %match_map) {
            my $regex = $match_map{$key};
            $d = $data;
            $d =~ s/.*?$regex\s*([^\n]*)\n.*/$1/si;
            $_SSLinfo{$key} = $d if ($data =~ m/$regex/);
        }

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
            # ToDo: pedantically we also need to check if "RENEGOTIATING" is
            #       there, as just the information "IS supported" does not
            #       mean that it works
        $d = $data; $d =~ s/.*?((?:Secure\s*)?Renegotiation[^\n]*)\n.*/$1/si;$_SSLinfo{'renegotiation'}  = $d;

            # from s_client:
            #    Reused, TLSv1/SSLv3, Cipher is RC4-SHA
            #    Session-ID: F4AD8F441FDEBDCE445D4BD676EE592F6A0CEDA86F08860DF824F8D29049564F
            # we do a simple check: just grep for "Reused" in s_client
            # in details it should check if all "Reused" strings are
            # identical *and* the "Session-ID" is the same for all
            # if more than 2 "New" are detected, we assume no resumption
            # finally "Reused" must be part of s_client data
        $d = $data;
        my $cnt =()= $d =~ m/(New|Reused),/g;
        if ($cnt < 3) {
            _trace("do_ssl_open: slow target server; resumption not detected; try to increase \$Net::SSLinfo::timeout_sec");
        } else {
            $cnt =()= $d =~ m/New,/g;
            _trace("do_ssl_open: checking resumption: found $cnt `New' ");
            if ($cnt > 2) { # too much "New" reconnects, assume no resumption
                $cnt =()= $d =~ m/Reused,/g;
                _trace("do_ssl_open: checking resumption: found $cnt `Reused' ");
                $_SSLinfo{'resumption'} = 'no';
            } else {
                $d =~ s/.*?(Reused,[^\n]*).*/$1/si;
                $_SSLinfo{'resumption'} = $d if ($d =~ m/Reused,/);
            }
        }

            # from s_client (different openssl return different strings):
            #       Verify return code: 20 (unable to get local issuer certificate)
            #       verify error:num=20:unable to get local issuer certificate
            #       Verify return code: 19 (self signed certificate in certificate chain)
        $d = $data; $d =~ s/.*?Verify (?:error|return code):\s*((?:num=)?[\d]*[^\n]*).*/$1/si;
        $_SSLinfo{'verify'}         = $d;
        # ToDo: $_SSLinfo{'verify_host'}= $ssl->verify_hostname($host, 'http');  # returns 0 or 1
        # scheme can be: ldap, pop3, imap, acap, nntp http, smtp

        $d =~ s/.*?(self signed.*)/$1/si;
        $_SSLinfo{'selfsigned'}     = $d;
        
            # from s_client:
            # $_SSLinfo{'s_client'} grep
            #       Certificate chain
        # ToDo: $_SSLinfo{'chain'}    = $d;

        _trace("do_ssl_open() with openssl done.");
        print Net::SSLinfo::dump() if ($trace > 0);
        goto finished;
    } # TRY
    # error handling
    push(@{$_SSLinfo{'errors'}}, "do_ssl_open() failed calling $src: $err");
    if ($trace > 1) {
        Net::SSLeay::print_errs(SSLINFO_ERR);
        printf(SSLINFO_ERR);
        print join(SSLINFO_ERR, @{$_SSLinfo{'errors'}});
    }
    _trace("do_ssl_open() failed.");
    return undef;

    finished:
    _trace("do_ssl_open() done.");
    return wantarray ? ($_SSLinfo{'ssl'}, $_SSLinfo{'ctx'}) : $_SSLinfo{'ssl'};
} # do_ssl_open

=pod

=head2 do_ssl_close( )

Close Net::SSLeay connection and free allocated objects.
=cut

sub do_ssl_close($$) {
    #? close TCP connection for SSL
    my ($host, $port) = @_;
    _trace("do_ssl_close($host,$port)");
    Net::SSLeay::free($_SSLinfo{'ssl'})     if (defined $_SSLinfo{'ssl'}); # or warn "**WARNING: Net::SSLeay::free(): $!";
    Net::SSLeay::CTX_free($_SSLinfo{'ctx'}) if (defined $_SSLinfo{'ctx'}); # or warn "**WARNING: Net::SSLeay::CTX_free(): $!";
    _SSLinfo_reset();
    close(S);
    return;
} # do_ssl_close

=pod

=head2 do_openssl($command,$host,$port,$data)

Wrapper for call of external L<openssl(1)> executable. Handles special
behaviours on some platforms.

If C<$command> equals C<s_client> it will add C<-reconnect -connect> to the
openssl call. All other values of C<$command> will be used verbatim.
Note that the SSL version must be part (added) as proper openssl option
to C<$command> as this option cannot preceed the command in openssl..

Examples for C<$command>:
    ciphers -sslv3
    s_client -tlsv1_1 -connect

The value of C<$data>, if set, is piped to openssl.

Returns retrieved data or '#' if openssl or s_client missing.
=cut

sub do_openssl($$$) {
    #? call external openssl executable to retrive more data
    my $mode = shift;   # must be openssl command
    my $host = shift;
    my $port = shift;
    my $data = shift || "";  # data is optional
    _trace("do_openssl($mode,$host,$port...).");
    _setcmd();
    if ($_openssl eq '') {
        _trace("do_openssl($mode): WARNING: no openssl") if ($trace > 1);
        return '#';
    }
    if ($mode =~ m/^-?(s_client)$/) {
        $mode =  's_client -reconnect -connect';
        if ($Net::SSLinfo::use_sclient == 0) {
            _trace("do_openssl($mode): WARNING: no openssl s_client") if ($trace > 1);
            return '#';
        }
    }
    $host = $port = "" if ($mode =~ m/^-?(ciphers)/);
    _trace("echo '' | $_timeout $_openssl $mode $host$port 2>&1") ;#if ($trace > 1);
    if ($^O !~ m/MSWin32/) {
        $host .= ':' if ($port ne '');
        $data = `echo $data | $_timeout $_openssl $mode $host$port 2>&1`;
    } else {
        $data = _openssl_MS($mode, $host, $port, '');
    }
    chomp $data;
    $data =~ s/\s*$//;  # be sure ...
    return $data;
} # do_openssl

=pod

=head2 set_cipher_list($cipherlist)

Set cipher list for connection.

Returns empty string on success, errors otherwise.
=cut

# ToDo: buggy, Net::SSLeay::set_cipher_list() returns  Segmentation fault
#       (12/2012 for Net::SSLeay 1.49, OpenSSL 0.9.8o)
sub set_cipher_list($$) {
    my $ssl    = shift;
    my $cipher = shift;
    Net::SSLeay::set_cipher_list($ssl, $cipher) or return SSLINFO . '::set_cipher_list(' . $cipher . ')';
    $_SSLinfo{'cipherlist'} = $cipher;
    return '';
}

=pod

=head2 s_client( )

Dump data retrived from "openssl s_client ..." call. For debugging only.

=head2 errors( )

Get list of errors from C<$Net::SSLeay::*> calls.

=head2 PEM( ), pem( )

Get certificate in PEM format.

=head2 text( )

Get certificate in human readable format.

=head2 before( )

Get date before certificate is valid.

=head2 after( )

Get date after certificate is valid.

=head2 dates( )

Get dates when certificate is valid.

=head2 issuer( )

Get issuer of certificate.

=head2 subject( )
 
Get subject of certificate.

=head2 default( )

Get default cipher offered by server. Returns ciphers string.

=head2 ciphers( ), cipher_list( )

Get cipher list offered by local SSL implementation. Returns space-separated list of ciphers.

Requires successful connection to target.

=head2 cipher_local( )

Get cipher list offered by local openssl implementation. Returns colon-separated list of ciphers.

Does not require connection to any target.

=head2 cn( ), commonname( )

Get common name (CN) from certificate.

=head2 altname( )

Get alternate name (subjectAltNames) from certificate.

=head2 authority( )

Get authority (issuer) from certificate.

=head2 owner( )

Get owner (subject) from certificate.

=head2 certificate( )

Get certificate (subject, issuer) from certificate.
=cut

#=head2 version( )
#
#Get version from certificate.
#
#=head2 keysize( )
#
#Get certificate private key size.
#
#=head2 keyusage( )
#
#Get certificate X509v3 Extended Key Usage (Version 3 and TLS only?)
#=cut

=pod

=head2 dump( )

Print all available (by Net::SSLinfo) data.

Due to huge amount of data, the value for s_client is usually omitted.
Please set C<$Net::SSLinfo::use_sclient > 1> to print this data also.

=head2 (details)

All following require that C<$Net::SSLinfo::use_openssl=1;> being set.

=head2 compression( )

Get target's compression support.

=head2 exapansion( )

Get target's exapansion support.

=head2 krb5

Get target's Krb5 Principal.

=head2 psk_identity

Get target's PSK identity.

=head2 psk_hint

Get target's PSK identity hint.

=head2 srp

Get target's SRP username.

=head2 master_key

Get target's Master-Key.

=head2 session_ticket

Get target's TLS session ticket.

=head2 fingerprint_hash( )

Get certificate fingerprint hash value.

=head2 fingerprint_md5( )

Get  MD5 fingerprint if available (Net::SSLeay >= 1.49)

=head2 fingerprint_sha1( )

Get SHA1 fingerprint if available (Net::SSLeay >= 1.49)

=head2 fingerprint_type( )

Get certificate fingerprint hash algorithm.

=head2 fingerprint_text( )

Get certificate fingerprint, which is the hash algorthm followed by the hash
value. This is usually the same as C<fingerprint_type()=fingerprint_hash()>.

=head2 fingerprint( )

Alias for C<fingerprint_text()>.

=head2 email( )

Get certificate email address(es).

=head2 serial( )

Get certificate serial number.

=head2 modulus( )

Get certificate modulus of the public key.

=head2 modulus_exponent( )

Get certificate modulus' exponent of the public key.

=head2 modulus_len( )

Get certificate modulus (bit) length of the public key.

=head2 pubkey( )

Get certificate's public key.

=head2 pubkey_algorithm( )

Get certificate's public key algorithm.

=head2 pubkey_value( )

Get certificate's public key value.
Same as I<modulus()>  but may be different format.

=head2 renegotiation( )

Get certificate's renegotiation support.

=head2 resumption( )

Get certificate's resumption support.
Some target servers respond with  `New' and `Reused'  connections in
unexpected sequence. If `Reused' is found and less than 3 `New' then
resumption is assumed. 

If resumption is not detected, increasing the timeout with i.e.
"$Net::SSLinfo::timeout_sec = 5"  may return different results.

=head2 sigkey_len( )

Get certificate signature key (bit).

=head2 sigkey_value( )

Get certificate signature value (hexdump).

=head2 selfsigned( )

If certificate is self signed.

=head2 https_alerts( )

Get HTTPS alerts send by server.

=head2 https_status( )

Get HTTPS response (aka status) line.

=head2 https_server( )

Get HTTPS Server header.

=head2 https_location( )

Get HTTPS Location header.

=head2 https_refresh( )

Get HTTPS Refresh header.

=head2 http_status( )

Get HTTP response (aka status) line.

=head2 http_location( )

Get HTTP Location header.

=head2 http_refresh( )

Get HTTP Refresh header.

=head2 http_sts( )

Get HTTP Strict-Transport-Security header, if any.

=head2 hsts( )

Get complete STS header.

=head2 hsts_maxage( )

Get max-age attribute of STS header.

=head2 hsts_subdom( )

Get includeSubDomains attribute of STS header.

=head2 hsts_pins( )

Get pins attribute of STS header.

=cut

sub s_client        { return _SSLinfo_get('s_client',         $_[0], $_[1]); }
sub errors          { return _SSLinfo_get('errors',           $_[0], $_[1]); }
sub PEM             { return _SSLinfo_get('PEM',              $_[0], $_[1]); }
sub pem             { return _SSLinfo_get('PEM',              $_[0], $_[1]); } # alias for PEM
sub text            { return _SSLinfo_get('text',             $_[0], $_[1]); }
sub before          { return _SSLinfo_get('before',           $_[0], $_[1]); }
sub after           { return _SSLinfo_get('after',            $_[0], $_[1]); }
sub dates           { return _SSLinfo_get('dates',            $_[0], $_[1]); }
sub issuer          { return _SSLinfo_get('issuer',           $_[0], $_[1]); }
sub subject         { return _SSLinfo_get('subject',          $_[0], $_[1]); }
sub default         { return _SSLinfo_get('default',          $_[0], $_[1]); }
sub ciphers         { return _SSLinfo_get('ciphers',          $_[0], $_[1]); }
sub cipher_list     { return _SSLinfo_get('ciphers',          $_[0], $_[1]); } # alias for ciphers
sub cipher_local    { return _SSLinfo_get('ciphers_openssl',  $_[0], $_[1]); }
sub cn              { return _SSLinfo_get('cn',               $_[0], $_[1]); }
sub commonname      { return _SSLinfo_get('cn',               $_[0], $_[1]); } # alias for cn
sub altname         { return _SSLinfo_get('altname',          $_[0], $_[1]); }
sub authority       { return _SSLinfo_get('authority',        $_[0], $_[1]); }
sub owner           { return _SSLinfo_get('owner',            $_[0], $_[1]); } # alias for subject
sub certificate     { return _SSLinfo_get('certificate',      $_[0], $_[1]); }
sub version         { return _SSLinfo_get('version',          $_[0], $_[1]); } # NOT IMPLEMENTED
sub keysize         { return _SSLinfo_get('keysize',          $_[0], $_[1]); } # NOT IMPLEMENTED
sub keyusage        { return _SSLinfo_get('keyusage',         $_[0], $_[1]); } # NOT IMPLEMENTED
sub email           { return _SSLinfo_get('email',            $_[0], $_[1]); }
sub modulus         { return _SSLinfo_get('modulus',          $_[0], $_[1]); }
sub serial          { return _SSLinfo_get('serial',           $_[0], $_[1]); }
sub aux             { return _SSLinfo_get('aux',              $_[0], $_[1]); }
sub extensions      { return _SSLinfo_get('extensions',       $_[0], $_[1]); }
sub trustout        { return _SSLinfo_get('trustout',         $_[0], $_[1]); }
sub ocsp_uri        { return _SSLinfo_get('ocsp_uri',         $_[0], $_[1]); }
sub ocspid          { return _SSLinfo_get('ocspid',           $_[0], $_[1]); }
sub pubkey          { return _SSLinfo_get('pubkey',           $_[0], $_[1]); }
sub signame         { return _SSLinfo_get('signame',          $_[0], $_[1]); }
sub sigdump         { return _SSLinfo_get('sigdump',          $_[0], $_[1]); }
sub sigkey_value    { return _SSLinfo_get('sigkey_value',     $_[0], $_[1]); }
sub sigkey_len      { return _SSLinfo_get('sigkey_len',       $_[0], $_[1]); }
sub subject_hash    { return _SSLinfo_get('subject_hash',     $_[0], $_[1]); }
sub issuer_hash     { return _SSLinfo_get('issuer_hash',      $_[0], $_[1]); }
sub verify          { return _SSLinfo_get('verify',           $_[0], $_[1]); }
sub compression     { return _SSLinfo_get('compression',      $_[0], $_[1]); }
sub expansion       { return _SSLinfo_get('expansion',        $_[0], $_[1]); }
sub krb5            { return _SSLinfo_get('krb5',             $_[0], $_[1]); }
sub psk_hint        { return _SSLinfo_get('psk_hint',         $_[0], $_[1]); }
sub psk_identity    { return _SSLinfo_get('psk_identity',     $_[0], $_[1]); }
sub srp             { return _SSLinfo_get('srp',              $_[0], $_[1]); }
sub master_key      { return _SSLinfo_get('master_key',       $_[0], $_[1]); }
sub session_id      { return _SSLinfo_get('session_id',       $_[0], $_[1]); }
sub session_ticket  { return _SSLinfo_get('session_ticket',   $_[0], $_[1]); }
sub fingerprint_hash{ return _SSLinfo_get('fingerprint_hash', $_[0], $_[1]); }
sub fingerprint_text{ return _SSLinfo_get('fingerprint_text', $_[0], $_[1]); }
sub fingerprint_type{ return _SSLinfo_get('fingerprint_type', $_[0], $_[1]); }
sub fingerprint_sha1{ return _SSLinfo_get('fingerprint_sha1', $_[0], $_[1]); }
sub fingerprint_md5 { return _SSLinfo_get('fingerprint_md5' , $_[0], $_[1]); }
sub fingerprint     { return _SSLinfo_get('fingerprint',      $_[0], $_[1]); } # alias for fingerprint_text
sub modulus_len     { return _SSLinfo_get('modulus_len',      $_[0], $_[1]); }
sub modulus_exponent{ return _SSLinfo_get('modulus_exponent', $_[0], $_[1]); }
sub pubkey_algorithm{ return _SSLinfo_get('pubkey_algorithm', $_[0], $_[1]); }
sub pubkey_value    { return _SSLinfo_get('pubkey_value',     $_[0], $_[1]); }
sub renegotiation   { return _SSLinfo_get('renegotiation',    $_[0], $_[1]); }
sub resumption      { return _SSLinfo_get('resumption',       $_[0], $_[1]); }
sub selfsigned      { return _SSLinfo_get('selfsigned',       $_[0], $_[1]); }
sub https_status    { return _SSLinfo_get('https_status',     $_[0], $_[1]); }
sub https_server    { return _SSLinfo_get('https_server',     $_[0], $_[1]); }
sub https_alerts    { return _SSLinfo_get('https_alerts',     $_[0], $_[1]); }
sub https_location  { return _SSLinfo_get('https_location',   $_[0], $_[1]); }
sub https_refresh   { return _SSLinfo_get('https_refresh',    $_[0], $_[1]); }
sub http_status     { return _SSLinfo_get('http_status',      $_[0], $_[1]); }
sub http_location   { return _SSLinfo_get('http_location',    $_[0], $_[1]); }
sub http_refresh    { return _SSLinfo_get('http_refresh',     $_[0], $_[1]); }
sub http_sts        { return _SSLinfo_get('http_sts',         $_[0], $_[1]); }
sub hsts            { return _SSLinfo_get('hsts',             $_[0], $_[1]); }
sub hsts_maxage     { return _SSLinfo_get('hsts_maxage',      $_[0], $_[1]); }
sub hsts_subdom     { return _SSLinfo_get('hsts_subdom',      $_[0], $_[1]); }
sub hsts_pins       { return _SSLinfo_get('hsts_pins',        $_[0], $_[1]); }

=pod

=head2 verify_hostname( )

Verify if given hostname matches common name (CN) in certificate.
=cut

############ ToDo:  do_ssl_open  vorbereiten fuer verify_*
sub verify_hostname {
    my ($host, $port) = @_;
    return undef if !defined do_ssl_open($host, $port);
    return $Net::SSLinfo::no_cert_txt if ($Net::SSLinfo::no_cert != 0);
    my $cname = $_SSLinfo{'cn'};
    my $match = '';
    if ($Net::SSLinfo::ignore_case == 1) {
        $host = lc($host);
        $cname= lc($cname);
    }
    $match = ($host eq $cname) ? 'matches' : 'does not match';
    return sprintf("Given hostname '%s' %s CN '%s' in certificate", $host, $match, $cname);
}

=head2 verify_altname( ), verify_alias( )

Verify if given hostname matches alternate name (subjectAltNames) in certificate.
=cut

sub verify_altname($$) {
    my ($host, $port) = @_;
    return undef if !defined do_ssl_open($host, $port);
    return $Net::SSLinfo::no_cert_txt if ($Net::SSLinfo::no_cert != 0);
    _trace("verify_altname($host)");
    my $match = 'does not match';
    my $cname = $_SSLinfo{'altname'};
    return "No alternate name defined in certificate" if ($cname eq '');
    _trace("verify_altname: $cname");
    foreach my $alt (split(' ', $cname)) {
        my ($type, $name) = split(':', $alt);
# ToDo: implement IP and URI
        push(@{$_SSLinfo{'errors'}}, "verify_altname() $type not supported in SNA") if ($type !~ m/DNS/i);
        my $rex = $name;
        if ($Net::SSLinfo::ignore_case == 1) {
            $host = lc($host);
            $rex  = lc($rex);
        }
        $rex =~ s/[.]/\\./g;
        if ($name =~ m/[*]/) {
            $rex =~ s/(\*)/.*?/;
        }
        _trace("verify_altname: $host =~ $rex ");
        if ($host =~ /^$rex$/) {
            $match = 'matches';
            $cname = $alt;   # only show matching name
            last;
        }
    }
    _trace("verify_altname() done.");
    return sprintf("Given hostname '%s' %s alternate name '%s' in certificate", $host, $match, $cname);
}

sub verify_alias { verify_altname($_[0], $_[1]); }

sub _check_peer() {
    # TBD
    my ($ok, $x509_store_ctx) = @_;
    _trace("_check_peer($ok, $x509_store_ctx)");
    $_SSLinfo{'verify_cnt'} += 1;
    #print "## check_peer $ok";
}
sub _check_client_cert() {print "##check_client_cert\n";}
#$my $err = Net::SSLeay::set_verify ($ssl, Net::SSLeay::VERIFY_CLIENT_ONCE, \&_check_client_cert );

sub _check_crl($$) {
    # TBD
    my $ssl = shift;
    _trace("_check_crl()");
}

sub error($) {
    # TBD
    #return Net::SSLeay::ERR_get_error;
}

#dbx# if ($#ARGV >= 0) {
#dbx#     $\="\n";
#dbx#     do_ssl_open( shift, 443);
#dbx#     print Net::SSLinfo::dump();
#dbx# }

1;

######################################################## public documentation #

=pod

=head1 SEE ALSO

L<Net::SSLeay(1)>

=head1 AUTHOR

08-aug-12 Achim Hoffmann
=cut
