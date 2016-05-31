#!/usr/bin/perl
## PACKAGE {

##################################  E X P E R I M E N T A L  #################

# TODO: see comment at %cipher_names

package OSaft::Ciphers;

use strict;
use warnings;
use Carp;
our @CARP_NOT = qw(OSaft::Ciphers); # TODO: funktioniert nicht

use Readonly;
Readonly our $VERSION     => '16.05.31';    # offizial verion number of tis file
Readonly our $CIPHERS_SID => '@(#) ciphers.pm 1.1 16/05/31 02:07:05';
Readonly my  $STR_UNDEF   => '<<undef>>';   # defined in osaft.pm

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

# more public documentation, see start of methods section, and at end of file.

## no critic qw(Variables::ProtectPrivateVars)
#  Our private variable names start with an  _  as suggested by percritic.
#  However, percritic is too stupid to recognice such names if the is fully
#  qualified with preceding package name.

## no critic qw(Documentation::RequirePodSections)
#  Our POD below is fine, perlcritic (severity 2) is too pedantic here.

## no critic qw(Documentation::RequirePodAtEnd)
#  Our POD is inline as it serves for documenting the code itself too.
#  But: this is a violation for severity 1, which is fixed and the produces
#       another violation for severity 2.

=pod

=encoding utf8

=head1 NAME

OSaft::Ciphers - common perl module for O-Saft ciphers

=head1 SYNOPSIS

    OSaft::Ciphers.pm       # on command line will print help

    use OSaft::Ciphers;     # from within perl code

=head1 OPTIONS

=head1 DESCRIPTION

Utility package for O-Saft (o-saft.pl and related tools). This package declares
and defines common L</VARIABLES> and L</METHODS> to be used in the calling tool.

=head2 Used Functions

Following functions (methods) must be defined in the calling program:

None (06/2016).

=head1 VARIABLES

=over 4

=item %ciphers

Hash with all cipher suites and paramters of each suite. Indexed by cipher ID.

=item %ciphers_desc

=item %cipher_names

Hash with various names, identifiers and constants for each cipher suites.
Indexed by cipher ID.

=item %cipher_alias

Hash with various additional names, identifiers and constants for cipher suites.
Indexed by cipher ID.

=item %cipher_results

Hash with all checked ciphers.

=back

=head1 METHODS

Only getter, setter and print methods are exported. All other methods must be
used with the full package name.

=cut

## no critic qw(Modules::ProhibitAutomaticExportation, Variables::ProhibitPackageVars)
# FIXME: perlcritic complains to not declare (global) package variables, but
#        the purpose of this module is to do that. This may change in future.

use Exporter qw(import);
use base     qw(Exporter);
our @EXPORT_OK  = qw(
                %ciphers_desc
                %ciphers
                %cipher_names
                %cipher_alias
                @cipher_results
                get_cipher_param
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
                get_cipher_rfc
                get_cipher_dtls
                get_cipher_hex
                get_cipher_name
                cipher_done
);
# insert above in vi with:
# :r !sed -ne 's/^our \([\%$@][a-zA-Z0-9_][^ (]*\).*/\t\t\1/p' %
# :r !sed -ne 's/^sub \([a-zA-Z][^ (]*\).*/\t\t\1/p' %

# TODO: interanl wrappers for main's methods
sub _trace(@)   { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _trace0(@)  { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _trace1(@)  { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _trace2(@)  { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _trace3(@)  { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)

sub _warn(@)    { my @args = @_; carp("**WARNING: ", join(" ", @args)); return; }

#_____________________________________________________________________________
#________________________________________________________________ variables __|

our %ciphers_desc = (   # description of following %ciphers table
    'head'          => [qw(  sec  ssl   keyx   auth  enc  bits mac  tags)],
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
        'tags',             # export  as reported by openssl 0.9.8 .. 1.0.1h
                            # OSX     on Mac OS X only
                            # :    (colon) is empty marker (need for other tools
        ],
); # %ciphers_desc

####### nur  %ciphers  und  %cipher_names  wird verwendet
####### alle anderen  %_cipher*  sind nur zur Initialisierung

our %ciphers = (
    #? list of all ciphers, will be generated in _ciphers_init()
    #-------------------+----+----+----+----+----+----+-------+----+---+-------,
    # hex,hex    => [qw( ssl  keyx auth enc  bits mac  DTLS-OK RFC  sec tags )],
    #-------------------+----+----+----+----+----+----+-------+----+---+-------,
    #-------------------+----+----+----+----+----+----+-------+----+---+-------,
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
    #!#----------+-------------------------------------+--------------------------+
#
    # Note(c)
    #   according https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305-04
    #   some hex keys for ciphers changed
); # %cipher_names

our %_ciphers_openssl_all = (
    #? internal list, generated by gen_ciphers.sh
    #-------------------+----+----+----+----+----+----+----+-------,
    # hex,hex    => [qw( ssl  keyx auth enc  bits mac  name tags )],
    #-------------------+----+----+----+----+----+----+----+-------,
#   '0x00,0x05'  => [qw( SSLv3 RSA RSA  RC4   128 SHA1 RC4-SHA
    #-------------------+----+----+----+----+----+----+----+-------,
); # %_ciphers_openssl_all
eval {require qw{OSaft/_ciphers_openssl_all.pm}; } or _warn "cannot read OSaft/_ciphers_openssl_bin.pm";

our %_ciphers_openssl_inc = (
    #? internal list, generated from openssl source
); # %_ciphers_openssl_inc

our %_ciphers_iana = (
    #? internal list, generated by gen_ciphers.sh
    #-------------------+------------------------------------+-------+---------,
    # hex,hex    => [qw( IANA cipher suite constant           RFC(s) DTLS-OK )],
    #-------------------+------------------------------------+-------+---------,
#   '0xC0,0x32'  => [qw( TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 5289    Y      )],
#   '0xC0,0x33'  => [qw( TLS_ECDHE_PSK_WITH_RC4_128_SHA       5489,6347    N )],
    #-------------------+------------------------------------+-------+---------,
); # %__ciphers_iana
eval {require qw{OSaft/_ciphers_iana.pm}; } or _warn "cannot read OSaft/_ciphers_iana.pm";

our %_ciphers_osaft = (
    #? internal list, additions to %_ciphers_openssl
    # /opt/tools/openssl-chacha/bin/openssl ciphers -V ALL:eNULL:LOW:EXP \
);# %_ciphers_osaft
eval {require qw{OSaft/_ciphers_osaft.pm}; } or _warn "cannot read OSaft/_ciphers_osaft.pm";

our %cipher_alias = ( # TODO: list not yet used
    #!#----------+-------------------------------------+-----------------------,
    #!# constant =>     cipher suite name alias        # comment (where found)
    #!#----------+-------------------------------------+-----------------------,
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


our @cipher_results = [
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


#_____________________________________________________________________________
#__________________________________________________________________ methods __|

=pod

=head2 get_cipher_param($cipher, $key)

=head2 get_cipher_sec( $cipher)

=head2 get_cipher_ssl( $cipher)

=head2 get_cipher_enc( $cipher)

=head2 get_cipher_bits($cipher)

=head2 get_cipher_mac( $cipher)

=head2 get_cipher_auth($cipher)

=head2 get_cipher_keyx($cipher)

=head2 get_cipher_score($cipher)

=head2 get_cipher_tags($cipher)

=head2 get_cipher_desc($cipher)

=head2 get_cipher_rfc( $cipher)

=head2 get_cipher_dtls($cipher)

Get information from internal C<%cipher> data structure.

=cut

# some people prefer to use a getter function to get data from objects
# each function returns a spcific value (column) from the %cipher table
# see %ciphers_desc about description of the columns
# returns STR_UNDEF if requested cipher is missing
sub get_cipher_param($$) {
    #? internal method to return required value from %cipher
    my ($cipher, $key) = @_;
    return $ciphers{$cipher}->{$key} || '' if ((grep{/^$cipher/} %ciphers)>0);
    return $STR_UNDEF;
}; # get_cipher_param
sub get_cipher_sec($)  { my $c=shift; return get_cipher_param($c, 'sec'); }
sub get_cipher_ssl($)  { my $c=shift; return get_cipher_param($c, 'ssl'); }
sub get_cipher_enc($)  { my $c=shift; return get_cipher_param($c, 'enc'); }
sub get_cipher_bits($) { my $c=shift; return get_cipher_param($c, 'bit'); }
sub get_cipher_mac($)  { my $c=shift; return get_cipher_param($c, 'mac'); }
sub get_cipher_auth($) { my $c=shift; return get_cipher_param($c, 'au');  }
sub get_cipher_keyx($) { my $c=shift; return get_cipher_param($c, 'kx');  }
sub get_cipher_tags($) { my $c=shift; return get_cipher_param($c, 'tag'); }
sub get_cipher_rfc($)  { my $c=shift; return get_cipher_param($c, 'rfc'); }
sub get_cipher_dtls($) { my $c=shift; return get_cipher_param($c, 'dtls'); }
sub get_cipher_score($){ my $c=shift; return $STR_UNDEF; } # obsolete since 16.06.16

sub get_cipher_desc($) { my $c=shift;
    # get description for specified cipher from %ciphers
    if (! defined $ciphers{$c}) {
       _warn("undefined cipher description for '$c'"); # TODO: correct %ciphers
       return $STR_UNDEF;
    }
    my @c = @{$ciphers{$c}};
    shift @c;
    return @c if ((grep{/^$c/} %ciphers)>0);
    return '';
}

=pod

=head2 get_cipher_hex($cipher)

Get cipher's hex key from C<%cipher_names> or C<%cipher_alias> data structure.

=head2 get_cipher_name($cipher)

Check if given C<%cipher> name is a known cipher.

=cut

sub get_cipher_hex($)  {
    # find hex key for cipher in %cipher_names or %cipher_alias
    my $c = shift;
    foreach my $k (keys %cipher_names) { # database up to VERSION 14.07.14
        return $k if (($cipher_names{$k}[0] eq $c) or ($cipher_names{$k}[1] eq $c));
    }
    foreach my $k (keys %cipher_alias) { # not yet found, check for alias
        return $k if ($cipher_alias{$k}[0] eq $c);
    }
    return '';
} # get_cipher_hex

sub get_cipher_name($) {
    # check if given cipher name is a known cipher
    # checks in %ciphers if nof found in %cipher_names
    my $cipher  = shift;
    return $cipher if ((grep{/^$cipher/} %ciphers)>0);
    _trace("get_cipher_name: search $cipher");
    foreach my $k (keys %cipher_names) {
        return $cipher_names{$k}[0] if ($cipher =~ m/$cipher_names{$k}[0]/);
        return $cipher_names{$k}[0] if ($cipher_names{$k}[1] =~ /$cipher/);
    }
    # nothing found yet, try more lazy match
    foreach my $k (keys %cipher_names) {
        if ($cipher_names{$k}[0] =~ m/$cipher/) {
            _warn("partial match for cipher name found '$cipher'");
            return $cipher_names{$k}[0];
        }
    }
    return '';
} # get_cipher_name

=pod

=head2 printciphers($format)

Print C<%ciphers> data structure in specified format.

Supported formats are:
  openssl       - like openssl ciphers -V
  osaft         - most important data
  dump          - all available data
  15.12.15      - forma like in version 15.12.15 (for compatibility)

=cut

sub printciphers($) {
    #? print internal list of ciphers in specified format
    my $format = shift;
    foreach my $key (keys %ciphers) {

        my @values;
        if ($format =~ m/^(?:dump|yeast)/) {
            foreach my $val (sort keys %{$ciphers{$key}}) {
                push(@values, $ciphers{$key}->{$val});
            }
            printf"%12s\t%s\n", $key, join("\t",@values); next;
        }

        my $name= $cipher_names{$key}->{'iana'} || '';
        my $ssl = $ciphers{$key}->{'ssl'} || '';
        my $kx  = $ciphers{$key}->{'kx'}  || '';
        my $au  = $ciphers{$key}->{'au'}  || '';
        my $enc = $ciphers{$key}->{'enc'} || '';
        my $bit = $ciphers{$key}->{'bit'} || '0';
        my $mac = $ciphers{$key}->{'mac'} || '';
        my $sec = $ciphers{$key}->{'sec'} || '';
        my $tag = $ciphers{$key}->{'tag'} || '';

        if ($format =~ m/^(?:15|15.12.15|old)/) {
            $name= $cipher_names{$key}->{'osaft'} || '';
    next if $key =~ m/0x/;    # dirty hack 'til %cipher is clean
            my $score= '0'; # dummy because we don't have scores in new structure
            printf(" %-30s %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                     $key, $sec, $ssl, $enc, $bit, $mac, $au, $kx, $score, $tag  );
        }

        if ($format =~ m/^(?:16|16.06.16|new|osaft)/) {
            $name= $cipher_names{$key}->{'iana'} || '';
            $name= $key;
            printf("%14s\t%-41s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                    $key, $name, $ssl, $kx, $au, $enc, $bit, $mac, $tag  );
        }

        if ($format =~ m/^(?:openssl)/) {
            $name= $cipher_names{$key}->{'openssl'} || '';
            printf("%19s - %-23s %-5s Kx=%-8s Au=%-4s Enc=%s(%s) Mac=%-4s %s\n",
                    $key, $name, $ssl, $kx,   $au,   $enc, $bit, $mac,    $tag  );
        }

    }
    return;
}; # printciphers


# internal methods

sub _ciphers_init() {
    #? additional initializations for data structures
    my @keys;   # for checking duplicates

    # initialize data from IANA tls-parameters.txt
    foreach my $key (keys %OSaft::Ciphers::_ciphers_iana) {
        if (grep{/^$key$/} @keys) {
            _warn(" duplicate IANA key: »$key«");
        } else {
            push(@keys, $key);
        }
        $cipher_names{$key}->{'iana'} = $OSaft::Ciphers::_ciphers_iana{$key}[0] || '';
        $ciphers{$key}->{'rfc'} = $OSaft::Ciphers::_ciphers_iana{$key}[1] || '';
        $ciphers{$key}->{'dtls'}= $OSaft::Ciphers::_ciphers_iana{$key}[2] || '';
    }

    # initialize data from O-Saft settings
    foreach my $key (keys %OSaft::Ciphers::_ciphers_osaft) {
        if (grep{/^$key$/} @keys) {
            _warn(" duplicate O-Saft key: »$key«");
        } else {
            push(@keys, $key);
        }
        $ciphers{$key}->{'ssl'} = $OSaft::Ciphers::_ciphers_osaft{$key}[0] || '';
        $ciphers{$key}->{'kx'}  = $OSaft::Ciphers::_ciphers_osaft{$key}[1] || '';
        $ciphers{$key}->{'au'}  = $OSaft::Ciphers::_ciphers_osaft{$key}[2] || '';
        $ciphers{$key}->{'enc'} = $OSaft::Ciphers::_ciphers_osaft{$key}[3] || '';
        $ciphers{$key}->{'bit'} = $OSaft::Ciphers::_ciphers_osaft{$key}[4] || '';
        $ciphers{$key}->{'mac'} = $OSaft::Ciphers::_ciphers_osaft{$key}[5] || '';
        $ciphers{$key}->{'sec'} = $OSaft::Ciphers::_ciphers_osaft{$key}[6] || '';
        $ciphers{$key}->{'tag'} = $OSaft::Ciphers::_ciphers_osaft{$key}[7] || '';
            $ciphers{$key}->{'score'} = "80";
        #$cipher_names{$key}->{'osaft'} = $key;
    }

    # initialize data from "openssl ciphers -V
    undef @keys;
    foreach my $key (keys %OSaft::Ciphers::_ciphers_openssl_all) {
        if (grep{/^$key$/} @keys) {
            _warn(" duplicate openssl key: »$key«");
        } else {
            push(@keys, $key);
        }
        #print $key;
        $ciphers{$key}->{'ssl'} = $OSaft::Ciphers::_ciphers_openssl_all{$key}[0];
        $ciphers{$key}->{'kx'}  = $OSaft::Ciphers::_ciphers_openssl_all{$key}[1];
        $ciphers{$key}->{'au'}  = $OSaft::Ciphers::_ciphers_openssl_all{$key}[2];
        $ciphers{$key}->{'enc'} = $OSaft::Ciphers::_ciphers_openssl_all{$key}[3];
        $ciphers{$key}->{'bit'} = $OSaft::Ciphers::_ciphers_openssl_all{$key}[4];
        $ciphers{$key}->{'mac'} = $OSaft::Ciphers::_ciphers_openssl_all{$key}[5];
        $ciphers{$key}->{'tag'} = $OSaft::Ciphers::_ciphers_openssl_all{$key}[7] || '';
        $cipher_names{$key}->{'openssl'} = $OSaft::Ciphers::_ciphers_openssl_all{$key}[6] || '';
        #$ciphers{$key}->{'sec'} = $OSaft::Ciphers::_ciphers_openssl_all{$key}[7];
    }

    return;
}; # _ciphers_init

sub cipher_done() {};           # dummy to check successful include

# complete initializations
_ciphers_init();

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

28-may-16 Achim Hoffmann

=cut

## PACKAGE }


#_____________________________________________________________________________
#_____________________________________________________________________ self __|

if (! defined caller) {     # print myself or open connection
    if ($#ARGV < 0) {       # no arguments given, print help
        printf("# %s %s\n", __PACKAGE__, $VERSION);
        if (eval {require POD::Perldoc;}) {
            # pod2usage( -verbose => 1 );
            exit( Pod::Perldoc->run(args=>[$0]) );
        }
        if (qx(perldoc -V)) {
            # may return:  You need to install the perl-doc package to use this program.
            #exec "perldoc $0"; # scary ...
            printf("# no POD::Perldoc installed, please try:\n  perldoc $0\n");
        }
        exit 0;
    }

    # got arguments, do something special
    while (my $arg = shift @ARGV) {
        printciphers($1) if ($arg =~ /^ciphers=(.*)$/);  # 15|16|dump|osaft|openssl
    }
}

1;

